//! Bounded Linux x86_64 ELF loading for the compatibility service.
//!
//! 职责：使用成熟 ELF 解析库生成映射、重定位和生命周期计划，并通过可注入内存后端执行。
//! 边界：不解析 Linux 路径，不实现完整动态链接器，也不直接进入 Linux 用户态。
//! Responsibility: plan bounded ELF images and apply mappings, relocations, and lifecycle
//! metadata through an injected memory backend. Linux process startup remains outside this crate.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod execution;
mod memory;
mod relocation;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::mem::size_of;

use goblin::elf::dynamic::{
    DT_FINI, DT_FINI_ARRAY, DT_FINI_ARRAYSZ, DT_INIT, DT_INIT_ARRAY, DT_INIT_ARRAYSZ,
};
use goblin::elf::header::{ELFCLASS64, ELFDATA2LSB, EM_X86_64, ET_DYN, ET_EXEC};
use goblin::elf::program_header::{PF_R, PF_W, PF_X, PT_GNU_RELRO, PT_INTERP, PT_LOAD, PT_TLS};
use goblin::elf::reloc::*;
use goblin::elf::sym::{STB_GLOBAL, STB_LOCAL, STB_WEAK};
use goblin::elf::Elf;

pub use execution::{
    build_initial_stack, plan_dynamic_program, run_preloaded_entry, run_preloaded_exit,
    run_process_entry, stack_input_for_program, AuxvEntry, DynamicProgramPlan, EntryCall,
    EntryCallKind, EntryFrame, EntrySource, ExecutionBackend, ExecutionPlan, InitialStackInput,
    InitialStackPlan, ProgramStackInput, RuntimeModule,
};
pub use memory::{
    initialize_tls_block, map_image, protect_relro, select_load_bias, ImageLayout, LoaderMemory,
    MappedFileRange, MappedPage, MappedSegment, MappingRequest, MemoryPermissions,
    RuntimeLifecycle, RuntimeRange, TlsImage,
};
pub use relocation::{
    apply_relocation_patches, plan_lifecycle_order, prepare_relocations, read_lifecycle_callbacks,
    LifecycleCallbacks, LifecycleOrder, MemoryPatch, RelocationContext, ResolvedSymbol,
    SymbolResolver, SymbolTable,
};

const MAX_PROGRAM_HEADERS: usize = 128;
const MAX_LOAD_SEGMENTS: usize = 64;
const MAX_RELOCATIONS: usize = 1_000_000;
const MAX_DYNAMIC_NAMES: usize = 256;
const MAX_DYNAMIC_NAME_BYTES: usize = 4096;
const MAX_TLS_BYTES: u64 = 16 * 1024 * 1024;
const MAX_LIFECYCLE_BYTES: u64 = 1024 * 1024;
const MAX_USER_ADDRESS: u64 = 1 << 47;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// ELF 校验或存取失败的原因。
///
/// Reason an ELF validation or memory operation failed.
pub enum LoaderError {
    Parse,
    WrongMachine,
    UnsupportedFormat,
    TooManySegments,
    TooManyRelocations,
    TooManyDynamicNames,
    BadSegment,
    BadAlignment,
    OverlappingSegments,
    BadInterpreter,
    BadTls,
    BadRelocation,
    EntryOutsideExecutable,
    BadExecution,
    BadStack,
    UnsupportedRelocation(u32),
    BadPageSize,
    BadLoadBias,
    ImageTooLarge,
    SourceOutOfBounds,
    MemoryMap,
    MemoryRead,
    MemoryWrite,
    MemoryProtect,
    BadTransaction,
    TransactionRollbackFailed,
    OverlappingImages,
    UnresolvedSymbol,
    IfuncUnsupported,
    BadLifecycle,
    CyclicDependencies,
    DependencyOutOfBounds,
}

/// 一段 ELF 虚拟地址范围。
///
/// A virtual-address range expressed relative to the ELF image before relocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtualRange {
    pub address: u64,
    pub bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// 一个可执行文件装入内存的 PT_LOAD 段。
///
/// A PT_LOAD segment in the executable file image.
pub struct LoadSegment {
    /// 文件内偏移。/ Offset in the ELF file.
    pub file_offset: u64,
    /// 重定位前的虚拟地址。/ Virtual address before load-bias relocation.
    pub virtual_address: u64,
    /// 从文件复制的字节数。/ Number of bytes copied from the file.
    pub file_bytes: u64,
    /// 映射的总内存字节数，包含 BSS。/ Total mapped bytes, including BSS.
    pub memory_bytes: u64,
    /// 文件偏移与虚拟地址要求页对齐。
    ///
    /// Required page alignment for the file offset and virtual address.
    pub align: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// PT_TLS 线程局部存储模板。
///
/// Thread-local storage template from PT_TLS.
pub struct TlsSegment {
    pub file_offset: u64,
    pub virtual_address: u64,
    pub file_bytes: u64,
    pub memory_bytes: u64,
    pub align: u64,
}

/// 动态链接生命周期入口的地址计划。
///
/// Planned dynamic lifecycle entries in pre-relocation virtual addresses.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LifecyclePlan {
    pub init: Option<u64>,
    pub fini: Option<u64>,
    pub init_array: Option<VirtualRange>,
    pub fini_array: Option<VirtualRange>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// x86_64 动态重定位类别。
///
/// A supported x86_64 dynamic relocation category.
pub enum RelocationKind {
    None,
    Relative,
    GlobDat,
    JumpSlot,
    Absolute,
    PcRelative,
    Copy,
    TlsModule,
    DtpOffset,
    TpOffset,
    TlsDesc,
    IRelative,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// ELF 动态符号绑定类别。
///
/// ELF dynamic-symbol binding category.
pub enum SymbolBinding {
    Local,
    Global,
    Weak,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// 一项待解析的动态重定位。
///
/// One dynamic relocation awaiting symbol resolution and writeback.
pub struct Relocation {
    /// 重定位目标的重定位前虚拟地址。
    ///
    /// Pre-relocation virtual address of the relocation target.
    pub offset: u64,
    /// RELA 记录的符号加数。/ Symbol addend from the RELA record.
    pub addend: i64,
    /// x86_64 重定位类别。/ x86_64 relocation category.
    pub kind: RelocationKind,
    /// 动态符号名；无符号重定位为空。
    ///
    /// Dynamic symbol name, or `None` when the relocation has no symbol.
    pub symbol: Option<String>,
    /// 动态符号表中的原始 `st_value`。
    ///
    /// Raw `st_value` from the dynamic symbol table.
    pub symbol_value: u64,
    /// 动态符号表中的 `st_size`。
    ///
    /// `st_size` from the dynamic symbol table.
    pub symbol_size: u64,
    /// 符号是否在本对象中定义。
    ///
    /// Whether the symbol is defined in this object.
    pub symbol_defined: bool,
    /// 符号绑定；无符号重定位为空。
    ///
    /// Symbol binding, or `None` when the relocation has no symbol.
    pub symbol_binding: Option<SymbolBinding>,
    /// 符号是否为 GNU IFUNC；调用解析器前必须显式处理。
    ///
    /// Whether the symbol is a GNU IFUNC that requires explicit resolver invocation.
    pub symbol_is_ifunc: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SymbolLookup {
    pub value: u64,
    pub size: u64,
    pub defined: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// 有界、已验证的 Linux ELF 动态装载计划。
///
/// A bounded and validated dynamic load plan for a Linux ELF object.
pub struct LoadPlan {
    pub entry: u64,
    pub position_independent: bool,
    pub interpreter: Option<String>,
    pub needed: Vec<String>,
    pub rpaths: Vec<String>,
    pub runpaths: Vec<String>,
    pub segments: Vec<LoadSegment>,
    pub program_headers: Option<VirtualRange>,
    pub program_header_entry_size: u16,
    pub program_header_count: u16,
    pub tls: Option<TlsSegment>,
    pub relro: Option<VirtualRange>,
    pub lifecycle: LifecyclePlan,
    pub relocations: Vec<Relocation>,
    pub max_align: u64,
}

impl LoadPlan {
    pub fn contains_virtual(&self, address: u64) -> bool {
        self.segments.iter().any(|segment| {
            segment
                .virtual_address
                .checked_add(segment.memory_bytes)
                .is_some_and(|end| (segment.virtual_address..end).contains(&address))
        })
    }

    pub fn symbol(&self, bytes: &[u8], name: &str) -> Option<SymbolLookup> {
        let elf = Elf::parse(bytes).ok()?;
        let symbol = elf
            .dynsyms
            .iter()
            .find(|symbol| elf.dynstrtab.get_at(symbol.st_name) == Some(name))?;
        Some(SymbolLookup {
            value: symbol.st_value,
            size: symbol.st_size,
            defined: symbol.st_shndx != 0,
        })
    }
}

pub fn parse(bytes: &[u8]) -> Result<LoadPlan, LoaderError> {
    let elf = Elf::parse(bytes).map_err(|_| LoaderError::Parse)?;
    let header = &elf.header;
    if header.e_ident[4] != ELFCLASS64
        || header.e_ident[5] != ELFDATA2LSB
        || header.e_machine != EM_X86_64
    {
        return Err(LoaderError::WrongMachine);
    }
    if header.e_type != ET_EXEC && header.e_type != ET_DYN {
        return Err(LoaderError::UnsupportedFormat);
    }
    if elf.program_headers.len() > MAX_PROGRAM_HEADERS {
        return Err(LoaderError::TooManySegments);
    }

    let mut segments = Vec::new();
    let mut interp = None;
    let mut tls = None;
    let mut relro = None;
    let mut max_align = 1u64;
    let mut interpreter_headers = 0usize;
    let mut tls_headers = 0usize;
    let mut relro_headers = 0usize;
    for program in &elf.program_headers {
        if program.p_filesz > program.p_memsz
            || program
                .p_offset
                .checked_add(program.p_filesz)
                .is_none_or(|end| end > bytes.len() as u64)
            || program.p_vaddr.checked_add(program.p_memsz).is_none()
        {
            return Err(LoaderError::BadSegment);
        }
        if program.p_align != 0 && !program.p_align.is_power_of_two() {
            return Err(LoaderError::BadAlignment);
        }
        if program.p_type == PT_LOAD {
            max_align = max_align.max(program.p_align.max(1));
            if program.p_vaddr >= MAX_USER_ADDRESS
                || program
                    .p_vaddr
                    .checked_add(program.p_memsz)
                    .is_none_or(|end| end > MAX_USER_ADDRESS)
            {
                return Err(LoaderError::BadSegment);
            }
            if !segment_alignment_matches(program.p_offset, program.p_vaddr, program.p_align) {
                return Err(LoaderError::BadAlignment);
            }
            segments.push(LoadSegment {
                file_offset: program.p_offset,
                virtual_address: program.p_vaddr,
                file_bytes: program.p_filesz,
                memory_bytes: program.p_memsz,
                align: program.p_align,
                readable: program.p_flags & PF_R != 0,
                writable: program.p_flags & PF_W != 0,
                executable: program.p_flags & PF_X != 0,
            });
        } else if program.p_type == PT_INTERP {
            interpreter_headers += 1;
            let path = elf.interpreter.ok_or(LoaderError::BadInterpreter)?;
            if program.p_filesz == 0 || !valid_dynamic_name(path) {
                return Err(LoaderError::BadInterpreter);
            }
            interp = Some(path.to_string());
        } else if program.p_type == PT_TLS {
            tls_headers += 1;
            if program.p_memsz > MAX_TLS_BYTES {
                return Err(LoaderError::ImageTooLarge);
            }
            tls = Some(TlsSegment {
                file_offset: program.p_offset,
                virtual_address: program.p_vaddr,
                file_bytes: program.p_filesz,
                memory_bytes: program.p_memsz,
                align: program.p_align,
            });
        } else if program.p_type == PT_GNU_RELRO {
            relro_headers += 1;
            if program.p_memsz == 0 {
                return Err(LoaderError::BadSegment);
            }
            relro = Some(VirtualRange {
                address: program.p_vaddr,
                bytes: program.p_memsz,
            });
        }
    }
    if interpreter_headers > 1 || tls_headers > 1 || relro_headers > 1 {
        return Err(LoaderError::BadSegment);
    }
    if segments.len() > MAX_LOAD_SEGMENTS {
        return Err(LoaderError::TooManySegments);
    }
    validate_segments(&mut segments)?;
    if let Some(tls) = tls {
        if tls.file_bytes > tls.memory_bytes
            || !tls_in_load_image(&tls, &segments)
            || (tls.align > 1 && tls.file_offset % tls.align != tls.virtual_address % tls.align)
        {
            return Err(LoaderError::BadTls);
        }
    }
    if let Some(range) = relro {
        if !range_in_writable_image(range, &segments) {
            return Err(LoaderError::BadSegment);
        }
    }
    if !segments.iter().any(|segment| {
        segment.executable
            && (segment.virtual_address..segment.virtual_address + segment.memory_bytes)
                .contains(&header.e_entry)
    }) {
        return Err(LoaderError::EntryOutsideExecutable);
    }

    let mut relocations = Vec::new();
    collect_relocations(&elf, elf.dynrelas.iter(), &segments, &mut relocations)?;
    collect_relocations(&elf, elf.pltrelocs.iter(), &segments, &mut relocations)?;
    if relocations.len() > MAX_RELOCATIONS {
        return Err(LoaderError::TooManyRelocations);
    }

    let needed = collect_dynamic_names(elf.libraries.iter().copied())?;
    let rpaths = collect_dynamic_names(elf.rpaths.iter().copied())?;
    let runpaths = collect_dynamic_names(elf.runpaths.iter().copied())?;
    let lifecycle = collect_lifecycle(&elf, &segments)?;
    let program_headers = program_header_range(
        header.e_phoff,
        header.e_phentsize,
        header.e_phnum,
        &segments,
        bytes.len() as u64,
    )?;

    Ok(LoadPlan {
        entry: header.e_entry,
        position_independent: header.e_type == ET_DYN,
        interpreter: interp,
        needed,
        rpaths,
        runpaths,
        segments,
        program_headers,
        program_header_entry_size: header.e_phentsize,
        program_header_count: header.e_phnum,
        tls,
        relro,
        lifecycle,
        relocations,
        max_align,
    })
}

fn program_header_range(
    file_offset: u64,
    entry_size: u16,
    count: u16,
    segments: &[LoadSegment],
    file_len: u64,
) -> Result<Option<VirtualRange>, LoaderError> {
    if count == 0 {
        return Ok(None);
    }
    if entry_size == 0 {
        return Err(LoaderError::BadSegment);
    }
    let bytes = u64::from(entry_size)
        .checked_mul(u64::from(count))
        .ok_or(LoaderError::BadSegment)?;
    let end = file_offset
        .checked_add(bytes)
        .ok_or(LoaderError::BadSegment)?;
    if end > file_len {
        return Err(LoaderError::BadSegment);
    }
    for segment in segments {
        let segment_file_end = segment
            .file_offset
            .checked_add(segment.file_bytes)
            .ok_or(LoaderError::BadSegment)?;
        if segment.readable && file_offset >= segment.file_offset && end <= segment_file_end {
            return Ok(Some(VirtualRange {
                address: segment
                    .virtual_address
                    .checked_add(file_offset - segment.file_offset)
                    .ok_or(LoaderError::BadSegment)?,
                bytes,
            }));
        }
    }
    // A static image may keep its program headers outside PT_LOAD. Report the table
    // as unavailable; dynamic stack construction will reject the absence of AT_PHDR.
    // 静态映像可把程序头表留在 PT_LOAD 外；此处报告不可用，动态初始栈会失败关闭。
    Ok(None)
}

fn collect_relocations<'a>(
    elf: &Elf<'a>,
    iter: impl Iterator<Item = goblin::elf::reloc::Reloc>,
    segments: &[LoadSegment],
    output: &mut Vec<Relocation>,
) -> Result<(), LoaderError> {
    for relocation in iter {
        if relocation.r_sym != 0 && relocation.r_sym >= elf.dynsyms.len() {
            return Err(LoaderError::BadRelocation);
        }
        let kind = match relocation.r_type {
            R_X86_64_NONE => RelocationKind::None,
            R_X86_64_RELATIVE => RelocationKind::Relative,
            R_X86_64_GLOB_DAT => RelocationKind::GlobDat,
            R_X86_64_JUMP_SLOT => RelocationKind::JumpSlot,
            R_X86_64_64 => RelocationKind::Absolute,
            R_X86_64_PC32 => RelocationKind::PcRelative,
            R_X86_64_COPY => RelocationKind::Copy,
            R_X86_64_DTPMOD64 => RelocationKind::TlsModule,
            R_X86_64_DTPOFF64 => RelocationKind::DtpOffset,
            R_X86_64_TPOFF64 => RelocationKind::TpOffset,
            R_X86_64_TLSDESC => RelocationKind::TlsDesc,
            R_X86_64_IRELATIVE => RelocationKind::IRelative,
            kind => return Err(LoaderError::UnsupportedRelocation(kind)),
        };
        let target_bytes = match kind {
            RelocationKind::None => 0,
            RelocationKind::PcRelative => size_of::<i32>() as u64,
            RelocationKind::TlsDesc => 2 * size_of::<u64>() as u64,
            _ => size_of::<u64>() as u64,
        };
        if kind != RelocationKind::None
            && !writable_target(relocation.r_offset, target_bytes, segments)
        {
            return Err(LoaderError::BadRelocation);
        }
        let (symbol, symbol_value, symbol_size, symbol_defined, symbol_binding, symbol_is_ifunc) =
            if relocation.r_sym == 0 {
                (None, 0, 0, false, None, false)
            } else {
                let symbol = elf
                    .dynsyms
                    .get(relocation.r_sym)
                    .ok_or(LoaderError::BadRelocation)?;
                let name = Some(
                    elf.dynstrtab
                        .get_at(symbol.st_name)
                        .ok_or(LoaderError::BadRelocation)?
                        .to_string(),
                );
                let binding = match symbol.st_bind() {
                    STB_LOCAL => SymbolBinding::Local,
                    STB_GLOBAL => SymbolBinding::Global,
                    STB_WEAK => SymbolBinding::Weak,
                    _ => return Err(LoaderError::BadRelocation),
                };
                (
                    name,
                    symbol.st_value,
                    symbol.st_size,
                    symbol.st_shndx != 0,
                    Some(binding),
                    symbol.st_type() == 10,
                )
            };
        if output.len() == MAX_RELOCATIONS {
            return Err(LoaderError::TooManyRelocations);
        }
        output.push(Relocation {
            offset: relocation.r_offset,
            addend: relocation.r_addend.unwrap_or(0),
            kind,
            symbol,
            symbol_value,
            symbol_size,
            symbol_defined,
            symbol_binding,
            symbol_is_ifunc,
        });
    }
    Ok(())
}

fn validate_segments(segments: &mut [LoadSegment]) -> Result<(), LoaderError> {
    segments.sort_unstable_by_key(|segment| segment.virtual_address);
    for pair in segments.windows(2) {
        let previous_end = pair[0]
            .virtual_address
            .checked_add(pair[0].memory_bytes)
            .ok_or(LoaderError::BadSegment)?;
        if pair[1].virtual_address < previous_end {
            return Err(LoaderError::OverlappingSegments);
        }
    }
    Ok(())
}

fn segment_alignment_matches(file_offset: u64, virtual_address: u64, align: u64) -> bool {
    align <= 1 || file_offset % align == virtual_address % align
}

fn tls_in_load_image(tls: &TlsSegment, segments: &[LoadSegment]) -> bool {
    let file_end = tls.file_offset.checked_add(tls.file_bytes);
    let memory_end = tls.virtual_address.checked_add(tls.memory_bytes);
    let (Some(file_end), Some(memory_end)) = (file_end, memory_end) else {
        return false;
    };
    segments.iter().any(|segment| {
        let segment_file_end = segment.file_offset.checked_add(segment.file_bytes);
        let segment_memory_end = segment.virtual_address.checked_add(segment.memory_bytes);
        matches!(
            (segment_file_end, segment_memory_end),
            (Some(segment_file_end), Some(segment_memory_end))
                if tls.file_offset >= segment.file_offset
                    && file_end <= segment_file_end
                    && tls.virtual_address >= segment.virtual_address
                    && memory_end <= segment_memory_end
        )
    })
}

fn writable_target(offset: u64, bytes: u64, segments: &[LoadSegment]) -> bool {
    let Some(end) = offset.checked_add(bytes) else {
        return false;
    };
    segments.iter().any(|segment| {
        segment.writable
            && offset >= segment.virtual_address
            && end <= segment.virtual_address + segment.memory_bytes
    })
}

fn range_in_writable_image(range: VirtualRange, segments: &[LoadSegment]) -> bool {
    let Some(end) = range.address.checked_add(range.bytes) else {
        return false;
    };
    segments.iter().any(|segment| {
        segment.writable
            && range.address >= segment.virtual_address
            && end <= segment.virtual_address + segment.memory_bytes
    })
}

fn range_in_executable_image(range: VirtualRange, segments: &[LoadSegment]) -> bool {
    let Some(end) = range.address.checked_add(range.bytes) else {
        return false;
    };
    segments.iter().any(|segment| {
        segment.executable
            && range.address >= segment.virtual_address
            && end <= segment.virtual_address + segment.memory_bytes
    })
}

fn range_in_loaded_image(range: VirtualRange, segments: &[LoadSegment]) -> bool {
    let Some(end) = range.address.checked_add(range.bytes) else {
        return false;
    };
    segments.iter().any(|segment| {
        range.address >= segment.virtual_address
            && end <= segment.virtual_address + segment.memory_bytes
    })
}

/// 收集 DT_INIT、DT_FINI 及其数组范围，并拒绝越界或非代码入口。
///
/// Collects DT_INIT, DT_FINI, and their array ranges while rejecting invalid addresses.
fn collect_lifecycle(
    elf: &Elf<'_>,
    segments: &[LoadSegment],
) -> Result<LifecyclePlan, LoaderError> {
    let mut plan = LifecyclePlan::default();
    let Some(dynamic) = &elf.dynamic else {
        return Ok(plan);
    };
    let mut init_array_size = None;
    let mut fini_array_size = None;
    for entry in &dynamic.dyns {
        match entry.d_tag {
            DT_INIT => {
                if plan.init.is_some() || entry.d_val == 0 {
                    return Err(LoaderError::BadLifecycle);
                }
                plan.init = Some(entry.d_val);
            }
            DT_FINI => {
                if plan.fini.is_some() || entry.d_val == 0 {
                    return Err(LoaderError::BadLifecycle);
                }
                plan.fini = Some(entry.d_val);
            }
            DT_INIT_ARRAY => {
                if plan.init_array.is_some() {
                    return Err(LoaderError::BadLifecycle);
                }
                plan.init_array = Some(VirtualRange {
                    address: entry.d_val,
                    bytes: 0,
                });
            }
            DT_FINI_ARRAY => {
                if plan.fini_array.is_some() {
                    return Err(LoaderError::BadLifecycle);
                }
                plan.fini_array = Some(VirtualRange {
                    address: entry.d_val,
                    bytes: 0,
                });
            }
            DT_INIT_ARRAYSZ => {
                if init_array_size.replace(entry.d_val).is_some() {
                    return Err(LoaderError::BadLifecycle);
                }
            }
            DT_FINI_ARRAYSZ if fini_array_size.replace(entry.d_val).is_some() => {
                return Err(LoaderError::BadLifecycle);
            }
            _ => {}
        }
    }

    for (range, size) in [
        (&mut plan.init_array, init_array_size),
        (&mut plan.fini_array, fini_array_size),
    ] {
        match (*range, size) {
            (Some(mut value), Some(size)) => {
                if size == 0 || size > MAX_LIFECYCLE_BYTES || size % size_of::<u64>() as u64 != 0 {
                    return Err(LoaderError::BadLifecycle);
                }
                value.bytes = size;
                if !range_in_loaded_image(value, segments) {
                    return Err(LoaderError::BadLifecycle);
                }
                *range = Some(value);
            }
            (None, None) => {}
            _ => return Err(LoaderError::BadLifecycle),
        }
    }
    if let Some(init) = plan.init {
        if !range_in_executable_image(
            VirtualRange {
                address: init,
                bytes: 1,
            },
            segments,
        ) {
            return Err(LoaderError::BadLifecycle);
        }
    }
    if let Some(fini) = plan.fini {
        if !range_in_executable_image(
            VirtualRange {
                address: fini,
                bytes: 1,
            },
            segments,
        ) {
            return Err(LoaderError::BadLifecycle);
        }
    }
    Ok(plan)
}

fn collect_dynamic_names<'a>(
    names: impl Iterator<Item = &'a str>,
) -> Result<Vec<String>, LoaderError> {
    let mut output = Vec::new();
    for name in names {
        if !valid_dynamic_name(name) {
            return Err(LoaderError::BadSegment);
        }
        output.push(name.to_string());
        if output.len() > MAX_DYNAMIC_NAMES {
            return Err(LoaderError::TooManyDynamicNames);
        }
    }
    Ok(output)
}

fn valid_dynamic_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_DYNAMIC_NAME_BYTES && !name.contains('\0')
}

const _: () = assert!(MAX_RELOCATIONS * size_of::<Relocation>() > 0);

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn real_dynamic_linux_binary_yields_bounded_load_plan() {
        let bytes = fs::read("/bin/bash").expect("/bin/bash fixture");
        let plan = parse(&bytes).unwrap();
        assert!(plan.position_independent);
        assert!(plan.interpreter.is_some());
        assert!(plan.needed.iter().any(|name| name.contains("libc.so")));
        assert!(!plan.segments.is_empty());
        assert!(!plan.relocations.is_empty());
        assert!(plan.segments.iter().any(|segment| segment.executable));
        assert!(plan.contains_virtual(plan.entry));
    }
    #[test]
    fn real_tls_segment_is_represented() {
        let bytes = fs::read("/lib/x86_64-linux-gnu/libc.so.6").expect("libc fixture");
        let plan = parse(&bytes).unwrap();
        let tls = plan.tls.expect("libc PT_TLS");
        assert!(tls.file_bytes > 0);
        assert!(tls.memory_bytes >= tls.file_bytes);
        assert!(tls.align.is_power_of_two());
    }

    #[test]
    fn dynamic_symbol_lookup_uses_real_symbol_table() {
        let bytes = fs::read("/bin/bash").unwrap();
        let plan = parse(&bytes).unwrap();
        let symbol = plan.symbol(&bytes, "malloc").expect("malloc dynsym");
        assert!(!symbol.defined);
        assert!(plan.relocations.iter().any(|relocation| {
            matches!(
                relocation.kind,
                RelocationKind::JumpSlot | RelocationKind::GlobDat
            ) && relocation.symbol.as_deref() == Some("malloc")
        }));
    }

    #[test]
    fn wrong_arch_and_truncation_fail_closed() {
        let mut bytes = fs::read("/bin/bash").unwrap();
        assert_eq!(parse(&bytes[..32]), Err(LoaderError::Parse));
        let machine = 18usize;
        bytes[machine] = 0xf3;
        bytes[machine + 1] = 0x00;
        assert_eq!(parse(&bytes), Err(LoaderError::WrongMachine));
    }

    #[test]
    fn segment_alignment_and_overlap_fail_closed() {
        assert!(segment_alignment_matches(0x1000, 0x400000, 0x1000));
        assert!(!segment_alignment_matches(0, 0x1001, 0x1000));

        let mut segments = [
            LoadSegment {
                file_offset: 0,
                virtual_address: 0x1000,
                file_bytes: 0x2000,
                memory_bytes: 0x2000,
                align: 0x1000,
                readable: true,
                writable: false,
                executable: true,
            },
            LoadSegment {
                file_offset: 0x2000,
                virtual_address: 0x2000,
                file_bytes: 0x1000,
                memory_bytes: 0x1000,
                align: 0x1000,
                readable: true,
                writable: false,
                executable: false,
            },
        ];
        assert_eq!(
            validate_segments(&mut segments),
            Err(LoaderError::OverlappingSegments)
        );
    }

    #[test]
    fn relocation_targets_and_tls_must_be_inside_load_image() {
        let segments = [LoadSegment {
            file_offset: 0,
            virtual_address: 0x1000,
            file_bytes: 0x1000,
            memory_bytes: 0x2000,
            align: 0x1000,
            readable: true,
            writable: true,
            executable: false,
        }];
        assert!(writable_target(0x1ff8, 8, &segments));
        assert!(writable_target(0x2ffc, 4, &segments));
        assert!(!writable_target(0x2ffc, 8, &segments));
        assert!(!writable_target(0x2ff9, 8, &segments));
        assert!(!writable_target(0x3000, 8, &segments));

        let valid_tls = TlsSegment {
            file_offset: 0x100,
            virtual_address: 0x1100,
            file_bytes: 0x10,
            memory_bytes: 0x20,
            align: 0x10,
        };
        assert!(tls_in_load_image(&valid_tls, &segments));
        let outside_tls = TlsSegment {
            virtual_address: 0x2ff0,
            memory_bytes: 0x20,
            ..valid_tls
        };
        assert!(!tls_in_load_image(&outside_tls, &segments));
    }

    #[test]
    fn program_headers_report_only_complete_readable_load_ranges() {
        let segment = LoadSegment {
            file_offset: 0x100,
            virtual_address: 0x40_0100,
            file_bytes: 0x100,
            memory_bytes: 0x100,
            align: 0x100,
            readable: true,
            writable: false,
            executable: false,
        };
        assert_eq!(
            program_header_range(0x110, 56, 2, &[segment], 0x200),
            Ok(Some(VirtualRange {
                address: 0x40_0110,
                bytes: 112,
            }))
        );
        assert_eq!(
            program_header_range(
                0x110,
                56,
                2,
                &[LoadSegment {
                    readable: false,
                    ..segment
                }],
                0x200,
            ),
            Ok(None)
        );
        assert_eq!(
            program_header_range(0x1f0, 56, 2, &[segment], 0x300),
            Ok(None)
        );
        assert_eq!(
            program_header_range(0x110, 56, 2, &[segment], 0x120),
            Err(LoaderError::BadSegment)
        );
        assert_eq!(
            program_header_range(0x110, 0, 0, &[segment], 0x200),
            Ok(None)
        );
    }
}
