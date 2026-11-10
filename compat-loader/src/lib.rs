//! Bounded Linux x86_64 ELF load planning for the compatibility service.
//!
//! 职责：使用成熟 ELF 解析库生成段、依赖、TLS 与重定位装载计划。
//! 边界：不映射页、不解析 Linux 路径、不执行重定位或完整动态链接。
//! Responsibility: validate ELF metadata and produce a bounded load plan.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::mem::size_of;

use goblin::elf::header::{ELFCLASS64, ELFDATA2LSB, EM_X86_64, ET_DYN, ET_EXEC};
use goblin::elf::program_header::{PF_R, PF_W, PF_X, PT_INTERP, PT_LOAD, PT_TLS};
use goblin::elf::reloc::*;
use goblin::elf::Elf;

const MAX_PROGRAM_HEADERS: usize = 128;
const MAX_LOAD_SEGMENTS: usize = 64;
const MAX_RELOCATIONS: usize = 1_000_000;
const MAX_DYNAMIC_NAMES: usize = 256;
const MAX_DYNAMIC_NAME_BYTES: usize = 4096;
const MAX_USER_ADDRESS: u64 = 1 << 47;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    UnsupportedRelocation(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoadSegment {
    pub file_offset: u64,
    pub virtual_address: u64,
    pub file_bytes: u64,
    pub memory_bytes: u64,
    pub align: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsSegment {
    pub file_offset: u64,
    pub virtual_address: u64,
    pub file_bytes: u64,
    pub memory_bytes: u64,
    pub align: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelocationKind {
    None,
    Relative,
    GlobDat,
    JumpSlot,
    Absolute,
    PcRelative,
    Copy,
    TlsModule,
    TlsOffset,
    TlsDesc,
    IRelative,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Relocation {
    pub offset: u64,
    pub addend: i64,
    pub kind: RelocationKind,
    pub symbol: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SymbolLookup {
    pub value: u64,
    pub size: u64,
    pub defined: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadPlan {
    pub entry: u64,
    pub position_independent: bool,
    pub interpreter: Option<String>,
    pub needed: Vec<String>,
    pub rpaths: Vec<String>,
    pub runpaths: Vec<String>,
    pub segments: Vec<LoadSegment>,
    pub tls: Option<TlsSegment>,
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
    let mut max_align = 1u64;
    let mut interpreter_headers = 0usize;
    let mut tls_headers = 0usize;
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
            if !segment_alignment_matches(
                program.p_offset,
                program.p_vaddr,
                program.p_align,
            ) {
                return Err(LoaderError::BadAlignment);
            }
            segments.push(LoadSegment {
                file_offset: program.p_offset,
                virtual_address: program.p_vaddr,
                file_bytes: program.p_filesz,
                memory_bytes: program.p_memsz,
                align: program.p_align,
                readable: program.p_flags & u32::from(PF_R) != 0,
                writable: program.p_flags & u32::from(PF_W) != 0,
                executable: program.p_flags & u32::from(PF_X) != 0,
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
            tls = Some(TlsSegment {
                file_offset: program.p_offset,
                virtual_address: program.p_vaddr,
                file_bytes: program.p_filesz,
                memory_bytes: program.p_memsz,
                align: program.p_align,
            });
        }
    }
    if interpreter_headers > 1 || tls_headers > 1 {
        return Err(LoaderError::BadSegment);
    }
    if segments.len() > MAX_LOAD_SEGMENTS {
        return Err(LoaderError::TooManySegments);
    }
    validate_segments(&mut segments)?;
    if let Some(tls) = tls {
        if tls.file_bytes > tls.memory_bytes
            || !tls_in_load_image(&tls, &segments)
            || (tls.align > 1
                && tls.file_offset % tls.align != tls.virtual_address % tls.align)
        {
            return Err(LoaderError::BadTls);
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

    Ok(LoadPlan {
        entry: header.e_entry,
        position_independent: header.e_type == ET_DYN,
        interpreter: interp,
        needed,
        rpaths,
        runpaths,
        segments,
        tls,
        relocations,
        max_align,
    })
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
            R_X86_64_DTPOFF64 | R_X86_64_TPOFF64 => RelocationKind::TlsOffset,
            R_X86_64_TLSDESC => RelocationKind::TlsDesc,
            R_X86_64_IRELATIVE => RelocationKind::IRelative,
            kind => return Err(LoaderError::UnsupportedRelocation(kind)),
        };
        if kind != RelocationKind::None && !writable_target(relocation.r_offset, segments) {
            return Err(LoaderError::BadRelocation);
        }
        let symbol = if relocation.r_sym == 0 {
            None
        } else {
            let symbol = elf
                .dynsyms
                .get(relocation.r_sym)
                .ok_or(LoaderError::BadRelocation)?;
            Some(
                elf.dynstrtab
                    .get_at(symbol.st_name)
                    .ok_or(LoaderError::BadRelocation)?
                    .to_string(),
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

fn writable_target(offset: u64, segments: &[LoadSegment]) -> bool {
    let Some(end) = offset.checked_add(size_of::<u64>() as u64) else {
        return false;
    };
    segments.iter().any(|segment| {
        segment.writable
            && offset >= segment.virtual_address
            && end <= segment.virtual_address + segment.memory_bytes
    })
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
        assert!(writable_target(0x1ff8, &segments));
        assert!(!writable_target(0x2ff9, &segments));
        assert!(!writable_target(0x3000, &segments));

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
}
