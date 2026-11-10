//! x86_64 动态重定位求解与一次性写回补丁。
//!
//! x86_64 dynamic-relocation resolution and prevalidated writeback patches. Symbol lookup is
//! supplied by the caller so object search order and security policy remain explicit.

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::mem::size_of;

use goblin::elf::section_header::{SHN_ABS, SHN_COMMON};
use goblin::elf::sym::{STB_GLOBAL, STB_WEAK, STT_GNU_IFUNC, STT_TLS, STV_DEFAULT, STV_PROTECTED};
use goblin::elf::Elf;

use super::memory::{validate_layout, with_transaction, LoaderMemory, RuntimeRange};
use super::{ImageLayout, LoadPlan, LoaderError, Relocation, RelocationKind, SymbolBinding};

const MAX_SYMBOLS: usize = 500_000;
const MAX_COPY_BYTES: u64 = 1024 * 1024;
const MAX_LIFECYCLE_BYTES: usize = 1024 * 1024;
const MAX_USER_ADDRESS: u64 = 1 << 47;
const MAX_LIFECYCLE_MODULES: usize = 65_536;

/// 已解析符号在目标进程中的值。
///
/// A resolved symbol value in the target process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedSymbol {
    /// 符号在目标地址空间中的地址；TLS 符号不使用此字段保存块偏移。
    ///
    /// Symbol address in the target address space; TLS block offsets use separate fields.
    pub address: u64,
    /// 符号字节大小。/ Symbol size in bytes.
    pub size: u64,
    /// 定义符号的模块标识。/ Module identifier defining the symbol.
    pub module_id: u64,
    /// TLS 符号在所属模块中的偏移。
    ///
    /// Offset of a TLS symbol within its defining module.
    pub module_tls_offset: Option<u64>,
    /// TLS 符号相对线程指针的静态偏移。
    ///
    /// Static offset of a TLS symbol relative to the thread pointer.
    pub thread_pointer_offset: Option<i64>,
    /// 是否需要先调用 IFUNC 解析器。
    ///
    /// Whether an IFUNC resolver must be invoked first.
    pub is_ifunc: bool,
}

/// 重定位解析器，由动态链接器按真实对象搜索顺序实现。
///
/// Relocation resolver implemented by the dynamic linker using the real object search order.
pub trait SymbolResolver {
    fn resolve(&self, name: &str) -> Option<ResolvedSymbol>;

    /// 为 COPY 重定位选择非引用对象中的定义。
    ///
    /// Selects the source definition outside the referring object for a COPY relocation.
    fn resolve_copy(&self, name: &str, referring_module: u64) -> Option<ResolvedSymbol> {
        let _ = referring_module;
        self.resolve(name)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SymbolDefinition {
    name: String,
    value: ResolvedSymbol,
}

/// 从真实 ELF 动态符号表构建的有序符号提供器。
///
/// Ordered symbol provider built from real ELF dynamic symbol tables. Earlier entries win,
/// matching caller-selected object search order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SymbolTable {
    definitions: Vec<SymbolDefinition>,
}

impl SymbolTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// 追加一个真实 ELF 映像的全局和弱定义。
    ///
    /// Appends global and weak definitions from one real ELF image.
    pub fn append_image(
        &mut self,
        bytes: &[u8],
        layout: &ImageLayout,
        module_id: u64,
    ) -> Result<(), LoaderError> {
        validate_layout(layout, None)?;
        if module_id == 0 {
            return Err(LoaderError::BadRelocation);
        }
        let elf = Elf::parse(bytes).map_err(|_| LoaderError::Parse)?;
        if self.definitions.len() + elf.dynsyms.len() > MAX_SYMBOLS {
            return Err(LoaderError::ImageTooLarge);
        }
        for symbol in elf.dynsyms.iter() {
            if symbol.st_shndx == SHN_COMMON as usize {
                return Err(LoaderError::BadRelocation);
            }
            if symbol.st_shndx == 0
                || (symbol.st_bind() != STB_GLOBAL && symbol.st_bind() != STB_WEAK)
            {
                continue;
            }
            let visibility = symbol.st_visibility();
            if visibility != STV_DEFAULT && visibility != STV_PROTECTED {
                continue;
            }
            let Some(name) = elf.dynstrtab.get_at(symbol.st_name) else {
                return Err(LoaderError::BadRelocation);
            };
            if name.is_empty() || name.contains('\0') {
                continue;
            }
            let is_tls = symbol.st_type() == STT_TLS;
            let address = if is_tls || symbol.st_shndx == SHN_ABS as usize {
                symbol.st_value
            } else {
                layout
                    .load_bias
                    .checked_add(symbol.st_value)
                    .ok_or(LoaderError::BadRelocation)?
            };
            self.definitions.push(SymbolDefinition {
                name: String::from(name),
                value: ResolvedSymbol {
                    address,
                    size: symbol.st_size,
                    module_id,
                    module_tls_offset: is_tls.then_some(symbol.st_value),
                    thread_pointer_offset: None,
                    is_ifunc: symbol.st_type() == STT_GNU_IFUNC,
                },
            });
        }
        Ok(())
    }

    pub fn assign_thread_pointer_offset(
        &mut self,
        module_id: u64,
        module_base_offset: i64,
    ) -> Result<(), LoaderError> {
        let mut found = false;
        for definition in &mut self.definitions {
            if definition.value.module_id == module_id {
                let Some(raw_symbol_offset) = definition.value.module_tls_offset else {
                    continue;
                };
                let symbol_offset =
                    i64::try_from(raw_symbol_offset).map_err(|_| LoaderError::BadTls)?;
                definition.value.thread_pointer_offset = Some(
                    module_base_offset
                        .checked_add(symbol_offset)
                        .ok_or(LoaderError::BadTls)?,
                );
                found = true;
            }
        }
        if found {
            Ok(())
        } else {
            Err(LoaderError::BadTls)
        }
    }
}

impl SymbolResolver for SymbolTable {
    fn resolve(&self, name: &str) -> Option<ResolvedSymbol> {
        self.definitions
            .iter()
            .find(|definition| definition.name == name)
            .map(|definition| definition.value)
    }

    fn resolve_copy(&self, name: &str, referring_module: u64) -> Option<ResolvedSymbol> {
        self.definitions
            .iter()
            .find(|definition| {
                definition.name == name && definition.value.module_id != referring_module
            })
            .map(|definition| definition.value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelocationContext {
    /// 当前重定位对象的模块标识。
    ///
    /// Module identifier of the object being relocated.
    pub module_id: u64,
    /// 当前对象静态 TLS 块相对线程指针的偏移。
    ///
    /// Static TLS-block offset of the current object relative to the thread pointer.
    pub static_tls_offset: Option<i64>,
}

/// 已验证的连续内存写回。
///
/// A fully validated contiguous memory writeback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryPatch {
    /// 补丁目标运行地址。/ Runtime address targeted by the patch.
    pub address: u64,
    /// 已校验的小端字节序列。/ Validated little-endian patch bytes.
    pub bytes: Vec<u8>,
}

/// 重定位后准备调用的初始化/终结入口。
///
/// Initialization and finalization entries read after relocation and before RELRO protection.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LifecycleCallbacks {
    /// DT_INIT 入口。/ DT_INIT entry.
    pub init: Option<u64>,
    /// DT_FINI 入口。/ DT_FINI entry.
    pub fini: Option<u64>,
    /// 重定位后的 DT_INIT_ARRAY 入口。
    ///
    /// Relocated DT_INIT_ARRAY entries.
    pub init_array: Vec<u64>,
    /// 重定位后的 DT_FINI_ARRAY 入口。
    ///
    /// Relocated DT_FINI_ARRAY entries.
    pub fini_array: Vec<u64>,
}

impl LifecycleCallbacks {
    /// 返回单个对象的 ELF 初始化调用顺序：DT_INIT，随后按正向遍历 DT_INIT_ARRAY。
    ///
    /// Returns the per-object ELF initialization order: DT_INIT followed by DT_INIT_ARRAY
    /// in forward order.
    pub fn initializers(&self) -> Vec<u64> {
        self.init
            .into_iter()
            .chain(self.init_array.iter().copied())
            .collect()
    }

    /// 返回单个对象的 ELF 终结调用顺序：反向遍历 DT_FINI_ARRAY，随后 DT_FINI。
    ///
    /// Returns the per-object ELF finalization order: DT_FINI_ARRAY in reverse, then DT_FINI.
    pub fn finalizers(&self) -> Vec<u64> {
        self.fini_array
            .iter()
            .rev()
            .copied()
            .chain(self.fini)
            .collect()
    }
}

/// 跨依赖图的初始化与终结顺序。
///
/// Initialization and finalization module order across a dependency graph. Values are
/// caller-defined module indices.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LifecycleOrder {
    /// 依赖优先的初始化模块索引。
    ///
    /// Module indices ordered so dependencies initialize first.
    pub initializers: Vec<usize>,
    /// 依赖后终结的模块索引。
    ///
    /// Module indices ordered so dependencies finalize last.
    pub finalizers: Vec<usize>,
}

/// 按“依赖先初始化、依赖后终结”生成稳定拓扑顺序。
///
/// Produces a stable topological order where dependencies initialize first and finalize last.
/// `requires[module]` lists the modules required by `module`; cycles and out-of-range edges fail.
pub fn plan_lifecycle_order(requires: &[Vec<usize>]) -> Result<LifecycleOrder, LoaderError> {
    if requires.len() > MAX_LIFECYCLE_MODULES {
        return Err(LoaderError::ImageTooLarge);
    }
    let mut dependents = vec![Vec::new(); requires.len()];
    let mut indegree = vec![0usize; requires.len()];
    for (module, dependencies) in requires.iter().enumerate() {
        for &dependency in dependencies {
            if dependency >= requires.len() {
                return Err(LoaderError::DependencyOutOfBounds);
            }
            dependents[dependency].push(module);
            indegree[module] = indegree[module]
                .checked_add(1)
                .ok_or(LoaderError::ImageTooLarge)?;
        }
    }
    let mut ready = VecDeque::new();
    for (module, degree) in indegree.iter().copied().enumerate() {
        if degree == 0 {
            ready.push_back(module);
        }
    }
    let mut initializers = Vec::with_capacity(requires.len());
    while let Some(module) = ready.pop_front() {
        initializers.push(module);
        for dependent in &dependents[module] {
            indegree[*dependent] -= 1;
            if indegree[*dependent] == 0 {
                ready.push_back(*dependent);
            }
        }
    }
    if initializers.len() != requires.len() {
        return Err(LoaderError::CyclicDependencies);
    }
    let finalizers = initializers.iter().rev().copied().collect();
    Ok(LifecycleOrder {
        initializers,
        finalizers,
    })
}

/// 解析并验证全部重定位，返回在任何写入发生前已完成的补丁集合。
///
/// Resolves every relocation and returns a complete patch set before any relocation write.
/// COPY sources are read from already mapped dependency images. Unknown global symbols and
/// unsupported descriptor/IFUNC forms fail closed.
pub fn prepare_relocations<M: LoaderMemory, R: SymbolResolver>(
    memory: &mut M,
    plan: &LoadPlan,
    layout: &ImageLayout,
    context: RelocationContext,
    resolver: &R,
) -> Result<Vec<MemoryPatch>, LoaderError> {
    validate_layout(layout, None)?;
    if context.module_id == 0 {
        return Err(LoaderError::BadRelocation);
    }
    let mut patches = Vec::new();
    for relocation in &plan.relocations {
        if relocation.kind == RelocationKind::None {
            continue;
        }
        let target = relocation
            .offset
            .checked_add(layout.load_bias)
            .ok_or(LoaderError::BadRelocation)?;
        let target_bytes = relocation_target_bytes(relocation);
        if target_bytes == 0
            || target_bytes > MAX_COPY_BYTES
            || !writable_range(layout, target, target_bytes)
        {
            return Err(LoaderError::BadRelocation);
        }
        match relocation.kind {
            RelocationKind::None => unreachable!(),
            RelocationKind::Copy => {
                let symbol = resolve_copy_required(relocation, context.module_id, resolver)?;
                if symbol.is_ifunc {
                    return Err(LoaderError::IfuncUnsupported);
                }
                let mut bytes = alloc::vec![0u8; target_bytes as usize];
                memory.read(symbol.address, &mut bytes)?;
                patches.push(MemoryPatch {
                    address: target,
                    bytes,
                });
            }
            RelocationKind::TlsDesc | RelocationKind::IRelative => {
                return Err(LoaderError::UnsupportedRelocation(match relocation.kind {
                    RelocationKind::TlsDesc => 36,
                    RelocationKind::IRelative => 37,
                    _ => unreachable!(),
                }));
            }
            kind => {
                let value = relocation_value(
                    relocation,
                    kind,
                    layout.load_bias,
                    target,
                    context,
                    resolver,
                )?;
                patches.push(MemoryPatch {
                    address: target,
                    bytes: encode_relocation_value(kind, value)?,
                });
            }
        }
    }
    Ok(patches)
}

/// 在一次顺序写回中应用全部已准备补丁。
///
/// Applies every prepared patch. Each backend write must be failure-atomic; preparation has
/// already validated every target and resolved every symbol.
pub fn apply_relocation_patches<M: LoaderMemory>(
    memory: &mut M,
    layout: &ImageLayout,
    patches: &[MemoryPatch],
) -> Result<(), LoaderError> {
    validate_layout(layout, None)?;
    for patch in patches {
        if patch.bytes.is_empty()
            || !writable_range(layout, patch.address, patch.bytes.len() as u64)
        {
            return Err(LoaderError::BadRelocation);
        }
    }
    with_transaction(memory, |memory| {
        for patch in patches {
            memory.write(patch.address, &patch.bytes)?;
        }
        Ok(())
    })
}

/// 在 RELRO 保护前读取已重定位的初始化与终结函数指针。
///
/// Reads relocated lifecycle function pointers before RELRO protection and rejects entries
/// outside the image's executable segments.
pub fn read_lifecycle_callbacks<M: LoaderMemory>(
    memory: &mut M,
    layout: &ImageLayout,
) -> Result<LifecycleCallbacks, LoaderError> {
    validate_layout(layout, None)?;
    let mut callbacks = LifecycleCallbacks {
        init: layout.lifecycle.init,
        fini: layout.lifecycle.fini,
        ..LifecycleCallbacks::default()
    };
    if let Some(range) = layout.lifecycle.init_array {
        callbacks.init_array = read_pointer_array(memory, layout, range)?;
    }
    if let Some(range) = layout.lifecycle.fini_array {
        callbacks.fini_array = read_pointer_array(memory, layout, range)?;
    }
    for entry in callbacks
        .init
        .into_iter()
        .chain(callbacks.fini)
        .chain(callbacks.init_array.iter().copied())
        .chain(callbacks.fini_array.iter().copied())
    {
        if !executable_range(layout, entry, 1) {
            return Err(LoaderError::BadLifecycle);
        }
    }
    Ok(callbacks)
}

fn relocation_value<R: SymbolResolver>(
    relocation: &Relocation,
    kind: RelocationKind,
    load_bias: u64,
    target: u64,
    context: RelocationContext,
    resolver: &R,
) -> Result<i128, LoaderError> {
    let addend = i128::from(relocation.addend);
    let base = match kind {
        RelocationKind::Relative => i128::from(load_bias),
        RelocationKind::TlsModule => i128::from(context.module_id),
        RelocationKind::TpOffset if relocation.symbol.is_none() => {
            i128::from(context.static_tls_offset.ok_or(LoaderError::BadTls)?)
        }
        RelocationKind::DtpOffset if relocation.symbol.is_none() => {
            i128::from(relocation.symbol_value)
        }
        RelocationKind::GlobDat
        | RelocationKind::JumpSlot
        | RelocationKind::Absolute
        | RelocationKind::PcRelative
        | RelocationKind::DtpOffset
        | RelocationKind::TpOffset => {
            let symbol = resolve_required(relocation, resolver)?;
            if symbol.is_ifunc {
                return Err(LoaderError::IfuncUnsupported);
            }
            match kind {
                RelocationKind::DtpOffset => {
                    i128::from(symbol.module_tls_offset.ok_or(LoaderError::BadTls)?)
                }
                RelocationKind::TpOffset => {
                    i128::from(symbol.thread_pointer_offset.ok_or(LoaderError::BadTls)?)
                }
                _ => i128::from(symbol.address),
            }
        }
        RelocationKind::None | RelocationKind::Copy => return Err(LoaderError::BadRelocation),
        RelocationKind::TlsDesc | RelocationKind::IRelative => {
            return Err(LoaderError::UnsupportedRelocation(0))
        }
    };
    let value = if kind == RelocationKind::PcRelative {
        base + addend - i128::from(target)
    } else {
        base + addend
    };
    Ok(value)
}

fn relocation_target_bytes(relocation: &Relocation) -> u64 {
    match relocation.kind {
        RelocationKind::PcRelative => size_of::<i32>() as u64,
        RelocationKind::Copy => relocation.symbol_size,
        RelocationKind::TlsDesc => 2 * size_of::<u64>() as u64,
        _ => size_of::<u64>() as u64,
    }
}

fn encode_relocation_value(kind: RelocationKind, value: i128) -> Result<Vec<u8>, LoaderError> {
    if kind == RelocationKind::PcRelative {
        let value = i32::try_from(value).map_err(|_| LoaderError::BadRelocation)?;
        return Ok(value.to_le_bytes().to_vec());
    }
    let value = i64::try_from(value).map_err(|_| LoaderError::BadRelocation)?;
    Ok(value.to_le_bytes().to_vec())
}

fn resolve_required<R: SymbolResolver>(
    relocation: &Relocation,
    resolver: &R,
) -> Result<ResolvedSymbol, LoaderError> {
    let Some(name) = relocation.symbol.as_deref() else {
        return Err(LoaderError::BadRelocation);
    };
    if let Some(symbol) = resolver.resolve(name) {
        return Ok(symbol);
    }
    if !relocation.symbol_defined && relocation.symbol_binding == Some(SymbolBinding::Weak) {
        return Ok(ResolvedSymbol {
            address: 0,
            size: 0,
            module_id: 0,
            module_tls_offset: None,
            thread_pointer_offset: None,
            is_ifunc: false,
        });
    }
    Err(LoaderError::UnresolvedSymbol)
}

fn resolve_copy_required<R: SymbolResolver>(
    relocation: &Relocation,
    referring_module: u64,
    resolver: &R,
) -> Result<ResolvedSymbol, LoaderError> {
    let Some(name) = relocation.symbol.as_deref() else {
        return Err(LoaderError::BadRelocation);
    };
    if let Some(symbol) = resolver.resolve_copy(name, referring_module) {
        if symbol.module_id != referring_module {
            return Ok(symbol);
        }
    }
    Err(LoaderError::UnresolvedSymbol)
}

fn read_pointer_array<M: LoaderMemory>(
    memory: &mut M,
    layout: &ImageLayout,
    range: RuntimeRange,
) -> Result<Vec<u64>, LoaderError> {
    if !range.bytes.is_multiple_of(size_of::<u64>() as u64)
        || range.bytes > MAX_LIFECYCLE_BYTES as u64
        || !layout.contains(range.address, range.bytes)
    {
        return Err(LoaderError::BadLifecycle);
    }
    let mut bytes = alloc::vec![0u8; range.bytes as usize];
    memory.read(range.address, &mut bytes)?;
    let mut entries = Vec::with_capacity(bytes.len() / size_of::<u64>());
    for chunk in bytes.as_chunks::<8>().0 {
        let address = u64::from_le_bytes(*chunk);
        if address != 0 {
            entries.push(address);
        }
    }
    Ok(entries)
}

fn writable_range(layout: &ImageLayout, address: u64, bytes: u64) -> bool {
    let Some(end) = address.checked_add(bytes) else {
        return false;
    };
    layout.segments.iter().any(|segment| {
        let Some(segment_end) = segment.end() else {
            return false;
        };
        segment.permissions.writable && address >= segment.load_address && end <= segment_end
    })
}

fn executable_range(layout: &ImageLayout, address: u64, bytes: u64) -> bool {
    let Some(end) = address.checked_add(bytes) else {
        return false;
    };
    address < MAX_USER_ADDRESS
        && layout.segments.iter().any(|segment| {
            let Some(segment_end) = segment.end() else {
                return false;
            };
            segment.permissions.executable && address >= segment.load_address && end <= segment_end
        })
}

const _: () = assert!(MAX_SYMBOLS > 0);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{map_image, protect_relro, MappingRequest, MemoryPermissions};
    use crate::parse;
    use alloc::vec;
    use std::collections::BTreeMap;
    use std::fs;

    #[derive(Clone, Default)]
    struct TestMemory {
        bytes: BTreeMap<u64, u8>,
        permissions: BTreeMap<u64, MemoryPermissions>,
        snapshot_bytes: Option<BTreeMap<u64, u8>>,
        snapshot_permissions: Option<BTreeMap<u64, MemoryPermissions>>,
        fail_map_address: Option<u64>,
        fail_write_address: Option<u64>,
    }

    impl TestMemory {
        fn reserve(&mut self, address: u64, bytes: u64) {
            for offset in 0..bytes {
                self.bytes.insert(address + offset, 0);
                self.permissions.insert(
                    address + offset,
                    MemoryPermissions {
                        readable: true,
                        writable: true,
                        executable: false,
                    },
                );
            }
        }

        fn read_u64(&mut self, address: u64) -> u64 {
            let mut bytes = [0u8; 8];
            self.read(address, &mut bytes).unwrap();
            u64::from_le_bytes(bytes)
        }
    }

    impl LoaderMemory for TestMemory {
        fn begin_transaction(&mut self) -> Result<(), LoaderError> {
            if self.snapshot_bytes.is_some() {
                return Err(LoaderError::BadTransaction);
            }
            self.snapshot_bytes = Some(self.bytes.clone());
            self.snapshot_permissions = Some(self.permissions.clone());
            Ok(())
        }

        fn commit_transaction(&mut self) -> Result<(), LoaderError> {
            if self.snapshot_bytes.is_none() || self.snapshot_permissions.is_none() {
                return Err(LoaderError::BadTransaction);
            }
            self.snapshot_bytes = None;
            self.snapshot_permissions = None;
            Ok(())
        }

        fn rollback_transaction(&mut self) -> Result<(), LoaderError> {
            self.bytes = self
                .snapshot_bytes
                .take()
                .ok_or(LoaderError::BadTransaction)?;
            self.permissions = self
                .snapshot_permissions
                .take()
                .ok_or(LoaderError::BadTransaction)?;
            Ok(())
        }

        fn map(&mut self, source: &[u8], request: MappingRequest<'_>) -> Result<(), LoaderError> {
            if self.fail_map_address == Some(request.address) {
                self.fail_map_address = None;
                return Err(LoaderError::MemoryMap);
            }
            self.reserve(request.address, request.memory_bytes);
            for range in request.file_ranges {
                let source_end = range
                    .source_offset
                    .checked_add(range.bytes)
                    .ok_or(LoaderError::MemoryMap)?;
                let destination_end = range
                    .destination_offset
                    .checked_add(range.bytes)
                    .ok_or(LoaderError::MemoryMap)?;
                if source_end > source.len() as u64 || destination_end > request.memory_bytes {
                    return Err(LoaderError::MemoryMap);
                }
                let start = range.source_offset as usize;
                for (offset, byte) in source[start..source_end as usize].iter().enumerate() {
                    self.bytes.insert(
                        request.address + range.destination_offset + offset as u64,
                        *byte,
                    );
                }
            }
            for offset in 0..request.memory_bytes {
                self.permissions
                    .insert(request.address + offset, request.permissions);
            }
            Ok(())
        }

        fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), LoaderError> {
            let end = address
                .checked_add(bytes.len() as u64)
                .ok_or(LoaderError::MemoryWrite)?;
            if let Some(failure) = self.fail_write_address {
                if failure >= address && failure < end {
                    self.fail_write_address = None;
                    return Err(LoaderError::MemoryWrite);
                }
            }
            if !(address..end).all(|address| {
                self.permissions
                    .get(&address)
                    .is_some_and(|permissions| permissions.writable)
            }) {
                return Err(LoaderError::MemoryWrite);
            }
            for (offset, byte) in bytes.iter().enumerate() {
                self.bytes.insert(address + offset as u64, *byte);
            }
            Ok(())
        }

        fn read(&mut self, address: u64, output: &mut [u8]) -> Result<(), LoaderError> {
            let end = address
                .checked_add(output.len() as u64)
                .ok_or(LoaderError::MemoryRead)?;
            if !(address..end).all(|address| {
                self.permissions
                    .get(&address)
                    .is_some_and(|permissions| permissions.readable)
            }) {
                return Err(LoaderError::MemoryRead);
            }
            for (offset, byte) in output.iter_mut().enumerate() {
                *byte = *self
                    .bytes
                    .get(&(address + offset as u64))
                    .ok_or(LoaderError::MemoryRead)?;
            }
            Ok(())
        }

        fn protect(
            &mut self,
            address: u64,
            bytes: u64,
            permissions: MemoryPermissions,
        ) -> Result<(), LoaderError> {
            let end = address
                .checked_add(bytes)
                .ok_or(LoaderError::MemoryProtect)?;
            if !(address..end).all(|address| self.permissions.contains_key(&address)) {
                return Err(LoaderError::MemoryProtect);
            }
            for offset in 0..bytes {
                self.permissions.insert(address + offset, permissions);
            }
            Ok(())
        }
    }

    #[test]
    fn lifecycle_graph_orders_dependencies_first_and_finalizers_last() {
        let order = plan_lifecycle_order(&[vec![1], Vec::new(), vec![1, 3], Vec::new()]).unwrap();
        assert_eq!(order.initializers, vec![1, 3, 0, 2]);
        assert_eq!(order.finalizers, vec![2, 0, 3, 1]);
        assert_eq!(
            plan_lifecycle_order(&[vec![1], vec![0]]),
            Err(LoaderError::CyclicDependencies)
        );
        assert_eq!(
            plan_lifecycle_order(&[vec![2]]),
            Err(LoaderError::DependencyOutOfBounds)
        );

        let callbacks = LifecycleCallbacks {
            init: Some(1),
            fini: Some(2),
            init_array: vec![3, 4],
            fini_array: vec![5, 6],
        };
        assert_eq!(callbacks.initializers(), vec![1, 3, 4]);
        assert_eq!(callbacks.finalizers(), vec![6, 5, 2]);
    }

    #[test]
    fn relocation_encoding_preserves_signed_widths() {
        assert_eq!(
            encode_relocation_value(RelocationKind::PcRelative, -1).unwrap(),
            [0xff; 4]
        );
        assert_eq!(
            encode_relocation_value(RelocationKind::TpOffset, -16).unwrap(),
            (-16i64).to_le_bytes()
        );
        assert_eq!(
            encode_relocation_value(RelocationKind::PcRelative, i128::from(i32::MAX) + 1),
            Err(LoaderError::BadRelocation)
        );
    }

    #[test]
    fn static_tls_offsets_include_each_symbol_offset() {
        let mut symbols = SymbolTable::new();
        symbols.definitions = vec![
            SymbolDefinition {
                name: String::from("first_tls"),
                value: ResolvedSymbol {
                    address: 8,
                    size: 8,
                    module_id: 7,
                    module_tls_offset: Some(8),
                    thread_pointer_offset: None,
                    is_ifunc: false,
                },
            },
            SymbolDefinition {
                name: String::from("second_tls"),
                value: ResolvedSymbol {
                    address: 24,
                    size: 8,
                    module_id: 7,
                    module_tls_offset: Some(24),
                    thread_pointer_offset: None,
                    is_ifunc: false,
                },
            },
        ];
        symbols.assign_thread_pointer_offset(7, -128).unwrap();
        assert_eq!(
            symbols.resolve("first_tls").unwrap().thread_pointer_offset,
            Some(-120)
        );
        assert_eq!(
            symbols.resolve("second_tls").unwrap().thread_pointer_offset,
            Some(-104)
        );
    }

    #[test]
    fn relocation_write_failure_rolls_back_the_whole_patch_set() {
        let bytes = fs::read("/bin/true").unwrap();
        let plan = parse(&bytes).unwrap();
        let layout = ImageLayout::new(&plan, 0x3000_0000_0000, 4096).unwrap();
        let writable = layout
            .segments
            .iter()
            .find(|segment| segment.permissions.writable && segment.memory_bytes >= 32)
            .unwrap();
        let first = MemoryPatch {
            address: writable.load_address,
            bytes: vec![0xa5; 8],
        };
        let second = MemoryPatch {
            address: writable.load_address + 8,
            bytes: vec![0x5a; 8],
        };
        let mut memory = TestMemory::default();
        map_image(&mut memory, &bytes, &layout).unwrap();
        let mut before = [0u8; 16];
        memory.read(writable.load_address, &mut before).unwrap();
        memory.fail_write_address = Some(second.address);
        assert_eq!(
            apply_relocation_patches(&mut memory, &layout, &[first, second]),
            Err(LoaderError::MemoryWrite)
        );
        let mut after = [0u8; 16];
        memory.read(writable.load_address, &mut after).unwrap();
        assert_eq!(after, before);
    }

    #[test]
    fn real_bin_true_relocations_use_real_libc_definitions() {
        let main_bytes = fs::read("/bin/true").expect("/bin/true fixture");
        let libc_bytes = fs::read("/lib/x86_64-linux-gnu/libc.so.6").expect("libc fixture");
        let main_plan = parse(&main_bytes).unwrap();
        let libc_plan = parse(&libc_bytes).unwrap();
        let main_layout = ImageLayout::new(&main_plan, 0x400000, 4096).unwrap();
        let libc_layout = ImageLayout::new(&libc_plan, 0x7000_0000_0000, 4096).unwrap();
        assert!(!main_layout.overlaps(&libc_layout));

        let mut memory = TestMemory::default();
        map_image(&mut memory, &main_bytes, &main_layout).unwrap();
        map_image(&mut memory, &libc_bytes, &libc_layout).unwrap();
        let mut symbols = SymbolTable::new();
        symbols.append_image(&main_bytes, &main_layout, 1).unwrap();
        symbols.append_image(&libc_bytes, &libc_layout, 2).unwrap();

        let context = RelocationContext {
            module_id: 1,
            static_tls_offset: None,
        };
        assert_eq!(
            prepare_relocations(&mut memory, &main_plan, &main_layout, context, &symbols),
            Err(LoaderError::IfuncUnsupported)
        );
        let mut supported_plan = main_plan.clone();
        supported_plan.relocations.retain(|relocation| {
            relocation
                .symbol
                .as_deref()
                .and_then(|name| symbols.resolve(name))
                .is_none_or(|symbol| !symbol.is_ifunc)
        });
        let patches = prepare_relocations(
            &mut memory,
            &supported_plan,
            &main_layout,
            context,
            &symbols,
        )
        .unwrap();
        let expected_patches = supported_plan
            .relocations
            .iter()
            .filter(|relocation| relocation.kind != RelocationKind::None)
            .count();
        assert_eq!(patches.len(), expected_patches);
        apply_relocation_patches(&mut memory, &main_layout, &patches).unwrap();

        let relative = supported_plan
            .relocations
            .iter()
            .find(|relocation| relocation.kind == RelocationKind::Relative)
            .unwrap();
        assert_eq!(
            memory.read_u64(main_layout.load_bias + relative.offset),
            (main_layout.load_bias as i64 + relative.addend) as u64
        );
        let startup = supported_plan
            .relocations
            .iter()
            .find(|relocation| {
                relocation.kind == RelocationKind::GlobDat
                    && relocation.symbol.as_deref() == Some("__libc_start_main")
            })
            .unwrap();
        assert_eq!(
            memory.read_u64(main_layout.load_bias + startup.offset),
            symbols.resolve("__libc_start_main").unwrap().address
        );

        let copy = supported_plan
            .relocations
            .iter()
            .find(|relocation| {
                relocation.kind == RelocationKind::Copy
                    && relocation.symbol.as_deref() == Some("__progname")
            })
            .unwrap();
        let source = symbols.resolve_copy("__progname", 1).unwrap();
        let mut source_bytes = vec![0u8; copy.symbol_size as usize];
        memory.read(source.address, &mut source_bytes).unwrap();
        let mut copied_bytes = vec![0u8; copy.symbol_size as usize];
        memory
            .read(main_layout.load_bias + copy.offset, &mut copied_bytes)
            .unwrap();
        assert_eq!(copied_bytes, source_bytes);

        let weak = supported_plan
            .relocations
            .iter()
            .find(|relocation| {
                relocation.symbol_binding == Some(SymbolBinding::Weak) && !relocation.symbol_defined
            })
            .unwrap();
        assert_eq!(memory.read_u64(main_layout.load_bias + weak.offset), 0);

        let lifecycle = read_lifecycle_callbacks(&mut memory, &main_layout).unwrap();
        assert_eq!(lifecycle.init_array.len(), 1);
        assert!(main_layout
            .segments
            .iter()
            .any(|segment| segment.permissions.executable
                && lifecycle.init_array[0] >= segment.load_address
                && lifecycle.init_array[0] < segment.end().unwrap()));
        protect_relro(&mut memory, &main_layout, 4096).unwrap();
    }
}
