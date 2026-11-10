//! 有界 ELF 页映射计划与可注入内存后端。
//!
//! Bounded page-mapping plans and the injected memory interface used by the compatibility
//! service. The backend owns real mapping and protection effects; this module owns address
//! selection, page construction, and BSS/TLS semantics.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use super::{LoadPlan, LoadSegment, LoaderError, VirtualRange};

const MAX_PAGE_SIZE: u64 = 64 * 1024;
const MAX_IMAGE_PAGES: usize = 262_144;
const MAX_USER_ADDRESS: u64 = 1 << 47;

/// 一页的最终访问权限。
///
/// Final access permissions for one mapped page.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemoryPermissions {
    /// 允许读取。/ Read access is permitted.
    pub readable: bool,
    /// 允许写入。/ Write access is permitted.
    pub writable: bool,
    /// 允许取指令。/ Instruction fetch is permitted.
    pub executable: bool,
}

impl MemoryPermissions {
    fn union(self, other: Self) -> Self {
        Self {
            readable: self.readable || other.readable,
            writable: self.writable || other.writable,
            executable: self.executable || other.executable,
        }
    }

    fn from_segment(segment: &LoadSegment) -> Self {
        Self {
            readable: segment.readable,
            writable: segment.writable,
            executable: segment.executable,
        }
    }
}

/// 单个 PT_LOAD 在运行地址空间中的位置。
///
/// Runtime placement of one PT_LOAD segment after load-bias selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MappedSegment {
    /// 原 ELF 文件偏移。/ Original ELF file offset.
    pub file_offset: u64,
    /// 重定位后的段首地址。/ Segment start after load-bias relocation.
    pub load_address: u64,
    /// 文件支持的字节数。/ Number of file-backed bytes.
    pub file_bytes: u64,
    /// 包含 BSS 的段总字节数。/ Total segment bytes, including BSS.
    pub memory_bytes: u64,
    /// ELF 声明的段对齐。/ Segment alignment declared by ELF.
    pub align: u64,
    /// 该段的访问权限。/ Access permissions for this segment.
    pub permissions: MemoryPermissions,
}

impl MappedSegment {
    pub fn end(&self) -> Option<u64> {
        self.load_address.checked_add(self.memory_bytes)
    }
}

/// 页内一段由 ELF 文件初始化的连续字节。
///
/// One contiguous file-initialized range inside a mapped page. `destination_offset` is the
/// page offset that receives `bytes` from `source_offset` in the ELF file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MappedFileRange {
    /// 页内目标偏移。/ Destination offset inside the page.
    pub destination_offset: u64,
    /// ELF 文件源偏移。/ Source offset in the ELF file.
    pub source_offset: u64,
    /// 复制字节数。/ Number of bytes to copy.
    pub bytes: u64,
}

/// 一个页映射计划。
///
/// One page-mapping plan. File-backed ranges can be discontiguous in the file while remaining
/// correctly placed inside the page. All bytes not covered by a file range are zero-filled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MappedPage {
    /// 页对齐的运行地址。/ Page-aligned runtime address.
    pub address: u64,
    /// 页内文件区间，按页内目标偏移排序且互不重叠。
    ///
    /// File-backed ranges sorted by destination offset and non-overlapping.
    pub file_ranges: Vec<MappedFileRange>,
    /// 本页映射的字节数；末页可小于页大小。
    ///
    /// Number of bytes mapped in this page; the final page may be partial.
    pub memory_bytes: u64,
    /// 合并重叠 PT_LOAD 后的最终权限。
    ///
    /// Final permissions after merging overlapping PT_LOAD contributions.
    pub permissions: MemoryPermissions,
}

/// 传给内存后端的只读页映射描述。
///
/// Immutable page-mapping description passed to a `LoaderMemory` implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MappingRequest<'a> {
    /// 页对齐的运行地址。/ Page-aligned runtime address.
    pub address: u64,
    /// 页内文件初始化区间。/ File-initialized ranges inside the page.
    pub file_ranges: &'a [MappedFileRange],
    /// 要建立映射的页内字节数。/ Number of bytes to map in this page.
    pub memory_bytes: u64,
    /// 映射后的访问权限。/ Access permissions after mapping.
    pub permissions: MemoryPermissions,
}

/// 运行地址空间中的范围。
///
/// A range expressed in the final runtime address space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeRange {
    /// 运行地址。/ Runtime address.
    pub address: u64,
    /// 范围字节数。/ Number of bytes in the range.
    pub bytes: u64,
}

impl RuntimeRange {
    pub fn end(&self) -> Option<u64> {
        self.address.checked_add(self.bytes)
    }
}

/// PT_TLS 映像在已装载对象中的运行位置。
///
/// Runtime location of a PT_TLS template inside the loaded object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsImage {
    /// PT_TLS 模板的运行地址。/ Runtime address of the PT_TLS template.
    pub address: u64,
    /// 文件初始化字节数。/ Number of file-initialized bytes.
    pub file_bytes: u64,
    /// TLS 块总字节数。/ Total TLS-block bytes.
    pub memory_bytes: u64,
    /// TLS 块首地址对齐。/ Required TLS-block start alignment.
    pub align: u64,
}

/// DT_INIT、DT_FINI 及初始化数组的运行位置。
///
/// Runtime locations of DT_INIT, DT_FINI, and their pointer arrays.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RuntimeLifecycle {
    /// DT_INIT 的运行地址。/ Runtime address of DT_INIT.
    pub init: Option<u64>,
    /// DT_FINI 的运行地址。/ Runtime address of DT_FINI.
    pub fini: Option<u64>,
    /// DT_INIT_ARRAY 的运行范围。/ Runtime range of DT_INIT_ARRAY.
    pub init_array: Option<RuntimeRange>,
    /// DT_FINI_ARRAY 的运行范围。/ Runtime range of DT_FINI_ARRAY.
    pub fini_array: Option<RuntimeRange>,
}

/// 已完成地址选择、页构造和范围校验的 ELF 映像。
///
/// A fully validated ELF image with selected addresses, unique pages, RELRO and lifecycle
/// ranges. Constructing a layout has no external side effects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageLayout {
    /// 加到 ELF 虚拟地址上的 load bias。
    ///
    /// Load bias added to pre-relocation ELF virtual addresses.
    pub load_bias: u64,
    /// 映像第一页地址。/ First mapped page address.
    pub image_start: u64,
    /// 映像末页后的地址。/ Address immediately after the last mapped page.
    pub image_end: u64,
    /// 构造本布局使用的页大小。/ Page size used to construct this layout.
    pub page_size: u64,
    /// 重定位后的入口地址。/ Entry address after relocation.
    pub entry: u64,
    /// PT_LOAD 运行布局。/ Runtime PT_LOAD layout.
    pub segments: Vec<MappedSegment>,
    /// 唯一且排序的页映射计划。/ Unique, sorted page-mapping plan.
    pub pages: Vec<MappedPage>,
    /// PT_TLS 模板运行位置。/ Runtime PT_TLS template location.
    pub tls: Option<TlsImage>,
    /// PT_GNU_RELRO 运行范围。/ Runtime PT_GNU_RELRO range.
    pub relro: Option<RuntimeRange>,
    /// 初始化与终结入口运行位置。
    ///
    /// Runtime lifecycle entry locations.
    pub lifecycle: RuntimeLifecycle,
}

impl ImageLayout {
    /// 按给定 load bias 构造映像；ET_EXEC 必须使用零 bias。
    ///
    /// Builds an image at the supplied load bias. ET_EXEC images must use a zero bias.
    pub fn new(plan: &LoadPlan, load_bias: u64, page_size: u64) -> Result<Self, LoaderError> {
        validate_page_size(page_size)?;
        let required_alignment = required_load_alignment(plan, page_size)?;
        if !load_bias.is_multiple_of(required_alignment) {
            return Err(LoaderError::BadLoadBias);
        }
        if !plan.position_independent && load_bias != 0 {
            return Err(LoaderError::BadLoadBias);
        }
        let first = plan.segments.first().ok_or(LoaderError::BadSegment)?;
        let mut image_address = first.virtual_address;
        let mut image_limit = first
            .virtual_address
            .checked_add(first.memory_bytes)
            .ok_or(LoaderError::BadSegment)?;
        let mut segments = Vec::with_capacity(plan.segments.len());
        for segment in &plan.segments {
            let load_address = segment
                .virtual_address
                .checked_add(load_bias)
                .ok_or(LoaderError::BadLoadBias)?;
            let segment_end = load_address
                .checked_add(segment.memory_bytes)
                .ok_or(LoaderError::BadLoadBias)?;
            if segment_end > MAX_USER_ADDRESS {
                return Err(LoaderError::BadLoadBias);
            }
            image_address = image_address.min(segment.virtual_address);
            image_limit = image_limit.max(
                segment
                    .virtual_address
                    .checked_add(segment.memory_bytes)
                    .ok_or(LoaderError::BadSegment)?,
            );
            segments.push(MappedSegment {
                file_offset: segment.file_offset,
                load_address,
                file_bytes: segment.file_bytes,
                memory_bytes: segment.memory_bytes,
                align: segment.align,
                permissions: MemoryPermissions::from_segment(segment),
            });
        }
        image_address = image_address
            .checked_add(load_bias)
            .ok_or(LoaderError::BadLoadBias)?;
        image_limit = image_limit
            .checked_add(load_bias)
            .ok_or(LoaderError::BadLoadBias)?;
        let image_start = align_down(image_address, page_size);
        let image_end = align_up(image_limit, page_size).ok_or(LoaderError::ImageTooLarge)?;
        if image_end > MAX_USER_ADDRESS {
            return Err(LoaderError::ImageTooLarge);
        }

        let pages = build_pages(&segments, page_size)?;
        let entry = plan
            .entry
            .checked_add(load_bias)
            .ok_or(LoaderError::BadLoadBias)?;
        let tls = plan.tls.map(|tls| TlsImage {
            address: tls.virtual_address + load_bias,
            file_bytes: tls.file_bytes,
            memory_bytes: tls.memory_bytes,
            align: tls.align,
        });
        let relro = plan.relro.map(|range| RuntimeRange {
            address: range.address + load_bias,
            bytes: range.bytes,
        });
        let lifecycle = RuntimeLifecycle {
            init: plan.lifecycle.init.map(|value| value + load_bias),
            fini: plan.lifecycle.fini.map(|value| value + load_bias),
            init_array: plan
                .lifecycle
                .init_array
                .map(|range| relocate_range(range, load_bias)),
            fini_array: plan
                .lifecycle
                .fini_array
                .map(|range| relocate_range(range, load_bias)),
        };
        Ok(Self {
            load_bias,
            image_start,
            image_end,
            page_size,
            entry,
            segments,
            pages,
            tls,
            relro,
            lifecycle,
        })
    }

    pub fn contains(&self, address: u64, bytes: u64) -> bool {
        address
            .checked_add(bytes)
            .is_some_and(|end| address >= self.image_start && end <= self.image_end)
    }

    pub fn overlaps(&self, other: &Self) -> bool {
        self.image_start < other.image_end && other.image_start < self.image_end
    }
}

/// 选择满足页大小和全部 PT_LOAD 对齐要求且不回绕的 ET_DYN load bias。
///
/// Selects an ET_DYN load bias satisfying the page size and every PT_LOAD alignment. A fixed
/// ET_EXEC image returns zero.
pub fn select_load_bias(
    plan: &LoadPlan,
    requested_base: u64,
    page_size: u64,
) -> Result<u64, LoaderError> {
    validate_page_size(page_size)?;
    if !plan.position_independent {
        return if requested_base == 0 {
            Ok(0)
        } else {
            Err(LoaderError::BadLoadBias)
        };
    }
    if requested_base == 0 {
        return Err(LoaderError::BadLoadBias);
    }
    let alignment = required_load_alignment(plan, page_size)?;
    let bias = align_up(requested_base, alignment).ok_or(LoaderError::BadLoadBias)?;
    if bias == 0 || bias >= MAX_USER_ADDRESS {
        return Err(LoaderError::BadLoadBias);
    }
    Ok(bias)
}

/// 内存后端接口。
///
/// The memory interface required by the loader. Every implementation must make each individual
/// mutation failure-atomic and implement the transaction calls over all mutations until commit
/// or rollback. The loader directly uses these transactions for multi-page mappings and
/// relocation writeback.
pub trait LoaderMemory {
    /// 开启覆盖后续映射、写入和权限修改的事务。
    ///
    /// Starts a transaction covering subsequent mapping, writes, and protection changes.
    fn begin_transaction(&mut self) -> Result<(), LoaderError>;

    /// 原子提交当前事务。/ Atomically commits the current transaction.
    fn commit_transaction(&mut self) -> Result<(), LoaderError>;

    /// 回滚当前事务并恢复开始前的状态。
    ///
    /// Rolls back the current transaction and restores the state at its start.
    fn rollback_transaction(&mut self) -> Result<(), LoaderError>;

    /// 映射一页并复制文件前缀，其余部分清零。
    ///
    /// Maps one page, copies all file-backed ranges to their page destinations, and zero-fills
    /// every remaining byte.
    fn map(&mut self, source: &[u8], request: MappingRequest<'_>) -> Result<(), LoaderError>;

    /// 写入已经过范围校验的字节。
    ///
    /// Writes a byte range that the loader has already validated.
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), LoaderError>;

    /// 读取已经过范围校验的字节。
    ///
    /// Reads a byte range that the loader has already validated.
    fn read(&mut self, address: u64, output: &mut [u8]) -> Result<(), LoaderError>;

    /// 修改已经映射范围的最终权限。
    ///
    /// Changes the final permissions of an already mapped range.
    fn protect(
        &mut self,
        address: u64,
        bytes: u64,
        permissions: MemoryPermissions,
    ) -> Result<(), LoaderError>;
}

pub(crate) fn with_transaction<M: LoaderMemory, T>(
    memory: &mut M,
    operation: impl FnOnce(&mut M) -> Result<T, LoaderError>,
) -> Result<T, LoaderError> {
    memory.begin_transaction()?;
    match operation(memory) {
        Ok(value) => match memory.commit_transaction() {
            Ok(()) => Ok(value),
            Err(error) => match memory.rollback_transaction() {
                Ok(()) => Err(error),
                Err(_) => Err(LoaderError::TransactionRollbackFailed),
            },
        },
        Err(error) => match memory.rollback_transaction() {
            Ok(()) => Err(error),
            Err(_) => Err(LoaderError::TransactionRollbackFailed),
        },
    }
}

/// 将 ELF 文件页和 BSS 写入内存后端。
///
/// Revalidates the complete layout and source bounds before entering one backend transaction.
/// A later mapping failure rolls back every page mapped by this call.
pub fn map_image<M: LoaderMemory>(
    memory: &mut M,
    source: &[u8],
    layout: &ImageLayout,
) -> Result<(), LoaderError> {
    validate_layout(layout, Some(source.len() as u64))?;
    with_transaction(memory, |memory| {
        for page in &layout.pages {
            memory.map(
                source,
                MappingRequest {
                    address: page.address,
                    file_ranges: &page.file_ranges,
                    memory_bytes: page.memory_bytes,
                    permissions: page.permissions,
                },
            )?;
        }
        Ok(())
    })
}

/// 在重定位完成后将 PT_GNU_RELRO 页改为只读。
///
/// Makes the page-aligned PT_GNU_RELRO range read-only after relocations have been applied.
pub fn protect_relro<M: LoaderMemory>(
    memory: &mut M,
    layout: &ImageLayout,
    page_size: u64,
) -> Result<(), LoaderError> {
    validate_page_size(page_size)?;
    if page_size != layout.page_size {
        return Err(LoaderError::BadPageSize);
    }
    validate_layout(layout, None)?;
    let Some(relro) = layout.relro else {
        return Ok(());
    };
    if !layout.contains(relro.address, relro.bytes) {
        return Err(LoaderError::BadSegment);
    }
    let start = align_down(relro.address, page_size);
    let end = align_up(relro.end().ok_or(LoaderError::BadSegment)?, page_size)
        .ok_or(LoaderError::ImageTooLarge)?;
    with_transaction(memory, |memory| {
        memory.protect(
            start,
            end - start,
            MemoryPermissions {
                readable: true,
                writable: false,
                executable: false,
            },
        )
    })
}

/// 从已映射 PT_TLS 模板初始化一个线程的静态 TLS 块。
///
/// Copies the PT_TLS initialized prefix from the loaded image into a caller-provided TLS block
/// and zero-fills the BSS tail. Allocation and thread-pointer placement remain the runtime's
/// responsibility.
pub fn initialize_tls_block<M: LoaderMemory>(
    memory: &mut M,
    layout: &ImageLayout,
    target: u64,
) -> Result<(), LoaderError> {
    let Some(tls) = layout.tls else {
        return Ok(());
    };
    validate_layout(layout, None)?;
    if tls.file_bytes > tls.memory_bytes {
        return Err(LoaderError::BadTls);
    }
    let target_end = target
        .checked_add(tls.memory_bytes)
        .ok_or(LoaderError::BadTls)?;
    if target_end > MAX_USER_ADDRESS
        || (target < layout.image_end && layout.image_start < target_end)
    {
        return Err(LoaderError::BadTls);
    }
    let file_bytes = usize::try_from(tls.file_bytes).map_err(|_| LoaderError::BadTls)?;
    with_transaction(memory, |memory| {
        let mut initialized = vec![0u8; file_bytes];
        memory.read(tls.address, &mut initialized)?;
        if !initialized.is_empty() {
            memory.write(target, &initialized)?;
        }
        let mut zeroed = 0u64;
        let zero = [0u8; 4096];
        while zeroed < tls.memory_bytes - tls.file_bytes {
            let remaining = tls.memory_bytes - tls.file_bytes - zeroed;
            let chunk = remaining.min(zero.len() as u64) as usize;
            memory.write(target + tls.file_bytes + zeroed, &zero[..chunk])?;
            zeroed += chunk as u64;
        }
        Ok(())
    })
}

fn build_pages(segments: &[MappedSegment], page_size: u64) -> Result<Vec<MappedPage>, LoaderError> {
    let mut pages = BTreeMap::<u64, MappedPage>::new();
    for segment in segments {
        let segment_end = segment.end().ok_or(LoaderError::BadSegment)?;
        if segment.memory_bytes == 0 {
            continue;
        }
        let first_page = align_down(segment.load_address, page_size);
        let last_page = align_up(segment_end, page_size).ok_or(LoaderError::ImageTooLarge)?;
        let mut page_address = first_page;
        while page_address < last_page {
            if !pages.contains_key(&page_address) && pages.len() == MAX_IMAGE_PAGES {
                return Err(LoaderError::ImageTooLarge);
            }
            let page_end = page_address
                .checked_add(page_size)
                .ok_or(LoaderError::ImageTooLarge)?;
            let memory_end = page_end.min(segment_end);
            let file_start = page_address.max(segment.load_address);
            let file_end = page_end.min(
                segment
                    .load_address
                    .checked_add(segment.file_bytes)
                    .ok_or(LoaderError::BadSegment)?,
            );
            let file_range = if file_start < file_end {
                Some(MappedFileRange {
                    destination_offset: file_start - page_address,
                    source_offset: segment.file_offset + (file_start - segment.load_address),
                    bytes: file_end - file_start,
                })
            } else {
                None
            };
            let page = pages.entry(page_address).or_insert(MappedPage {
                address: page_address,
                file_ranges: Vec::new(),
                memory_bytes: 0,
                permissions: MemoryPermissions::default(),
            });
            page.memory_bytes = page.memory_bytes.max(memory_end - page_address);
            page.permissions = page.permissions.union(segment.permissions);
            if page.permissions.writable && page.permissions.executable {
                return Err(LoaderError::BadSegment);
            }
            if let Some(file_range) = file_range {
                page.file_ranges.push(file_range);
            }
            page_address = page_end;
        }
    }
    let mut pages = pages.into_values().collect::<Vec<_>>();
    for page in &mut pages {
        page.file_ranges
            .sort_unstable_by_key(|range| range.destination_offset);
        for pair in page.file_ranges.windows(2) {
            let end = pair[0]
                .destination_offset
                .checked_add(pair[0].bytes)
                .ok_or(LoaderError::BadSegment)?;
            if end > pair[1].destination_offset {
                return Err(LoaderError::BadSegment);
            }
        }
    }
    Ok(pages)
}

fn relocate_range(range: VirtualRange, load_bias: u64) -> RuntimeRange {
    RuntimeRange {
        address: range.address + load_bias,
        bytes: range.bytes,
    }
}

fn validate_page_size(page_size: u64) -> Result<(), LoaderError> {
    if page_size == 0 || !page_size.is_power_of_two() || page_size > MAX_PAGE_SIZE {
        return Err(LoaderError::BadPageSize);
    }
    Ok(())
}

fn required_load_alignment(plan: &LoadPlan, page_size: u64) -> Result<u64, LoaderError> {
    validate_page_size(page_size)?;
    let mut alignment = plan.max_align.max(page_size).max(1);
    for segment in &plan.segments {
        alignment = alignment.max(segment.align.max(1));
    }
    if !alignment.is_power_of_two() {
        return Err(LoaderError::BadAlignment);
    }
    Ok(alignment)
}

pub(crate) fn validate_layout(
    layout: &ImageLayout,
    source_len: Option<u64>,
) -> Result<(), LoaderError> {
    validate_page_size(layout.page_size)?;
    if layout.pages.is_empty()
        || !layout.image_start.is_multiple_of(layout.page_size)
        || layout.image_end <= layout.image_start
        || layout.image_end > MAX_USER_ADDRESS
        || layout.image_end - layout.image_start > MAX_IMAGE_PAGES as u64 * layout.page_size
    {
        return Err(LoaderError::BadSegment);
    }
    let mut previous_end = layout.image_start;
    for page in &layout.pages {
        if page.address % layout.page_size != 0
            || page.address < previous_end
            || page.address < layout.image_start
            || page.memory_bytes == 0
            || page.memory_bytes > layout.page_size
        {
            return Err(LoaderError::BadSegment);
        }
        let page_end = page
            .address
            .checked_add(page.memory_bytes)
            .ok_or(LoaderError::BadSegment)?;
        if page_end > layout.image_end || (page.permissions.writable && page.permissions.executable)
        {
            return Err(LoaderError::BadSegment);
        }
        let mut previous_range_end = 0u64;
        for range in &page.file_ranges {
            if range.bytes == 0 || range.destination_offset < previous_range_end {
                return Err(LoaderError::BadSegment);
            }
            let destination_end = range
                .destination_offset
                .checked_add(range.bytes)
                .ok_or(LoaderError::BadSegment)?;
            let source_end = range
                .source_offset
                .checked_add(range.bytes)
                .ok_or(LoaderError::SourceOutOfBounds)?;
            if destination_end > page.memory_bytes
                || source_len.is_some_and(|length| source_end > length)
            {
                return Err(LoaderError::SourceOutOfBounds);
            }
            previous_range_end = destination_end;
        }
        previous_end = page_end;
    }
    Ok(())
}

fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}

fn align_up(value: u64, align: u64) -> Option<u64> {
    value
        .checked_add(align - 1)
        .map(|value| align_down(value, align))
}

const _: () = assert!(MAX_IMAGE_PAGES > 0);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse;
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
            if !self.permissions_in_range(address, bytes.len() as u64, |permissions| {
                permissions.writable
            }) {
                return Err(LoaderError::MemoryWrite);
            }
            for (offset, byte) in bytes.iter().enumerate() {
                self.bytes.insert(address + offset as u64, *byte);
            }
            Ok(())
        }

        fn read(&mut self, address: u64, output: &mut [u8]) -> Result<(), LoaderError> {
            if !self.permissions_in_range(address, output.len() as u64, |permissions| {
                permissions.readable
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
            if !self.permissions_in_range(address, bytes, |_| true) {
                return Err(LoaderError::MemoryProtect);
            }
            for offset in 0..bytes {
                self.permissions.insert(address + offset, permissions);
            }
            Ok(())
        }
    }

    impl TestMemory {
        fn permissions_in_range(
            &self,
            address: u64,
            bytes: u64,
            predicate: impl Fn(MemoryPermissions) -> bool,
        ) -> bool {
            let Some(end) = address.checked_add(bytes) else {
                return false;
            };
            (address..end).all(|address| {
                self.permissions
                    .get(&address)
                    .is_some_and(|permissions| predicate(*permissions))
            })
        }
    }

    #[test]
    fn real_pie_maps_unique_aligned_pages_and_zero_fills_bss() {
        let bytes = fs::read("/bin/true").expect("/bin/true fixture");
        let plan = parse(&bytes).unwrap();
        let bias = select_load_bias(&plan, 0x2a_0000_1001, 4096).unwrap();
        assert_eq!(bias, 0x2a_0000_2000);
        let layout = ImageLayout::new(&plan, bias, 4096).unwrap();
        assert!(!layout.pages.is_empty());
        let mut addresses = layout
            .pages
            .iter()
            .map(|page| page.address)
            .collect::<Vec<_>>();
        addresses.sort_unstable();
        addresses.dedup();
        assert_eq!(addresses.len(), layout.pages.len());
        assert!(layout.pages.iter().all(|page| page.address % 4096 == 0));

        let mut memory = TestMemory::default();
        map_image(&mut memory, &bytes, &layout).unwrap();
        let entry_segment = plan
            .segments
            .iter()
            .find(|segment| {
                segment.executable
                    && (segment.virtual_address..segment.virtual_address + segment.memory_bytes)
                        .contains(&plan.entry)
            })
            .unwrap();
        let entry_file_offset =
            entry_segment.file_offset + (plan.entry - entry_segment.virtual_address);
        let mut entry = [0u8; 1];
        memory.read(layout.entry, &mut entry).unwrap();
        assert_eq!(entry[0], bytes[entry_file_offset as usize]);

        let data = layout
            .segments
            .iter()
            .find(|segment| {
                segment.permissions.writable && segment.memory_bytes > segment.file_bytes
            })
            .unwrap();
        let mut bss = [1u8; 16];
        memory
            .read(data.load_address + data.file_bytes, &mut bss)
            .unwrap();
        assert!(bss.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn real_libc_tls_template_initializes_a_thread_block() {
        let bytes = fs::read("/lib/x86_64-linux-gnu/libc.so.6").expect("libc fixture");
        let plan = parse(&bytes).unwrap();
        let layout = ImageLayout::new(&plan, 0x6000_0000_0000, 4096).unwrap();
        let tls = layout.tls.expect("libc PT_TLS");
        let mut memory = TestMemory::default();
        map_image(&mut memory, &bytes, &layout).unwrap();
        let target = 0x7000_0000_0000;
        assert_eq!(
            initialize_tls_block(&mut memory, &layout, layout.image_start),
            Err(LoaderError::BadTls)
        );
        memory.reserve(target, tls.memory_bytes);

        let mut template = vec![0u8; tls.file_bytes as usize];
        memory.read(tls.address, &mut template).unwrap();
        initialize_tls_block(&mut memory, &layout, target).unwrap();
        let mut initialized = vec![0u8; tls.file_bytes as usize];
        memory.read(target, &mut initialized).unwrap();
        assert_eq!(initialized, template);
        let mut tail = vec![1u8; (tls.memory_bytes - tls.file_bytes) as usize];
        memory.read(target + tls.file_bytes, &mut tail).unwrap();
        assert!(tail.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn real_relro_becomes_read_only_after_relocation_phase() {
        let bytes = fs::read("/bin/true").unwrap();
        let plan = parse(&bytes).unwrap();
        let layout = ImageLayout::new(&plan, 0x3000_0000_0000, 4096).unwrap();
        let mut memory = TestMemory::default();
        map_image(&mut memory, &bytes, &layout).unwrap();
        let relro = layout.relro.unwrap();
        memory.write(relro.address, &[1]).unwrap();
        protect_relro(&mut memory, &layout, 4096).unwrap();
        assert_eq!(
            memory.write(relro.address, &[2]),
            Err(LoaderError::MemoryWrite)
        );
    }

    fn synthetic_plan(segments: Vec<LoadSegment>, max_align: u64) -> LoadPlan {
        LoadPlan {
            entry: segments[0].virtual_address,
            position_independent: false,
            interpreter: None,
            needed: Vec::new(),
            rpaths: Vec::new(),
            runpaths: Vec::new(),
            segments,
            program_headers: None,
            program_header_entry_size: 0,
            program_header_count: 0,
            tls: None,
            relro: None,
            lifecycle: super::super::LifecyclePlan::default(),
            relocations: Vec::new(),
            max_align,
        }
    }

    #[test]
    fn non_page_aligned_segment_preserves_page_destination_and_bss() {
        let plan = synthetic_plan(
            vec![LoadSegment {
                file_offset: 0x103,
                virtual_address: 0x1003,
                file_bytes: 8,
                memory_bytes: 12,
                align: 1,
                readable: true,
                writable: false,
                executable: false,
            }],
            1,
        );
        let layout = ImageLayout::new(&plan, 0, 4096).unwrap();
        assert_eq!(layout.pages.len(), 1);
        assert_eq!(
            layout.pages[0].file_ranges,
            vec![MappedFileRange {
                destination_offset: 3,
                source_offset: 0x103,
                bytes: 8,
            }]
        );

        let mut source = vec![0u8; 0x200];
        source[0x103..0x10b].copy_from_slice(b"JASPEROS");
        let mut memory = TestMemory::default();
        map_image(&mut memory, &source, &layout).unwrap();
        let mut initialized = [0u8; 8];
        memory.read(0x1003, &mut initialized).unwrap();
        assert_eq!(&initialized, b"JASPEROS");
        let mut bss = [1u8; 4];
        memory.read(0x100b, &mut bss).unwrap();
        assert_eq!(bss, [0; 4]);
    }

    #[test]
    fn discontiguous_file_ranges_in_one_page_remain_distinct() {
        let plan = synthetic_plan(
            vec![
                LoadSegment {
                    file_offset: 0x100,
                    virtual_address: 0x1000,
                    file_bytes: 4,
                    memory_bytes: 4,
                    align: 1,
                    readable: true,
                    writable: false,
                    executable: false,
                },
                LoadSegment {
                    file_offset: 0x300,
                    virtual_address: 0x1010,
                    file_bytes: 4,
                    memory_bytes: 4,
                    align: 1,
                    readable: true,
                    writable: true,
                    executable: false,
                },
            ],
            1,
        );
        let layout = ImageLayout::new(&plan, 0, 4096).unwrap();
        assert_eq!(layout.pages.len(), 1);
        assert_eq!(
            layout.pages[0].file_ranges,
            vec![
                MappedFileRange {
                    destination_offset: 0,
                    source_offset: 0x100,
                    bytes: 4,
                },
                MappedFileRange {
                    destination_offset: 16,
                    source_offset: 0x300,
                    bytes: 4,
                },
            ]
        );
        let mut source = vec![0u8; 0x400];
        source[0x100..0x104].copy_from_slice(b"HEAD");
        source[0x300..0x304].copy_from_slice(b"TAIL");
        let mut memory = TestMemory::default();
        map_image(&mut memory, &source, &layout).unwrap();
        let mut bytes = [1u8; 20];
        memory.read(0x1000, &mut bytes).unwrap();
        assert_eq!(&bytes[..4], b"HEAD");
        assert_eq!(&bytes[4..16], &[0; 12]);
        assert_eq!(&bytes[16..], b"TAIL");
    }

    #[test]
    fn write_execute_page_and_bad_alignment_fail_closed() {
        let mut writable_executable = synthetic_plan(
            vec![
                LoadSegment {
                    file_offset: 0,
                    virtual_address: 0x1000,
                    file_bytes: 4,
                    memory_bytes: 4,
                    align: 1,
                    readable: true,
                    writable: false,
                    executable: true,
                },
                LoadSegment {
                    file_offset: 4,
                    virtual_address: 0x1010,
                    file_bytes: 4,
                    memory_bytes: 4,
                    align: 1,
                    readable: true,
                    writable: true,
                    executable: false,
                },
            ],
            1,
        );
        assert_eq!(
            ImageLayout::new(&writable_executable, 0, 4096),
            Err(LoaderError::BadSegment)
        );

        writable_executable.segments.truncate(1);
        writable_executable.max_align = 64 * 1024;
        writable_executable.position_independent = true;
        assert_eq!(
            select_load_bias(&writable_executable, 0x2000, 4096).unwrap(),
            64 * 1024
        );
        assert_eq!(
            ImageLayout::new(&writable_executable, 0x2000, 4096),
            Err(LoaderError::BadLoadBias)
        );
    }

    #[test]
    fn mapping_failure_rolls_back_prior_pages_and_mutated_layout_is_rejected() {
        let bytes = fs::read("/bin/true").unwrap();
        let plan = parse(&bytes).unwrap();
        let layout = ImageLayout::new(&plan, 0x3000_0000_0000, 4096).unwrap();
        assert!(layout.pages.len() > 1);
        let mut memory = TestMemory {
            fail_map_address: Some(layout.pages[1].address),
            ..TestMemory::default()
        };
        assert_eq!(
            map_image(&mut memory, &bytes, &layout),
            Err(LoaderError::MemoryMap)
        );
        assert!(memory.bytes.is_empty());
        assert!(memory.permissions.is_empty());

        let mut mutated = layout.clone();
        mutated.pages[0].address = mutated.image_start - mutated.page_size;
        let mut untouched = TestMemory::default();
        assert_eq!(
            map_image(&mut untouched, &bytes, &mutated),
            Err(LoaderError::BadSegment)
        );
        assert!(untouched.bytes.is_empty());
    }
}
