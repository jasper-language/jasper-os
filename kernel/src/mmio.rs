//! 内核设备寄存器窗口映射：把内存型 BAR 的一段以不可缓存方式映射到平台预留的高半区。
//! Kernel device-register window mapping: map a memory BAR subrange uncached into a reserved high-half window.
//!
//! # 职责
//! * 按「BAR + BAR 内偏移 + 字节数」映射，页对齐处理、页表安装与回滚全部交给 [`crate::mm::map`]；
//!   本文件不实现页表，也不出现任何指令集专有值。
//! * 返回的 [`Mapping`] 把虚拟地址调整到请求的起始偏移；调用者用带偏移的 `read*` / `write*` 访问寄存器。
//! * 映射区间由运行时准入窗口的空闲段动态分配；每个映射丢弃后归还自己的区间。
//!
//! # 边界
//! * 只映射内存 BAR；I/O 端口 BAR、越界区间和超出准入窗口的映射返回结构化错误。
//! * 不解释设备语义、不注册中断、不分配 DMA；丢弃 [`Mapping`] 只取消映射，不修改设备状态。
//! * 映射页固定为可写、全局、不可缓存且不可执行；设备寄存器不得经缓存访问。

use alloc::vec::Vec;

use kernel_core::frame::{PhysFrame, FRAME_SIZE};
use kernel_core::paging::{MapFlags, VirtPage};
use kernel_core::pci::Bar;
use spin::{Mutex, Once};

use crate::{arch, mm};

/// Page-table pre-establishment granularity.
const PAGE_TABLE_BLOCK_BYTES: u64 = 2 * 1024 * 1024;
/// At most 1/128 of free frames may become persistent MMIO page-table state.
const PAGE_TABLE_FRAME_BUDGET_DIVISOR: usize = 128;

/// MMIO 映射错误。
/// MMIO mapping error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmioError {
    /// 平台没有提供设备寄存器窗口。
    /// The platform provides no device-register window.
    Unsupported,
    /// BAR 不存在、不是内存 BAR、基址未对齐，或请求区间越出 BAR。
    /// The BAR is absent, is not a memory BAR, is misaligned, or the range exceeds it.
    BadBar,
    /// The admitted MMIO window cannot satisfy this mapping.
    OutOfWindow,
    /// 页表映射失败。
    /// The page-table mapping failed.
    MapFailed,
}

impl MmioError {
    /// 规范名。
    /// Canonical name.
    pub const fn name(self) -> &'static str {
        match self {
            MmioError::Unsupported => "system.device.error.mmio_unsupported",
            MmioError::BadBar => "system.device.error.bad_bar",
            MmioError::OutOfWindow => "system.device.error.mmio_out_of_window",
            MmioError::MapFailed => "system.device.error.mmio_map_failed",
        }
    }
}

/// 一段已建立的内核 MMIO 映射；丢弃时取消映射。
/// One established kernel MMIO mapping, unmapped on drop.
pub struct Mapping {
    /// Page-aligned byte offset inside the admitted MMIO window.
    window_offset: u64,
    /// 请求起始偏移对应的虚拟地址。
    va: u64,
    /// 映射起始虚拟地址（页对齐）。
    page_va: u64,
    /// 映射页数。
    pages: u64,
    /// 请求的字节数。
    len: u64,
}

impl Mapping {
    /// 把 `bar` 内 `[offset, offset + len)` 映射为不可缓存内核窗口，返回指向 `offset` 的映射。
    ///
    /// `offset` 与 `len` 都必须落在 BAR 内；任何失败都归还本次已建立的页映射且不改动其它槽位。
    /// Maps `[offset, offset + len)` of a memory BAR and returns a handle pointing at `offset`.
    pub fn map(bar: &Bar, offset: u32, len: u32) -> Result<Mapping, MmioError> {
        let (base, size) = match *bar {
            Bar::Memory { base, size, .. } => (base, size),
            _ => return Err(MmioError::BadBar),
        };
        if base % FRAME_SIZE != 0 {
            return Err(MmioError::BadBar);
        }
        let end = offset as u64 + len as u64;
        if len == 0 || end > size || base.checked_add(end).is_none() {
            return Err(MmioError::BadBar);
        }
        let page_offset = offset as u64 % FRAME_SIZE;
        let page_start = offset as u64 - page_offset;
        let pages = (page_offset + len as u64).div_ceil(FRAME_SIZE);
        let required_bytes = pages
            .checked_mul(FRAME_SIZE)
            .ok_or(MmioError::OutOfWindow)?;
        let (window_offset, page_va) = allocate_window_range(required_bytes)?;

        let flags = MapFlags::WRITE | MapFlags::GLOBAL | MapFlags::NO_CACHE;
        let mut mapped = 0u64;
        while mapped < pages {
            let page = VirtPage::from_start(page_va + mapped * FRAME_SIZE)
                .ok_or(MmioError::OutOfWindow)?;
            let frame = PhysFrame::from_start(base + page_start + mapped * FRAME_SIZE)
                .ok_or(MmioError::BadBar)?;
            #[cfg(all(feature = "s2-fuzz", target_arch = "x86_64"))]
            let injected = crate::s2::MMIO_MAP.hit();
            #[cfg(not(all(feature = "s2-fuzz", target_arch = "x86_64")))]
            let injected = false;
            if injected || mm::map::map(page, frame, flags).is_err() {
                // chatgpt: an unconfirmed rollback may leave stale remote TLB
                // entries. Quarantine the VA slot exactly as Mapping::drop does.
                if mapped == 0
                    || mm::map::unmap_pages(VirtPage::containing(page_va), mapped).is_ok()
                {
                    release_window_range(window_offset, pages);
                }
                return Err(MmioError::MapFailed);
            }
            mapped += 1;
        }
        Ok(Mapping {
            window_offset,
            va: page_va + page_offset,
            page_va,
            pages,
            len: len as u64,
        })
    }

    /// 请求起始偏移对应的虚拟地址。
    /// Virtual address of the requested start offset.
    pub const fn va(&self) -> u64 {
        self.va
    }

    /// 映射覆盖的字节数（请求长度）。
    /// Requested length in bytes.
    pub const fn len(&self) -> u64 {
        self.len
    }

    /// 是否为空映射（构造成功后恒为 `false`）。
    /// Whether this mapping is empty.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// 读取 32 位寄存器。
    /// Reads a 32-bit register.
    ///
    /// # Safety
    /// `offset + 4` 必须落在本映射内且 4 字节对齐；设备必须仍在工作。
    pub unsafe fn read32(&self, offset: u64) -> u32 {
        ((self.va + offset) as *const u32).read_volatile()
    }

    /// 写入 32 位寄存器。
    /// Writes a 32-bit register.
    ///
    /// # Safety
    /// 同 [`Mapping::read32`]；写入值必须是该寄存器的合法值。
    pub unsafe fn write32(&self, offset: u64, value: u32) {
        ((self.va + offset) as *mut u32).write_volatile(value);
    }

    /// 读取 16 位寄存器。
    /// Reads a 16-bit register.
    ///
    /// # Safety
    /// `offset + 2` 必须落在本映射内且 2 字节对齐。
    pub unsafe fn read16(&self, offset: u64) -> u16 {
        ((self.va + offset) as *const u16).read_volatile()
    }

    /// 写入 16 位寄存器。
    /// Writes a 16-bit register.
    ///
    /// # Safety
    /// 同 [`Mapping::read16`]。
    pub unsafe fn write16(&self, offset: u64, value: u16) {
        ((self.va + offset) as *mut u16).write_volatile(value);
    }

    /// 读取 8 位寄存器。
    /// Reads an 8-bit register.
    ///
    /// # Safety
    /// `offset` 必须落在本映射内。
    pub unsafe fn read8(&self, offset: u64) -> u8 {
        ((self.va + offset) as *const u8).read_volatile()
    }

    /// 写入 8 位寄存器。
    /// Writes an 8-bit register.
    ///
    /// # Safety
    /// 同 [`Mapping::read8`]。
    pub unsafe fn write8(&self, offset: u64, value: u8) {
        ((self.va + offset) as *mut u8).write_volatile(value);
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        if let Some(start) = VirtPage::from_start(self.page_va) {
            if mm::map::unmap_pages(start, self.pages).is_ok() {
                release_window_range(self.window_offset, self.pages);
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Allocation {
    offset: u64,
    pages: u64,
}

struct State {
    base: u64,
    span: u64,
    active_len: u64,
    allocations: Vec<Allocation>,
}

static STATE: Mutex<State> = Mutex::new(State {
    base: 0,
    span: 0,
    active_len: 0,
    allocations: Vec::new(),
});
static PREPARED: Once<Result<(), MmioError>> = Once::new();

fn allocate_window_range(required_bytes: u64) -> Result<(u64, u64), MmioError> {
    let (base, span) = arch::mmio_window().ok_or(MmioError::Unsupported)?;
    let mut state = STATE.lock();
    if state.base != base || state.span != span || state.active_len == 0 {
        return Err(MmioError::Unsupported);
    }
    state
        .allocations
        .try_reserve(1)
        .map_err(|_| MmioError::OutOfWindow)?;

    let mut cursor = 0u64;
    for allocation in &state.allocations {
        if allocation.offset.saturating_sub(cursor) >= required_bytes {
            break;
        }
        cursor = cursor.max(
            allocation
                .offset
                .saturating_add(allocation.pages.saturating_mul(FRAME_SIZE)),
        );
    }
    let end = cursor
        .checked_add(required_bytes)
        .ok_or(MmioError::OutOfWindow)?;
    if end > state.active_len {
        return Err(MmioError::OutOfWindow);
    }
    let page_va = base.checked_add(cursor).ok_or(MmioError::OutOfWindow)?;
    state.allocations.push(Allocation {
        offset: cursor,
        pages: required_bytes / FRAME_SIZE,
    });
    state
        .allocations
        .sort_unstable_by_key(|allocation| allocation.offset);
    Ok((cursor, page_va))
}

fn release_window_range(offset: u64, _pages: u64) {
    let mut state = STATE.lock();
    if let Some(index) = state
        .allocations
        .iter()
        .position(|allocation| allocation.offset == offset)
    {
        state.allocations.remove(index);
    }
}

/// Number of currently mapped MMIO regions.
pub fn mapped_regions() -> usize {
    STATE.lock().allocations.len()
}

/// Remaining bytes in the admitted MMIO window, including fragmentation.
pub fn free_bytes() -> u64 {
    let state = STATE.lock();
    let used = state
        .allocations
        .iter()
        .map(|allocation| allocation.pages.saturating_mul(FRAME_SIZE))
        .sum::<u64>();
    state.active_len.saturating_sub(used)
}

/// Admitted active window length.
pub fn active_window_bytes() -> u64 {
    STATE.lock().active_len
}

/// Admit a runtime-budgeted portion of the reserved MMIO span. Intermediate
/// page tables are established on demand by [`Mapping::map`]; the admission
/// path itself does not create temporary device mappings.
/// 按运行时内存预算准入 MMIO 窗口；中间页表由实际映射按需建立。
pub fn prepare_window() -> Result<(), MmioError> {
    *PREPARED.call_once(prepare_window_inner)
}

fn prepare_window_inner() -> Result<(), MmioError> {
    let (window_base, span) = arch::mmio_window().ok_or(MmioError::Unsupported)?;
    if window_base % FRAME_SIZE != 0 || span < PAGE_TABLE_BLOCK_BYTES {
        return Err(MmioError::OutOfWindow);
    }
    let max_blocks = span / PAGE_TABLE_BLOCK_BYTES;
    let budget_blocks = (mm::frame::free_frames() / PAGE_TABLE_FRAME_BUDGET_DIVISOR) as u64;
    let blocks = max_blocks.min(budget_blocks);
    if blocks == 0 {
        return Err(MmioError::OutOfWindow);
    }

    let active_len = blocks
        .checked_mul(PAGE_TABLE_BLOCK_BYTES)
        .ok_or(MmioError::OutOfWindow)?;
    let mut state = STATE.lock();
    state.base = window_base;
    state.span = span;
    state.active_len = active_len;
    Ok(())
}
