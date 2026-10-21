//! 内核设备寄存器窗口映射：把内存型 BAR 的一段以不可缓存方式映射到平台预留的高半区。
//! Kernel device-register window mapping: map a memory BAR subrange uncached into a reserved high-half window.
//!
//! # 职责
//! * 按「BAR + BAR 内偏移 + 字节数」映射，页对齐处理、页表安装与回滚全部交给 [`crate::mm::map`]；
//!   本文件不实现页表，也不出现任何指令集专有值。
//! * 返回的 [`Mapping`] 把虚拟地址调整到请求的起始偏移；调用者用带偏移的 `read*` / `write*` 访问寄存器。
//! * 槽位从平台给出的窗口内顺序分配，数量有固定上界；槽位不回收，避免并发演示时地址重用。
//!
//! # 边界
//! * 只映射内存 BAR；I/O 端口 BAR、越界区间、超出窗口或大于一个槽位的映射一律返回结构化错误。
//! * 不解释设备语义、不注册中断、不分配 DMA；丢弃 [`Mapping`] 只取消映射，不修改设备状态。
//! * 映射页固定为可写、全局、不可缓存且不可执行；设备寄存器不得经缓存访问。

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::frame::{PhysFrame, FRAME_SIZE};
use kernel_core::paging::{MapFlags, VirtPage};
use kernel_core::pci::Bar;

use crate::{arch, mm};

/// 每个映射槽位的虚拟地址间距（64 KiB，足以容纳一个 MSI-X 表与相邻寄存器窗）。
/// Virtual-address stride of one mapping slot.
pub const SLOT_STRIDE: u64 = 64 * 1024;
/// 窗口内最多分配的槽位数（与平台给出的 2 MiB 窗口一致）。
/// Maximum number of mapping slots in the reserved window.
pub const MAX_SLOTS: usize = (2 * 1024 * 1024 / SLOT_STRIDE) as usize;

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
    /// 请求区间超过一个槽位，或窗口槽位已用尽。
    /// The range exceeds one slot, or the window is exhausted.
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
        if pages * FRAME_SIZE > SLOT_STRIDE {
            return Err(MmioError::OutOfWindow);
        }
        let (window_base, window_len) = arch::mmio_window().ok_or(MmioError::Unsupported)?;
        let slot = NEXT_SLOT.fetch_add(1, Ordering::Relaxed) as u64;
        if slot as usize >= MAX_SLOTS {
            return Err(MmioError::OutOfWindow);
        }
        let page_va = window_base
            .checked_add(slot * SLOT_STRIDE)
            .ok_or(MmioError::OutOfWindow)?;
        if page_va.checked_add(pages * FRAME_SIZE).is_none_or(|e| e > window_base + window_len) {
            return Err(MmioError::OutOfWindow);
        }

        let flags = MapFlags::WRITE | MapFlags::GLOBAL | MapFlags::NO_CACHE;
        let mut mapped = 0u64;
        while mapped < pages {
            let page = VirtPage::from_start(page_va + mapped * FRAME_SIZE).ok_or(MmioError::OutOfWindow)?;
            let frame = PhysFrame::from_start(base + page_start + mapped * FRAME_SIZE).ok_or(MmioError::BadBar)?;
            if mm::map::map(page, frame, flags).is_err() {
                let mut undo = 0u64;
                while undo < mapped {
                    if let Some(page) = VirtPage::from_start(page_va + undo * FRAME_SIZE) {
                        let _ = mm::map::unmap(page);
                    }
                    undo += 1;
                }
                return Err(MmioError::MapFailed);
            }
            mapped += 1;
        }
        Ok(Mapping { va: page_va + page_offset, page_va, pages, len: len as u64 })
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
        for page in 0..self.pages {
            if let Some(page) = VirtPage::from_start(self.page_va + page * FRAME_SIZE) {
                let _ = mm::map::unmap(page);
            }
        }
    }
}

/// 下一个可用槽位（启动期一次性递增；槽位不回收）。
static NEXT_SLOT: AtomicU32 = AtomicU32::new(0);

/// 映射槽位使用数（诊断用）。
/// Number of mapping slots handed out.
pub fn slots_used() -> usize {
    NEXT_SLOT.load(Ordering::Relaxed) as usize
}

/// 预先建立窗口所需的下级页表：映射并立即取消映射一个临时页。
///
/// 这样后续真实映射只在已存在的页表中填写叶项，不再消耗页帧；调用者在页帧基线测量之前执行一次即可。
/// Pre-establishes the page tables of the reserved window so later mappings allocate no frames.
pub fn prepare_window() -> Result<(), MmioError> {
    let (window_base, window_len) = arch::mmio_window().ok_or(MmioError::Unsupported)?;
    if window_len < FRAME_SIZE {
        return Err(MmioError::OutOfWindow);
    }
    let page = VirtPage::from_start(window_base).ok_or(MmioError::OutOfWindow)?;
    let frame = mm::frame::allocate().map_err(|_| MmioError::MapFailed)?;
    let flags = MapFlags::WRITE | MapFlags::GLOBAL | MapFlags::NO_CACHE;
    if mm::map::map(page, frame, flags).is_err() {
        let _ = mm::frame::deallocate(frame);
        return Err(MmioError::MapFailed);
    }
    let unmapped = mm::map::unmap(page);
    let freed = mm::frame::deallocate(frame);
    match (unmapped, freed) {
        (Ok(mapped), Ok(())) if mapped == frame => Ok(()),
        _ => Err(MmioError::MapFailed),
    }
}
