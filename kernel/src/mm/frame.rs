//! 全局物理页帧分配服务（M2.1）。
//!
//! 职责：用引导交接信息里的物理内存图初始化 `kernel-core` 的 [`BitmapFrameAllocator`]，
//! 并以中断安全的方式对整个内核提供 `allocate` / `deallocate` / 统计。
//!
//! 设计：
//! * 位图存放在 `.bss` 的静态数组里（无堆）。[`BITMAP_WORDS`] 个 `u64` 覆盖
//!   `BITMAP_WORDS × 64 × 4 KiB` 的物理地址空间；超出部分由分配器计入 `ignored_frames` 并在启动时打印。
//! * 分配器本身由 [`IrqSpinLock`] 保护：中断处理程序（将来的缺页处理等）与任务都可能分配页帧。
//! * 分配策略可替换（`FrameAllocator` trait）；这里只是选定位图实现并管理它的生命周期。

use core::ptr::addr_of_mut;

use kernel_core::frame::{BitmapFrameAllocator, FrameAllocator, FrameError, PhysFrame};
use spin::Once;

use crate::boot::BootSpec;
use crate::sync::IrqSpinLock;

/// 位图字数：16384 × 64 帧 × 4 KiB = 4 GiB 物理地址空间（位图本身占 128 KiB）。
/// 位图字数随配置档变化：standard 覆盖 64 GiB，compact 覆盖 4 GiB。
pub const BITMAP_WORDS: usize = crate::config::ACTIVE.memory.frame_bitmap_words;

/// 位图存储（`.bss`，由引导器清零映射）。只在 [`init`] 中被借出一次。
static mut BITMAP: [u64; BITMAP_WORDS] = [0; BITMAP_WORDS];

/// 全局分配器（初始化一次）。
static ALLOCATOR: Once<IrqSpinLock<BitmapFrameAllocator<'static>>> = Once::new();

/// 初始化统计（供启动日志与验收使用）。
#[derive(Debug, Clone, Copy)]
pub struct FrameStats {
    /// 物理内存图中的区域数。
    pub regions: usize,
    /// 可分配帧总数。
    pub usable: usize,
    /// 当前空闲帧数。
    pub free: usize,
    /// 超出位图管理范围而未纳入的可用帧数。
    pub ignored: usize,
}

/// 用交接信息初始化全局分配器（只生效一次）。
pub fn init(boot: &'static BootSpec) -> FrameStats {
    ALLOCATOR.call_once(|| {
        // SAFETY：`Once` 保证这段只执行一次，BITMAP 的唯一可变借用交给分配器、此后不再被直接访问。
        let bits: &'static mut [u64] = unsafe { &mut *addr_of_mut!(BITMAP) };
        IrqSpinLock::ranked(crate::lockorder::MEMORY_FRAME, BitmapFrameAllocator::new(bits, boot.regions()))
    });
    stats(boot.regions().len())
}

fn stats(regions: usize) -> FrameStats {
    match ALLOCATOR.get() {
        Some(a) => {
            let a = a.lock();
            FrameStats { regions, usable: a.usable_frames(), free: a.free_frames(), ignored: a.ignored_frames() }
        }
        None => FrameStats { regions, usable: 0, free: 0, ignored: 0 },
    }
}

/// 分配一个物理页帧。未初始化时视为没有空闲帧。
pub fn allocate() -> Result<PhysFrame, FrameError> {
    #[cfg(feature = "fault-inject")]
    if crate::fault_inject::FRAME.hit() { return Err(FrameError::OutOfFrames); }
    ALLOCATOR.get().ok_or(FrameError::OutOfFrames)?.lock().allocate()
}

/// 分配一个起始地址低于 `limit` 的物理页帧（硬件只能寻址低端内存时使用）；没有则失败且不改动。
/// Allocate a frame below `limit`.
pub fn allocate_below(limit: u64) -> Result<PhysFrame, FrameError> {
    #[cfg(feature = "fault-inject")]
    if crate::fault_inject::FRAME.hit() { return Err(FrameError::OutOfFrames); }
    ALLOCATOR.get().ok_or(FrameError::OutOfFrames)?.lock().allocate_below(limit)
}

/// 分配 `count` 个物理相邻的空闲页帧并返回首帧；失败时分配器状态不变。
/// Allocate `count` physically contiguous free frames.
pub fn allocate_contiguous(count: usize) -> Result<PhysFrame, FrameError> {
    #[cfg(feature = "fault-inject")]
    if crate::fault_inject::FRAME.hit() { return Err(FrameError::OutOfFrames); }
    ALLOCATOR.get().ok_or(FrameError::OutOfFrames)?.lock().allocate_contiguous(count)
}

/// 归还一段物理相邻的页帧；整段校验失败时不做任何改动。
/// Release a contiguous run of frames.
pub fn deallocate_contiguous(first: PhysFrame, count: usize) -> Result<(), FrameError> {
    ALLOCATOR.get().ok_or(FrameError::NotUsable)?.lock().deallocate_contiguous(first, count)
}

/// 释放一个物理页帧。
pub fn deallocate(frame: PhysFrame) -> Result<(), FrameError> {
    ALLOCATOR.get().ok_or(FrameError::NotUsable)?.lock().deallocate(frame)
}

/// 当前空闲帧数。
pub fn free_frames() -> usize {
    ALLOCATOR.get().map(|a| a.lock().free_frames()).unwrap_or(0)
}

/// 可分配帧总数（内存压力按它的比例判级）。
pub fn usable_frames() -> usize {
    ALLOCATOR.get().map(|a| a.lock().usable_frames()).unwrap_or(0)
}
