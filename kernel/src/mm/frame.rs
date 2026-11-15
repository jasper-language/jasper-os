//! 全局物理页帧分配服务（M2.1）。
//!
//! 职责：用引导交接信息里的物理内存图初始化 `kernel-core` 的 [`BitmapFrameAllocator`]，
//! 并以中断安全的方式对整个内核提供 `allocate` / `deallocate` / 统计。
//!
//! 设计：
//! * 位图元数据在启动交接时按完整物理内存图推导，并从可用 RAM 中动态预留；
//!   不使用编译 Profile 固定数组，也不依赖内核堆。
//! * 分配器本身由 [`IrqSpinLock`] 保护：中断处理程序（将来的缺页处理等）与任务都可能分配页帧。
//! * 分配策略可替换（`FrameAllocator` trait）；这里只是选定位图实现并管理它的生命周期。

use kernel_core::frame::{BitmapFrameAllocator, FrameAllocator, FrameError, PhysFrame};
use spin::Once;

use crate::boot::BootSpec;
use crate::sync::IrqSpinLock;

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
    if ALLOCATOR.get().is_some() {
        return stats(boot.regions().len());
    }
    let Some(metadata) = boot.frame_bitmap else {
        crate::kprintln!(
            "[JSR-FRAME] reject=frame_bitmap_missing reason=derived_metadata_unavailable"
        );
        return stats(boot.regions().len());
    };
    let Some(phys_offset) = boot.phys_offset else {
        crate::kprintln!("[JSR-FRAME] reject=frame_bitmap_unmapped");
        return stats(boot.regions().len());
    };
    let Some(pointer) = phys_offset.checked_add(metadata.physical) else {
        crate::kprintln!("[JSR-FRAME] reject=frame_bitmap_pointer_overflow");
        return stats(boot.regions().len());
    };
    // SAFETY: boot hand-off reserved exactly this zeroed range from complete
    // usable RAM and provided a verified direct-map offset. Once guarantees the
    // slice is handed to the allocator only once and never mutated elsewhere.
    let bits: &'static mut [u64] =
        unsafe { core::slice::from_raw_parts_mut(pointer as *mut u64, metadata.words) };
    ALLOCATOR.call_once(|| {
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
    let result=ALLOCATOR.get().ok_or(FrameError::OutOfFrames)?.lock().allocate();
    if result.is_ok() {crate::mm::pressure::note_frame_change();}
    result
}

/// 分配一个起始地址低于 `limit` 的物理页帧（硬件只能寻址低端内存时使用）；没有则失败且不改动。
/// Allocate a frame below `limit`.
pub fn allocate_below(limit: u64) -> Result<PhysFrame, FrameError> {
    #[cfg(feature = "fault-inject")]
    if crate::fault_inject::FRAME.hit() { return Err(FrameError::OutOfFrames); }
    let result=ALLOCATOR.get().ok_or(FrameError::OutOfFrames)?.lock().allocate_below(limit);
    if result.is_ok() {crate::mm::pressure::note_frame_change();}
    result
}

/// 分配 `count` 个物理相邻的空闲页帧并返回首帧；失败时分配器状态不变。
/// Allocate `count` physically contiguous free frames.
pub fn allocate_contiguous(count: usize) -> Result<PhysFrame, FrameError> {
    #[cfg(feature = "fault-inject")]
    if crate::fault_inject::FRAME.hit() { return Err(FrameError::OutOfFrames); }
    let result=ALLOCATOR.get().ok_or(FrameError::OutOfFrames)?.lock().allocate_contiguous(count);
    if result.is_ok() {crate::mm::pressure::note_frame_change();}
    result
}

/// 归还一段物理相邻的页帧；整段校验失败时不做任何改动。
/// Release a contiguous run of frames.
pub fn deallocate_contiguous(first: PhysFrame, count: usize) -> Result<(), FrameError> {
    let result=ALLOCATOR.get().ok_or(FrameError::NotUsable)?.lock().deallocate_contiguous(first, count);
    if result.is_ok() {crate::mm::pressure::note_frame_change();}
    result
}

/// 释放一个物理页帧。
pub fn deallocate(frame: PhysFrame) -> Result<(), FrameError> {
    let result=ALLOCATOR.get().ok_or(FrameError::NotUsable)?.lock().deallocate(frame);
    if result.is_ok() {crate::mm::pressure::note_frame_change();}
    result
}

/// 当前空闲帧数。
pub fn free_frames() -> usize {
    ALLOCATOR.get().map(|a| a.lock().free_frames()).unwrap_or(0)
}

/// 可分配帧总数（内存压力按它的比例判级）。
pub fn usable_frames() -> usize {
    ALLOCATOR.get().map(|a| a.lock().usable_frames()).unwrap_or(0)
}
