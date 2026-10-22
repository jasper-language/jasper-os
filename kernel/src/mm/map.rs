//! 内核地址空间映射服务（M2.2）：对整个内核提供中断安全的 map / unmap / translate / protect。
//!
//! 职责：持有当前（内核）地址空间唯一的 `arch::Mapper`，并把全局页帧分配服务适配成映射层需要的
//! [`FrameAllocator`]。不含 ISA 代码：页表格式全部在 `arch/<isa>/paging.rs`。
//!
//! 为什么全局唯一：同一地址空间若同时存在两个映射器，会对同一张顶级页表产生别名可变借用。
//! M2.4 引入多个地址空间后，每个地址空间对象各持有自己的映射器，这里只管内核空间。

use kernel_core::frame::{FrameAllocator, FrameError, PhysFrame};
use kernel_core::paging::{MapError, MapFlags, PageMapper, VirtPage};
use spin::Once;

use super::frame;
use crate::arch;
use crate::boot::BootSpec;
use crate::sync::IrqSpinLock;

/// 内核地址空间映射器（初始化一次）。
static KERNEL: Once<IrqSpinLock<arch::Mapper>> = Once::new();

/// 把全局页帧分配服务适配成 [`FrameAllocator`]（每次调用各自加锁，不与映射器锁嵌套持有）。
pub struct GlobalFrames;

impl FrameAllocator for GlobalFrames {
    fn allocate(&mut self) -> Result<PhysFrame, FrameError> {
        frame::allocate()
    }
    fn deallocate(&mut self, f: PhysFrame) -> Result<(), FrameError> {
        frame::deallocate(f)
    }
    fn free_frames(&self) -> usize {
        frame::free_frames()
    }
    fn usable_frames(&self) -> usize {
        frame::free_frames()
    }
}

/// 初始化内核映射器；引导器未提供物理内存映射时返回 `false`。
pub fn init(boot: &'static BootSpec) -> bool {
    let Some(offset) = boot.phys_offset else {
        return false;
    };
    // SAFETY：offset 来自引导器；`Once` 保证内核地址空间只有这一个映射器。
    KERNEL.call_once(|| IrqSpinLock::new(unsafe { arch::active_mapper(offset) }));
    true
}

fn with<R>(f: impl FnOnce(&mut arch::Mapper) -> Result<R, MapError>) -> Result<R, MapError> {
    let m = KERNEL.get().ok_or(MapError::NotMapped)?;
    f(&mut m.lock())
}

/// 映射一页（中间页表的帧从全局页帧分配服务取）。
pub fn map(page: VirtPage, frame: PhysFrame, flags: MapFlags) -> Result<(), MapError> {
    with(|m| m.map(page, frame, flags, &mut GlobalFrames))
}

/// 取消映射、等待所有在线处理器完成击落，然后返回原帧（帧不归还，由调用者决定）。
///
/// 击落失败时映射已经撤销，但不返回帧；调用者不得把任何仍可能被旧 TLB 引用的帧放回分配器。
/// Unmap, wait for the SMP shootdown, then return the frame.
pub fn unmap(page: VirtPage) -> Result<PhysFrame, MapError> {
    let frame = with(|m| m.unmap(page))?;
    crate::smp::tlb_shootdown(page.start(), 1).map_err(|_| MapError::Busy)?;
    Ok(frame)
}

/// 批量取消内核映射；所有页表修改完成后只发起一次击落。
///
/// 用于 MMIO 窗口等不拥有 RAM 帧的映射，因此不返回物理帧。中途失败时仍对已修改前缀执行击落，
/// 避免留下未同步的旧缓存项。
/// Unmap several kernel pages with one shootdown request.
pub fn unmap_pages(page: VirtPage, pages: u64) -> Result<(), MapError> {
    if pages == 0 || pages.checked_mul(kernel_core::frame::FRAME_SIZE).and_then(|n| page.start().checked_add(n)).is_none() {
        return Err(MapError::InvalidAddress);
    }
    let changed = {
        let m = KERNEL.get().ok_or(MapError::NotMapped)?;
        let mut m = m.lock();
        let mut changed = 0u64;
        let mut failure = None;
        while changed < pages {
            let at = VirtPage::from_start(page.start() + changed * kernel_core::frame::FRAME_SIZE)
                .ok_or(MapError::InvalidAddress)?;
            if let Err(e) = m.unmap(at) {
                failure = Some(e);
                break;
            }
            changed += 1;
        }
        (changed, failure)
    };
    if changed.0 > 0 {
        crate::smp::tlb_shootdown(page.start(), changed.0).map_err(|_| MapError::Busy)?;
    }
    match changed.1 {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// 查询映射。
pub fn translate(page: VirtPage) -> Option<(PhysFrame, MapFlags)> {
    KERNEL.get()?.lock().translate(page)
}

/// 修改内核映射权限；返回前等待所有在线处理器完成击落。
pub fn protect(page: VirtPage, flags: MapFlags) -> Result<(), MapError> {
    with(|m| m.protect(page, flags))?;
    crate::smp::tlb_shootdown(page.start(), 1).map_err(|_| MapError::Busy)
}
