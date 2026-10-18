//! RISC-V 地址空间：顶级页表的创建、切换（satp）与销毁。
//! RISC-V address spaces: create, switch (satp) and destroy top-level tables.
//!
//! # 模型（与 x86_64 / AArch64 相同）
//! * 每个地址空间 = 一张独立的顶级表，经 satp 生效。
//! * **私有窗口**：顶级下标 [`USER_FIRST`, `USER_LAST`) 归各地址空间私有；其余顶级表项在创建时从当前（内核）表复制，
//!   指向同一批下级表或同一批大页 ⇒ 内核映射在所有空间共享。
//! * **内核共享部分**：顶级下标 [`KERNEL_FIRST`, `KERNEL_LAST`)。启动时一次性预分配全部下级表，
//!   此后在这里新增的内核映射自动对所有地址空间可见。
//! * 不使用地址空间标识（ASID = 0）：切换时作废本处理器的全部地址转换缓存。

use kernel_core::frame::{FrameAllocator, PhysFrame, FRAME_SIZE};
use kernel_core::paging::{MapError, MapFlags};
use kernel_core::pagetable::PageTable;

use super::cpu::{self, read_csr, write_csr};
use super::mmu;
use super::paging::{PhysTables, Sv39Table};

/// 私有窗口的第一个顶级下标（含）：`0x8_0000_0000`。
pub const USER_FIRST: usize = 32;
/// 私有窗口的最后一个顶级下标（不含）：`0x10_0000_0000`。
pub const USER_LAST: usize = 64;
/// 私有窗口对应的虚拟地址区间 `[start, end)`（32 GiB）。
pub const USER_WINDOW: (u64, u64) = ((USER_FIRST as u64) << 30, (USER_LAST as u64) << 30);
// 用户态运行时与用户程序的链接地址按同一数值布局：两边必须一致。
const _: () = assert!(USER_WINDOW.0 == kernel_core::user_layout::WINDOW_BASE_RISCV64);
/// 内核共享部分的第一个顶级下标（含）。
pub const KERNEL_FIRST: usize = 128;
/// 内核共享部分的最后一个顶级下标（不含）= 低半区的顶级表项数。
pub const KERNEL_LAST: usize = Sv39Table::TOP_ENTRIES;
/// satp 中的物理页号字段。
const SATP_PPN_MASK: u64 = (1 << 44) - 1;

/// 地址空间根：顶级表所在物理帧（不透明地交给 Core）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpaceRoot(pub u64);

/// 以 `root` 为根的遍历器。
///
/// # Safety
/// `root` 必须是有效的顶级表；`phys_offset` 为全物理内存映射偏移。
unsafe fn table(root: u64, phys_offset: u64) -> Sv39Table {
    PageTable::new(root, PhysTables::new(phys_offset))
}

/// 当前 satp 指向的地址空间。
pub fn current() -> SpaceRoot {
    SpaceRoot((read_csr!("satp") & SATP_PPN_MASK) << 12)
}

/// 新建地址空间：分配并清零一张顶级表，复制私有窗口之外的全部顶级表项。
/// 当前空间若在私有窗口里已有映射则拒绝（否则这些映射会被所有空间意外共享）。
///
/// # Safety
/// `phys_offset` 必须是全物理内存映射偏移。
pub unsafe fn create(phys_offset: u64, frames: &mut dyn FrameAllocator) -> Result<SpaceRoot, MapError> {
    let cur = current().0;
    if table(cur, phys_offset).used_top(USER_FIRST..USER_LAST) != 0 {
        return Err(MapError::InvalidAddress);
    }
    let f = frames.allocate().map_err(|_| MapError::OutOfFrames)?;
    let mut t = empty_table(f, phys_offset);
    t.adopt_top_except(cur, USER_FIRST..USER_LAST);
    Ok(SpaceRoot(f.start()))
}

/// 把帧清零并返回以它为根的遍历器。
unsafe fn empty_table(frame: PhysFrame, phys_offset: u64) -> Sv39Table {
    core::ptr::write_bytes((phys_offset + frame.start()) as *mut u8, 0, FRAME_SIZE as usize);
    table(frame.start(), phys_offset)
}

/// 把一个物理帧清零并当作空的顶级表（自检用的临时根，从不激活）。
///
/// # Safety
/// `frame` 必须由调用者独占且未被任何页表引用。
pub unsafe fn empty_root(frame: PhysFrame, phys_offset: u64) -> SpaceRoot {
    empty_table(frame, phys_offset);
    SpaceRoot(frame.start())
}

/// 预分配内核共享部分的全部顶级表项（全有或全无），返回新安装数。
///
/// # Safety
/// `root` 必须是有效的顶级表；对内核空间须在创建任何其他地址空间之前调用。
pub unsafe fn prealloc_kernel_part(root: SpaceRoot, phys_offset: u64, frames: &mut dyn FrameAllocator) -> Result<usize, MapError> {
    let n = table(root.0, phys_offset).prealloc_top(KERNEL_FIRST..KERNEL_LAST, frames)?;
    cpu::tlb_flush_all();
    Ok(n)
}

/// 内核共享部分已使用的顶级表项数。
///
/// # Safety
/// `root` 必须是有效的顶级表。
pub unsafe fn kernel_part_used(root: SpaceRoot, phys_offset: u64) -> usize {
    table(root.0, phys_offset).used_top(KERNEL_FIRST..KERNEL_LAST)
}

/// 只读查询任意地址空间中 `va` 所在页的映射与有效权限（不构造可修改页表的映射器）。
///
/// # Safety
/// `root` 必须有效，调用期间其页表不被并发修改。
pub unsafe fn translate(root: SpaceRoot, phys_offset: u64, va: u64) -> Option<(PhysFrame, MapFlags)> {
    table(root.0, phys_offset).translate(va)
}

/// 切换到 `root`：写 satp 后作废全部地址转换缓存。
///
/// # Safety
/// `root` 必须是由 [`create`] 建立且未销毁的空间（或启动时的内核空间），其中包含当前代码与栈的映射。
pub unsafe fn switch(root: SpaceRoot) {
    write_csr!("satp", mmu::satp_for(root.0));
    cpu::tlb_flush_all();
}

/// 销毁地址空间：释放私有窗口内的全部**页表**帧与顶级表本身（叶子指向的数据帧由其所有者负责）。
///
/// # Safety
/// `root` 不能是当前活动空间，也不能再被使用。
pub unsafe fn destroy(root: SpaceRoot, phys_offset: u64, frames: &mut dyn FrameAllocator) {
    table(root.0, phys_offset).free_tables(USER_FIRST..USER_LAST, frames);
    if let Some(f) = PhysFrame::from_start(root.0) {
        let _ = frames.deallocate(f);
    }
}
