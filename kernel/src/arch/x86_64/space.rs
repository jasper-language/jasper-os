//! x86_64 地址空间：PML4 的创建、切换（CR3）与销毁。
//!
//! # 模型
//! * 每个地址空间 = 一张独立的 PML4。
//! * **私有窗口**：PML4 下标 [`USER_FIRST`, `USER_LAST`) 覆盖的虚拟区间归各地址空间私有；
//!   窗口之外的顶级表项在创建时从当前（内核）PML4 原样复制，指向**同一批**下级页表 ⇒ 内核映射在所有空间共享。
//! * 只有本文件知道 PML4、CR3；Core 通过 `Platform` 契约里的 `SpaceRoot`（不透明）使用它。
//!
//! # 内核映射的同步
//! 共享的是下级页表而不是 PML4 本身，所以创建之后在**新的**顶级下标上新增的内核映射不会自动同步。
//! [`prealloc_kernel_half`] 在启动时预分配高半区（下标 256..512）的全部顶级表项；
//! 规则：**此后新增的内核虚拟区一律放在高半区**。低半区现有的内核映射（镜像、栈、堆、物理内存映射）
//! 都在创建任何地址空间之前就已存在，因而已被复制共享。

use kernel_core::frame::{FrameAllocator, PhysFrame, FRAME_SIZE};
use kernel_core::paging::MapError;
use x86_64::registers::control::{Cr3, Cr3Flags};
use x86_64::structures::paging::{PageTable, PageTableFlags, PhysFrame as X86Frame};
use x86_64::PhysAddr;

/// 私有窗口的第一个 PML4 下标（含）。下标 32 ⇒ 0x0000_1000_0000_0000。
pub const USER_FIRST: usize = 32;
/// 私有窗口的最后一个 PML4 下标（不含）。下标 64 ⇒ 0x0000_2000_0000_0000。
pub const USER_LAST: usize = 64;
/// 私有窗口对应的虚拟地址区间 `[start, end)`。
pub const USER_WINDOW: (u64, u64) = ((USER_FIRST as u64) << 39, (USER_LAST as u64) << 39);
// 用户态运行时与用户程序的链接地址按同一数值布局：两边必须一致。
const _: () = assert!(USER_WINDOW.0 == kernel_core::user_layout::WINDOW_BASE_X86_64);

/// 地址空间根：PML4 所在物理帧（不透明地交给 Core）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpaceRoot(pub u64);

/// 经全物理内存映射访问某个物理帧上的页表。
unsafe fn table_at(phys_offset: u64, phys: u64) -> &'static mut PageTable {
    &mut *((phys_offset + phys) as *mut PageTable)
}

/// 当前 CR3 指向的地址空间。
pub fn current() -> SpaceRoot {
    SpaceRoot(Cr3::read().0.start_address().as_u64())
}

/// 新建地址空间：分配并清零一张 PML4，复制私有窗口之外的全部顶级表项。
///
/// 当前空间若在私有窗口里已有映射则拒绝（否则这些映射会被所有空间意外共享）。
///
/// # Safety
/// `phys_offset` 必须是全物理内存映射偏移。
pub unsafe fn create(phys_offset: u64, frames: &mut dyn FrameAllocator) -> Result<SpaceRoot, MapError> {
    let cur = table_at(phys_offset, current().0);
    if (USER_FIRST..USER_LAST).any(|i| !cur[i].is_unused()) {
        return Err(MapError::InvalidAddress);
    }
    let f = frames.allocate().map_err(|_| MapError::OutOfFrames)?;
    let new = table_at(phys_offset, f.start());
    new.zero();
    for i in 0..512 {
        if !(USER_FIRST..USER_LAST).contains(&i) {
            new[i] = cur[i].clone();
        }
    }
    Ok(SpaceRoot(f.start()))
}

/// 把一个物理帧清零并当作「空的顶级表」使用（自检用：在不触碰活动空间的前提下演练预分配的失败路径）。
/// Zero `frame` and treat it as an empty top-level table (self-test scratch root).
///
/// # Safety
/// `frame` 必须是调用者独占、未被任何页表引用的帧；`phys_offset` 为全物理内存映射偏移。
pub unsafe fn empty_root(frame: PhysFrame, phys_offset: u64) -> SpaceRoot {
    table_at(phys_offset, frame.start()).zero();
    SpaceRoot(frame.start())
}

/// 预分配 `root` 的内核半区（PML4 下标 256..512）全部顶级表项，使之后在高半区新增的内核映射
/// 自动对所有地址空间可见（共享的是下级 PDPT）。消除模块文档所述的「新顶级下标不同步」问题。
///
/// **全有或全无**：先为所有空表项分配并清零下级表帧（暂存在本地数组里），任一分配失败 ⇒
/// 归还本次已分配的全部帧并返回错误，`root` 一项都不改；全部成功后才一次性安装。返回新安装的表项数。
/// All-or-nothing: frames are collected first; on any failure they are all freed and `root` is untouched.
///
/// # Safety
/// `root` 必须是有效的顶级表；若为内核空间，必须在创建任何其他地址空间之前调用。
pub unsafe fn prealloc_kernel_half(
    root: SpaceRoot,
    phys_offset: u64,
    frames: &mut dyn FrameAllocator,
) -> Result<usize, MapError> {
    let pml4 = table_at(phys_offset, root.0);
    // 第一阶段：只分配，不安装（256 个槽位足够覆盖整个高半区）
    let mut staged: [Option<PhysFrame>; 256] = [None; 256];
    for i in 256..512 {
        if !pml4[i].is_unused() {
            continue;
        }
        match frames.allocate() {
            Ok(f) => {
                table_at(phys_offset, f.start()).zero();
                staged[i - 256] = Some(f);
            }
            Err(_) => {
                // 回滚：归还本次分配的全部帧，顶级表保持原样
                for f in staged.iter().flatten() {
                    let _ = frames.deallocate(*f);
                }
                return Err(MapError::OutOfFrames);
            }
        }
    }
    // 第二阶段：一次性安装（不会再失败）
    let mut n = 0;
    for (k, f) in staged.iter().enumerate() {
        if let Some(f) = f {
            pml4[256 + k].set_addr(PhysAddr::new(f.start()), PageTableFlags::PRESENT | PageTableFlags::WRITABLE);
            n += 1;
        }
    }
    Ok(n)
}

/// 统计 `root` 内核半区里已使用的顶级表项数（自检用）。
/// Count used top-level entries in the kernel half of `root` (self-test).
///
/// # Safety
/// `root` 必须是有效的顶级表。
pub unsafe fn kernel_half_used(root: SpaceRoot, phys_offset: u64) -> usize {
    let pml4 = table_at(phys_offset, root.0);
    (256..512).filter(|&i| !pml4[i].is_unused()).count()
}

/// 切换到 `root`（写 CR3，隐式刷新非全局 TLB 项）。
///
/// # Safety
/// `root` 必须是由 [`create`] 建立且未销毁的空间（或启动时的内核空间），其中包含当前代码与栈的映射。
pub unsafe fn switch(root: SpaceRoot) {
    let frame = X86Frame::containing_address(PhysAddr::new(root.0));
    Cr3::write(frame, Cr3Flags::empty());
}

/// 销毁地址空间：释放私有窗口内的全部**页表**帧与 PML4 本身（叶子映射指向的数据帧由其所有者负责）。
///
/// # Safety
/// `root` 不能是当前活动空间，也不能再被使用。
pub unsafe fn destroy(root: SpaceRoot, phys_offset: u64, frames: &mut dyn FrameAllocator) {
    let pml4 = table_at(phys_offset, root.0);
    for i in USER_FIRST..USER_LAST {
        free_subtree(&mut pml4[i], 3, phys_offset, frames);
    }
    let _ = frames.deallocate(PhysFrame::from_start(root.0).unwrap_or(PhysFrame::from_number(0)));
}

/// 递归释放一个表项指向的下级页表。`level` = 该表项所指表的层级（3=PDPT, 2=PD, 1=PT）。
unsafe fn free_subtree(
    entry: &mut x86_64::structures::paging::page_table::PageTableEntry,
    level: u8,
    phys_offset: u64,
    frames: &mut dyn FrameAllocator,
) {
    if entry.is_unused() || entry.flags().contains(PageTableFlags::HUGE_PAGE) {
        entry.set_unused();
        return;
    }
    let phys = entry.addr().as_u64();
    if level > 1 {
        let t = table_at(phys_offset, phys);
        for e in t.iter_mut() {
            free_subtree(e, level - 1, phys_offset, frames);
        }
    }
    // level == 1：这是一张 PT，它的表项指向数据帧（不由我们释放），只释放 PT 本身
    let _ = frames.deallocate(PhysFrame::from_start(phys - phys % FRAME_SIZE).unwrap_or(PhysFrame::from_number(0)));
    entry.set_unused();
}
