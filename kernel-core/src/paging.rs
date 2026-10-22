//! 页映射契约（M2.2）：架构无关的「虚拟页 ↔ 物理帧」映射接口。
//!
//! # 职责
//! * [`VirtPage`]：4 KiB 对齐的虚拟页
//! * [`MapFlags`]：**中立**的映射权限位（读/写/执行/用户可访问/全局/不可缓存）——不出现任何 ISA 的 PTE 位
//! * [`PageMapper`]：映射、取消映射、查询、改权限的契约（Strategy：每个 ISA 一个实现）
//! * [`MapError`]：带规范名的错误（`system.memory.error.*`）
//!
//! # 为什么这样分（设计约束：地址空间由 Core 抽象、arch 实现）
//! Core 只描述「要什么映射」；x86_64 用 4 级页表（PML4…PT）实现，AArch64 用 TTBR、RISC-V 用 satp，
//! 各自把 [`MapFlags`] 翻译成自己的表项位。Core 永远不出现 PML4、PTE、CR3 等词。
//!
//! # 约定
//! * 「已映射」即可读：没有「可映射但不可读」的状态，因此 [`MapFlags`] 没有单独的 READ 位
//! * 中间页表所需的物理帧由调用者通过 [`FrameAllocator`] 提供（映射层不自己藏一个分配器）

use crate::frame::{FrameAllocator, PhysFrame, FRAME_SIZE};

/// 一个 4 KiB 对齐的虚拟页（以起始虚拟地址表示）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VirtPage(u64);

impl VirtPage {
    /// 由对齐的起始地址构造；未对齐返回 `None`。
    pub const fn from_start(addr: u64) -> Option<Self> {
        if addr % FRAME_SIZE == 0 {
            Some(VirtPage(addr))
        } else {
            None
        }
    }

    /// 包含该地址的页。
    pub const fn containing(addr: u64) -> Self {
        VirtPage(addr - addr % FRAME_SIZE)
    }

    /// 起始虚拟地址。
    pub const fn start(self) -> u64 {
        self.0
    }
}

/// 中立的映射权限位（位掩码）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MapFlags(u32);

impl MapFlags {
    /// 只读、内核、不可执行（最小权限；其余位按需叠加）。
    pub const READ_ONLY: MapFlags = MapFlags(0);
    /// 可写。
    pub const WRITE: MapFlags = MapFlags(1 << 0);
    /// 可执行。
    pub const EXECUTE: MapFlags = MapFlags(1 << 1);
    /// 用户态可访问。
    pub const USER: MapFlags = MapFlags(1 << 2);
    /// 全局（切换地址空间时不必刷新，用于内核共享半区）。
    pub const GLOBAL: MapFlags = MapFlags(1 << 3);
    /// 不可缓存（MMIO 窗口必须使用，避免 CPU 缓存与设备寄存器语义冲突）。
    /// Uncached mapping, required for MMIO windows.
    pub const NO_CACHE: MapFlags = MapFlags(1 << 4);

    /// 并集。
    pub const fn union(self, other: MapFlags) -> MapFlags {
        MapFlags(self.0 | other.0)
    }

    /// 去掉某些位。
    pub const fn difference(self, other: MapFlags) -> MapFlags {
        MapFlags(self.0 & !other.0)
    }

    /// 是否包含 `other` 的全部位。
    pub const fn contains(self, other: MapFlags) -> bool {
        self.0 & other.0 == other.0
    }

    /// 原始位（诊断用）。
    pub const fn bits(self) -> u32 {
        self.0
    }
}

impl core::ops::BitOr for MapFlags {
    type Output = MapFlags;
    fn bitor(self, rhs: MapFlags) -> MapFlags {
        self.union(rhs)
    }
}

/// 映射错误（`system.memory.error.*`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapError {
    /// 同一地址空间的一次跨核作废尚未完成，本次修改被拒绝。
    Busy,
    /// 该虚拟页已有映射（不允许静默覆盖）。
    AlreadyMapped,
    /// 该虚拟页没有映射。
    NotMapped,
    /// 建立中间页表时没有空闲帧。
    OutOfFrames,
    /// 地址不能在本架构上映射（如 x86_64 的非规范地址）。
    InvalidAddress,
    /// 该地址被更大的页覆盖，无法按 4 KiB 粒度操作。
    HugePage,
}

impl MapError {
    /// 规范错误名（命名约定）。
    pub const fn name(self) -> &'static str {
        match self {
            MapError::Busy => "system.memory.error.busy",
            MapError::AlreadyMapped => "system.memory.error.already_mapped",
            MapError::NotMapped => "system.memory.error.not_mapped",
            MapError::OutOfFrames => "system.memory.error.out_of_frames",
            MapError::InvalidAddress => "system.memory.error.invalid_address",
            MapError::HugePage => "system.memory.error.huge_page",
        }
    }
}

/// 页映射契约。每个 ISA 提供一个实现，作用于某个地址空间的页表。
pub trait PageMapper {
    /// 把 `page` 映射到 `frame`。中间页表从 `frames` 取帧。已映射则返回 [`MapError::AlreadyMapped`]。
    fn map(
        &mut self,
        page: VirtPage,
        frame: PhysFrame,
        flags: MapFlags,
        frames: &mut dyn FrameAllocator,
    ) -> Result<(), MapError>;

    /// 取消映射并返回原来映射的帧（帧本身不释放，由调用者决定归还与否）。
    fn unmap(&mut self, page: VirtPage) -> Result<PhysFrame, MapError>;

    /// 查询映射：返回帧与权限；未映射返回 `None`。
    fn translate(&self, page: VirtPage) -> Option<(PhysFrame, MapFlags)>;

    /// 修改已有映射的权限。
    fn protect(&mut self, page: VirtPage, flags: MapFlags) -> Result<(), MapError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_compose_and_compare() {
        let rw = MapFlags::WRITE | MapFlags::USER;
        assert!(rw.contains(MapFlags::WRITE));
        assert!(rw.contains(MapFlags::READ_ONLY), "只读是最小权限，任何映射都包含它");
        assert!(!rw.contains(MapFlags::EXECUTE));
        assert_eq!(rw.difference(MapFlags::WRITE), MapFlags::USER);
    }

    #[test]
    fn pages_are_aligned() {
        assert_eq!(VirtPage::from_start(0x1001), None);
        assert_eq!(VirtPage::containing(0x1fff).start(), 0x1000);
        assert_eq!(MapError::NotMapped.name(), "system.memory.error.not_mapped");
    }
}
