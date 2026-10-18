//! RISC-V Sv39 页映射：3 级、4 KiB 页、只使用 39 位虚拟地址的低半区，实现 Core 的 [`PageMapper`] 契约。
//! RISC-V Sv39 page mapping (3 levels, 4 KiB pages, low half of the 39-bit VA) implementing `PageMapper`.
//!
//! 遍历算法用 `kernel_core::pagetable`、页表内存经共享的 [`PhysTables`] 访问（均与 AArch64 共用）；
//! 本文件只给出**页表项位格式**（[`Sv39Format`]）与修改后的地址转换缓存维护。
//!
//! 中立权限 → 页表项：
//! * 一律置 `R`（RISC-V 不允许「可写不可读」）；`WRITE` ⇒ `W`；`EXECUTE` ⇒ `X`；
//! * `USER` ⇒ `U`：监管态既不能执行 U 页，在 sstatus.SUM = 0（本内核的设置）时也不能读写 U 页——
//!   内核永不执行用户页，用户永不访问内核页；
//! * `GLOBAL` ⇒ `G`；
//! * 访问位 `A` 预置为 1、可写页的脏位 `D` 预置为 1：不依赖硬件更新这两位（硬件不更新时访问会触发缺页）。
//! * 非叶级表项只有 `V`（`R`/`W`/`X` 全 0 即表示「指向下级表」）。

use kernel_core::frame::{FrameAllocator, PhysFrame};
use kernel_core::paging::{MapError, MapFlags, PageMapper, VirtPage};
use kernel_core::pagetable::{EntryFormat, PageTable};

pub use crate::arch::phys_tables::PhysTables;

use super::cpu;

/// 页表项位。
pub mod pte {
    /// 有效。
    pub const V: u64 = 1 << 0;
    /// 可读。
    pub const R: u64 = 1 << 1;
    /// 可写。
    pub const W: u64 = 1 << 2;
    /// 可执行。
    pub const X: u64 = 1 << 3;
    /// 用户态可访问。
    pub const U: u64 = 1 << 4;
    /// 全局（所有地址空间共享）。
    pub const G: u64 = 1 << 5;
    /// 已访问。
    pub const A: u64 = 1 << 6;
    /// 已写。
    pub const D: u64 = 1 << 7;
    /// 物理页号字段（位 10..54）。
    pub const PPN_MASK: u64 = ((1 << 44) - 1) << 10;

    /// 由物理地址得到页表项中的物理页号字段。
    pub const fn ppn(phys: u64) -> u64 {
        ((phys >> 12) << 10) & PPN_MASK
    }

    /// 由页表项取出输出物理地址。
    pub const fn phys(raw: u64) -> u64 {
        ((raw & PPN_MASK) >> 10) << 12
    }
}

/// 本内核使用的虚拟地址位数：Sv39 的低半区 `[0, 2^38)`（高半区要求高位符号扩展，本内核不使用）。
pub const VA_BITS: u32 = 38;

/// Sv39 页表项格式。
/// Sv39 page-table entry format.
pub struct Sv39Format;

impl EntryFormat for Sv39Format {
    const LEVELS: usize = 3;
    const VA_BITS: u32 = VA_BITS;

    fn is_valid(raw: u64) -> bool {
        raw & pte::V != 0
    }

    fn is_table(raw: u64) -> bool {
        raw & (pte::R | pte::W | pte::X) == 0
    }

    fn table_entry(table_phys: u64) -> u64 {
        pte::ppn(table_phys) | pte::V
    }

    fn leaf_entry(frame_phys: u64, flags: MapFlags) -> u64 {
        let mut e = pte::ppn(frame_phys) | pte::V | pte::R | pte::A;
        if flags.contains(MapFlags::WRITE) {
            e |= pte::W | pte::D;
        }
        if flags.contains(MapFlags::EXECUTE) {
            e |= pte::X;
        }
        if flags.contains(MapFlags::USER) {
            e |= pte::U;
        }
        if flags.contains(MapFlags::GLOBAL) {
            e |= pte::G;
        }
        e
    }

    fn output_address(raw: u64) -> u64 {
        pte::phys(raw)
    }

    fn leaf_flags(raw: u64) -> MapFlags {
        let mut f = MapFlags::READ_ONLY;
        if raw & pte::W != 0 {
            f = f | MapFlags::WRITE;
        }
        if raw & pte::X != 0 {
            f = f | MapFlags::EXECUTE;
        }
        if raw & pte::U != 0 {
            f = f | MapFlags::USER;
        }
        if raw & pte::G != 0 {
            f = f | MapFlags::GLOBAL;
        }
        f
    }
}

/// 一棵 Sv39 页表的遍历器。
pub type Sv39Table = PageTable<Sv39Format, PhysTables>;

/// 某个地址空间（顶级表 = satp 所指的表）的映射器。
pub struct Sv39Mapper {
    root: u64,
    tables: PhysTables,
}

impl Sv39Mapper {
    /// 为顶级表 `root` 建立映射器。
    ///
    /// # Safety
    /// `root` 必须是有效的顶级表；`phys_offset` 为全物理内存映射偏移；同一顶级表同时只能有一个映射器修改它。
    pub unsafe fn for_root(root: u64, phys_offset: u64) -> Self {
        Sv39Mapper { root, tables: PhysTables::new(phys_offset) }
    }

    fn table(&self) -> Sv39Table {
        PageTable::new(self.root, self.tables)
    }

    /// 可执行映射生效前同步指令流：内核经全物理内存映射写入的代码必须先对取指可见，RISC-V 不保证两者自动一致。
    fn sync_if_executable(flags: MapFlags) {
        if flags.contains(MapFlags::EXECUTE) {
            cpu::sync_icache();
        }
    }
}

impl PageMapper for Sv39Mapper {
    fn map(&mut self, page: VirtPage, frame: PhysFrame, flags: MapFlags, frames: &mut dyn FrameAllocator) -> Result<(), MapError> {
        Self::sync_if_executable(flags);
        self.table().map(page.start(), frame, flags, frames)?;
        // RISC-V 允许缓存无效表项：无效 → 有效同样要作废该页的转换缓存
        cpu::tlb_flush_page(page.start());
        Ok(())
    }

    fn unmap(&mut self, page: VirtPage) -> Result<PhysFrame, MapError> {
        let f = self.table().unmap(page.start())?;
        cpu::tlb_flush_page(page.start());
        Ok(f)
    }

    fn translate(&self, page: VirtPage) -> Option<(PhysFrame, MapFlags)> {
        self.table().translate(page.start())
    }

    fn protect(&mut self, page: VirtPage, flags: MapFlags) -> Result<(), MapError> {
        Self::sync_if_executable(flags);
        self.table().protect(page.start(), flags)?;
        cpu::tlb_flush_page(page.start());
        Ok(())
    }
}
