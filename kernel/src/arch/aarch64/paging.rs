//! AArch64 页映射：4 KiB 粒度、4 级、47 位虚拟地址的阶段 1 转换表，实现 Core 的 [`PageMapper`] 契约。
//! AArch64 page mapping (4 KiB granule, 4 levels, 47-bit VA) implementing the Core `PageMapper`.
//!
//! 遍历算法用 `kernel_core::pagetable`（与 RISC-V 共享）；本文件只给出**描述符位格式**（[`A64Format`]）、
//! 「经全物理内存映射访问页表」（[`PhysTables`]）与修改后的 TLB 维护。
//!
//! 中立权限 → 描述符：
//! * `USER` ⇒ AP[1]=1（EL0 可访问）且 nG=1（随地址空间切换失效）；
//! * 无 `WRITE` ⇒ AP[2]=1（只读）；
//! * `EXECUTE` ⇒ 用户页只清 UXN、内核页只清 PXN——内核永不执行用户页，用户永不执行内核页；
//! * 一律为普通内存（写回缓存）、内部共享、访问标志预置（不依赖硬件更新访问位）。

use kernel_core::frame::{FrameAllocator, PhysFrame};
use kernel_core::paging::{MapError, MapFlags, PageMapper, VirtPage};
use kernel_core::pagetable::{EntryFormat, PageTable, TableMemory, ENTRIES};

use super::cpu;

/// 描述符位。
pub mod desc {
    /// 有效。
    pub const VALID: u64 = 1 << 0;
    /// 非叶级：指向下级表；叶级（第 3 级）：页描述符。两者编码相同。
    pub const TABLE_OR_PAGE: u64 = 1 << 1;
    /// 内存属性索引 0：普通内存，写回缓存（见 `mmu.rs` 的 MAIR）。
    pub const ATTR_NORMAL: u64 = 0 << 2;
    /// 内存属性索引 1：设备内存 nGnRE。
    pub const ATTR_DEVICE: u64 = 1 << 2;
    /// AP[1]：EL0 可访问。
    pub const AP_EL0: u64 = 1 << 6;
    /// AP[2]：只读。
    pub const AP_RO: u64 = 1 << 7;
    /// 内部共享。
    pub const SH_INNER: u64 = 3 << 8;
    /// 访问标志（预置为 1）。
    pub const AF: u64 = 1 << 10;
    /// 非全局（按地址空间区分）。
    pub const NG: u64 = 1 << 11;
    /// EL1 不可执行。
    pub const PXN: u64 = 1 << 53;
    /// EL0 不可执行。
    pub const UXN: u64 = 1 << 54;
    /// 输出地址字段。
    pub const ADDR_MASK: u64 = 0x0000_ffff_ffff_f000;
}

/// 本内核使用的虚拟地址位数（TTBR0 覆盖 `[0, 2^47)`）。
pub const VA_BITS: u32 = 47;

/// AArch64 阶段 1 描述符格式。
/// AArch64 stage-1 descriptor format.
pub struct A64Format;

impl EntryFormat for A64Format {
    const LEVELS: usize = 4;
    const VA_BITS: u32 = VA_BITS;

    fn is_valid(raw: u64) -> bool {
        raw & desc::VALID != 0
    }

    fn is_table(raw: u64) -> bool {
        raw & desc::TABLE_OR_PAGE != 0
    }

    fn table_entry(table_phys: u64) -> u64 {
        (table_phys & desc::ADDR_MASK) | desc::VALID | desc::TABLE_OR_PAGE
    }

    fn leaf_entry(frame_phys: u64, flags: MapFlags) -> u64 {
        let mut e = (frame_phys & desc::ADDR_MASK) | desc::VALID | desc::TABLE_OR_PAGE | desc::ATTR_NORMAL | desc::SH_INNER | desc::AF;
        let user = flags.contains(MapFlags::USER);
        if user {
            e |= desc::AP_EL0;
        }
        if !flags.contains(MapFlags::WRITE) {
            e |= desc::AP_RO;
        }
        if !flags.contains(MapFlags::GLOBAL) {
            e |= desc::NG;
        }
        e |= match (flags.contains(MapFlags::EXECUTE), user) {
            (true, true) => desc::PXN,
            (true, false) => desc::UXN,
            (false, _) => desc::PXN | desc::UXN,
        };
        e
    }

    fn output_address(raw: u64) -> u64 {
        raw & desc::ADDR_MASK
    }

    fn leaf_flags(raw: u64) -> MapFlags {
        let mut f = MapFlags::READ_ONLY;
        let user = raw & desc::AP_EL0 != 0;
        if raw & desc::AP_RO == 0 {
            f = f | MapFlags::WRITE;
        }
        if user {
            f = f | MapFlags::USER;
        }
        if raw & desc::NG == 0 {
            f = f | MapFlags::GLOBAL;
        }
        let exec = if user { raw & desc::UXN == 0 } else { raw & desc::PXN == 0 };
        if exec {
            f = f | MapFlags::EXECUTE;
        }
        f
    }
}

/// 经全物理内存映射读写页表。
/// Page-table memory reached through the linear physical map.
#[derive(Clone, Copy)]
pub struct PhysTables {
    offset: u64,
}

impl PhysTables {
    /// `offset` 为全物理内存映射偏移。
    ///
    /// # Safety
    /// 之后交给遍历器的表地址都必须是有效页表所在的物理帧。
    pub unsafe fn new(offset: u64) -> Self {
        PhysTables { offset }
    }

    fn slot(&self, table: u64, index: usize) -> *mut u64 {
        debug_assert!(index < ENTRIES);
        (self.offset + table + index as u64 * 8) as *mut u64
    }
}

impl TableMemory for PhysTables {
    fn read(&self, table: u64, index: usize) -> u64 {
        // SAFETY：构造者保证 `table` 是有效页表；下标由遍历器限制在 512 以内。
        unsafe { self.slot(table, index).read_volatile() }
    }

    fn write(&mut self, table: u64, index: usize, raw: u64) {
        // SAFETY：同上。
        unsafe { self.slot(table, index).write_volatile(raw) }
    }

    fn zero(&mut self, table: u64) {
        for i in 0..ENTRIES {
            self.write(table, i, 0);
        }
    }
}

/// 一棵 AArch64 页表的遍历器。
pub type A64Table = PageTable<A64Format, PhysTables>;

/// 某个地址空间（顶级表 = TTBR0 所指的表）的映射器。
pub struct A64Mapper {
    root: u64,
    tables: PhysTables,
}

impl A64Mapper {
    /// 为顶级表 `root` 建立映射器。
    ///
    /// # Safety
    /// `root` 必须是有效的顶级表；`phys_offset` 为全物理内存映射偏移；同一顶级表同时只能有一个映射器修改它。
    pub unsafe fn for_root(root: u64, phys_offset: u64) -> Self {
        A64Mapper { root, tables: PhysTables::new(phys_offset) }
    }

    fn table(&self) -> A64Table {
        PageTable::new(self.root, self.tables)
    }
}

impl PageMapper for A64Mapper {
    fn map(&mut self, page: VirtPage, frame: PhysFrame, flags: MapFlags, frames: &mut dyn FrameAllocator) -> Result<(), MapError> {
        self.table().map(page.start(), frame, flags, frames)?;
        // 无效 → 有效不需要作废 TLB，只需让表写入对遍历可见
        cpu::table_write_barrier();
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
        self.table().protect(page.start(), flags)?;
        cpu::tlb_flush_page(page.start());
        Ok(())
    }
}
