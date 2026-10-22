//! AArch64 页映射：4 KiB 粒度、4 级、47 位虚拟地址的阶段 1 转换表，实现 Core 的 [`PageMapper`] 契约。
//! AArch64 page mapping (4 KiB granule, 4 levels, 47-bit VA) implementing the Core `PageMapper`.
//!
//! 遍历算法用 `kernel_core::pagetable`、页表内存经共享的 [`PhysTables`] 访问（均与 RISC-V 共用）；本文件只给出**描述符位格式**（[`A64Format`]）
//! 与修改后的 TLB 维护。
//!
//! 中立权限 → 描述符：
//! * `USER` ⇒ AP[1]=1（EL0 可访问）且 nG=1（随地址空间切换失效）；
//! * 无 `WRITE` ⇒ AP[2]=1（只读）；
//! * `EXECUTE` ⇒ 用户页只清 UXN、内核页只清 PXN——内核永不执行用户页，用户永不执行内核页；
//! * 带 `NO_CACHE` 的映射用设备内存属性（nGnRE），其余为普通内存（写回缓存）；内部共享、访问标志预置
//!   （不依赖硬件更新访问位）。

use kernel_core::frame::{FrameAllocator, PhysFrame};
use kernel_core::paging::{MapError, MapFlags, PageMapper, VirtPage};
use kernel_core::pagetable::{EntryFormat, PageTable};

pub use crate::arch::phys_tables::PhysTables;

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
        let attr = if flags.contains(MapFlags::NO_CACHE) { desc::ATTR_DEVICE } else { desc::ATTR_NORMAL };
        let mut e = (frame_phys & desc::ADDR_MASK) | desc::VALID | desc::TABLE_OR_PAGE | attr | desc::SH_INNER | desc::AF;
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
        if raw & desc::ATTR_DEVICE != 0 {
            f = f | MapFlags::NO_CACHE;
        }
        let exec = if user { raw & desc::UXN == 0 } else { raw & desc::PXN == 0 };
        if exec {
            f = f | MapFlags::EXECUTE;
        }
        f
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

    /// 可执行映射生效前同步该帧的指令缓存：内核经全物理内存映射写入的代码（ELF 段、复制的机器码、
    /// 用户程序改为可执行的页）必须先对取指可见，AArch64 不保证数据写入与取指自动一致。
    fn sync_if_executable(&self, frame: PhysFrame, flags: MapFlags) {
        if flags.contains(MapFlags::EXECUTE) {
            cpu::sync_icache(self.tables.offset() + frame.start(), kernel_core::frame::FRAME_SIZE);
        }
    }
}

impl PageMapper for A64Mapper {
    fn map(&mut self, page: VirtPage, frame: PhysFrame, flags: MapFlags, frames: &mut dyn FrameAllocator) -> Result<(), MapError> {
        self.sync_if_executable(frame, flags);
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
        if let Some((frame, _)) = self.table().translate(page.start()) {
            self.sync_if_executable(frame, flags);
        }
        self.table().protect(page.start(), flags)?;
        cpu::tlb_flush_page(page.start());
        Ok(())
    }
}
