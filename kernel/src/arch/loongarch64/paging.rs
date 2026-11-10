//! LoongArch64 4 KiB、4 级、48 位软件页表格式。
//!
//! 非叶表项是一个页对齐的物理地址；叶表项使用 LoongArch TLB EntryLo 权限位。
//! 软件页表位域来自 LoongArch `pgtable-bits.h`，硬件页走表由 `PWCTL*` 配置。

use kernel_core::frame::{FrameAllocator, PhysFrame};
use kernel_core::paging::{MapError, MapFlags, PageMapper, VirtPage};
use kernel_core::pagetable::{EntryFormat, PageTable};

pub use crate::arch::phys_tables::PhysTables;

use super::cpu;

pub mod pte {
    pub const VALID: u64 = 1 << 0;
    pub const DIRTY: u64 = 1 << 1;
    pub const PLV_USER: u64 = 3 << 2;
    pub const CACHE_CC: u64 = 1 << 4;
    pub const CACHE_SUC: u64 = 0;
    pub const GLOBAL: u64 = 1 << 6;
    pub const PRESENT: u64 = 1 << 7;
    pub const WRITE: u64 = 1 << 8;
    pub const MODIFIED: u64 = 1 << 9;
    pub const NO_EXEC: u64 = 1 << 62;
    pub const ADDR_MASK: u64 = 0x0000_ffff_ffff_f000;
}

/// LoongArch 64-bit page-table format.
pub struct La64Format;

impl EntryFormat for La64Format {
    const LEVELS: usize = 4;
    const VA_BITS: u32 = 48;

    fn is_valid(raw: u64) -> bool {
        raw != 0
    }

    fn is_table(raw: u64) -> bool {
        raw & pte::PRESENT == 0
    }

    fn table_entry(table_phys: u64) -> u64 {
        table_phys & pte::ADDR_MASK
    }

    fn leaf_entry(frame_phys: u64, flags: MapFlags) -> u64 {
        let mut entry = (frame_phys & pte::ADDR_MASK)
            | pte::PRESENT
            | pte::VALID
            | pte::CACHE_CC;
        if flags.contains(MapFlags::USER) {
            entry |= pte::PLV_USER;
        }
        if flags.contains(MapFlags::WRITE) {
            entry |= pte::WRITE | pte::DIRTY | pte::MODIFIED;
        }
        if flags.contains(MapFlags::GLOBAL) {
            entry |= pte::GLOBAL;
        }
        if !flags.contains(MapFlags::EXECUTE) {
            entry |= pte::NO_EXEC;
        }
        entry
    }

    fn output_address(raw: u64) -> u64 {
        raw & pte::ADDR_MASK
    }

    fn leaf_flags(raw: u64) -> MapFlags {
        let mut flags = MapFlags::READ_ONLY;
        if raw & pte::WRITE != 0 {
            flags = flags | MapFlags::WRITE;
        }
        if raw & pte::PLV_USER != 0 {
            flags = flags | MapFlags::USER;
        }
        if raw & pte::GLOBAL != 0 {
            flags = flags | MapFlags::GLOBAL;
        }
        if raw & pte::NO_EXEC == 0 {
            flags = flags | MapFlags::EXECUTE;
        }
        flags
    }
}

pub type La64Table = PageTable<La64Format, PhysTables>;

pub struct La64Mapper {
    root: u64,
    tables: PhysTables,
}

impl La64Mapper {
    /// # Safety
    /// `root` must address a valid top-level table through the physical direct map.
    pub unsafe fn for_root(root: u64, phys_offset: u64) -> Self {
        Self { root, tables: PhysTables::new(phys_offset) }
    }

    fn table(&self) -> La64Table {
        PageTable::new(self.root, self.tables)
    }

    fn sync_if_executable(flags: MapFlags) {
        if flags.contains(MapFlags::EXECUTE) {
            cpu::sync_icache();
        }
    }
}

impl PageMapper for La64Mapper {
    fn map(
        &mut self,
        page: VirtPage,
        frame: PhysFrame,
        flags: MapFlags,
        frames: &mut dyn FrameAllocator,
    ) -> Result<(), MapError> {
        Self::sync_if_executable(flags);
        self.table().map(page.start(), frame, flags, frames)?;
        cpu::data_barrier();
        cpu::tlb_flush_page(page.start());
        Ok(())
    }

    fn unmap(&mut self, page: VirtPage) -> Result<PhysFrame, MapError> {
        let frame = self.table().unmap(page.start())?;
        cpu::data_barrier();
        cpu::tlb_flush_page(page.start());
        Ok(frame)
    }

    fn translate(&self, page: VirtPage) -> Option<(PhysFrame, MapFlags)> {
        self.table().translate(page.start())
    }

    fn protect(&mut self, page: VirtPage, flags: MapFlags) -> Result<(), MapError> {
        Self::sync_if_executable(flags);
        self.table().protect(page.start(), flags)?;
        cpu::data_barrier();
        cpu::tlb_flush_page(page.start());
        Ok(())
    }
}
