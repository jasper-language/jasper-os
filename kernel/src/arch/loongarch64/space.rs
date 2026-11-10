//! LoongArch64 地址空间：PGDL/PGDH、私有窗口和共享内核顶级表项。

use kernel_core::frame::{FrameAllocator, PhysFrame, FRAME_SIZE};
use kernel_core::paging::{MapError, MapFlags};
use kernel_core::pagetable::PageTable;

use super::cpu::{self, write_csr};
use super::paging::{pte, La64Table, PhysTables};

/// Private user top-level entries start at 0x1000_0000_0000.
pub const USER_FIRST: usize = 32;
/// Private user top-level entries end at 0x2000_0000_0000.
pub const USER_LAST: usize = 64;
pub const USER_WINDOW: (u64, u64) = ((USER_FIRST as u64) << 39, (USER_LAST as u64) << 39);

/// Shared kernel top-level entries start at 0x4000_0000_0000.
pub const KERNEL_FIRST: usize = 128;
pub const KERNEL_LAST: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpaceRoot(pub u64);

unsafe fn table(root: u64, phys_offset: u64) -> La64Table {
    PageTable::new(root, PhysTables::new(phys_offset))
}

pub fn current() -> SpaceRoot {
    SpaceRoot(cpu::read_csr!("0x19") & pte::ADDR_MASK)
}

/// # Safety
/// `phys_offset` must select a coherent physical direct map and `template` must be valid.
pub unsafe fn create(
    template: SpaceRoot,
    phys_offset: u64,
    frames: &mut dyn FrameAllocator,
) -> Result<SpaceRoot, MapError> {
    if table(template.0, phys_offset).used_top(USER_FIRST..USER_LAST) != 0 {
        return Err(MapError::InvalidAddress);
    }
    let frame = frames.allocate().map_err(|_| MapError::OutOfFrames)?;
    let mut output = empty_table(frame, phys_offset);
    output.adopt_top_except(template.0, USER_FIRST..USER_LAST);
    Ok(SpaceRoot(frame.start()))
}

unsafe fn empty_table(frame: PhysFrame, phys_offset: u64) -> La64Table {
    core::ptr::write_bytes(
        (phys_offset + frame.start()) as *mut u8,
        0,
        FRAME_SIZE as usize,
    );
    table(frame.start(), phys_offset)
}

/// # Safety
/// `frame` must be exclusively owned and not referenced by a page table.
pub unsafe fn empty_root(frame: PhysFrame, phys_offset: u64) -> SpaceRoot {
    empty_table(frame, phys_offset);
    SpaceRoot(frame.start())
}

/// # Safety
/// `root` must be a valid top-level table.
pub unsafe fn prealloc_kernel_part(
    root: SpaceRoot,
    phys_offset: u64,
    frames: &mut dyn FrameAllocator,
) -> Result<usize, MapError> {
    let installed = table(root.0, phys_offset).prealloc_top(KERNEL_FIRST..KERNEL_LAST, frames)?;
    cpu::data_barrier();
    Ok(installed)
}

/// # Safety
/// `root` must be a valid top-level table.
pub unsafe fn kernel_part_used(root: SpaceRoot, phys_offset: u64) -> usize {
    table(root.0, phys_offset).used_top(KERNEL_FIRST..KERNEL_LAST)
}

/// # Safety
/// `root` must remain immutable for the duration of the query.
pub unsafe fn translate(
    root: SpaceRoot,
    phys_offset: u64,
    va: u64,
) -> Option<(PhysFrame, MapFlags)> {
    table(root.0, phys_offset).translate(va)
}

/// # Safety
/// `root` must contain the current instruction and stack mappings.
pub unsafe fn switch(root: SpaceRoot) {
    write_csr!("0x19", root.0);
    write_csr!("0x1a", root.0);
    cpu::data_barrier();
    cpu::tlb_flush_all();
}

/// # Safety
/// `root` must not be active and must never be used again.
pub unsafe fn destroy(root: SpaceRoot, phys_offset: u64, frames: &mut dyn FrameAllocator) {
    table(root.0, phys_offset).free_tables(USER_FIRST..USER_LAST, frames);
    if let Some(frame) = PhysFrame::from_start(root.0) {
        let _ = frames.deallocate(frame);
    }
}
