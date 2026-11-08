//! Hardware second-level page tables for HWV-1.
//!
//! The tables are real 4 KiB resident paging structures. Intel vCPUs use the
//! EPT entry format and AMD vCPUs use the NPT format. HWV-1 builds and
//! validates these tables but never installs them into a VMCS/VMCB or enters a
//! guest; those activation steps belong to HWV-2/HWV-3.

use kernel_core::frame::{PhysFrame, FRAME_SIZE};
use kernel_core::hwvirt::Backend;
use kernel_core::hwvirt_vcpu::{GuestPermissions, MAX_GPA};
use kernel_core::pagetable::{EntryFormat, PageTable, TableMemory};
use kernel_core::paging::MapFlags;

use crate::mm::map::GlobalFrames;

const PHYSICAL_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;

/// Four-level Intel EPT entry format. Guest permissions are independent from
/// host permissions; read is mandatory in the current object contract.
#[derive(Clone, Copy, Debug)]
pub struct EptFormat;

impl EntryFormat for EptFormat {
    const LEVELS: usize = 4;
    const VA_BITS: u32 = 48;

    fn is_valid(raw: u64) -> bool {
        raw & 1 != 0
    }

    fn is_table(raw: u64) -> bool {
        raw & 0b111 == 0b111
    }

    fn table_entry(table_phys: u64) -> u64 {
        table_phys | 0b111
    }

    fn leaf_entry(frame_phys: u64, flags: MapFlags) -> u64 {
        let mut entry = frame_phys | 1;
        if flags.contains(MapFlags::WRITE) {
            entry |= 1 << 1;
        }
        if flags.contains(MapFlags::EXECUTE) {
            entry |= 1 << 2;
        }
        // EPT memory type 6 is write-back; type 0 is uncached.
        if !flags.contains(MapFlags::NO_CACHE) {
            entry |= 6 << 3;
        }
        entry
    }

    fn output_address(raw: u64) -> u64 {
        raw & PHYSICAL_ADDRESS_MASK
    }

    fn leaf_flags(raw: u64) -> MapFlags {
        let mut flags = MapFlags::READ_ONLY;
        if raw & (1 << 1) != 0 {
            flags = flags | MapFlags::WRITE;
        }
        if raw & (1 << 2) != 0 {
            flags = flags | MapFlags::EXECUTE;
        }
        if raw & (0b111 << 3) == 0 {
            flags = flags | MapFlags::NO_CACHE;
        }
        flags
    }
}

/// Four-level AMD NPT entry format using the standard x86 present/write/NX
/// bits. The guest-physical window is the same 48-bit contract as EPT.
#[derive(Clone, Copy, Debug)]
pub struct NptFormat;

impl EntryFormat for NptFormat {
    const LEVELS: usize = 4;
    const VA_BITS: u32 = 48;

    fn is_valid(raw: u64) -> bool {
        raw & 1 != 0
    }

    fn is_table(raw: u64) -> bool {
        raw & (1 << 7) == 0
    }

    fn table_entry(table_phys: u64) -> u64 {
        table_phys | 0b11
    }

    fn leaf_entry(frame_phys: u64, flags: MapFlags) -> u64 {
        let mut entry = frame_phys | 1;
        if flags.contains(MapFlags::WRITE) {
            entry |= 1 << 1;
        }
        if flags.contains(MapFlags::NO_CACHE) {
            entry |= 1 << 4;
        }
        if !flags.contains(MapFlags::EXECUTE) {
            entry |= 1 << 63;
        }
        entry
    }

    fn output_address(raw: u64) -> u64 {
        raw & PHYSICAL_ADDRESS_MASK
    }

    fn leaf_flags(raw: u64) -> MapFlags {
        let mut flags = MapFlags::READ_ONLY;
        if raw & (1 << 1) != 0 {
            flags = flags | MapFlags::WRITE;
        }
        if raw & (1 << 63) == 0 {
            flags = flags | MapFlags::EXECUTE;
        }
        if raw & (1 << 4) != 0 {
            flags = flags | MapFlags::NO_CACHE;
        }
        flags
    }
}

#[derive(Clone, Copy)]
struct PhysicalMemory {
    offset: u64,
}

impl PhysicalMemory {
    fn slot(self, table: u64, index: usize) -> usize {
        (self.offset + table + (index * 8) as u64) as usize
    }
}

impl TableMemory for PhysicalMemory {
    const ENTRY_BYTES: usize = 8;

    fn read(&self, table: u64, index: usize) -> u64 {
        let slot = self.slot(table, index);
        // SAFETY: `SecondLevel` installs only frames allocated by the global
        // frame allocator, and the walker keeps every index within 0..512.
        unsafe { (slot as *const u64).read_volatile() }
    }

    fn write(&mut self, table: u64, index: usize, raw: u64) {
        let slot = self.slot(table, index);
        // SAFETY: same validity and bounds argument as `read`.
        unsafe { (slot as *mut u64).write_volatile(raw) }
    }

    fn zero(&mut self, table: u64) {
        for index in 0..512 {
            self.write(table, index, 0);
        }
    }
}

enum Table {
    Ept(PageTable<EptFormat, PhysicalMemory>),
    Npt(PageTable<NptFormat, PhysicalMemory>),
}

impl Table {
    fn map(
        &mut self,
        guest: u64,
        frame: PhysFrame,
        permissions: GuestPermissions,
    ) -> Result<(), kernel_core::paging::MapError> {
        let flags = map_flags(permissions);
        match self {
            Table::Ept(table) => table.map(guest, frame, flags, &mut GlobalFrames),
            Table::Npt(table) => table.map(guest, frame, flags, &mut GlobalFrames),
        }
    }

    fn unmap_and_prune(&mut self, guest: u64) -> Result<PhysFrame, kernel_core::paging::MapError> {
        match self {
            Table::Ept(table) => table.unmap_and_prune(guest, &mut GlobalFrames),
            Table::Npt(table) => table.unmap_and_prune(guest, &mut GlobalFrames),
        }
    }

    fn translate(&self, guest: u64) -> Option<PhysFrame> {
        match self {
            Table::Ept(table) => table.translate(guest).map(|(frame, _)| frame),
            Table::Npt(table) => table.translate(guest).map(|(frame, _)| frame),
        }
    }

    fn free_tables(&mut self) {
        match self {
            Table::Ept(table) => {
                table.free_tables(0..PageTable::<EptFormat, PhysicalMemory>::ENTRIES, &mut GlobalFrames);
            }
            Table::Npt(table) => {
                table.free_tables(0..PageTable::<NptFormat, PhysicalMemory>::ENTRIES, &mut GlobalFrames);
            }
        }
    }
}

fn map_flags(permissions: GuestPermissions) -> MapFlags {
    let mut flags = MapFlags::READ_ONLY;
    if permissions.write {
        flags = flags | MapFlags::WRITE;
    }
    if permissions.execute {
        flags = flags | MapFlags::EXECUTE;
    }
    flags
}

/// One vCPU's isolated guest-physical address space.
pub struct SecondLevel {
    backend: Backend,
    root: PhysFrame,
    table: Table,
}

impl SecondLevel {
    pub fn new(backend: Backend) -> Result<Self, kernel_core::paging::MapError> {
        let offset = crate::boot::get()
            .and_then(|boot| boot.phys_offset)
            .ok_or(kernel_core::paging::MapError::NotMapped)?;
        let root = crate::mm::frame::allocate()
            .map_err(|_| kernel_core::paging::MapError::OutOfFrames)?;
        let Some(root_ptr) = crate::mm::phys_to_virt(root.start()) else {
            let _ = crate::mm::frame::deallocate(root);
            return Err(kernel_core::paging::MapError::NotMapped);
        };
        // SAFETY: the frame was just allocated and is not reachable from any
        // page table. The full-physical map makes all 4096 bytes writable.
        unsafe { core::ptr::write_bytes(root_ptr, 0, FRAME_SIZE as usize) };

        let memory = PhysicalMemory { offset };
        let table = match backend {
            Backend::Vmx => Table::Ept(PageTable::new(root.start(), memory)),
            Backend::Svm => Table::Npt(PageTable::new(root.start(), memory)),
        };
        Ok(Self { backend, root, table })
    }

    pub fn backend(&self) -> Backend {
        self.backend
    }

    pub fn root_physical(&self) -> u64 {
        self.root.start()
    }

    /// Install a range of physically backed 4 KiB pages. Newly created paging
    /// structures are removed again if any page fails.
    pub fn map(
        &mut self,
        guest_start: u64,
        frames: &[PhysFrame],
        permissions: GuestPermissions,
    ) -> Result<(), kernel_core::paging::MapError> {
        for (index, frame) in frames.iter().copied().enumerate() {
            let guest = guest_start + index as u64 * FRAME_SIZE;
            if let Err(error) = self.table.map(guest, frame, permissions) {
                for mapped in 0..index {
                    let rollback_guest = guest_start + mapped as u64 * FRAME_SIZE;
                    let _ = self.table.unmap_and_prune(rollback_guest);
                }
                return Err(error);
            }
        }
        Ok(())
    }

    /// Remove a range. Every now-empty intermediate table is returned to the
    /// global frame allocator.
    pub fn unmap(
        &mut self,
        guest_start: u64,
        pages: u64,
    ) -> Result<(), kernel_core::paging::MapError> {
        for index in 0..pages {
            let guest = guest_start + index * FRAME_SIZE;
            self.table.unmap_and_prune(guest)?;
        }
        Ok(())
    }

    pub fn translate(&self, guest: u64) -> Option<PhysFrame> {
        if guest >= MAX_GPA {
            return None;
        }
        self.table.translate(guest)
    }
}

impl Drop for SecondLevel {
    fn drop(&mut self) {
        self.table.free_tables();
        let _ = crate::mm::frame::deallocate(self.root);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ept_and_npt_leaf_bits_remain_vendor_specific() {
        let ept = EptFormat::leaf_entry(0xa000, MapFlags::WRITE | MapFlags::EXECUTE);
        assert_eq!(ept & 0b111, 0b111);
        assert_eq!((ept >> 3) & 0b111, 6);
        assert!(EptFormat::leaf_flags(ept).contains(MapFlags::WRITE));
        assert!(EptFormat::leaf_flags(ept).contains(MapFlags::EXECUTE));

        let npt = NptFormat::leaf_entry(0xb000, MapFlags::WRITE);
        assert_eq!(npt & 0b11, 0b11);
        assert_ne!(npt & (1 << 63), 0);
        assert!(NptFormat::leaf_flags(npt).contains(MapFlags::WRITE));
        assert!(!NptFormat::leaf_flags(npt).contains(MapFlags::EXECUTE));
    }
}
