// Adapted from bootloader-x86_64-uefi 0.11.17, licensed MIT OR Apache-2.0.
// 将 UEFI 内存描述转换为成熟 bootloader 的 legacy allocator 输入。
// Converts UEFI memory descriptors into the mature bootloader's legacy-allocator input.

use bootloader_api::info::MemoryRegionKind;
use bootloader_x86_64_common::legacy_memory_region::LegacyMemoryRegion;
use uefi::boot::{MemoryDescriptor, MemoryType};
use x86_64::PhysAddr;

const PAGE_SIZE: u64 = 4096;

#[derive(Debug, Copy, Clone)]
pub struct UefiMemoryDescriptor(pub MemoryDescriptor);

impl LegacyMemoryRegion for UefiMemoryDescriptor {
    fn start(&self) -> PhysAddr {
        PhysAddr::new(self.0.phys_start)
    }

    fn len(&self) -> u64 {
        self.0.page_count * PAGE_SIZE
    }

    fn kind(&self) -> MemoryRegionKind {
        match self.0.ty {
            MemoryType::CONVENTIONAL => MemoryRegionKind::Usable,
            other => MemoryRegionKind::UnknownUefi(other.0),
        }
    }

    fn usable_after_bootloader_exit(&self) -> bool {
        matches!(
            self.0.ty,
            MemoryType::CONVENTIONAL
                | MemoryType::LOADER_CODE
                | MemoryType::LOADER_DATA
                | MemoryType::BOOT_SERVICES_CODE
                | MemoryType::BOOT_SERVICES_DATA
        )
    }
}
