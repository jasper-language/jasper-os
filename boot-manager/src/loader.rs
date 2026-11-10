// Adapted from bootloader-x86_64-uefi 0.11.17, licensed MIT OR Apache-2.0.
// 复用成熟 bootloader 的 ELF 装载、页表、framebuffer 与跳转逻辑。
// Reuses the mature bootloader's ELF loading, page-table, framebuffer and transfer logic.

use bootloader_api::info::FrameBufferInfo;
use bootloader_boot_config::BootConfig;
use bootloader_x86_64_common::{
    legacy_memory_region::LegacyFrameAllocator, Kernel, PageTables, RawFrameBufferInfo, SystemInfo,
};
use core::slice;
use uefi::boot;
use uefi::mem::memory_map::{MemoryMap, MemoryMapMut};
use uefi::table::cfg::ConfigTableEntry;
use uefi::{
    boot::ScopedProtocol,
    proto::console::gop::{GraphicsOutput, PixelFormat},
};
use x86_64::{
    structures::paging::{FrameAllocator, OffsetPageTable, PageTable, PhysFrame, Size4KiB},
    PhysAddr, VirtAddr,
};

use crate::memory_descriptor::UefiMemoryDescriptor;

/// 从已校验内核字节启动；成功路径不会返回。
/// Boots from verified kernel bytes; the success path never returns.
pub fn boot(kernel_bytes: &'static mut [u8]) -> ! {
    let kernel = Kernel::parse(kernel_bytes);
    let mut config = BootConfig::default();
    #[allow(deprecated)]
    {
        if config.frame_buffer.minimum_framebuffer_height.is_none() {
            config.frame_buffer.minimum_framebuffer_height =
                kernel.config.frame_buffer.minimum_framebuffer_height;
        }
        if config.frame_buffer.minimum_framebuffer_width.is_none() {
            config.frame_buffer.minimum_framebuffer_width =
                kernel.config.frame_buffer.minimum_framebuffer_width;
        }
    }
    let framebuffer = init_logger(&config);
    log::info!("Jasper-OS mature bootloader common starting");

    log::trace!("exiting boot services");
    let mut memory_map = unsafe { boot::exit_boot_services(None) };
    memory_map.sort();
    let mut frame_allocator =
        LegacyFrameAllocator::new(memory_map.entries().copied().map(UefiMemoryDescriptor));
    let max_phys_addr = frame_allocator.max_phys_addr();
    let page_tables = create_page_tables(&mut frame_allocator, max_phys_addr, framebuffer.as_ref());
    let system_info = SystemInfo {
        framebuffer,
        rsdp_addr: uefi::system::with_config_table(|entries| {
            entries
                .iter()
                .find(|entry| matches!(entry.guid, ConfigTableEntry::ACPI2_GUID))
                .or_else(|| {
                    entries
                        .iter()
                        .find(|entry| matches!(entry.guid, ConfigTableEntry::ACPI_GUID))
                })
                .map(|entry| PhysAddr::new(entry.address as u64))
        }),
        ramdisk_addr: None,
        ramdisk_len: 0,
    };
    bootloader_x86_64_common::load_and_switch_to_kernel(
        kernel,
        config,
        frame_allocator,
        page_tables,
        system_info,
    );
}

fn create_page_tables(
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    max_phys_addr: PhysAddr,
    frame_buffer: Option<&RawFrameBufferInfo>,
) -> PageTables {
    let phys_offset = VirtAddr::new(0);
    let bootloader_page_table = {
        let old_table = {
            let frame = x86_64::registers::control::Cr3::read().0;
            let ptr: *const PageTable = (phys_offset + frame.start_address().as_u64()).as_ptr();
            unsafe { &*ptr }
        };
        let new_frame = frame_allocator
            .allocate_frame()
            .expect("failed to allocate bootloader PML4");
        let new_table: &mut PageTable = {
            let ptr: *mut PageTable =
                (phys_offset + new_frame.start_address().as_u64()).as_mut_ptr();
            unsafe {
                ptr.write(PageTable::new());
                &mut *ptr
            }
        };
        let end_addr = VirtAddr::new(max_phys_addr.as_u64() - 1);
        for p4 in 0..=usize::from(end_addr.p4_index()) {
            new_table[p4] = old_table[p4].clone();
        }
        if let Some(frame_buffer) = frame_buffer {
            let start_addr = VirtAddr::new(frame_buffer.addr.as_u64());
            let end_addr = start_addr + frame_buffer.info.byte_len as u64;
            for p4 in usize::from(start_addr.p4_index())..=usize::from(end_addr.p4_index()) {
                new_table[p4] = old_table[p4].clone();
            }
        }
        unsafe {
            x86_64::registers::control::Cr3::write(
                new_frame,
                x86_64::registers::control::Cr3Flags::empty(),
            );
            OffsetPageTable::new(&mut *new_table, phys_offset)
        }
    };

    let (kernel_page_table, kernel_level_4_frame) = {
        let frame: PhysFrame = frame_allocator
            .allocate_frame()
            .expect("failed to allocate kernel PML4");
        let addr = phys_offset + frame.start_address().as_u64();
        let ptr = addr.as_mut_ptr();
        unsafe { *ptr = PageTable::new() };
        let level_4_table = unsafe { &mut *ptr };
        (
            unsafe { OffsetPageTable::new(level_4_table, phys_offset) },
            frame,
        )
    };
    PageTables {
        bootloader: bootloader_page_table,
        kernel: kernel_page_table,
        kernel_level_4_frame,
    }
}

fn init_logger(config: &BootConfig) -> Option<RawFrameBufferInfo> {
    let handle = boot::get_handle_for_protocol::<GraphicsOutput>().ok()?;
    let mut gop: ScopedProtocol<GraphicsOutput> = boot::open_protocol_exclusive(handle).ok()?;
    let mode = {
        let modes = gop.modes();
        match (
            config
                .frame_buffer
                .minimum_framebuffer_height
                .map(|value| usize::try_from(value).unwrap()),
            config
                .frame_buffer
                .minimum_framebuffer_width
                .map(|value| usize::try_from(value).unwrap()),
        ) {
            (Some(height), Some(width)) => modes
                .filter(|mode| {
                    let (mode_width, mode_height) = mode.info().resolution();
                    mode_height >= height && mode_width >= width
                })
                .last(),
            (Some(height), None) => modes
                .filter(|mode| mode.info().resolution().1 >= height)
                .last(),
            (None, Some(width)) => modes
                .filter(|mode| mode.info().resolution().0 >= width)
                .last(),
            _ => None,
        }
    };
    if let Some(mode) = mode {
        gop.set_mode(&mode).expect("failed to set framebuffer mode");
    }
    let mode_info = gop.current_mode_info();
    let mut framebuffer = gop.frame_buffer();
    let slice = unsafe { slice::from_raw_parts_mut(framebuffer.as_mut_ptr(), framebuffer.size()) };
    let info = FrameBufferInfo {
        byte_len: framebuffer.size(),
        width: mode_info.resolution().0,
        height: mode_info.resolution().1,
        pixel_format: match mode_info.pixel_format() {
            PixelFormat::Rgb => bootloader_api::info::PixelFormat::Rgb,
            PixelFormat::Bgr => bootloader_api::info::PixelFormat::Bgr,
            PixelFormat::Bitmask | PixelFormat::BltOnly => {
                panic!("unsupported framebuffer pixel format")
            }
        },
        bytes_per_pixel: 4,
        stride: mode_info.stride(),
    };
    bootloader_x86_64_common::init_logger(
        slice,
        info,
        config.log_level,
        config.frame_buffer_logging,
        config.serial_logging,
    );
    Some(RawFrameBufferInfo {
        addr: PhysAddr::new(framebuffer.as_mut_ptr() as u64),
        info,
    })
}
