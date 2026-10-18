//! 引导适配层（按目标指令集二选一）：
//! * x86_64：`bootloader` 0.11（BIOS 镜像）的内核入口——声明引导器配置（要求把全部物理内存线性映射进内核地址空间），
//!   接住引导器入口约定，把 `bootloader_api::BootInfo` 转成与引导协议无关的 `BootSpec`，再交给 `jasper_kernel::kmain::start`；
//! * AArch64 / RISC-V：没有引导器，入口 `_start` 与设备树解析在库的 `arch/<isa>/boot.rs` 中；本文件只保证该入口被链接进二进制。
//!
//! 换引导方式或换 ISA 时，只替换本文件（以及 `arch/<isa>/`）；内核主流程不改。
//! `#[panic_handler]` 在库 crate 的 `panic.rs` 中，保证最终二进制里只有一个。
#![no_std]
#![no_main]

#[cfg(target_arch = "x86_64")]
mod bios {
    use bootloader_api::config::{BootloaderConfig, Mapping};
    use bootloader_api::info::MemoryRegionKind;
    use bootloader_api::BootInfo;
    use jasper_kernel::boot::{self, BootSpec};
    use kernel_core::frame::{PhysRegion, RegionKind};

    /// 引导器配置：全物理内存映射到引导器选定的虚拟地址（偏移经 `BootInfo` 传回）。
    static BOOTLOADER_CONFIG: BootloaderConfig = {
        let mut config = BootloaderConfig::new_default();
        config.mappings.physical_memory = Some(Mapping::Dynamic);
        config
    };

    bootloader_api::entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

    /// 引导器入口：转换交接信息后进入内核主流程。
    fn kernel_main(info: &'static mut BootInfo) -> ! {
        let mut spec = BootSpec::new();
        for r in info.memory_regions.iter() {
            // 只有 Usable 可自由使用；引导器自身的页表/数据、固件未知类型一律视为保留。
            let kind = match r.kind {
                MemoryRegionKind::Usable => RegionKind::Usable,
                _ => RegionKind::Reserved,
            };
            spec.push_region(PhysRegion { start: r.start, end: r.end, kind });
        }
        spec.phys_offset = info.physical_memory_offset.into_option();
        jasper_kernel::kmain::start(boot::install(spec))
    }
}

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
mod direct {
    // 链接内核库（其中有 `#[panic_handler]` 与入口代码）。
    use jasper_kernel as _;

    extern "C" {
        /// 库中定义的内核入口（链接脚本的 `ENTRY`）。
        fn _start() -> !;
    }

    /// 引用入口符号，保证库中定义它的目标文件被链接进来。
    #[used]
    static ENTRY: unsafe extern "C" fn() -> ! = _start;
}
