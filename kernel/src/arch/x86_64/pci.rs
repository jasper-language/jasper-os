//! x86_64 PCI 配置空间访问：传统端口机制（0xCF8 / 0xCFC）与 ACPI MCFG 给出的 ECAM 窗口。
//! x86_64 PCI config-space access: legacy port mechanism (0xCF8/0xCFC) and the ECAM window from ACPI MCFG.
//!
//! # 职责
//! * 实现 `kernel_core::pci::ConfigSpace` 的两种后端；解码、BAR 探测与总线枚举全部复用 kernel-core，
//!   本文件只负责「怎样碰到配置空间」。
//! * MCFG 存在时优先 ECAM：把窗口映射到内核高半区的一个固定虚拟区间，并置不可缓存（MMIO 语义）；
//!   没有 MCFG 或窗口不可映射时退回传统端口机制。
//! * 传统端口访问用「地址端口 + 数据端口」两个 32 位写 / 读，过程中关中断，避免其它执行流改写地址端口。
//!
//! # 边界
//! * 只读 / 写配置空间，不解释设备语义、不分配 DMA、不注册中断；设备表与启动期枚举在
//!   ISA 无关的 `crate::pci` 中。
//! * ECAM 虚拟窗口固定且只建立一次；建立失败时完整回滚已映射页，再退回端口机制，不留半张映射。

use alloc::boxed::Box;

use kernel_core::acpi;
use kernel_core::frame::PhysFrame;
use kernel_core::paging::{MapFlags, VirtPage};
use kernel_core::pci::{legacy_address, Bdf, ConfigSpace, Ecam};

use super::port::{inl, outl};
use super::smp::PhysWindow;
use crate::arch::{PciAccess, PciMechanism};
use crate::boot::BootSpec;
use crate::mm::map;

/// 传统机制的地址端口。
const CONFIG_ADDRESS: u16 = 0x0CF8;
/// 传统机制的数据端口。
const CONFIG_DATA: u16 = 0x0CFC;
/// ECAM 映射在内核高半区的固定虚拟基址（PML4 下标 288，启动期已预分配）。
const ECAM_VA_BASE: u64 = 0xFFFF_9000_0000_0000;
/// 单个 ECAM 窗口最多映射的字节数（256 条总线 = 256 MiB）。
const MAX_ECAM_BYTES: u64 = 1 << 28;

/// 取得本平台的配置空间访问者（启动期调用一次）。
///
/// 有可用 MCFG 窗口时返回 ECAM 后端，否则返回传统端口后端；两者都不可用时返回 `None`。
/// Returns the platform config-space accessor: ECAM when an MCFG window is usable, otherwise legacy port.
pub fn access(boot: &BootSpec) -> Option<PciAccess> {
    if let Some(window) = ecam_window(boot) {
        if let Some(va) = map_ecam(window) {
            let cfg: &'static mut EcamConfig = Box::leak(Box::new(EcamConfig { window, va }));
            return Some(PciAccess { config: cfg, mechanism: PciMechanism::Ecam, buses: window.buses() });
        }
    }
    let cfg: &'static mut PortConfig = Box::leak(Box::new(PortConfig));
    Some(PciAccess { config: cfg, mechanism: PciMechanism::Port, buses: 0..=u8::MAX })
}

/// 解析 MCFG 并挑出 PCI 段 0 的第一条可用窗口；没有固件表或没有 MCFG 时返回 `None`。
fn ecam_window(boot: &BootSpec) -> Option<Ecam> {
    let offset = boot.phys_offset?;
    let rsdp = boot.acpi_rsdp?;
    let mcfg = acpi::parse_mcfg(&PhysWindow(offset), rsdp).ok()?;
    mcfg.windows().iter().copied().find(|w| w.segment == 0 && !w.is_empty())
}

/// 把 ECAM 窗口映射为不可缓存 MMIO；任一步失败都归还窗口内已建立的映射并返回 `None`。
fn map_ecam(window: Ecam) -> Option<u64> {
    let len = window.len();
    if len == 0 || len > MAX_ECAM_BYTES || window.base % 4096 != 0 || window.base.checked_add(len).is_none() {
        return None;
    }
    let pages = len / 4096;
    let flags = MapFlags::WRITE | MapFlags::GLOBAL | MapFlags::NO_CACHE;
    let mut mapped = 0u64;
    while mapped < pages {
        let page = VirtPage::from_start(ECAM_VA_BASE.checked_add(mapped * 4096)?)?;
        let frame = PhysFrame::from_start(window.base.checked_add(mapped * 4096)?)?;
        if map::map(page, frame, flags).is_err() {
            let mut undo = 0u64;
            while undo < mapped {
                if let Some(p) = VirtPage::from_start(ECAM_VA_BASE + undo * 4096) {
                    let _ = map::unmap(p);
                }
                undo += 1;
            }
            return None;
        }
        mapped += 1;
    }
    Some(ECAM_VA_BASE)
}

/// 传统端口机制后端（无状态；地址由 [`legacy_address`] 编码）。
struct PortConfig;

impl ConfigSpace for PortConfig {
    fn read32(&mut self, bdf: Bdf, offset: u16) -> Option<u32> {
        let address = legacy_address(bdf, offset)?;
        let _guard = IrqGuard::new();
        // SAFETY：0xCF8 / 0xCFC 是 PCI 传统配置机制的标准端口；地址已由 kernel-core 校验为对齐且在前 256 字节内。
        unsafe {
            outl(CONFIG_ADDRESS, address);
            Some(inl(CONFIG_DATA))
        }
    }

    fn write32(&mut self, bdf: Bdf, offset: u16, value: u32) -> bool {
        let Some(address) = legacy_address(bdf, offset) else {
            return false;
        };
        let _guard = IrqGuard::new();
        // SAFETY：同 `read32`；写入的是该功能的配置空间双字。
        unsafe {
            outl(CONFIG_ADDRESS, address);
            outl(CONFIG_DATA, value);
        }
        true
    }
}

/// ECAM 后端：配置空间经固定虚拟窗口访问，窗口在建立时已置不可缓存。
struct EcamConfig {
    window: Ecam,
    va: u64,
}

impl EcamConfig {
    /// 功能 `bdf` 在 `offset` 处的虚拟地址；不在本窗口内或越界时返回 `None`。
    fn address(&self, bdf: Bdf, offset: u16) -> Option<u64> {
        let phys = self.window.address(bdf, offset)?;
        let rel = phys.checked_sub(self.window.base)?;
        self.va.checked_add(rel)
    }
}

impl ConfigSpace for EcamConfig {
    fn read32(&mut self, bdf: Bdf, offset: u16) -> Option<u32> {
        let address = self.address(bdf, offset)?;
        // SAFETY：地址落在本后端建立并验证过的不可缓存 MMIO 窗口内；32 位对齐读。
        Some(unsafe { (address as *const u32).read_volatile() })
    }

    fn write32(&mut self, bdf: Bdf, offset: u16, value: u32) -> bool {
        let Some(address) = self.address(bdf, offset) else {
            return false;
        };
        // SAFETY：同 `read32`；写的是该功能的配置空间双字。
        unsafe { (address as *mut u32).write_volatile(value) };
        true
    }
}

/// 一次传统端口访问期间的关中断守卫：地址端口与数据端口之间不得被其它执行流插入。
struct IrqGuard(bool);

impl IrqGuard {
    fn new() -> Self {
        IrqGuard(crate::arch::irq_save_disable())
    }
}

impl Drop for IrqGuard {
    fn drop(&mut self) {
        crate::arch::irq_restore(self.0);
    }
}
