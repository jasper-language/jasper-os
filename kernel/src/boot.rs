//! 引导交接信息（架构与引导协议无关）。
//!
//! 引导适配层（`main.rs`：x86_64 + `bootloader` 0.11）把引导器给的原始信息转换成 [`BootSpec`]，
//! 交给 [`crate::kmain::start`]。内核其余部分只认这里的类型，不认 `bootloader_api`、UEFI 表
//! 或设备树——换引导方式时只改适配层。
//!
//! 生命周期：`BootSpec` 在启动最早期由 [`install`] 放进 `'static` 存储，之后只读。

use kernel_core::frame::PhysRegion;
use kernel_core::psci::Conduit;
use spin::Once;

/// 最多记录的物理内存区域数（超出部分计入 `dropped_regions`，不静默丢弃）。
pub const MAX_REGIONS: usize = 128;

/// 帧缓冲像素格式（与设备树 `simple-framebuffer` 的常见取值对应）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameBufferFormat {
    /// 16 位 RGB565。
    R5G6B5,
    /// 32 位 a8b8g8r8。
    A8B8G8R8,
    /// 32 位 x8r8g8b8。
    X8R8G8B8,
    /// 32 位 a8r8g8b8。
    A8R8G8B8,
    /// 引导信息里出现但内核不认识的格式。
    Unknown,
}

/// 引导器/固件交给内核的帧缓冲描述。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameBufferInfo {
    /// 物理基址。
    pub base: u64,
    /// 字节长度。
    pub size: u64,
    /// 可见宽度。
    pub width: u32,
    /// 可见高度。
    pub height: u32,
    /// 每行字节数。
    pub stride: u32,
    /// 像素格式。
    pub format: FrameBufferFormat,
}

/// PSCI 调用途径与 `cpu_on` 功能号（来自设备树，不猜测）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PsciBoot {
    /// `hvc` 或 `smc`。
    pub conduit: Conduit,
    /// 设备树给出的 `cpu_on` 功能号。
    pub cpu_on: Option<u32>,
}

/// 早期控制台串口（物理地址）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerialBoot {
    /// `reg` 的物理基址。
    pub base: u64,
    /// `reg` 的字节长度。
    pub size: u64,
    /// 共享外设中断号。
    pub irq: Option<u32>,
}

/// 内核需要从引导器得到的全部信息。
pub struct BootSpec {
    regions: [PhysRegion; MAX_REGIONS],
    region_count: usize,
    /// 因超出 `MAX_REGIONS` 而未记录的区域数。
    pub dropped_regions: usize,
    /// 「物理地址 + 偏移 = 内核可访问的虚拟地址」中的偏移；引导器未映射全部物理内存时为 `None`。
    pub phys_offset: Option<u64>,
    /// 固件 ACPI 根指针（RSDP）的物理地址；引导器未提供时为 `None`（处理器发现退回只用引导处理器）。
    pub acpi_rsdp: Option<u64>,
    /// 帧缓冲（设备树 `simple-framebuffer`；没有时为 `None`）。
    pub framebuffer: Option<FrameBufferInfo>,
    /// PSCI 调用途径（没有 `/psci` 时为 `None`）。
    pub psci: Option<PsciBoot>,
    /// 早期控制台串口。
    pub serial: Option<SerialBoot>,
    /// `/chosen/bootargs`（指向已标为保留的设备树内存）。
    pub bootargs: Option<&'static str>,
    /// `/chosen/linux,initrd-start` / `-end` 给出的 `(start, end)`。
    pub initrd: Option<(u64, u64)>,
}

impl BootSpec {
    /// 空的交接信息。
    pub const fn new() -> Self {
        BootSpec {
            regions: [PhysRegion::EMPTY; MAX_REGIONS],
            region_count: 0,
            dropped_regions: 0,
            phys_offset: None,
            acpi_rsdp: None,
            framebuffer: None,
            psci: None,
            serial: None,
            bootargs: None,
            initrd: None,
        }
    }

    /// 追加一个区域；满了则计数丢弃。
    pub fn push_region(&mut self, region: PhysRegion) {
        if self.region_count < MAX_REGIONS {
            self.regions[self.region_count] = region;
            self.region_count += 1;
        } else {
            self.dropped_regions += 1;
        }
    }

    /// 已记录的物理内存区域。
    pub fn regions(&self) -> &[PhysRegion] {
        &self.regions[..self.region_count]
    }
}

impl Default for BootSpec {
    fn default() -> Self {
        Self::new()
    }
}

static BOOT: Once<BootSpec> = Once::new();

/// 把交接信息放进 `'static` 存储（只允许一次；重复调用返回第一次的值）。
pub fn install(spec: BootSpec) -> &'static BootSpec {
    BOOT.call_once(|| spec)
}

/// 已安装的交接信息（未安装时为 `None`）。
pub fn get() -> Option<&'static BootSpec> {
    BOOT.get()
}
