//! 引导交接信息（架构与引导协议无关）。
//!
//! 引导适配层（`main.rs`：x86_64 + `bootloader` 0.11）把引导器给的原始信息转换成 [`BootSpec`]，
//! 交给 [`crate::kmain::start`]。内核其余部分只认这里的类型，不认 `bootloader_api`、UEFI 表
//! 或设备树——换引导方式时只改适配层。
//!
//! 生命周期：`BootSpec` 在启动最早期由 [`install`] 放进 `'static` 存储，之后只读。

use kernel_core::frame::PhysRegion;
use spin::Once;

/// 最多记录的物理内存区域数（超出部分计入 `dropped_regions`，不静默丢弃）。
pub const MAX_REGIONS: usize = 128;

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
}

impl BootSpec {
    /// 空的交接信息。
    pub const fn new() -> Self {
        BootSpec { regions: [PhysRegion::EMPTY; MAX_REGIONS], region_count: 0, dropped_regions: 0, phys_offset: None, acpi_rsdp: None }
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
