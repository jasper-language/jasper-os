//! PCI 设备发现的启动期部分：取得平台访问者、穷举总线 / 设备 / 功能、建立只读设备表并输出结构化事件。
//! Boot-time PCI discovery: obtain the platform accessor, enumerate functions, and build a read-only device table.
//!
//! # 职责
//! * 复用 `kernel_core::pci` 的头部解码、BAR 探测与穷举枚举；本文件不重复任何解码规则。
//! * 把每个存在功能的 BDF、厂商 / 设备号、类 / 子类 / 编程接口、头部类型与 BAR（类型、基址、尺寸）
//!   存进容量有界的启动期设备表；超出容量只计数并报告，不 panic，也不丢弃已记录项。
//! * BAR 探测前后各取一份标准头快照，确认探测结束后寄存器恢复原状；恢复失败如实计入失败。
//! * 每发现一个功能输出一行 `[JSR-PCI] dev …`；汇总行由 `pci_demo` 在所有断言之后输出。
//!
//! # 边界
//! * 不含端口号、`asm!` 或任何 ISA 专有内容；配置空间后端由 `arch::PciAccess` 注入。
//! * 设备表建立后只读；不在运行时重新枚举，也不为设备注册中断或 DMA。
//! * 设备数量超限、枚举读取失败、BAR 编码非法都只记录并继续，由演练汇总判据决定启动是否失败。

use alloc::boxed::Box;
use kernel_core::device::{CapabilityRecord, CAP_CFG_NOTIFY, CAP_ID_VENDOR};
use kernel_core::pci::{
    self as core_pci, Bar, Bdf, ConfigSpace, Function, Header, MsiCapability, MsiConfigError,
    MsixCapability, MAX_BARS,
};
use spin::Once;

use crate::arch::{self, PciMechanism};
use crate::boot::BootSpec;
use crate::kprintln;
use crate::sync::IrqSpinLock;

/// 启动期设备表容量（QEMU 默认机型的功能数远低于此；超出只计数并报告）。
/// Boot-time device-table capacity; excess functions are counted and reported.
pub const MAX_DEVICES: usize = 64;
/// 每个功能最多保留的厂商专有能力条数（virtio 1.x 通常 3–5 条）。
/// Maximum vendor capabilities retained per function.
pub const MAX_CAPABILITIES: usize = 16;
/// BAR 探测前后快照覆盖的标准头字节数（16 个双字）。
const SNAPSHOT_WORDS: usize = 16;

/// 一个已枚举功能的只读快照。
/// Read-only snapshot of one enumerated function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Device {
    /// 总线 / 设备 / 功能地址。
    /// Bus/device/function address.
    pub bdf: Bdf,
    /// 标准头解码结果。
    /// Decoded standard header.
    pub header: Header,
    /// 全部 BAR 槽位（未实现与 64 位 BAR 的高半槽位为 [`Bar::None`]）。
    /// Every BAR slot; unimplemented slots and 64-bit high halves are [`Bar::None`].
    pub bars: [Bar; MAX_BARS],
    /// 厂商专有能力快照（仅 PCI 能力号 0x09；其余能力号不保留）。
    /// Vendor-specific capability snapshots (PCI capability ID 0x09 only).
    pub caps: [CapabilityRecord; MAX_CAPABILITIES],
    /// 有效能力条数（`caps[..cap_count]`）。
    /// Number of valid capability records.
    pub cap_count: usize,
    /// 能力链遍历或能力字段读取失败（不把部分结果当成完整结果）。
    /// The chain walk or a capability-field read failed.
    pub caps_error: bool,
    /// 解析得到的 MSI 能力（每功能至多一个；没有时为 `None`）。
    /// Parsed MSI capability, at most one per function.
    pub msi: Option<MsiCapability>,
    /// 解析得到的 MSI-X 能力（每功能至多一个；没有时为 `None`）。
    /// Parsed MSI-X capability, at most one per function.
    pub msix: Option<MsixCapability>,
    /// MSI 能力解析失败的结构化原因（与厂商能力分开保存）。
    /// Structured reason when MSI parsing failed.
    pub msi_error: Option<MsiConfigError>,
    /// MSI-X 能力解析失败的结构化原因（与厂商能力分开保存）。
    /// Structured reason when MSI-X parsing failed.
    pub msix_error: Option<MsiConfigError>,
}

impl Device {
    /// 实际实现的 BAR 个数（不含未实现槽位与 64 位 BAR 的高半槽位）。
    /// Number of implemented BARs.
    pub fn bar_count(&self) -> usize {
        self.bars.iter().filter(|b| !matches!(b, Bar::None)).count()
    }
}

/// 启动期 PCI 设备表（只读）。
/// Read-only boot-time PCI device table.
pub struct Table {
    /// 实际使用的访问机制。
    /// Access mechanism actually used.
    pub mechanism: PciMechanism,
    /// 每个功能单独装箱，避免启动栈上出现整张设备表的大对象。
    /// Each function is boxed so the boot stack never holds the whole device table.
    entries: [Option<Box<Device>>; MAX_DEVICES],
    count: usize,
    /// 因超出容量而未记录的功能数。
    /// Functions dropped because the table was full.
    pub dropped: usize,
    /// 所有已记录功能中实际实现的 BAR 总数。
    /// Number of implemented BARs across all recorded functions.
    pub bars: usize,
    /// 枚举过程中配置空间读取失败。
    /// A config-space read failed during enumeration.
    pub enumerate_error: bool,
    /// 有功能的 BAR 探测失败。
    /// Number of functions whose BAR probe failed.
    pub probe_failed: usize,
    /// 所有 BAR 探测前后标准头逐双字一致。
    /// Every standard header was dword-identical before and after BAR probing.
    pub restored: bool,
}

impl Table {
    /// 空表（平台没有 PCI 或尚未初始化时使用；不含任何虚构设备）。
    /// Empty table.
    pub const fn empty() -> Table {
        Table {
            mechanism: PciMechanism::Unavailable,
            entries: [const { None }; MAX_DEVICES],
            count: 0,
            dropped: 0,
            bars: 0,
            enumerate_error: false,
            probe_failed: 0,
            restored: false,
        }
    }

    /// 已记录的功能数。
    /// Number of recorded functions.
    pub fn functions(&self) -> usize {
        self.count
    }

    /// 遍历已记录的功能。
    /// Iterate recorded functions.
    pub fn devices(&self) -> impl Iterator<Item = &Device> {
        self.entries[..self.count].iter().flatten().map(|entry| &**entry)
    }

    /// 按 BDF 查找已记录的功能；不存在返回 `None`（不触碰硬件，只查启动期快照）。
    /// Looks up a recorded function by BDF; `None` when absent.
    pub fn find(&self, bdf: Bdf) -> Option<&Device> {
        self.devices().find(|device| device.bdf == bdf)
    }
}

static TABLE: Once<Table> = Once::new();
/// 启动期枚举使用的唯一配置空间后端（枚举结束后保留，供设备初始化写 MSI-X 控制字段）。
static CONFIG: Once<IrqSpinLock<&'static mut dyn ConfigSpace>> = Once::new();
static EMPTY: Table = Table::empty();

/// 启动期枚举一次并把结果放进只读静态表；重复调用返回第一次的结果。
/// Enumerate once at boot; repeated calls return the same table.
pub fn init(boot: &'static BootSpec) -> &'static Table {
    TABLE.call_once(|| {
        let Some(access) = arch::pci_access(boot) else {
            kprintln!("[JSR-PCI] unavailable reason=system.device.error.config_unreachable");
            return Table::empty();
        };
        let arch::PciAccess { config, mechanism, buses } = access;
        let table = build(config, mechanism, buses);
        let _ = CONFIG.call_once(|| IrqSpinLock::new(config));
        table
    })
}

/// 已建立的设备表；未初始化时返回空表（机制不可用，不伪造设备）。
/// The established table, or an empty table when not initialised.
pub fn table() -> &'static Table {
    TABLE.get().unwrap_or(&EMPTY)
}

/// 读取一个功能的配置空间双字；设备表尚未建立时返回 `None`。
/// Reads a configuration dword of one function, or `None` before PCI initialisation.
pub fn read_config32(bdf: Bdf, offset: u16) -> Option<u32> {
    CONFIG.get()?.lock().read32(bdf, offset)
}

/// 写入一个功能的配置空间双字；设备表尚未建立时返回 `false` 且不触碰硬件。
/// Writes a configuration dword of one function.
pub fn write_config32(bdf: Bdf, offset: u16, value: u32) -> bool {
    match CONFIG.get() {
        Some(lock) => lock.lock().write32(bdf, offset, value),
        None => false,
    }
}

/// 打开或关闭一个功能的总线主控位，返回修改前是否已打开；设备表尚未建立时返回不可达。
/// Sets or clears the bus-master bit of one function.
pub fn set_bus_master(bdf: Bdf, on: bool) -> Result<bool, core_pci::PciError> {
    let lock = CONFIG.get().ok_or(core_pci::PciError::Unreachable)?;
    let mut cfg = lock.lock();
    kernel_core::pci::set_bus_master(&mut **cfg, bdf, on)
}

/// 读取设备通知能力中的 `notify_off_multiplier`；没有通知能力或配置空间不可达时返回 `None`。
///
/// 只在需要时读配置空间，不把倍率缓存进设备表（设备表在启动期建立，必须保持紧凑）。
/// Reads the notification multiplier on demand instead of caching it in the boot-time table.
pub fn notify_multiplier(device: &Device) -> Option<u32> {
    let capability = device.caps[..device.cap_count]
        .iter()
        .find(|cap| cap.cfg_type == CAP_CFG_NOTIFY)?;
    read_config32(device.bdf, capability.pci_offset as u16 + 16)
}

fn build(config: &mut dyn ConfigSpace, mechanism: PciMechanism, buses: core::ops::RangeInclusive<u8>) -> Table {
    let mut out = Table { mechanism, ..Table::empty() };

    // 穷举只读取头部；BAR 探测需要独占 `config`，所以先把功能收集到有界槽位里。
    let mut slots: [Option<Function>; MAX_DEVICES] = [None; MAX_DEVICES];
    let mut found = 0usize;
    let result = core_pci::enumerate(config, buses, |f| {
        if found < MAX_DEVICES {
            slots[found] = Some(*f);
            found += 1;
        } else {
            out.dropped += 1;
        }
        true
    });
    if let Err(e) = result {
        out.enumerate_error = true;
        kprintln!("[JSR-PCI] error enumerate={}", e.name());
    }
    if out.dropped > 0 {
        kprintln!("[JSR-PCI] dropped functions={} capacity={}", out.dropped, MAX_DEVICES);
    }

    out.restored = true;
    for function in slots[..found].iter().flatten() {
        let before = snapshot(config, function.bdf);
        let bars = match core_pci::probe_bars(config, function.bdf, function.header.kind) {
            Ok(bars) => bars,
            Err(e) => {
                out.probe_failed += 1;
                kprintln!("[JSR-PCI] error probe bdf={} reason={}", format_bdf(function.bdf), e.name());
                [Bar::None; MAX_BARS]
            }
        };
        let after = snapshot(config, function.bdf);
        let same = match (before, after) {
            (Some(b), Some(a)) => b == a,
            _ => false,
        };
        if !same {
            out.restored = false;
            kprintln!("[JSR-PCI] error restore bdf={}", format_bdf(function.bdf));
        }
        let (caps, cap_count, caps_error) = probe_capabilities(config, function.bdf);
        let (msi, msi_error) = match core_pci::parse_msi(config, function.bdf) {
            Ok(cap) => (cap, None),
            Err(e) => {
                kprintln!("[JSR-PCI] error msi bdf={} reason={}", format_bdf(function.bdf), e.name());
                (None, Some(e))
            }
        };
        let (msix, msix_error) = match core_pci::parse_msix(config, function.bdf, &bars) {
            Ok(cap) => (cap, None),
            Err(e) => {
                kprintln!("[JSR-PCI] error msix bdf={} reason={}", format_bdf(function.bdf), e.name());
                (None, Some(e))
            }
        };
        let device = Device {
            bdf: function.bdf,
            header: function.header,
            bars,
            caps,
            cap_count,
            caps_error,
            msi,
            msix,
            msi_error,
            msix_error,
        };
        out.bars += device.bar_count();
        kprintln!(
            "[JSR-PCI] dev bdf={} vendor=0x{:04x} device=0x{:04x} class=0x{:06x} bars={}",
            format_bdf(device.bdf),
            device.header.vendor,
            device.header.device,
            class_code(&device.header),
            device.bar_count()
        );
        out.entries[out.count] = Some(Box::new(device));
        out.count += 1;
    }
    out
}

/// 遍历一个功能的配置空间能力链，只保留厂商专有能力（0x09）并解析 virtio 1.x 的四个字段。
///
/// 能力链遍历复用 `kernel_core::pci::for_each_capability`；字段读取失败时返回 `caps_error = true`，
/// 调用方不得把部分结果当成完整能力表。能力条数超过 [`MAX_CAPABILITIES`] 时只保留前面的条目并继续，
/// 不改变设备是否存在这一事实。
/// Snapshot vendor-specific capabilities of one function, reusing the DRV-1A chain walker.
fn probe_capabilities(
    cfg: &mut dyn ConfigSpace,
    bdf: Bdf,
) -> ([CapabilityRecord; MAX_CAPABILITIES], usize, bool) {
    let mut offsets = [0u8; MAX_CAPABILITIES];
    let mut count = 0usize;
    let walked = core_pci::for_each_capability(cfg, bdf, |id, at| {
        if id == CAP_ID_VENDOR && count < MAX_CAPABILITIES {
            offsets[count] = at;
            count += 1;
        }
        true
    });
    if walked.is_err() {
        return ([CapabilityRecord::NONE; MAX_CAPABILITIES], 0, true);
    }
    let mut caps = [CapabilityRecord::NONE; MAX_CAPABILITIES];
    let mut valid = 0usize;
    for at in offsets.iter().take(count) {
        let Some(header) = cfg.read32(bdf, *at as u16) else {
            return ([CapabilityRecord::NONE; MAX_CAPABILITIES], 0, true);
        };
        // virtio 能力结构固定 16 字节；更短的厂商专有能力不是 virtio 能力，跳过而不猜测字段。
        let cap_len = ((header >> 16) & 0xFF) as u8;
        if cap_len < 16 {
            continue;
        }
        let Some(fields) = cfg.read32(bdf, *at as u16 + 4) else {
            return ([CapabilityRecord::NONE; MAX_CAPABILITIES], 0, true);
        };
        let Some(offset) = cfg.read32(bdf, *at as u16 + 8) else {
            return ([CapabilityRecord::NONE; MAX_CAPABILITIES], 0, true);
        };
        let Some(length) = cfg.read32(bdf, *at as u16 + 12) else {
            return ([CapabilityRecord::NONE; MAX_CAPABILITIES], 0, true);
        };
        caps[valid] = CapabilityRecord {
            pci_offset: *at,
            id: (header & 0xFF) as u8,
            // 字节 3 是 cfg_type；字节 4 是 BAR 号，随后是 id 与保留字节。
            cfg_type: (header >> 24) as u8,
            bar: (fields & 0xFF) as u8,
            bar_offset: offset,
            length,
        };
        valid += 1;
    }
    (caps, valid, false)
}

/// 读取标准头前 64 字节；任一读失败返回 `None`（不把「读不到」当成「没变化」）。
fn snapshot(cfg: &mut dyn ConfigSpace, bdf: Bdf) -> Option<[u32; SNAPSHOT_WORDS]> {
    let mut words = [0u32; SNAPSHOT_WORDS];
    for (i, word) in words.iter_mut().enumerate() {
        *word = cfg.read32(bdf, (i * 4) as u16)?;
    }
    Some(words)
}

/// `bb:dd.f` 形式的 BDF（诊断输出用）。
fn format_bdf(bdf: Bdf) -> BdfFmt {
    BdfFmt(bdf)
}

struct BdfFmt(Bdf);

impl core::fmt::Display for BdfFmt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:02x}:{:02x}.{}", self.0.bus(), self.0.device(), self.0.function())
    }
}

/// 类 / 子类 / 编程接口合成值（`class << 16 | subclass << 8 | prog_if`）。
fn class_code(header: &Header) -> u32 {
    (header.class as u32) << 16 | (header.subclass as u32) << 8 | header.prog_if as u32
}
