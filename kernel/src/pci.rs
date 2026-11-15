//! PCI 设备发现的启动期部分：`devices` 阶段取得平台访问者，`devices` 模块激活时穷举并建立只读设备表。
//! Boot-time PCI discovery: the devices stage prepares access and module activation builds the table.
//!
//! # 职责
//! * 复用 `kernel_core::pci` 的头部解码、BAR 探测与穷举枚举；本文件不重复任何解码规则。
//! * 把每个存在功能的 BDF、厂商 / 设备号、类 / 子类 / 编程接口、头部类型与 BAR（类型、基址、尺寸）
//!   存进按实际发现结果和启动期内存预算动态建立的只读设备表。
//! * BAR 探测前后各取一份标准头快照，确认探测结束后寄存器恢复原状；恢复失败如实计入失败。
//! * 每发现一个功能输出一行 `[JSR-PCI] dev …`；汇总行由 `pci_demo` 在所有断言之后输出。
//!
//! # 边界
//! * 不含端口号、`asm!` 或任何 ISA 专有内容；配置空间后端由 `arch::PciAccess` 注入。
//! * 设备表建立后只读；不在运行时重新枚举，也不为设备注册中断或 DMA。
//! * 枚举读取失败、BAR 编码非法、能力链损坏或动态库存预算不足都会标记表不完整并失败关闭。

use alloc::vec::Vec;
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

/// BAR 探测前后快照覆盖的标准头字节数（16 个双字）。
const SNAPSHOT_WORDS: usize = 16;

/// Boot inventory budget derived from currently free heap bytes. The PCI table
/// may consume at most one quarter of that snapshot; crossing it fails closed.
struct InventoryBudget {
    remaining: usize,
}

impl InventoryBudget {
    const fn new(bytes: usize) -> Self {
        Self { remaining: bytes }
    }

    fn charge<T>(&mut self) -> bool {
        let Some(remaining) = self.remaining.checked_sub(core::mem::size_of::<T>()) else {
            return false;
        };
        self.remaining = remaining;
        true
    }
}

/// 一个已枚举功能的只读快照。
/// Read-only snapshot of one enumerated function.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub caps: Vec<CapabilityRecord>,
    /// 能力链上发现的目标厂商能力总数。
    /// Number of matching vendor capabilities discovered on the chain.
    pub cap_discovered: usize,
    /// 已发现但不满足 virtio 厂商能力格式的条目数。
    /// Discovered vendor entries rejected before admission as virtio records.
    pub cap_rejected: usize,
    /// 能力链遍历、字段读取或库存分配失败（不得发布部分结果）。
    /// Capability walking, field reads, or inventory allocation failed.
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
    /// 动态设备库存，规模由枚举结果与启动期内存预算共同决定。
    /// Dynamic device inventory sized by enumeration and boot-memory budget.
    entries: Vec<Device>,
    /// 因预算不足而未记录的功能数。
    /// Functions not recorded because the inventory budget was exhausted.
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
    /// 枚举、探测和所有能力库存均可发布。
    pub complete: bool,
}

impl Table {
    /// 空表（平台没有 PCI 或尚未初始化时使用；不含任何虚构设备）。
    /// Empty table.
    pub const fn empty() -> Table {
        Table {
            mechanism: PciMechanism::Unavailable,
            entries: Vec::new(),
            dropped: 0,
            bars: 0,
            enumerate_error: false,
            probe_failed: 0,
            restored: false,
            complete: true,
        }
    }

    /// 已记录的功能数。
    /// Number of recorded functions.
    pub fn functions(&self) -> usize {
        self.entries.len()
    }

    /// 遍历已记录的功能。
    /// Iterate recorded functions.
    pub fn devices(&self) -> impl Iterator<Item = &Device> {
        self.entries.iter()
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
/// `devices` 阶段取得、等待模块激活消费的一次性访问者。
/// One-shot accessor prepared by the devices stage and consumed by module activation.
static PREPARED: IrqSpinLock<Option<arch::PciAccess>> = IrqSpinLock::new(None);
static EMPTY: Table = Table::empty();

/// 硬件顺序阶段只取得平台配置空间访问者，不建立设备服务状态。
/// The hardware-order stage only obtains the platform config-space accessor.
pub fn prepare(boot: &'static BootSpec) {
    if TABLE.is_completed() {
        return;
    }
    match arch::pci_access(boot) {
        Some(access) => *PREPARED.lock() = Some(access),
        None => kprintln!("[JSR-PCI] unavailable reason=system.device.error.config_unreachable"),
    }
}

/// `devices` 模块激活：消费准备好的访问者，枚举总线并建立只读设备表。
/// Device-module activation: consume prepared access, enumerate and build the read-only table.
pub fn activate() -> Result<(), &'static str> {
    TABLE.call_once(|| {
        let Some(access) = PREPARED.lock().take() else {
            kprintln!("[JSR-PCI] unavailable reason=system.device.error.config_unreachable");
            return Table::empty();
        };
        let arch::PciAccess {
            config,
            mechanism,
            buses,
        } = access;
        let table = build(config, mechanism, buses);
        let _ = CONFIG.call_once(|| IrqSpinLock::new(config));
        table
    });
    let table = TABLE.get().ok_or("PCI table not activated")?;
    if table.complete {
        Ok(())
    } else {
        Err("PCI inventory incomplete")
    }
}

/// 设备表已由模块激活建立（空表也包括不可用平台的真实结果）。
/// Whether module activation has established the table, including a real empty table.
pub fn ready() -> bool {
    TABLE.is_completed()
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

/// 读回一个功能的总线主控位当前是否打开；设备表尚未建立时返回不可达。
///
/// 复位失败后的拆除路径用它确认设备确实已经失去发起 DMA 的能力，读回是真实读取而不是写入的镜像。
/// Reads back whether the bus-master bit of one function is currently set.
pub fn bus_master_enabled(bdf: Bdf) -> Result<bool, core_pci::PciError> {
    let lock = CONFIG.get().ok_or(core_pci::PciError::Unreachable)?;
    let mut cfg = lock.lock();
    kernel_core::pci::bus_master_enabled(&mut **cfg, bdf)
}

/// 读取设备通知能力中的 `notify_off_multiplier`；没有通知能力或配置空间不可达时返回 `None`。
///
/// 只在需要时读配置空间，不把倍率缓存进设备表（设备表在启动期建立，必须保持紧凑）。
/// Reads the notification multiplier on demand instead of caching it in the boot-time table.
pub fn notify_multiplier(device: &Device) -> Option<u32> {
    let capability = device
        .caps
        .iter()
        .find(|cap| cap.cfg_type == CAP_CFG_NOTIFY)?;
    read_config32(device.bdf, capability.pci_offset as u16 + 16)
}

fn build(
    config: &mut dyn ConfigSpace,
    mechanism: PciMechanism,
    buses: core::ops::RangeInclusive<u8>,
) -> Table {
    let mut out = Table {
        mechanism,
        complete: true,
        ..Table::empty()
    };
    let mut budget = InventoryBudget::new(crate::mm::heap::stats().1 / 4);

    // Enumeration only reads headers; BAR probing needs exclusive access, so
    // collect the discovered functions into the admitted runtime inventory.
    let mut slots = Vec::new();
    let result = core_pci::enumerate(config, buses, |f| {
        if !budget.charge::<Function>() || slots.try_reserve(1).is_err() {
            out.dropped += 1;
            out.complete = false;
            return false;
        }
        slots.push(*f);
        true
    });
    if let Err(e) = result {
        out.enumerate_error = true;
        out.complete = false;
        kprintln!("[JSR-PCI] error enumerate={}", e.name());
    }
    if out.dropped > 0 {
        kprintln!(
            "[JSR-PCI] dropped functions={} reason=system.memory.error.capacity",
            out.dropped
        );
    }

    out.restored = true;
    for function in &slots {
        let before = snapshot(config, function.bdf);
        let bars = match core_pci::probe_bars(config, function.bdf, function.header.kind) {
            Ok(bars) => bars,
            Err(e) => {
                out.probe_failed += 1;
                out.complete = false;
                kprintln!(
                    "[JSR-PCI] error probe bdf={} reason={}",
                    format_bdf(function.bdf),
                    e.name()
                );
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
            out.complete = false;
            kprintln!("[JSR-PCI] error restore bdf={}", format_bdf(function.bdf));
        }
        let snapshot = probe_capabilities(config, function.bdf, &mut budget);
        let (msi, msi_error) = match core_pci::parse_msi(config, function.bdf) {
            Ok(cap) => (cap, None),
            Err(e) => {
                out.complete = false;
                kprintln!(
                    "[JSR-PCI] error msi bdf={} reason={}",
                    format_bdf(function.bdf),
                    e.name()
                );
                (None, Some(e))
            }
        };
        let (msix, msix_error) = match core_pci::parse_msix(config, function.bdf, &bars) {
            Ok(cap) => (cap, None),
            Err(e) => {
                out.complete = false;
                kprintln!(
                    "[JSR-PCI] error msix bdf={} reason={}",
                    format_bdf(function.bdf),
                    e.name()
                );
                (None, Some(e))
            }
        };
        let cap_rejected = snapshot.discovered.saturating_sub(snapshot.caps.len());
        let device = Device {
            bdf: function.bdf,
            header: function.header,
            bars,
            caps: snapshot.caps,
            cap_discovered: snapshot.discovered,
            cap_rejected,
            caps_error: snapshot.error,
            msi,
            msix,
            msi_error,
            msix_error,
        };
        out.bars += device.bar_count();
        kprintln!(
            "[JSR-PCI] dev bdf={} vendor=0x{:04x} device=0x{:04x} class=0x{:06x} bars={} caps_discovered={} caps_admitted={} caps_truncated={}",
            format_bdf(device.bdf),
            device.header.vendor,
            device.header.device,
            class_code(&device.header),
            device.bar_count(),
            device.cap_discovered,
            device.caps.len(),
            device.cap_rejected
        );
        if !budget.charge::<Device>() || out.entries.try_reserve(1).is_err() {
            out.dropped += 1;
            out.complete = false;
            break;
        }
        if device.caps_error {
            out.complete = false;
        }
        out.entries.push(device);
    }
    out
}

/// 遍历一个功能的配置空间能力链，只保留厂商专有能力（0x09）并解析 virtio 1.x 的四个字段。
///
/// 能力链遍历复用 `kernel_core::pci::for_each_capability`；所有目标偏移先进入
/// 动态库存，再逐项解析。字段读取或库存分配失败时返回 `caps_error = true`，
/// 调用方不得把部分结果当成完整能力表。
/// Snapshot vendor-specific capabilities of one function, reusing the DRV-1A chain walker.
struct CapabilitySnapshot {
    caps: Vec<CapabilityRecord>,
    discovered: usize,
    error: bool,
}

fn probe_capabilities(
    cfg: &mut dyn ConfigSpace,
    bdf: Bdf,
    budget: &mut InventoryBudget,
) -> CapabilitySnapshot {
    let mut snapshot = CapabilitySnapshot {
        caps: Vec::new(),
        discovered: 0,
        error: false,
    };
    let mut offsets = Vec::new();
    if let Err(error) = core_pci::for_each_capability(cfg, bdf, |id, at| {
        if id != CAP_ID_VENDOR {
            return true;
        }
        snapshot.discovered += 1;
        if !budget.charge::<u8>() || offsets.try_reserve(1).is_err() {
            snapshot.error = true;
            return false;
        }
        offsets.push(at);
        true
    }) {
        snapshot.error = true;
        kprintln!(
            "[JSR-PCI] capability error bdf={} reason={}",
            format_bdf(bdf),
            error.name()
        );
    }
    if snapshot.error {
        return snapshot;
    }

    for at in offsets {
        let Some(header) = cfg.read32(bdf, at as u16) else {
            snapshot.error = true;
            return snapshot;
        };
        // virtio 能力结构固定 16 字节；更短的厂商专有能力不是 virtio 能力，跳过而不猜测字段。
        let cap_len = ((header >> 16) & 0xFF) as u8;
        if cap_len < 16 {
            continue;
        }
        let Some(fields) = cfg.read32(bdf, at as u16 + 4) else {
            snapshot.error = true;
            return snapshot;
        };
        let Some(offset) = cfg.read32(bdf, at as u16 + 8) else {
            snapshot.error = true;
            return snapshot;
        };
        let Some(length) = cfg.read32(bdf, at as u16 + 12) else {
            snapshot.error = true;
            return snapshot;
        };
        if !budget.charge::<CapabilityRecord>() || snapshot.caps.try_reserve(1).is_err() {
            snapshot.error = true;
            return snapshot;
        }
        snapshot.caps.push(CapabilityRecord {
            pci_offset: at,
            id: (header & 0xFF) as u8,
            // 字节 3 是 cfg_type；字节 4 是 BAR 号，随后是 id 与保留字节。
            cfg_type: (header >> 24) as u8,
            bar: (fields & 0xFF) as u8,
            bar_offset: offset,
            length,
        });
    }
    snapshot
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
        write!(
            f,
            "{:02x}:{:02x}.{}",
            self.0.bus(),
            self.0.device(),
            self.0.function()
        )
    }
}

/// 类 / 子类 / 编程接口合成值（`class << 16 | subclass << 8 | prog_if`）。
fn class_code(header: &Header) -> u32 {
    (header.class as u32) << 16 | (header.subclass as u32) << 8 | header.prog_if as u32
}
