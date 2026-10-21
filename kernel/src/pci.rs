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

use kernel_core::pci::{self as core_pci, Bar, Bdf, ConfigSpace, Function, Header, MAX_BARS};
use spin::Once;

use crate::arch::{self, PciMechanism};
use crate::boot::BootSpec;
use crate::kprintln;

/// 启动期设备表容量（QEMU 默认机型的功能数远低于此；超出只计数并报告）。
/// Boot-time device-table capacity; excess functions are counted and reported.
pub const MAX_DEVICES: usize = 64;
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
    entries: [Option<Device>; MAX_DEVICES],
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
            entries: [None; MAX_DEVICES],
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
        self.entries[..self.count].iter().flatten()
    }
}

static TABLE: Once<Table> = Once::new();
static EMPTY: Table = Table::empty();

/// 启动期枚举一次并把结果放进只读静态表；重复调用返回第一次的结果。
/// Enumerate once at boot; repeated calls return the same table.
pub fn init(boot: &'static BootSpec) -> &'static Table {
    TABLE.call_once(|| build(boot))
}

/// 已建立的设备表；未初始化时返回空表（机制不可用，不伪造设备）。
/// The established table, or an empty table when not initialised.
pub fn table() -> &'static Table {
    TABLE.get().unwrap_or(&EMPTY)
}

fn build(boot: &'static BootSpec) -> Table {
    let Some(access) = arch::pci_access(boot) else {
        kprintln!("[JSR-PCI] unavailable reason=system.device.error.config_unreachable");
        return Table::empty();
    };
    let arch::PciAccess { config, mechanism, buses } = access;
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
        let device = Device { bdf: function.bdf, header: function.header, bars };
        out.bars += device.bar_count();
        kprintln!(
            "[JSR-PCI] dev bdf={} vendor=0x{:04x} device=0x{:04x} class=0x{:06x} bars={}",
            format_bdf(device.bdf),
            device.header.vendor,
            device.header.device,
            class_code(&device.header),
            device.bar_count()
        );
        out.entries[out.count] = Some(device);
        out.count += 1;
    }
    out
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
