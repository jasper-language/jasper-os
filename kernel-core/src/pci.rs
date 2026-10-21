//! PCI 设备发现的指令集无关部分：配置空间访问契约、地址编码、头部与 BAR 解码、能力链遍历、总线枚举。
//! ISA-neutral PCI discovery: config-space access contract, address encoding, header/BAR decoding, enumeration.
//!
//! # 职责与边界
//! * 只定义「怎样读懂配置空间」，不定义「怎样碰到配置空间」：真正的 32 位读写由调用者经 [`ConfigSpace`] 注入
//!   （x86_64 可走传统 I/O 端口机制或 ECAM，AArch64 / RISC-V 的 QEMU `virt` 走 ECAM；宿主测试用内存模型）。
//!   本模块不出现端口号、`asm!` 或任何指令集专有内容，所以四个指令集共用同一份解码与枚举逻辑。
//! * 不分配：枚举经回调逐个交出功能，BAR 结果是定长数组。
//! * 配置空间来自硬件 / 仿真器，是**不可信输入**：所有循环有上界（能力链最多 48 跳且要求偏移对齐、不回到头部区），
//!   保留编码与越界组合（例如 64 位 BAR 落在最后一个槽）一律返回带规范名的错误，而不是猜。
//! * BAR 尺寸探测必须写配置空间：探测期间关闭该功能的 I/O 与内存译码，结束后（无论成功或失败）把每个被写过的
//!   BAR 与命令寄存器恢复原值，不留残留改动；写命令寄存器时状态半字写 0，避免清掉其中「写 1 清除」的位。
//!
//! # 为什么放在 kernel-core
//! 解码规则与指令集无关，放在这里可以在宿主上用构造的设备模型测试成功与失败路径。

use core::ops::RangeInclusive;

/// 每条总线的设备号上限。
pub const DEVICES_PER_BUS: u8 = 32;
/// 每个设备的功能号上限。
pub const FUNCTIONS_PER_DEVICE: u8 = 8;
/// ECAM 下每个功能的配置空间字节数。
pub const ECAM_FUNCTION_SPAN: u16 = 4096;
/// 传统端口机制可达的配置空间字节数。
pub const LEGACY_FUNCTION_SPAN: u16 = 256;
/// 一个功能最多的 BAR 个数（普通设备头）。
pub const MAX_BARS: usize = 6;
/// 能力链最多跟随的跳数（配置空间头之后最多容纳 48 个 4 字节对齐的能力）。
pub const MAX_CAPABILITY_HOPS: usize = 48;
/// 「不存在的功能」读到的厂商号。
pub const VENDOR_NONE: u16 = 0xFFFF;

const REG_ID: u16 = 0x00;
const REG_COMMAND: u16 = 0x04;
const REG_CLASS: u16 = 0x08;
const REG_HEADER: u16 = 0x0C;
const REG_BAR0: u16 = 0x10;
const REG_SUBSYSTEM: u16 = 0x2C;
const REG_CAP_PTR: u16 = 0x34;
const REG_INTERRUPT: u16 = 0x3C;
/// 命令寄存器：I/O 译码（位 0）与内存译码（位 1）。
const COMMAND_DECODE: u32 = 0b11;
/// 命令寄存器位 2：总线主控（允许功能发起 DMA 与 MSI / MSI-X 消息写）。
const COMMAND_BUS_MASTER: u32 = 1 << 2;
/// 状态寄存器（命令所在双字的高半字）位 4：存在能力链。
const STATUS_CAP_LIST: u32 = 1 << (16 + 4);
/// 能力结构只能位于标准头之后。
const CAP_MIN_OFFSET: u8 = 0x40;

/// PCI 发现错误。
/// PCI discovery error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciError {
    /// 配置空间读写失败（地址不在访问窗口内或后端拒绝）。
    Unreachable,
    /// BAR 编码非法（保留的内存类型，或 64 位 BAR 没有高半部分的槽位）。
    BadBar,
    /// 能力链非法（偏移未对齐、指回头部区或超过跳数上限）。
    BadCapability,
}

impl PciError {
    /// 规范名。
    /// Canonical name.
    pub const fn name(self) -> &'static str {
        match self {
            PciError::Unreachable => "system.device.error.config_unreachable",
            PciError::BadBar => "system.device.error.bad_bar",
            PciError::BadCapability => "system.device.error.bad_capability",
        }
    }
}

/// 总线 / 设备 / 功能三元组（构造时校验设备号 < 32、功能号 < 8）。
/// Bus/device/function address, validated at construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Bdf {
    bus: u8,
    device: u8,
    function: u8,
}

impl Bdf {
    /// 构造；设备号或功能号越界返回 `None`。
    /// Builds a BDF; `None` if device or function is out of range.
    pub const fn new(bus: u8, device: u8, function: u8) -> Option<Self> {
        if device < DEVICES_PER_BUS && function < FUNCTIONS_PER_DEVICE {
            Some(Bdf { bus, device, function })
        } else {
            None
        }
    }

    /// 总线号。
    /// Bus number.
    pub const fn bus(self) -> u8 {
        self.bus
    }

    /// 设备号。
    /// Device number.
    pub const fn device(self) -> u8 {
        self.device
    }

    /// 功能号。
    /// Function number.
    pub const fn function(self) -> u8 {
        self.function
    }
}

/// 配置空间的 32 位访问能力（由各指令集或宿主测试注入）。
///
/// `offset` 总是 4 字节对齐；实现对不可达的地址返回 `None` / `false`，不得 panic。
/// 32-bit configuration-space accessor supplied by the platform or a host model.
///
/// `Send` 是必要的：启动期枚举结束后，内核会保留唯一后端供后续设备配置写入使用。
/// `Send` is required because the kernel keeps the single backend after boot-time enumeration.
pub trait ConfigSpace: Send {
    /// 读 `bdf` 功能在 `offset` 处的双字。
    /// Reads the dword at `offset` of function `bdf`.
    fn read32(&mut self, bdf: Bdf, offset: u16) -> Option<u32>;
    /// 写 `bdf` 功能在 `offset` 处的双字；成功返回 `true`。
    /// Writes the dword at `offset` of function `bdf`.
    fn write32(&mut self, bdf: Bdf, offset: u16, value: u32) -> bool;
}

/// 一段 ECAM 窗口（ACPI MCFG 的一条，或设备树 `pci-host-ecam-generic` 的 `reg` 与 `bus-range`）。
/// One ECAM window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ecam {
    /// 窗口物理基址（对应 `bus_start` 号总线）。
    pub base: u64,
    /// PCI 段号。
    pub segment: u16,
    /// 窗口覆盖的第一条总线。
    pub bus_start: u8,
    /// 窗口覆盖的最后一条总线（含）。
    pub bus_end: u8,
}

impl Ecam {
    /// 功能 `bdf` 在 `offset` 处的物理地址；总线不在窗口内、偏移未对齐或越过 4 KiB 时返回 `None`。
    /// Physical address of `offset` in function `bdf`, or `None` if outside this window.
    pub fn address(&self, bdf: Bdf, offset: u16) -> Option<u64> {
        if offset % 4 != 0 || offset >= ECAM_FUNCTION_SPAN || !self.buses().contains(&bdf.bus) {
            return None;
        }
        let rel = ((bdf.bus - self.bus_start) as u64) << 20
            | (bdf.device as u64) << 15
            | (bdf.function as u64) << 12
            | offset as u64;
        self.base.checked_add(rel)
    }

    /// 窗口覆盖的总线范围；`bus_end < bus_start` 的损坏条目得到空范围。
    /// Bus range covered by this window.
    pub fn buses(&self) -> RangeInclusive<u8> {
        self.bus_start..=self.bus_end
    }

    /// 窗口字节数（每条总线 1 MiB）；损坏条目为 0。
    /// Window length in bytes.
    pub fn len(&self) -> u64 {
        if self.bus_end < self.bus_start {
            0
        } else {
            ((self.bus_end - self.bus_start) as u64 + 1) << 20
        }
    }

    /// 窗口是否为空（损坏条目）。
    /// Whether the window is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// 传统配置机制（地址端口 + 数据端口）的地址字；偏移未对齐或不在前 256 字节内时返回 `None`。
///
/// 只做编码；读写哪个端口由指令集层决定。
/// Address word for the legacy configuration mechanism.
pub const fn legacy_address(bdf: Bdf, offset: u16) -> Option<u32> {
    if offset % 4 != 0 || offset >= LEGACY_FUNCTION_SPAN {
        return None;
    }
    Some(
        0x8000_0000
            | (bdf.bus as u32) << 16
            | (bdf.device as u32) << 11
            | (bdf.function as u32) << 8
            | offset as u32,
    )
}

/// 头部布局类型。
/// Header layout kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderKind {
    /// 普通设备（6 个 BAR）。
    Endpoint,
    /// PCI 到 PCI 桥（2 个 BAR）。
    Bridge,
    /// CardBus 桥（无 BAR）。
    CardBus,
    /// 未定义的布局编号（不解析 BAR）。
    Unknown(u8),
}

impl HeaderKind {
    /// 该布局的 BAR 个数。
    /// Number of BARs for this layout.
    pub const fn bar_count(self) -> usize {
        match self {
            HeaderKind::Endpoint => 6,
            HeaderKind::Bridge => 2,
            HeaderKind::CardBus | HeaderKind::Unknown(_) => 0,
        }
    }
}

/// 一个已存在功能的标识信息（只读快照）。
/// Identity snapshot of one present function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// 厂商号。
    pub vendor: u16,
    /// 设备号（厂商内）。
    pub device: u16,
    /// 修订号。
    pub revision: u8,
    /// 编程接口。
    pub prog_if: u8,
    /// 子类。
    pub subclass: u8,
    /// 类。
    pub class: u8,
    /// 头部布局。
    pub kind: HeaderKind,
    /// 是否多功能设备（只在功能 0 上有意义）。
    pub multifunction: bool,
    /// 子系统厂商号（只有普通设备有，其余为 0）。
    pub subsystem_vendor: u16,
    /// 子系统号（只有普通设备有，其余为 0）。
    pub subsystem: u16,
    /// 中断引脚（0 = 不用，1–4 = INTA–INTD）。
    pub interrupt_pin: u8,
}

/// 读取 `bdf` 的头部；功能不存在（厂商号为 0xFFFF）返回 `Ok(None)`。
/// Reads the header of `bdf`; `Ok(None)` if no function is present.
pub fn read_header(cfg: &mut dyn ConfigSpace, bdf: Bdf) -> Result<Option<Header>, PciError> {
    let id = read(cfg, bdf, REG_ID)?;
    let vendor = id as u16;
    if vendor == VENDOR_NONE {
        return Ok(None);
    }
    let class = read(cfg, bdf, REG_CLASS)?;
    let header_type = (read(cfg, bdf, REG_HEADER)? >> 16) as u8;
    let kind = match header_type & 0x7F {
        0 => HeaderKind::Endpoint,
        1 => HeaderKind::Bridge,
        2 => HeaderKind::CardBus,
        other => HeaderKind::Unknown(other),
    };
    let (subsystem_vendor, subsystem) = if kind == HeaderKind::Endpoint {
        let s = read(cfg, bdf, REG_SUBSYSTEM)?;
        (s as u16, (s >> 16) as u16)
    } else {
        (0, 0)
    };
    let interrupt_pin = (read(cfg, bdf, REG_INTERRUPT)? >> 8) as u8;
    Ok(Some(Header {
        vendor,
        device: (id >> 16) as u16,
        revision: class as u8,
        prog_if: (class >> 8) as u8,
        subclass: (class >> 16) as u8,
        class: (class >> 24) as u8,
        kind,
        multifunction: header_type & 0x80 != 0,
        subsystem_vendor,
        subsystem,
        interrupt_pin,
    }))
}

/// 一个 BAR 的解码结果。
/// Decoded base address register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bar {
    /// 未实现（尺寸掩码为 0），或是 64 位 BAR 的高半部分槽位。
    None,
    /// I/O 端口区间。
    Io {
        /// 起始端口。
        base: u32,
        /// 字节数。
        size: u32,
    },
    /// 内存映射区间。
    Memory {
        /// 物理基址（固件分配的值，可能为 0 表示尚未分配）。
        base: u64,
        /// 字节数（2 的幂）。
        size: u64,
        /// 是否可预取。
        prefetchable: bool,
        /// 是否 64 位 BAR（占两个槽）。
        wide: bool,
    },
}

/// 探测 `bdf` 的全部 BAR（基址与尺寸）。
///
/// 探测期间关闭该功能的 I/O 与内存译码；结束时（含失败）恢复所有被写过的 BAR 与命令寄存器。
/// 恢复本身失败时返回 [`PciError::Unreachable`]。
/// Probes base and size of every BAR of `bdf`, restoring all touched registers afterwards.
pub fn probe_bars(cfg: &mut dyn ConfigSpace, bdf: Bdf, kind: HeaderKind) -> Result<[Bar; MAX_BARS], PciError> {
    let command = read(cfg, bdf, REG_COMMAND)? & 0xFFFF;
    write(cfg, bdf, REG_COMMAND, command & !COMMAND_DECODE)?;
    let mut saved = [0u32; MAX_BARS];
    let mut touched = 0usize;
    let result = size_bars(cfg, bdf, kind.bar_count(), &mut saved, &mut touched);
    let mut restored = true;
    for (i, &value) in saved.iter().enumerate().take(touched) {
        restored &= cfg.write32(bdf, bar_reg(i), value);
    }
    restored &= cfg.write32(bdf, REG_COMMAND, command);
    match (result, restored) {
        (Ok(bars), true) => Ok(bars),
        (Err(e), true) => Err(e),
        (_, false) => Err(PciError::Unreachable),
    }
}

/// 逐个写全 1 读回尺寸掩码；`saved[..touched]` 记录已经被改写过的 BAR 原值，供调用者恢复。
fn size_bars(
    cfg: &mut dyn ConfigSpace,
    bdf: Bdf,
    count: usize,
    saved: &mut [u32; MAX_BARS],
    touched: &mut usize,
) -> Result<[Bar; MAX_BARS], PciError> {
    let mut bars = [Bar::None; MAX_BARS];
    let mut i = 0;
    while i < count {
        let lo = read(cfg, bdf, bar_reg(i))?;
        saved[i] = lo;
        *touched = i + 1;
        let lo_mask = sample(cfg, bdf, i)?;
        if lo & 1 == 1 {
            let m = lo_mask & 0xFFFF_FFFC;
            if m != 0 {
                // 有的设备高 16 位读回 0：按 16 位端口空间补齐后再求补。
                bars[i] = Bar::Io { base: lo & 0xFFFF_FFFC, size: (!(m | 0xFFFF_0000)).wrapping_add(1) };
            }
            i += 1;
            continue;
        }
        let prefetchable = lo & 0b1000 != 0;
        match (lo >> 1) & 0b11 {
            0b00 => {
                let m = lo_mask & 0xFFFF_FFF0;
                if m != 0 {
                    let size = (!m).wrapping_add(1) as u64;
                    bars[i] = Bar::Memory { base: (lo & 0xFFFF_FFF0) as u64, size, prefetchable, wide: false };
                }
                i += 1;
            }
            0b10 => {
                if i + 1 >= count {
                    return Err(PciError::BadBar);
                }
                let hi = read(cfg, bdf, bar_reg(i + 1))?;
                saved[i + 1] = hi;
                *touched = i + 2;
                let hi_mask = sample(cfg, bdf, i + 1)?;
                let m = (hi_mask as u64) << 32 | (lo_mask & 0xFFFF_FFF0) as u64;
                if m != 0 {
                    let base = (hi as u64) << 32 | (lo & 0xFFFF_FFF0) as u64;
                    bars[i] = Bar::Memory { base, size: (!m).wrapping_add(1), prefetchable, wide: true };
                }
                i += 2;
            }
            _ => return Err(PciError::BadBar),
        }
    }
    Ok(bars)
}

/// 对第 `i` 个 BAR 写全 1 并读回尺寸掩码（原值由调用者负责恢复）。
fn sample(cfg: &mut dyn ConfigSpace, bdf: Bdf, i: usize) -> Result<u32, PciError> {
    write(cfg, bdf, bar_reg(i), 0xFFFF_FFFF)?;
    read(cfg, bdf, bar_reg(i))
}

fn bar_reg(i: usize) -> u16 {
    REG_BAR0 + 4 * i as u16
}

/// 遍历 `bdf` 的能力链，对每一项回调 `(能力号, 偏移)`；回调返回 `false` 时提前停止。
///
/// 没有能力链（状态寄存器位 4 为 0）时不回调、返回 `Ok(())`。
/// Walks the capability list of `bdf`, calling `f(id, offset)` per entry.
pub fn for_each_capability(
    cfg: &mut dyn ConfigSpace,
    bdf: Bdf,
    mut f: impl FnMut(u8, u8) -> bool,
) -> Result<(), PciError> {
    if read(cfg, bdf, REG_COMMAND)? & STATUS_CAP_LIST == 0 {
        return Ok(());
    }
    let mut at = (read(cfg, bdf, REG_CAP_PTR)? as u8) & 0xFC;
    for _ in 0..MAX_CAPABILITY_HOPS {
        if at == 0 {
            return Ok(());
        }
        if at < CAP_MIN_OFFSET {
            return Err(PciError::BadCapability);
        }
        let word = read(cfg, bdf, at as u16)?;
        if !f(word as u8, at) {
            return Ok(());
        }
        let next = (word >> 8) as u8;
        if next & 0b11 != 0 {
            return Err(PciError::BadCapability);
        }
        at = next;
    }
    if at == 0 { Ok(()) } else { Err(PciError::BadCapability) }
}

// ---------------------------------------------------------------------------
// MSI / MSI-X 能力
// ---------------------------------------------------------------------------

/// MSI 能力号。
/// MSI capability ID.
pub const CAP_ID_MSI: u8 = 0x05;
/// MSI-X 能力号。
/// MSI-X capability ID.
pub const CAP_ID_MSIX: u8 = 0x11;
/// 一个 MSI-X 表项的字节数。
/// Size of one MSI-X table entry in bytes.
pub const MSIX_TABLE_ENTRY: u64 = 16;
/// MSI-X 控制字段能表示的最大向量数（11 位字段 + 1）。
/// Largest vector count representable by the MSI-X control field.
pub const MSIX_MAX_ENTRIES: u16 = 2048;

/// MSI-X 控制字段的全局使能位（位 15）。
/// Global-enable bit of the MSI-X control field.
pub const MSIX_CONTROL_ENABLE: u16 = 0x8000;
/// MSI-X 控制字段的功能屏蔽位（位 14）。
/// Function-mask bit of the MSI-X control field.
pub const MSIX_CONTROL_FUNCTION_MASK: u16 = 0x4000;
/// MSI-X 表项向量控制字段的屏蔽位（位 0）。
/// Per-vector mask bit of an MSI-X table entry.
pub const MSIX_ENTRY_MASK_BIT: u32 = 1;
/// MSI-X 表项中消息地址低半部分的字下标。
/// Word index of the low half of the message address.
pub const MSIX_ENTRY_ADDR_LOW: usize = 0;
/// MSI-X 表项中消息地址高半部分的字下标。
/// Word index of the high half of the message address.
pub const MSIX_ENTRY_ADDR_HIGH: usize = 1;
/// MSI-X 表项中消息数据的字下标。
/// Word index of the message data.
pub const MSIX_ENTRY_DATA: usize = 2;
/// MSI-X 表项中向量控制字段的字下标。
/// Word index of the vector control field.
pub const MSIX_ENTRY_CONTROL: usize = 3;

/// 一个 MSI-X 表项（四个 32 位字，按小端序位于表内）。
///
/// 表项布局与屏蔽位由本类型解释；写入设备由调用者完成。
/// One MSI-X table entry; the layout and mask bit are interpreted here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsixEntry {
    words: [u32; 4],
}

impl MsixEntry {
    /// 由四个原始字构造（不做消息合法性判断）。
    /// Builds an entry from four raw words.
    pub const fn from_words(words: [u32; 4]) -> MsixEntry {
        MsixEntry { words }
    }

    /// 四个原始字（小端序）。
    /// The four raw words in little-endian order.
    pub const fn words(self) -> [u32; 4] {
        self.words
    }

    /// 组合出的 64 位消息地址。
    /// The composed 64-bit message address.
    pub const fn address(self) -> u64 {
        self.words[MSIX_ENTRY_ADDR_LOW] as u64 | (self.words[MSIX_ENTRY_ADDR_HIGH] as u64) << 32
    }

    /// 消息数据。
    /// Message data.
    pub const fn data(self) -> u32 {
        self.words[MSIX_ENTRY_DATA]
    }

    /// 该项是否被屏蔽（向量控制位 0）。
    /// Whether the entry is masked.
    pub const fn masked(self) -> bool {
        self.words[MSIX_ENTRY_CONTROL] & MSIX_ENTRY_MASK_BIT != 0
    }

    /// 设置消息地址与数据；地址未按 4 字节对齐时返回 `None` 且不产生新表项。
    /// Replaces the message; `None` when the address is not 4-byte aligned.
    pub const fn with_message(self, address: u64, data: u32) -> Option<MsixEntry> {
        if address & 0x3 != 0 {
            return None;
        }
        let mut words = self.words;
        words[MSIX_ENTRY_ADDR_LOW] = address as u32;
        words[MSIX_ENTRY_ADDR_HIGH] = (address >> 32) as u32;
        words[MSIX_ENTRY_DATA] = data;
        Some(MsixEntry { words })
    }

    /// 设置或清除屏蔽位，消息字段保持不变。
    /// Sets or clears the mask bit, keeping the message unchanged.
    pub const fn with_mask(self, masked: bool) -> MsixEntry {
        let mut words = self.words;
        if masked {
            words[MSIX_ENTRY_CONTROL] |= MSIX_ENTRY_MASK_BIT;
        } else {
            words[MSIX_ENTRY_CONTROL] &= !MSIX_ENTRY_MASK_BIT;
        }
        MsixEntry { words }
    }
}

/// 置位 MSI-X 控制字段的全局使能位。
/// Sets the global-enable bit.
pub const fn msix_control_enable(control: u16) -> u16 {
    control | MSIX_CONTROL_ENABLE
}

/// 清除 MSI-X 控制字段的全局使能位。
/// Clears the global-enable bit.
pub const fn msix_control_disable(control: u16) -> u16 {
    control & !MSIX_CONTROL_ENABLE
}

/// 置位或清除 MSI-X 控制字段的功能屏蔽位。
/// Sets or clears the function-mask bit.
pub const fn msix_control_set_function_masked(control: u16, masked: bool) -> u16 {
    if masked {
        control | MSIX_CONTROL_FUNCTION_MASK
    } else {
        control & !MSIX_CONTROL_FUNCTION_MASK
    }
}

/// MSI-X 控制字段是否已全局使能。
/// Whether the global-enable bit is set.
pub const fn msix_control_enabled(control: u16) -> bool {
    control & MSIX_CONTROL_ENABLE != 0
}

/// MSI-X 控制字段的功能屏蔽位是否已置位。
/// Whether the function-mask bit is set.
pub const fn msix_control_function_masked(control: u16) -> bool {
    control & MSIX_CONTROL_FUNCTION_MASK != 0
}

/// MSI / MSI-X 能力解析错误。
/// MSI / MSI-X capability parsing error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsiConfigError {
    /// 配置空间读取失败。
    /// A configuration-space read failed.
    Unreachable,
    /// 能力链非法，或同一功能出现重复的同类能力。
    /// The capability chain is malformed or repeats the same capability.
    BadCapability,
    /// BAR 指示寄存器（BIR）超出 0..=5。
    /// The BAR indicator register is outside 0..=5.
    BadBir,
    /// 表或 PBA 偏移没有按 8 字节对齐。
    /// A table or PBA offset is not 8-byte aligned.
    MisalignedOffset,
    /// 表或 PBA 超出所指示的 BAR。
    /// The table or PBA extends beyond the indicated BAR.
    BeyondBar,
    /// 所指示的 BAR 未实现或不是内存 BAR。
    /// The indicated BAR is absent or is not a memory BAR.
    NotMemoryBar,
}

impl MsiConfigError {
    /// 规范名。
    /// Canonical name.
    pub const fn name(self) -> &'static str {
        match self {
            MsiConfigError::Unreachable => "system.device.error.config_unreachable",
            MsiConfigError::BadCapability => "system.device.error.bad_capability",
            MsiConfigError::BadBir => "system.device.error.bad_bir",
            MsiConfigError::MisalignedOffset => "system.device.error.misaligned_offset",
            MsiConfigError::BeyondBar => "system.device.error.beyond_bar",
            MsiConfigError::NotMemoryBar => "system.device.error.bar_not_memory",
        }
    }
}

/// MSI 能力（能力号 0x05）的只读快照。
/// Read-only snapshot of an MSI capability (ID 0x05).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsiCapability {
    offset: u8,
    control: u16,
}

impl MsiCapability {
    /// 能力结构在配置空间中的偏移。
    /// Offset of the capability structure.
    pub const fn offset(&self) -> u8 {
        self.offset
    }

    /// 可请求的消息数（log2）。
    /// Requested message count as log2.
    pub const fn log2_vectors(&self) -> u8 {
        (self.control & 0x7) as u8
    }

    /// 可请求的消息数（`1 << log2`）。
    /// Requested message count.
    pub const fn vectors(&self) -> u16 {
        1u16 << self.log2_vectors()
    }

    /// 是否支持 64 位消息地址。
    /// Whether a 64-bit message address is supported.
    pub const fn address64(&self) -> bool {
        self.control & 0x0080 != 0
    }

    /// 是否支持每向量屏蔽。
    /// Whether per-vector masking is supported.
    pub const fn per_vector_mask(&self) -> bool {
        self.control & 0x0100 != 0
    }
}

/// MSI-X 表与 PBA（待决位数组）的位置，构造函数完成全部合法性校验。
/// Location of the MSI-X table and pending-bit array, validated at construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsixTable {
    table_size: u16,
    table_bir: u8,
    table_offset: u32,
    pba_bir: u8,
    pba_offset: u32,
}

impl MsixTable {
    /// 由 BIR / 偏移 / 向量数与各 BAR 的尺寸构造；非法时返回结构化错误且不产生对象。
    ///
    /// 拒绝：向量数为 0 或超出 11 位字段、BIR 超出 0..=5、偏移未按 8 字节对齐、
    /// 所指示的 BAR 未实现或不是内存 BAR、表或 PBA 超出 BAR 尺寸。
    /// Builds a validated table/PBA location from raw fields and BAR sizes.
    pub fn new(
        table_size: u16,
        table_bir: u8,
        table_offset: u32,
        pba_bir: u8,
        pba_offset: u32,
        bars: &[Bar; MAX_BARS],
    ) -> Result<MsixTable, MsiConfigError> {
        if table_size == 0 || table_size > MSIX_MAX_ENTRIES {
            return Err(MsiConfigError::BadCapability);
        }
        if table_bir > 5 || pba_bir > 5 {
            return Err(MsiConfigError::BadBir);
        }
        if table_offset % 8 != 0 || pba_offset % 8 != 0 {
            return Err(MsiConfigError::MisalignedOffset);
        }
        for bir in [table_bir, pba_bir] {
            if !matches!(bars[bir as usize], Bar::Memory { .. }) {
                return Err(MsiConfigError::NotMemoryBar);
            }
        }
        let table_bytes = table_size as u64 * MSIX_TABLE_ENTRY;
        if !bar_holds(&bars[table_bir as usize], table_offset, table_bytes) {
            return Err(MsiConfigError::BeyondBar);
        }
        // PBA 每个向量一位，按 64 位向上取整，并以 8 字节为访问单位。
        let pba_bytes = (table_size as u64).div_ceil(64) * 8;
        if !bar_holds(&bars[pba_bir as usize], pba_offset, pba_bytes) {
            return Err(MsiConfigError::BeyondBar);
        }
        Ok(MsixTable { table_size, table_bir, table_offset, pba_bir, pba_offset })
    }

    /// 向量数（表项数）。
    /// Number of table entries (vectors).
    pub const fn table_size(&self) -> u16 {
        self.table_size
    }

    /// 表所在的 BAR 号。
    /// BAR holding the table.
    pub const fn table_bir(&self) -> u8 {
        self.table_bir
    }

    /// 表在 BAR 内的字节偏移。
    /// Byte offset of the table inside its BAR.
    pub const fn table_offset(&self) -> u32 {
        self.table_offset
    }

    /// PBA 所在的 BAR 号。
    /// BAR holding the PBA.
    pub const fn pba_bir(&self) -> u8 {
        self.pba_bir
    }

    /// PBA 在 BAR 内的字节偏移。
    /// Byte offset of the PBA inside its BAR.
    pub const fn pba_offset(&self) -> u32 {
        self.pba_offset
    }

    /// 表项 `index` 在表内的字节偏移；下标越界返回 `None`。
    /// Byte offset of table entry `index`, or `None` when out of range.
    pub const fn entry_offset(&self, index: u16) -> Option<u64> {
        if index >= self.table_size {
            return None;
        }
        Some(self.table_offset as u64 + index as u64 * MSIX_TABLE_ENTRY)
    }

    /// PBA 占用的字节数（每个向量一位，按 64 位向上取整）。
    /// PBA length in bytes.
    pub const fn pba_bytes(&self) -> u64 {
        (self.table_size as u64).div_ceil(64) * 8
    }

    /// 表项 `index` 对应的 PBA 字偏移；下标越界返回 `None`。
    /// Byte offset of the PBA word for `index`, or `None` when out of range.
    pub const fn pba_word_offset(&self, index: u16) -> Option<u64> {
        if index >= self.table_size {
            return None;
        }
        Some(self.pba_offset as u64 + (index as u64 / 64) * 8)
    }
}

/// 从已读出的 PBA 字中取表项 `entry` 的待决位。
///
/// 表项下标越界或 PBA 字不足时返回 `None`，不猜测。
/// Reads the pending bit of `entry` from the given PBA words.
pub fn msix_pba_pending(pba: &[u64], table_size: u16, entry: u16) -> Option<bool> {
    if entry >= table_size {
        return None;
    }
    let word = *pba.get((entry / 64) as usize)?;
    Some(word & (1u64 << (entry % 64)) != 0)
}

/// `offset` 起 `bytes` 字节的区间是否完整落在内存 BAR 内。
/// Whether `bytes` starting at `offset` fit inside a memory BAR.
fn bar_holds(bar: &Bar, offset: u32, bytes: u64) -> bool {
    match *bar {
        Bar::Memory { size, .. } => offset as u64 + bytes <= size,
        _ => false,
    }
}

/// MSI-X 能力（能力号 0x11）的只读快照。
/// Read-only snapshot of an MSI-X capability (ID 0x11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsixCapability {
    offset: u8,
    control: u16,
    table: MsixTable,
}

impl MsixCapability {
    /// 能力结构在配置空间中的偏移。
    /// Offset of the capability structure.
    pub const fn offset(&self) -> u8 {
        self.offset
    }

    /// 表与 PBA 的位置。
    /// Table and PBA location.
    pub const fn table(&self) -> MsixTable {
        self.table
    }

    /// 全局使能位（控制字段位 15）。
    /// Global enable bit.
    pub const fn enabled(&self) -> bool {
        self.control & 0x8000 != 0
    }

    /// 功能屏蔽位（控制字段位 14）。
    /// Function mask bit.
    pub const fn function_masked(&self) -> bool {
        self.control & 0x4000 != 0
    }
}

/// 在能力链中查找 `want`；没有返回 `Ok(None)`，出现两次或链非法返回错误。
/// Finds a capability by ID; `Ok(None)` when absent.
fn find_capability(
    cfg: &mut dyn ConfigSpace,
    bdf: Bdf,
    want: u8,
) -> Result<Option<u8>, MsiConfigError> {
    let mut found = None;
    let mut duplicate = false;
    for_each_capability(cfg, bdf, |id, at| {
        if id == want {
            if found.is_some() {
                duplicate = true;
                return false;
            }
            found = Some(at);
        }
        true
    })
    .map_err(|e| match e {
        PciError::Unreachable => MsiConfigError::Unreachable,
        PciError::BadBar | PciError::BadCapability => MsiConfigError::BadCapability,
    })?;
    if duplicate {
        Err(MsiConfigError::BadCapability)
    } else {
        Ok(found)
    }
}

/// 解析功能的 MSI 能力；没有该能力返回 `Ok(None)`。
///
/// 只读配置空间，不修改设备状态。
/// Parses the MSI capability of `bdf`; `Ok(None)` when absent.
pub fn parse_msi(
    cfg: &mut dyn ConfigSpace,
    bdf: Bdf,
) -> Result<Option<MsiCapability>, MsiConfigError> {
    let Some(at) = find_capability(cfg, bdf, CAP_ID_MSI)? else {
        return Ok(None);
    };
    let word = cfg.read32(bdf, at as u16).ok_or(MsiConfigError::Unreachable)?;
    Ok(Some(MsiCapability { offset: at, control: (word >> 16) as u16 }))
}

/// 解析功能的 MSI-X 能力，并用调用者给出的 BAR 尺寸校验表与 PBA；没有该能力返回 `Ok(None)`。
///
/// 只读配置空间，既不写设备的 MSI-X 表，也不改全局使能 / 功能屏蔽位。
/// Parses the MSI-X capability and validates table/PBA placement against the given BARs.
pub fn parse_msix(
    cfg: &mut dyn ConfigSpace,
    bdf: Bdf,
    bars: &[Bar; MAX_BARS],
) -> Result<Option<MsixCapability>, MsiConfigError> {
    let Some(at) = find_capability(cfg, bdf, CAP_ID_MSIX)? else {
        return Ok(None);
    };
    let header = cfg.read32(bdf, at as u16).ok_or(MsiConfigError::Unreachable)?;
    let table_word = cfg.read32(bdf, at as u16 + 4).ok_or(MsiConfigError::Unreachable)?;
    let pba_word = cfg.read32(bdf, at as u16 + 8).ok_or(MsiConfigError::Unreachable)?;
    let control = (header >> 16) as u16;
    let table_size = (control & 0x07FF) + 1;
    let table = MsixTable::new(
        table_size,
        (table_word & 0x7) as u8,
        table_word & !0x7,
        (pba_word & 0x7) as u8,
        pba_word & !0x7,
        bars,
    )?;
    Ok(Some(MsixCapability { offset: at, control, table }))
}

/// 枚举得到的一个功能。
/// One function found by enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Function {
    /// 地址。
    pub bdf: Bdf,
    /// 头部快照。
    pub header: Header,
}

/// 穷举扫描 `buses` 内每条总线的每个设备；功能 0 标为多功能时再查功能 1–7。
///
/// 对每个存在的功能回调一次，回调返回 `false` 时提前停止；返回交出的功能个数。
/// 穷举而不是沿桥递归，因此桥的次级总线号是否已由固件分配不影响结果，循环次数有固定上界。
/// Brute-force scan of `buses`, calling `f` for each present function; returns how many were reported.
pub fn enumerate(
    cfg: &mut dyn ConfigSpace,
    buses: RangeInclusive<u8>,
    mut f: impl FnMut(&Function) -> bool,
) -> Result<usize, PciError> {
    let mut found = 0usize;
    for bus in buses {
        for device in 0..DEVICES_PER_BUS {
            let Some(first) = Bdf::new(bus, device, 0) else { continue };
            let Some(header) = read_header(cfg, first)? else { continue };
            found += 1;
            if !f(&Function { bdf: first, header }) {
                return Ok(found);
            }
            if !header.multifunction {
                continue;
            }
            for function in 1..FUNCTIONS_PER_DEVICE {
                let Some(bdf) = Bdf::new(bus, device, function) else { continue };
                if let Some(header) = read_header(cfg, bdf)? {
                    found += 1;
                    if !f(&Function { bdf, header }) {
                        return Ok(found);
                    }
                }
            }
        }
    }
    Ok(found)
}

/// 打开或关闭 `bdf` 的总线主控位，返回修改前该位是否已打开。
///
/// MSI / MSI-X 消息本身是设备发起的内存写，未打开总线主控时会被静默丢弃，驱动必须显式打开。
/// 只改命令半字的这一位，状态半字写 0（写 1 清除的错误位不会被误清）；
/// 读或写不可达时返回 [`PciError::Unreachable`]，读失败时不写任何寄存器。
/// Sets or clears the bus-master bit of `bdf`, returning whether it was set before.
pub fn set_bus_master(cfg: &mut dyn ConfigSpace, bdf: Bdf, on: bool) -> Result<bool, PciError> {
    let command = read(cfg, bdf, REG_COMMAND)? & 0xFFFF;
    let was_on = command & COMMAND_BUS_MASTER != 0;
    let next = if on { command | COMMAND_BUS_MASTER } else { command & !COMMAND_BUS_MASTER };
    if next != command {
        write(cfg, bdf, REG_COMMAND, next)?;
    }
    Ok(was_on)
}

fn read(cfg: &mut dyn ConfigSpace, bdf: Bdf, offset: u16) -> Result<u32, PciError> {
    cfg.read32(bdf, offset).ok_or(PciError::Unreachable)
}

fn write(cfg: &mut dyn ConfigSpace, bdf: Bdf, offset: u16, value: u32) -> Result<(), PciError> {
    cfg.write32(bdf, offset, value).then_some(()).ok_or(PciError::Unreachable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// 宿主上的设备模型：每个功能 256 字节配置空间；BAR 按尺寸掩码响应写入；状态半字「写 1 清除」。
    #[derive(Default)]
    struct Model {
        space: BTreeMap<Bdf, [u32; 64]>,
        /// 每个 (功能, BAR 槽) 的可写位掩码；未列出的槽位只读为 0。
        masks: BTreeMap<(Bdf, usize), u32>,
        /// 这些功能的写操作失败（模拟后端拒绝）。
        refuse_writes: Vec<Bdf>,
        writes: usize,
    }

    impl Model {
        fn add(&mut self, bdf: Bdf, vendor: u16, device: u16, class: u32, header_type: u8) {
            let mut s = [0u32; 64];
            s[0] = (device as u32) << 16 | vendor as u32;
            s[1] = 0x0007; // I/O + 内存 + 总线主控
            s[2] = class;
            s[3] = (header_type as u32) << 16;
            self.space.insert(bdf, s);
        }

        fn bar(&mut self, bdf: Bdf, slot: usize, value: u32, mask: u32) {
            self.space.get_mut(&bdf).unwrap()[4 + slot] = value;
            self.masks.insert((bdf, slot), mask);
        }
    }

    impl ConfigSpace for Model {
        fn read32(&mut self, bdf: Bdf, offset: u16) -> Option<u32> {
            assert_eq!(offset % 4, 0);
            if offset >= 256 {
                return None;
            }
            Some(self.space.get(&bdf).map_or(0xFFFF_FFFF, |s| s[offset as usize / 4]))
        }

        fn write32(&mut self, bdf: Bdf, offset: u16, value: u32) -> bool {
            if self.refuse_writes.contains(&bdf) || offset >= 256 {
                return false;
            }
            self.writes += 1;
            let Some(s) = self.space.get_mut(&bdf) else { return true };
            let idx = offset as usize / 4;
            if (4..10).contains(&idx) {
                let slot = idx - 4;
                let mask = self.masks.get(&(bdf, slot)).copied().unwrap_or(0);
                let low_flags = s[idx] & 0xF & !mask;
                s[idx] = (value & mask) | low_flags;
            } else if idx == 1 {
                // 命令半字可写；状态半字写 1 清除。
                let status = (s[1] >> 16) & !(value >> 16);
                s[1] = status << 16 | (value & 0xFFFF);
            } else {
                s[idx] = value;
            }
            true
        }
    }

    fn bdf(b: u8, d: u8, f: u8) -> Bdf {
        Bdf::new(b, d, f).unwrap()
    }

    #[test]
    fn bdf_validates_ranges() {
        assert!(Bdf::new(255, 31, 7).is_some());
        assert_eq!(Bdf::new(0, 32, 0), None);
        assert_eq!(Bdf::new(0, 0, 8), None);
    }

    #[test]
    fn ecam_address_encoding_and_rejections() {
        let e = Ecam { base: 0x3000_0000, segment: 0, bus_start: 0, bus_end: 0xFF };
        assert_eq!(e.address(bdf(0, 0, 0), 0), Some(0x3000_0000));
        assert_eq!(e.address(bdf(1, 2, 3), 0x10), Some(0x3000_0000 + (1 << 20) + (2 << 15) + (3 << 12) + 0x10));
        assert_eq!(e.address(bdf(0, 0, 0), 0xFFC), Some(0x3000_0FFC));
        assert_eq!(e.len(), 256 << 20);
        let w = Ecam { base: 0xE000_0000, segment: 1, bus_start: 0x10, bus_end: 0x1F };
        assert_eq!(w.address(bdf(0x10, 0, 0), 0), Some(0xE000_0000));
        assert_eq!(w.address(bdf(0x0F, 0, 0), 0), None, "总线在窗口之前");
        assert_eq!(w.address(bdf(0x20, 0, 0), 0), None, "总线在窗口之后");
        assert_eq!(w.address(bdf(0x10, 0, 0), 2), None, "未对齐");
        assert_eq!(w.address(bdf(0x10, 0, 0), 0x1000), None, "越过 4 KiB");
        let broken = Ecam { base: 0, segment: 0, bus_start: 5, bus_end: 4 };
        assert!(broken.is_empty());
        assert_eq!(broken.address(bdf(5, 0, 0), 0), None);
        let top = Ecam { base: u64::MAX - 0xFFF, segment: 0, bus_start: 0, bus_end: 0 };
        assert_eq!(top.address(bdf(0, 1, 0), 0), None, "基址加偏移溢出");
    }

    #[test]
    fn legacy_address_encoding_and_rejections() {
        assert_eq!(legacy_address(bdf(0, 0, 0), 0), Some(0x8000_0000));
        assert_eq!(legacy_address(bdf(2, 31, 7), 0xFC), Some(0x8000_0000 | 2 << 16 | 31 << 11 | 7 << 8 | 0xFC));
        assert_eq!(legacy_address(bdf(0, 0, 0), 0x100), None);
        assert_eq!(legacy_address(bdf(0, 0, 0), 1), None);
    }

    #[test]
    fn header_decodes_identity_and_absent_function() {
        let mut m = Model::default();
        let d = bdf(0, 3, 0);
        m.add(d, 0x1AF4, 0x1041, 0x0200_0001, 0x80);
        m.space.get_mut(&d).unwrap()[11] = 0x0001_1AF4;
        m.space.get_mut(&d).unwrap()[15] = 0x0000_010B;
        let h = read_header(&mut m, d).unwrap().unwrap();
        assert_eq!((h.vendor, h.device, h.revision), (0x1AF4, 0x1041, 1));
        assert_eq!((h.class, h.subclass, h.prog_if), (0x02, 0x00, 0x00));
        assert_eq!(h.kind, HeaderKind::Endpoint);
        assert!(h.multifunction);
        assert_eq!((h.subsystem_vendor, h.subsystem, h.interrupt_pin), (0x1AF4, 1, 1));
        assert_eq!(read_header(&mut m, bdf(0, 4, 0)), Ok(None));
        let b = bdf(0, 5, 0);
        m.add(b, 0x8086, 0x1234, 0x0604_0000, 0x01);
        let hb = read_header(&mut m, b).unwrap().unwrap();
        assert_eq!((hb.kind, hb.subsystem), (HeaderKind::Bridge, 0));
        m.add(bdf(0, 6, 0), 0x8086, 0x1, 0, 0x7E);
        assert_eq!(read_header(&mut m, bdf(0, 6, 0)).unwrap().unwrap().kind, HeaderKind::Unknown(0x7E));
        assert_eq!(HeaderKind::Unknown(3).bar_count(), 0);
    }

    #[test]
    fn unreachable_config_reported() {
        struct Dead;
        impl ConfigSpace for Dead {
            fn read32(&mut self, _: Bdf, _: u16) -> Option<u32> {
                None
            }
            fn write32(&mut self, _: Bdf, _: u16, _: u32) -> bool {
                false
            }
        }
        assert_eq!(read_header(&mut Dead, bdf(0, 0, 0)), Err(PciError::Unreachable));
        assert_eq!(enumerate(&mut Dead, 0..=0, |_| true), Err(PciError::Unreachable));
        assert_eq!(PciError::Unreachable.name(), "system.device.error.config_unreachable");
    }

    #[test]
    fn bars_sized_and_registers_restored() {
        let mut m = Model::default();
        let d = bdf(0, 1, 0);
        m.add(d, 0x1AF4, 0x1000, 0, 0);
        m.space.get_mut(&d).unwrap()[1] |= 0x0010_0000 | 0x0100_0000; // 状态位：能力链 + 一个「写 1 清除」位
        m.bar(d, 0, 0x0000_C041, 0xFFFF_FFE1); // I/O，32 字节；高 16 位按全 1 读回
        m.bar(d, 1, 0xFEB0_0000, 0xFFFF_F000); // 32 位内存，4 KiB
        m.bar(d, 2, 0x0000_000C, 0xFFFF_C00C); // 64 位可预取，低半（尺寸 16 KiB）
        m.bar(d, 3, 0x0000_0001, 0xFFFF_FFFF); // 高半：基址高 32 位为 1
        m.bar(d, 5, 0x0000_0001, 0x0000_FFF1); // I/O，高 16 位读回 0，16 字节
        let before = m.space[&d];
        let bars = probe_bars(&mut m, d, HeaderKind::Endpoint).unwrap();
        assert_eq!(bars[0], Bar::Io { base: 0xC040, size: 0x20 });
        assert_eq!(bars[1], Bar::Memory { base: 0xFEB0_0000, size: 0x1000, prefetchable: false, wide: false });
        assert_eq!(bars[2], Bar::Memory { base: 0x1_0000_0000, size: 0x4000, prefetchable: true, wide: true });
        assert_eq!(bars[3], Bar::None, "64 位 BAR 的高半槽位");
        assert_eq!(bars[4], Bar::None, "未实现的槽位");
        assert_eq!(bars[5], Bar::Io { base: 0, size: 0x10 });
        assert_eq!(m.space[&d], before, "探测后配置空间（含状态位）与探测前一致");
    }

    #[test]
    fn bridge_probes_only_two_bars() {
        let mut m = Model::default();
        let d = bdf(0, 2, 0);
        m.add(d, 0x8086, 0x1, 0x0604_0000, 1);
        m.bar(d, 0, 0xFE00_0000, 0xFFF0_0000);
        m.bar(d, 2, 0xFFFF_FFF0, 0xFFFF_FFF0); // 桥的 0x18 是总线号寄存器，不得被当作 BAR 探测
        let before = m.space[&d];
        let bars = probe_bars(&mut m, d, HeaderKind::Bridge).unwrap();
        assert_eq!(bars[0], Bar::Memory { base: 0xFE00_0000, size: 1 << 20, prefetchable: false, wide: false });
        assert!(bars[1..].iter().all(|b| *b == Bar::None));
        assert_eq!(m.space[&d], before);
    }

    #[test]
    fn bad_bar_rejected_without_residue() {
        let mut m = Model::default();
        let d = bdf(0, 1, 0);
        m.add(d, 0x1AF4, 0x1000, 0, 0);
        m.bar(d, 0, 0xFEB0_0000, 0xFFFF_F000);
        m.bar(d, 5, 0x0000_0004, 0xFFFF_F004); // 64 位 BAR 落在最后一个槽：没有高半部分
        let before = m.space[&d];
        assert_eq!(probe_bars(&mut m, d, HeaderKind::Endpoint), Err(PciError::BadBar));
        assert_eq!(m.space[&d], before, "失败后无残留改动");
        let e = bdf(0, 2, 0);
        m.add(e, 0x1AF4, 0x1000, 0, 0);
        m.bar(e, 1, 0x0000_0002, 0xFFFF_F002); // 保留的内存类型 01
        let before = m.space[&e];
        assert_eq!(probe_bars(&mut m, e, HeaderKind::Endpoint), Err(PciError::BadBar));
        assert_eq!(m.space[&e], before);
        assert_eq!(PciError::BadBar.name(), "system.device.error.bad_bar");
    }

    #[test]
    fn refused_writes_reported_and_nothing_changed() {
        let mut m = Model::default();
        let d = bdf(0, 1, 0);
        m.add(d, 0x1AF4, 0x1000, 0, 0);
        m.bar(d, 0, 0xFEB0_0000, 0xFFFF_F000);
        m.refuse_writes.push(d);
        let before = m.space[&d];
        assert_eq!(probe_bars(&mut m, d, HeaderKind::Endpoint), Err(PciError::Unreachable));
        assert_eq!(m.space[&d], before);
        assert_eq!(m.writes, 0);
    }

    #[test]
    fn bus_master_toggles_only_its_bit_and_keeps_status() {
        let mut m = Model::default();
        let d = bdf(0, 3, 0);
        m.add(d, 0x1AF4, 0x1044, 0, 0);
        // 状态半字置一个写 1 清除的错误位（位 29，收到主控中止）。
        m.space.get_mut(&d).unwrap()[1] = (1 << 29) | 0x0103;
        assert_eq!(set_bus_master(&mut m, d, true), Ok(false));
        assert_eq!(m.space[&d][1], (1 << 29) | 0x0107, "只置总线主控位，状态位保留");
        let writes = m.writes;
        assert_eq!(set_bus_master(&mut m, d, true), Ok(true));
        assert_eq!(m.writes, writes, "已打开时不再写寄存器");
        assert_eq!(set_bus_master(&mut m, d, false), Ok(true));
        assert_eq!(m.space[&d][1], (1 << 29) | 0x0103);
    }

    #[test]
    fn bus_master_refused_or_unreachable_changes_nothing() {
        let mut m = Model::default();
        let d = bdf(0, 3, 0);
        m.add(d, 0x1AF4, 0x1044, 0, 0);
        m.space.get_mut(&d).unwrap()[1] = 0x0003;
        m.refuse_writes.push(d);
        let before = m.space[&d];
        assert_eq!(set_bus_master(&mut m, d, true), Err(PciError::Unreachable));
        assert_eq!(m.space[&d], before);
        assert_eq!(m.writes, 0);
        // 超出配置空间的功能：读不可达，不发生任何写。
        struct Dead;
        impl ConfigSpace for Dead {
            fn read32(&mut self, _: Bdf, _: u16) -> Option<u32> {
                None
            }
            fn write32(&mut self, _: Bdf, _: u16, _: u32) -> bool {
                panic!("读失败后不得写入");
            }
        }
        assert_eq!(set_bus_master(&mut Dead, d, true), Err(PciError::Unreachable));
    }

    fn with_caps(m: &mut Model, d: Bdf, chain: &[(u8, u8, u8)]) {
        let s = m.space.get_mut(&d).unwrap();
        s[1] |= STATUS_CAP_LIST;
        s[REG_CAP_PTR as usize / 4] = chain.first().map_or(0, |c| c.1 as u32);
        for &(id, at, next) in chain {
            s[at as usize / 4] = (next as u32) << 8 | id as u32;
        }
    }

    #[test]
    fn capabilities_walked_in_order() {
        let mut m = Model::default();
        let d = bdf(0, 1, 0);
        m.add(d, 0x1AF4, 0x1041, 0, 0);
        with_caps(&mut m, d, &[(0x11, 0x98, 0x84), (0x09, 0x84, 0x70), (0x09, 0x70, 0)]);
        let mut seen = Vec::new();
        for_each_capability(&mut m, d, |id, at| {
            seen.push((id, at));
            true
        })
        .unwrap();
        assert_eq!(seen, vec![(0x11, 0x98), (0x09, 0x84), (0x09, 0x70)]);
        let mut first = None;
        for_each_capability(&mut m, d, |id, _| {
            first = Some(id);
            false
        })
        .unwrap();
        assert_eq!(first, Some(0x11));
        let plain = bdf(0, 2, 0);
        m.add(plain, 0x1AF4, 0x1000, 0, 0);
        for_each_capability(&mut m, plain, |_, _| panic!("无能力链时不得回调")).unwrap();
    }

    #[test]
    fn malformed_capability_chains_rejected() {
        let mut m = Model::default();
        let lp = bdf(0, 1, 0);
        m.add(lp, 0x1AF4, 0x1041, 0, 0);
        with_caps(&mut m, lp, &[(0x09, 0x40, 0x50), (0x09, 0x50, 0x40)]); // 环
        assert_eq!(for_each_capability(&mut m, lp, |_, _| true), Err(PciError::BadCapability));
        let low = bdf(0, 2, 0);
        m.add(low, 0x1AF4, 0x1041, 0, 0);
        with_caps(&mut m, low, &[(0x09, 0x40, 0x10)]); // 指回头部区
        assert_eq!(for_each_capability(&mut m, low, |_, _| true), Err(PciError::BadCapability));
        let odd = bdf(0, 3, 0);
        m.add(odd, 0x1AF4, 0x1041, 0, 0);
        with_caps(&mut m, odd, &[(0x09, 0x40, 0x52)]); // 未对齐
        assert_eq!(for_each_capability(&mut m, odd, |_, _| true), Err(PciError::BadCapability));
        assert_eq!(PciError::BadCapability.name(), "system.device.error.bad_capability");
    }

    #[test]
    fn enumerate_finds_single_and_multifunction_devices() {
        let mut m = Model::default();
        m.add(bdf(0, 0, 0), 0x8086, 0x29C0, 0x0600_0000, 0x00);
        m.add(bdf(0, 1, 0), 0x1AF4, 0x1000, 0x0200_0000, 0x00);
        m.add(bdf(0, 1, 3), 0x1AF4, 0x9999, 0, 0x00); // 功能 0 不是多功能 ⇒ 功能 3 不扫描
        m.add(bdf(0, 31, 0), 0x8086, 0x2918, 0x0601_0000, 0x80);
        m.add(bdf(0, 31, 2), 0x8086, 0x2922, 0x0106_0101, 0x00);
        m.add(bdf(0, 31, 3), 0x8086, 0x2930, 0x0C05_0000, 0x00);
        m.add(bdf(1, 0, 0), 0x1AF4, 0x1042, 0x0100_0000, 0x00);
        let mut seen = Vec::new();
        let n = enumerate(&mut m, 0..=1, |f| {
            seen.push((f.bdf, f.header.device));
            true
        })
        .unwrap();
        assert_eq!(n, 6);
        assert_eq!(
            seen,
            vec![
                (bdf(0, 0, 0), 0x29C0),
                (bdf(0, 1, 0), 0x1000),
                (bdf(0, 31, 0), 0x2918),
                (bdf(0, 31, 2), 0x2922),
                (bdf(0, 31, 3), 0x2930),
                (bdf(1, 0, 0), 0x1042),
            ]
        );
        assert_eq!(enumerate(&mut m, 0..=0, |f| f.bdf != bdf(0, 1, 0)), Ok(2), "回调返回 false 即停止");
        assert_eq!(m.writes, 0, "枚举只读");
    }

    const CAP_MSI: u8 = 0x60;
    const CAP_MSIX: u8 = 0x80;

    /// 写入一个能力头（ID / 下一项 / 控制字段）并把能力链指针指向 `at`。
    fn cap(m: &mut Model, d: Bdf, at: u8, id: u8, next: u8, control: u16) {
        let s = m.space.get_mut(&d).unwrap();
        s[1] |= STATUS_CAP_LIST;
        s[REG_CAP_PTR as usize / 4] = at as u32;
        s[at as usize / 4] = (control as u32) << 16 | (next as u32) << 8 | id as u32;
    }

    fn memory(size: u64) -> Bar {
        Bar::Memory { base: 0x1000, size, prefetchable: false, wide: false }
    }

    #[test]
    fn msi_capability_decodes_64bit_masking_and_message_count() {
        let mut m = Model::default();
        let d = bdf(0, 1, 0);
        m.add(d, 0x1AF4, 0x1041, 0, 0);
        // log2 = 2（4 条消息）+ 64 位地址 + 每向量屏蔽。
        cap(&mut m, d, CAP_MSI, CAP_ID_MSI, 0, 0x0182);
        let c = parse_msi(&mut m, d).unwrap().unwrap();
        assert_eq!(c.offset(), CAP_MSI);
        assert_eq!(c.log2_vectors(), 2);
        assert_eq!(c.vectors(), 4);
        assert!(c.address64());
        assert!(c.per_vector_mask());
        let plain = bdf(0, 2, 0);
        m.add(plain, 0x1AF4, 0x1000, 0, 0);
        assert_eq!(parse_msi(&mut m, plain), Ok(None), "没有能力链 ⇒ 没有 MSI");
        assert_eq!(MsiConfigError::BadBir.name(), "system.device.error.bad_bir");
    }

    #[test]
    fn msix_capability_decodes_table_and_pba_within_bars() {
        let mut m = Model::default();
        let d = bdf(0, 1, 0);
        m.add(d, 0x1AF4, 0x1041, 0, 0);
        // 表 4 项；全局使能 + 功能屏蔽。表 0x1000、PBA 0x3000，都在 BAR 1。
        cap(&mut m, d, CAP_MSIX, CAP_ID_MSIX, 0, 0xC003);
        let s = m.space.get_mut(&d).unwrap();
        s[CAP_MSIX as usize / 4 + 1] = 0x1000 | 1; // table BIR 1 / offset 0x1000
        s[CAP_MSIX as usize / 4 + 2] = 0x3000 | 1; // pba BIR 1 / offset 0x3000
        let mut bars = [Bar::None; MAX_BARS];
        bars[1] = memory(0x4000);
        let c = parse_msix(&mut m, d, &bars).unwrap().unwrap();
        assert_eq!(c.offset(), CAP_MSIX);
        assert!(c.enabled());
        assert!(c.function_masked());
        let t = c.table();
        assert_eq!(t.table_size(), 4);
        assert_eq!((t.table_bir(), t.pba_bir()), (1, 1));
        assert_eq!((t.table_offset(), t.pba_offset()), (0x1000, 0x3000));
        let plain = bdf(0, 2, 0);
        m.add(plain, 0x1AF4, 0x1000, 0, 0);
        assert_eq!(parse_msix(&mut m, plain, &bars), Ok(None));
    }

    #[test]
    fn msix_rejects_bad_bir_non_memory_and_out_of_range() {
        let mut m = Model::default();
        let d = bdf(0, 1, 0);
        m.add(d, 0x1AF4, 0x1041, 0, 0);
        cap(&mut m, d, CAP_MSIX, CAP_ID_MSIX, 0, 0x0003);
        let mut bars = [Bar::None; MAX_BARS];
        bars[1] = memory(0x4000);
        let s = m.space.get_mut(&d).unwrap();
        s[CAP_MSIX as usize / 4 + 2] = 0x3000 | 1;
        s[CAP_MSIX as usize / 4 + 1] = 0x1000 | 6; // BIR 6
        assert_eq!(parse_msix(&mut m, d, &bars), Err(MsiConfigError::BadBir));
        // BIR 合法但 BAR 未实现 / 是 I/O BAR。
        let s = m.space.get_mut(&d).unwrap();
        s[CAP_MSIX as usize / 4 + 1] = 0x1000 | 2;
        assert_eq!(parse_msix(&mut m, d, &bars), Err(MsiConfigError::NotMemoryBar));
        let mut io = bars;
        io[2] = Bar::Io { base: 0x1000, size: 0x20 };
        assert_eq!(parse_msix(&mut m, d, &io), Err(MsiConfigError::NotMemoryBar));
        // 表本身越出 BAR（16 × 4 = 64 字节，从 0x3FF0 起到 0x4030）。
        let mut small = [Bar::None; MAX_BARS];
        small[2] = memory(0x4000);
        let s = m.space.get_mut(&d).unwrap();
        s[CAP_MSIX as usize / 4 + 2] = 0x1000 | 2;
        s[CAP_MSIX as usize / 4 + 1] = 0x3FF0 | 2;
        assert_eq!(parse_msix(&mut m, d, &small), Err(MsiConfigError::BeyondBar));
        // PBA 越出 BAR。
        let s = m.space.get_mut(&d).unwrap();
        s[CAP_MSIX as usize / 4 + 1] = 0x1000 | 2;
        s[CAP_MSIX as usize / 4 + 2] = 0x4000 | 2;
        assert_eq!(parse_msix(&mut m, d, &small), Err(MsiConfigError::BeyondBar));
    }

    #[test]
    fn msix_table_constructor_rejects_misalignment_and_duplicate_capability() {
        let mut bars = [Bar::None; MAX_BARS];
        bars[1] = memory(0x4000);
        assert_eq!(
            MsixTable::new(4, 1, 0x1001, 1, 0x2000, &bars),
            Err(MsiConfigError::MisalignedOffset)
        );
        assert_eq!(
            MsixTable::new(4, 1, 0x1000, 1, 0x2001, &bars),
            Err(MsiConfigError::MisalignedOffset)
        );
        assert_eq!(MsixTable::new(0, 1, 0x1000, 1, 0x2000, &bars), Err(MsiConfigError::BadCapability));
        let mut m = Model::default();
        let d = bdf(0, 1, 0);
        m.add(d, 0x1AF4, 0x1041, 0, 0);
        // 同一功能的两个 MSI-X 能力：拒绝而不是随意取一个。
        cap(&mut m, d, CAP_MSIX, CAP_ID_MSIX, 0x90, 0x0003);
        let s = m.space.get_mut(&d).unwrap();
        s[0x90 / 4] = (CAP_ID_MSIX as u32) | 0 << 8;
        s[0x90 / 4] |= 0x0003 << 16;
        s[CAP_MSIX as usize / 4 + 1] = 0x1000 | 1;
        s[CAP_MSIX as usize / 4 + 2] = 0x2000 | 1;
        assert_eq!(parse_msix(&mut m, d, &bars), Err(MsiConfigError::BadCapability));
        assert_eq!(MsiConfigError::MisalignedOffset.name(), "system.device.error.misaligned_offset");
        assert_eq!(MsiConfigError::BeyondBar.name(), "system.device.error.beyond_bar");
        assert_eq!(MsiConfigError::NotMemoryBar.name(), "system.device.error.bar_not_memory");
    }

    #[test]
    fn msix_entry_layout_address_data_and_mask() {
        let raw = MsixEntry::from_words([0x1122_3344, 0x5566_7788, 0x42, 0]);
        assert_eq!(raw.address(), 0x5566_7788_1122_3344);
        assert_eq!(raw.data(), 0x42);
        assert!(!raw.masked());

        let masked = raw.with_mask(true);
        assert!(masked.masked());
        assert_eq!(masked.address(), raw.address(), "屏蔽不改变消息地址");
        assert_eq!(masked.words()[MSIX_ENTRY_ADDR_LOW], 0x1122_3344);
        assert!(!masked.with_mask(false).masked());

        let message = MsixEntry::from_words([0, 0, 0, MSIX_ENTRY_MASK_BIT])
            .with_message(0xFEE0_0000, 0x60)
            .unwrap();
        assert_eq!(message.address(), 0xFEE0_0000);
        assert_eq!(message.data(), 0x60);
        assert!(message.masked(), "换消息不改变屏蔽状态");
        assert_eq!(
            MsixEntry::from_words([0; 4]).with_message(0xFEE0_0001, 0x60),
            None,
            "地址未按 4 字节对齐"
        );
    }

    #[test]
    fn msix_control_bits_are_set_and_cleared_explicitly() {
        let v = msix_control_enable(0);
        assert_eq!(v, MSIX_CONTROL_ENABLE);
        assert!(msix_control_enabled(v));
        assert!(!msix_control_function_masked(v));

        let masked = msix_control_set_function_masked(v, true);
        assert_eq!(masked, MSIX_CONTROL_ENABLE | MSIX_CONTROL_FUNCTION_MASK);
        assert!(msix_control_enabled(masked));
        assert!(msix_control_function_masked(masked));

        let unmasked = msix_control_set_function_masked(masked, false);
        assert_eq!(unmasked, MSIX_CONTROL_ENABLE);
        assert!(!msix_control_enabled(msix_control_disable(masked)));
        assert!(
            msix_control_function_masked(msix_control_disable(masked)),
            "关闭全局使能不改变功能屏蔽位"
        );
    }

    #[test]
    fn msix_table_entry_and_pba_offsets_reject_out_of_range() {
        let mut bars = [Bar::None; MAX_BARS];
        bars[1] = memory(0x4000);
        let t = MsixTable::new(4, 1, 0x1000, 1, 0x2000, &bars).unwrap();
        assert_eq!(t.entry_offset(0), Some(0x1000));
        assert_eq!(t.entry_offset(3), Some(0x1000 + 3 * MSIX_TABLE_ENTRY));
        assert_eq!(t.entry_offset(4), None, "表项下标越界");
        assert_eq!(t.pba_bytes(), 8);
        assert_eq!(t.pba_word_offset(0), Some(0x2000));
        assert_eq!(t.pba_word_offset(3), Some(0x2000));
        assert_eq!(t.pba_word_offset(4), None, "PBA 表项下标越界");

        let mut wide = [Bar::None; MAX_BARS];
        wide[2] = memory(0x8000);
        let w = MsixTable::new(128, 2, 0x1000, 2, 0x4000, &wide).unwrap();
        assert_eq!(w.pba_bytes(), 16);
        assert_eq!(w.pba_word_offset(63), Some(0x4000));
        assert_eq!(w.pba_word_offset(64), Some(0x4008), "第二组 64 个向量");
        assert_eq!(w.pba_word_offset(127), Some(0x4008));
        assert_eq!(w.pba_word_offset(128), None);
    }

    #[test]
    fn msix_pba_pending_reads_the_right_bit_and_rejects_bad_input() {
        let pba = [0b1000u64, 1u64];
        assert_eq!(msix_pba_pending(&pba, 4, 3), Some(true));
        assert_eq!(msix_pba_pending(&pba, 4, 2), Some(false));
        assert_eq!(msix_pba_pending(&pba, 4, 4), None, "表项下标越界");
        assert_eq!(msix_pba_pending(&pba, 128, 64), Some(true), "第二组 64 位");
        assert_eq!(msix_pba_pending(&pba, 128, 65), Some(false));
        assert_eq!(msix_pba_pending(&pba[..1], 128, 64), None, "PBA 字不足");
    }

    #[test]
    fn msi_parsing_reports_unreachable_config() {
        struct Dead;
        impl ConfigSpace for Dead {
            fn read32(&mut self, _: Bdf, _: u16) -> Option<u32> {
                None
            }
            fn write32(&mut self, _: Bdf, _: u16, _: u32) -> bool {
                false
            }
        }
        let bars = [Bar::None; MAX_BARS];
        assert_eq!(parse_msi(&mut Dead, bdf(0, 0, 0)), Err(MsiConfigError::Unreachable));
        assert_eq!(parse_msix(&mut Dead, bdf(0, 0, 0), &bars), Err(MsiConfigError::Unreachable));
        assert_eq!(MsiConfigError::BadCapability.name(), "system.device.error.bad_capability");
    }
}
