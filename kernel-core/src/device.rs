//! `system.device` 的用户态二进制布局：过滤字、列表记录与完整设备描述的按字节编解码。
//! User-visible binary layout of `system.device`: filter word, list record and full description.
//!
//! # 职责与边界
//! * 只定义格式与编解码，不访问配置空间、不持有句柄、不做权限检查；语义由内核的系统调用实现负责。
//! * 所有整数按小端序逐字节写入定长缓冲区，因此用户程序可以安全地按相同偏移读取，不依赖 Rust 结构体的
//!   填充与对齐（内核从不把用户内存直接当作结构体引用）。
//! * 布局一经发布不得改变；新增字段只能占用保留区，或提高版本并同步用户态。
//!
//! # 记录大小
//! * [`RECORD_SIZE`]：`system.device.list` 的一条记录（BDF、ID、类与首个 BAR 摘要）。
//! * [`DESC_SIZE`]：`system.device.get` 的完整描述（身份、头部布局、全部 BAR）。
//! * [`FILTER_SIZE`]：过滤字占 32 位，作为系统调用的标量参数传递，不占用户缓冲区。
//!
//! 本模块不出现指令集专有内容，所有支持的架构共用同一份格式。

use crate::pci::{Bar, Bdf, Header, HeaderKind, MAX_BARS};

/// `system.device.list` 一条记录的字节数。
/// Size in bytes of one record returned by `system.device.list`.
pub const RECORD_SIZE: usize = 32;
/// `system.device.get` 完整描述的字节数。
/// Size in bytes of the full description returned by `system.device.get`.
pub const DESC_SIZE: usize = 24 + MAX_BARS * 24;
/// `system.device.capability.list` 一条能力记录的字节数。
/// Size in bytes of one capability record returned by `system.device.capability.list`.
pub const CAP_RECORD_SIZE: usize = 16;
/// PCI 厂商专有能力号（virtio 的现代能力都使用它）。
/// PCI vendor-specific capability ID (used by all modern virtio capabilities).
pub const CAP_ID_VENDOR: u8 = 0x09;
/// virtio 能力类型：通用配置（common configuration）。
/// Virtio capability type: common configuration.
pub const CAP_CFG_COMMON: u8 = 1;
/// virtio 能力类型：通知配置（notify configuration）。
/// Virtio capability type: notification configuration.
pub const CAP_CFG_NOTIFY: u8 = 2;
/// virtio 能力类型：中断状态（ISR）。
/// Virtio capability type: ISR status.
pub const CAP_CFG_ISR: u8 = 3;
/// virtio 能力类型：设备专用配置（device-specific configuration）。
/// Virtio capability type: device-specific configuration.
pub const CAP_CFG_DEVICE: u8 = 4;
/// virtio 能力类型：PCI 公共配置（PCI common configuration）。
/// Virtio capability type: PCI common configuration.
pub const CAP_CFG_PCI: u8 = 5;
/// 列表过滤字中「不限制厂商」的值。
/// Wildcard vendor value in the list filter word.
pub const FILTER_ALL_VENDOR: u16 = 0xFFFF;
/// 列表过滤字中「不限制类别」的值。
/// Wildcard class value in the list filter word.
pub const FILTER_ALL_CLASS: u8 = 0xFF;
/// BAR 摘要 / 描述中的 BAR 种类：未实现。
/// BAR kind: not implemented.
pub const BAR_KIND_NONE: u8 = 0;
/// BAR 摘要 / 描述中的 BAR 种类：I/O 端口。
/// BAR kind: I/O port.
pub const BAR_KIND_IO: u8 = 1;
/// BAR 摘要 / 描述中的 BAR 种类：内存映射。
/// BAR kind: memory mapped.
pub const BAR_KIND_MEMORY: u8 = 2;
/// BAR 标志位：可预取（仅内存 BAR 有意义）。
/// BAR flag: prefetchable (meaningful for memory BARs only).
pub const BAR_FLAG_PREFETCHABLE: u8 = 1 << 0;
/// BAR 标志位：64 位 BAR（占两个配置空间槽位）。
/// BAR flag: 64-bit BAR (occupies two configuration slots).
pub const BAR_FLAG_WIDE: u8 = 1 << 1;
/// 头部布局编码：普通设备。
/// Header kind encoding: endpoint.
pub const HEADER_KIND_ENDPOINT: u8 = 0;
/// 头部布局编码：PCI 到 PCI 桥。
/// Header kind encoding: PCI-to-PCI bridge.
pub const HEADER_KIND_BRIDGE: u8 = 1;
/// 头部布局编码：CardBus 桥。
/// Header kind encoding: CardBus bridge.
pub const HEADER_KIND_CARDBUS: u8 = 2;
/// 头部布局编码：未定义的头部类型。
/// Header kind encoding: unknown header type.
pub const HEADER_KIND_UNKNOWN: u8 = 3;

/// 把 BDF 打包成用户态使用的 32 位值：`bus << 16 | device << 8 | function`。
/// Packs a BDF into `bus << 16 | device << 8 | function`.
pub const fn pack_bdf(bdf: Bdf) -> u32 {
    (bdf.bus() as u32) << 16 | (bdf.device() as u32) << 8 | bdf.function() as u32
}

/// 从 32 位打包值还原 BDF；高 8 位必须为 0，设备号 / 功能号越界时返回 `None`。
/// Unpacks a BDF; rejects a non-zero high byte and out-of-range device/function.
pub const fn unpack_bdf(raw: u32) -> Option<Bdf> {
    if raw >> 24 != 0 {
        return None;
    }
    Bdf::new((raw >> 16) as u8, ((raw >> 8) & 0xFF) as u8, (raw & 0xFF) as u8)
}

/// `system.device.list` 的过滤条件：厂商号与类别，各有一个通配值。
/// List filter: vendor and class, each with a wildcard value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Filter {
    /// 厂商号；[`FILTER_ALL_VENDOR`] 表示不限制。
    /// Vendor ID; [`FILTER_ALL_VENDOR`] means no restriction.
    pub vendor: u16,
    /// 类别（配置空间 class 字节）；[`FILTER_ALL_CLASS`] 表示不限制。
    /// Class byte; [`FILTER_ALL_CLASS`] means no restriction.
    pub class: u8,
}

impl Filter {
    /// 不限制任何字段。
    /// Matches every function.
    pub const ALL: Filter = Filter { vendor: FILTER_ALL_VENDOR, class: FILTER_ALL_CLASS };

    /// 由系统调用参数中的 32 位过滤字构造：低 16 位厂商号、次 8 位类别、高 8 位保留（必须为 0）。
    /// Builds a filter from the syscall word; the high byte is reserved and must be zero.
    pub const fn from_word(word: u32) -> Option<Filter> {
        if word >> 24 != 0 {
            return None;
        }
        Some(Filter { vendor: (word & 0xFFFF) as u16, class: ((word >> 16) & 0xFF) as u8 })
    }

    /// 编成系统调用参数中的 32 位过滤字。
    /// Encodes the filter into the 32-bit syscall word.
    pub const fn to_word(self) -> u32 {
        (self.vendor as u32) | (self.class as u32) << 16
    }

    /// 头部是否满足过滤条件。
    /// Whether a header matches this filter.
    pub fn matches(&self, header: &Header) -> bool {
        (self.vendor == FILTER_ALL_VENDOR || header.vendor == self.vendor)
            && (self.class == FILTER_ALL_CLASS || header.class == self.class)
    }
}

/// `system.device.list` 的一条结构化记录。
/// One structured record returned by `system.device.list`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record {
    /// 打包后的 BDF（见 [`pack_bdf`]）。
    /// Packed BDF (see [`pack_bdf`]).
    pub bdf: u32,
    /// 厂商号。
    /// Vendor ID.
    pub vendor: u16,
    /// 设备号（厂商内）。
    /// Device ID.
    pub device: u16,
    /// 类别。
    /// Class byte.
    pub class: u8,
    /// 子类。
    /// Subclass byte.
    pub subclass: u8,
    /// 编程接口。
    /// Programming interface.
    pub prog_if: u8,
    /// 实现的 BAR 个数。
    /// Number of implemented BARs.
    pub bar_count: u8,
    /// 首个已实现 BAR 的种类（[`BAR_KIND_NONE`] 表示没有 BAR）。
    /// Kind of the first implemented BAR ([`BAR_KIND_NONE`] when there are none).
    pub first_bar_kind: u8,
    /// 首个已实现 BAR 的起始地址（I/O 为端口号，内存为物理基址）。
    /// Base of the first implemented BAR (port number or physical address).
    pub first_bar_base: u64,
    /// 首个已实现 BAR 的字节数。
    /// Size in bytes of the first implemented BAR.
    pub first_bar_size: u64,
}

impl Record {
    /// 由 BDF、头部快照与 BAR 解码结果构造列表记录。
    /// Builds a list record from decoded PCI data.
    pub fn from_parts(bdf: Bdf, header: &Header, bars: &[Bar; MAX_BARS]) -> Record {
        let first = bars.iter().find(|bar| !matches!(bar, Bar::None));
        let (kind, base, size) = match first {
            Some(Bar::Io { base, size }) => (BAR_KIND_IO, *base as u64, *size as u64),
            Some(Bar::Memory { base, size, .. }) => (BAR_KIND_MEMORY, *base, *size),
            Some(Bar::None) | None => (BAR_KIND_NONE, 0, 0),
        };
        Record {
            bdf: pack_bdf(bdf),
            vendor: header.vendor,
            device: header.device,
            class: header.class,
            subclass: header.subclass,
            prog_if: header.prog_if,
            bar_count: bars.iter().filter(|bar| !matches!(bar, Bar::None)).count() as u8,
            first_bar_kind: kind,
            first_bar_base: base,
            first_bar_size: size,
        }
    }

    /// 写入 32 字节缓冲区（小端序）。
    /// Encodes into a 32-byte little-endian buffer.
    pub fn encode(&self, out: &mut [u8; RECORD_SIZE]) {
        put_u32(out, 0, self.bdf);
        put_u16(out, 4, self.vendor);
        put_u16(out, 6, self.device);
        out[8] = self.class;
        out[9] = self.subclass;
        out[10] = self.prog_if;
        out[11] = self.bar_count;
        out[12] = self.first_bar_kind;
        out[13] = 0;
        put_u16(out, 14, 0);
        put_u64(out, 16, self.first_bar_base);
        put_u64(out, 24, self.first_bar_size);
    }

    /// 从 32 字节缓冲区解码（小端序）。
    /// Decodes from a 32-byte little-endian buffer.
    pub fn decode(src: &[u8; RECORD_SIZE]) -> Record {
        Record {
            bdf: get_u32(src, 0),
            vendor: get_u16(src, 4),
            device: get_u16(src, 6),
            class: src[8],
            subclass: src[9],
            prog_if: src[10],
            bar_count: src[11],
            first_bar_kind: src[12],
            first_bar_base: get_u64(src, 16),
            first_bar_size: get_u64(src, 24),
        }
    }
}

/// 完整描述中的一个 BAR。
/// One BAR in the full description.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BarEntry {
    /// 种类：0 未实现、1 I/O、2 内存。
    /// Kind: 0 none, 1 I/O, 2 memory.
    pub kind: u8,
    /// 标志位（[`BAR_FLAG_PREFETCHABLE`]、[`BAR_FLAG_WIDE`]）。
    /// Flags ([`BAR_FLAG_PREFETCHABLE`], [`BAR_FLAG_WIDE`]).
    pub flags: u8,
    /// 起始地址（I/O 为端口号）。
    /// Base address (port number for I/O).
    pub base: u64,
    /// 字节数。
    /// Size in bytes.
    pub size: u64,
}

impl BarEntry {
    /// 未实现的 BAR。
    /// An unimplemented BAR.
    pub const NONE: BarEntry = BarEntry { kind: BAR_KIND_NONE, flags: 0, base: 0, size: 0 };

    /// 由解码结果构造。
    /// Builds an entry from a decoded BAR.
    pub fn from_bar(bar: &Bar) -> BarEntry {
        match *bar {
            Bar::None => BarEntry::NONE,
            Bar::Io { base, size } => BarEntry { kind: BAR_KIND_IO, flags: 0, base: base as u64, size: size as u64 },
            Bar::Memory { base, size, prefetchable, wide } => BarEntry {
                kind: BAR_KIND_MEMORY,
                flags: (if prefetchable { BAR_FLAG_PREFETCHABLE } else { 0 }) | (if wide { BAR_FLAG_WIDE } else { 0 }),
                base,
                size,
            },
        }
    }

    fn encode(&self, out: &mut [u8], off: usize) {
        out[off] = self.kind;
        out[off + 1] = self.flags;
        put_u16(out, off + 2, 0);
        put_u32(out, off + 4, 0);
        put_u64(out, off + 8, self.base);
        put_u64(out, off + 16, self.size);
    }

    fn decode(src: &[u8], off: usize) -> BarEntry {
        BarEntry { kind: src[off], flags: src[off + 1], base: get_u64(src, off + 8), size: get_u64(src, off + 16) }
    }
}

/// `system.device.capability.list` 返回的一条 PCI 能力记录。
///
/// 只导出厂商专有能力（[`CAP_ID_VENDOR`]）；virtio 1.x 用其中的 [`cfg_type`](Self::cfg_type)、
/// [`bar`](Self::bar)、[`bar_offset`](Self::bar_offset) 与 [`length`](Self::length) 定位通用配置等窗口。
/// One PCI capability record exposed to user space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityRecord {
    /// 能力结构在配置空间中的偏移（0x40–0xFF，4 字节对齐）。
    /// Offset of the capability structure in configuration space.
    pub pci_offset: u8,
    /// PCI 能力号（这里总是 [`CAP_ID_VENDOR`]）。
    /// PCI capability ID (always [`CAP_ID_VENDOR`] here).
    pub id: u8,
    /// 厂商定义的配置类型（virtio：1 通用、2 通知、3 ISR、4 设备专用、5 PCI 公共）。
    /// Vendor-defined configuration type (virtio: 1 common, 2 notify, 3 ISR, 4 device, 5 PCI).
    pub cfg_type: u8,
    /// 能力指向的 BAR 编号（0–5）。
    /// BAR index the capability points at (0-5).
    pub bar: u8,
    /// 能力结构在 BAR 内的字节偏移。
    /// Byte offset of the structure inside the BAR.
    pub bar_offset: u32,
    /// 结构字节数（可能为 0，表示使用该类型的规范长度）。
    /// Structure length in bytes (0 means the canonical length for this type).
    pub length: u32,
}

impl CapabilityRecord {
    /// 未初始化的记录（数组初始化用）。
    /// An empty record used for array initialisation.
    pub const NONE: CapabilityRecord =
        CapabilityRecord { pci_offset: 0, id: 0, cfg_type: 0, bar: 0, bar_offset: 0, length: 0 };

    /// 写入 [`CAP_RECORD_SIZE`] 字节缓冲区（小端序）。
    /// Encodes into a [`CAP_RECORD_SIZE`]-byte little-endian buffer.
    pub fn encode(&self, out: &mut [u8; CAP_RECORD_SIZE]) {
        out[0] = self.pci_offset;
        out[1] = self.id;
        out[2] = self.cfg_type;
        out[3] = self.bar;
        put_u32(out, 4, self.bar_offset);
        put_u32(out, 8, self.length);
        put_u32(out, 12, 0);
    }

    /// 从 [`CAP_RECORD_SIZE`] 字节缓冲区解码（小端序）。
    /// Decodes from a [`CAP_RECORD_SIZE`]-byte little-endian buffer.
    pub fn decode(src: &[u8; CAP_RECORD_SIZE]) -> CapabilityRecord {
        CapabilityRecord {
            pci_offset: src[0],
            id: src[1],
            cfg_type: src[2],
            bar: src[3],
            bar_offset: get_u32(src, 4),
            length: get_u32(src, 8),
        }
    }
}

/// `system.device.get` 返回的完整设备描述。
/// Full device description returned by `system.device.get`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Desc {
    /// 打包后的 BDF。
    /// Packed BDF.
    pub bdf: u32,
    /// 厂商号。
    /// Vendor ID.
    pub vendor: u16,
    /// 设备号。
    /// Device ID.
    pub device: u16,
    /// 修订号。
    /// Revision.
    pub revision: u8,
    /// 编程接口。
    /// Programming interface.
    pub prog_if: u8,
    /// 子类。
    /// Subclass byte.
    pub subclass: u8,
    /// 类别。
    /// Class byte.
    pub class: u8,
    /// 头部布局（[`HEADER_KIND_ENDPOINT`] 等）。
    /// Header kind ([`HEADER_KIND_ENDPOINT`] etc.).
    pub header_kind: u8,
    /// 是否多功能设备。
    /// Whether this is a multifunction device.
    pub multifunction: bool,
    /// 中断引脚（0 = 不用，1–4 = INTA–INTD）。
    /// Interrupt pin (0 = none, 1–4 = INTA–INTD).
    pub interrupt_pin: u8,
    /// 实现的 BAR 个数。
    /// Number of implemented BARs.
    pub bar_count: u8,
    /// 子系统厂商号。
    /// Subsystem vendor ID.
    pub subsystem_vendor: u16,
    /// 子系统号。
    /// Subsystem ID.
    pub subsystem: u16,
    /// 全部 BAR 槽位（未实现与 64 位 BAR 的高半槽位为 [`BarEntry::NONE`]）。
    /// All BAR slots (unimplemented and upper halves of 64-bit BARs are [`BarEntry::NONE`]).
    pub bars: [BarEntry; MAX_BARS],
}

impl Desc {
    /// 由 BDF、头部快照与 BAR 解码结果构造完整描述。
    /// Builds the full description from decoded PCI data.
    pub fn from_parts(bdf: Bdf, header: &Header, bars: &[Bar; MAX_BARS]) -> Desc {
        let mut entries = [BarEntry::NONE; MAX_BARS];
        for (slot, bar) in entries.iter_mut().zip(bars.iter()) {
            *slot = BarEntry::from_bar(bar);
        }
        Desc {
            bdf: pack_bdf(bdf),
            vendor: header.vendor,
            device: header.device,
            revision: header.revision,
            prog_if: header.prog_if,
            subclass: header.subclass,
            class: header.class,
            header_kind: header_kind(header.kind),
            multifunction: header.multifunction,
            interrupt_pin: header.interrupt_pin,
            bar_count: entries.iter().filter(|bar| bar.kind != BAR_KIND_NONE).count() as u8,
            subsystem_vendor: header.subsystem_vendor,
            subsystem: header.subsystem,
            bars: entries,
        }
    }

    /// 写入 [`DESC_SIZE`] 字节缓冲区（小端序）。
    /// Encodes into a [`DESC_SIZE`]-byte little-endian buffer.
    pub fn encode(&self, out: &mut [u8; DESC_SIZE]) {
        put_u32(out, 0, self.bdf);
        put_u16(out, 4, self.vendor);
        put_u16(out, 6, self.device);
        out[8] = self.revision;
        out[9] = self.prog_if;
        out[10] = self.subclass;
        out[11] = self.class;
        out[12] = self.header_kind;
        out[13] = self.multifunction as u8;
        out[14] = self.interrupt_pin;
        out[15] = self.bar_count;
        put_u16(out, 16, self.subsystem_vendor);
        put_u16(out, 18, self.subsystem);
        put_u32(out, 20, 0);
        for (i, bar) in self.bars.iter().enumerate() {
            bar.encode(out, 24 + i * 24);
        }
    }

    /// 从 [`DESC_SIZE`] 字节缓冲区解码（小端序）。
    /// Decodes from a [`DESC_SIZE`]-byte little-endian buffer.
    pub fn decode(src: &[u8; DESC_SIZE]) -> Desc {
        let mut bars = [BarEntry::NONE; MAX_BARS];
        for (i, bar) in bars.iter_mut().enumerate() {
            *bar = BarEntry::decode(src, 24 + i * 24);
        }
        Desc {
            bdf: get_u32(src, 0),
            vendor: get_u16(src, 4),
            device: get_u16(src, 6),
            revision: src[8],
            prog_if: src[9],
            subclass: src[10],
            class: src[11],
            header_kind: src[12],
            multifunction: src[13] != 0,
            interrupt_pin: src[14],
            bar_count: src[15],
            subsystem_vendor: get_u16(src, 16),
            subsystem: get_u16(src, 18),
            bars,
        }
    }
}

/// 头部布局编号 → 用户态编码。
/// Maps a header kind to its user-visible encoding.
pub const fn header_kind(kind: HeaderKind) -> u8 {
    match kind {
        HeaderKind::Endpoint => HEADER_KIND_ENDPOINT,
        HeaderKind::Bridge => HEADER_KIND_BRIDGE,
        HeaderKind::CardBus => HEADER_KIND_CARDBUS,
        HeaderKind::Unknown(_) => HEADER_KIND_UNKNOWN,
    }
}

fn put_u16(out: &mut [u8], off: usize, value: u16) {
    out[off..off + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut [u8], off: usize, value: u32) {
    out[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut [u8], off: usize, value: u64) {
    out[off..off + 8].copy_from_slice(&value.to_le_bytes());
}

fn get_u16(src: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([src[off], src[off + 1]])
}

fn get_u32(src: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([src[off], src[off + 1], src[off + 2], src[off + 3]])
}

fn get_u64(src: &[u8], off: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&src[off..off + 8]);
    u64::from_le_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bdf(bus: u8, device: u8, function: u8) -> Bdf {
        Bdf::new(bus, device, function).unwrap()
    }

    fn header(vendor: u16, device: u16, class: u8) -> Header {
        Header {
            vendor,
            device,
            revision: 3,
            prog_if: 0x10,
            subclass: 0x00,
            class,
            kind: HeaderKind::Endpoint,
            multifunction: true,
            subsystem_vendor: 0x1AF4,
            subsystem: 0x0001,
            interrupt_pin: 1,
        }
    }

    #[test]
    fn bdf_packing_roundtrip_and_rejections() {
        let b = bdf(0x12, 31, 7);
        let raw = pack_bdf(b);
        assert_eq!(raw, 0x0012_1F07);
        assert_eq!(unpack_bdf(raw), Some(b));
        assert_eq!(unpack_bdf(0x0100_0000), None, "高 8 位必须为 0");
        assert_eq!(unpack_bdf(0x0000_2000), None, "设备号 32 越界");
        assert_eq!(unpack_bdf(0x0000_0008), None, "功能号 8 越界");
    }

    #[test]
    fn filter_word_and_matching() {
        assert_eq!(Filter::from_word(0), Some(Filter { vendor: 0, class: 0 }));
        assert_eq!(Filter::from_word(0x00FF_FFFF), Some(Filter::ALL));
        assert_eq!(Filter::from_word(0x0100_0000), None, "保留位非零");
        assert_eq!(Filter::ALL.to_word(), 0x00FF_FFFF);
        let h = header(0x1AF4, 0x1041, 0x02);
        assert!(Filter::ALL.matches(&h));
        assert!(Filter { vendor: 0x1AF4, class: 0x02 }.matches(&h));
        assert!(Filter { vendor: FILTER_ALL_VENDOR, class: 0x02 }.matches(&h));
        assert!(Filter { vendor: 0x1AF4, class: FILTER_ALL_CLASS }.matches(&h));
        assert!(!Filter { vendor: 0x8086, class: 0x02 }.matches(&h));
        assert!(!Filter { vendor: 0x1AF4, class: 0x03 }.matches(&h));
    }

    #[test]
    fn record_encodes_identity_and_first_bar() {
        let mut bars = [Bar::None; MAX_BARS];
        bars[0] = Bar::Memory { base: 0xFEB0_0000, size: 0x1000, prefetchable: true, wide: false };
        bars[2] = Bar::Io { base: 0xC040, size: 0x20 };
        let h = header(0x1AF4, 0x1041, 0x02);
        let record = Record::from_parts(bdf(0, 3, 0), &h, &bars);
        assert_eq!(record.bar_count, 2);
        assert_eq!(record.first_bar_kind, BAR_KIND_MEMORY);
        assert_eq!((record.first_bar_base, record.first_bar_size), (0xFEB0_0000, 0x1000));
        let mut raw = [0u8; RECORD_SIZE];
        record.encode(&mut raw);
        assert_eq!(Record::decode(&raw), record);
        assert_eq!(raw[13], 0, "保留字节为 0");
    }

    #[test]
    fn record_without_bars_and_io_first() {
        let none = [Bar::None; MAX_BARS];
        let h = header(0x8086, 0x1234, 0x06);
        let r = Record::from_parts(bdf(0, 1, 0), &h, &none);
        assert_eq!((r.bar_count, r.first_bar_kind, r.first_bar_base, r.first_bar_size), (0, BAR_KIND_NONE, 0, 0));
        let mut bars = [Bar::None; MAX_BARS];
        bars[5] = Bar::Io { base: 0xC000, size: 0x40 };
        let r = Record::from_parts(bdf(0, 2, 0), &h, &bars);
        assert_eq!((r.first_bar_kind, r.first_bar_base, r.first_bar_size), (BAR_KIND_IO, 0xC000, 0x40));
    }

    #[test]
    fn desc_roundtrip_covers_every_field() {
        let mut bars = [Bar::None; MAX_BARS];
        bars[0] = Bar::Io { base: 0xC040, size: 0x20 };
        bars[1] = Bar::Memory { base: 0xFEB0_0000, size: 0x1000, prefetchable: false, wide: false };
        bars[2] = Bar::Memory { base: 0x1_0000_0000, size: 0x4000, prefetchable: true, wide: true };
        let mut h = header(0x1AF4, 0x1041, 0x02);
        h.kind = HeaderKind::Bridge;
        h.multifunction = false;
        let desc = Desc::from_parts(bdf(2, 5, 0), &h, &bars);
        assert_eq!(desc.header_kind, HEADER_KIND_BRIDGE);
        assert_eq!(desc.bar_count, 3);
        assert_eq!(desc.bars[0], BarEntry { kind: BAR_KIND_IO, flags: 0, base: 0xC040, size: 0x20 });
        assert_eq!(
            desc.bars[2],
            BarEntry { kind: BAR_KIND_MEMORY, flags: BAR_FLAG_PREFETCHABLE | BAR_FLAG_WIDE, base: 0x1_0000_0000, size: 0x4000 }
        );
        let mut raw = [0u8; DESC_SIZE];
        desc.encode(&mut raw);
        assert_eq!(Desc::decode(&raw), desc);
        assert_eq!(raw[20..24], [0; 4], "保留区为 0");
    }

    #[test]
    fn capability_record_roundtrip_and_constants() {
        let cap = CapabilityRecord {
            pci_offset: 0x60,
            id: CAP_ID_VENDOR,
            cfg_type: CAP_CFG_COMMON,
            bar: 4,
            bar_offset: 0x1000,
            length: 0x40,
        };
        let mut raw = [0u8; CAP_RECORD_SIZE];
        cap.encode(&mut raw);
        assert_eq!(CapabilityRecord::decode(&raw), cap);
        assert_eq!(raw[12..16], [0; 4], "保留区为 0");
        assert_eq!((CAP_CFG_COMMON, CAP_CFG_NOTIFY, CAP_CFG_ISR, CAP_CFG_DEVICE, CAP_CFG_PCI), (1, 2, 3, 4, 5));
        assert_eq!(CapabilityRecord::NONE, CapabilityRecord { pci_offset: 0, id: 0, cfg_type: 0, bar: 0, bar_offset: 0, length: 0 });
    }

    #[test]
    fn desc_unknown_header_kind_and_zero_bars() {
        let mut h = header(0x1234, 0x5678, 0x0C);
        h.kind = HeaderKind::Unknown(0x7E);
        let desc = Desc::from_parts(bdf(0, 0, 0), &h, &[Bar::None; MAX_BARS]);
        assert_eq!(desc.header_kind, HEADER_KIND_UNKNOWN);
        assert_eq!(desc.bar_count, 0);
        let mut raw = [0u8; DESC_SIZE];
        desc.encode(&mut raw);
        assert_eq!(Desc::decode(&raw), desc);
    }
}
