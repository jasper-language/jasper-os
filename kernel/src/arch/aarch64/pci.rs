//! AArch64 的 PCI 配置空间访问：设备树 `pci-host-ecam-generic` 给出的 ECAM 窗口。
//! AArch64 PCI config-space access through the ECAM window described by the device tree.
//!
//! # 职责
//! * 从设备树读出 ECAM 物理基址与总线范围，并在全物理内存映射里把覆盖它的 GiB 段标记为设备内存
//!   （ECAM 在 `virt` 机型上位于高物理地址，早期映射不会自动覆盖它）。
//! * 为直接引导、没有固件代为分配的总线分配 BAR：内存 BAR 放进 32 位 MMIO 窗口，I/O BAR 放进端口窗口，
//!   随后打开该功能的 I/O 与内存译码。已有非零基址的功能保持原分配不动。
//! * 实现 `kernel_core::pci::ConfigSpace`：把 `(BDF, 偏移)` 换算成 ECAM 地址后做 32 位 volatile 访问。
//!
//! # 边界
//! * 只碰配置空间，不解释设备语义；设备表与启动期枚举在架构无关的 `crate::pci` 中。
//! * 不含端口号与传统机制：AArch64 没有 x86 的 0xCF8 / 0xCFC。

use alloc::boxed::Box;
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use kernel_core::fdt::{Fdt, Node};
use kernel_core::pci::{self as core_pci, Bar, Bdf, ConfigSpace, Ecam};

use super::mmu;
use crate::arch::{PciAccess, PciMechanism};
use crate::boot::BootSpec;

/// 配置空间里的命令寄存器与第一个 BAR 的偏移。
const REG_COMMAND: u16 = 0x04;
const REG_BAR0: u16 = 0x10;
/// 命令寄存器的 I/O 与内存译码位。
const COMMAND_DECODE: u32 = 0b11;

/// `ranges` 里的一条地址窗口。
#[derive(Clone, Copy)]
struct Window {
    base: u64,
    size: u64,
    io: bool,
    mem64: bool,
}

/// 解析 `ranges`：PCI 地址 3 个单元、CPU 地址与长度各按父节点单元数；最多保留 8 条窗口。
fn windows(node: &Node<'_>) -> ([Option<Window>; 8], usize) {
    let mut out = [None; 8];
    let Some(value) = node.property("ranges") else { return (out, 0) };
    let pci_cells = node.cell("#address-cells", 0).unwrap_or(3) as usize;
    let cpu_cells = node.address_cells as usize;
    let size_cells = node.size_cells as usize;
    if pci_cells != 3 || cpu_cells == 0 || cpu_cells > 2 || size_cells == 0 || size_cells > 2 {
        return (out, 0);
    }
    let stride = (pci_cells + cpu_cells + size_cells) * 4;
    let read = |at: usize, cells: usize| -> Option<u64> {
        match cells {
            1 => node_cell(value, at).map(u64::from),
            2 => node_cell(value, at).and_then(|hi| node_cell(value, at + 4).map(|lo| (u64::from(hi) << 32) | u64::from(lo))),
            _ => None,
        }
    };
    let mut count = 0usize;
    while count < out.len() {
        let at = count * stride;
        let (Some(hi), Some(base), Some(size)) = (
            node_cell(value, at),
            read(at + pci_cells * 4, cpu_cells),
            read(at + (pci_cells + cpu_cells) * 4, size_cells),
        ) else {
            break;
        };
        if size != 0 {
            let kind = (hi >> 24) & 0x3;
            out[count] = Some(Window { base, size, io: kind == 1, mem64: kind == 3 });
        }
        count += 1;
    }
    (out, count)
}

/// 大端序的 32 位单元；越界返回 `None`。
fn node_cell(value: &[u8], at: usize) -> Option<u32> {
    let bytes = value.get(at..at + 4)?;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// ECAM 物理基址（0 = 设备树里没有该节点）。
static ECAM_BASE: AtomicU64 = AtomicU64::new(0);
/// ECAM 字节数。
static ECAM_SIZE: AtomicU64 = AtomicU64::new(0);
/// 窗口覆盖的第一条 / 最后一条总线（含）。
static BUS_START: AtomicU8 = AtomicU8::new(0);
static BUS_END: AtomicU8 = AtomicU8::new(0);
/// 设备树 `ranges` 给出的地址窗口（最多 8 条）；标志位：1 = I/O，2 = 64 位内存。
static WIN_BASE: [AtomicU64; 8] = [const { AtomicU64::new(0) }; 8];
static WIN_SIZE: [AtomicU64; 8] = [const { AtomicU64::new(0) }; 8];
static WIN_FLAGS: [AtomicU8; 8] = [const { AtomicU8::new(0) }; 8];
static WIN_COUNT: AtomicU8 = AtomicU8::new(0);

/// 从设备树记录 ECAM 窗口；没有该节点时返回 `false`（平台没有 PCI）。
///
/// 只记录参数，不建立映射：调用发生在 MMU 打开之后、内核映射服务与堆就绪之前。
pub fn configure(fdt: &Fdt<'_>) -> bool {
    let Ok(Some(node)) = fdt.find_compatible("pci-host-ecam-generic") else {
        return false;
    };
    let Some((base, size)) = node.reg(0) else {
        return false;
    };
    if base == 0 || size < (1 << 20) || base % 4096 != 0 {
        return false;
    }
    let (start, end) = bus_range(&node);
    if end < start {
        return false;
    }
    let needed = (u64::from(end) - u64::from(start) + 1) << 20;
    if size < needed {
        return false;
    }
    ECAM_BASE.store(base, Ordering::Release);
    ECAM_SIZE.store(needed, Ordering::Release);
    BUS_START.store(start, Ordering::Release);
    BUS_END.store(end, Ordering::Release);
    let (ranges, count) = windows(&node);
    for (index, window) in ranges.iter().enumerate().take(count) {
        let Some(window) = window else { continue };
        WIN_BASE[index].store(window.base, Ordering::Release);
        WIN_SIZE[index].store(window.size, Ordering::Release);
        WIN_FLAGS[index].store((window.io as u8) | ((window.mem64 as u8) << 1), Ordering::Release);
    }
    WIN_COUNT.store(count as u8, Ordering::Release);
    true
}

/// `bus-range`：两条大端 32 位单元（起点、终点）；缺失时按整条总线范围处理。
fn bus_range(node: &Node<'_>) -> (u8, u8) {
    match (node.cell("bus-range", 0), node.cell("bus-range", 1)) {
        (Some(start), Some(end)) if start <= 0xff && end <= 0xff => (start as u8, end as u8),
        _ => (0, 0xff),
    }
}

/// 取得 ECAM 配置空间访问者；设备树没有 PCI 节点或窗口无法映射时返回 `None`。
pub fn access(boot: &BootSpec) -> Option<PciAccess> {
    let base = ECAM_BASE.load(Ordering::Acquire);
    let size = ECAM_SIZE.load(Ordering::Acquire);
    let offset = boot.phys_offset?;
    if base == 0 || size == 0 {
        return None;
    }
    // ECAM 必须按设备内存访问：把覆盖它的整段 GiB 在全物理内存映射里切成设备块。
    if !mmu::ensure_device_region(base, base.checked_add(size)?) {
        return None;
    }
    let window = Ecam {
        base,
        segment: 0,
        bus_start: BUS_START.load(Ordering::Acquire),
        bus_end: BUS_END.load(Ordering::Acquire),
    };
    if window.is_empty() || window.len() > size {
        return None;
    }
    let mut config = EcamConfig { window, offset };
    assign_bars(&mut config);
    let config: &'static mut EcamConfig = Box::leak(Box::new(config));
    Some(PciAccess { config, mechanism: PciMechanism::Ecam, buses: window.buses() })
}

/// 为直接引导（没有固件代分配）的总线填写 BAR。
///
/// 基址已经非零的功能保持原样；只给未分配的内存 BAR / I/O BAR 从设备树 `ranges` 的对应窗口取地址，
/// 然后把该功能的 I/O 与内存译码打开。窗口缺失或放不下时不写任何超出窗口的地址。
fn assign_bars(config: &mut EcamConfig) {
    let count = WIN_COUNT.load(Ordering::Acquire) as usize;
    let mut windows = [None; 8];
    for (index, slot) in windows.iter_mut().enumerate().take(count) {
        let flags = WIN_FLAGS[index].load(Ordering::Acquire);
        *slot = Some(Window {
            base: WIN_BASE[index].load(Ordering::Acquire),
            size: WIN_SIZE[index].load(Ordering::Acquire),
            io: flags & 1 != 0,
            mem64: flags & 2 != 0,
        });
    }
    let io = windows.iter().flatten().find(|w| w.io && w.size != 0).copied();
    // 64 位 BAR 也放在 32 位窗口内（高半写 0）：内核的全物理内存映射只覆盖到 512 GiB。
    let mem32 = windows.iter().flatten().find(|w| !w.io && !w.mem64 && w.size != 0).copied();
    let mem64 = windows.iter().flatten().find(|w| !w.io && w.mem64 && w.size != 0).copied();
    let (Some(io_window), Some(mem_window)) = (io, mem32.or(mem64)) else { return };
    let mut io_next = io_window.base;
    let mut mem_next = mem_window.base;
    let io_end = io_window.base.saturating_add(io_window.size);
    let mem_end = mem_window.base.saturating_add(mem_window.size);

    for bus in u32::from(config.window.bus_start)..=u32::from(config.window.bus_end) {
        for device in 0..32u8 {
            for function in 0..8u8 {
                let Some(bdf) = Bdf::new(bus as u8, device, function) else { continue };
                let Ok(Some(header)) = core_pci::read_header(config, bdf) else { continue };
                if header.kind.bar_count() == 0 {
                    continue;
                }
                let Ok(bars) = core_pci::probe_bars(config, bdf, header.kind) else { continue };
                let mut index = 0usize;
                while index < header.kind.bar_count() {
                    match bars[index] {
                        Bar::Io { base, size } if size != 0 => {
                            if base == 0 {
                                if let Some(address) = take(&mut io_next, u64::from(size), io_end) {
                                    let offset = REG_BAR0 + index as u16 * 4;
                                    let lo = config.read32(bdf, offset).unwrap_or(0);
                                    let _ = config.write32(bdf, offset, (address as u32 & 0xFFFF_FFFC) | (lo & 0x3));
                                }
                            }
                        }
                        Bar::Memory { base, size, wide, .. } if size != 0 => {
                            if base == 0 {
                                if let Some(address) = take(&mut mem_next, size, mem_end) {
                                    let offset = REG_BAR0 + index as u16 * 4;
                                    let lo = config.read32(bdf, offset).unwrap_or(0);
                                    let _ = config.write32(bdf, offset, (address as u32 & 0xFFFF_FFF0) | (lo & 0xF));
                                    if wide {
                                        let _ = config.write32(bdf, offset + 4, (address >> 32) as u32);
                                    }
                                }
                            }
                            if wide {
                                index += 1;
                            }
                        }
                        _ => {}
                    }
                    index += 1;
                }
                let command = config.read32(bdf, REG_COMMAND).unwrap_or(0);
                let _ = config.write32(bdf, REG_COMMAND, command | COMMAND_DECODE);
            }
        }
    }
}

/// 从窗口里取一段按 `size` 对齐的区间；放不下时返回 `None` 且不移动游标。
fn take(next: &mut u64, size: u64, end: u64) -> Option<u64> {
    if size == 0 || !size.is_power_of_two() {
        return None;
    }
    let base = next.checked_add(size - 1)? & !(size - 1);
    if base.checked_add(size)? > end {
        return None;
    }
    *next = base + size;
    Some(base)
}


/// ECAM 后端：物理地址经全物理内存映射访问。
struct EcamConfig {
    window: Ecam,
    /// 全物理内存映射偏移。
    offset: u64,
}

impl EcamConfig {
    /// 功能 `bdf` 在 `offset` 处的可访问虚拟地址。
    fn address(&self, bdf: Bdf, offset: u16) -> Option<u64> {
        let phys = self.window.address(bdf, offset)?;
        self.offset.checked_add(phys)
    }
}

impl ConfigSpace for EcamConfig {
    fn read32(&mut self, bdf: Bdf, offset: u16) -> Option<u32> {
        let address = self.address(bdf, offset)?;
        // SAFETY：地址落在 ECAM 窗口内，该窗口已按设备内存映射；32 位对齐读。
        Some(unsafe { (address as *const u32).read_volatile() })
    }

    fn write32(&mut self, bdf: Bdf, offset: u16, value: u32) -> bool {
        let Some(address) = self.address(bdf, offset) else {
            return false;
        };
        // SAFETY：同 `read32`；写入的是该功能的配置空间双字。
        unsafe { (address as *mut u32).write_volatile(value) };
        true
    }
}
