//! I/O APIC 与本平台的两条可路由设备中断线：COM1 串口（ISA 4）与 CMOS 实时时钟（ISA 8）。
//! I/O APIC driver and this platform's two routable device lines: the COM1 UART and the CMOS RTC.
//!
//! # 职责
//! * 由 MADT 找到负责这两条 ISA 中断的 I/O APIC 与输入线（应用中断源覆盖条目的极性与触发方式），
//!   初始化时屏蔽该控制器的全部输入线，再为两条线写好向量与目标。
//! * 路由 = 改写重定向表项的目标 APIC 标识（物理目标模式）；屏蔽 = 表项的屏蔽位。
//! * 设备侧：串口的「发送保持寄存器空」中断、实时时钟的周期中断；确认与持续自触发都在这里。
//!
//! # 边界与原因
//! * 8259 仍只负责引导处理器的 PIT（虚拟线模式）；这两条 ISA 中断在 8259 上保持屏蔽，只经 I/O APIC 投递，
//!   因此可以送到任意处理器。
//! * 边沿触发的输入线在屏蔽期间到来的边沿会被丢弃，所以解除屏蔽时要让设备重新产生一次中断条件
//!   （串口重写中断使能寄存器、时钟读状态寄存器 C），不丢中断。
//! * 寄存器窗口是「选择 + 数据」两步访问，全部经一把关中断的自旋锁串行；CMOS 的索引 / 数据端口另用一把。

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use kernel_core::acpi::Madt;
use kernel_core::irq::IrqError;
use spin::Mutex;

use super::port::{inb, outb};
use super::smp;
use crate::arch::without_irq;

/// 串口线的向量。
pub const SERIAL_VECTOR: u8 = 0x50;
/// 实时时钟线的向量。
pub const RTC_VECTOR: u8 = 0x51;

/// 本平台的设备中断线：（规范名, ISA 中断号, 向量）。
const LINES: [(&str, u8, u8); 2] = [("serial", 4, SERIAL_VECTOR), ("rtc", 8, RTC_VECTOR)];
/// 串口线下标。
pub const LINE_SERIAL: usize = 0;
/// 实时时钟线下标。
pub const LINE_RTC: usize = 1;

const IOREGSEL: u64 = 0x00;
const IOWIN: u64 = 0x10;
const REG_VERSION: u32 = 0x01;
const REG_REDIRECT: u32 = 0x10;
const RTE_MASKED: u32 = 1 << 16;
const RTE_LEVEL: u32 = 1 << 15;
const RTE_ACTIVE_LOW: u32 = 1 << 13;

const COM1: u16 = 0x3F8;
const UART_IER: u16 = COM1 + 1;
const UART_IIR: u16 = COM1 + 2;
const UART_MCR: u16 = COM1 + 4;
/// 中断使能：发送保持寄存器空。
const IER_THRI: u8 = 0x02;
/// 调制解调器控制：DTR + RTS + OUT2（PC 上 OUT2 连通串口的中断输出）。
const MCR_OUT2: u8 = 0x0B;

const CMOS_INDEX: u16 = 0x70;
const CMOS_DATA: u16 = 0x71;
const RTC_REG_A: u8 = 0x0A;
const RTC_REG_B: u8 = 0x0B;
const RTC_REG_C: u8 = 0x0C;
/// 寄存器 B：周期中断使能。
const RTC_PIE: u8 = 0x40;
/// 寄存器 A 的速率选择 3 = 8192 Hz（周期中断的最高频率）。
const RTC_RATE_8192: u8 = 0x03;

/// 一条线在 I/O APIC 上的位置。
struct Pin {
    /// 控制器寄存器窗口的虚拟地址（0 = 这条线不可用）。
    base: u64,
    pin: u32,
    /// 重定向表项低 32 位中除屏蔽位外的部分（向量、极性、触发方式）。
    low: u32,
    masked: bool,
}

static PINS: Mutex<[Pin; 2]> = Mutex::new([
    Pin { base: 0, pin: 0, low: 0, masked: true },
    Pin { base: 0, pin: 0, low: 0, masked: true },
]);
/// 可用线数（配置成功后为 2）。
static COUNT: AtomicUsize = AtomicUsize::new(0);
/// 各线的持续自触发开关。
static STORM: [AtomicBool; 2] = [const { AtomicBool::new(false) }; 2];
/// CMOS 索引 / 数据端口。
static CMOS: Mutex<()> = Mutex::new(());

fn read_reg(base: u64, reg: u32) -> u32 {
    // SAFETY：`base` 是 MADT 给出的 I/O APIC 寄存器窗口（经全物理映射，不可缓存）；先选后读。
    unsafe {
        ((base + IOREGSEL) as *mut u32).write_volatile(reg);
        ((base + IOWIN) as *const u32).read_volatile()
    }
}

fn write_reg(base: u64, reg: u32, v: u32) {
    // SAFETY：同 [`read_reg`]；先选后写。
    unsafe {
        ((base + IOREGSEL) as *mut u32).write_volatile(reg);
        ((base + IOWIN) as *mut u32).write_volatile(v);
    }
}

fn write_low(p: &Pin) {
    write_reg(p.base, REG_REDIRECT + 2 * p.pin, p.low | if p.masked { RTE_MASKED } else { 0 });
}

/// 由 MADT 配置两条线（引导处理器上调用一次）：屏蔽所在控制器的全部输入线，写好向量与目标（引导处理器），保持屏蔽。
/// 找不到控制器或输入线超出控制器容量时该线不可用；返回可用线数。
/// Configure the device lines from the MADT.
pub fn configure(madt: &Madt, phys_offset: u64, boot_apic_id: u32) -> usize {
    let mut pins = PINS.lock();
    let mut ok = 0;
    let mut masked_all = [0u64; kernel_core::acpi::MAX_IO_CONTROLLERS];
    for (i, &(_, isa, vector)) in LINES.iter().enumerate() {
        let route = madt.isa_route(isa);
        let Some((ctrl, pin)) = madt.controller_for(route.gsi) else {
            break;
        };
        if ctrl.address >= 1 << 32 {
            break;
        }
        let base = phys_offset + ctrl.address;
        let entries = ((read_reg(base, REG_VERSION) >> 16) & 0xFF) + 1;
        if pin >= entries {
            break;
        }
        // 第一次见到这个控制器：屏蔽它的全部输入线
        if !masked_all.contains(&base) {
            for e in 0..entries {
                write_reg(base, REG_REDIRECT + 2 * e, RTE_MASKED);
            }
            if let Some(slot) = masked_all.iter_mut().find(|s| **s == 0) {
                *slot = base;
            }
        }
        let low = vector as u32 | if route.active_low { RTE_ACTIVE_LOW } else { 0 } | if route.level { RTE_LEVEL } else { 0 };
        pins[i] = Pin { base, pin, low, masked: true };
        write_reg(base, REG_REDIRECT + 2 * pin + 1, boot_apic_id << 24);
        write_low(&pins[i]);
        ok = i + 1;
    }
    COUNT.store(ok, Ordering::Release);
    ok
}

/// 可用线数。
pub fn count() -> usize {
    COUNT.load(Ordering::Acquire)
}

/// 线的规范名。
pub fn name(line: usize) -> &'static str {
    LINES.get(line).map(|l| l.0).unwrap_or("none")
}

/// 线号是否可用。
fn valid(line: usize) -> bool {
    line < count()
}

/// 路由到逻辑下标 `cpu`（改目标 APIC 标识，屏蔽状态不变）。
pub fn route(line: usize, cpu: usize) -> Result<(), IrqError> {
    if !valid(line) {
        return Err(IrqError::NoLine);
    }
    let id = smp::hw_id_of(cpu).filter(|&id| id < 256).ok_or(IrqError::RouteFailed)?;
    without_irq(|| {
        let pins = PINS.lock();
        let p = &pins[line];
        write_reg(p.base, REG_REDIRECT + 2 * p.pin + 1, id << 24);
    });
    Ok(())
}

/// 屏蔽 / 解除屏蔽；解除时让设备重新产生中断条件（边沿在屏蔽期间被丢弃）。
pub fn set_masked(line: usize, masked: bool) {
    if !valid(line) {
        return;
    }
    without_irq(|| {
        let mut pins = PINS.lock();
        pins[line].masked = masked;
        write_low(&pins[line]);
    });
    if !masked {
        rearm(line);
    }
}

/// 设备侧确认：串口读中断标识寄存器、时钟读状态寄存器 C；持续自触发时立即重新触发。
pub fn ack(line: usize) {
    match line {
        LINE_SERIAL => {
            // SAFETY：读 IIR 清除「发送保持寄存器空」中断条件；只影响中断状态。
            unsafe { inb(UART_IIR) };
            if STORM[LINE_SERIAL].load(Ordering::Relaxed) {
                retrigger_serial();
            }
        }
        LINE_RTC => {
            cmos_read(RTC_REG_C);
        }
        _ => {}
    }
}

/// 打开 / 关闭持续自触发。
pub fn self_trigger(line: usize, on: bool) -> Result<(), IrqError> {
    if !valid(line) {
        return Err(IrqError::NoLine);
    }
    STORM[line].store(on, Ordering::Relaxed);
    match line {
        LINE_SERIAL => {
            // SAFETY：只改串口的中断使能与 OUT2；控制台的轮询发送不依赖这两个寄存器。
            unsafe {
                outb(UART_MCR, MCR_OUT2);
                outb(UART_IER, if on { IER_THRI } else { 0 });
            }
        }
        _ => {
            without_irq(|| {
                let _g = CMOS.lock();
                let a = cmos_read_locked(RTC_REG_A);
                cmos_write_locked(RTC_REG_A, (a & 0xF0) | RTC_RATE_8192);
                let b = cmos_read_locked(RTC_REG_B);
                cmos_write_locked(RTC_REG_B, if on { b | RTC_PIE } else { b & !RTC_PIE });
                cmos_read_locked(RTC_REG_C);
            });
        }
    }
    Ok(())
}

/// 解除屏蔽后重新产生中断条件。
fn rearm(line: usize) {
    match line {
        LINE_SERIAL if STORM[LINE_SERIAL].load(Ordering::Relaxed) => retrigger_serial(),
        LINE_RTC => {
            cmos_read(RTC_REG_C);
        }
        _ => {}
    }
}

/// 关再开「发送保持寄存器空」中断：发送缓冲已空时设备立即再次请求中断。
fn retrigger_serial() {
    // SAFETY：同 [`self_trigger`]。
    unsafe {
        outb(UART_IER, 0);
        outb(UART_IER, IER_THRI);
    }
}

fn cmos_read(reg: u8) -> u8 {
    without_irq(|| {
        let _g = CMOS.lock();
        cmos_read_locked(reg)
    })
}

fn cmos_read_locked(reg: u8) -> u8 {
    // SAFETY：CMOS 索引 / 数据端口的标准访问；调用者持有 CMOS 锁。
    unsafe {
        outb(CMOS_INDEX, reg);
        inb(CMOS_DATA)
    }
}

fn cmos_write_locked(reg: u8, v: u8) {
    // SAFETY：同上。
    unsafe {
        outb(CMOS_INDEX, reg);
        outb(CMOS_DATA, v);
    }
}
