//! RISC-V 平台的可路由设备中断线：NS16550A 串口与 goldfish 实时时钟，经 PLIC 投递到任意处理器。
//! Routable device interrupt lines on RISC-V: the NS16550A UART and the goldfish RTC, delivered through the PLIC.
//!
//! # 职责
//! * 线 0 = 串口（「发送保持寄存器空」中断），线 1 = 实时时钟（闹钟中断，设备树里有时才存在）。
//! * 路由 = 只在目标处理器的 PLIC 上下文里使能该中断源；屏蔽 = 在目标上下文里关闭它（目标记录保留）。
//! * 设备侧确认：串口读中断标识寄存器、时钟写「清中断」寄存器；持续自触发时立即让设备再次请求中断
//!   （串口关再开发送中断，时钟把闹钟设在「现在」）。
//!
//! # 边界与原因
//! * 两个源在 PLIC 上都是电平触发：屏蔽期间设备的中断条件一直保持，解除屏蔽后照常送达，不会丢失。
//! * 处理器在本地完成 PLIC 上下文初始化后才登记为「可作为目标」，未就绪的处理器拒绝路由。
//! * 线状态（中断源、目标、屏蔽）经一把关中断的自旋锁串行；串口的控制台发送不依赖中断使能寄存器。

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use kernel_core::irq::IrqError;
use kernel_core::smp::MAX_CPUS;
use spin::Mutex;

use super::{plic, uart};
use crate::arch::without_irq;

/// 线的规范名。
const NAMES: [&str; 2] = ["uart", "rtc"];
/// 串口线下标。
const LINE_UART: usize = 0;
/// 实时时钟线下标。
const LINE_RTC: usize = 1;
/// 设备中断源使用的优先级（阈值为 0，任何非 0 优先级都能送达）。
const PRIORITY: u32 = 1;

/// goldfish 实时时钟寄存器。
const RTC_TIME_LOW: usize = 0x00;
const RTC_TIME_HIGH: usize = 0x04;
const RTC_ALARM_LOW: usize = 0x08;
const RTC_ALARM_HIGH: usize = 0x0c;
const RTC_IRQ_ENABLED: usize = 0x10;
const RTC_CLEAR_ALARM: usize = 0x14;
const RTC_CLEAR_INTERRUPT: usize = 0x1c;

/// 一条线的状态。
#[derive(Clone, Copy)]
struct Line {
    /// PLIC 中断源编号（0 = 不可用）。
    source: u32,
    target: usize,
    masked: bool,
}

static LINES: Mutex<[Line; 2]> = Mutex::new([Line { source: 0, target: 0, masked: true }; 2]);
/// 可用线数（串口可用即 1，再有实时时钟即 2）。
static COUNT: AtomicUsize = AtomicUsize::new(0);
/// 各线的持续自触发开关。
static STORM: [AtomicBool; 2] = [const { AtomicBool::new(false) }; 2];
/// 实时时钟寄存器块的虚拟地址与中断源（0 = 没有）。
static RTC_BASE: AtomicUsize = AtomicUsize::new(0);
static RTC_IRQ: AtomicU32 = AtomicU32::new(0);
/// 已完成本地 PLIC 上下文初始化、可作为目标的处理器（位图）。
static READY: AtomicU32 = AtomicU32::new(0);

/// 登记实时时钟（引导适配层解析设备树后调用）。
pub fn set_rtc(va: u64, irq: u32) {
    RTC_BASE.store(va as usize, Ordering::Relaxed);
    RTC_IRQ.store(irq, Ordering::Relaxed);
}

/// 登记处理器 `index` 已可作为设备中断的目标。
pub fn mark_ready(index: usize) {
    if index < MAX_CPUS {
        READY.fetch_or(1 << index, Ordering::Release);
    }
}

/// 引导处理器上配置（PLIC 自检之后调用一次）：设优先级、在所有上下文关闭两个源、目标为引导处理器且屏蔽。返回可用线数。
pub fn configure() -> usize {
    let uart_src = uart::interrupt().unwrap_or(0);
    let rtc_src = if RTC_BASE.load(Ordering::Relaxed) != 0 { RTC_IRQ.load(Ordering::Relaxed) } else { 0 };
    let mut lines = LINES.lock();
    let mut n = 0;
    for (i, src) in [uart_src, rtc_src].into_iter().enumerate() {
        if src == 0 {
            break;
        }
        plic::set_priority(src, PRIORITY);
        for c in 0..MAX_CPUS {
            plic::set_enabled_on(c, src, false);
        }
        lines[i] = Line { source: src, target: 0, masked: true };
        n = i + 1;
    }
    mark_ready(0);
    COUNT.store(n, Ordering::Release);
    n
}

/// 可用线数。
pub fn count() -> usize {
    COUNT.load(Ordering::Acquire)
}

/// 线的规范名。
pub fn name(line: usize) -> &'static str {
    NAMES.get(line).copied().unwrap_or("none")
}

/// 中断源编号对应的线（外部中断入口用）。
pub fn line_of_source(source: u32) -> Option<usize> {
    if source == 0 {
        return None;
    }
    let n = count();
    let lines = LINES.lock();
    (0..n).find(|&i| lines[i].source == source)
}

/// 路由到处理器 `cpu`：未屏蔽时先在新目标使能、再在旧目标关闭（屏蔽状态不变）。
pub fn route(line: usize, cpu: usize) -> Result<(), IrqError> {
    if line >= count() {
        return Err(IrqError::NoLine);
    }
    if cpu >= MAX_CPUS || READY.load(Ordering::Acquire) & (1 << cpu) == 0 || !plic::has_context(cpu) {
        return Err(IrqError::RouteFailed);
    }
    without_irq(|| {
        let mut lines = LINES.lock();
        let l = &mut lines[line];
        if !l.masked && l.target != cpu {
            plic::set_enabled_on(cpu, l.source, true);
            plic::set_enabled_on(l.target, l.source, false);
        }
        l.target = cpu;
    });
    Ok(())
}

/// 屏蔽 / 解除屏蔽（在目标上下文里关闭 / 使能）；解除时让持续自触发的设备重新产生中断条件。
pub fn set_masked(line: usize, masked: bool) {
    if line >= count() {
        return;
    }
    without_irq(|| {
        let mut lines = LINES.lock();
        let l = &mut lines[line];
        l.masked = masked;
        plic::set_enabled_on(l.target, l.source, !masked);
    });
    if !masked && STORM[line].load(Ordering::Relaxed) {
        retrigger(line);
    }
}

/// 设备侧确认；持续自触发时立即重新触发。
pub fn ack(line: usize) {
    match line {
        LINE_UART => uart::read_iir(),
        LINE_RTC => rtc_write(RTC_CLEAR_INTERRUPT, 1),
        _ => return,
    }
    if STORM.get(line).is_some_and(|s| s.load(Ordering::Relaxed)) {
        retrigger(line);
    }
}

/// 打开 / 关闭持续自触发。
pub fn self_trigger(line: usize, on: bool) -> Result<(), IrqError> {
    if line >= count() {
        return Err(IrqError::NoLine);
    }
    STORM[line].store(on, Ordering::Relaxed);
    match line {
        LINE_UART => uart::set_tx_interrupt(on),
        _ => {
            if on {
                rtc_write(RTC_IRQ_ENABLED, 1);
                rtc_alarm_now();
            } else {
                rtc_write(RTC_IRQ_ENABLED, 0);
                rtc_write(RTC_CLEAR_ALARM, 1);
                rtc_write(RTC_CLEAR_INTERRUPT, 1);
            }
        }
    }
    Ok(())
}

/// 让设备再次请求中断。
fn retrigger(line: usize) {
    match line {
        LINE_UART => {
            // 关再开发送中断：发送缓冲已空时设备立即再次请求中断
            uart::set_tx_interrupt(false);
            uart::set_tx_interrupt(true);
        }
        LINE_RTC => rtc_alarm_now(),
        _ => {}
    }
}

/// 把闹钟设在「现在」：设备立即挂起闹钟中断（先写高半字，写低半字时生效）。
fn rtc_alarm_now() {
    let lo = rtc_read(RTC_TIME_LOW);
    let hi = rtc_read(RTC_TIME_HIGH);
    rtc_write(RTC_ALARM_HIGH, hi);
    rtc_write(RTC_ALARM_LOW, lo);
}

fn rtc_read(off: usize) -> u32 {
    match RTC_BASE.load(Ordering::Relaxed) {
        0 => 0,
        // SAFETY：基地址来自设备树中的 goldfish 实时时钟节点；只读时间寄存器（读低半字锁存高半字）。
        b => unsafe { ((b + off) as *const u32).read_volatile() },
    }
}

fn rtc_write(off: usize, v: u32) {
    let b = RTC_BASE.load(Ordering::Relaxed);
    if b != 0 {
        // SAFETY：同上；只写闹钟、中断使能与清除寄存器。
        unsafe { ((b + off) as *mut u32).write_volatile(v) };
    }
}
