//! NS16550A 兼容串口：RISC-V 平台的早期控制台。
//! NS16550A-compatible UART used as the early console.
//!
//! 寄存器基地址与中断号来自设备树（`ns16550a`），经全物理内存映射访问；寄存器按字节排列（`reg-shift` = 0）。
//! 波特率沿用固件已设置的值。只负责「把一个字节送出去」，以及中断控制器自检所需的「发送保持寄存器空」中断开关；
//! 格式化、换行转换与中断临界区由 Core 的 `console` 负责。

use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

/// 发送保持寄存器（写）。
const THR: usize = 0;
/// 中断使能寄存器。
const IER: usize = 1;
/// FIFO 控制寄存器（写）。
const FCR: usize = 2;
/// 线路控制寄存器。
const LCR: usize = 3;
/// 线路状态寄存器。
const LSR: usize = 5;
/// LSR：发送保持寄存器空。
const LSR_THRE: u8 = 1 << 5;
/// IER：发送保持寄存器空中断。
const IER_THRE: u8 = 1 << 1;
/// LCR：8 位数据、无校验、1 停止位。
const LCR_8N1: u8 = 0x03;
/// FCR：使能并清空收发 FIFO。
const FCR_ENABLE_CLEAR: u8 = 0x07;

/// 寄存器块的虚拟地址（0 = 尚未从设备树得到）。
static BASE: AtomicUsize = AtomicUsize::new(0);
/// 设备树给出的中断号（0 = 未知）。
static IRQ: AtomicU32 = AtomicU32::new(0);

/// 设置寄存器块的虚拟地址与中断号（引导适配层解析设备树后调用）。
pub fn set_base(va: u64, irq: u32) {
    BASE.store(va as usize, Ordering::Relaxed);
    IRQ.store(irq, Ordering::Relaxed);
}

/// 设备树给出的中断号。
pub fn interrupt() -> Option<u32> {
    match IRQ.load(Ordering::Relaxed) {
        0 => None,
        n => Some(n),
    }
}

fn reg(off: usize) -> Option<*mut u8> {
    match BASE.load(Ordering::Relaxed) {
        0 => None,
        b => Some((b + off) as *mut u8),
    }
}

/// 初始化：8N1、开 FIFO、关闭串口自身的全部中断。基地址未知时什么都不做。
pub fn init() {
    let (Some(ier), Some(fcr), Some(lcr)) = (reg(IER), reg(FCR), reg(LCR)) else {
        return;
    };
    // SAFETY：基地址来自设备树中的 ns16550a 节点；只写线路控制、FIFO 控制与中断使能寄存器。
    unsafe {
        ier.write_volatile(0);
        lcr.write_volatile(LCR_8N1);
        fcr.write_volatile(FCR_ENABLE_CLEAR);
    }
}

/// 打开或关闭「发送保持寄存器空」中断（中断控制器自检用；平时保持关闭）。
pub fn set_tx_interrupt(on: bool) {
    if let Some(ier) = reg(IER) {
        // SAFETY：只写中断使能寄存器；接收中断始终保持关闭。
        unsafe { ier.write_volatile(if on { IER_THRE } else { 0 }) };
    }
}

/// 阻塞直到发送保持寄存器空，然后写出一个字节。基地址未知时丢弃。
pub fn write_byte(byte: u8) {
    let (Some(lsr), Some(thr)) = (reg(LSR), reg(THR)) else {
        return;
    };
    // SAFETY：只读线路状态寄存器、只写发送保持寄存器。
    unsafe {
        while lsr.read_volatile() & LSR_THRE == 0 {}
        thr.write_volatile(byte);
    }
}
