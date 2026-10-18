//! PL011 UART：AArch64 平台的早期控制台。
//! PL011 UART used as the early console.
//!
//! 寄存器基地址来自设备树（`arm,pl011`），经全物理内存映射访问（设备内存属性）。
//! 波特率沿用固件 / 仿真器已设置的值：分频依赖的参考时钟要经设备树的时钟引用解析，早期控制台不做这件事。
//! 只负责「把一个字节送出去」；格式化、换行转换与中断临界区由 Core 的 `console` 负责。

use core::sync::atomic::{AtomicU64, Ordering};

/// 数据寄存器。
const DR: u64 = 0x00;
/// 标志寄存器。
const FR: u64 = 0x18;
/// 线路控制寄存器。
const LCR_H: u64 = 0x2c;
/// 控制寄存器。
const CR: u64 = 0x30;
/// 中断屏蔽寄存器。
const IMSC: u64 = 0x38;
/// FR：发送 FIFO 满。
const FR_TXFF: u32 = 1 << 5;
/// FR：正在发送。
const FR_BUSY: u32 = 1 << 3;
/// LCR_H：8 位数据 + 开 FIFO（无校验、1 停止位）。
const LCR_8N1_FIFO: u32 = (3 << 5) | (1 << 4);
/// CR：使能 UART、发送、接收。
const CR_ENABLE: u32 = (1 << 0) | (1 << 8) | (1 << 9);

/// 寄存器块的虚拟地址（0 = 尚未从设备树得到）。
static BASE: AtomicU64 = AtomicU64::new(0);

/// 设置寄存器块的虚拟地址（引导适配层解析设备树后调用）。
pub fn set_base(va: u64) {
    BASE.store(va, Ordering::Relaxed);
}

fn reg(off: u64) -> Option<*mut u32> {
    match BASE.load(Ordering::Relaxed) {
        0 => None,
        b => Some((b + off) as *mut u32),
    }
}

/// 初始化：关闭 → 等发送完 → 8N1 + FIFO → 屏蔽 UART 自身中断 → 使能。基地址未知时什么都不做。
pub fn init() {
    let (Some(cr), Some(fr), Some(lcr), Some(imsc)) = (reg(CR), reg(FR), reg(LCR_H), reg(IMSC)) else {
        return;
    };
    // SAFETY：基地址来自设备树中的 PL011 节点，并以设备内存属性映射；以下为 PL011 手册规定的重配置顺序。
    unsafe {
        cr.write_volatile(0);
        while fr.read_volatile() & FR_BUSY != 0 {}
        lcr.write_volatile(LCR_8N1_FIFO);
        imsc.write_volatile(0);
        cr.write_volatile(CR_ENABLE);
    }
}

/// 阻塞直到发送 FIFO 有空位，然后写出一个字节。基地址未知时丢弃。
pub fn write_byte(byte: u8) {
    let (Some(fr), Some(dr)) = (reg(FR), reg(DR)) else {
        return;
    };
    // SAFETY：只读标志寄存器、只写数据寄存器。
    unsafe {
        while fr.read_volatile() & FR_TXFF != 0 {}
        dr.write_volatile(u32::from(byte));
    }
}
