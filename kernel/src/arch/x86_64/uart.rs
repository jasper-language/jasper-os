//! COM1（I/O 端口 0x3F8）16550 UART：x86 平台的早期控制台。
//!
//! 初始化序列沿用前期验证实现中已实测可用的写法：38400 波特、8N1、开 FIFO。
//! 只负责「把一个字节送出去」；格式化、换行转换与中断临界区由 Core 的 `console` 负责。

use super::port::{inb, outb};

/// COM1 基地址。
const COM1: u16 = 0x3F8;
/// 线路状态寄存器中「发送保持寄存器空」位。
const LSR_THR_EMPTY: u8 = 0x20;

/// 初始化 COM1。
pub fn init() {
    // SAFETY：标准 PC 平台上 COM1 的寄存器布局固定；以下为 16550 的标准初始化序列。
    unsafe {
        outb(COM1 + 1, 0x00); // 关闭 UART 自身中断
        outb(COM1 + 3, 0x80); // 打开 DLAB 以设置分频
        outb(COM1, 0x03); // 分频低字节：38400 波特
        outb(COM1 + 1, 0x00); // 分频高字节
        outb(COM1 + 3, 0x03); // 8 位数据、无校验、1 停止位
        outb(COM1 + 2, 0xC7); // 开 FIFO、清空、14 字节阈值
        outb(COM1 + 4, 0x03); // DTR + RTS
    }
}

/// 阻塞直到发送缓冲空，然后写出一个字节。
pub fn write_byte(byte: u8) {
    // SAFETY：只读线路状态、只写数据寄存器。
    unsafe {
        while (inb(COM1 + 5) & LSR_THR_EMPTY) == 0 {}
        outb(COM1, byte);
    }
}
