//! 8253/8254 PIT：x86 平台的周期定时器（IRQ0）。
//!
//! 通道 0、模式 3（方波），分频 = 1193182 / hz。只负责「按频率产生中断」；
//! tick 计数与打印属于 Core 的 `clock`，与具体定时器硬件无关。

use super::port::outb;

/// PIT 输入时钟频率（Hz）。
const PIT_BASE_FREQ: u32 = 1_193_182;
/// 通道 0 数据端口。
const PIT_CHANNEL0: u16 = 0x40;
/// 模式/命令端口。
const PIT_COMMAND: u16 = 0x43;

/// 把通道 0 配置为 `hz` 赫兹的周期中断。
pub fn init(hz: u32) {
    let divisor = (PIT_BASE_FREQ / hz) as u16;
    // SAFETY：标准 PIT 编程序列：0x36 = 通道 0、先低后高字节、模式 3、二进制计数。
    unsafe {
        outb(PIT_COMMAND, 0x36);
        outb(PIT_CHANNEL0, (divisor & 0xff) as u8);
        outb(PIT_CHANNEL0, (divisor >> 8) as u8);
    }
}
