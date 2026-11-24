//! 8253/8254 PIT：x86 平台的周期定时器（IRQ0）。
//!
//! 通道 0、模式 3（方波），分频 = 1193182 / hz。只负责「按频率产生中断」；
//! tick 计数与打印属于 Core 的 `clock`，与具体定时器硬件无关。

use super::port::outb;

/// PIT 输入时钟频率（Hz）。
const PIT_BASE_FREQ: u32 = 1_193_182;
/// 16 位通道计数器可表示的最大计数；延迟分段由该硬件事实推导。
const PIT_MAX_COUNT: u32 = u16::MAX as u32;
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

/// 通道 2 数据端口（不接中断，用于忙等计时）。
const PIT_CHANNEL2: u16 = 0x42;
/// 通道 2 门控与输出状态端口（位 0 = 门控，位 1 = 扬声器，位 5 = 通道 2 输出）。
const PIT_GATE: u16 = 0x61;
/// 单个完整 16 位计数周期对应的最长微秒数。
const MAX_CHUNK_US: u32 = (PIT_MAX_COUNT as u64 * 1_000_000 / PIT_BASE_FREQ as u64) as u32; // JASPER-HARDCODE-REVIEW: issue=35 source=PIT-8254-HARDWARE reason=derived-from-sixteen-bit-counter-and-input-clock
/// Bound the output-bit poll so a disconnected or disabled PIT channel cannot
/// stall SMP bring-up forever.
const OUTPUT_WAIT_SPINS: u32 = 10_000_000;

/// 忙等至少 `us` 微秒（通道 2 单次计数、轮询输出位；不需要中断，可在关中断时使用）。
///
/// 只在引导处理器上调用（命令端口与通道 0 共享，同一时刻只能有一个编程者）。
pub fn delay_us(us: u32) {
    let mut left = us;
    while left > 0 {
        let chunk = left.min(MAX_CHUNK_US); // JASPER-HARDCODE-REVIEW: issue=35 source=PIT-8254-HARDWARE reason=single-hardware-count-period-not-runtime-work-capacity
        let count = ((PIT_BASE_FREQ as u64 * chunk as u64) / 1_000_000)
            .clamp(1, u64::from(PIT_MAX_COUNT)) as u16;
        // SAFETY：标准 PIT 编程：0xB0 = 通道 2、先低后高字节、模式 0（计满输出变高）、二进制；
        // 端口 0x61 只改门控与扬声器位（扬声器保持关闭）。
        unsafe {
            let gate = super::port::inb(PIT_GATE) & !0x03;
            outb(PIT_GATE, gate);
            outb(PIT_COMMAND, 0xB0);
            outb(PIT_CHANNEL2, (count & 0xff) as u8);
            outb(PIT_CHANNEL2, (count >> 8) as u8);
            outb(PIT_GATE, gate | 0x01);
            let mut completed = false;
            for _ in 0..OUTPUT_WAIT_SPINS {
                if super::port::inb(PIT_GATE) & 0x20 != 0 {
                    completed = true;
                    break;
                }
                core::hint::spin_loop();
            }
            outb(PIT_GATE, gate);
            if !completed {
                crate::console::emergency_print(format_args!(
                    "[JSR-PIT] timeout channel2_output_not_observed\n"
                ));
                return;
            }
        }
        left -= chunk;
    }
}
