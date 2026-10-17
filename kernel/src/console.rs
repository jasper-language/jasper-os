//! 内核控制台（架构无关）：UTF-8 文本输出、格式化与中断安全。
//!
//! 职责：把文本变成字节流交给 `arch::console_write_byte`；`\n` 前补 `\r`（串口终端习惯）。
//! 文本按 UTF-8 原样输出，中文可直接打印（设计约束：UTF-8 + 原生中文）。
//!
//! 中断安全：每一次 `write_str` / `_print` 都在**一个**关中断临界区内完成。
//! 抢占式调度下，定时器中断可能在任意位置切走任务并打印 `[JSR-SCHED]` 行；
//! 不这样做的话两行日志会被切碎交错，验收 grep 就会失真。

use core::fmt;

use crate::arch;

/// 输出一段 UTF-8 文本（整段原子输出）。
pub fn write_str(s: &str) {
    arch::without_irq(|| write_str_raw(s));
}

/// 不加临界区的输出，只在已经处于临界区内时调用。
fn write_str_raw(s: &str) {
    for b in s.bytes() {
        if b == b'\n' {
            arch::console_write_byte(b'\r');
        }
        arch::console_write_byte(b);
    }
}

/// `core::fmt::Write` 适配器（零大小类型）。
struct Console;

impl fmt::Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        write_str_raw(s);
        Ok(())
    }
}

/// 格式化输出：整条消息在一个关中断临界区内完成，保证一行日志不被中断打断。
pub fn _print(args: fmt::Arguments) {
    use fmt::Write;
    arch::without_irq(|| {
        let _ = Console.write_fmt(args);
    });
}

/// 格式化打印（不换行）。
#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => ($crate::console::_print(format_args!($($arg)*)));
}

/// 格式化打印并换行。
#[macro_export]
macro_rules! kprintln {
    () => ($crate::console::write_str("\n"));
    ($($arg:tt)*) => ({
        $crate::console::_print(format_args!("{}\n", format_args!($($arg)*)));
    });
}
