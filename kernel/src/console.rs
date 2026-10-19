//! 内核控制台（架构无关）：UTF-8 文本输出、格式化与中断安全。
//!
//! 职责：把文本变成字节流交给 `arch::console_write_byte`；`\n` 前补 `\r`（串口终端习惯）。
//! 文本按 UTF-8 原样输出，中文可直接打印（设计约束：UTF-8 + 原生中文）。
//!
//! 中断与多核安全：每一次 `write_str` / `_print` 都在**一把**关中断自旋锁内完成。
//! 抢占式调度下，定时器中断可能在任意位置切走任务并打印 `[JSR-SCHED]` 行；多处理器下其他核也会同时打印。
//! 不这样做的话两行日志会被切碎交错，验收 grep 就会失真。这把锁是锁顺序链的最内层：持有时不再获取任何锁。
//!
//! 停机前的输出（panic、锁顺序违反）走 [`emergency_print`]：有界地尝试取锁，取不到也照样输出，
//! 绝不因控制台锁被本处理器或已停住的处理器持有而卡死。

use core::fmt;

use crate::arch;
use crate::sync::IrqSpinLock;

/// 控制台锁（保护的是「一条消息不被拆开」，数据本身在硬件里）。
static CONSOLE: IrqSpinLock<()> = IrqSpinLock::ranked(crate::lockorder::CONSOLE, ());

/// 紧急输出尝试取锁的次数上限。
const EMERGENCY_SPINS: u32 = 1 << 20;

/// 输出一段 UTF-8 文本（整段原子输出）。
pub fn write_str(s: &str) {
    let _g = CONSOLE.lock();
    write_str_raw(s);
}

/// 停机前的紧急格式化输出：有界尝试取控制台锁（不登记顺序），取不到也照样输出。
/// Emergency formatted output before halting; never blocks indefinitely.
pub fn emergency_print(args: fmt::Arguments) {
    use fmt::Write;
    arch::without_irq(|| {
        let mut guard = None;
        for _ in 0..EMERGENCY_SPINS {
            guard = CONSOLE.try_lock_bypass();
            if guard.is_some() {
                break;
            }
            core::hint::spin_loop();
        }
        let _ = Console.write_fmt(args);
        drop(guard);
    });
}

/// 控制台锁遇到占用的次数（多核同时打印时增长）。
/// Contended acquisitions of the console lock.
pub fn contended() -> u32 {
    CONSOLE.contended()
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

/// 格式化输出：整条消息在控制台锁内完成，保证一行日志不被中断或其他处理器打断。
pub fn _print(args: fmt::Arguments) {
    use fmt::Write;
    let _g = CONSOLE.lock();
    let _ = Console.write_fmt(args);
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
