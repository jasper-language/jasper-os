//! 时钟（架构无关）：在延迟路径上对定时器 tick 计数并输出验收标记。
//!
//! 与调度器的 `timer_ticks()` 区别：那个在中断上下文里递增（用于时间片与忙等），
//! 这里在 `irq::poll_and_handle` 里递增，只统计「被主循环处理过」的 tick，用于 M1.2 验收。

use core::sync::atomic::Ordering;

use crate::sync::IrqU64;
use crate::kprintln;

/// 已处理的 tick 数。
static TICKS: IrqU64 = IrqU64::new(0);

/// 已处理的 tick 数。
pub fn ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

/// 处理一个 tick：计数；启动自检期间打印 `[JSR-TICK] n=<n>`，之后不再输出（生产启动的等待循环会一直走到这里）。
/// Count a tick; print the marker only during the boot self-check, since a production boot keeps
/// coming here while it waits.
pub fn on_tick() {
    let n = TICKS.fetch_add(1, Ordering::Relaxed) + 1;
    if n <= crate::config::ACTIVE.clock.boot_ticks {
        kprintln!("[JSR-TICK] n={}", n);
    }
}
