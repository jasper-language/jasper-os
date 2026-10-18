//! 监管态定时器：经 SBI TIME 扩展设置下一次中断，周期由设备树的 `timebase-frequency` 换算。
//! Supervisor timer via the SBI TIME extension; period derived from `timebase-frequency`.
//!
//! 每次以「当前计数 + 周期」重装（相对时间）：长时间关中断后只补发一次中断，不为追赶错过的周期而连续触发——
//! 过载时宁可少记几个 tick，也不让中断风暴挤占处理器（与 AArch64 用倒计时值重装的取舍相同）。

use core::sync::atomic::{AtomicU32, Ordering};

use super::{cpu, sbi};

/// `time` 计数器频率（Hz，来自设备树的 32 位单元；初始化前为 0）。
static FREQUENCY: AtomicU32 = AtomicU32::new(0);
/// 每个周期的计数值（不超过频率本身，32 位足够；用 32 位原子使 RV32 与 RV64 共用同一实现）。
static INTERVAL: AtomicU32 = AtomicU32::new(0);

/// 记录设备树给出的计数器频率。
pub fn set_frequency(hz: u32) {
    FREQUENCY.store(hz, Ordering::Relaxed);
}

/// 定时器是否可用：频率已知且固件实现了 TIME 扩展。
pub fn available() -> bool {
    FREQUENCY.load(Ordering::Relaxed) != 0 && sbi::has_extension(sbi::EID_TIME)
}

/// 以 `hz` 的频率开始产生周期中断（是否送达由 sie / sstatus 决定）。
pub fn init(hz: u32) {
    let interval = (FREQUENCY.load(Ordering::Relaxed) / hz.max(1)).max(1);
    INTERVAL.store(interval, Ordering::Relaxed);
    sbi::set_timer(cpu::read_time() + u64::from(interval));
    cpu::enable_sources(cpu::SIE_STIE);
}

/// 重装下一个周期（在定时器中断里调用；同时撤下挂起的定时器中断）。
pub fn rearm() {
    sbi::set_timer(cpu::read_time() + u64::from(INTERVAL.load(Ordering::Relaxed)));
}

/// 读 `time` 计数器。
#[inline(always)]
pub fn counter() -> u64 {
    cpu::read_time()
}
