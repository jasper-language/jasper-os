//! 通用定时器（Generic Timer）的虚拟定时器：周期时钟中断与单调计数器。
//! Virtual generic timer: periodic tick and monotonic counter.
//!
//! 用「倒计时值」（TVAL）而不是「比较值」（CVAL）重装：长时间关中断后只补发一次中断，
//! 不会为追赶错过的周期而连续触发——过载时宁可少记几个 tick，也不让中断风暴挤占处理器。

use core::sync::atomic::{AtomicU64, Ordering};

use super::cpu::{read_sysreg, write_sysreg};

/// 每个周期的计数值。
static INTERVAL: AtomicU64 = AtomicU64::new(0);
/// 虚拟定时器的私有中断号（来自设备树；初始化前为 0）。
static PPI: AtomicU64 = AtomicU64::new(0);

/// 记录设备树给出的虚拟定时器中断号。
pub fn set_interrupt(ppi: u32) {
    PPI.store(u64::from(ppi), Ordering::Relaxed);
}

/// 虚拟定时器的中断号（未从设备树得到时为 `None`）。
pub fn interrupt() -> Option<u32> {
    match PPI.load(Ordering::Relaxed) {
        0 => None,
        p => Some(p as u32),
    }
}

/// CNTKCTL_EL1.EL0VCTEN：EL0 读 `cntvct_el0` 不陷入。
const CNTKCTL_EL0VCTEN: u64 = 1 << 1;

/// 以 `hz` 的频率开始产生周期中断（中断是否送达由 GIC 与 PSTATE 决定）。
pub fn init(hz: u32) {
    let freq = read_sysreg!("cntfrq_el0");
    let interval = (freq / u64::from(hz.max(1))).max(1);
    INTERVAL.store(interval, Ordering::Relaxed);
    // SAFETY：只配置本处理器的虚拟定时器：先装倒计时值，再使能且不屏蔽其中断输出。
    // CNTKCTL_EL1 只置 EL0VCTEN：用户态可读虚拟计数器（与 x86_64 用户态可读时间戳计数器对等），
    // 但不能访问任何定时器的控制与比较寄存器，也不能读物理计数器。
    unsafe {
        write_sysreg!("cntkctl_el1", CNTKCTL_EL0VCTEN);
        write_sysreg!("cntv_tval_el0", interval);
        write_sysreg!("cntv_ctl_el0", 1u64);
    }
    super::cpu::isb();
}

/// 重装下一个周期（在定时器中断里、结束中断之前调用；同时撤下电平触发的中断信号）。
pub fn rearm() {
    // SAFETY：只写本处理器虚拟定时器的倒计时值。
    unsafe { write_sysreg!("cntv_tval_el0", INTERVAL.load(Ordering::Relaxed)) };
    super::cpu::isb();
}

/// 读虚拟计数器（单调递增；频率见 `cntfrq_el0`）。
#[inline(always)]
pub fn counter() -> u64 {
    super::cpu::isb();
    read_sysreg!("cntvct_el0")
}
