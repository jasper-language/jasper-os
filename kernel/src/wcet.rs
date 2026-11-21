//! WCET 证据：关键路径的最大实测值（系统调用、交互唤醒）。
//! WCET evidence: measured maxima on the critical paths.
//!
//! # 为什么需要
//! 「实时可行」不能靠口头保证。至少要能回答：一次系统调用最长花了多少周期、
//! 交互任务从睡着到真正运行最长等了多少 tick。两者都可测，且一旦退化会立刻暴露。
//!
//! # 边界
//! 只做测量与报告，不影响调度决策。周期计数在 QEMU 上是虚拟 TSC，
//! **不能**据此推断真实硬件的绝对耗时；这里只用于横向比较与回归。

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use spin::Once;

use kernel_core::sync::Atomic64;
use kernel_core::smp::MAX_CPUS;
use kernel_core::cpu_storage::CpuTailLayout;

// 32 位目标没有 64 位原子指令：用 kernel-core 的自旋锁模拟单元。
static SYSCALL_MAX_CYCLES: Atomic64 = Atomic64::new(0);
static SYSCALL_SAMPLES: AtomicU32 = AtomicU32::new(0);
static IRQ_OFF_MAX_CYCLES: Atomic64 = Atomic64::new(0);
static IRQ_OFF_SAMPLES: AtomicU32 = AtomicU32::new(0);
static LOCK_MAX_CYCLES: Atomic64 = Atomic64::new(0);
static LOCK_SAMPLES: AtomicU32 = AtomicU32::new(0);

struct IrqOffState {
    start: AtomicU32,
    depth: AtomicU32,
}

impl IrqOffState {
    const fn new() -> Self {
        Self {
            start: AtomicU32::new(0),
            depth: AtomicU32::new(0),
        }
    }
}

/// 每处理器「关中断起点」与嵌套深度。周期戳只取低 32 位：只比较差值，
/// 环绕减法仍然正确；超过一秒量级的临界区本就不该存在。
static BOOTSTRAP_IRQ_OFF: [IrqOffState; MAX_CPUS] =
    [const { IrqOffState::new() }; MAX_CPUS];
static EXTRA_IRQ_OFF: Once<Result<Vec<IrqOffState>, ReserveError>> = Once::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReserveError {
    Allocation,
    AlreadyReservedTooSmall,
}

impl ReserveError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Allocation => "system.wcet.error.cpu_storage_allocation",
            Self::AlreadyReservedTooSmall => "system.wcet.error.cpu_storage_capacity",
        }
    }
}

/// Reserve the complete per-CPU WCET IRQ-off state before any AP starts.
pub fn prepare_cpu_storage(cpus: usize) -> Result<(), ReserveError> {
    let needed = CpuTailLayout::new(MAX_CPUS, cpus).tail_len();
    let states = EXTRA_IRQ_OFF.call_once(|| {
        let mut states = Vec::new();
        states
            .try_reserve_exact(needed)
            .map_err(|_| ReserveError::Allocation)?;
        for _ in 0..needed {
            states.push(IrqOffState::new());
        }
        Ok(states)
    });
    match states {
        Ok(states) if states.len() >= needed => Ok(()),
        Ok(_) => Err(ReserveError::AlreadyReservedTooSmall),
        Err(error) => Err(*error),
    }
}

fn irq_off_state(cpu: usize) -> Option<&'static IrqOffState> {
    let layout = CpuTailLayout::new(MAX_CPUS, crate::smp::cpu_count());
    if cpu >= layout.admitted() {
        return None;
    }
    if let Some(state) = BOOTSTRAP_IRQ_OFF.get(cpu) {
        return Some(state);
    }
    if !layout.is_tail(cpu) {
        return None;
    }
    let extra = layout.tail_index(cpu)?;
    EXTRA_IRQ_OFF.get()?.as_ref().ok()?.get(extra)
}

/// 记录一次系统调用的耗时（周期）。
pub fn record_syscall(cycles: u64) {
    SYSCALL_SAMPLES.fetch_add(1, Ordering::Relaxed);
    // 非原子的「读-比-写」：并发下最多丢掉一次更大值的更新，
    // 对「量级证据」足够；真正的精确最大值要等 64 位原子或按核分开统计。
    if cycles > SYSCALL_MAX_CYCLES.load(Ordering::Relaxed) {
        SYSCALL_MAX_CYCLES.store(cycles, Ordering::Relaxed);
    }
}

/// 进入关中断区：最外层记起点，嵌套只加深计数。
pub fn irq_off_enter() {
    let cpu = crate::arch::cpu_index();
    let Some(state) = irq_off_state(cpu) else {
        crate::arch::halt_forever()
    };
    if state.depth.fetch_add(1, Ordering::Relaxed) == 0 {
        state
            .start
            .store(crate::arch::cycles() as u32, Ordering::Relaxed);
    }
}

/// 离开关中断区：最外层退出时结算本次窗口。
pub fn irq_off_exit() {
    let cpu = crate::arch::cpu_index();
    let Some(state) = irq_off_state(cpu) else {
        crate::arch::halt_forever()
    };
    if state.depth.fetch_sub(1, Ordering::Relaxed) != 1 {
        return;
    }
    let start = state.start.load(Ordering::Relaxed);
    let elapsed = (crate::arch::cycles() as u32).wrapping_sub(start) as u64;
    IRQ_OFF_SAMPLES.fetch_add(1, Ordering::Relaxed);
    if elapsed > IRQ_OFF_MAX_CYCLES.load(Ordering::Relaxed) {
        IRQ_OFF_MAX_CYCLES.store(elapsed, Ordering::Relaxed);
    }
}

/// 记录一次锁持有时间（周期）。
pub fn record_lock(cycles: u64) {
    LOCK_SAMPLES.fetch_add(1, Ordering::Relaxed);
    if cycles > LOCK_MAX_CYCLES.load(Ordering::Relaxed) {
        LOCK_MAX_CYCLES.store(cycles, Ordering::Relaxed);
    }
}

/// 输出证据：本构建实测到的最长系统调用耗时与最长交互唤醒延迟。
///
/// 唤醒延迟来自调度器的交互档直方图（单位 tick）；系统调用耗时单位是周期。
/// English: print the measured maxima; QEMU cycles are virtual and only
/// comparable within the same build.
pub fn report() {
    let samples = SYSCALL_SAMPLES.load(Ordering::Relaxed);
    let max = SYSCALL_MAX_CYCLES.load(Ordering::Relaxed);
    let wake = crate::sched::latency(kernel_core::sched::Qos::Interactive);
    crate::kprintln!(
        "[JSR-WCET] syscall_samples={} syscall_max_cycles_incl_blocking={} wake_samples={} wake_max_ticks={}",
        samples,
        max,
        wake.count(),
        wake.max()
    );
    crate::kprintln!(
        "[JSR-WCET] irq_off_samples={} irq_off_max_cycles={} lock_samples={} lock_max_cycles={}",
        IRQ_OFF_SAMPLES.load(Ordering::Relaxed),
        IRQ_OFF_MAX_CYCLES.load(Ordering::Relaxed),
        LOCK_SAMPLES.load(Ordering::Relaxed),
        LOCK_MAX_CYCLES.load(Ordering::Relaxed)
    );
}
