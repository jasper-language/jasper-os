//! 里程碑演示：调度器的「客户」，与机制分离，删掉本文件不影响机制本身。
//!
//! * M1.3 `run()`：A/B/C 三个任务协作式轮转（主动 yield），验证真实栈切换
//! * M1.4 `run_preemptive()`：P/Q/R 三个任务**从不主动让出**，只靠定时器抢占轮转
//!
//! 串口标记格式由规格 §M1.3/§M1.4 固定，验收脚本 `verify-m1.3.sh` / `verify-m1.4.sh` 按它 grep。

use core::sync::atomic::Ordering;

use crate::sync::IrqU64;
use crate::console;
use crate::task::TaskId;
use kernel_core::smp::CpuSet;

use super::scheduler::SwitchEvent;

/// 每个演示任务执行的步数。
const DEMO_STEPS: u32 = 3;

/// 切换观察者：把每次切换打印成 `[JSR-SCHED]` 行。
fn log_switch(e: &SwitchEvent) {
    console::_print(format_args!(
        "[JSR-SCHED] switch from={} to={} n={} cause={}\n",
        e.from, e.to, e.seq, e.cause
    ));
}

/// 演示任务体：每步打印一次后主动让出。
fn demo_task() {
    for step in 1..=DEMO_STEPS {
        let (id, name) = super::current();
        console::_print(format_args!("[JSR-TASK] name={} step={} task_id={}\n", name, step, id.0));
        super::yield_now();
    }
}

/// 运行演示：创建 A/B/C 三个任务，轮转到全部退出后回到引导线程。
///
/// 协作式演示要求可复现的交错顺序：演示期间关闭时间片抢占，结束后恢复。
pub fn run() {
    let prev_preemption = super::set_preemption(false);
    super::set_observer(log_switch);
    for (id, name) in [(1, "A"), (2, "B"), (3, "C")] {
        if super::spawn(TaskId(id), name, demo_task).is_err() {
            console::_print(format_args!("[JSR-SCHED] spawn failed name={}\n", name));
        }
    }
    super::run();
    super::set_preemption(prev_preemption);
    console::_print(format_args!(
        "[JSR-SCHED] all tasks exited switches={} policy={}\n",
        super::switch_count(),
        super::policy_name()
    ));
}

/// 抢占演示中每个任务执行的步数。
const PREEMPT_STEPS: u32 = 8;

/// 由定时器抢占触发的切换次数（观察者统计）。
static TICK_SWITCHES: IrqU64 = IrqU64::new(0);

/// 抢占演示的切换观察者：打印并统计 `cause=tick` 的切换。
fn log_and_count_switch(e: &SwitchEvent) {
    if e.cause == "tick" {
        TICK_SWITCHES.fetch_add(1, Ordering::Relaxed);
    }
    log_switch(e);
}

/// 抢占演示任务体：**从不调用 yield**。每一步忙等到定时器再走一个 tick 后打印一行。
/// 若没有抢占，第一个任务会把所有步数背靠背跑完，其他任务的步数不会与它交错。
fn busy_task() {
    for step in 1..=PREEMPT_STEPS {
        let target = super::timer_ticks() + 1;
        while super::timer_ticks() < target {
            core::hint::spin_loop();
        }
        let (id, name) = super::current();
        console::_print(format_args!("[JSR-TASK] name={} step={} task_id={}\n", name, step, id.0));
    }
}

/// M1.4 演示：打开抢占，P/Q/R 三个忙等任务只靠时间片轮转，全部退出后回到引导线程。
///
/// 前置条件：PIC/PIT 已初始化；调用时中断已开启（否则定时器中断无法投递）。
pub fn run_preemptive() {
    // 起始标记：验收从这里开始统计 tick 切换。若从 P 的第一步开始数，P 可能在打印第一步之前
    // 就被同一个 tick 抢占，开头的几次切换会被漏数（取决于引导线程让出时落在 tick 周期的哪个相位）。
    console::_print(format_args!("[JSR-SCHED] preemptive demo start\n"));
    super::set_observer(log_and_count_switch);
    // 三个任务钉在执行演练的处理器上：本演练验证的是「单个处理器上只靠时间片轮转」。
    // 多处理器时若允许分散，各任务可能独占一个处理器而无需被抢占，tick 切换数随负载均衡的时机浮动。
    let mut here = CpuSet::EMPTY;
    here.insert(crate::arch::cpu_index());
    for (id, name) in [(11, "P"), (12, "Q"), (13, "R")] {
        if super::spawn_on(TaskId(id), name, busy_task, None, here).is_err() {
            console::_print(format_args!("[JSR-SCHED] spawn failed name={}\n", name));
        }
    }
    let prev_preemption = super::set_preemption(true);
    super::run();
    super::set_preemption(prev_preemption);
    console::_print(format_args!(
        "[JSR-SCHED] preemptive demo done tick_switches={} quantum_ticks={} policy={}\n",
        TICK_SWITCHES.load(Ordering::Relaxed),
        super::quantum_ticks(),
        super::policy_name()
    ));
}
