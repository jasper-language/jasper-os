//! POL-4 演练：实时任务的准入、预算记账、节流与证据报告。
//! POL-4 drill: admission, quota accounting, throttling and evidence reporting.
//!
//! # 覆盖
//! 1. 利用率在界内时接纳，超额请求被拒且**已有预留不受影响**；
//! 2. 预算耗尽时记账返回 `Exhausted`，任务节流一次；
//! 3. 周期到达后预算重置，任务可以继续；
//! 4. 节流期间交互任务不被饿死（完成全部唤醒轮次）；
//! 5. 输出证据：交互唤醒延迟的最大值与样本数。
//!
//! # 边界（必须如实说明）
//! 本阶段是**协作式**预算：任务自己记账并在耗尽时让出。抢占式执行
//! （时钟中断里强制把超预算任务换下）尚未接入，因此不能宣称「失控任务也会被停住」。

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::rt::Charge;
use kernel_core::sched::Qos;

use crate::sched;
use crate::task::TaskId;
use crate::{kprintln, rt};

static CHECKS: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);
static DONE: AtomicU32 = AtomicU32::new(0);

const ROUNDS: u32 = 10;

fn check(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-RTCLASS-FAIL] {}", what);
    }
}

/// 本演练的失败断言数。
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

/// 实时任务：每轮记 1 tick 预算，耗尽后让出直到下一个周期。
fn rt_body() {
    loop {
        match rt::charge(20, 1) {
            Ok(Charge::Within) => {
                sched::pause();
            }
            Ok(Charge::Exhausted) => {
                // 协作式节流：睡到下一个周期，再继续。
                sched::sleep_until(sched::timer_ticks() + 5);
                rt::replenish(sched::timer_ticks());
            }
            Err(_) => return,
        }
        if rt::get(20).is_some_and(|t| t.throttles >= 1 && t.remaining == t.quota) {
            return;
        }
    }
}

/// 交互任务：每 tick 醒一次。
fn interactive() {
    // 先抬高档位上限再声明档位：否则 set_current_qos 会因上限不足被拒，
    // 交互延迟样本不会记进交互档直方图（证据就会是空的）。
    sched::set_current_qos_ceiling(Some(Qos::Interactive));
    let _ = sched::set_current_qos(Qos::Interactive);
    for _ in 0..ROUNDS {
        sched::sleep_until(sched::timer_ticks() + 1);
        DONE.fetch_add(1, Ordering::Relaxed);
    }
}

/// 失控任务：不让出、不记账，只靠调度器按预算换下。
fn runaway() {
    let deadline = sched::timer_ticks() + 60;
    while sched::timer_ticks() < deadline {
        core::hint::spin_loop();
    }
}

fn quiet<R>(f: impl FnOnce() -> R) -> R {
    let prev = sched::set_preemption(false);
    let r = f();
    sched::set_preemption(prev);
    r
}

/// 演练入口。
pub fn run() {
    let now = sched::timer_ticks();
    // 1) 准入：500‰ 在界内；再加 600‰ 会被拒。
    check(rt::admit(10, 2, 10, now).is_ok(), "2/10 应被接纳");
    check(rt::admit(11, 3, 10, now).is_ok(), "3/10 应被接纳");
    let before = rt::utilisation_permille();
    check(rt::admit(12, 6, 10, now).is_err(), "超额请求应被拒绝");
    check(rt::utilisation_permille() == before, "被拒后已有预留的利用率不得变化");
    check(rt::get(10).is_some() && rt::get(11).is_some(), "已有预留必须保留");
    kprintln!(
        "[JSR-RTCLASS] admit accepted=2 rejected=1 utilisation={} limit={}",
        rt::utilisation_permille(),
        rt::limit_permille()
    );

    // 2) 预算耗尽与节流（协作式）。
    check(rt::admit(20, 3, 10, now).is_ok(), "3/10 的实时任务应被接纳");
    quiet(|| sched::spawn(TaskId(9400), "rt-quota", rt_body)).expect("创建实时任务");
    // 3) 节流期间交互任务照常运行。
    DONE.store(0, Ordering::Relaxed);
    quiet(|| sched::spawn(TaskId(9401), "rt-ui", interactive)).expect("创建交互任务");
    sched::run();
    let task = rt::get(20);
    check(task.is_some_and(|t| t.throttles >= 1), "预算耗尽后应记录节流");
    check(task.is_some_and(|t| t.remaining == t.quota), "周期补充后预算应重置");
    let done = DONE.load(Ordering::Relaxed);
    check(done == ROUNDS, "节流期间交互任务未完成全部唤醒");

    // 3b) 抢占式节流：失控任务不让出，也必须被预算换下。
    let _ = rt::release(20);
    check(rt::admit(9404, 2, 10, sched::timer_ticks()).is_ok(), "失控任务的实时声明应被接纳");
    quiet(|| sched::spawn(TaskId(9404), "rt-runaway", runaway)).expect("创建失控任务");
    check(sched::set_rt(TaskId(9404), 2, 10), "设置实时预算失败");
    DONE.store(0, Ordering::Relaxed);
    quiet(|| sched::spawn(TaskId(9405), "rt-ui2", interactive)).expect("创建交互任务");
    let started = sched::timer_ticks();
    sched::run();
    let elapsed = sched::timer_ticks() - started;
    kprintln!(
        "[JSR-RTCLASS] preemptive ui_rounds={} rounds={} elapsed_ticks={} throttles={}",
        DONE.load(Ordering::Relaxed),
        ROUNDS,
        elapsed,
        sched::throttle_count()
    );
    let throttles = sched::throttle_count();
    check(DONE.load(Ordering::Relaxed) == ROUNDS, "失控任务期间交互任务被饿死");
    // 失控任务以「墙钟 deadline」收工，elapsed 反映的是墙钟而不是它拿到的 CPU，
    // 因此判据用节流次数：证明调度器确实按预算把它换下（而不是靠它自己让出）。
    check(throttles >= 3, "失控任务未被预算抢占式节流");

    // 4) 证据：交互唤醒延迟的最大值与样本数。
    let lat = sched::latency(Qos::Interactive);
    kprintln!(
        "[JSR-RTCLASS] evidence wake_samples={} wake_max_ticks={} throttle={}",
        lat.count(),
        lat.max(),
        task.map(|t| t.throttles).unwrap_or(0)
    );

    // 5) 收尾：释放额度，供后续演练复用。
    let _ = rt::release(10);
    let _ = rt::release(11);
    let _ = rt::release(20);
    let _ = rt::release(9404);
    kprintln!(
        "[JSR-RTCLASS] summary checks={} failed={} utilisation_after={}",
        CHECKS.load(Ordering::Relaxed),
        failed(),
        rt::utilisation_permille()
    );
}
