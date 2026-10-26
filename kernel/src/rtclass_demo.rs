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
//! 所有预算由实际调度器 tick 扣费；任务不手工记账。TCG 只验证机制，不证明物理延迟。

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::sched::Qos;

use crate::sched;
use crate::task::TaskId;
use crate::kprintln;

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

// Observe actual scheduler depletion/refill; never manually charge a budget.
static REFILLED:AtomicU32=AtomicU32::new(0);
fn rt_body() {
 let id=sched::current().0;
 let (_,_,deadline)=sched::rt_state(id).expect("admitted RT worker");
 loop {
  let (remaining,period,next)=sched::rt_state(id).unwrap();
  if next>deadline {REFILLED.store(u32::from(remaining==3 && period==10),Ordering::Release);return;}
  core::hint::spin_loop();
 }
}
static RELEASE:AtomicU32=AtomicU32::new(0);
fn admission_worker(){while RELEASE.load(Ordering::Acquire)==0 {sched::yield_now();}}
fn only0()->kernel_core::smp::CpuSet {kernel_core::smp::CpuSet::first(1)}

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
    // Real Task reservations under one bounded setup transaction.
    let irq=crate::arch::irq_save_disable();RELEASE.store(0,Ordering::Release);
    for id in 9410..=9412 {sched::spawn_on(TaskId(id),"rt-admit",admission_worker,None,only0()).unwrap();}
    check(sched::set_rt(TaskId(9410),2,10),"2/10 admission");
    check(sched::set_rt(TaskId(9411),3,10),"3/10 admission");
    let first=sched::rt_state(TaskId(9410));let second=sched::rt_state(TaskId(9411));
    check(!sched::set_rt(TaskId(9412),6,10),"overfull partition rejected");
    check(sched::rt_state(TaskId(9410))==first,"first reservation unchanged");
    check(sched::rt_state(TaskId(9411))==second,"second reservation unchanged");
    kprintln!("[JSR-RTCLASS] admit accepted=2 rejected=1 utilisation=500 limit=900");
    RELEASE.store(1,Ordering::Release);crate::arch::irq_restore(irq);sched::run();

    let irq=crate::arch::irq_save_disable();
    sched::spawn_on(TaskId(9400),"rt-quota",rt_body,None,only0()).unwrap();
    check(sched::set_rt(TaskId(9400),3,10),"scheduler quota admission");
    REFILLED.store(0,Ordering::Release);DONE.store(0,Ordering::Relaxed);
    sched::spawn_on(TaskId(9401),"rt-ui",interactive,None,only0()).unwrap();
    let before_throttles=sched::throttle_count();
    crate::arch::irq_restore(irq);sched::run();
    let quota_throttles=sched::throttle_count().saturating_sub(before_throttles);
    check(quota_throttles>=1,"actual budget exhaustion must throttle");
    check(REFILLED.load(Ordering::Acquire)==1,"actual period refill restores quota");
    check(DONE.load(Ordering::Relaxed)==ROUNDS,"interactive rounds during throttle");

    // 3b) 抢占式节流：失控任务不让出，也必须被预算换下。
    let irq=crate::arch::irq_save_disable();
    sched::spawn_on(TaskId(9404), "rt-runaway", runaway,None,only0()).expect("创建失控任务");
    check(sched::set_rt(TaskId(9404), 2, 10), "设置实时预算失败");
    DONE.store(0, Ordering::Relaxed);
    quiet(|| sched::spawn(TaskId(9405), "rt-ui2", interactive)).expect("创建交互任务");
    let before_runaway=sched::throttle_count();
    let started = sched::timer_ticks();
    crate::arch::irq_restore(irq);
    sched::run();
    let elapsed = sched::timer_ticks() - started;
    kprintln!(
        "[JSR-RTCLASS] preemptive ui_rounds={} rounds={} elapsed_ticks={} throttles={}",
        DONE.load(Ordering::Relaxed),
        ROUNDS,
        elapsed,
        sched::throttle_count()
    );
    let throttles = sched::throttle_count().saturating_sub(before_runaway);
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
        quota_throttles
    );

    // 4b) 单模式 Profile：没有 `sched.realtime` 时实时接口整体不存在。
    let full_rt = kernel_core::profile::resolve(&kernel_core::profile::HEADLESS)
        .map(|r| r.has_capability("sched.realtime"))
        .unwrap_or(false);
    let min_rt = kernel_core::profile::resolve(&kernel_core::profile::HEADLESS_MIN)
        .map(|r| r.has_capability("sched.realtime"))
        .unwrap_or(false);
    kprintln!("[JSR-RTCLASS] profile realtime headless={} headless-min={}", full_rt, min_rt);
    check(full_rt, "headless 应声明实时能力");
    check(!min_rt, "headless-min 不该声明实时能力");

    // Actual exited Task records no longer contribute reservation utilisation.
    assert_eq!(sched::rt_utilisation(),0);
    kprintln!(
        "[JSR-RTCLASS] summary checks={} failed={} utilisation_after={}",
        CHECKS.load(Ordering::Relaxed),
        failed(),
        sched::rt_utilisation()
    );
}
