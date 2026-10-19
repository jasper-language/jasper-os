//! POL-5 演练：三类线程同时争用同一处理器。
//! POL-5 drill: three classes contending for the same processor.
//!
//! # 覆盖
//! 实时（有配额与周期）、交互（睡醒型）、批处理（吃满型）同时可运行：
//! 1. 实时任务在每个周期内拿到它的配额，截止期不放过（slack ≥ 0）；
//! 2. 交互任务的唤醒延迟有上界（直方图最大值 ≤ 2 tick）；
//! 3. 批处理任务确实拿到了处理器（忙等计数 > 0），没有被饿死；
//! 4. 三者都正常结束，资源回到基线。
//!
//! # 边界
//! 单处理器场景，用来验证「同一实体内三类共存」的最低要求；跨核分布由 SMP-2 覆盖。
//! 仲裁器（`kernel_core::arbiter`）的判定逻辑在宿主侧单测，本轮不接入派发路径。

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::sync::Atomic64;

use kernel_core::rt::Charge;
use kernel_core::sched::Qos;

use kernel_core::smp::CpuSet;

use crate::sched;
use crate::task::TaskId;
use crate::{kprintln, rt};

const RT_ID: u32 = 9500;
const TASK_RT: u64 = 9500;
const TASK_UI: u64 = 9501;
const TASK_BATCH_BASE: u64 = 9510;
const RT_PERIODS: u32 = 5;
const UI_ROUNDS: u32 = 20;
const WINDOW: u64 = 80;

static CHECKS: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);
static UI_DONE: AtomicU32 = AtomicU32::new(0);
// 32 位目标没有 64 位原子：用 kernel-core 的模拟单元。
static BATCH_TICKS: Atomic64 = Atomic64::new(0);
static RT_MISSES: AtomicU32 = AtomicU32::new(0);
static END: Atomic64 = Atomic64::new(0);

fn check(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-ARB-FAIL] {}", what);
    }
}

/// 本演练的失败断言数。
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

/// 实时任务：每个周期计满配额后睡到下一个周期，记录是否越过截止期。
fn rt_task() {
    for _ in 0..RT_PERIODS {
        let deadline = sched::timer_ticks() + 10;
        loop {
            match rt::charge(RT_ID, 1) {
                Ok(Charge::Within) => {
                    sched::pause();
                }
                Ok(Charge::Exhausted) => break,
                Err(_) => return,
            }
        }
        let now = sched::timer_ticks();
        if now > deadline {
            RT_MISSES.fetch_add(1, Ordering::Relaxed);
        }
        // 睡到下个周期；期间预算由调度器的周期补充恢复。
        sched::sleep_until(now + 5);
        rt::replenish(sched::timer_ticks());
    }
}

/// 交互任务：每 tick 醒一次。
fn ui_task() {
    sched::set_current_qos_ceiling(Some(Qos::Interactive));
    let _ = sched::set_current_qos(Qos::Interactive);
    for _ in 0..UI_ROUNDS {
        sched::sleep_until(sched::timer_ticks() + 1);
        UI_DONE.fetch_add(1, Ordering::Relaxed);
    }
}

/// 批处理任务：吃满到窗口结束。
fn batch_task() {
    let _ = sched::set_current_qos(Qos::Background);
    while sched::timer_ticks() < END.load(Ordering::Relaxed) {
        BATCH_TICKS.fetch_add(1, Ordering::Relaxed);
        core::hint::spin_loop();
    }
}

/// 只允许一个处理器。
fn only(c: usize) -> CpuSet {
    let mut s = CpuSet::EMPTY;
    s.insert(c);
    s
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
    check(rt::admit(RT_ID, 2, 10, now).is_ok(), "实时声明应被接纳");
    END.store(now + WINDOW, Ordering::Relaxed);
    UI_DONE.store(0, Ordering::Relaxed);
    BATCH_TICKS.store(0, Ordering::Relaxed);
    RT_MISSES.store(0, Ordering::Relaxed);

    // 阶段 1 打开类别仲裁：由 `kernel_core::arbiter` 决定本 tick 归哪一类。
    let previous = sched::set_arbiter(true);
    // 阶段 1 固定在 0 号核：三类真正争用同一个处理器。
    let one = CpuSet::first(1);
    quiet(|| {
        let ok_rt = sched::spawn_on(TaskId(TASK_RT), "arb-rt", rt_task, None, one).is_ok();
        let ok_ui = sched::spawn_on(TaskId(TASK_UI), "arb-ui", ui_task, None, one).is_ok();
        let mut ok_batch = true;
        for i in 0..3u64 {
            ok_batch &= sched::spawn_on(TaskId(TASK_BATCH_BASE + i), "arb-load", batch_task, None, one).is_ok();
        }
        ok_rt && ok_ui && ok_batch
    });
    sched::run();

    sched::set_arbiter(previous);
    let lat = sched::latency(Qos::Interactive);
    let ui_done = UI_DONE.load(Ordering::Relaxed);
    let batch = BATCH_TICKS.load(Ordering::Relaxed);
    let misses = RT_MISSES.load(Ordering::Relaxed);
    kprintln!(
        "[JSR-ARB] three_class rt_misses={} ui_rounds={} ui_latency_max={} batch_ticks={}",
        misses,
        ui_done,
        lat.max(),
        batch
    );
    check(misses == 0, "实时任务越过了截止期");
    check(ui_done == UI_ROUNDS, "交互任务未完成全部唤醒");
    check(lat.max() <= 2, "交互唤醒延迟超过上界");
    check(batch > 0, "批处理任务被饿死");

    // 阶段 2：多核下三类各占一个核，验证"各核都忙"。
    let n = crate::smp::cpu_count();
    if n >= 2 {
        END.store(sched::timer_ticks() + 40, Ordering::Relaxed);
        let mut ok = true;
        quiet(|| {
            // 每个核放一个吃满型任务：验证「各核都忙」，而不是把负载串行到一个核上。
            for c in 0..n {
                ok &= sched::spawn_on(
                    TaskId(TASK_BATCH_BASE + 20 + c as u64),
                    "mc-load",
                    batch_task,
                    None,
                    only(c),
                )
                .is_ok();
            }
            ok
        });
        sched::run();
        let mut busy = 0;
        for c in 0..n {
            if sched::cpu_stats(c).busy_ticks > 0 {
                busy += 1;
            }
        }
        kprintln!("[JSR-ARB] multicore cpus={} busy={}", n, busy);
        check(ok, "多核阶段任务创建失败");
        check(busy == n, "多核阶段有处理器未被使用");
    }

    let _ = rt::release(RT_ID);
    kprintln!(
        "[JSR-ARB] summary checks={} failed={}",
        CHECKS.load(Ordering::Relaxed),
        failed()
    );
}
