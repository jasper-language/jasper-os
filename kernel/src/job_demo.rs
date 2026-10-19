//! POL-3 演练：作业队列的生命周期、依赖、优先级、取消，以及批处理负载下的交互性。
//! POL-3 drill: job lifecycle, dependencies, priority, cancellation and interactive
//! responsiveness under batch load.
//!
//! # 覆盖
//! 1. 依赖未完成的作业不会被选中；依赖完成后才变为可运行；
//! 2. 同一时刻按优先级选择，同级按提交顺序；
//! 3. 作业以真实任务运行，结束时记录退出码（成功 / 失败分别落到不同终态）；
//! 4. 取消等待中与运行中的作业，任务退出后活动任务数回到 0；
//! 5. 批处理档任务吃满处理器时，交互档任务仍能在窗口内完成全部唤醒轮次；
//! 6. 作业服务只属于声明了批处理能力的 Profile（精简档没有 `system.job`）。

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::job::JobPriority;
use kernel_core::sched::Qos;
use kernel_core::smp::CpuSet;

use crate::sched;
use crate::task::TaskId;
use crate::{arch, job, kprintln, profile, smp};

const TASK_BASE: u64 = 9300;
const ROUNDS: u32 = 20;
const WINDOW: u64 = 120;

static CHECKS: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);
static STARTED: AtomicU32 = AtomicU32::new(0);
static ALIVE: AtomicU32 = AtomicU32::new(0);
static DONE: AtomicU32 = AtomicU32::new(0);
// 32 位目标没有 AtomicU64：窗口只有 120 tick，用 32 位足够。
static HOG_END: AtomicU32 = AtomicU32::new(0);
static HOG_CPUS: AtomicU32 = AtomicU32::new(0);

fn check(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-JOB-FAIL] {}", what);
    }
}

/// 本演练的失败断言数。
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

/// 作业任务：以最低档（Background，只用空闲容量）运行，退出时登记。
/// 专用「批处理调度类」的长时间片与最低份额由 POL-5 的仲裁器接入，本阶段先复用最低档。
fn job_body() {
    let _ = sched::set_current_qos(Qos::Background);
    ALIVE.fetch_add(1, Ordering::Relaxed);
    STARTED.fetch_add(1, Ordering::Relaxed);
    // 让出一次处理器：证明它是被调度器真正运行过的任务，而不是只在队列里登记。
    sched::pause();
    ALIVE.fetch_sub(1, Ordering::Relaxed);
}

/// 吃满处理器的批处理任务。
fn batch_hog() {
    let _ = sched::set_current_qos(Qos::Background);
    while sched::timer_ticks() < HOG_END.load(Ordering::Relaxed) as u64 {
        HOG_CPUS.fetch_or(1 << arch::cpu_index(), Ordering::Relaxed);
        core::hint::spin_loop();
    }
}

/// 交互档：每 tick 醒一次，共 [`ROUNDS`] 轮。
fn interactive() {
    let _ = sched::set_current_qos(Qos::Interactive);
    for _ in 0..ROUNDS {
        sched::sleep_until(sched::timer_ticks() + 1);
        DONE.fetch_add(1, Ordering::Relaxed);
    }
}

/// 在关闭抢占的情况下创建任务，避免引导线程被自己刚创建的任务抢走。
fn quiet<R>(f: impl FnOnce() -> R) -> R {
    let prev = sched::set_preemption(false);
    let r = f();
    sched::set_preemption(prev);
    r
}

/// 演练入口。
pub fn run() {
    job::reset();
    STARTED.store(0, Ordering::Relaxed);
    ALIVE.store(0, Ordering::Relaxed);

    // 1) 提交三个作业：2、3 依赖 1；2 为高优先级。
    check(job::submit(1, JobPriority::Normal, &[]).is_ok(), "提交 1 号作业");
    check(job::submit(2, JobPriority::High, &[1]).is_ok(), "提交 2 号作业");
    check(job::submit(3, JobPriority::Low, &[1]).is_ok(), "提交 3 号作业");
    check(job::pick() == Some(1), "依赖未完成时只能选中 1 号");
    check(job::get(2).is_some_and(|j| j.state == kernel_core::job::JobState::Submitted), "2 号应等待依赖");

    // 2) 真实运行 1 号作业，然后按优先级选 2 号。
    check(job::start(1).is_ok(), "启动 1 号");
    quiet(|| sched::spawn(TaskId(TASK_BASE), "job-1", job_body)).expect("创建 1 号任务");
    sched::run();
    check(job::finish(1, 0).is_ok(), "结束 1 号");
    check(job::pick() == Some(2), "依赖完成后应优先选高优先级的 2 号");

    // 3) 2 号以失败退出，3 号仍可运行。
    check(job::start(2).is_ok(), "启动 2 号");
    quiet(|| sched::spawn(TaskId(TASK_BASE + 1), "job-2", job_body)).expect("创建 2 号任务");
    sched::run();
    check(job::finish(2, 3).is_ok(), "结束 2 号");
    check(job::pick() == Some(3), "3 号应变为可运行");
    check(job::start(3).is_ok(), "启动 3 号");
    quiet(|| sched::spawn(TaskId(TASK_BASE + 2), "job-3", job_body)).expect("创建 3 号任务");
    sched::run();
    check(job::finish(3, 0).is_ok(), "结束 3 号");

    // 4) 取消：等待中与运行中都要生效，且不留下活动任务。
    check(job::submit(4, JobPriority::Normal, &[]).is_ok(), "提交 4 号");
    check(job::cancel(4).is_ok(), "取消等待中的 4 号");
    check(
        job::get(4).is_some_and(|j| j.state == kernel_core::job::JobState::Cancelled),
        "4 号应为已取消",
    );
    check(job::submit(5, JobPriority::High, &[]).is_ok(), "提交 5 号");
    check(job::start(5).is_ok(), "启动 5 号");
    check(job::cancel(5).is_ok(), "取消运行中的 5 号");
    check(job::start(5).is_err(), "已取消的作业不能再启动");
    let st = job::stats();
    check(st.completed == 2 && st.failed == 1 && st.cancelled == 2, "统计应反映终态分布");
    check(ALIVE.load(Ordering::Relaxed) == 0, "作业任务退出后活动任务数应为 0");

    // 5) 批处理满载下的交互性：4 个批处理档任务吃满处理器，交互档仍完成全部唤醒。
    DONE.store(0, Ordering::Relaxed);
    HOG_CPUS.store(0, Ordering::Relaxed);
    HOG_END.store((sched::timer_ticks() + WINDOW) as u32, Ordering::Relaxed);
    quiet(|| {
        let all = CpuSet::first(smp::cpu_count());
        for i in 0..4u64 {
            let _ = sched::spawn_on(TaskId(TASK_BASE + 10 + i), "job-hog", batch_hog, None, all);
        }
        sched::spawn(TaskId(TASK_BASE + 9), "job-ui", interactive).is_ok()
    });
    sched::run();
    let done = DONE.load(Ordering::Relaxed);
    let cpus = HOG_CPUS.load(Ordering::Relaxed).count_ones();
    kprintln!("[JSR-JOB] overload done={} rounds={} hog_cpus={}", done, ROUNDS, cpus);
    check(done == ROUNDS, "批处理满载时交互任务未完成全部唤醒");
    // 本演练在第二处理器启动前运行，因此只要求「确实跑过」；跨核分布由 SMP-2 判据覆盖。
    check(cpus >= 1, "批处理任务应真的运行过");

    // 6) 作业服务只属于声明了批处理能力的 Profile。
    let full = profile::resolved();
    let min = kernel_core::profile::resolve(&kernel_core::profile::HEADLESS_MIN).ok();
    let allowed_full = full.is_some_and(|r| r.allows_op("system.job.submit"));
    let allowed_min = min.is_some_and(|r| r.allows_op("system.job.submit"));
    kprintln!(
        "[JSR-JOB] profile headless={} headless-min={}",
        allowed_full,
        allowed_min
    );
    check(allowed_full, "headless 应暴露作业服务");
    check(!allowed_min, "headless-min 不该暴露作业服务");

    kprintln!(
        "[JSR-JOB] summary jobs={} completed={} failed={} cancelled={} checks={} failed_checks={}",
        st.total,
        st.completed,
        st.failed,
        st.cancelled,
        CHECKS.load(Ordering::Relaxed),
        failed()
    );
}
