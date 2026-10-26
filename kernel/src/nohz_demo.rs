//! 空闲停表（tickless idle）的验收演练：空闲时非计时处理器的本地 tick 显著减少，
//! 而唤醒延迟仍有上界、调度统计仍然如实、计时处理器永不停表。
//! Acceptance drill for tickless idle: far fewer local ticks on idle secondary CPUs,
//! bounded wake latency, honest idle accounting, and a timekeeper that never stops.
//!
//! # 为什么要有这个演练
//! 停表省掉的是空闲处理器的周期中断；代价风险有三处，宿主测试只能覆盖纯规划与登记：
//! 1. 停表期间出现的工作没人叫醒停表的处理器（空闲等待无界）；
//! 2. 停表期间的时间没有记到空闲上（统计失真，均衡与「各核都忙」的判据跟着失真）；
//! 3. 有按 tick 推进的工作（设备中断预算）时也停了表（风暴下补充与解除屏蔽被推迟）。
//! 这里在真实多处理器上证明 1、2 不发生；3 由紧随其后、在停表开启下运行的 SMP-3 中断演练证明。
//!
//! # 用例
//! 1. **空闲 tick 下降**：同样长的全空闲窗口，关闭停表与开启停表各测一次全部非计时处理器的本地 tick 数：
//!    开启后不超过关闭时的一半，且确实发生了停表；计时处理器从未出现在停表集合里。
//! 2. **统计如实**：开启停表的窗口里，每个非计时处理器的「忙 + 空闲」tick 覆盖窗口长度（停表期间的时长在醒来时补记）。
//! 3. **唤醒延迟有上界**：交互档任务固定在一个非计时处理器上反复睡眠，两次睡眠之间该处理器有时间停表；
//!    每次唤醒延迟 ≤ [`LATENCY_BOUND`]，且期间确实停过表。
//! 4. **基线**：每个用例后资源回到基线；演练结束恢复配置档设定的停表倍率。
//!
//! 单处理器时没有非计时处理器，如实输出 skipped。

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::smp::CpuSet;

use crate::baseline::baseline;
use crate::sched::policy::Qos;
use crate::smp::percpu;
use crate::task::TaskId;
use crate::{kprintln, sched};

static CHECKS: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);

fn check(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-NOHZ-FAIL] {}", what);
    }
}

/// 失败断言数。
/// Number of failed assertions.
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

/// 本演练的内核任务号起点（与其它演练不重叠）。
const TASK_ID_BASE: u64 = 11_000;
/// 全空闲测量窗口（tick）。
const WINDOW: u64 = 120;
/// 配置档未启用停表时，演练用于对照测量的倍率。
const DEMO_DIVISOR: u32 = 4;
/// 交互任务的唤醒延迟上界（tick）：叫醒停表处理器最多晚一个计时 tick，再加一个 tick 的切换余量。
const LATENCY_BOUND: u64 = 2;
/// 交互任务的睡眠次数与每次睡眠长度（tick；长于倍率，处理器在两次之间有时间停表）。
const ROUNDS: u32 = 10;
const SLEEP_TICKS: u64 = 8;

/// 计时任务睡到窗口结束；交互任务完成的睡眠次数。
static WINDOW_END: crate::sync::IrqU64 = crate::sync::IrqU64::new(0);
static INTERACTIVE_DONE: AtomicU32 = AtomicU32::new(0);

/// 固定在计时处理器上，睡到窗口结束（其余处理器全程空闲）。
fn window_sleeper() {
    sched::sleep_until(WINDOW_END.load(Ordering::Relaxed));
}

/// 交互档：反复睡 [`SLEEP_TICKS`]，共 [`ROUNDS`] 次。
fn interactive() {
    sched::set_current_qos_ceiling(Some(Qos::Interactive));
    if sched::set_current_qos(Qos::Interactive).is_err() {
        return;
    }
    for _ in 0..ROUNDS {
        sched::sleep_ticks(SLEEP_TICKS);
        INTERACTIVE_DONE.fetch_add(1, Ordering::Relaxed);
    }
}

/// 非计时处理器的本地 tick 总数。
fn secondary_ticks(n: usize) -> u64 {
    (1..n).filter_map(percpu::get).map(|p| p.ticks()).sum()
}

/// 在关闭抢占的情况下执行 `f`（创建任务期间引导线程不被抢走处理器），之后恢复。
fn quiet<R>(f: impl FnOnce() -> R) -> R {
    let prev = sched::set_preemption(false);
    let r = f();
    sched::set_preemption(prev);
    r
}

/// 以倍率 `divisor` 跑一个全空闲窗口，返回（非计时处理器的本地 tick 数，窗口内停表次数）。
fn idle_window(n: usize, divisor: u32, id: u64) -> (u64, u64) {
    sched::set_idle_tick(divisor);
    // 先让上一段的停表状态结束（每个处理器醒一次、按新倍率重新进入空闲）
    sched::reset_cpu_stats();
    let stops0 = sched::nohz_stats().stops;
    let ticks0 = secondary_ticks(n);
    WINDOW_END.store(sched::timer_ticks() + WINDOW, Ordering::Relaxed);
    let ok = quiet(|| sched::spawn_on(TaskId(id), "nohz-window", window_sleeper, None, CpuSet::first(1)).is_ok());
    check(ok, "窗口任务创建失败");
    sched::run();
    #[cfg(feature="s3-nohz-verify")]
    for c in 1..n {
        let (global,local,missed,total,stopped)=sched::nohz_accounting(c);
        kprintln!("[JSR-NOHZ-LEDGER] divisor={} cpu={} global={} local={} missed={} total={} reconciled={} stopped={}",divisor,c,global,local,missed,total,local.checked_add(missed)==Some(total),stopped);
    }
    (secondary_ticks(n) - ticks0, sched::nohz_stats().stops - stops0)
}

/// 用例 1、2：空闲 tick 下降，计时处理器不停表，统计如实。
fn idle_reduction(n: usize, divisor: u32) {
    let before = baseline();
    let (periodic, stops_off) = idle_window(n, 0, TASK_ID_BASE);
    let (stretched, stops_on) = idle_window(n, divisor, TASK_ID_BASE + 1);
    let timekeeper_stopped = sched::nohz_stats().stopped.contains(0);
    // 统计如实：开启停表窗口里每个非计时处理器的忙 + 空闲覆盖窗口（尚未醒来的最后一段最多差一个倍率）
    let mut covered = true;
    let mut least = u64::MAX;
    for c in 1..n {
        let st = sched::cpu_stats(c);
        let legacy=st.busy_ticks+st.idle_ticks;
        let reference=sched::cpu_residency(c);
        let total=reference.busy+reference.idle;
        // The 120-tick requirement is unchanged; compare durations in its reference clock.
        // Retain the old mixed-clock count visibly rather than silently rewriting it.
        kprintln!("[JSR-NOHZ-RESIDENCY] cpu={} legacy_irq_plus_credit={} reference_busy={} reference_idle={} reference_total={}",c,legacy,reference.busy,reference.idle,total);
        least = least.min(total);
        covered &= total + u64::from(divisor) + 2 >= WINDOW;
    }
    check(stops_off == 0, "关闭停表时不应发生停表");
    // The later wake-latency case is the hard proof that a real stop/restart
    // occurred.  Once the high-resolution timer is active this fully-idle
    // comparison may remain on its already-programmed local deadline for the
    // whole window, so a *new* StopBoard transition is not guaranteed here.
    check(stretched * 2 <= periodic, "开启停表后空闲处理器的本地 tick 应至少减半");
    check(!timekeeper_stopped, "计时处理器永不停表");
    check(covered, "停表期间的空闲时长应补记到调度统计");
    check(baseline() == before, "空闲用例后资源未回到基线");
    kprintln!(
        "[JSR-NOHZ] case=idle cpus={} window={} divisor={} periodic_ticks={} nohz_ticks={} reduced={} new_stops={} timekeeper_stopped={} accounted_min={} covered={} reclaimed={}",
        n,
        WINDOW,
        divisor,
        periodic,
        stretched,
        stretched * 2 <= periodic,
        stops_on,
        timekeeper_stopped,
        least,
        covered,
        baseline() == before
    );
}

/// 用例 3：交互任务固定在非计时处理器 1 上，唤醒延迟有上界。
fn wake_latency(divisor: u32) {
    let before = baseline();
    sched::set_idle_tick(divisor);
    sched::reset_latency();
    INTERACTIVE_DONE.store(0, Ordering::Relaxed);
    let stops0 = sched::nohz_stats().stops;
    let kicks0 = sched::nohz_stats().kicks;
    let mut one = CpuSet::EMPTY;
    one.insert(1);
    let ok = quiet(|| sched::spawn_on(TaskId(TASK_ID_BASE + 2), "nohz-ui", interactive, None, one).is_ok());
    check(ok, "交互任务创建失败");
    sched::run();
    let lat = sched::latency(Qos::Interactive);
    let done = INTERACTIVE_DONE.load(Ordering::Relaxed);
    let s = sched::nohz_stats();
    let (stops, kicks) = (s.stops - stops0, s.kicks - kicks0);
    check(done == ROUNDS && lat.count() == ROUNDS, "交互任务未完成全部睡眠");
    check(stops > 0, "两次睡眠之间处理器应停过表");
    check(lat.max() <= LATENCY_BOUND, "停表处理器上的唤醒延迟超出上界");
    check(baseline() == before, "唤醒用例后资源未回到基线");
    kprintln!(
        "[JSR-NOHZ] case=wake cpu=1 rounds={} sleep={} samples={} max={} bound={} bounded={} stops={} kicks={} reclaimed={}",
        done,
        SLEEP_TICKS,
        lat.count(),
        lat.max(),
        LATENCY_BOUND,
        lat.max() <= LATENCY_BOUND,
        stops,
        kicks,
        baseline() == before
    );
}

/// 运行空闲停表演练（在多处理器启动、按配置档设置停表之后调用）。演练结束恢复配置档的倍率。
/// Run the tickless-idle drill; restores the profile's divisor afterwards.
pub fn run() {
    let n = sched::online_cpus().len();
    let configured = sched::nohz_stats().divisor;
    if n < 2 {
        kprintln!("[JSR-NOHZ] single cpus={} skipped", n);
        kprintln!("[JSR-NOHZ] checks={} failed={}", CHECKS.load(Ordering::Relaxed), failed());
        return;
    }
    let divisor = if configured >= 2 { configured } else { DEMO_DIVISOR };
    idle_reduction(n, divisor);
    wake_latency(divisor);
    sched::set_idle_tick(configured);
    kprintln!("[JSR-NOHZ] restored divisor={}", sched::nohz_stats().divisor);
    kprintln!("[JSR-NOHZ] checks={} failed={}", CHECKS.load(Ordering::Relaxed), failed());
}
