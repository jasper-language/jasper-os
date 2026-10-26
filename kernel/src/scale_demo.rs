//! 调度规模化的验收演练：大量睡眠任务存在时，选择路径只遍历本处理器的运行列表；
//! 每 tick 的到期唤醒扫描只在最早到期时刻到达时发生；测量调度器锁与对象表锁的争用；
//! 并在同样的规模下复核两条响应性底线（过载时交互延迟有上界、压力撤销后立即恢复；各核都忙）。
//! Acceptance drill for scheduler scaling: run-list-only selection, deadline-cached wake scans,
//! lock contention measurement, plus the responsiveness floor under the same scale.
//!
//! # 为什么要有这个演练
//! 选择路径若按任务表容量线性扫描，任务数一多每次切换的代价就随容量增长，且这段代价全在调度器锁内，
//! 会放大锁争用。宿主测试已证明运行列表本身正确；这里证明接上之后，在真实多处理器上：
//! 睡眠任务不进入选择遍历、遍历量与可运行任务数相当、到期唤醒扫描不再每 tick 发生，且行为与之前一致。
//!
//! # 用例
//! 1. **拒绝路径**：空亲和集合的创建被拒，运行列表与运行队列仍一致，资源不变。
//! 2. **规模**：`S` 个睡到窗口之后的任务 + `2N` 个吃满处理器的任务：单次选择遍历量 ≤ `2N + 1`
//!    （远小于睡眠任务数与槽位数），窗口内到期唤醒扫描 ≤ 1 次，各核都忙、空闲等待有界。
//! 3. **过载 + 交互**：同样规模下再加 1 个交互档任务：唤醒延迟 ≤ [`LATENCY_BOUND`]，各核都忙。
//! 4. **恢复**：压力撤销后交互任务的唤醒延迟都是 0。
//! 5. **锁争用测量**：`N` 个任务在各核上反复让出并读对象表统计：记录调度器锁与对象表锁的
//!    加锁次数、遇到占用次数、自旋次数与单次最多自旋次数（测量项，只断言计数自洽）。
//!
//! 每个用例结束后检查资源回到用例前的基线、运行列表与运行队列一致。

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::smp::CpuSet;

use crate::baseline::baseline;
use crate::sched::policy::Qos;
use crate::sched::scheduler::SpawnError;
use crate::sync::{IrqU64, LockStats};
use crate::task::TaskId;
use crate::{kobj, kprintln, sched};

static CHECKS: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);
/// 计时类断言超界的次数：只记录，不计入功能失败（仿真器下计时不可信）。
static TIMING_FAILED: AtomicU32 = AtomicU32::new(0);

fn check(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-SCALE-FAIL] {}", what);
    }
}

/// 计时类断言：超界只累加 [`TIMING_FAILED`] 并单独打印，不改变功能失败数。
/// Timing-class assertion: an over-limit result is recorded separately and does not fail the drill.
fn check_timing(ok: bool, what: core::fmt::Arguments<'_>) {
    if !ok {
        TIMING_FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-SCALE-TIMING] {}", what);
    }
}

/// 失败断言数。
/// Number of failed assertions.
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

/// 计时类断言超界数（功能断言之外的参考结论）。
/// Number of timing-class assertions that exceeded their limit.
pub fn timing_failed() -> u32 {
    TIMING_FAILED.load(Ordering::Relaxed)
}

/// 本演练的内核任务号起点（与其它演练不重叠）。
const TASK_ID_BASE: u64 = 10_000;
/// 规模用例的目标任务总数（睡眠任务 + 吃满处理器的任务 + 交互任务；受启动容量限制）。
const TARGET_TASKS: usize = 64;
/// 吃满处理器的窗口（tick）。
const WINDOW: u64 = 60;
/// 每个核在窗口内至少忙碌的千分比。
const BUSY_PERMILLE: u64 = 850;
/// 「本核空闲而别处有可运行任务在等」的连续时长上界（tick）。
const IDLE_BOUND: u32 = 2;
/// 过载时交互档任务的唤醒延迟上界（tick）。
const LATENCY_BOUND: u64 = 2;
/// 交互任务的睡眠次数。
const ROUNDS: u32 = 20;
/// 锁争用测量中每个任务的让出次数。
const CHURN_ROUNDS: u32 = 2000;

/// 吃满处理器的任务的截止时刻。
static HOG_END: IrqU64 = IrqU64::new(0);
/// 睡眠任务的唤醒时刻。
static SLEEP_END: IrqU64 = IrqU64::new(0);
/// 已进入睡眠的睡眠任务数。
static ASLEEP: AtomicU32 = AtomicU32::new(0);
/// 已从睡眠中醒来的睡眠任务数（用于在测量窗口结束时判断前提是否仍成立）。
static AWAKE: AtomicU32 = AtomicU32::new(0);
/// 交互任务完成的睡眠次数。
static INTERACTIVE_DONE: AtomicU32 = AtomicU32::new(0);

#[cfg(feature = "krn3-p999-verify")]
static P999_DONE: AtomicU32 = AtomicU32::new(0);
#[cfg(feature = "krn3-p999-verify")]
const P999_ROUNDS: u32 = 160;
#[cfg(feature = "krn3-p999-verify")]
const P999_ISOLATED_ROUNDS: u32 = 1_200;

#[cfg(feature = "krn3-p999-verify")]
fn p999_sleeper() {
    for _ in 0..P999_ROUNDS {
        sched::sleep_ticks(1);
    }
    P999_DONE.fetch_add(1, Ordering::Release);
}

#[cfg(feature = "krn3-p999-verify")]
fn p999_isolated_sleeper() {
    for _ in 0..P999_ISOLATED_ROUNDS {
        sched::sleep_ticks(1);
    }
    P999_DONE.fetch_add(1, Ordering::Release);
}

/// Complete wake/resume sampling contract. Seven AP-affine workers each wake
/// 160 times, yielding 1,120 observations on an eight-CPU guest. The test
/// validates identity, completeness and resource recovery; latency thresholds
/// remain a reported performance result rather than a correctness gate.
#[cfg(feature = "krn3-p999-verify")]
pub fn run_wake_latency_contract() -> u32 {
    FAILED.store(0, Ordering::Relaxed);
    TIMING_FAILED.store(0, Ordering::Relaxed);
    P999_DONE.store(0, Ordering::Relaxed);
    let saved = baseline();
    let cpus = sched::online_cpus().len();
    check(cpus >= 8, "p99.9契约需要八个在线CPU");

    // First establish the local, non-fanout baseline on CPU1.
    sched::reset_raw_wakes();
    let mut cpu1 = CpuSet::EMPTY;
    cpu1.insert(1);
    let isolated_spawned = quiet(|| sched::spawn_on(
        TaskId(0x5039393949534f),
        "p999-isolated",
        p999_isolated_sleeper,
        None,
        cpu1,
    ).is_ok());
    check(isolated_spawned, "必须创建CPU1隔离唤醒任务");
    if isolated_spawned { sched::run(); }
    let (isolated_raw, isolated, isolated_errors, isolated_carried, isolated_pending) =
        sched::raw_wake_snapshot();
    let isolated_complete = isolated.count == u64::from(P999_ISOLATED_ROUNDS)
        && isolated.invalid == 0 && isolated_errors == [0; 3]
        && isolated_carried == 0 && isolated_pending == 0;
    check(isolated_complete, "隔离唤醒延迟样本必须完整");
    check(P999_DONE.load(Ordering::Acquire) == 1, "隔离唤醒任务必须完成");
    check(baseline() == saved, "隔离p99.9演练资源必须回到基线");
    kprintln!("[JSR-WAKE-LATENCY] mode=isolated samples={} expected={} invalid={} p50_us={} p99_us={} p999_us={} max_ns={} complete={} raw_retained={} raw_dropped={} endpoint=resume-hook clock=shared-ns-serialized platform_sync=assumed",
        isolated.count, P999_ISOLATED_ROUNDS, isolated.invalid, isolated.p50_us,
        isolated.p99_us, isolated.p999_us, isolated.max_ns, isolated_complete,
        isolated_raw.entries().len(), isolated_raw.dropped());

    // Then measure a seven-way same-tick fanout separately.
    P999_DONE.store(0, Ordering::Relaxed);
    sched::reset_raw_wakes();
    let workers = cpus.saturating_sub(1).min(7);
    let spawned = quiet(|| {
        (0..workers).all(|i| {
            let mut affinity = CpuSet::EMPTY;
            affinity.insert(i + 1);
            sched::spawn_on(
                TaskId(0x503939390000 + i as u64),
                "p999-sleeper",
                p999_sleeper,
                None,
                affinity,
            ).is_ok()
        })
    });
    check(spawned && workers == 7, "必须创建七个AP固定唤醒工作任务");
    if spawned { sched::run(); }
    let (raw, latency, errors, carried, pending) = sched::raw_wake_snapshot();
    let expected = workers as u64 * u64::from(P999_ROUNDS);
    let complete = latency.count == expected && latency.invalid == 0
        && errors == [0; 3] && carried == 0 && pending == 0;
    check(complete, "唤醒延迟样本必须完整且身份/时钟有效");
    check(P999_DONE.load(Ordering::Acquire) as usize == workers,
        "全部唤醒工作任务必须完成");
    check(baseline() == saved, "p99.9演练资源必须回到基线");
    check(lists_consistent(), "p99.9演练后运行列表必须一致");
    kprintln!("[JSR-WAKE-LATENCY] mode=fanout-7 samples={} expected={} invalid={} p50_us={} p99_us={} p999_us={} max_ns={} complete={} raw_retained={} raw_dropped={} endpoint=resume-hook clock=shared-ns-serialized platform_sync=assumed",
        latency.count, expected, latency.invalid, latency.p50_us, latency.p99_us,
        latency.p999_us, latency.max_ns, complete, raw.entries().len(), raw.dropped());
    kprintln!("[JSR-KRN3-P999] done failed={} workers={} rounds={} resources={} lists={}",
        failed(), workers, P999_ROUNDS, baseline() == saved, lists_consistent());
    failed()
}

/// 睡到 [`SLEEP_END`]（期间不可运行，不应出现在任何选择遍历里）。
fn sleeper() {
    ASLEEP.fetch_add(1, Ordering::Relaxed);
    sched::sleep_until(SLEEP_END.load(Ordering::Relaxed));
    AWAKE.fetch_add(1, Ordering::Relaxed);
}

/// 工具档、吃满处理器直到 [`HOG_END`]。
fn hog() {
    let _ = sched::set_current_qos(Qos::Utility);
    while sched::timer_ticks() < HOG_END.load(Ordering::Relaxed) {
        core::hint::spin_loop();
    }
}

/// 交互档：反复睡 1 tick，共 [`ROUNDS`] 次。
fn interactive() {
    sched::set_current_qos_ceiling(Some(Qos::Interactive));
    if sched::set_current_qos(Qos::Interactive).is_err() {
        return;
    }
    for _ in 0..ROUNDS {
        sched::sleep_ticks(1);
        INTERACTIVE_DONE.fetch_add(1, Ordering::Relaxed);
    }
}

/// 锁争用测量：反复让出（取调度器锁）并读对象表统计（取对象表锁）。
// Author: chatgpt. Publish AP tasks before CPU0; all participants reset the
// measurement once via the last-arrival leader, then perform the SAME workload.
static CHURN_TARGET: AtomicU32 = AtomicU32::new(0);
static CHURN_READY: AtomicU32 = AtomicU32::new(0);
static CHURN_GO: AtomicU32 = AtomicU32::new(0);
static CHURN_DONE: AtomicU32 = AtomicU32::new(0);
static CHURN_MASK: AtomicU32 = AtomicU32::new(0);
fn churn() {
    let target = CHURN_TARGET.load(Ordering::Acquire);
    CHURN_MASK.fetch_or(1u32 << crate::arch::cpu_index(), Ordering::AcqRel);
    if CHURN_READY.fetch_add(1, Ordering::AcqRel) + 1 == target {
        sched::reset_lock_stats();
        kobj::reset_lock_stats();
        CHURN_GO.store(1, Ordering::Release);
    }
    while CHURN_GO.load(Ordering::Acquire) == 0 { core::hint::spin_loop(); }
    if CHURN_GO.load(Ordering::Acquire) != 1 { return; }
    for _ in 0..CHURN_ROUNDS {
        sched::yield_now();
        let _ = kobj::stats();
    }
    CHURN_DONE.fetch_add(1, Ordering::Release);
}

// Author: chatgpt. Observe actual registered heap ownership before migration.
static TIMED_CPU: AtomicU32 = AtomicU32::new(0);
fn timed_remote_worker() {
    sched::sleep_ticks(30);
    TIMED_CPU.store(crate::arch::cpu_index() as u32 + 1, Ordering::Release);
}
fn deadline_owner_contract(n: usize) {
    if n < 2 { return; }
    let id = TaskId(0x444541444f574e);
    let saved = baseline();
    TIMED_CPU.store(0, Ordering::Relaxed);
    let old_idle = sched::set_idle_tick(64);
    let mut first = CpuSet::EMPTY; first.insert(1);
    let target = if n > 2 { 2 } else { 1 };
    let mut dest = CpuSet::EMPTY; dest.insert(target);
    let spawned = quiet(|| sched::spawn_on(id, "deadline-owner", timed_remote_worker, None, first).is_ok());
    let limit = sched::timer_ticks() + 100;
    while sched::deadline_owners(id).and_then(|(w,_)|w).is_none() && sched::timer_ticks() < limit { sched::sleep_ticks(1); }
    let registered = sched::deadline_owners(id).is_some_and(|(w,_)|w == Some(1));
    let moved = sched::set_affinity(id, dest).is_ok() && sched::deadline_owners(id).is_some_and(|(w,_)|w == Some(target));
    #[cfg(feature = "fault-inject")]
    sched::fault_delay_deadline_timer(target, true);
    let before = sched::deadline_stats().0[target];
    sched::run();
    let consumed = sched::deadline_stats().0[target].wrapping_sub(before) > 0;
    let ran = TIMED_CPU.load(Ordering::Acquire) == target as u32 + 1;
    #[cfg(feature = "fault-inject")]
    {
        let trace = sched::fault_deadline_trace(target).unwrap();
        let ipi = trace.ipis_after.wrapping_sub(trace.ipis_before);
        let linked = trace.stopped && trace.consumed && trace.consumer == target
            && trace.requested_at >= trace.at && trace.consumed_at >= trace.requested_at && ipi > 0;
        sched::fault_delay_deadline_timer(target, false);
        check(linked, "延迟本地到期timer后必须关联停表、BSP到期通知、IPI接收和owner消费");
        kprintln!("[JSR-DEADLINE-IPI] slot={} generation={} at={} requested={} consumed={} stopped={} ipis={} cpu={} linked={}",
            trace.token.slot, trace.token.generation, trace.at, trace.requested_at, trace.consumed_at, trace.stopped, ipi, trace.consumer, linked);
    }
    sched::set_idle_tick(old_idle);
    check(spawned && registered && moved && consumed && ran, "每核到期堆迁移后必须由目标CPU唤醒");
    check(saved == baseline(), "每核到期唤醒演练资源不守恒");
    kprintln!("[JSR-DEADLINE-OWNER] registered={} moved={} target={} consumed={} ran={} reclaimed={}", registered, moved, target, consumed, ran, saved == baseline());
}
// Author: chatgpt. Two APs share one real group and independent RT budgets.
static BUDGET_STOP: AtomicU32 = AtomicU32::new(0);
fn budget_worker() { while BUDGET_STOP.load(Ordering::Acquire) == 0 { core::hint::spin_loop(); } }

#[cfg(feature = "krn3-fast-tick-verify")]
static FAST_TICK_STOP: AtomicU32 = AtomicU32::new(0);
#[cfg(feature = "krn3-fast-tick-verify")]
fn fast_tick_worker() {
    while FAST_TICK_STOP.load(Ordering::Acquire) == 0 { core::hint::spin_loop(); }
}

/// Isolated KRN-3 production contract: two ordinary AP workers compete on one
/// leaf. Timer accounting, policy choice and the actual context switch must
/// complete without acquiring the global scheduler lock. Reading counters is
/// a cold transaction and reconciles the generation-bound leaf handoff.
#[cfg(feature = "krn3-fast-tick-verify")]
pub fn run_fast_leaf_tick_contract() -> u32 {
    FAILED.store(0, Ordering::Relaxed);
    let saved = baseline();
    let old_arbiter = sched::set_arbiter(false);
    let id = TaskId(0x4b524e3346415354);
    let peer = TaskId(0x4b524e3346415355);
    FAST_TICK_STOP.store(0, Ordering::Relaxed);
    sched::reset_cpu_stats();
    let before = sched::local_tick_hits(1);
    let finishes_before = sched::leaf_finish_count();
    let worker_finishes_before = sched::leaf_worker_finish_count();
    let local_switches_before = sched::leaf_local_switch_count();
    let mut cpu = CpuSet::EMPTY; cpu.insert(1);
    let spawned = quiet(|| {
        sched::spawn_on(id, "krn3-fast-a", fast_tick_worker, None, cpu).is_ok()
            && sched::spawn_on(peer, "krn3-fast-b", fast_tick_worker, None, cpu).is_ok()
    });
    let deadline = sched::timer_ticks() + 120;
    let mut hits = 0;
    while spawned && sched::timer_ticks() < deadline {
        if sched::leaf_local_switch_count().wrapping_sub(local_switches_before) >= 3 { break; }
        core::hint::spin_loop();
    }
    kprintln!("[JSR-KRN3-FAST-STAGE] stage=observed switches={}",
        sched::leaf_local_switch_count().wrapping_sub(local_switches_before));
    hits = sched::local_tick_hits(1).wrapping_sub(before);
    kprintln!("[JSR-KRN3-FAST-STAGE] stage=hits value={}", hits);
    let entity_ticks = sched::task_cpu_ticks(id).unwrap_or(0)
        .saturating_add(sched::task_cpu_ticks(peer).unwrap_or(0));
    kprintln!("[JSR-KRN3-FAST-STAGE] stage=entity value={}", entity_ticks);
    let busy_ticks = sched::cpu_stats(1).busy_ticks;
    let batch_peak = sched::local_tick_batch_peak(1);
    let local_switches = sched::leaf_local_switch_count().wrapping_sub(local_switches_before);
    let audit = sched::queue_audit();
    let exact = hits >= 3 && batch_peak == 1 && local_switches >= 3
        && entity_ticks == busy_ticks && entity_ticks >= u64::from(hits);
    check(spawned && exact, "competing leaf ticks must switch and account exactly once");
    let lists_ok = audit.misplaced == 0 && audit.count_mismatch == 0
        && audit.hook_errors == 0 && audit.list_mismatch == 0;
    kprintln!("[JSR-KRN3-FAST-AUDIT] queued={} misplaced={} count_mismatch={} hook_errors={} list_mismatch={}",
        audit.queued, audit.misplaced, audit.count_mismatch, audit.hook_errors, audit.list_mismatch);
    check(lists_ok,
        "fast leaf tick must preserve queue and hot ownership");
    FAST_TICK_STOP.store(1, Ordering::Release);
    sched::run();
    sched::set_arbiter(old_arbiter);
    let finishes = sched::leaf_finish_count().wrapping_sub(finishes_before);
    let worker_finishes = sched::leaf_worker_finish_count().wrapping_sub(worker_finishes_before);
    let reclaimed = saved == baseline();
    check(worker_finishes >= 1, "worker switch-out must complete in the local leaf");
    check(reclaimed, "fast leaf tick guest resources must return to baseline");
    kprintln!("[JSR-KRN3-FAST-TICK] spawned={} hits={} batch_peak={} local_switches={} entity_ticks={} busy_ticks={} exact={} leaf_finishes={} worker_finishes={} lists_ok={} reclaimed={} failed={}",
        spawned, hits, batch_peak, local_switches, entity_ticks, busy_ticks, exact,
        finishes,
        worker_finishes,
        lists_ok,
        reclaimed, failed());
    failed()
}
fn budget_tick_contract(n: usize) {
    if n < 3 { return; }
    let saved = baseline();
    let before = sched::budget_tick_stats();
    let throttle_before = sched::throttle_count();
    BUDGET_STOP.store(0, Ordering::Relaxed);
    let group = sched::create_cpu_group(900).expect("budget lease group");
    let mut configured = true;
    let ids = [TaskId(0x42554447455401), TaskId(0x42554447455402)];
    for (index, c) in (1..=2).enumerate() {
        let id = ids[index];
        let mut cpus = CpuSet::EMPTY; cpus.insert(c);
        configured &= quiet(|| sched::spawn_on(id, "budget-credit", budget_worker, None, cpus).is_ok());
        configured &= sched::assign_cpu_group(id, Some(group)).is_ok();
        configured &= sched::set_rt(id, 4, 16);
    }
    // Bootstrap task cannot block; sleep_ticks(80) would merely wait for one IRQ.
    // Measure the actual global clock instead of assuming that call slept 80 ticks.
    let until = sched::timer_ticks() + 80;
    let mut rt_exhausted = false;
    while sched::timer_ticks() < until {
        rt_exhausted |= ids.iter().any(|&id| sched::rt_state(id).is_some_and(|(remaining, period, _)|
            period == 16 && remaining == 0));
        sched::sleep_ticks(1);
    }
    let after = sched::budget_tick_stats();
    let group_stats = sched::cpu_group_stats(group).unwrap();
    let used = group_stats.used_ticks;
    let throttled = sched::throttle_count().wrapping_sub(throttle_before);
    BUDGET_STOP.store(1, Ordering::Release);
    for id in ids { sched::set_rt(id, 0, 0); }
    sched::run();
    let released = sched::release_cpu_group(group).is_ok();
    let rt = after[0].wrapping_sub(before[0]);
    let shared = after[1].wrapping_sub(before[1]);
    check(configured && rt_exhausted && used > 0 && throttled > 0 && released,
        "预算任务必须实际耗尽RT额度、触发调度节流并产生共享组扣费");
    check(saved == baseline(), "预算单tick演练资源不守恒");
    kprintln!("[JSR-BUDGET-TICK] tick_path_rt={} tick_path_shared={} rt_exhausted={} used={} group_throttle_events={} scheduler_throttles={} configured={} reclaimed={}",
        rt, shared, rt_exhausted, used, group_stats.throttle_events, throttled, configured, saved == baseline());
}
static RT_STOP: AtomicU32 = AtomicU32::new(0);
fn local_rt_worker() { while RT_STOP.load(Ordering::Acquire) == 0 { core::hint::spin_loop(); } }
fn local_rt_contract(n: usize) {
    if n < 2 { return; }
    let id = TaskId(0x52544c4f43414c);
    let saved = baseline();
    RT_STOP.store(0, Ordering::Relaxed);
    let mut cpus = CpuSet::EMPTY; cpus.insert(1);
    let spawned = quiet(|| sched::spawn_on(id, "rt-local", local_rt_worker, None, cpus).is_ok());
    let configured = sched::set_rt(id, 1, 4);
    let initial_next = sched::rt_state(id).map(|(_, _, next)| next).unwrap_or(0);
    let limit = sched::timer_ticks() + 200;
    let mut exhausted = false;
    let mut refilled = false;
    while sched::timer_ticks() < limit {
        if let Some((remaining, period, next)) = sched::rt_state(id) {
            exhausted |= period == 4 && remaining == 0 && sched::timer_ticks() < next;
            refilled |= next > initial_next;
        }
        if exhausted && refilled { break; }
        sched::sleep_ticks(1);
    }
    // Author: chatgpt. Keep the worker alive until its configuration API has
    // completed; publishing STOP first permits exit before set_rt finds it.
    let disabled = sched::set_rt(id, 0, 0);
    RT_STOP.store(1, Ordering::Release);
    sched::run();
    check(spawned && configured && exhausted && refilled && disabled, "AP必须实际扣完预算并由本核到期堆补充");
    check(saved == baseline(), "AP实时记账演练资源不守恒");
    kprintln!("[JSR-RT-LOCAL] exhausted={} refilled={} disabled={} reclaimed={}", exhausted, refilled, disabled, saved == baseline());
}

#[cfg(feature = "fault-inject")]
static FULL_AWAKE: AtomicU32 = AtomicU32::new(0);
#[cfg(feature = "fault-inject")]
fn full_mailbox_worker() { sched::sleep_ticks(1000); FULL_AWAKE.fetch_add(1, Ordering::Release); }
#[cfg(feature = "fault-inject")]
fn mailbox_full_contract(n: usize) {
    if n < 2 { return; }
    const COUNT: usize = crate::sched::scheduler::WAKE_MAILBOX_CAPACITY + 1;
    let ids: [TaskId; COUNT] = core::array::from_fn(|i| TaskId(0x46554c4c0000 + i as u64));
    let saved = baseline();
    FULL_AWAKE.store(0, Ordering::Relaxed);
    let mut cpus = CpuSet::EMPTY; cpus.insert(1);
    let spawned = quiet(|| ids.iter().all(|&id| sched::spawn_on(id, "mailbox-full", full_mailbox_worker, None, cpus).is_ok()));
    let limit = sched::timer_ticks() + 100;
    let registered = loop {
        let all = ids.iter().all(|&id| sched::deadline_owners(id).is_some_and(|(w,_)| w == Some(1)));
        if all || sched::timer_ticks() >= limit { break all; }
        sched::sleep_ticks(1);
    };
    let before = sched::remote_wake_stats();
    let started = sched::timer_ticks();
    sched::fault_wake_batch(&ids);
    sched::run();
    let after = sched::remote_wake_stats();
    let queued = after.0.wrapping_sub(before.0);
    let fallback = after.1.wrapping_sub(before.1);
    let returned = FULL_AWAKE.load(Ordering::Acquire) as usize;
    let timely = sched::timer_ticks().saturating_sub(started) < 100;
    check(spawned && registered && queued as usize == COUNT-1 && fallback == 1 && returned == COUNT && timely,
        "邮箱满后同步回退且原有队列与额外唤醒全部返回，不能等待自然超时");
    check(saved == baseline(), "满邮箱唤醒演练资源不守恒");
    kprintln!("[JSR-WAKE-FULL] queued={} fallback={} returned={}/{} timely={} reclaimed={}", queued, fallback, returned, COUNT, timely, saved == baseline());
}

// Author: chatgpt. CPU1 blocks; BSP routes its wake through the real mailbox.
static REMOTE_STAGE: AtomicU32 = AtomicU32::new(0);
fn remote_sleeper() {
    REMOTE_STAGE.store(1, Ordering::Release);
    sched::sleep_ticks(1000);
    REMOTE_STAGE.store(2, Ordering::Release);
}
fn remote_wake_contract(n: usize) {
    if n < 2 { return; }
    REMOTE_STAGE.store(0, Ordering::Relaxed);
    let saved = baseline();
    let before = sched::remote_wake_stats().0;
    let mut cpus = CpuSet::EMPTY; cpus.insert(1);
    let spawned = quiet(|| sched::spawn_on(TaskId(0x57414b45), "remote-sleeper", remote_sleeper, None, cpus).is_ok());
    let deadline = sched::timer_ticks() + 100;
    while REMOTE_STAGE.load(Ordering::Acquire) == 0 && sched::timer_ticks() < deadline { sched::sleep_ticks(1); }
    // The stage store precedes block_current; one extra tick lets CPU1 commit
    // the block. The generous 1000-tick sleep cannot count as an explicit wake.
    sched::sleep_ticks(1);
    let started = sched::timer_ticks();
    sched::wake(TaskId(0x57414b45));
    sched::run();
    let routed = sched::remote_wake_stats().0.wrapping_sub(before);
    let timely = sched::timer_ticks().saturating_sub(started) < 100;
    let returned = REMOTE_STAGE.load(Ordering::Acquire) == 2;
    check(spawned && routed > 0 && timely && returned, "跨核消息必须唤醒真实阻塞任务而非等超时");
    check(saved == baseline(), "跨核唤醒演练资源不守恒");
    kprintln!("[JSR-WAKE-MSG] routed={} timely={} returned={} reclaimed={}", routed, timely, returned, saved == baseline());
}

// Author: chatgpt. Exercise the real scheduler index, not a shadow map.
fn identity_worker() {}
fn identity_contracts() {
    const ID: TaskId = TaskId(0x4b524e324944);
    let before = baseline();
    let (created, duplicate, unchanged) = quiet(|| {
        let first = sched::spawn_on(ID, "index-first", identity_worker, None, CpuSet::first(1));
        let ticks = sched::cpu_ticks(ID);
        let duplicate = sched::spawn_on(ID, "index-duplicate", identity_worker, None, CpuSet::first(1));
        (first.is_ok(), duplicate == Err(SpawnError::DuplicateId), sched::cpu_ticks(ID) == ticks)
    });
    check(created && duplicate && unchanged, "活任务标签重复必须拒绝且保持原任务");
    sched::run();
    check(sched::cpu_ticks(ID).is_some(), "退出后必须保留历史记账查询");
    let reused = quiet(|| sched::spawn_on(ID, "index-reused", identity_worker, None, CpuSet::first(1)).is_ok());
    check(reused, "已退出且换下的显式标签应可复用");
    sched::run();
    check(sched::cpu_ticks(ID).is_some() && baseline() == before, "标签复用后历史可查且资源守恒");
    kprintln!("[JSR-TASK-INDEX] duplicate={} unchanged={} reused={} reclaimed={}", duplicate, unchanged, reused, baseline() == before);
}

/// 在关闭抢占的情况下执行 `f`（批量创建任务期间引导线程不被抢走处理器），之后恢复。
fn quiet<R>(f: impl FnOnce() -> R) -> R {
    let prev = sched::set_preemption(false);
    let r = f();
    sched::set_preemption(prev);
    r
}

/// 运行列表与运行队列一致、没有被拒绝的钩子调用。
fn lists_consistent() -> bool {
    let a = sched::queue_audit();
    a.list_mismatch == 0 && a.misplaced == 0 && a.count_mismatch == 0 && a.hook_errors == 0
}

/// 各核在本场景中是否都忙、空闲等待有界。
fn cores_busy(n: usize, window: u64) -> (bool, u64, u32) {
    let (mut all, mut least, mut worst) = (true, u64::MAX, 0u32);
    for c in 0..n {
        let st = sched::cpu_stats(c);
        all &= st.busy_ticks * 1000 >= window * BUSY_PERMILLE && st.max_idle_waiting <= IDLE_BOUND;
        least = least.min(st.busy_ticks);
        worst = worst.max(st.max_idle_waiting);
    }
    (all, least, worst)
}

/// 睡眠任务数：凑满 [`TARGET_TASKS`]，但给吃满处理器的任务、交互任务与其他演练的余量留出槽位。
fn sleeper_count(n: usize) -> usize {
    let free = sched::capacity().saturating_sub(1 + sched::live_workers());
    let others = 2 * n + 1;
    TARGET_TASKS.saturating_sub(others).min(free.saturating_sub(others + 2))
}

/// 创建 `count` 个睡眠任务并等它们全部进入睡眠（睡到 `until`）。返回是否全部创建成功。
fn spawn_sleepers(base: u64, count: usize, until: u64, all: CpuSet) -> bool {
    ASLEEP.store(0, Ordering::Relaxed);
    AWAKE.store(0, Ordering::Relaxed);
    SLEEP_END.store(until, Ordering::Relaxed);
    let ok = quiet(|| (0..count).all(|i| sched::spawn_on(TaskId(base + i as u64), "scale-sleep", sleeper, None, all).is_ok()));
    // 让它们运行到睡下（引导线程睡一会儿，把处理器交给它们）
    let give_up = sched::timer_ticks() + 20;
    while (ASLEEP.load(Ordering::Relaxed) as usize) < count && sched::timer_ticks() < give_up {
        sched::sleep_until(sched::timer_ticks() + 1);
    }
    // 计数先于真正睡下：再等一个 tick，确保最后一个也已离开运行列表
    sched::sleep_until(sched::timer_ticks() + 1);
    ok && ASLEEP.load(Ordering::Relaxed) as usize == count
}

/// 运行全部用例；演练期间保持抢占开启，结束时恢复进入前的设置。
pub fn run() {
    let prev_preemption = sched::set_preemption(true);
    let start = baseline();
    let n = sched::online_cpus().len();
    #[cfg(feature = "krn2-observe")]
    sched::reset_raw_wakes();
    refusals();
    identity_contracts();
    remote_wake_contract(n);
    #[cfg(feature = "fault-inject")]
    mailbox_full_contract(n);
    deadline_owner_contract(n);
    local_rt_contract(n);
    budget_tick_contract(n);
    scale(n);
    overload(n);
    recovery(n);
    contention(n);
    #[cfg(feature = "krn2-observe")]
    {
        let (raw, latency, errors, carried, pending) = sched::raw_wake_snapshot();
        let valid = !raw.entries().is_empty() && raw.entries().iter().flatten().all(|r|
            matches!(r.path, 3 | 4) && r.generation > 0 && r.wait_round > 0) && errors == [0; 3];
        check(valid, "真实唤醒选择记录必须匹配槽代次和轮次");
        kprintln!("[JSR-RAW-WAKE] samples={} dropped={} complete={} begin_refused={} finish_refused={} abandoned={} valid={} pending_at_reset={} pending_now={} endpoint=resume-hook clock=raw-unserialized",
            raw.entries().len(), raw.dropped(), raw.complete(), errors[0],errors[1],errors[2],valid,carried,pending);
        let complete = latency.count >= 1_000 && latency.invalid == 0 && pending == 0 && errors == [0; 3];
        kprintln!("[JSR-WAKE-LATENCY] samples={} invalid={} p50_us={} p99_us={} p999_us={} max_ns={} complete={} endpoint=resume-hook clock=shared-ns-serialized platform_sync=assumed",
            latency.count, latency.invalid, latency.p50_us, latency.p99_us, latency.p999_us,
            latency.max_ns, complete);
        for r in raw.entries().iter().flatten() {
            kprintln!("[JSR-WAKE-SAMPLE] path={} slot={} generation={} wait_round={} start_cpu={} end_cpu={} start={} end={}",
                r.path,r.slot,r.generation,r.wait_round,r.start.cpu,r.end.cpu,r.start.counter,r.end.counter);
        }
    }
    kprintln!("[JSR-SCHED-TICK] local_bypasses={}", sched::local_tick_bypasses());
    let end = baseline();
    check(end == start, "演练结束后资源未回到起点");
    check(lists_consistent(), "演练结束后运行列表与运行队列不一致");
    // 验收专用：注入一条必然失败的功能断言，证明功能失败仍按失败判定（只在启用该特性时执行）。
    #[cfg(feature = "selftest-inject-failure")]
    check(false, "注入的功能失败（selftest-inject-failure）");
    sched::set_preemption(prev_preemption);
    kprintln!(
        "[JSR-SCALE] summary cpus={} slots={} free_frames={}/{} objects={}/{} reclaimed={} checks={} failed={} timing_failed={}",
        n,
        sched::slots(),
        end.free_frames,
        start.free_frames,
        end.objects,
        start.objects,
        end == start,
        CHECKS.load(Ordering::Relaxed),
        failed(),
        timing_failed()
    );
}

/// 空亲和集合的创建被拒：任务数、运行列表、资源都不变。
fn refusals() {
    let before = baseline();
    let live = sched::live_workers();
    let queued = sched::queue_audit().queued;
    let r = sched::spawn_on(TaskId(TASK_ID_BASE), "scale-bad", hog, None, CpuSet::EMPTY);
    let refused = matches!(r, Err(SpawnError::BadAffinity));
    let unchanged = sched::live_workers() == live && sched::queue_audit().queued == queued && lists_consistent() && baseline() == before;
    check(refused, "空亲和集合应被拒绝");
    check(unchanged, "被拒绝后运行列表、任务或资源有改动");
    kprintln!("[JSR-SCALE] case=refusals empty_set={} unchanged={}", if refused { "refused" } else { "accepted" }, unchanged);
}

/// 睡眠任务 + 2N 个吃满处理器的任务：选择遍历量与可运行任务数相当，到期唤醒扫描不再每 tick 发生。
fn scale(n: usize) {
    let before = baseline();
    let all = CpuSet::first(n);
    let sleepers = sleeper_count(n);
    let hogs = 2 * n;
    let t0 = sched::timer_ticks();
    let slept = spawn_sleepers(TASK_ID_BASE + 100, sleepers, t0 + WINDOW + 30, all);
    check(slept, "睡眠任务创建失败或没有全部睡下");
    let ok = quiet(|| {
        sched::reset_cpu_stats();
        sched::reset_scan_stats();
        HOG_END.store(sched::timer_ticks() + WINDOW, Ordering::Relaxed);
        (0..hogs).all(|i| sched::spawn_on(TaskId(TASK_ID_BASE + 10 + i as u64), "scale-hog", hog, None, all).is_ok())
    });
    check(ok, "吃满处理器的任务创建失败");
    // 窗口内只等吃满处理器的任务结束（睡眠任务在窗口之后才醒）
    while sched::timer_ticks() < HOG_END.load(Ordering::Relaxed) {
        sched::sleep_until(HOG_END.load(Ordering::Relaxed));
    }
    let scan = sched::scan_stats();
    let (busy, least, worst) = cores_busy(n, WINDOW);
    let consistent = lists_consistent();
    // 测量窗口结束时的前提：窗口内睡眠任务应都还睡着。它们若已到期（时间被放慢时引导线程可能晚于窗口才被调度），
    // 遍历量与到期唤醒扫描次数就不再说明「睡眠任务被排除在选择之外」，两条判据只记计时、不判功能失败。
    let still_asleep = (ASLEEP.load(Ordering::Relaxed) as usize).saturating_sub(AWAKE.load(Ordering::Relaxed) as usize);
    let premise_held = still_asleep == sleepers;
    let expired = sleepers.saturating_sub(still_asleep);
    sched::run();
    let bound = (hogs + 1) as u32;
    let visit_ok = scan.max_visited <= bound;
    let scan_ok = scan.wake_scans <= 1 && scan.ticks >= WINDOW;
    // 睡眠任务必须明显多于可运行任务，否则「遍历量 ≤ 可运行任务数」说明不了睡眠任务被排除在外
    check(sleepers > bound as usize, "规模用例睡眠任务数不足");
    if premise_held {
        check(visit_ok, "单次选择遍历量超过可运行任务数（遍历了睡眠任务）");
        check(scan_ok, "窗口内到期唤醒扫描次数超过 1（没有按最早到期时刻跳过）");
    } else {
        check_timing(false, format_args!("单次选择遍历量判据的前提被时间破坏：窗口内有 {} 个睡眠任务已到期", expired));
        check_timing(false, format_args!("到期唤醒扫描判据的前提被时间破坏：窗口内有 {} 个睡眠任务已到期", expired));
    }
    check_timing(busy, format_args!("规模用例中有核空闲或空闲等待超过上界"));
    check(consistent, "规模用例中运行列表与运行队列不一致");
    check(baseline() == before, "规模用例后资源未回到基线");
    let avg_x100 = if scan.picks == 0 { 0 } else { scan.visited * 100 / scan.picks };
    kprintln!(
        "[JSR-SCALE] case=scale cpus={} slots={} sleepers={} hogs={} picks={} max_visited={} avg_visited_x100={} bound={} wake_scans={} ticks={} least_busy={} worst_idle_waiting={} all_busy={} lists_ok={} ok={}",
        n,
        sched::slots(),
        sleepers,
        hogs,
        scan.picks,
        scan.max_visited,
        avg_x100,
        bound,
        scan.wake_scans,
        scan.ticks,
        least,
        worst,
        busy,
        consistent,
        visit_ok && scan_ok && busy && consistent
    );
}

/// 同样规模（睡眠任务 + 2N 个吃满处理器的任务）下加 1 个交互档任务：唤醒延迟有上界，各核都忙。
fn overload(n: usize) {
    let before = baseline();
    let all = CpuSet::first(n);
    let sleepers = sleeper_count(n);
    let hogs = 2 * n;
    let window = 2 * WINDOW;
    let t0 = sched::timer_ticks();
    let slept = spawn_sleepers(TASK_ID_BASE + 300, sleepers, t0 + window + 30, all);
    check(slept, "睡眠任务创建失败或没有全部睡下");
    let ok = quiet(|| {
        sched::reset_cpu_stats();
        sched::reset_latency();
        INTERACTIVE_DONE.store(0, Ordering::Relaxed);
        HOG_END.store(sched::timer_ticks() + window, Ordering::Relaxed);
        let mut ok = (0..hogs).all(|i| sched::spawn_on(TaskId(TASK_ID_BASE + 40 + i as u64), "scale-load", hog, None, all).is_ok());
        ok &= sched::spawn_on(TaskId(TASK_ID_BASE + 39), "scale-ui", interactive, None, all).is_ok();
        ok
    });
    check(ok, "过载用例任务创建失败");
    while sched::timer_ticks() < HOG_END.load(Ordering::Relaxed) {
        sched::sleep_until(HOG_END.load(Ordering::Relaxed));
    }
    let (busy, least, worst) = cores_busy(n, window);
    sched::run();
    let lat = sched::latency(Qos::Interactive);
    let done = INTERACTIVE_DONE.load(Ordering::Relaxed);
    check(done == ROUNDS && lat.count() == ROUNDS, "交互任务未完成全部睡眠");
    check_timing(lat.max() <= LATENCY_BOUND, format_args!("过载时交互唤醒延迟超过上界"));
    check_timing(busy, format_args!("过载时有核空闲或空闲等待超过上界"));
    check(baseline() == before, "过载用例后资源未回到基线");
    kprintln!(
        "[JSR-SCALE] case=overload cpus={} sleepers={} hogs={} window={} interactive_rounds={} samples={} latency_max={} bound={} bounded={} least_busy={} worst_idle_waiting={} all_busy={}",
        n,
        sleepers,
        hogs,
        window,
        done,
        lat.count(),
        lat.max(),
        LATENCY_BOUND,
        lat.max() <= LATENCY_BOUND,
        least,
        worst,
        busy
    );
}

/// 压力撤销后：交互任务连续睡眠，唤醒延迟都是 0。
fn recovery(n: usize) {
    let before = baseline();
    sched::reset_latency();
    INTERACTIVE_DONE.store(0, Ordering::Relaxed);
    let ok = quiet(|| sched::spawn_on(TaskId(TASK_ID_BASE + 60), "scale-ui", interactive, None, CpuSet::first(n)).is_ok());
    check(ok, "恢复任务创建失败");
    sched::run();
    let lat = sched::latency(Qos::Interactive);
    let done = INTERACTIVE_DONE.load(Ordering::Relaxed);
    check(done == ROUNDS && lat.count() == ROUNDS, "恢复任务未完成全部睡眠");
    check_timing(lat.max() == 0, format_args!("压力撤销后唤醒延迟应为 0"));
    check(baseline() == before, "恢复用例后资源未回到基线");
    kprintln!(
        "[JSR-SCALE] case=recovery cpus={} rounds={} samples={} max={} immediate={} reclaimed={}",
        n,
        done,
        lat.count(),
        lat.max(),
        lat.max() == 0,
        baseline() == before
    );
}

/// 输出一把锁的测量值，返回计数是否自洽（加锁次数 > 0，遇到占用次数不超过加锁次数）。
fn report_lock(name: &str, cpus: usize, s: LockStats) -> bool {
    let sane = s.acquired > 0 && s.contended <= s.acquired && (s.contended > 0 || s.spins == 0);
    let permille = if s.acquired == 0 { 0 } else { (s.contended as u64 * 1000 / s.acquired as u64) as u32 };
    kprintln!(
        "[JSR-SCALE] lock name={} cpus={} acquired={} contended={} contended_permille={} spins={} max_spins={} sane={}",
        name,
        cpus,
        s.acquired,
        s.contended,
        permille,
        s.spins,
        s.max_spins,
        sane
    );
    sane
}

/// 锁争用测量：N 个任务（各核一个）反复让出并读对象表统计。
fn contention(n: usize) {
    let fast_before = sched::fast_yield_count();
    let before = baseline();
    CHURN_TARGET.store(n as u32, Ordering::Release);
    CHURN_READY.store(0, Ordering::Relaxed);
    CHURN_GO.store(0, Ordering::Relaxed);
    CHURN_DONE.store(0, Ordering::Relaxed);
    CHURN_MASK.store(0, Ordering::Relaxed);
    let ok = quiet(|| {
        // Pin one participant per CPU, APs first so CPU0 cannot prevent publication.
        (1..n).chain(core::iter::once(0)).all(|i| {
            let mut affinity = CpuSet::EMPTY; affinity.insert(i);
            sched::spawn_on(TaskId(TASK_ID_BASE + 80 + i as u64), "scale-churn", churn, None, affinity).is_ok()
        })
    });
    check(ok, "锁争用测量任务创建失败");
    if !ok { CHURN_GO.store(2, Ordering::Release); }
    sched::run();
    let s = sched::lock_stats();
    let o = kobj::lock_stats();
    kprintln!("[JSR-SCHED-FAST] cpus={} yield_bypasses={}", n, sched::fast_yield_count().wrapping_sub(fast_before));
    let ready = CHURN_READY.load(Ordering::Acquire);
    let done = CHURN_DONE.load(Ordering::Acquire);
    let mask = CHURN_MASK.load(Ordering::Acquire);
    let expected = if n == 32 { u32::MAX } else { (1u32 << n) - 1 };
    check(ready == n as u32 && done == n as u32 && mask == expected, "争用测量必须全部核就绪并完成原轮数");
    kprintln!("[JSR-CHURN-BARRIER] ready={}/{} done={}/{} mask={:#x} rounds={}", ready,n,done,n,mask,CHURN_ROUNDS);
    #[cfg(feature = "krn2-observe")]
    {
        let (total, window) = sched::pi_work_stats();
        for (scope, work) in [("boot", total), ("churn", window)] {
            kprintln!("[JSR-PI-WORK] scope={} calls={} slot_visits={} active_visits={} steps={} max_walk={} truncated={} overflow={}",
                scope, work.calls, work.slots, work.live, work.steps, work.max_walk, work.truncated, work.overflow);
        }
        let (origins, window, aggregate) = sched::global_origin_stats();
        for (scope, counts) in [("boot", origins), ("churn", window)] {
            let sum = counts.by_origin.iter().try_fold(0u64, |n, value| n.checked_add(*value));
            let reconciled = !counts.overflow && sum == Some(counts.total)
                && (scope != "churn" || counts.total == aggregate);
            let [read, mutation, switch, bsp, ap, diagnostic] = counts.by_origin;
            kprintln!("[JSR-GLOBAL-ORIGIN] scope={} total={} read={} mutation={} switch={} bsp_tick={} ap_fallback={} diagnostic={} aggregate_window={} overflow={} reconciled={}",
                scope, counts.total, read, mutation, switch, bsp, ap, diagnostic, aggregate, counts.overflow, reconciled);
            check(reconciled, "全局事务来源必须与同锁窗口总数对账");
        }
        let [transactions, leaves, contended, spins] = sched::sync_work_stats();
        let upper = u64::from(transactions).saturating_mul(n as u64);
        let bounded = transactions > 0 && leaves > 0 && u64::from(leaves) <= upper
            && contended <= leaves;
        let avoided = upper.saturating_sub(u64::from(leaves));
        check(bounded, "诊断叶获取必须非空、有界且争用数不超过实际获取数");
        kprintln!("[JSR-SYNC-WORK] transactions={} leaf_acquired={} leaf_contended={} leaf_spins={} online={} upper={} avoided={} bounded={}",
            transactions, leaves, contended, spins, n, upper, avoided, bounded);
    }
    #[cfg(feature = "krn2-observe")]
    {
        let raw = sched::raw_callback_snapshot();
        let valid = !raw.entries().is_empty() && raw.entries().iter().flatten().all(|r|
            r.path == 1 && r.wait_round == 0 && r.start.cpu == r.end.cpu);
        check(valid, "原始回调记录必须保留路径和同核端点");
        kprintln!("[JSR-RAW-CALLBACK] samples={} dropped={} complete={} valid={} clock=raw-unserialized",
            raw.entries().len(), raw.dropped(), raw.complete(), valid);
        for r in raw.entries().iter().flatten() {
            kprintln!("[JSR-RAW-SAMPLE] path={} slot={} generation={} wait_round={} start_cpu={} end_cpu={} start={} end={}",
                r.path,r.slot,r.generation,r.wait_round,r.start.cpu,r.end.cpu,r.start.counter,r.end.counter);
        }
    }
    let sane = report_lock("sched", n, s) & report_lock("objtable", n, o);
    check(sane, "锁争用计数不自洽");
    check(baseline() == before, "锁争用测量后资源未回到基线");
    kprintln!("[JSR-SCALE] case=contention cpus={} tasks={} rounds={} measured={}", n, n, CHURN_ROUNDS, sane);
}
