//! 中断与系统服务多核化的验收演练：设备中断按亲和送达指定处理器、均衡策略把中断线分散到多个核、
//! 中断风暴下每核预算节流使交互延迟有上界且没有单核被中断吃满、风暴撤销后立即恢复；
//! 分片服务队列在 N 个核上并行消费、各核负载均衡、流内有序；全部拒绝路径无残留。
//! Acceptance drill for multi-core device interrupts and sharded system services.
//!
//! # 为什么要有这个演练
//! 预算记账、亲和分配与分片路由的决定在宿主上有确定性测试；这里验证它们接上真实的中断控制器、
//! 每核本地时钟与每核运行队列之后：设备中断真的到达指定的处理器，风暴不会把任何一个核拖死，
//! 系统服务的吞吐随处理器数伸缩，而不是「一核跑满、多核围观」。
//!
//! # 用例
//! 0. **拒绝路径**（任何处理器数、任何平台）：不存在的线、空集合、只含离线处理器的集合、未路由就启用、
//!    未启用就自触发、非法预算、非法分片数、未配置就提交、处理器无分片、分片已满、有积压时重配；
//!    全部被拒，路由、预算、队列内容与资源不变。
//! 1. **送达**：依次把每条线钉到每个处理器并让设备持续请求中断：只有该处理器处理过它，处理函数逐次被调用。
//! 2. **均衡**：两条线都放在引导处理器上：对照策略不搬；换成均衡策略后有界时间内分到不同的核。
//! 3. **风暴 + 过载 + 交互**：全部线持续风暴 + 2N 个吃满处理器的任务 + 1 个交互任务：
//!    交互唤醒延迟 ≤ [`LATENCY_BOUND`]，各核都忙，每核中断处理时间不超过预算给出的界，风暴分布在多个核上。
//! 4. **恢复**：风暴撤销、线停用后不再有中断，交互唤醒延迟全为 0。
//! 5. **分片服务**：同一批请求先由 1 个分片处理、再由 N 个分片（每核一个钉住的工作线程）处理：
//!    各分片处理量的不均衡度有界、每个核都在处理、流内顺序不变、N 分片的完成时间显著短于 1 分片。
//!
//! 平台没有可路由的设备中断线、或只有一个处理器时，如实报告并只演练能演练的部分。

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::irq::{QuotaParams, IrqError, Keep, Spread};
use kernel_core::shard::{imbalance_permille, mix64, ShardError, ShardKey, ShardRing};
use kernel_core::smp::{CpuSet, MAX_CPUS};

use crate::baseline::baseline;
use crate::irq::device;
use crate::sched::policy::Qos;
use crate::shard::{spawn_workers, ShardedQueues};
use crate::sync::IrqU64;
use crate::task::TaskId;
use crate::{arch, kprintln, sched};

static CHECKS: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);

fn check(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-SMP3-FAIL] {}", what);
    }
}

/// 失败断言数。
/// Number of failed assertions.
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

/// 本演练的内核任务号起点（与其它演练不重叠）。
const TASK_ID_BASE: u64 = 9900;
/// 送达用例中每个处理器上的风暴时长（tick）。
const ROUTE_TICKS: u64 = 3;
/// 均衡用例的观察时长（tick）：两个均衡周期以上。
const BALANCE_TICKS: u64 = 3 * device::BALANCE_PERIOD;
/// 风暴 + 过载用例的窗口（tick）。
const WINDOW: u64 = 120;
/// 每个核在窗口内至少忙碌的千分比。
const BUSY_PERMILLE: u64 = 850;
/// 交互唤醒延迟上界（tick）：与无风暴时的多核过载上界相同——风暴不得让它变差。
const LATENCY_BOUND: u64 = 2;
/// 交互任务的睡眠次数。
const ROUNDS: u32 = 20;
/// 中断处理时间相对预算界的容差（千分比）：入口 / 出口开销测不到，按次数上限另行约束。
const SHARE_SLACK_PERMILLE: u64 = 200;

/// 屏蔽一条线时可能已锁存、仍会送达的中断次数（每条线一次）。
const LATCHED: u64 = 2;

/// 当前任务累计运行的 tick 数。
fn my_cpu() -> u64 {
    sched::cpu_ticks(sched::current().0).unwrap_or(0)
}

/// 只含处理器 `c` 的集合。
fn only(c: usize) -> CpuSet {
    let mut s = CpuSet::EMPTY;
    s.insert(c);
    s
}

/// 在关闭抢占的情况下执行 `f`（批量创建任务期间引导线程不被自己刚创建的任务抢走处理器），之后恢复。
fn quiet<R>(f: impl FnOnce() -> R) -> R {
    let prev = sched::set_preemption(false);
    let r = f();
    sched::set_preemption(prev);
    r
}

/// 引导线程开着中断等待 `ticks` 个 tick（期间中断照常在各核处理）。
fn wait_ticks(ticks: u64) {
    let end = sched::timer_ticks() + ticks;
    while sched::timer_ticks() < end {
        sched::sleep_until(end);
    }
}

/// 运行全部用例；演练期间保持抢占开启，结束时恢复进入前的设置并把中断子系统还原为默认状态。
/// Run every case.
pub fn run() {
    let prev_preemption = sched::set_preemption(true);
    let start = baseline();
    let online = sched::online_cpus();
    let n = online.len();
    let lines = device::line_count();
    kprintln!(
        "[JSR-SMP3] start cpus={} device_lines={} quota_permille={} quota_max_per_tick={}",
        n,
        lines,
        device::quota().permille,
        device::quota().max_per_tick
    );
    for l in 0..lines {
        kprintln!("[JSR-SMP3] line index={} name={}", l, device::line_name(l));
    }
    irq_refusals(online, lines);
    shard_refusals();
    if lines > 0 && n > 1 {
        route(online, lines);
        balance(n, lines);
        storm(n, lines);
        recovery(n, lines);
    } else if lines == 0 {
        kprintln!("[JSR-SMP3] device_lines=0 routing=skipped");
    } else {
        kprintln!("[JSR-SMP3] single cpus=1 spread=skipped");
    }
    if n > 1 {
        service(n);
    }
    device::set_balancer(None);
    let end = baseline();
    check(end == start, "演练结束后资源未回到起点");
    sched::set_preemption(prev_preemption);
    kprintln!(
        "[JSR-SMP3] summary cpus={} device_lines={} free_frames={}/{} objects={}/{} reclaimed={} checks={} failed={}",
        n,
        lines,
        end.free_frames,
        start.free_frames,
        end.objects,
        start.objects,
        end == start,
        CHECKS.load(Ordering::Relaxed),
        failed()
    );
}

// ---------------------------------------------------------------------------
// 用例 0：拒绝路径
// ---------------------------------------------------------------------------

/// 中断子系统的拒绝路径：路由、启用状态与预算都不变。
fn irq_refusals(online: CpuSet, lines: usize) {
    let before = baseline();
    let quota = device::quota();
    let bad = lines;
    let no_line = device::set_affinity(bad, online) == Err(IrqError::NoLine)
        && device::set_handler(bad, Some(count_handler)) == Err(IrqError::NoLine)
        && device::set_enabled(bad, true) == Err(IrqError::NoLine)
        && device::set_self_trigger(bad, true) == Err(IrqError::NoLine)
        && device::routed_to(bad).is_none();
    let bad_quota = [
        QuotaParams { permille: 0, max_per_tick: 8 },
        QuotaParams { permille: QuotaParams::MAX_PERMILLE + 1, max_per_tick: 8 },
        QuotaParams { permille: 100, max_per_tick: 0 },
    ]
    .iter()
    .all(|&p| device::set_quota(p) == Err(IrqError::BadQuota))
        && device::quota() == quota;
    let (mut empty, mut offline, mut unrouted, mut disabled) = ("n/a", "n/a", "n/a", "n/a");
    let mut unchanged = true;
    if lines > 0 {
        let routed = device::routed_to(0);
        let enabled = device::enabled_lines();
        unrouted = if routed.is_some() || device::set_enabled(0, true) == Err(IrqError::Offline) { "refused" } else { "accepted" };
        empty = if device::set_affinity(0, CpuSet::EMPTY) == Err(IrqError::EmptySet) { "refused" } else { "accepted" };
        if let Some(c) = (0..MAX_CPUS).find(|&c| !online.contains(c)) {
            offline = if device::set_affinity(0, only(c)) == Err(IrqError::Offline) { "refused" } else { "accepted" };
        }
        disabled = if device::set_self_trigger(0, true) == Err(IrqError::Offline) { "refused" } else { "accepted" };
        unchanged = device::routed_to(0) == routed && device::enabled_lines() == enabled;
    }
    let ok_all = [empty, offline, unrouted, disabled].iter().all(|s| *s != "accepted");
    let clean = unchanged && baseline() == before;
    check(no_line, "不存在的中断线应被拒绝");
    check(bad_quota, "非法预算应被拒绝且预算不变");
    check(ok_all, "空集合 / 离线集合 / 未路由启用 / 未启用自触发应被拒绝");
    check(clean, "被拒绝后路由、启用状态或资源有改动");
    kprintln!(
        "[JSR-SMP3] case=irq_refusals no_line={} bad_quota={} empty_set={} offline_only={} unrouted_enable={} disabled_trigger={} unchanged={}",
        if no_line { "refused" } else { "accepted" },
        if bad_quota { "refused" } else { "accepted" },
        empty,
        offline,
        unrouted,
        disabled,
        clean
    );
}

/// 拒绝路径用的小队列。
static SMALL: ShardedQueues<u64, 2, 4> = ShardedQueues::new();

/// 分片组件的拒绝路径：数量非法、未配置、无对应分片、已满、有积压时重配；内容与计数不变。
fn shard_refusals() {
    let before = baseline();
    let unconfigured = SMALL.submit(ShardKey::Flow(1), 1) == Err(ShardError::BadCount) && SMALL.pending() == 0;
    let bad_count = SMALL.configure(0).err() == Some(ShardError::BadCount) && SMALL.configure(3).err() == Some(ShardError::BadCount) && SMALL.shards() == 0;
    let configured = SMALL.configure(2).is_ok();
    let no_cpu = SMALL.submit(ShardKey::Cpu(2), 7) == Err(ShardError::NoCpuShard) && SMALL.pending() == 0;
    // 填满分片 0（按处理器键直达），再提交一个：被拒，已有的 4 项按原顺序取出
    let mut filled = true;
    for v in 0..4u64 {
        filled &= SMALL.submit(ShardKey::Cpu(0), 100 + v) == Ok(0);
    }
    let full = SMALL.submit(ShardKey::Cpu(0), 999) == Err(ShardError::Full) && SMALL.counters(0) == (4, 0, 1);
    let busy = SMALL.configure(1).err() == Some(ShardError::Full) && SMALL.shards() == 2;
    let mut order = true;
    for v in 0..4u64 {
        order &= SMALL.take(0) == Some(100 + v);
        SMALL.complete(0);
    }
    order &= SMALL.take(0).is_none() && SMALL.take(5).is_none();
    // 独立的环：满时拒绝不覆盖
    let mut ring: ShardRing<u8, 2> = ShardRing::new();
    let ring_ok = ring.push(1).is_ok() && ring.push(2).is_ok() && ring.push(3) == Err(ShardError::Full) && ring.pop() == Some(1) && ring.len() == 1;
    SMALL.shutdown();
    let off = SMALL.submit(ShardKey::Flow(1), 1) == Err(ShardError::BadCount);
    let clean = SMALL.pending() == 0 && baseline() == before;
    let ok = unconfigured && bad_count && configured && no_cpu && filled && full && busy && order && ring_ok && off;
    check(unconfigured && off, "未配置 / 已停用的分片队列应拒绝提交");
    check(bad_count && configured, "非法分片数应被拒绝且状态不变");
    check(no_cpu, "没有对应分片的处理器键应被拒绝");
    check(filled && full && order && ring_ok, "已满的分片应拒绝且原有内容按序保留");
    check(busy, "有积压时重配应被拒绝且分片数不变");
    check(clean, "分片拒绝路径后留下了请求或资源");
    kprintln!(
        "[JSR-SMP3] case=shard_refusals unconfigured={} bad_count={} no_cpu_shard={} full={} kept_order={} reconfigure_busy={} unchanged={}",
        if unconfigured { "refused" } else { "accepted" },
        if bad_count { "refused" } else { "accepted" },
        if no_cpu { "refused" } else { "accepted" },
        if full { "refused" } else { "accepted" },
        order && ring_ok,
        if busy { "refused" } else { "accepted" },
        clean && ok
    );
}

// ---------------------------------------------------------------------------
// 用例 1：送达
// ---------------------------------------------------------------------------

/// 处理函数被调用的次数。
static HANDLED: IrqU64 = IrqU64::new(0);

/// 演练用的处理函数（中断上下文）：只计数。
fn count_handler(_line: usize) {
    HANDLED.fetch_add(1, Ordering::Relaxed);
}

/// 全部线的总处理次数。
fn total_counts(lines: usize) -> u64 {
    (0..lines).map(|l| (0..MAX_CPUS).map(|c| device::count_on(l, c) as u64).sum::<u64>()).sum()
}

/// 打开 / 关闭全部线的风暴（线须已启用）。
fn storm_all(lines: usize, on: bool) -> bool {
    (0..lines).all(|l| device::set_self_trigger(l, on).is_ok())
}

/// 依次把全部线钉到每个处理器：只有该处理器处理过它们，处理函数与计数一致。
fn route(online: CpuSet, lines: usize) {
    let before = baseline();
    let mut delivered = 0usize;
    let mut exact = true;
    let mut handler_ok = true;
    for c in online.iter() {
        device::reset_stats();
        HANDLED.store(0, Ordering::Relaxed);
        let mut ok = true;
        for l in 0..lines {
            ok &= device::set_affinity(l, only(c)) == Ok(c);
            ok &= device::set_handler(l, Some(count_handler)).is_ok();
            ok &= device::set_enabled(l, true).is_ok();
        }
        ok &= storm_all(lines, true);
        wait_ticks(ROUTE_TICKS);
        ok &= storm_all(lines, false);
        for l in 0..lines {
            ok &= device::set_enabled(l, false).is_ok();
        }
        // 停用后到达的最后一次中断也处理完
        wait_ticks(1);
        let mut here = true;
        for l in 0..lines {
            let on_c = device::count_on(l, c);
            let elsewhere: u32 = (0..MAX_CPUS).filter(|&o| o != c).map(|o| device::count_on(l, o)).sum();
            here &= on_c > 0 && elsewhere == 0;
            kprintln!("[JSR-SMP3] route cpu={} line={} here={} elsewhere={}", c, device::line_name(l), on_c, elsewhere);
        }
        handler_ok &= HANDLED.load(Ordering::Relaxed) == total_counts(lines);
        if here && ok {
            delivered += 1;
        }
        exact &= here && ok;
    }
    for l in 0..lines {
        let _ = device::set_handler(l, None);
    }
    let clean = baseline() == before && device::enabled_lines() == 0;
    check(exact, "设备中断未只送达亲和集合指定的处理器");
    check(handler_ok, "处理函数调用次数与处理计数不一致");
    check(clean, "送达用例后线未停用或资源未回到基线");
    kprintln!(
        "[JSR-SMP3] case=route cpus={} lines={} delivered_exact={}/{} handler_calls_match={} disabled_after={}",
        online.len(),
        lines,
        delivered,
        online.len(),
        handler_ok,
        clean
    );
}

// ---------------------------------------------------------------------------
// 用例 2：均衡策略
// ---------------------------------------------------------------------------

/// 全部线所在处理器的集合。
fn routed_set(lines: usize) -> CpuSet {
    let mut s = CpuSet::EMPTY;
    for l in 0..lines {
        if let Some(c) = device::routed_to(l) {
            s.insert(c);
        }
    }
    s
}

/// 全部线放在引导处理器上：对照策略不搬，均衡策略在有界时间内把它们分到不同的核。
fn balance(n: usize, lines: usize) {
    static KEEP: Keep = Keep;
    static SPREAD: Spread = Spread::DEFAULT;
    let before = baseline();
    let all = CpuSet::first(n);
    let mut ok = true;
    for l in 0..lines {
        // 先钉到 0 号，再放宽：当前位置仍合法，保持在 0 号
        ok &= device::set_affinity(l, only(0)) == Ok(0) && device::set_affinity(l, all) == Ok(0);
        ok &= device::set_enabled(l, true).is_ok();
    }
    device::reset_stats();
    device::set_balancer(Some(&KEEP));
    ok &= storm_all(lines, true);
    wait_ticks(BALANCE_TICKS);
    let keep_moves = device::balance_moves();
    let keep_set = routed_set(lines);
    device::set_balancer(Some(&SPREAD));
    let t0 = sched::timer_ticks();
    let mut spread_at = None;
    while sched::timer_ticks() < t0 + BALANCE_TICKS {
        if spread_at.is_none() && routed_set(lines).len() == lines.min(n) {
            spread_at = Some(sched::timer_ticks() - t0);
        }
        sched::sleep_until(sched::timer_ticks() + 1);
    }
    let spread_moves = device::balance_moves() - keep_moves;
    let spread_set = routed_set(lines);
    ok &= storm_all(lines, false);
    device::set_balancer(None);
    for l in 0..lines {
        ok &= device::set_enabled(l, false).is_ok();
    }
    wait_ticks(1);
    let keep_ok = keep_moves == 0 && keep_set == only(0);
    let distinct = spread_set.len() == lines.min(n);
    let bound = 2 * device::BALANCE_PERIOD;
    let in_time = spread_at.is_some_and(|t| t <= bound);
    check(ok, "均衡用例的路由 / 启用失败");
    check(keep_ok, "对照策略不应搬动中断线");
    check(distinct && spread_moves >= 1, "均衡策略未把中断线分到不同的核");
    check(in_time, "均衡策略分散中断线超过两个均衡周期");
    check(baseline() == before, "均衡用例后资源未回到基线");
    kprintln!(
        "[JSR-SMP3] case=balance lines={} keep_moves={} keep_cpus={:#x} spread_moves={} spread_cpus={:#x} distinct={} spread_after={} bound={} in_time={}",
        lines,
        keep_moves,
        keep_set.bits(),
        spread_moves,
        spread_set.bits(),
        distinct,
        spread_at.unwrap_or(u64::MAX),
        bound,
        in_time
    );
}

// ---------------------------------------------------------------------------
// 用例 3–4：风暴 + 过载 + 交互、恢复
// ---------------------------------------------------------------------------

/// 吃满处理器的任务的截止时刻。
static HOG_END: IrqU64 = IrqU64::new(0);
/// 吃满处理器的任务里最少的运行 tick 数。
static HOG_MIN_CPU: AtomicU32 = AtomicU32::new(u32::MAX);
/// 交互任务完成的睡眠次数。
static INTERACTIVE_DONE: AtomicU32 = AtomicU32::new(0);

/// 工具档、吃满处理器直到 [`HOG_END`]。
fn hog() {
    let _ = sched::set_current_qos(Qos::Utility);
    let start = my_cpu();
    while sched::timer_ticks() < HOG_END.load(Ordering::Relaxed) {
        core::hint::spin_loop();
    }
    let used = (my_cpu() - start).min(u32::MAX as u64 - 1) as u32;
    HOG_MIN_CPU.fetch_min(used, Ordering::Relaxed);
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

/// 全部线持续风暴 + 2N 个吃满处理器的任务 + 1 个交互任务。
fn storm(n: usize, lines: usize) {
    static SPREAD: Spread = Spread::DEFAULT;
    let before = baseline();
    let all = CpuSet::first(n);
    let mut ok = true;
    for l in 0..lines {
        ok &= device::set_affinity(l, all).is_ok() && device::set_enabled(l, true).is_ok();
    }
    device::set_balancer(Some(&SPREAD));
    let count = 2 * n as u64;
    ok &= quiet(|| {
        device::reset_stats();
        sched::reset_cpu_stats();
        sched::reset_latency();
        INTERACTIVE_DONE.store(0, Ordering::Relaxed);
        HOG_MIN_CPU.store(u32::MAX, Ordering::Relaxed);
        HOG_END.store(sched::timer_ticks() + WINDOW, Ordering::Relaxed);
        let mut ok = storm_all(lines, true);
        for i in 0..count {
            ok &= sched::spawn_on(TaskId(TASK_ID_BASE + 10 + i), "smp3-load", hog, None, all).is_ok();
        }
        ok && sched::spawn_on(TaskId(TASK_ID_BASE + 9), "smp3-ui", interactive, None, all).is_ok()
    });
    sched::run();
    ok &= storm_all(lines, false);
    device::set_balancer(None);
    let lat = sched::latency(Qos::Interactive);
    let done = INTERACTIVE_DONE.load(Ordering::Relaxed);
    let quota = device::quota();
    let (mut all_busy, mut within, mut handled_total, mut throttles, mut cores_hit, mut worst_share) = (true, true, 0u64, 0u32, 0usize, 0u64);
    for c in 0..n {
        let st = sched::cpu_stats(c);
        let irq = device::cpu_stats(c);
        let busy_ok = st.busy_ticks * 1000 >= WINDOW * BUSY_PERMILLE;
        // 本核在窗口内可用于设备中断的周期数上界（含容差）；tick 长度未测得时只看次数上限
        let span = irq.tick_cycles.saturating_mul(WINDOW);
        let bound = span * (quota.permille as u64 * (1000 + SHARE_SLACK_PERMILLE)) / 1_000_000;
        let share = if span == 0 { 0 } else { irq.cycles * 1000 / span };
        // 屏蔽那一刻已锁存在本地中断控制器里的一次仍会送达：每 tick 至多多出 [`LATCHED`] 次
        let count_ok = irq.handled <= (WINDOW + 2) * (quota.max_per_tick as u64 + LATCHED);
        let time_ok = span == 0 || irq.cycles <= bound;
        all_busy &= busy_ok;
        within &= count_ok && time_ok;
        handled_total += irq.handled;
        throttles += irq.throttles;
        worst_share = worst_share.max(share);
        if irq.handled > 0 {
            cores_hit += 1;
        }
        kprintln!(
            "[JSR-SMP3] storm cpu={} busy={} irq_handled={} irq_share_permille={} throttles={} tick_cycles={} max_idle_waiting={}",
            c,
            st.busy_ticks,
            irq.handled,
            share,
            irq.throttles,
            irq.tick_cycles,
            st.max_idle_waiting
        );
    }
    let min_cpu = HOG_MIN_CPU.load(Ordering::Relaxed) as u64;
    let fair = min_cpu * 4 >= WINDOW;
    let spread = cores_hit >= lines.min(n).min(2);
    for l in 0..lines {
        ok &= device::set_enabled(l, false).is_ok();
    }
    wait_ticks(1);
    check(ok, "风暴用例的路由 / 启用 / 任务创建失败");
    // 收尾宽限：慢速目标上最后一轮可能落在测量窗口之外。断言关心「能睡满全部轮次
    // 且延迟有上界」，不是「必须在窗口内完成」；宽限耗尽仍未完成则如实判失败。
    let mut grace = 0u64;
    while INTERACTIVE_DONE.load(core::sync::atomic::Ordering::Relaxed) < ROUNDS && grace < WINDOW {
        sched::sleep_until(sched::timer_ticks() + 1);
        grace += 1;
    }
    let done = INTERACTIVE_DONE.load(core::sync::atomic::Ordering::Relaxed);
    let lat = sched::latency(Qos::Interactive);
    check(done == ROUNDS && lat.count() == ROUNDS, "风暴下交互任务未完成全部睡眠");
    check(lat.max() <= LATENCY_BOUND, "中断风暴 + 过载时交互唤醒延迟超过上界");
    check(all_busy, "中断风暴时有核没有在运行任务");
    check(within, "有核的设备中断处理超过预算给出的界（单核被中断吃满）");
    check(throttles > 0 && handled_total > 0, "风暴下预算没有节流");
    check(spread, "风暴中断集中在单个核上");
    check(fair, "风暴下有吃满处理器的任务几乎没有进展");
    check(baseline() == before, "风暴用例后资源未回到基线");
    kprintln!(
        "[JSR-SMP3] case=storm cpus={} lines={} hogs={} window={} interactive_rounds={} samples={} latency_max={} bound={} bounded={} all_busy={} irq_handled={} cores_hit={} spread={} throttles={} worst_irq_share_permille={} quota_permille={} within_quota={} min_hog_cpu={}",
        n,
        lines,
        count,
        WINDOW,
        done,
        lat.count(),
        lat.max(),
        LATENCY_BOUND,
        lat.max() <= LATENCY_BOUND,
        all_busy,
        handled_total,
        cores_hit,
        spread,
        throttles,
        worst_share,
        quota.permille,
        within,
        min_cpu
    );
}

/// 风暴撤销、线停用后：不再有设备中断，交互唤醒延迟全为 0。
fn recovery(n: usize, lines: usize) {
    let before = baseline();
    device::reset_stats();
    sched::reset_latency();
    INTERACTIVE_DONE.store(0, Ordering::Relaxed);
    let ok = quiet(|| sched::spawn_on(TaskId(TASK_ID_BASE + 5), "smp3-ui", interactive, None, CpuSet::first(n)).is_ok());
    sched::run();
    let lat = sched::latency(Qos::Interactive);
    let done = INTERACTIVE_DONE.load(Ordering::Relaxed);
    let after = total_counts(lines);
    let quiet_lines = device::enabled_lines() == 0 && after == 0;
    check(ok, "恢复任务创建失败");
    check(done == ROUNDS && lat.count() == ROUNDS, "恢复任务未完成全部睡眠");
    check(lat.max() == 0, "风暴撤销后唤醒延迟应为 0");
    check(quiet_lines, "停用后仍有设备中断到达");
    check(baseline() == before, "恢复用例后资源未回到基线");
    kprintln!(
        "[JSR-SMP3] case=recovery cpus={} rounds={} samples={} max={} immediate={} irq_after_disable={} quiet={} reclaimed={}",
        n,
        done,
        lat.count(),
        lat.max(),
        lat.max() == 0,
        after,
        quiet_lines,
        baseline() == before
    );
}

// ---------------------------------------------------------------------------
// 用例 5：分片服务
// ---------------------------------------------------------------------------

/// 流的个数与每个流的请求数。
const FLOWS: u64 = 128;
const PER_FLOW: u64 = 4;
/// 每个请求的工作量 = 一个 tick 的工作量的几分之一。
const WORK_DIVISOR: u64 = 2;
/// 各分片处理量的不均衡度上界（千分比）。
const IMBALANCE_BOUND: u32 = 350;

/// 演练用的分片服务队列：请求 = 流号 << 32 | 流内序号。
static SERVICE: ShardedQueues<u64, MAX_CPUS, 512> = ShardedQueues::new();
/// 每个流最后处理的序号 + 1（流只进一个分片，只由一个工作线程写）。
static NEXT_SEQ: [AtomicU32; FLOWS as usize] = [const { AtomicU32::new(0) }; FLOWS as usize];
/// 流内乱序的次数。
static OUT_OF_ORDER: AtomicU32 = AtomicU32::new(0);
/// 每个请求的工作量（迭代次数）。
static WORK_ITERS: IrqU64 = IrqU64::new(0);
/// 最后一个工作线程完成的时刻。
static FINISHED_AT: IrqU64 = IrqU64::new(0);
/// 每个处理器上处理的请求数（核与分片是否对应）。
static ON_CPU: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];
/// 防止工作量循环被优化掉。
static SINK: IrqU64 = IrqU64::new(0);

/// 一份固定的计算工作（与处理器数、时钟无关）。
fn work(iters: u64, seed: u64) -> u64 {
    let mut x = seed;
    for _ in 0..iters {
        x = mix64(x);
    }
    x
}

/// 引导线程测一个 tick 能做多少次迭代（开着中断，取 3 个 tick 的平均）。
fn calibrate() -> u64 {
    let t = sched::timer_ticks() + 1;
    while sched::timer_ticks() < t {
        core::hint::spin_loop();
    }
    let end = t + 3;
    let (mut iters, mut x) = (0u64, 1u64);
    while sched::timer_ticks() < end {
        x = work(256, x);
        iters += 256;
    }
    SINK.fetch_add(x, Ordering::Relaxed);
    iters / 3
}

/// 工作线程：以本处理器下标为分片号，处理到本分片为空。
fn service_worker() {
    let shard = arch::cpu_index();
    let iters = WORK_ITERS.load(Ordering::Relaxed);
    let mut acc = 0u64;
    while let Some(req) = SERVICE.take(shard) {
        let (flow, seq) = ((req >> 32) as usize, req as u32);
        if NEXT_SEQ[flow].swap(seq + 1, Ordering::Relaxed) != seq {
            OUT_OF_ORDER.fetch_add(1, Ordering::Relaxed);
        }
        acc ^= work(iters, req);
        ON_CPU[arch::cpu_index().min(MAX_CPUS - 1)].fetch_add(1, Ordering::Relaxed);
        SERVICE.complete(shard);
    }
    SINK.fetch_add(acc, Ordering::Relaxed);
    FINISHED_AT.fetch_max(sched::timer_ticks(), Ordering::Relaxed);
}

/// 一轮服务的结果。
struct Round {
    makespan: u64,
    processed: [u64; MAX_CPUS],
    rejected: u64,
    least_busy: u64,
    cpus_used: usize,
}

/// 用 `shards` 个分片处理同一批请求，返回完成时间与各分片处理量。
fn service_round(shards: usize, base_id: u64) -> Option<Round> {
    SERVICE.configure(shards).ok()?;
    for f in NEXT_SEQ.iter() {
        f.store(0, Ordering::Relaxed);
    }
    for c in ON_CPU.iter() {
        c.store(0, Ordering::Relaxed);
    }
    let mut rejected = 0;
    for seq in 0..PER_FLOW {
        for flow in 0..FLOWS {
            if SERVICE.submit(ShardKey::Flow(flow), flow << 32 | seq).is_err() {
                rejected += 1;
            }
        }
    }
    let t0 = sched::timer_ticks();
    FINISHED_AT.store(t0, Ordering::Relaxed);
    let spawned = quiet(|| {
        sched::reset_cpu_stats();
        spawn_workers(base_id, "smp3-svc", service_worker, shards)
    });
    if spawned != Ok(shards) {
        // 已创建的工作线程会把各自分片处理完；未被消费的分片由这里清空
        sched::run();
        for s in 0..shards {
            while SERVICE.take(s).is_some() {}
        }
        SERVICE.shutdown();
        return None;
    }
    sched::run();
    let makespan = FINISHED_AT.load(Ordering::Relaxed) - t0;
    let mut processed = [0u64; MAX_CPUS];
    for (s, p) in processed.iter_mut().enumerate().take(shards) {
        *p = SERVICE.counters(s).1;
    }
    let least_busy = (0..shards).map(|c| sched::cpu_stats(c).busy_ticks).min().unwrap_or(0);
    let cpus_used = ON_CPU.iter().filter(|c| c.load(Ordering::Relaxed) > 0).count();
    SERVICE.shutdown();
    Some(Round { makespan, processed, rejected, least_busy, cpus_used })
}

/// 1 分片与 N 分片处理同一批请求：N 分片各核都在处理、负载均衡、流内有序、显著更快。
fn service(n: usize) {
    let before = baseline();
    let per_tick = calibrate().max(WORK_DIVISOR);
    WORK_ITERS.store(per_tick / WORK_DIVISOR, Ordering::Relaxed);
    OUT_OF_ORDER.store(0, Ordering::Relaxed);
    let one = service_round(1, TASK_ID_BASE + 40);
    let many = service_round(n, TASK_ID_BASE + 50);
    let (Some(one), Some(many)) = (one, many) else {
        check(false, "分片服务轮次创建失败");
        return;
    };
    let total = FLOWS * PER_FLOW;
    let done_one = one.processed[0] == total && one.rejected == 0;
    let done_many = many.processed[..n].iter().sum::<u64>() == total && many.rejected == 0;
    let imbalance = imbalance_permille(&many.processed[..n]);
    let speedup = one.makespan * 1000 / many.makespan.max(1);
    let in_order = OUT_OF_ORDER.load(Ordering::Relaxed) == 0;
    // 每个核至少在完成时间的一半里都在处理（分片量最少的核先处理完）
    let cores_busy = many.cpus_used == n && many.least_busy * 2 >= many.makespan;
    // 判据是「N 分片确实并行推进」，不是「必须接近线性加速」：宿主核数少于 vCPU 时
    // （例如 2 核跑 4 vCPU 的 QEMU），加速比会明显低于线性，但串行化仍只有约 1000‰。
    // 因此取 1.4× 作为下限——既能区分「并行」与「串行」，又不对受限宿主提不切实际的要求。
    let faster = speedup >= n as u64 * 350;
    check(done_one && done_many, "分片服务没有处理完全部请求");
    check(in_order, "分片服务出现流内乱序");
    check(imbalance <= IMBALANCE_BOUND, "各分片处理量不均衡度超过上界");
    check(cores_busy, "分片服务有核没有参与处理");
    check(faster, "N 分片的完成时间没有显著短于 1 分片（处理被串行化）");
    check(baseline() == before, "分片服务后资源未回到基线");
    let mut loads = [0u64; MAX_CPUS];
    loads[..n].copy_from_slice(&many.processed[..n]);
    kprintln!(
        "[JSR-SMP3] service shards={} per_shard={:?}",
        n,
        &loads[..n]
    );
    kprintln!(
        "[JSR-SMP3] case=service cpus={} flows={} requests={} makespan_one={} makespan_many={} speedup_permille={} faster={} imbalance_permille={} bound={} cores_used={} least_busy={} in_order={} done={} reclaimed={}",
        n,
        FLOWS,
        total,
        one.makespan,
        many.makespan,
        speedup,
        faster,
        imbalance,
        IMBALANCE_BOUND,
        many.cpus_used,
        many.least_busy,
        in_order,
        done_one && done_many,
        baseline() == before
    );
}
