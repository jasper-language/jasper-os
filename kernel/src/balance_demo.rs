//! 每核运行队列与负载均衡的验收演练：各核都忙、空闲窃取、过载下交互延迟有上界、压力撤销后立即恢复、
//! 亲和集合与迁移、跨核优先级继承、跨核 CPU 上限、拒绝路径。
//! Acceptance drill for per-CPU run queues and load balancing.
//!
//! # 为什么要有这个演练
//! 放置 / 窃取 / 周期均衡的决定在宿主上有确定性测试；这里验证机制接上之后，在真实的多处理器、
//! 各核本地时钟与核间中断下：吃满处理器的任务铺满所有核，没有「一核跑满、多核围观」；
//! 交互任务在全部核都过载时唤醒延迟仍有上界；压力撤销后立即恢复。
//!
//! # 用例（只有一个处理器时如实报告，只演练拒绝路径）
//! 1. **铺满**：N 核 N 个吃满处理器的任务：每个核的忙碌 tick ≥ 窗口的 [`BUSY_PERMILLE`]‰，
//!    「本核空闲而别处有任务在等」的连续时长不超过 [`IDLE_BOUND`]。
//! 2. **窃取**：2N 个任务全部先放在引导处理器的队列里，再放宽亲和集合：其他核在有界时间内窃取，各核都忙。
//! 3. **过载 + 交互**：2N 个吃满处理器的任务 + 1 个反复睡眠的交互档任务：各核都忙、交互唤醒延迟 ≤ [`LATENCY_BOUND`]，
//!    每个吃满处理器的任务都有进展。
//! 4. **恢复**：压力撤销后交互任务连续睡眠，唤醒延迟都是 0，各核回到空闲。
//! 5. **亲和与迁移**：钉在某核的任务只在该核运行；改亲和集合后（他人修改、自己修改）只在新核运行；
//!    空集合 / 不存在的任务 / 只含离线核的集合被拒绝，亲和与运行位置不变。
//! 6. **跨核优先级继承**：后台档持锁者 + 2N 个工具档任务压满全部核 + 交互档任务来要锁：等待 ≤ 工作量 + 2 tick。
//! 7. **跨核 CPU 上限**：一个组的 N 个成员分散在各核同时运行：整组用量不超过单组上限给出的界（多核合计计费）。
//!
//! 每个用例结束后检查资源回到用例前的基线。

use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

use kernel_core::smp::{CpuSet, MAX_CPUS};

use crate::baseline::baseline;
use crate::sched::policy::Qos;
use crate::sched::scheduler::SpawnError;
use crate::sched::{AffinityError, KMutex};
use crate::sync::IrqU64;
use crate::task::TaskId;
use crate::{arch, kprintln, sched};

static CHECKS: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);

fn check(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-SMP2-FAIL] {}", what);
    }
}

/// 失败断言数。
/// Number of failed assertions.
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

/// 本演练的内核任务号起点（与其它演练不重叠）。
const TASK_ID_BASE: u64 = 9700;
/// 吃满处理器的窗口（tick）。
const WINDOW: u64 = 60;
/// 每个核在窗口内至少忙碌的千分比。
const BUSY_PERMILLE: u64 = 850;
/// 「本核空闲而别处有可运行任务在等」的连续时长上界（tick）。
const IDLE_BOUND: u32 = 2;
/// 过载时交互档任务的唤醒延迟上界（tick）：远端核在下一个本地 tick 抢占 + 时钟粒度。
const LATENCY_BOUND: u64 = 2;
/// 交互任务的睡眠次数。
const ROUNDS: u32 = 20;
/// 持锁者在临界区内还需的处理器时间（tick）。
const WORK: u64 = 4;
/// CPU 上限用例的上限（千分比）与窗口（tick）。
const LIMIT_PERMILLE: u32 = 250;
const LIMIT_WINDOW: u64 = 160;

/// 演练用的锁（锁内数据：进入临界区的次数）。
static LOCK: KMutex<u64> = KMutex::new(0);

/// 吃满处理器的任务的截止时刻。
static HOG_END: IrqU64 = IrqU64::new(0);
/// 吃满处理器的任务里最少的运行 tick 数（每个任务结束时取最小；多个处理器同时写，用原子取小）。
static HOG_MIN_CPU: AtomicU32 = AtomicU32::new(u32::MAX);
/// 吃满处理器的任务曾运行过的处理器的并集。
static HOG_CPUS: AtomicU32 = AtomicU32::new(0);
/// 交互任务完成的睡眠次数。
static INTERACTIVE_DONE: AtomicU32 = AtomicU32::new(0);

/// 当前任务累计运行的 tick 数。
fn my_cpu() -> u64 {
    sched::cpu_ticks(sched::current().0).unwrap_or(0)
}

/// 把当前内核任务提升到交互档（内核内的创建方先授予上限，再提升）。
fn become_interactive() -> bool {
    sched::set_current_qos_ceiling(Some(Qos::Interactive));
    sched::set_current_qos(Qos::Interactive).is_ok()
}

/// 只含处理器 `c` 的集合。
fn only(c: usize) -> CpuSet {
    let mut s = CpuSet::EMPTY;
    s.insert(c);
    s
}

/// 工具档、吃满处理器直到 [`HOG_END`]；记下自己的运行量与到过的处理器。
fn hog() {
    let _ = sched::set_current_qos(Qos::Utility);
    let start = my_cpu();
    while sched::timer_ticks() < HOG_END.load(Ordering::Relaxed) {
        HOG_CPUS.fetch_or(1 << arch::cpu_index(), Ordering::Relaxed);
        core::hint::spin_loop();
    }
    let used = (my_cpu() - start).min(u32::MAX as u64 - 1) as u32;
    HOG_MIN_CPU.fetch_min(used, Ordering::Relaxed);
}

/// 继承用例里的工具档任务：等持锁者拿到锁之后才开始吃满处理器（否则后台档持锁者可能迟迟拿不到锁）。
fn pi_hog() {
    while PI_HOLDING.load(Ordering::Relaxed) == 0 {
        sched::pause();
    }
    hog();
}

/// 在关闭抢占的情况下执行 `f`（批量创建任务期间引导线程不被自己刚创建的任务抢走处理器），之后恢复。
fn quiet<R>(f: impl FnOnce() -> R) -> R {
    let prev = sched::set_preemption(false);
    let r = f();
    sched::set_preemption(prev);
    r
}

/// 交互档：反复睡 1 tick，共 [`ROUNDS`] 次（唤醒延迟由调度器记入交互档直方图）。
fn interactive() {
    if !become_interactive() {
        return;
    }
    for _ in 0..ROUNDS {
        sched::sleep_until(sched::timer_ticks() + 1);
        INTERACTIVE_DONE.fetch_add(1, Ordering::Relaxed);
    }
}

/// 各核在本场景中的统计是否满足「都忙、空闲等待有界」，并输出一行。
fn cores_busy(case: &str, n: usize, window: u64) -> bool {
    let mut all = true;
    let (mut steals, mut pulls, mut hot, mut worst_idle, mut least_busy) = (0u32, 0u32, 0u32, 0u32, u64::MAX);
    for c in 0..n {
        let st = sched::cpu_stats(c);
        let busy_ok = st.busy_ticks * 1000 >= window * BUSY_PERMILLE;
        let idle_ok = st.max_idle_waiting <= IDLE_BOUND;
        all &= busy_ok && idle_ok;
        steals += st.steals;
        pulls += st.pulls;
        hot += st.pull_hot;
        worst_idle = worst_idle.max(st.max_idle_waiting);
        least_busy = least_busy.min(st.busy_ticks);
        kprintln!(
            "[JSR-SMP2] core case={} cpu={} busy={} idle={} max_idle_waiting={} steals={} pulls={} pull_hot={}",
            case,
            c,
            st.busy_ticks,
            st.idle_ticks,
            st.max_idle_waiting,
            st.steals,
            st.pulls,
            st.pull_hot
        );
    }
    kprintln!(
        "[JSR-SMP2] cores case={} cpus={} window={} least_busy={} worst_idle_waiting={} idle_bound={} steals={} pulls={} pull_hot={} all_busy={}",
        case,
        n,
        window,
        least_busy,
        worst_idle,
        IDLE_BOUND,
        steals,
        pulls,
        hot,
        all
    );
    all
}

/// 运行全部用例；演练期间保持抢占开启，结束时恢复进入前的设置。
pub fn run() {
    let prev_preemption = sched::set_preemption(true);
    let start = baseline();
    let online = sched::online_cpus();
    let n = online.len();
    refusals(online);
    if n > 1 {
        spread(n);
        steal(n);
        overload(n);
        recovery(n);
        affinity(n);
        inherit(n);
        limit(n);
    } else {
        kprintln!("[JSR-SMP2] single cpus=1 balance=skipped");
    }
    let end = baseline();
    check(end == start, "演练结束后资源未回到起点");
    sched::set_preemption(prev_preemption);
    kprintln!(
        "[JSR-SMP2] summary cpus={} free_frames={}/{} objects={}/{} reclaimed={} checks={} failed={}",
        n,
        end.free_frames,
        start.free_frames,
        end.objects,
        start.objects,
        end == start,
        CHECKS.load(Ordering::Relaxed),
        failed()
    );
}

/// 重置吃满处理器任务的记录，设截止时刻。
fn arm_hogs(window: u64) {
    HOG_MIN_CPU.store(u32::MAX, Ordering::Relaxed);
    HOG_CPUS.store(0, Ordering::Relaxed);
    HOG_END.store(sched::timer_ticks() + window, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// 拒绝路径
// ---------------------------------------------------------------------------

/// 空亲和集合、只含离线处理器的集合、不存在的任务：全部被拒，任务数与资源不变。
fn refusals(online: CpuSet) {
    let before = baseline();
    let live = sched::live_workers();
    let empty = sched::spawn_on(TaskId(TASK_ID_BASE), "smp2-bad", hog, None, CpuSet::EMPTY);
    let offline = (0..MAX_CPUS).find(|&c| !online.contains(c));
    let off = offline.map(|c| sched::spawn_on(TaskId(TASK_ID_BASE + 1), "smp2-bad", hog, None, only(c)));
    let no_task = sched::set_affinity(TaskId(TASK_ID_BASE + 99), online);
    let boot = sched::set_affinity(TaskId(0), online);
    let ok_empty = matches!(empty, Err(SpawnError::BadAffinity));
    let ok_off = off.is_none_or(|r| matches!(r, Err(SpawnError::BadAffinity)));
    let ok_none = no_task == Err(AffinityError::NoTask) && boot == Err(AffinityError::NoTask);
    let unchanged = sched::live_workers() == live && baseline() == before;
    check(ok_empty, "空亲和集合应被拒绝");
    check(ok_off, "只含离线处理器的亲和集合应被拒绝");
    check(ok_none, "不存在的任务 / 引导线程改亲和应被拒绝");
    check(unchanged, "被拒绝后留下了任务或资源");
    kprintln!(
        "[JSR-SMP2] case=refusals empty_set={} offline_only={} no_task={} boot_thread={} unchanged={}",
        if ok_empty { "refused" } else { "accepted" },
        if offline.is_none() { "n/a" } else if ok_off { "refused" } else { "accepted" },
        if no_task == Err(AffinityError::NoTask) { "refused" } else { "accepted" },
        if boot == Err(AffinityError::NoTask) { "refused" } else { "accepted" },
        unchanged
    );
}

// ---------------------------------------------------------------------------
// 用例 1–4：铺满、窃取、过载 + 交互、恢复
// ---------------------------------------------------------------------------

/// N 核 N 个吃满处理器的任务：放置时即铺满各核。
fn spread(n: usize) {
    let before = baseline();
    let all = CpuSet::first(n);
    let spawned = quiet(|| {
        sched::reset_cpu_stats();
        arm_hogs(WINDOW);
        (0..n).all(|i| sched::spawn_on(TaskId(TASK_ID_BASE + 10 + i as u64), "smp2-hog", hog, None, all).is_ok())
    });
    check(spawned, "铺满用例任务创建失败");
    sched::run();
    let busy = cores_busy("spread", n, WINDOW);
    let covered = HOG_CPUS.load(Ordering::Relaxed) == all.bits();
    let least_cpu = HOG_MIN_CPU.load(Ordering::Relaxed) as u64;
    check(busy, "N 核 N 任务时有核空闲或空闲等待超过上界");
    check(covered, "吃满处理器的任务没有铺到每一个核");
    check(least_cpu * 1000 >= WINDOW * BUSY_PERMILLE, "每个任务应独占约一个核");
    check(baseline() == before, "铺满用例后资源未回到基线");
    kprintln!(
        "[JSR-SMP2] case=spread cpus={} tasks={} window={} cores_covered={} min_task_cpu={} all_busy={}",
        n,
        n,
        WINDOW,
        covered,
        least_cpu,
        busy
    );
}

/// 2N 个任务先全部放在引导处理器的队列里，再放宽亲和集合：其他核必须把它们窃取过去。
fn steal(n: usize) {
    let before = baseline();
    let all = CpuSet::first(n);
    let count = 2 * n as u64;
    // 全部任务在引导处理器的队列里排好、亲和放宽之后才开始调度（抢占关闭期间引导线程不被换下）
    let ok = quiet(|| {
        sched::reset_cpu_stats();
        arm_hogs(WINDOW);
        let mut ok = true;
        for i in 0..count {
            ok &= sched::spawn_on(TaskId(TASK_ID_BASE + 20 + i), "smp2-steal", hog, None, only(0)).is_ok();
        }
        for i in 0..count {
            ok &= sched::set_affinity(TaskId(TASK_ID_BASE + 20 + i), all).is_ok();
        }
        ok
    });
    check(ok, "窃取用例任务创建或放宽亲和失败");
    sched::run();
    let busy = cores_busy("steal", n, WINDOW);
    let steals: u32 = (0..n).map(|c| sched::cpu_stats(c).steals).sum();
    let covered = HOG_CPUS.load(Ordering::Relaxed) == all.bits();
    check(busy, "窃取用例中有核空闲或空闲等待超过上界");
    check(steals as usize >= n - 1, "其他核应从引导处理器的队列窃取任务");
    check(covered, "窃取后任务没有铺到每一个核");
    check(baseline() == before, "窃取用例后资源未回到基线");
    kprintln!(
        "[JSR-SMP2] case=steal cpus={} tasks={} queued_on=cpu0 steals={} cores_covered={} all_busy={}",
        n,
        count,
        steals,
        covered,
        busy
    );
}

/// 2N 个吃满处理器的任务 + 1 个交互档任务：交互唤醒延迟有上界，各核都忙。
fn overload(n: usize) {
    let before = baseline();
    let all = CpuSet::first(n);
    let count = 2 * n as u64;
    let window = 2 * WINDOW;
    let ok = quiet(|| {
        sched::reset_cpu_stats();
        sched::reset_latency();
        INTERACTIVE_DONE.store(0, Ordering::Relaxed);
        arm_hogs(window);
        let mut ok = true;
        for i in 0..count {
            ok &= sched::spawn_on(TaskId(TASK_ID_BASE + 40 + i), "smp2-load", hog, None, all).is_ok();
        }
        ok && sched::spawn_on(TaskId(TASK_ID_BASE + 39), "smp2-ui", interactive, None, all).is_ok()
    });
    check(ok, "过载用例任务创建失败");
    sched::run();
    let lat = sched::latency(Qos::Interactive);
    let busy = cores_busy("overload", n, window);
    let min_cpu = HOG_MIN_CPU.load(Ordering::Relaxed) as u64;
    // 2N 个任务分 N 个核：每个任务约得半个核；至少四分之一视为都有进展（交互任务也占一点）
    let fair = min_cpu * 4 >= window;
    let done = INTERACTIVE_DONE.load(Ordering::Relaxed);
    check(done == ROUNDS && lat.count() == ROUNDS, "交互任务未完成全部睡眠");
    check(lat.max() <= LATENCY_BOUND, "全部核过载时交互唤醒延迟超过上界");
    check(busy, "过载时有核空闲或空闲等待超过上界");
    check(fair, "过载时有吃满处理器的任务几乎没有进展");
    check(baseline() == before, "过载用例后资源未回到基线");
    kprintln!(
        "[JSR-SMP2] case=overload cpus={} hogs={} window={} interactive_rounds={} samples={} latency_max={} bound={} bounded={} min_hog_cpu={} all_busy={}",
        n,
        count,
        window,
        done,
        lat.count(),
        lat.max(),
        LATENCY_BOUND,
        lat.max() <= LATENCY_BOUND,
        min_cpu,
        busy
    );
}

/// 压力撤销后：交互任务连续睡眠，唤醒延迟都是 0，各核几乎全空闲。
fn recovery(n: usize) {
    let before = baseline();
    sched::reset_cpu_stats();
    sched::reset_latency();
    INTERACTIVE_DONE.store(0, Ordering::Relaxed);
    let t0 = sched::timer_ticks();
    let ok = quiet(|| sched::spawn_on(TaskId(TASK_ID_BASE + 60), "smp2-ui", interactive, None, CpuSet::first(n)).is_ok());
    check(ok, "恢复任务创建失败");
    sched::run();
    let span = sched::timer_ticks() - t0;
    let lat = sched::latency(Qos::Interactive);
    let busy: u64 = (0..n).map(|c| sched::cpu_stats(c).busy_ticks).sum();
    let done = INTERACTIVE_DONE.load(Ordering::Relaxed);
    check(done == ROUNDS && lat.count() == ROUNDS, "恢复任务未完成全部睡眠");
    check(lat.max() == 0, "压力撤销后唤醒延迟应为 0");
    // 只剩一个几乎不占处理器的任务：全部核合计的忙碌 tick 远小于经过的时间
    check(busy * 4 <= span, "压力撤销后各核没有回到空闲");
    check(baseline() == before, "恢复用例后资源未回到基线");
    kprintln!(
        "[JSR-SMP2] case=recovery cpus={} rounds={} samples={} max={} immediate={} span={} busy_all_cores={} reclaimed={}",
        n,
        done,
        lat.count(),
        lat.max(),
        lat.max() == 0,
        span,
        busy,
        baseline() == before
    );
}

// ---------------------------------------------------------------------------
// 用例 5：亲和集合与迁移
// ---------------------------------------------------------------------------

/// 亲和用例的阶段（0 = 钉在原核，1 = 被他人改到新核，2 = 自己改到第三个核，3 = 结束）。
static AFF_PHASE: AtomicU8 = AtomicU8::new(0);
/// 各阶段观察到的运行处理器集合。
static AFF_SEEN: [AtomicU32; 3] = [const { AtomicU32::new(0) }; 3];
/// 自己改亲和之后立即读到的处理器下标。
static AFF_SELF_AFTER: AtomicU32 = AtomicU32::new(u32::MAX);
/// 被他人改亲和之前，第 0 阶段观察到的运行处理器集合（之后迁移途中的记录不算在内）。
static AFF_PINNED_SEEN: AtomicU32 = AtomicU32::new(0);
/// 拒绝路径是否全部被拒且运行位置不变。
static AFF_REFUSED: AtomicU8 = AtomicU8::new(0);
/// 参与用例的三个核：起始、他人修改后、自己修改后。
static AFF_CPUS: [AtomicU32; 3] = [const { AtomicU32::new(0) }; 3];

fn aff_cpu(i: usize) -> usize {
    AFF_CPUS[i].load(Ordering::Relaxed) as usize
}

/// 被钉住的任务：按阶段记录自己运行在哪个核；第 2 阶段自己把亲和改到第三个核。
fn aff_pinned() {
    loop {
        let phase = AFF_PHASE.load(Ordering::Relaxed);
        match phase {
            0 | 1 => {
                AFF_SEEN[phase as usize].fetch_or(1 << arch::cpu_index(), Ordering::Relaxed);
            }
            2 => {
                if AFF_SELF_AFTER.load(Ordering::Relaxed) == u32::MAX {
                    let ok = sched::set_affinity(sched::current().0, only(aff_cpu(2))).is_ok();
                    // 返回时必须已经在新核上运行
                    let here = arch::cpu_index() as u32;
                    AFF_SELF_AFTER.store(if ok { here } else { u32::MAX - 1 }, Ordering::Relaxed);
                }
                AFF_SEEN[2].fetch_or(1 << arch::cpu_index(), Ordering::Relaxed);
            }
            _ => return,
        }
        core::hint::spin_loop();
    }
}

/// 控制者（钉在引导处理器上）：推进阶段、演练拒绝路径、改被钉任务的亲和。
fn aff_control() {
    let id = TaskId(TASK_ID_BASE + 70);
    let wait = |t: u64| sched::sleep_until(sched::timer_ticks() + t);
    wait(10);
    // 拒绝路径：空集合、只含离线核的集合；之后仍只在原核运行
    let empty = sched::set_affinity(id, CpuSet::EMPTY);
    let off = (0..MAX_CPUS).find(|&c| !sched::online_cpus().contains(c)).map(|c| sched::set_affinity(id, only(c)));
    let refused = empty == Err(AffinityError::NoOnlineCpu) && off.is_none_or(|r| r == Err(AffinityError::NoOnlineCpu));
    AFF_SEEN[0].store(0, Ordering::Relaxed);
    wait(6);
    let still = AFF_SEEN[0].load(Ordering::Relaxed) == 1 << aff_cpu(0);
    AFF_REFUSED.store((refused && still) as u8, Ordering::Relaxed);
    AFF_PINNED_SEEN.store(AFF_SEEN[0].load(Ordering::Relaxed), Ordering::Relaxed);
    // 他人修改：改到第二个核；留 2 tick 让迁移完成后再开始记录
    let moved = sched::set_affinity(id, only(aff_cpu(1))).is_ok();
    wait(2);
    AFF_PHASE.store(1, Ordering::Relaxed);
    wait(10);
    if moved {
        AFF_PHASE.store(2, Ordering::Relaxed);
    }
    wait(10);
    AFF_PHASE.store(3, Ordering::Relaxed);
}

fn affinity(n: usize) {
    let before = baseline();
    AFF_PHASE.store(0, Ordering::Relaxed);
    AFF_SELF_AFTER.store(u32::MAX, Ordering::Relaxed);
    AFF_REFUSED.store(0, Ordering::Relaxed);
    AFF_PINNED_SEEN.store(0, Ordering::Relaxed);
    for s in &AFF_SEEN {
        s.store(0, Ordering::Relaxed);
    }
    // 起始核为最后一个核，他人改到 1 号核，自己改到 2 号核（只有两个核时自己改到 0 号核）
    let cpus = [n - 1, 1, if n > 2 { 2 } else { 0 }];
    for (a, c) in AFF_CPUS.iter().zip(cpus) {
        a.store(c as u32, Ordering::Relaxed);
    }
    let ok = quiet(|| {
        sched::spawn_on(TaskId(TASK_ID_BASE + 70), "smp2-pinned", aff_pinned, None, only(cpus[0])).is_ok()
            && sched::spawn_on(TaskId(TASK_ID_BASE + 71), "smp2-ctl", aff_control, None, only(0)).is_ok()
    });
    check(ok, "亲和用例任务创建失败");
    sched::run();
    let mut seen: [u32; 3] = core::array::from_fn(|i| AFF_SEEN[i].load(Ordering::Relaxed));
    seen[0] = AFF_PINNED_SEEN.load(Ordering::Relaxed);
    let pinned = seen[0] == 1 << cpus[0];
    let moved = seen[1] == 1 << cpus[1];
    let self_after = AFF_SELF_AFTER.load(Ordering::Relaxed);
    let self_moved = self_after == cpus[2] as u32 && seen[2] == 1 << cpus[2];
    let refused = AFF_REFUSED.load(Ordering::Relaxed) == 1;
    check(pinned, "钉住的任务跑到了亲和集合之外");
    check(refused, "非法亲和集合应被拒绝且运行位置不变");
    check(moved, "他人改亲和后任务应只在新核运行");
    check(self_moved, "自己改亲和后应立即在新核运行");
    check(baseline() == before, "亲和用例后资源未回到基线");
    kprintln!(
        "[JSR-SMP2] case=affinity pinned_cpu={} seen_pinned={:#x} refused_unchanged={} moved_to={} seen_moved={:#x} self_to={} self_after={} seen_self={:#x} ok={}",
        cpus[0],
        seen[0],
        refused,
        cpus[1],
        seen[1],
        cpus[2],
        self_after as i64,
        seen[2],
        pinned && moved && self_moved && refused
    );
}

// ---------------------------------------------------------------------------
// 用例 6：跨核优先级继承
// ---------------------------------------------------------------------------

static PI_HOLDING: AtomicU8 = AtomicU8::new(0);
static PI_WAIT: IrqU64 = IrqU64::new(u64::MAX);
static PI_HOLDER_PEAK: AtomicU8 = AtomicU8::new(0xFF);

/// 后台档持锁者：拿锁后还需 [`WORK`] 个 tick 的处理器时间；记下自己出现过的最高有效档位。
fn pi_low() {
    let _ = sched::set_current_qos(Qos::Background);
    let Ok(mut g) = LOCK.lock() else { return };
    PI_HOLDING.store(1, Ordering::Relaxed);
    let start = my_cpu();
    let mut best = sched::current_effective_qos();
    while my_cpu() < start + WORK {
        if let (Some(b), Some(q)) = (best, sched::current_effective_qos()) {
            best = Some(b.higher(q));
        }
        core::hint::spin_loop();
    }
    *g += 1;
    drop(g);
    PI_HOLDER_PEAK.store(best.map(|q| q as u8).unwrap_or(0xFF), Ordering::Relaxed);
}

/// 交互档等待者：持锁者拿到锁、全部核压满之后来要锁，记录等待时长。
fn pi_high() {
    if !become_interactive() {
        return;
    }
    while PI_HOLDING.load(Ordering::Relaxed) == 0 {
        sched::pause();
    }
    sched::sleep_until(sched::timer_ticks() + 2);
    let t0 = sched::timer_ticks();
    if let Ok(mut g) = LOCK.lock() {
        *g += 1;
        PI_WAIT.store(sched::timer_ticks() - t0, Ordering::Relaxed);
    }
}

fn inherit(n: usize) {
    let before = baseline();
    let all = CpuSet::first(n);
    PI_HOLDING.store(0, Ordering::Relaxed);
    PI_WAIT.store(u64::MAX, Ordering::Relaxed);
    PI_HOLDER_PEAK.store(0xFF, Ordering::Relaxed);
    let window = 2 * WINDOW;
    let ok = quiet(|| {
        arm_hogs(window);
        let mut ok = sched::spawn_on(TaskId(TASK_ID_BASE + 80), "smp2-pi-low", pi_low, None, all).is_ok();
        for i in 0..2 * n as u64 {
            ok &= sched::spawn_on(TaskId(TASK_ID_BASE + 81 + i), "smp2-pi-hog", pi_hog, None, all).is_ok();
        }
        ok && sched::spawn_on(TaskId(TASK_ID_BASE + 79), "smp2-pi-high", pi_high, None, all).is_ok()
    });
    check(ok, "继承用例任务创建失败");
    sched::run();
    let wait = PI_WAIT.load(Ordering::Relaxed);
    let bound = WORK + 2;
    let peak = Qos::from_raw(PI_HOLDER_PEAK.load(Ordering::Relaxed) as u64);
    check(wait <= bound, "跨核继承时高档任务的等待超过上界");
    check(peak == Some(Qos::Interactive), "持有者应借到交互档");
    check(LOCK.owner().is_none(), "继承用例结束后锁未空闲");
    check(baseline() == before, "继承用例后资源未回到基线");
    kprintln!(
        "[JSR-SMP2] case=inherit cpus={} hogs={} work={} wait={} bound={} bounded={} holder_peak={} lock_free={}",
        n,
        2 * n,
        WORK,
        wait as i64,
        bound,
        wait <= bound,
        peak.map(Qos::name).unwrap_or("none"),
        LOCK.owner().is_none()
    );
}

// ---------------------------------------------------------------------------
// 用例 7：跨核 CPU 上限
// ---------------------------------------------------------------------------

fn limit(n: usize) {
    let before = baseline();
    let groups = sched::live_cpu_groups();
    let Ok(g) = sched::create_cpu_group(LIMIT_PERMILLE) else {
        check(false, "上限用例的 CPU 组创建失败");
        return;
    };
    let all = CpuSet::first(n);
    let ok = quiet(|| {
        arm_hogs(LIMIT_WINDOW);
        (0..n as u64).all(|i| sched::spawn_on(TaskId(TASK_ID_BASE + 90 + i), "smp2-capped", hog, Some(g), all).is_ok())
    });
    check(ok, "上限用例任务创建失败");
    sched::run();
    let st = sched::cpu_group_stats(g);
    let _ = sched::release_cpu_group(g);
    let Some(st) = st else {
        check(false, "上限用例读不到组统计");
        return;
    };
    // 单组上限的界：窗口 × 上限 + 桶容量 + 1；多核同时运行时最后一个可选中 tick 至多再超出 N−1
    let bound = (LIMIT_WINDOW * LIMIT_PERMILLE as u64).div_ceil(1000) + st.burst_ticks as u64 + 1 + (n as u64 - 1);
    let floor = LIMIT_WINDOW * LIMIT_PERMILLE as u64 / 1000 / 2;
    let spread = HOG_CPUS.load(Ordering::Relaxed).count_ones() as usize;
    check(st.used_ticks <= bound, "多核下整组用量超过上限的界");
    check(st.used_ticks >= floor, "上限之内的份额没有用上");
    check(st.throttle_events > 0, "多核下应同样被限速");
    check(spread > 1, "组成员应分散在多个核上运行");
    check(baseline() == before && sched::live_cpu_groups() == groups, "上限用例后资源或 CPU 组未回到基线");
    kprintln!(
        "[JSR-SMP2] case=limit cpus={} members={} limit_permille={} window={} used={} bound={} within={} floor={} throttle_events={} cores_used={}",
        n,
        n,
        LIMIT_PERMILLE,
        LIMIT_WINDOW,
        st.used_ticks,
        bound,
        st.used_ticks <= bound,
        floor,
        st.throttle_events,
        spread
    );
}
