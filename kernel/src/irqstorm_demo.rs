//! DRV-2C-2 演练：真实 virtio-rng 的 MSI-X 中断风暴受每核预算约束，交互任务延迟有上界、到达不丢。
//! DRV-2C-2 demo: a real virtio-rng MSI-X storm is bounded by the per-CPU quota; interactive latency stays bounded and no arrival is lost.
//!
//! # 做什么
//! * 用户程序 `user-irqprobe`（风暴模式）把表项 0 绑定到目标处理器（多处理器时 1 号核，单处理器时 0 号核），
//!   经 Ring 持续提交 `system.device.interrupt.wait` 并累加交付的到达次数；另挂一个长时间的时间等待作为「结束」信号。
//! * 内核驱动任务看到绑定上有等待后，为该表项换上自己的处理函数：每次完成中断**在中断上下文里立即**把同一描述符
//!   放回可用环并通知设备（不分配内存），设备因此持续产生真实 MSI-X 中断。
//!   同时运行 2N 个吃满处理器的任务与 1 个交互任务，窗口 [`WINDOW`] 个 tick。
//! * 每核预算（次数上限调小到 [`STORM_MAX_PER_TICK`]，时间千分比保持默认）用完 ⇒ 分发器屏蔽该表项；
//!   下一个 tick 解除屏蔽，设备在屏蔽期间置挂起位并在解除后重新送达。
//! * 核对：交互唤醒延迟 ≤ [`LATENCY_BOUND`]；各核都忙；目标核上吃满任务有进展；各核中断处理占比不超过预算；
//!   确有节流与重新送达；用户收到的到达总数 = 分发器记录的到达数 = 设备完成数。
//! * 撤销：关闭开关、等设备队列空闲后，有界 tick 内不再有中断，交互唤醒延迟全为 0；
//!   向量、页帧、对象回到基线，表项已屏蔽、功能 MSI-X 已关闭。
//! * 拒绝路径（无残留）：非法预算参数、为未绑定或越界处理器的向量登记屏蔽动作、越界槽位记账。
//!
//! 输出 `[JSR-IRQSTORM] case=storm …`、`case=recover …`、`summary …`；失败输出 `[JSR-IRQSTORM-FAIL] <原因>`。
//! 没有 virtio-rng 时输出 `skipped` 行并视为成功。

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use kernel_core::frame::FRAME_SIZE;
use kernel_core::irq::{CoreQuota, IrqError, QuotaParams};
use kernel_core::msi::{MsiError, MAX_SLOTS};
use kernel_core::objtable::ObjId;
use kernel_core::paging::MapFlags;
use kernel_core::pci::Bdf;
use kernel_core::smp::{CpuSet, MAX_CPUS};
use spin::Mutex;

use crate::irq::{self, device};
use crate::irqring_demo::Rig;
use crate::mm::frame;
use crate::proc::{self, ProcState};
use crate::sched::policy::Qos;
use crate::sync::{IrqSpinLock, IrqU64};
use crate::syscall::{table as abi, SyscallSet};
use crate::task::TaskId;
use crate::{arch, interrupt, kobj, kprintln, mmio, pci, ring, sched, virtio};

/// 用户栈顶部在私有窗口内的偏移（与其它 ELF 演练一致）。
const STACK_OFF: u64 = 0xC0_0000;
/// 本演练内核任务的任务号起点。
const TASK_BASE: u64 = 12_100;
/// 驱动任务等待单个条件的 tick 上界。
const WAIT_TICKS: u64 = 1_000;
/// virtio-rng 队列 0 使用的 MSI-X 表项。
const ENTRY: u16 = 0;
/// 风暴窗口（tick）。
const WINDOW: u64 = 120;
/// 交互任务的睡眠轮数。
const ROUNDS: u32 = 20;
/// 交互唤醒延迟上界（tick）。
const LATENCY_BOUND: u64 = 2;
/// 「核在忙」的门槛：窗口内运行任务的 tick 占比（千分比）。
const BUSY_PERMILLE: u64 = 850;
/// 中断处理时间相对预算的测量容差（千分比）。
const SHARE_SLACK_PERMILLE: u64 = 200;
/// 屏蔽那一刻已发出的消息仍会送达：每 tick 允许多出的次数。
const LATCHED: u64 = 2;
/// 演练期间的每 tick 次数上限：比默认小，保证风暴一定触发节流；时间千分比保持默认。
const STORM_MAX_PER_TICK: u32 = 8;
/// 风暴撤销后观察「不再有中断」的 tick 数。
const QUIET_TICKS: u64 = 5;
/// 用户程序第二个参数的风暴模式标志与目标处理器位置（与 `user-irqprobe` 一致）。
const ARG_STORM: u64 = 1 << 40;
const ARG_TARGET_SHIFT: u32 = 32;
/// 用户程序退出码各字段（与 `user-irqprobe` 一致）。
const EXIT_SUM_MASK: i64 = 0xFFFF_FFFF;
const EXIT_SETUP_OK: i64 = 1 << 32;
const EXIT_FAILED: i64 = 1 << 33;

/// 内嵌的用户程序 `user-irqprobe`（与中断 ring 演练共用）。
static USER_IRQPROBE: &[u8] = include_bytes!(env!("JSR_USER_IRQPROBE"));

static CHECKS: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);

fn check(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-IRQSTORM-FAIL] {}", what);
    }
}

/// 断言失败次数。
/// Number of failed assertions.
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

/// 设备的存放位：中断处理函数与驱动任务都经这把演练局部锁访问（持有期间不取其他锁）。
struct Slot(Option<Rig>);

// SAFETY：队列里的裸指针指向内核独占的 DMA 页（经物理映射访问），不与任何线程绑定；
// 同一时刻只有持有这把锁的一方访问它。
unsafe impl Send for Slot {}

static RIG: IrqSpinLock<Slot> = IrqSpinLock::new(Slot(None));
/// 风暴开关：打开时完成中断立即重新投递描述符。
static STORMING: AtomicBool = AtomicBool::new(false);
/// 设备上是否还有一个未完成的请求。
static OUTSTANDING: AtomicBool = AtomicBool::new(false);
/// 处理函数从已用环取走的完成数。
static COMPLETIONS: AtomicU64 = AtomicU64::new(0);
/// 中断上下文重新投递失败的次数。
static KICK_ERRORS: AtomicU32 = AtomicU32::new(0);

/// 吃满处理器的任务的截止时刻。
static HOG_END: IrqU64 = IrqU64::new(0);
/// 每个处理器上吃满任务的循环次数（目标核的进展由它判定）。
static PROGRESS: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
/// 交互任务完成的睡眠次数。
static INTERACTIVE_DONE: AtomicU32 = AtomicU32::new(0);

/// 驱动任务的输入：设备地址（打包）与用户进程。
static TARGET_BDF: AtomicU32 = AtomicU32::new(0);
static USER_PID: AtomicU64 = AtomicU64::new(0);
/// 驱动任务的输出。
static RESULT: Mutex<Option<Storm>> = Mutex::new(None);
static DRIVER_DONE: AtomicBool = AtomicBool::new(false);

/// 风暴阶段的测量结果。
#[derive(Clone, Copy)]
struct Storm {
    cpu: usize,
    vector: u8,
    spawned: bool,
    kicked: bool,
    all_busy: bool,
    target_progress: bool,
    msi_handled: u64,
    throttles: u32,
    masks: u64,
    redelivered: u64,
    worst_share: u64,
    within: bool,
    idle: bool,
    drained: bool,
    released: bool,
    arrivals: u64,
    completions: u64,
}

/// 风暴处理函数（中断上下文）：记分发 → 取走完成 → 开关打开就立即重新投递，否则标记队列空闲。
fn storm_arrival() {
    interrupt::note_arrival();
    let mut slot = RIG.lock();
    let Some(rig) = slot.0.as_mut() else { return };
    let mut done = 0u64;
    while rig.queue.take_used().is_some() {
        done += 1;
    }
    if done == 0 {
        return;
    }
    COMPLETIONS.fetch_add(done, Ordering::Relaxed);
    if STORMING.load(Ordering::Acquire) {
        if rig.kick().is_err() {
            KICK_ERRORS.fetch_add(1, Ordering::Relaxed);
            OUTSTANDING.store(false, Ordering::Release);
        }
    } else {
        OUTSTANDING.store(false, Ordering::Release);
    }
}

/// 工具档、吃满处理器直到 [`HOG_END`]，按所在处理器记进展。
fn hog() {
    let _ = sched::set_current_qos(Qos::Utility);
    while sched::timer_ticks() < HOG_END.load(Ordering::Relaxed) {
        PROGRESS[arch::cpu_index().min(MAX_CPUS - 1)].fetch_add(1, Ordering::Relaxed);
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

/// 在关闭抢占的情况下执行 `f`（批量创建任务期间不被刚创建的任务抢走处理器），之后恢复。
fn quiet<R>(f: impl FnOnce() -> R) -> R {
    let prev = sched::set_preemption(false);
    let r = f();
    sched::set_preemption(prev);
    r
}

/// 睡到 `end` 时刻。
fn sleep_to(end: u64) {
    while sched::timer_ticks() < end {
        sched::sleep_until(end);
    }
}

/// 有界等待条件成立：每个 tick 醒来检查一次，绝不无限等待。
fn wait_until(mut cond: impl FnMut() -> bool) -> bool {
    let start = sched::timer_ticks();
    loop {
        if cond() {
            return true;
        }
        if sched::timer_ticks().wrapping_sub(start) >= WAIT_TICKS || user_gone() {
            return cond();
        }
        sched::pause();
    }
}

/// 用户进程是否已经退出。
fn user_gone() -> bool {
    match ObjId::from_raw(USER_PID.load(Ordering::Relaxed)) {
        Some(id) => !matches!(proc::state(id), Some(ProcState::Running)),
        None => true,
    }
}

/// 驱动失败时终止用户程序：它停在等不到结束信号的等待上，终止后演练才能回收并报告失败。
fn abort_user() {
    if let Some(id) = ObjId::from_raw(USER_PID.load(Ordering::Relaxed)) {
        if proc::begin_exit(id, -2) {
            kprintln!("[JSR-IRQSTORM-FAIL] driver aborted the user program");
        }
    }
}

/// 风暴目标处理器：多处理器时 1 号核，单处理器时 0 号核。
fn target_cpu(online: CpuSet) -> usize {
    if online.contains(1) {
        1
    } else {
        online.iter().next().unwrap_or(0)
    }
}

/// 驱动任务：等用户绑定 → 换上风暴处理函数 → 加载并开风暴 → 撤销 → 等用户取完到达 → 放行用户。
fn driver() {
    let _ = sched::set_current_qos(Qos::UserInitiated);
    let result = kernel_core::device::unpack_bdf(TARGET_BDF.load(Ordering::Relaxed)).and_then(drive);
    if result.is_none() {
        abort_user();
    }
    *RESULT.lock() = result;
    DRIVER_DONE.store(true, Ordering::Release);
}

fn drive(bdf: Bdf) -> Option<Storm> {
    let mut found = None;
    let bound = wait_until(|| {
        found = interrupt::bound_object(bdf, ENTRY)
            .and_then(|id| interrupt::view(id).map(|v| (id, v)))
            .filter(|(_, v)| v.waiting && v.last_ring.is_some());
        found.is_some()
    });
    let Some((id, v)) = found.filter(|_| bound) else {
        check(false, "用户程序没有建立带等待的中断绑定");
        return None;
    };
    let base_count = irq::msi_count(v.cpu, v.vector);
    let base_masks = interrupt::throttle_masks();
    let base_redelivered = interrupt::redelivered();
    if interrupt::set_driver_handler(bdf, ENTRY, Some(storm_arrival)) != Ok((v.cpu, v.vector)) {
        check(false, "无法为绑定换上风暴处理函数");
        return None;
    }

    let online = sched::online_cpus();
    let n = online.len();
    let all = CpuSet::first(n);
    let end = sched::timer_ticks() + WINDOW;
    let spawned = quiet(|| {
        device::reset_stats();
        sched::reset_cpu_stats();
        sched::reset_latency();
        for p in PROGRESS.iter() {
            p.store(0, Ordering::Relaxed);
        }
        INTERACTIVE_DONE.store(0, Ordering::Relaxed);
        HOG_END.store(end, Ordering::Relaxed);
        let mut ok = true;
        for i in 0..2 * n as u64 {
            ok &= sched::spawn_on(TaskId(TASK_BASE + 10 + i), "irqstorm-load", hog, None, all).is_ok();
        }
        ok && sched::spawn_on(TaskId(TASK_BASE + 1), "irqstorm-ui", interactive, None, all).is_ok()
    });
    STORMING.store(true, Ordering::Release);
    OUTSTANDING.store(true, Ordering::Release);
    let kicked = RIG.lock().0.as_mut().map(|r| r.kick().is_ok()).unwrap_or(false);
    sleep_to(end);

    // 窗口结束时的快照：预算、各核忙碌度与目标核进展
    let quota = device::quota();
    let (mut all_busy, mut within, mut throttles, mut worst_share) = (true, true, 0u32, 0u64);
    for c in online.iter() {
        let st = sched::cpu_stats(c);
        let st_irq = device::cpu_stats(c);
        let span = st_irq.tick_cycles.saturating_mul(WINDOW);
        let bound = span * (quota.permille as u64 * (1000 + SHARE_SLACK_PERMILLE)) / 1_000_000;
        let share = if span == 0 { 0 } else { st_irq.cycles * 1000 / span };
        let count_ok = st_irq.handled <= (WINDOW + 2) * (quota.max_per_tick as u64 + LATCHED);
        all_busy &= st.busy_ticks * 1000 >= WINDOW * BUSY_PERMILLE;
        within &= count_ok && (span == 0 || st_irq.cycles <= bound);
        throttles += st_irq.msi_throttles;
        worst_share = worst_share.max(share);
        kprintln!(
            "[JSR-IRQSTORM] storm cpu={} busy={} msi_handled={} irq_share_permille={} msi_throttles={} tick_cycles={} hog_progress={}",
            c,
            st.busy_ticks,
            st_irq.handled,
            share,
            st_irq.msi_throttles,
            st_irq.tick_cycles,
            PROGRESS[c].load(Ordering::Relaxed)
        );
    }
    let msi_handled = device::cpu_stats(v.cpu).handled;
    let target_progress = PROGRESS[v.cpu].load(Ordering::Relaxed) > 0;

    // 撤销：关开关，等最后一个请求完成（被屏蔽的那次在下一个 tick 解除屏蔽后送达）
    STORMING.store(false, Ordering::Release);
    let idle = wait_until(|| !OUTSTANDING.load(Ordering::Acquire));
    // 用户取走全部到达、重新停在等待上之后才放行它
    let drained = wait_until(|| interrupt::view(id).map(|a| a.waiting && a.pending == 0).unwrap_or(false));
    let arrivals = irq::msi_count(v.cpu, v.vector).wrapping_sub(base_count) as u64;
    let masks = interrupt::throttle_masks() - base_masks;
    let redelivered = interrupt::redelivered() - base_redelivered;
    let _ = interrupt::set_driver_handler(bdf, ENTRY, None);
    let released = v.last_ring.map(ring::kernel_cancel_time_waits).unwrap_or(0) == 1;
    Some(Storm {
        cpu: v.cpu,
        vector: v.vector,
        spawned,
        kicked,
        all_busy,
        target_progress,
        msi_handled,
        throttles,
        masks,
        redelivered,
        worst_share,
        within,
        idle,
        drained,
        released,
        arrivals,
        completions: COMPLETIONS.load(Ordering::Relaxed),
    })
}

/// 拒绝路径：每一项都必须被拒且不留改动。返回 (通过数, 总数)。
fn refusals(target: usize) -> (u32, u32) {
    let (mut ok, mut total) = (0u32, 0u32);
    let mut expect = |pass: bool, what: &str| {
        total += 1;
        check(pass, what);
        if pass {
            ok += 1;
        }
    };
    // 1. 非法预算参数：被拒，各核参数不变
    let before: [Option<QuotaParams>; MAX_CPUS] = core::array::from_fn(device::quota_on);
    let bad = device::set_quota(QuotaParams { permille: 0, max_per_tick: 4 }) == Err(IrqError::BadQuota)
        && device::set_quota(QuotaParams { permille: QuotaParams::MAX_PERMILLE + 1, max_per_tick: 4 }) == Err(IrqError::BadQuota);
    let after: [Option<QuotaParams>; MAX_CPUS] = core::array::from_fn(device::quota_on);
    expect(bad && before == after, "非法预算参数没有被拒或改动了参数");
    // 2. 为未绑定处理函数的向量登记屏蔽动作：被拒，登记表不变
    static NOOP: irq::MsiMaskOps = irq::MsiMaskOps { mask: |_, _, _| {}, unmask: |_, _, _| {} };
    let unbound = (0..MAX_SLOTS as u16).map(|v| v as u8).find(|&v| !irq::msi_is_bound(target, v));
    let refused = unbound.map(|v| irq::msi_set_mask_ops(target, v, Some((&NOOP, 0))) == Err(MsiError::NotAllocated) && !irq::msi_is_bound(target, v));
    expect(refused == Some(true), "为未绑定的向量登记屏蔽动作没有被拒");
    // 3. 越界处理器：被拒
    expect(irq::msi_set_mask_ops(MAX_CPUS, 0, Some((&NOOP, 0))) == Err(MsiError::NoSuchCpu), "越界处理器登记屏蔽动作没有被拒");
    // 4. 越界槽位记账：被拒，预算状态不变
    let mut q = CoreQuota::new(QuotaParams { permille: 250, max_per_tick: 1 });
    let snapshot = (q.stats(), q.msi_throttled(), q.needs_tick());
    let charged = q.charge_msi(MAX_SLOTS, 1_000);
    expect(charged == Err(IrqError::NoLine) && (q.stats(), q.msi_throttled(), q.needs_tick()) == snapshot, "越界槽位记账没有被拒或留下了改动");
    (ok, total)
}

/// 运行演练并输出结果。
/// Run the demo and emit its results.
pub fn run() {
    let Some(device) = pci::table()
        .devices()
        .find(|d| d.header.vendor == virtio::VIRTIO_VENDOR && virtio::is_rng_device(d.header.device))
    else {
        kprintln!("[JSR-IRQSTORM] skipped reason=no_virtio_rng ok=true");
        return;
    };
    let bdf = device.bdf;
    let online = sched::online_cpus();
    let cpus = online.len();
    let target = target_cpu(online);
    let mut mask = 0u64;
    for cpu in online.iter() {
        mask |= 1 << cpu;
    }

    let was_enabled = arch::irq_save_disable();
    arch::irq_enable();
    let prev_preemption = sched::set_preemption(true);
    if let Err(e) = mmio::prepare_window() {
        check(false, e.name());
    }
    let (rejects_ok, rejects_total) = refusals(target);
    let frames_before = frame::free_frames();
    let (live_before, _, _) = kobj::stats();
    let vectors_before = interrupt::vectors_allocated();
    let default_quota = device::quota();
    let storm_quota = QuotaParams { permille: default_quota.permille, max_per_tick: STORM_MAX_PER_TICK };
    check(device::set_quota(storm_quota).is_ok(), "无法设置演练预算");

    let mut exit_code = None;
    match Rig::new(device) {
        Ok(rig) => {
            RIG.lock().0 = Some(rig);
            TARGET_BDF.store(kernel_core::device::pack_bdf(bdf), Ordering::Relaxed);
            let arg = kernel_core::device::pack_bdf(bdf) as u64 | ARG_STORM | (target as u64) << ARG_TARGET_SHIFT;
            exit_code = run_user(mask, arg);
        }
        Err(reason) => check(false, reason),
    }
    check(DRIVER_DONE.load(Ordering::Acquire), "驱动任务没有结束");
    let storm = *RESULT.lock();

    // 用户程序的结果
    let code = exit_code.unwrap_or(-1);
    let user_ok = code >= 0 && code & EXIT_SETUP_OK != 0 && code & EXIT_FAILED == 0;
    let user_delivered = if code >= 0 { (code & EXIT_SUM_MASK) as u64 } else { 0 };
    check(user_ok, "用户程序报告断言失败");

    let lat = sched::latency(Qos::Interactive);
    let done = INTERACTIVE_DONE.load(Ordering::Relaxed);
    let s = storm.unwrap_or(Storm {
        cpu: target,
        vector: 0,
        spawned: false,
        kicked: false,
        all_busy: false,
        target_progress: false,
        msi_handled: 0,
        throttles: 0,
        masks: 0,
        redelivered: 0,
        worst_share: 0,
        within: false,
        idle: false,
        drained: false,
        released: false,
        arrivals: 0,
        completions: 0,
    });
    let lossless = s.arrivals > 0 && s.arrivals == s.completions && user_delivered == s.arrivals;
    check(storm.is_some(), "驱动任务没有完成风暴阶段");
    check(s.spawned && s.kicked, "风暴任务创建或首次投递失败");
    check(KICK_ERRORS.load(Ordering::Relaxed) == 0, "中断上下文重新投递失败");
    check(done == ROUNDS && lat.count() == ROUNDS, "风暴下交互任务未完成全部睡眠");
    check(lat.max() <= LATENCY_BOUND, "MSI 风暴 + 过载时交互唤醒延迟超过上界");
    check(s.all_busy, "MSI 风暴时有核没有在运行任务");
    check(s.target_progress, "风暴目标核上的吃满任务没有进展");
    check(s.within, "有核的中断处理超过预算给出的界（单核被中断吃满）");
    check(s.throttles > 0 && s.masks > 0, "风暴下 MSI 预算没有节流");
    check(s.redelivered > 0, "解除屏蔽后没有重新送达");
    check(s.idle, "风暴撤销后设备队列没有空闲");
    check(s.drained && s.released, "用户程序没有取完到达或无法放行");
    check(lossless, "用户收到的到达数与设备完成数不一致（有丢失）");
    kprintln!(
        "[JSR-IRQSTORM] case=storm cpus={} target={} hogs={} window={} interactive_rounds={} samples={} latency_max={} bound={} bounded={} all_busy={} target_hog_progress={} msi_handled={} throttles={} redelivered={} worst_irq_share_permille={} quota_permille={} within_quota={} arrivals={} user_delivered={} lossless={}",
        cpus,
        s.cpu,
        2 * cpus,
        WINDOW,
        done,
        lat.count(),
        lat.max(),
        LATENCY_BOUND,
        lat.max() <= LATENCY_BOUND,
        s.all_busy,
        s.target_progress,
        s.msi_handled,
        s.throttles,
        s.redelivered,
        s.worst_share,
        storm_quota.permille,
        s.within,
        s.arrivals,
        user_delivered,
        lossless
    );

    // 恢复：设备复位、用户已退出；有界 tick 内不再有中断，交互唤醒延迟全为 0
    drop(RIG.lock().0.take());
    let quiet_before = irq::msi_count(s.cpu, s.vector);
    let spurious_before = irq::msi_spurious(s.cpu);
    sched::reset_latency();
    INTERACTIVE_DONE.store(0, Ordering::Relaxed);
    let spawned = quiet(|| sched::spawn_on(TaskId(TASK_BASE + 2), "irqstorm-ui", interactive, None, CpuSet::first(cpus)).is_ok());
    sched::run();
    let start = sched::timer_ticks();
    sleep_to(start + QUIET_TICKS);
    let storm_after = irq::msi_count(s.cpu, s.vector).wrapping_sub(quiet_before) + irq::msi_spurious(s.cpu).wrapping_sub(spurious_before);
    let lat = sched::latency(Qos::Interactive);
    let rec_done = INTERACTIVE_DONE.load(Ordering::Relaxed);
    check(spawned && rec_done == ROUNDS && lat.count() == ROUNDS, "恢复阶段交互任务未完成全部睡眠");
    check(storm_after == 0, "风暴撤销后仍有中断到达");
    check(lat.max() == 0, "风暴撤销后唤醒延迟应为 0");

    check(device::set_quota(default_quota).is_ok(), "无法恢复默认预算");
    kobj::run_cleanup(usize::MAX);
    let vectors_back = interrupt::vectors_allocated() == vectors_before;
    let msix = interrupt::msix_state(bdf, ENTRY);
    check(vectors_back, "向量没有全部归还");
    check(msix.map(|(n, enabled, masked)| n == 0 && !enabled && masked).unwrap_or(false), "表项未屏蔽或功能 MSI-X 未关闭");
    let (live_after, pending_after, _) = kobj::stats();
    check(live_after == live_before && pending_after == 0, "对象数 / 清理队列未回到基线（有残留句柄）");
    let frames_back = frame::free_frames() == frames_before;
    check(frames_back, "页帧没有回到演练前的基线");
    sched::set_preemption(prev_preemption);
    arch::irq_restore(was_enabled);
    kprintln!(
        "[JSR-IRQSTORM] case=recover storm_after={} latency_max={} vectors_back={} frames_back={}",
        storm_after,
        lat.max(),
        vectors_back,
        frames_back
    );
    kprintln!(
        "[JSR-IRQSTORM] summary cpus={} rejects={}/{} failed={}",
        cpus,
        rejects_ok,
        rejects_total,
        failed()
    );
}

/// 装载并运行用户程序（风暴模式）与驱动任务，回收进程；返回用户程序的退出码。
fn run_user(cpu_mask: u64, arg: u64) -> Option<i64> {
    let allowed = SyscallSet::of(&[
        abi::SYSTEM_CONSOLE_WRITE,
        abi::SYSTEM_DEVICE_OPEN,
        abi::SYSTEM_DEVICE_INTERRUPT_CREATE,
        abi::SYSTEM_DEVICE_INTERRUPT_WAIT,
        abi::SYSTEM_ASYNC_RING_CREATE,
        abi::SYSTEM_ASYNC_RING_ENTER,
        abi::SYSTEM_ASYNC_CANCEL,
        abi::SYSTEM_TIME_WAIT,
        abi::SYSTEM_HANDLE_CLOSE,
        abi::SYSTEM_TASK_EXIT,
    ]);
    let base = arch::USER_WINDOW.0;
    let pid = proc::create("irqstorm", allowed).ok()?;
    let fail = |stage: &str| {
        kprintln!("[JSR-IRQSTORM-FAIL] stage={}", stage);
        FAILED.fetch_add(1, Ordering::Relaxed);
        proc::exit_idle(pid, -1);
        proc::reap(pid);
        kobj::run_cleanup(usize::MAX);
        None
    };
    let Ok(entry) = proc::load_elf(pid, USER_IRQPROBE) else { return fail("load") };
    if proc::map_new(pid, base + STACK_OFF - FRAME_SIZE, MapFlags::USER | MapFlags::WRITE).is_err() {
        return fail("stack");
    }
    USER_PID.store(pid.raw(), Ordering::Relaxed);
    if proc::spawn_thread(pid, "irqstorm", entry, base + STACK_OFF, cpu_mask, arg).is_err() {
        return fail("thread");
    }
    if sched::spawn(TaskId(TASK_BASE), "irqstorm-driver", driver).is_err() {
        check(false, "无法创建驱动任务");
        abort_user();
        DRIVER_DONE.store(true, Ordering::Release);
    }
    sched::run();
    let code = match proc::state(pid) {
        Some(ProcState::Exited { code }) => Some(code),
        _ => None,
    };
    proc::reap(pid);
    kobj::run_cleanup(usize::MAX);
    code
}
