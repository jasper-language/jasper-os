//! 过载防护的验收演练：每进程 CPU 上限、看门狗、内存压力分级准入、压力撤销后回到基线。
//! Acceptance drill for overload protection: per-process CPU limit, watchdog, memory-pressure admission, recovery.
//!
//! # 为什么要有这个演练
//! 上限令牌桶、看门狗判定与压力准入规则本身在宿主上有确定性测试；这里验证的是它们**接进调度机制与
//! 内存管理之后**在真实时钟中断下的效果：失控进程真的被限速、旁观任务真的拿回处理器、交互任务的
//! 唤醒延迟在失控进程 + 内存紧张同时存在时仍有上界、低档内存申请真的在分配任何帧之前被拒。
//!
//! # 用例
//! 1. **规则**：非法上限被拒且组表不变；修改为非法值被拒且上限不变；用已释放的组创建任务被拒且不留任务；
//!    已退出的进程不能设置上限
//! 2. **失控进程（有上限）**：`user/schedtest` role 2（5 个线程吃满 CPU、从不睡眠），进程 CPU 上限
//!    [`LIMIT_PERMILLE`]；同时内存处于「紧张」级、一个同档内核任务吃满 CPU、一个交互档内核任务周期性睡眠。
//!    判据：进程用量不超过令牌桶上界并确有限速；旁观任务拿到多数处理器；交互档唤醒延迟 ≤ 1 tick；
//!    看门狗（阈值临时调到 [`DRILL_WATCHDOG_THRESHOLD`]）记录了失控线程与旁观任务、没有记录交互任务
//! 3. **失控进程（不限速，对照）**：同上但上限为 1000——旁观任务只拿到少数处理器（证明上一用例的差别来自上限）
//! 4. **内存压力准入**：用压舱帧把空闲帧压到「紧张」「危急」「保留线」三级，内核探测任务依次以四个档位申请匿名页：
//!    紧张时只准交互与用户发起、危急时只准交互、保留线下全部拒绝；被拒的申请不分配任何帧、不改动进程帧记账；
//!    用户程序（role 3）在紧张级以后台档申请被拒且没有留下映射；撤掉压舱后全部准入
//! 5. **压力撤销后恢复**：失控进程与压舱都撤掉后，交互任务连续睡眠 [`RECOVERY_ROUNDS`] 次，每次唤醒延迟为 0；
//!    CPU 组全部释放、压力回到「正常」
//!
//! 每个用例结束后检查空闲页帧、存活对象、清理队列、固定帧回到用例前的基线。

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};

use crate::sync::IrqU64;

use kernel_core::frame::PhysFrame;
use kernel_core::objtable::ObjId;
use kernel_core::pressure::PressureLevel;

use crate::mm::{frame, pressure};
use crate::proc::{self, CpuLimitError, MemError, ProcState};
use crate::baseline::baseline;
use crate::rt_demo::{finish_program, rt_calls, start_program};
use crate::sched::policy::{CpuLimit, Qos, CPU_BURST_TICKS};
use crate::sched::scheduler::{GroupError, SpawnError};
use crate::syscall::{table as abi, SyscallSet};
use crate::task::TaskId;
use crate::{arch, kprintln, sched};

static CHECKS: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);

fn check(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-OVL-FAIL] {}", what);
    }
}

/// 失败断言数。
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

/// 过载验收程序 `user/schedtest` 的 ELF 镜像（与服务质量演练共用）。
static USER_SCHEDTEST: &[u8] = include_bytes!(env!("JSR_USER_SCHEDTEST"));

/// 用例 2 的进程 CPU 上限（千分比）。
const LIMIT_PERMILLE: u32 = 250;
/// 旁观任务吃满 CPU 的时长（tick；落在失控进程的运行期内）。
const BYSTANDER_TICKS: u64 = 150;
/// 交互任务的测量轮数与每轮睡眠的 tick 数。
const PROBE_ROUNDS: u32 = 40;
const PROBE_PERIOD: u64 = 2;
/// 用例 5 的睡眠次数。
const RECOVERY_ROUNDS: u32 = 20;
/// 交互档唤醒延迟上界（tick）：严格优先下唯一可能的推迟是一次一个 tick 的最低份额补给。
const LATENCY_BOUND: u64 = 1;
/// 失控用例期间的看门狗阈值（tick）：每个失控线程只分到上限的几分之一，默认阈值在几秒的场景里抓不到它们。
const DRILL_WATCHDOG_THRESHOLD: u32 = 8;
/// 本演练的内核任务号起点（与其它演练的任务号不重叠）。
const TASK_ID_BASE: u64 = 9600;

/// 运行全部用例。演练期间保持抢占开启（默认设置）；结束时恢复进入前的设置。
pub fn run() {
    let prev_preemption = sched::set_preemption(true);
    let start = baseline();
    kprintln!(
        "[JSR-OVL] config cpu_burst={} watchdog_threshold={} pressure_low={}‰ pressure_critical={}‰ reserve_frames={} usable_frames={}",
        CPU_BURST_TICKS,
        sched::watchdog_threshold(),
        pressure::params().low_permille,
        pressure::params().critical_permille,
        pressure::params().reserve_frames,
        frame::usable_frames()
    );
    rules();
    let limited = runaway("limited", LIMIT_PERMILLE);
    let unlimited = runaway("unlimited", 1000);
    check(limited > unlimited, "有上限时旁观任务拿到的处理器应多于不限速对照");
    memory();
    recovery();
    let end = baseline();
    check(end == start, "演练结束后资源未回到起点");
    sched::set_preemption(prev_preemption);
    kprintln!(
        "[JSR-OVL] summary free_frames={}/{} objects={}/{} groups={} level={} reclaimed={} checks={} failed={}",
        end.free_frames,
        start.free_frames,
        end.objects,
        start.objects,
        sched::live_cpu_groups(),
        pressure::level().name(),
        end == start,
        CHECKS.load(Ordering::Relaxed),
        failed()
    );
}

// ---------------------------------------------------------------------------
// 压舱帧：把全局空闲帧压到指定水平（制造内存压力），用完全部归还
// ---------------------------------------------------------------------------

/// 一组暂时占用的物理帧。
struct Ballast {
    frames: Vec<PhysFrame>,
}

impl Ballast {
    /// 预留记录空间（一次性在堆上留够容纳全部可用帧的位置，之后调整水平不再触发堆增长）。
    fn new() -> Option<Self> {
        let mut frames = Vec::new();
        frames.try_reserve_exact(frame::usable_frames()).ok()?;
        Some(Ballast { frames })
    }

    /// 占用或归还帧，使全局空闲帧数等于 `target`（做不到时尽量接近）。
    fn set_free(&mut self, target: usize) {
        while frame::free_frames() > target {
            match frame::allocate() {
                Ok(f) if self.frames.len() < self.frames.capacity() => self.frames.push(f),
                Ok(f) => {
                    let _ = frame::deallocate(f);
                    break;
                }
                Err(_) => break,
            }
        }
        while frame::free_frames() < target {
            match self.frames.pop() {
                Some(f) => {
                    let _ = frame::deallocate(f);
                }
                None => break,
            }
        }
    }

    /// 把空闲帧压到可用帧总数的 `permille` 千分比。
    fn set_free_permille(&mut self, permille: u32) {
        self.set_free(frame::usable_frames() * permille as usize / 1000);
    }

    /// 全部归还。
    fn release(&mut self) {
        while let Some(f) = self.frames.pop() {
            let _ = frame::deallocate(f);
        }
    }
}

impl Drop for Ballast {
    fn drop(&mut self) {
        self.release();
    }
}

/// 「紧张」级中间位置的空闲比例（介于紧张与危急阈值之间）。
fn low_mid_permille() -> u32 {
    let p = pressure::params();
    (p.low_permille + p.critical_permille) / 2
}

// ---------------------------------------------------------------------------
// 用例 1：规则
// ---------------------------------------------------------------------------

fn rules() {
    let before = baseline();
    let groups0 = sched::live_cpu_groups();
    let zero = sched::create_cpu_group(0);
    let over = sched::create_cpu_group(1001);
    let invalid_refused = matches!(zero, Err(GroupError::Limit(_))) && matches!(over, Err(GroupError::Limit(_))) && sched::live_cpu_groups() == groups0;
    check(invalid_refused, "非法上限应被拒且组表不变");

    let mut unchanged = false;
    let mut stale_refused = false;
    if let Ok(g) = sched::create_cpu_group(300) {
        let s0 = sched::cpu_group_stats(g);
        let bad = sched::set_cpu_group_limit(g, 0);
        unchanged = matches!(bad, Err(GroupError::Limit(_))) && sched::cpu_group_stats(g) == s0 && s0.is_some_and(|s| s.limit_permille == 300);
        let released = sched::release_cpu_group(g).is_ok();
        let spawn = sched::spawn_in(TaskId(TASK_ID_BASE), "ovl-stale", filler, g);
        stale_refused = released
            && spawn == Err(SpawnError::BadGroup)
            && sched::release_cpu_group(g) == Err(GroupError::Stale)
            && sched::cpu_group_stats(g).is_none()
            && sched::effective_qos(TaskId(TASK_ID_BASE)).is_none()
            && sched::live_cpu_groups() == groups0;
    }
    check(unchanged, "修改为非法上限应被拒且上限不变");
    check(stale_refused, "已释放的组不能再使用，创建任务被拒且不留任务");

    let exited_refused = match proc::create("ovl-idle", SyscallSet::EMPTY) {
        Ok(pid) => {
            let idle_exit = proc::exit_idle(pid, 0);
            let r = proc::set_cpu_limit(pid, 500);
            let _ = finish_program(pid, true);
            idle_exit && r == Err(CpuLimitError::NoSuchProcess) && sched::live_cpu_groups() == groups0
        }
        Err(_) => false,
    };
    check(exited_refused, "已退出的进程不能设置 CPU 上限");
    let after = baseline();
    check(after == before, "规则用例后资源未回到基线");
    kprintln!(
        "[JSR-OVL] case=rules invalid_refused={} invalid_change_unchanged={} stale_group_refused={} exited_refused={} groups={} reclaimed={}",
        invalid_refused,
        unchanged,
        stale_refused,
        exited_refused,
        sched::live_cpu_groups(),
        after == before
    );
}

fn filler() {}

// ---------------------------------------------------------------------------
// 用例 2、3：失控进程
// ---------------------------------------------------------------------------

/// 旁观任务（同档、吃满 CPU）在其窗口内拿到的 tick 数。
static BYSTANDER_CPU: IrqU64 = IrqU64::new(0);
/// 交互任务完成的睡眠轮数。
static PROBE_DONE: AtomicU32 = AtomicU32::new(0);
/// 交互任务成功升到交互档。
static PROBE_RAISED: AtomicBool = AtomicBool::new(false);

/// 旁观任务：用户发起档（与失控进程同档），吃满 CPU [`BYSTANDER_TICKS`] 个 tick 后记下自己拿到的处理器时间。
fn bystander() {
    let (me, _) = sched::current();
    let end = sched::timer_ticks() + BYSTANDER_TICKS;
    while sched::timer_ticks() < end {
        core::hint::spin_loop();
    }
    BYSTANDER_CPU.store(sched::cpu_ticks(me).unwrap_or(0), Ordering::Relaxed);
}

/// 升到交互档（创建方先授予上限），然后周期性睡眠 `rounds` 次。
fn interactive_sleeper(rounds: u32, period: u64) {
    sched::set_current_qos_ceiling(Some(Qos::Interactive));
    PROBE_RAISED.store(sched::set_current_qos(Qos::Interactive).is_ok(), Ordering::Relaxed);
    for _ in 0..rounds {
        sched::sleep_until(sched::timer_ticks() + period);
        PROBE_DONE.fetch_add(1, Ordering::Relaxed);
    }
}

fn probe_task() {
    interactive_sleeper(PROBE_ROUNDS, PROBE_PERIOD);
}

/// `user/schedtest` 需要的系统调用：运行时的全部调用 + 设置档位。
fn schedtest_calls() -> SyscallSet {
    rt_calls().union(SyscallSet::of(&[abi::SYSTEM_TASK_QOS_SET]))
}

/// 运行一次失控进程场景（进程 CPU 上限 `limit` 千分比；1000 = 不限速的对照），返回旁观任务拿到的处理器千分比。
fn runaway(mode: &'static str, limit: u32) -> u64 {
    let before = baseline();
    BYSTANDER_CPU.store(0, Ordering::Relaxed);
    PROBE_DONE.store(0, Ordering::Relaxed);
    PROBE_RAISED.store(false, Ordering::Relaxed);
    let Some(mut ballast) = Ballast::new() else {
        check(false, "压舱记录空间分配失败");
        return 0;
    };
    // 先压到「紧张」级（失控进程 + 内存压力同时存在），再起任务与进程
    ballast.set_free_permille(low_mid_permille());
    let level = pressure::level();
    check(level == PressureLevel::Low, "失控用例期间内存应处于紧张级");
    sched::reset_latency();
    sched::clear_watchdog();
    let prev_threshold = sched::set_watchdog_threshold(DRILL_WATCHDOG_THRESHOLD);
    // 全部参与者就绪之后才允许运行：抢占开启时，先创建的任务会立刻把引导线程挤下去，
    // 旁观任务的计时窗口就落不到失控进程的运行期内。
    let prev_preemption = sched::set_preemption(false);
    let id = TASK_ID_BASE + if limit < 1000 { 100 } else { 200 };
    let spawned = sched::spawn(TaskId(id), "ovl-probe", probe_task).is_ok() && sched::spawn(TaskId(id + 1), "ovl-bystander", bystander).is_ok();
    check(spawned, "交互任务或旁观任务创建失败");
    let t0 = sched::timer_ticks();
    let Some((pid, started)) = start_program("runaway", USER_SCHEDTEST, 2, schedtest_calls(), |pid| {
        proc::set_cpu_limit(pid, limit).map_err(|_| proc::ProcError::NoTaskSlot)
    }) else {
        sched::set_preemption(prev_preemption);
        check(false, "失控进程创建失败");
        return 0;
    };
    check(started, "失控进程启动失败");
    sched::set_preemption(prev_preemption);
    if started {
        sched::run();
    }
    let window = sched::timer_ticks() - t0;
    sched::set_watchdog_threshold(prev_threshold);
    let stats = proc::cpu_stats(pid);
    let res = finish_program(pid, started);
    ballast.release();

    let used = stats.map(|s| s.used_ticks).unwrap_or(u64::MAX);
    let bound = CpuLimit::new(limit, CPU_BURST_TICKS).map(|l| l.bound(window)).unwrap_or(0);
    let throttled = stats.map(|s| s.throttled_ticks).unwrap_or(0);
    let events = stats.map(|s| s.throttle_events).unwrap_or(0);
    let lat = sched::latency(Qos::Interactive);
    let wd = sched::watchdog_log();
    let wd_runaway = wd.iter().filter(|r| r.name == "runaway" || r.name == "thread").count();
    let wd_bystander = wd.mentions(id + 1);
    let wd_probe = wd.mentions(id);
    let share = BYSTANDER_CPU.load(Ordering::Relaxed) * 1000 / BYSTANDER_TICKS;
    let exit_ok = matches!(res, Some((Some(ProcState::Exited { code: 0 }), Some(0))));
    check(exit_ok, "失控进程未以 0 退出");
    check(PROBE_RAISED.load(Ordering::Relaxed) && PROBE_DONE.load(Ordering::Relaxed) == PROBE_ROUNDS, "交互任务未完成测量");
    check(lat.count() >= PROBE_ROUNDS && lat.max() <= LATENCY_BOUND, "交互档唤醒延迟超过上界");
    check(used <= bound, "进程 CPU 用量超过上限的令牌桶上界");
    check(wd_runaway > 0 && !wd_probe, "看门狗应记录失控线程、不记录交互任务");
    if limit < 1000 {
        check(throttled > 0 && events > 0, "有上限时失控进程应被限速");
        check(share >= 500, "有上限时旁观任务应拿到多数处理器");
        check(wd_bystander, "看门狗应记录长时间吃满 CPU 的旁观任务");
    } else {
        check(throttled == 0, "不限速时不应有限速");
        check(share < 500, "不限速对照中旁观任务应只拿到少数处理器");
    }
    let after = baseline();
    check(after == before && sched::live_cpu_groups() == 0, "失控用例后资源未回到基线或 CPU 组未释放");
    kprintln!(
        "[JSR-OVL] case=runaway mode={} limit={} pressure={} exit={:?} window={} used={} bound={} within={} throttled_ticks={} throttle_events={} bystander_share={}‰ interactive_samples={} p99={} max={} latency_bound={} bounded={} watchdog_runaway={} watchdog_bystander={} watchdog_interactive={} groups={} reclaimed={}",
        mode,
        limit,
        level.name(),
        res.and_then(|r| r.1),
        window,
        used,
        bound,
        used <= bound,
        throttled,
        events,
        share,
        lat.count(),
        lat.percentile(990),
        lat.max(),
        LATENCY_BOUND,
        lat.max() <= LATENCY_BOUND,
        wd_runaway,
        wd_bystander,
        wd_probe,
        sched::live_cpu_groups(),
        after == before
    );
    share
}

// ---------------------------------------------------------------------------
// 用例 4：内存压力准入
// ---------------------------------------------------------------------------

/// 探测进程（没有线程，只用来承载匿名映射）。
static PROBE_PID: IrqU64 = IrqU64::new(0);
/// 探测结果：位 i = 档位 i 的申请被准入。
static ADMITTED: AtomicU8 = AtomicU8::new(0);
/// 探测结果：全部被拒的申请都没有改动空闲帧与进程帧记账、且报的是压力拒绝。
static REFUSED_CLEAN: AtomicBool = AtomicBool::new(false);
/// 探测映射的位置（私有窗口内）。
const PROBE_PAGES: u64 = 4;

/// 内核探测任务：取得交互档上限后从高到低依次以四个档位申请匿名页；准入的申请立即取消映射。
fn memory_probe() {
    let Some(pid) = ObjId::from_raw(PROBE_PID.load(Ordering::Relaxed)) else { return };
    // 窗口起点 + 256 MiB：落在各指令集中最小的私有窗口之内
    const PROBE_OFF: u64 = 0x1000_0000;
    const _: () = assert!(PROBE_OFF + PROBE_PAGES * 4096 <= kernel_core::user_layout::MIN_WINDOW_SIZE);
    let va = arch::USER_WINDOW.0 + PROBE_OFF;
    sched::set_current_qos_ceiling(Some(Qos::Interactive));
    let mut admitted = 0u8;
    let mut clean = true;
    for q in Qos::ALL {
        if sched::set_current_qos(q).is_err() {
            clean = false;
            continue;
        }
        let free0 = frame::free_frames();
        let owned0 = proc::frame_count(pid);
        match proc::map_anon(pid, va, PROBE_PAGES, true) {
            Ok(()) => {
                admitted |= 1 << q.index();
                clean &= proc::unmap_range(pid, va, PROBE_PAGES).is_ok();
            }
            Err(e) => clean &= e == MemError::Pressure && frame::free_frames() == free0 && proc::frame_count(pid) == owned0,
        }
    }
    ADMITTED.store(admitted, Ordering::Relaxed);
    REFUSED_CLEAN.store(clean, Ordering::Relaxed);
}

/// 在当前内存水平下跑一次探测，返回 (准入位集合, 被拒的申请是否干净)。
fn probe_admission(round: u64) -> (u8, bool) {
    ADMITTED.store(0, Ordering::Relaxed);
    REFUSED_CLEAN.store(false, Ordering::Relaxed);
    let ok = sched::spawn(TaskId(TASK_ID_BASE + 300 + round), "ovl-memprobe", memory_probe).is_ok();
    check(ok, "内存探测任务创建失败");
    sched::run();
    (ADMITTED.load(Ordering::Relaxed), REFUSED_CLEAN.load(Ordering::Relaxed))
}

/// 准入位集合的可读形式（交互/用户发起/工具/后台，准入为 1）。
fn mask_str(m: u8) -> [u8; 4] {
    let mut s = [b'0'; 4];
    for (i, c) in s.iter_mut().enumerate() {
        if m & (1 << i) != 0 {
            *c = b'1';
        }
    }
    s
}

fn memory() {
    let before = baseline();
    pressure::reset_stats();
    let Ok(pid) = proc::create("ovl-memprobe", SyscallSet::EMPTY) else {
        check(false, "探测进程创建失败");
        return;
    };
    PROBE_PID.store(pid.raw(), Ordering::Relaxed);
    let Some(mut ballast) = Ballast::new() else {
        check(false, "压舱记录空间分配失败");
        return;
    };
    let reserve = pressure::params().reserve_frames;
    let normal = (pressure::level(), probe_admission(0));
    ballast.set_free_permille(low_mid_permille());
    let low = (pressure::level(), probe_admission(1));
    // 用户程序：紧张级下以后台档申请匿名内存被拒，且不留映射
    let user = match start_program("pressure", USER_SCHEDTEST, 3, schedtest_calls(), |_| Ok(())) {
        Some((upid, started)) => {
            if started {
                sched::run();
            }
            finish_program(upid, started)
        }
        None => None,
    };
    let user_ok = matches!(user, Some((Some(ProcState::Exited { code: 0 }), Some(0))));
    ballast.set_free_permille(pressure::params().critical_permille / 2);
    let critical = (pressure::level(), probe_admission(2));
    ballast.set_free(reserve + PROBE_PAGES as usize / 2);
    let reserved = (pressure::level(), probe_admission(3));
    ballast.release();
    let restored = (pressure::level(), probe_admission(4));
    let stats = pressure::stats();
    proc::exit_idle(pid, 0);
    let _ = finish_program(pid, true);

    let all = 0b1111u8;
    check(normal.0 == PressureLevel::Normal && normal.1 == (all, true), "正常级应全部准入");
    check(low.0 == PressureLevel::Low && low.1 == (0b0011, true), "紧张级应只准入交互与用户发起，且被拒的申请不留改动");
    check(user_ok, "紧张级下用户程序以后台档申请应被拒且不留映射");
    check(critical.0 == PressureLevel::Critical && critical.1 == (0b0001, true), "危急级应只准入交互，且被拒的申请不留改动");
    check(reserved.1 == (0, true), "保留线下应全部拒绝，且被拒的申请不留改动");
    check(restored.0 == PressureLevel::Normal && restored.1 == (all, true), "撤掉压舱后应恢复全部准入");
    check(stats.refused[Qos::Background.index()] >= 4 && stats.worst == Some(PressureLevel::Critical), "压力统计不符");
    let after = baseline();
    check(after == before, "内存压力用例后资源未回到基线");
    let s = |m: u8| mask_str(m);
    kprintln!(
        "[JSR-OVL] case=memory order=I/U/T/B normal={}:{} low={}:{} critical={}:{} reserve={}:{} restored={}:{} refused_untouched={} user_background_refused={} refused={}/{}/{}/{} worst={} reclaimed={}",
        normal.0.name(),
        core::str::from_utf8(&s(normal.1 .0)).unwrap_or("?"),
        low.0.name(),
        core::str::from_utf8(&s(low.1 .0)).unwrap_or("?"),
        critical.0.name(),
        core::str::from_utf8(&s(critical.1 .0)).unwrap_or("?"),
        reserved.0.name(),
        core::str::from_utf8(&s(reserved.1 .0)).unwrap_or("?"),
        restored.0.name(),
        core::str::from_utf8(&s(restored.1 .0)).unwrap_or("?"),
        low.1 .1 && critical.1 .1 && reserved.1 .1,
        user_ok,
        stats.refused[0],
        stats.refused[1],
        stats.refused[2],
        stats.refused[3],
        stats.worst.map(|l| l.name()).unwrap_or("none"),
        after == before
    );
}

// ---------------------------------------------------------------------------
// 用例 5：压力撤销后恢复
// ---------------------------------------------------------------------------

fn recovery_task() {
    interactive_sleeper(RECOVERY_ROUNDS, 1);
}

fn recovery() {
    let before = baseline();
    PROBE_DONE.store(0, Ordering::Relaxed);
    sched::reset_latency();
    sched::clear_watchdog();
    let spawned = sched::spawn(TaskId(TASK_ID_BASE + 400), "ovl-recovery", recovery_task).is_ok();
    check(spawned, "恢复任务创建失败");
    sched::run();
    // 收尾宽限：慢速目标上最后一轮可能落在窗口之外。断言关心的是「能睡满全部轮次
    // 且延迟有上界」，不是「必须在窗口内完成」；宽限耗尽仍未完成则如实判失败。
    let mut grace = 0u64;
    while PROBE_DONE.load(Ordering::Relaxed) < RECOVERY_ROUNDS && grace < 200 {
        sched::sleep_until(sched::timer_ticks() + 1);
        grace += 1;
    }
    let lat = sched::latency(Qos::Interactive);
    let done = PROBE_DONE.load(Ordering::Relaxed);
    let wd = sched::watchdog_log().total();
    let level = pressure::level();
    check(done == RECOVERY_ROUNDS && lat.count() == RECOVERY_ROUNDS, "恢复任务未完成全部睡眠");
    check(lat.max() == 0, "压力撤销后唤醒延迟应为 0");
    check(wd == 0, "压力撤销后看门狗不应有新记录");
    check(level == PressureLevel::Normal && sched::live_cpu_groups() == 0, "压力撤销后应回到正常级且无 CPU 组");
    let after = baseline();
    check(after == before, "恢复用例后资源未回到基线");
    kprintln!(
        "[JSR-OVL] case=recovery rounds={} samples={} max={} immediate={} watchdog_new={} level={} groups={} reclaimed={}",
        done,
        lat.count(),
        lat.max(),
        lat.max() == 0,
        wd,
        level.name(),
        sched::live_cpu_groups(),
        after == before
    );
}
