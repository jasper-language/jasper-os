//! 服务质量分级调度的验收演练：档位规则、动态任务数、过载下的唤醒延迟、压力撤销后的恢复。
//! Acceptance drill for QoS scheduling: class rules, dynamic task count, wake latency under load, recovery.
//!
//! # 为什么要有这个演练
//! 调度策略本身在宿主上有确定性模拟测试；这里验证的是**机制接上策略之后**在真实时钟中断下的行为：
//! 睡眠由时钟唤醒、唤醒即抢占、档位经系统调用修改、任务数不再受静态栈数量限制。
//! 延迟的权威数字取内核侧直方图（从被唤醒到被选中运行，单位 tick），与用户态程序看到的迟到量互相印证。
//!
//! # 用例
//! 1. **档位规则（内核任务）**：引导线程没有档位；降档成功；无上限时升档被拒且档位不变；新任务继承创建者的档位；
//!    有上限时可升到上限、超过上限被拒且档位不变
//! 2. **动态任务数**：同时存在 [`MANY`] 个内核任务（远超原先的 4 个槽位），各自睡眠若干次后全部退出；
//!    槽位满时创建被拒；页帧回到基线
//! 3. **`user/schedtest` role 0（分级）**：4 个吃满 CPU 的用户线程降到后台档，主线程（用户发起）周期性睡眠——
//!    用户发起档的唤醒延迟最大不超过 1 tick（唯一可能的推迟是一次一个 tick 的最低份额补给）；
//!    主线程自己吃满 CPU 时后台线程仍有进展
//! 4. **role 1（同档对照）**：吃满线程与主线程同档——延迟最大不超过一个时间片 + 1 tick（档内唤醒优先）
//! 5. **压力撤销后恢复**：负载退出后，一个内核任务连续睡眠 [`RECOVERY_ROUNDS`] 次，每次唤醒延迟都是 0
//!
//! 每个用例结束后检查空闲页帧、存活对象、清理队列、固定帧回到用例前的基线。

use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

use crate::sync::IrqU64;
use crate::proc::ProcState;
use crate::baseline::baseline;
use crate::rt_demo::{rt_calls, run_program};
use crate::sched::policy::Qos;
use crate::sched::scheduler::{QosError, SpawnError};
use crate::syscall::{table as abi, SyscallSet};
use crate::task::TaskId;
use crate::{kprintln, sched};

static CHECKS: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);

fn check(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-QOS-FAIL] {}", what);
    }
}

/// 失败断言数。
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

/// 过载响应性验收程序 `user/schedtest` 的 ELF 镜像（构建期由 `kernel/build.rs` 产出并嵌入）。
static USER_SCHEDTEST: &[u8] = include_bytes!(env!("JSR_USER_SCHEDTEST"));

/// 用例 2 同时存在的内核任务数：槽位上限的 5/8（默认档 40），远多于静态栈数，又给其它演练留出槽位。
const MANY: u64 = (sched::MAX_TASKS * 5 / 8) as u64;
/// 用例 5 的睡眠次数。
const RECOVERY_ROUNDS: u32 = 20;
/// 本演练的内核任务号起点（与其它演练的任务号不重叠）。
const TASK_ID_BASE: u64 = 9200;

/// 运行全部用例。演练期间保持抢占开启（默认设置）；结束时恢复进入前的设置。
pub fn run() {
    let prev_preemption = sched::set_preemption(true);
    let start = baseline();
    rules();
    many_tasks();
    overload("qos", 0, 1);
    overload("same_class", 1, crate::config::ACTIVE.sched.qos.quantum[Qos::UserInitiated.index()] as u64 + 1);
    recovery();
    let end = baseline();
    check(end == start, "演练结束后资源未回到起点");
    sched::set_preemption(prev_preemption);
    kprintln!(
        "[JSR-QOS] summary free_frames={}/{} objects={}/{} reclaimed={} checks={} failed={}",
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
// 用例 1：档位规则
// ---------------------------------------------------------------------------

/// 档位编码（`AtomicU8` 存放；0xFF = 未记录）。
const NONE_QOS: u8 = 0xFF;

fn enc(q: Option<Qos>) -> u8 {
    q.map(|q| q as u8).unwrap_or(NONE_QOS)
}

/// 规则任务内各步骤的结果（位 i = 第 i 步通过）。
static RULE_BITS: AtomicU32 = AtomicU32::new(0);
/// 子任务看到的自己的档位。
static CHILD_QOS: AtomicU8 = AtomicU8::new(NONE_QOS);

/// 规则任务的步骤数。
const RULE_STEPS: u32 = 7;

fn rule_ok(step: u32, ok: bool) {
    if ok {
        RULE_BITS.fetch_or(1 << step, Ordering::Relaxed);
    }
}

fn rule_child() {
    CHILD_QOS.store(enc(sched::current_qos()), Ordering::Relaxed);
}

fn rule_task() {
    // 0：从引导线程创建的任务取默认档位
    rule_ok(0, sched::current_qos() == Some(Qos::UserInitiated));
    // 1：降档成功
    rule_ok(1, sched::set_current_qos(Qos::Background).is_ok() && sched::current_qos() == Some(Qos::Background));
    // 2：没有上限时升档被拒，且档位不变
    rule_ok(2, sched::set_current_qos(Qos::UserInitiated) == Err(QosError::RaiseDenied) && sched::current_qos() == Some(Qos::Background));
    // 3：新任务继承创建者的档位（不能靠创建新任务绕过降档）
    let spawned = sched::spawn(TaskId(TASK_ID_BASE + 1), "qos-child", rule_child).is_ok();
    while spawned && CHILD_QOS.load(Ordering::Relaxed) == NONE_QOS {
        sched::pause();
    }
    rule_ok(3, spawned && CHILD_QOS.load(Ordering::Relaxed) == Qos::Background as u8);
    // 4：创建方授予上限后可升到上限
    sched::set_current_qos_ceiling(Some(Qos::UserInitiated));
    rule_ok(4, sched::set_current_qos(Qos::UserInitiated).is_ok() && sched::current_qos() == Some(Qos::UserInitiated));
    // 5：超过上限被拒，且档位不变
    rule_ok(5, sched::set_current_qos(Qos::Interactive) == Err(QosError::RaiseDenied) && sched::current_qos() == Some(Qos::UserInitiated));
    // 6：不变总是允许
    rule_ok(6, sched::set_current_qos(Qos::UserInitiated).is_ok());
}

fn rules() {
    let before = baseline();
    // 引导线程不参与策略选择，没有档位可改
    let boot_refused = sched::current_qos().is_none() && sched::set_current_qos(Qos::Background) == Err(QosError::NotAWorker);
    check(boot_refused, "引导线程修改档位应被拒");
    let spawned = sched::spawn(TaskId(TASK_ID_BASE), "qos-rules", rule_task).is_ok();
    check(spawned, "规则任务创建失败");
    sched::run();
    let bits = RULE_BITS.load(Ordering::Relaxed);
    let all = (1u32 << RULE_STEPS) - 1;
    check(bits == all, "档位规则步骤未全部通过");
    let after = baseline();
    check(after == before, "档位规则用例后资源未回到基线");
    kprintln!(
        "[JSR-QOS] case=rules boot_refused={} steps={}/{} raise_refused_unchanged={} inherit={} ceiling={} reclaimed={}",
        boot_refused,
        bits.count_ones(),
        RULE_STEPS,
        bits & (1 << 2) != 0 && bits & (1 << 5) != 0,
        bits & (1 << 3) != 0,
        bits & (1 << 4) != 0,
        after == before
    );
}

// ---------------------------------------------------------------------------
// 用例 2：动态任务数
// ---------------------------------------------------------------------------

/// 已完成的任务数与此刻存活的峰值。
static MANY_DONE: IrqU64 = IrqU64::new(0);
static MANY_LIVE: IrqU64 = IrqU64::new(0);
static MANY_PEAK: IrqU64 = IrqU64::new(0);

fn many_task() {
    let live = MANY_LIVE.fetch_add(1, Ordering::Relaxed) + 1;
    MANY_PEAK.fetch_max(live, Ordering::Relaxed);
    for _ in 0..3 {
        sched::pause();
    }
    MANY_LIVE.fetch_sub(1, Ordering::Relaxed);
    MANY_DONE.fetch_add(1, Ordering::Relaxed);
}

fn filler() {}

fn many_tasks() {
    let before = baseline();
    let capacity = sched::capacity();
    check(capacity == sched::MAX_TASKS, "堆栈预留后可用槽位应等于上限");
    let mut spawned = 0u64;
    for i in 0..MANY {
        if sched::spawn(TaskId(TASK_ID_BASE + 100 + i), "qos-many", many_task).is_ok() {
            spawned += 1;
        }
    }
    check(spawned == MANY, "并发任务创建失败");
    sched::run();
    let done = MANY_DONE.load(Ordering::Relaxed);
    let peak = MANY_PEAK.load(Ordering::Relaxed);
    check(done == MANY, "并发任务未全部完成");
    // 同时创建、各自睡眠三次：全部任务应同时存活（证明并发数不受静态栈数量限制）
    check(peak == MANY, "并发任务未同时存活");

    // 槽位满：再创建被拒；占位任务结束后槽位腾空
    let mut fillers = 0u64;
    while sched::spawn(TaskId(TASK_ID_BASE + 200 + fillers), "qos-filler", filler).is_ok() {
        fillers += 1;
    }
    let full = sched::spawn(TaskId(TASK_ID_BASE + 199), "qos-over", filler);
    check(full == Err(SpawnError::NoFreeSlot) && fillers as usize == capacity - 1, "槽位满时创建应被拒");
    sched::run();
    let after = baseline();
    check(after == before, "动态任务数用例后资源未回到基线");
    kprintln!(
        "[JSR-QOS] case=many capacity={} spawned={} done={} peak_live={} full_refused={} fillers={} reclaimed={}",
        capacity,
        spawned,
        done,
        peak,
        full == Err(SpawnError::NoFreeSlot),
        fillers,
        after == before
    );
}

// ---------------------------------------------------------------------------
// 用例 3、4：过载下的唤醒延迟
// ---------------------------------------------------------------------------

/// `user/schedtest` 需要的系统调用：运行时的全部调用 + 设置档位。
fn schedtest_calls() -> SyscallSet {
    rt_calls().union(SyscallSet::of(&[abi::SYSTEM_TASK_QOS_SET]))
}

/// 运行 `user/schedtest` 的一个模式，并用内核侧直方图检查用户发起档的唤醒延迟上界 `bound`（tick）。
fn overload(mode: &'static str, role: u64, bound: u64) {
    let before = baseline();
    sched::reset_latency();
    let res = run_program("schedtest", USER_SCHEDTEST, role, schedtest_calls());
    let lat = sched::latency(Qos::UserInitiated);
    let bg = sched::latency(Qos::Background);
    let ok_exit = matches!(res, Some((Some(ProcState::Exited { code: 0 }), Some(0))));
    check(ok_exit, "schedtest 未以 0 退出");
    check(lat.count() > 0, "没有记录到唤醒延迟样本");
    check(lat.max() <= bound, "用户发起档唤醒延迟超过上界");
    let after = baseline();
    check(after == before, "过载用例后资源未回到基线");
    kprintln!(
        "[JSR-QOS] case=overload mode={} exit={:?} samples={} p50={} p99={} max={} bound={} bounded={} bg_samples={} reclaimed={}",
        mode,
        res.and_then(|r| r.1),
        lat.count(),
        lat.percentile(500),
        lat.percentile(990),
        lat.max(),
        bound,
        lat.max() <= bound,
        bg.count(),
        after == before
    );
}

// ---------------------------------------------------------------------------
// 用例 5：压力撤销后恢复
// ---------------------------------------------------------------------------

/// 恢复任务完成的睡眠次数。
static RECOVERY_DONE: AtomicU32 = AtomicU32::new(0);

fn recovery_task() {
    for _ in 0..RECOVERY_ROUNDS {
        sched::sleep_until(sched::timer_ticks() + 1);
        RECOVERY_DONE.fetch_add(1, Ordering::Relaxed);
    }
}

fn recovery() {
    let before = baseline();
    sched::reset_latency();
    let spawned = sched::spawn(TaskId(TASK_ID_BASE + 300), "qos-recovery", recovery_task).is_ok();
    check(spawned, "恢复任务创建失败");
    sched::run();
    let lat = sched::latency(Qos::UserInitiated);
    let done = RECOVERY_DONE.load(Ordering::Relaxed);
    check(done == RECOVERY_ROUNDS && lat.count() == RECOVERY_ROUNDS, "恢复任务未完成全部睡眠");
    check(lat.max() == 0, "压力撤销后唤醒延迟应为 0");
    let after = baseline();
    check(after == before, "恢复用例后资源未回到基线");
    kprintln!(
        "[JSR-QOS] case=recovery rounds={} samples={} max={} immediate={} reclaimed={}",
        done,
        lat.count(),
        lat.max(),
        lat.max() == 0,
        after == before
    );
}
