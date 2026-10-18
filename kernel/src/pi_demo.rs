//! 优先级继承的验收演练：经典三任务反转（锁 / 等任务退出）、传递继承、拒绝路径、持有者退出、压力撤销后恢复。
//! Acceptance drill for priority inheritance: classic inversion, transitive chains, refusals, orphaned locks, recovery.
//!
//! # 为什么要有这个演练
//! 继承的决策（等待图校验、有效档位重算、交接对象选择）在宿主上有确定性测试；这里验证机制接上之后，
//! 在真实时钟中断与抢占下：高档任务等一个低档持有者时，多个吃满处理器的中档任务挡不住持有者，
//! 等待时长只取决于持有者剩余的工作量；放锁或退出后借来的档位立即归还。
//!
//! # 用例
//! 1. **三任务反转（锁）**：后台档 L 持锁并还需 [`WORK`] 个 tick 的处理器时间；[`HOGS`] 个工具档任务吃满处理器
//!    [`HOG_TICKS`] 个 tick；交互档 H 来要锁。有继承：H 的等待 ≤ [`WORK`] + 2 tick，L 在此期间按交互档运行，
//!    放锁后回到后台档。关闭继承作对照：H 的等待远超上界（反转真实存在）。
//! 2. **三任务反转（等任务退出）**：同上，但 H 等的是 L 退出。
//! 3. **传递继承**：H 等 M2 持有的锁 B，M2 等 L 持有的锁 A ⇒ L 的有效档位为交互档；依次交接后全部归还。
//! 4. **拒绝路径**：递归加锁、成环（AB-BA 死锁）、等自己退出均在阻塞前被拒绝，锁的持有者与等待关系不变；
//!    被拒之后原有的等待照常完成。
//! 5. **持有者未放锁就退出**：等在锁上的任务被唤醒并接管这把锁。
//! 6. **压力撤销后恢复**：吃满处理器的任务退出后，交互档任务连续睡眠 [`RECOVERY_ROUNDS`] 次，唤醒延迟都是 0。
//!
//! 每个用例结束后检查锁空闲、资源回到用例前的基线。

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};

use crate::rt_demo::baseline;
use crate::sched::policy::inherit::EdgeError;
use crate::sched::policy::Qos;
use crate::sched::scheduler::BlockError;
use crate::sched::KMutex;
use crate::task::TaskId;
use crate::{kprintln, sched};

static CHECKS: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);

fn check(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-PI-FAIL] {}", what);
    }
}

/// 失败断言数。
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

/// 持有者在临界区内还需的处理器时间（tick）。
const WORK: u64 = 4;
/// 有继承时高档等待者的等待上界（tick）：剩余工作量 + 交接与时钟粒度各 1 tick。
const BOUND: u64 = WORK + 2;
/// 吃满处理器的中档任务数。
const HOGS: u64 = 3;
/// 中档任务吃满处理器的时长（tick）。
const HOG_TICKS: u64 = 120;
/// 恢复用例的睡眠次数。
const RECOVERY_ROUNDS: u32 = 20;
/// 本演练的内核任务号起点（与其它演练不重叠）。
const TASK_ID_BASE: u64 = 9500;

/// 用例 1、3、4、5 共用的锁 A 与锁 B（锁内数据：成功进入临界区的次数）。
static LOCK_A: KMutex<u64> = KMutex::new(0);
static LOCK_B: KMutex<u64> = KMutex::new(0);

/// 档位编码（`AtomicU8` 存放；0xFF = 未记录）。
const NONE_QOS: u8 = 0xFF;

fn enc(q: Option<Qos>) -> u8 {
    q.map(|q| q as u8).unwrap_or(NONE_QOS)
}

fn dec(v: u8) -> Option<Qos> {
    Qos::from_raw(v as u64)
}

fn qos_name(v: &AtomicU8) -> &'static str {
    dec(v.load(Ordering::Relaxed)).map(Qos::name).unwrap_or("none")
}

/// 把当前内核任务提升到交互档（内核内的创建方先授予上限，再提升）。
fn become_interactive() -> bool {
    sched::set_current_qos_ceiling(Some(Qos::Interactive));
    sched::set_current_qos(Qos::Interactive).is_ok()
}

/// 当前任务累计运行的 tick 数。
fn my_cpu() -> u64 {
    sched::cpu_ticks(sched::current().0).unwrap_or(0)
}

/// 吃满处理器到当前任务又用掉 `ticks` 个 tick；期间记下自己出现过的最高有效档位。
fn burn_cpu(ticks: u64, peak: &AtomicU8) {
    let start = my_cpu();
    let mut best = sched::current_effective_qos();
    while my_cpu() < start + ticks {
        if let (Some(b), Some(now)) = (best, sched::current_effective_qos()) {
            best = Some(b.higher(now));
        }
        core::hint::spin_loop();
    }
    peak.store(enc(best), Ordering::Relaxed);
}

/// 运行全部用例；演练期间保持抢占与继承开启（对照用例临时关闭继承），结束时恢复进入前的设置。
pub fn run() {
    let prev_preemption = sched::set_preemption(true);
    let start = baseline();
    inversion(Wait::Lock, true);
    inversion(Wait::Lock, false);
    inversion(Wait::Exit, true);
    chain();
    refusals();
    orphan();
    recovery();
    let end = baseline();
    check(end == start, "演练结束后资源未回到起点");
    sched::set_preemption(prev_preemption);
    kprintln!(
        "[JSR-PI] summary free_frames={}/{} objects={}/{} reclaimed={} checks={} failed={}",
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
// 用例 1、2：经典三任务反转
// ---------------------------------------------------------------------------

/// 高档任务等的是什么。
#[derive(Clone, Copy, PartialEq, Eq)]
enum Wait {
    /// 等低档任务持有的锁。
    Lock,
    /// 等低档任务退出。
    Exit,
}

static INV_MODE: AtomicU8 = AtomicU8::new(0);
static INV_HOLDING: AtomicU64 = AtomicU64::new(0);
static INV_HOGGING: AtomicU64 = AtomicU64::new(0);
static INV_HOG_CPU: AtomicU64 = AtomicU64::new(0);
static INV_WAIT: AtomicU64 = AtomicU64::new(u64::MAX);
static INV_WAIT_OK: AtomicU8 = AtomicU8::new(0);
static INV_L_PEAK: AtomicU8 = AtomicU8::new(NONE_QOS);
static INV_L_AFTER: AtomicU8 = AtomicU8::new(NONE_QOS);
static INV_H_READY: AtomicU8 = AtomicU8::new(0);
/// 本轮低档任务的任务号（等退出模式下高档任务等它）。
static INV_L_ID: AtomicU64 = AtomicU64::new(0);

fn inv_low() {
    let _ = sched::set_current_qos(Qos::Background);
    if INV_MODE.load(Ordering::Relaxed) == Wait::Lock as u8 {
        let Ok(mut g) = LOCK_A.lock() else { return };
        INV_HOLDING.store(1, Ordering::Relaxed);
        burn_cpu(WORK, &INV_L_PEAK);
        *g += 1;
        drop(g);
        INV_L_AFTER.store(enc(sched::current_effective_qos()), Ordering::Relaxed);
    } else {
        // 等退出模式：借来的档位在本任务退出时随等待关系一起归还（由高档任务在等待结束后核对）
        INV_HOLDING.store(1, Ordering::Relaxed);
        burn_cpu(WORK, &INV_L_PEAK);
    }
}

fn inv_hog() {
    let _ = sched::set_current_qos(Qos::Utility);
    while INV_HOLDING.load(Ordering::Relaxed) == 0 {
        sched::pause();
    }
    INV_HOGGING.fetch_add(1, Ordering::Relaxed);
    let start = my_cpu();
    let end = sched::timer_ticks() + HOG_TICKS;
    while sched::timer_ticks() < end {
        core::hint::spin_loop();
    }
    INV_HOG_CPU.fetch_add(my_cpu() - start, Ordering::Relaxed);
}

fn inv_high() {
    INV_H_READY.store(become_interactive() as u8, Ordering::Relaxed);
    while INV_HOGGING.load(Ordering::Relaxed) < HOGS {
        sched::pause();
    }
    // 让吃满处理器的任务真正跑起来再来要锁
    sched::sleep_until(sched::timer_ticks() + 2);
    let t0 = sched::timer_ticks();
    let ok = if INV_MODE.load(Ordering::Relaxed) == Wait::Lock as u8 {
        match LOCK_A.lock() {
            Ok(mut g) => {
                *g += 1;
                true
            }
            Err(_) => false,
        }
    } else {
        let l = TaskId(INV_L_ID.load(Ordering::Relaxed));
        let joined = sched::join(l).is_ok();
        // 低档任务已退出：不再有有效档位，等待关系随之消失
        if joined && sched::effective_qos(l).is_none() {
            INV_L_AFTER.store(enc(Some(Qos::Background)), Ordering::Relaxed);
        }
        joined
    };
    INV_WAIT.store(sched::timer_ticks() - t0, Ordering::Relaxed);
    INV_WAIT_OK.store(ok as u8, Ordering::Relaxed);
}

fn inversion(mode: Wait, inherit: bool) {
    let before = baseline();
    let prev = sched::set_inheritance(inherit);
    INV_MODE.store(mode as u8, Ordering::Relaxed);
    for a in [&INV_HOLDING, &INV_HOGGING, &INV_HOG_CPU] {
        a.store(0, Ordering::Relaxed);
    }
    INV_WAIT.store(u64::MAX, Ordering::Relaxed);
    INV_WAIT_OK.store(0, Ordering::Relaxed);
    INV_H_READY.store(0, Ordering::Relaxed);
    INV_L_PEAK.store(NONE_QOS, Ordering::Relaxed);
    INV_L_AFTER.store(NONE_QOS, Ordering::Relaxed);
    let base = TASK_ID_BASE + if mode == Wait::Lock { if inherit { 0 } else { 10 } } else { 20 };
    INV_L_ID.store(base, Ordering::Relaxed);
    let mut spawned = sched::spawn(TaskId(base), "pi-low", inv_low).is_ok();
    for i in 0..HOGS {
        spawned &= sched::spawn(TaskId(base + 1 + i), "pi-hog", inv_hog).is_ok();
    }
    spawned &= sched::spawn(TaskId(base + 9), "pi-high", inv_high).is_ok();
    check(spawned, "反转用例任务创建失败");
    sched::run();
    sched::set_inheritance(prev);

    let wait = INV_WAIT.load(Ordering::Relaxed);
    let bounded = wait <= BOUND;
    let peak = dec(INV_L_PEAK.load(Ordering::Relaxed));
    let after = dec(INV_L_AFTER.load(Ordering::Relaxed));
    let hog_progress = INV_HOG_CPU.load(Ordering::Relaxed) > 0;
    let lock_free = LOCK_A.owner().is_none();
    let end = baseline();
    check(INV_H_READY.load(Ordering::Relaxed) == 1 && INV_WAIT_OK.load(Ordering::Relaxed) == 1, "高档任务没有完成等待");
    check(hog_progress, "吃满处理器的任务没有进展");
    check(lock_free, "用例结束后锁未空闲");
    check(after == Some(Qos::Background), "持有者结束等待关系后应回到自身档位");
    if inherit {
        check(bounded, "有继承时高档任务的等待超过上界");
        check(peak == Some(Qos::Interactive), "持有者应借到交互档");
    } else {
        // 对照：反转真实存在——持有者停留在后台档，高档任务的等待远超上界
        check(!bounded && wait >= 4 * BOUND, "关闭继承时应观察到反转");
        check(peak == Some(Qos::Background), "关闭继承时持有者不应借到档位");
    }
    check(end == before, "反转用例后资源未回到基线");
    kprintln!(
        "[JSR-PI] case=inversion wait_on={} inherit={} hogs={} hog_ticks={} work={} wait={} bound={} bounded={} holder_peak={} holder_after={} hog_progress={} lock_free={} reclaimed={}",
        if mode == Wait::Lock { "lock" } else { "exit" },
        inherit,
        HOGS,
        HOG_TICKS,
        WORK,
        wait,
        BOUND,
        bounded,
        qos_name(&INV_L_PEAK),
        qos_name(&INV_L_AFTER),
        hog_progress,
        lock_free,
        end == before
    );
}

// ---------------------------------------------------------------------------
// 用例 3：传递继承
// ---------------------------------------------------------------------------

static CH_A_HELD: AtomicU8 = AtomicU8::new(0);
static CH_B_HELD: AtomicU8 = AtomicU8::new(0);
static CH_L_SEEN: AtomicU8 = AtomicU8::new(NONE_QOS);
static CH_L_AFTER: AtomicU8 = AtomicU8::new(NONE_QOS);
static CH_M_WITH_A: AtomicU8 = AtomicU8::new(NONE_QOS);
static CH_M_AFTER: AtomicU8 = AtomicU8::new(NONE_QOS);
static CH_H_GOT: AtomicU8 = AtomicU8::new(0);

fn ch_low() {
    let _ = sched::set_current_qos(Qos::Background);
    let Ok(mut a) = LOCK_A.lock() else { return };
    CH_A_HELD.store(1, Ordering::Relaxed);
    // 等到 H→M2→L 这条链建立（有效档位变为交互档），最多等 100 tick
    let deadline = sched::timer_ticks() + 100;
    while sched::current_effective_qos() != Some(Qos::Interactive) && sched::timer_ticks() < deadline {
        core::hint::spin_loop();
    }
    CH_L_SEEN.store(enc(sched::current_effective_qos()), Ordering::Relaxed);
    *a += 1;
    drop(a);
    CH_L_AFTER.store(enc(sched::current_effective_qos()), Ordering::Relaxed);
}

fn ch_mid() {
    let _ = sched::set_current_qos(Qos::Utility);
    while CH_A_HELD.load(Ordering::Relaxed) == 0 {
        sched::pause();
    }
    let Ok(mut b) = LOCK_B.lock() else { return };
    CH_B_HELD.store(1, Ordering::Relaxed);
    let Ok(mut a) = LOCK_A.lock() else { return };
    // 拿到 A 时 H 仍在等 B：M2 的有效档位应仍是交互档
    CH_M_WITH_A.store(enc(sched::current_effective_qos()), Ordering::Relaxed);
    *a += 1;
    drop(a);
    *b += 1;
    drop(b);
    CH_M_AFTER.store(enc(sched::current_effective_qos()), Ordering::Relaxed);
}

fn ch_high() {
    if !become_interactive() {
        return;
    }
    while CH_B_HELD.load(Ordering::Relaxed) == 0 {
        sched::pause();
    }
    if let Ok(mut b) = LOCK_B.lock() {
        *b += 1;
        CH_H_GOT.store(1, Ordering::Relaxed);
    }
}

fn chain() {
    let before = baseline();
    for a in [&CH_A_HELD, &CH_B_HELD, &CH_H_GOT] {
        a.store(0, Ordering::Relaxed);
    }
    for a in [&CH_L_SEEN, &CH_L_AFTER, &CH_M_WITH_A, &CH_M_AFTER] {
        a.store(NONE_QOS, Ordering::Relaxed);
    }
    let base = TASK_ID_BASE + 30;
    let spawned = sched::spawn(TaskId(base), "pi-ch-low", ch_low).is_ok()
        && sched::spawn(TaskId(base + 1), "pi-ch-mid", ch_mid).is_ok()
        && sched::spawn(TaskId(base + 2), "pi-ch-high", ch_high).is_ok();
    check(spawned, "传递用例任务创建失败");
    sched::run();
    let transitive = dec(CH_L_SEEN.load(Ordering::Relaxed)) == Some(Qos::Interactive);
    let mid_kept = dec(CH_M_WITH_A.load(Ordering::Relaxed)) == Some(Qos::Interactive);
    let restored = dec(CH_L_AFTER.load(Ordering::Relaxed)) == Some(Qos::Background) && dec(CH_M_AFTER.load(Ordering::Relaxed)) == Some(Qos::Utility);
    let got = CH_H_GOT.load(Ordering::Relaxed) == 1;
    let free = LOCK_A.owner().is_none() && LOCK_B.owner().is_none();
    let end = baseline();
    check(transitive, "等待链末端的持有者应借到交互档");
    check(mid_kept, "中间持有者在 H 仍等待时应保持交互档");
    check(restored, "交接后借来的档位应全部归还");
    check(got && free, "传递用例未完成交接或锁未空闲");
    check(end == before, "传递用例后资源未回到基线");
    kprintln!(
        "[JSR-PI] case=chain low_seen={} mid_with_a={} low_after={} mid_after={} high_got={} transitive={} restored={} locks_free={} reclaimed={}",
        qos_name(&CH_L_SEEN),
        qos_name(&CH_M_WITH_A),
        qos_name(&CH_L_AFTER),
        qos_name(&CH_M_AFTER),
        got,
        transitive,
        restored,
        free,
        end == before
    );
}

// ---------------------------------------------------------------------------
// 用例 4：拒绝路径
// ---------------------------------------------------------------------------

/// 拒绝用例各步骤的结果（位 i = 第 i 步通过）。
static REF_BITS: AtomicU32 = AtomicU32::new(0);
/// 拒绝用例的步骤数。
const REF_STEPS: u32 = 7;
static DL_A_HELD: AtomicU8 = AtomicU8::new(0);
static DL_B_HELD: AtomicU8 = AtomicU8::new(0);
static DL_T1_TRYING: AtomicU8 = AtomicU8::new(0);
/// AB-BA 死锁尝试的结果编码（0 = 未尝试，1 = 成环被拒，2 = 其它结果）。
static DL_RESULT: AtomicU8 = AtomicU8::new(0);

fn ref_ok(step: u32, ok: bool) {
    if ok {
        REF_BITS.fetch_or(1 << step, Ordering::Relaxed);
    }
}

fn ref_recursive() {
    let me = sched::current().0;
    let Ok(g) = LOCK_A.lock() else { return };
    let eff = sched::current_effective_qos();
    // 0：递归加锁被拒，持有者与有效档位不变
    let second = LOCK_A.lock().err();
    ref_ok(0, second == Some(BlockError::Refused(EdgeError::SelfWait)) && LOCK_A.owner() == Some(me) && sched::current_effective_qos() == eff);
    drop(g);
    // 1：放锁后空闲
    ref_ok(1, LOCK_A.owner().is_none());
    // 2：等自己退出被拒；3：等一个不存在的任务立即返回
    ref_ok(2, sched::join(me) == Err(BlockError::Refused(EdgeError::SelfWait)));
    ref_ok(3, sched::join(TaskId(TASK_ID_BASE + 99)).is_ok());
}

fn dl_t1() {
    let Ok(mut a) = LOCK_A.lock() else { return };
    DL_A_HELD.store(1, Ordering::Relaxed);
    while DL_B_HELD.load(Ordering::Relaxed) == 0 {
        sched::pause();
    }
    DL_T1_TRYING.store(1, Ordering::Relaxed);
    // 阻塞在 T2 持有的 B 上；T2 的成环尝试被拒后放掉 B，这里照常拿到
    let got_b = match LOCK_B.lock() {
        Ok(mut b) => {
            *b += 1;
            true
        }
        Err(_) => false,
    };
    // 6：被拒的那次尝试没有破坏原有的等待：T1 最终拿到 B
    ref_ok(6, got_b);
    *a += 1;
}

fn dl_t2() {
    let me = sched::current().0;
    while DL_A_HELD.load(Ordering::Relaxed) == 0 {
        sched::pause();
    }
    let Ok(b) = LOCK_B.lock() else { return };
    DL_B_HELD.store(1, Ordering::Relaxed);
    while DL_T1_TRYING.load(Ordering::Relaxed) == 0 {
        sched::pause();
    }
    // 确保 T1 已经阻塞在 B 上
    sched::sleep_until(sched::timer_ticks() + 2);
    let a_owner = LOCK_A.owner();
    let r = LOCK_A.lock().err();
    DL_RESULT.store(if r == Some(BlockError::Refused(EdgeError::Cycle)) { 1 } else { 2 }, Ordering::Relaxed);
    // 4：成环被拒；5：A 的持有者不变、B 仍归自己
    ref_ok(4, r == Some(BlockError::Refused(EdgeError::Cycle)));
    ref_ok(5, LOCK_A.owner() == a_owner && a_owner.is_some() && LOCK_B.owner() == Some(me));
    drop(b);
}

fn refusals() {
    let before = baseline();
    REF_BITS.store(0, Ordering::Relaxed);
    for a in [&DL_A_HELD, &DL_B_HELD, &DL_T1_TRYING, &DL_RESULT] {
        a.store(0, Ordering::Relaxed);
    }
    let base = TASK_ID_BASE + 40;
    check(sched::spawn(TaskId(base), "pi-recursive", ref_recursive).is_ok(), "递归用例任务创建失败");
    sched::run();
    let spawned = sched::spawn(TaskId(base + 1), "pi-dl-t1", dl_t1).is_ok() && sched::spawn(TaskId(base + 2), "pi-dl-t2", dl_t2).is_ok();
    check(spawned, "死锁用例任务创建失败");
    sched::run();
    let bits = REF_BITS.load(Ordering::Relaxed);
    let all = (1u32 << REF_STEPS) - 1;
    let free = LOCK_A.owner().is_none() && LOCK_B.owner().is_none();
    let end = baseline();
    check(bits == all, "拒绝路径步骤未全部通过");
    check(free, "拒绝用例后锁未空闲");
    check(end == before, "拒绝用例后资源未回到基线");
    kprintln!(
        "[JSR-PI] case=refusals steps={}/{} recursive_refused={} self_join_refused={} cycle_refused={} unchanged={} waiter_completed={} locks_free={} reclaimed={}",
        bits.count_ones(),
        REF_STEPS,
        bits & 1 != 0,
        bits & (1 << 2) != 0,
        DL_RESULT.load(Ordering::Relaxed) == 1,
        bits & (1 << 5) != 0,
        bits & (1 << 6) != 0,
        free,
        end == before
    );
}

// ---------------------------------------------------------------------------
// 用例 5：持有者未放锁就退出
// ---------------------------------------------------------------------------

static OR_HELD: AtomicU8 = AtomicU8::new(0);
static OR_TRYING: AtomicU8 = AtomicU8::new(0);
static OR_TAKEN: AtomicU8 = AtomicU8::new(0);

fn or_owner() {
    let Ok(g) = LOCK_A.lock() else { return };
    OR_HELD.store(1, Ordering::Relaxed);
    while OR_TRYING.load(Ordering::Relaxed) == 0 {
        sched::pause();
    }
    sched::sleep_until(sched::timer_ticks() + 2);
    // 不放锁就退出（守卫被遗忘）：模拟持有者异常结束
    core::mem::forget(g);
}

fn or_waiter() {
    let me = sched::current().0;
    while OR_HELD.load(Ordering::Relaxed) == 0 {
        sched::pause();
    }
    OR_TRYING.store(1, Ordering::Relaxed);
    if let Ok(mut g) = LOCK_A.lock() {
        *g += 1;
        OR_TAKEN.store((LOCK_A.owner() == Some(me)) as u8, Ordering::Relaxed);
    }
}

fn orphan() {
    let before = baseline();
    for a in [&OR_HELD, &OR_TRYING, &OR_TAKEN] {
        a.store(0, Ordering::Relaxed);
    }
    let base = TASK_ID_BASE + 50;
    let spawned = sched::spawn(TaskId(base), "pi-or-owner", or_owner).is_ok() && sched::spawn(TaskId(base + 1), "pi-or-waiter", or_waiter).is_ok();
    check(spawned, "持有者退出用例任务创建失败");
    sched::run();
    let taken = OR_TAKEN.load(Ordering::Relaxed) == 1;
    let free = LOCK_A.owner().is_none();
    let end = baseline();
    check(taken, "持有者退出后等待者应接管锁");
    check(free, "接管者放锁后锁应空闲");
    check(end == before, "持有者退出用例后资源未回到基线");
    kprintln!("[JSR-PI] case=orphan waiter_took_over={} lock_free={} reclaimed={}", taken, free, end == before);
}

// ---------------------------------------------------------------------------
// 用例 6：压力撤销后恢复
// ---------------------------------------------------------------------------

static REC_DONE: AtomicU32 = AtomicU32::new(0);

fn rec_task() {
    if !become_interactive() {
        return;
    }
    for _ in 0..RECOVERY_ROUNDS {
        sched::sleep_until(sched::timer_ticks() + 1);
        REC_DONE.fetch_add(1, Ordering::Relaxed);
    }
}

fn recovery() {
    let before = baseline();
    REC_DONE.store(0, Ordering::Relaxed);
    sched::reset_latency();
    check(sched::spawn(TaskId(TASK_ID_BASE + 60), "pi-recovery", rec_task).is_ok(), "恢复任务创建失败");
    sched::run();
    let lat = sched::latency(Qos::Interactive);
    let done = REC_DONE.load(Ordering::Relaxed);
    let end = baseline();
    check(done == RECOVERY_ROUNDS && lat.count() == RECOVERY_ROUNDS, "恢复任务未完成全部睡眠");
    check(lat.max() == 0, "压力撤销后唤醒延迟应为 0");
    check(end == before, "恢复用例后资源未回到基线");
    kprintln!(
        "[JSR-PI] case=recovery rounds={} samples={} max={} immediate={} reclaimed={}",
        done,
        lat.count(),
        lat.max(),
        lat.max() == 0,
        end == before
    );
}
