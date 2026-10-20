//! HARDEN-1C 演练：用户指针复制与并发取消映射（多核安全）。
//! HARDEN-1C drill: user-pointer copies racing concurrent unmapping (SMP safety).
//!
//! # 场景
//! 同时运行两个进程（`user/rtdemo` 的 role 3 与 role 4）：
//! * **攻击方**：「翻页」线程对页 X 反复取消映射、重新映射（每次是一块新的物理帧）；主线程同时反复让内核
//!   写 X（`system.profile.get` → copy_to_user）与读 X（`system.process.spawn` → copy_from_user，参数块必然被拒）。
//! * **受害方**：反复申请新页、填入图案、让出处理器后逐字节核对。
//!
//! 在多处理器上两个线程会落在不同的核上，真正并发；单处理器上靠时间片抢占交错。
//!
//! 跑两轮：**自然窗口**（不做任何人为延迟）与**撑大窗口**——内核在「校验 / 固定」与「复制」之间
//! 让攻击方线程睡一个 tick（[`crate::mm::user::RACE_WINDOW_TICKS`]），翻页线程让页保持映射一个 tick、取消映射后再空出一个 tick，受害方填好图案后睡三个 tick 再核对；
//! 并统计「固定期间被取消映射」的帧数（[`crate::mm::pin::orphaned_total`]），撑大窗口这一轮必须大于 0，证明竞态确实发生过。
//! 自然窗口只有几十纳秒，撞上的概率很低；撑大窗口才能让「窗口内帧被归还并分给受害方」稳定发生。
//! 对照实验（把进程的复制路径临时换回旧的「先校验、后复制」）：撑大窗口一轮的「陈旧复制」计数
//! （[`crate::mm::user::stale_copies`]：准备复制时目标帧已不再映射在原地址）大于 0，直接证明旧实现会读写已回收的帧；
//! 受害方是否恰好拿到那块帧取决于分配顺序，不作为对照的唯一依据。
//!
//! # 判据
//! 攻击方：翻页次数达到预期，内核读写 X 的结果只有「成功」或「地址无效」两种，没有第三种结果，
//! 也没有任何一次 spawn 被当成合法请求。受害方：所有轮次的图案都完好（没有被别的进程的内核复制写坏）。
//! 两个进程都以 0 退出；空闲页帧、存活对象、清理队列、固定帧都回到演练前的基线。

use core::sync::atomic::{AtomicU32, Ordering};

use crate::baseline::baseline;
use crate::proc::ProcState;
use crate::rt_demo::{finish_program, rt_calls, start_program_arg, USER_RTDEMO};
use crate::syscall::{self, table as abi, SyscallSet};
use crate::{kprintln, sched};

static FAILED: AtomicU32 = AtomicU32::new(0);
static CHECKS: AtomicU32 = AtomicU32::new(0);

fn check(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-UPTR-SMP-FAIL] {}", what);
    }
}

/// 断言失败数。
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

fn exited_with(r: Option<(Option<ProcState>, Option<i64>)>, want: i64) -> bool {
    matches!(r, Some((_, Some(code))) if code == want)
}

/// 撑大窗口时内核在校验 / 固定与复制之间睡眠的 tick 数。
const WIDE_TICKS: u32 = 1;

/// 运行演练：自然窗口一轮、撑大窗口一轮。
pub fn run() {
    let prev_preemption = sched::set_preemption(true);
    // 攻击方会发出数千次系统调用：演练期间关闭逐次系统调用日志（分发、权限检查与执行不变）
    let trace = syscall::set_trace(false);
    round("natural", 0, 0);
    round("wide", 1, WIDE_TICKS);
    syscall::set_trace(trace);
    sched::set_preemption(prev_preemption);
}

fn round(mode: &str, arg: u64, window: u32) {
    let before = baseline();
    let orphaned_before = crate::mm::pin::orphaned_total();
    let stale_before = crate::mm::user::stale_copies();
    crate::mm::user::RACE_WINDOW_TICKS.store(window, Ordering::Relaxed);
    let attack_calls = rt_calls().union(SyscallSet::of(&[abi::SYSTEM_PROFILE_GET, abi::SYSTEM_PROCESS_SPAWN]));
    let attacker = start_program_arg("uptr-attack", USER_RTDEMO, 3, arg, attack_calls, |_| Ok(()));
    let victim = start_program_arg("uptr-victim", USER_RTDEMO, 4, arg, rt_calls(), |_| Ok(()));
    let both_started = matches!((attacker, victim), (Some((_, true)), Some((_, true))));
    check(both_started, "攻击方或受害方进程启动失败");
    sched::run();
    crate::mm::user::RACE_WINDOW_TICKS.store(0, Ordering::Relaxed);
    let ra = attacker.and_then(|(pid, started)| finish_program(pid, started));
    let rv = victim.and_then(|(pid, started)| finish_program(pid, started));
    let after = baseline();
    // 窗口内被取消映射、因被固定而延后归还的帧数：撑大窗口这一轮必须 > 0，
    // 否则说明竞态根本没有发生，本轮也就证明不了任何东西。
    let raced = crate::mm::pin::orphaned_total() - orphaned_before;
    // 内核准备读写一块已不再映射在原地址的帧的次数：修复后必须为 0（对照实验中它 > 0，见模块文档）。
    let stale = crate::mm::user::stale_copies() - stale_before;
    check(stale == 0, "内核准备读写一块已不属于该进程的帧（陈旧复制）");
    if window > 0 {
        check(raced > 0, "撑大窗口这一轮没有发生「固定期间被取消映射」，竞态未被触发");
    }
    check(exited_with(ra, 0), "攻击方未以 0 退出（翻页不足、出现第三种结果或参数块被当成合法请求）");
    check(exited_with(rv, 0), "受害方未以 0 退出（图案被写坏）");
    check(after == before, "演练结束后资源未回到基线");
    kprintln!(
        "[JSR-UPTR-SMP] mode={} raced={} stale={} attack_exit={:?} victim_exit={:?} free_frames={}/{} objects={}/{} pending={} pinned={:?} reclaimed={} checks={} failed={}",
        mode,
        raced,
        stale,
        ra.and_then(|r| r.1),
        rv.and_then(|r| r.1),
        after.free_frames,
        before.free_frames,
        after.objects,
        before.objects,
        after.pending,
        after.pins,
        after == before,
        CHECKS.load(Ordering::Relaxed),
        failed()
    );
}
