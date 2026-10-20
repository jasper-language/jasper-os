//! HARDEN-1C ③ 演练：长期运行——同一组资源反复创建、使用、关闭之后，资源回到基线、容量不塌陷。
//! HARDEN-1C drill: long-running reuse returns to baseline and does not erode capacity.
//!
//! # 场景
//! `user/rtdemo` role 5 循环 1500 轮：通道对收发一条消息、异步环、线程创建与等待、匿名内存映射与取消映射，
//! 每轮全部关闭。对象表与进程句柄表的槽位因此被反复复用、世代反复推进。
//!
//! # 判据
//! * 程序以 0 退出（任何一轮创建失败都会以「轮次 + 1」退出——泄漏或耗尽会表现在这里）；
//! * 空闲页帧、存活对象、清理队列、固定帧回到演练前的基线；
//! * 对象表因世代用尽而退役的槽位数不增加（槽位复用不会侵蚀可用容量；世代是 32 位，
//!   每个槽位要被复用约 42 亿次才会退役，届时按设计永久退役而不是回绕）。

use core::sync::atomic::{AtomicU32, Ordering};

use crate::baseline::baseline;
use crate::rt_demo::{finish_program, rt_calls, start_program_arg, USER_RTDEMO};
use crate::syscall;
use crate::{kobj, kprintln, sched};

static FAILED: AtomicU32 = AtomicU32::new(0);
static CHECKS: AtomicU32 = AtomicU32::new(0);

fn check(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-LONGRUN-FAIL] {}", what);
    }
}

/// 断言失败数。
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

/// 运行演练。
pub fn run() {
    let prev_preemption = sched::set_preemption(true);
    // 1500 轮 × 每轮十余次系统调用：演练期间关闭逐次系统调用日志（分发、权限检查与执行不变）
    let trace = syscall::set_trace(false);
    let before = baseline();
    let retired_before = kobj::retired_slots();
    let capacity_before = kobj::capacity();
    let started = start_program_arg("longrun", USER_RTDEMO, 5, 0, rt_calls(), |_| Ok(()));
    check(matches!(started, Some((_, true))), "长期运行进程启动失败");
    sched::run();
    let r = started.and_then(|(pid, ok)| finish_program(pid, ok));
    let after = baseline();
    let retired_after = kobj::retired_slots();
    syscall::set_trace(trace);
    sched::set_preemption(prev_preemption);
    let code = r.and_then(|x| x.1);
    check(code == Some(0), "长期运行进程未以 0 退出（某一轮创建失败：泄漏或耗尽）");
    check(after == before, "长期运行后资源未回到基线");
    check(retired_after == retired_before && kobj::capacity() == capacity_before, "对象表可用容量下降（槽位退役）");
    kprintln!(
        "[JSR-LONGRUN] exit={:?} free_frames={}/{} objects={}/{} pending={} pinned={:?} retired={}/{} capacity={} reclaimed={} checks={} failed={}",
        code,
        after.free_frames,
        before.free_frames,
        after.objects,
        before.objects,
        after.pending,
        after.pins,
        retired_after,
        retired_before,
        kobj::capacity(),
        after == before,
        CHECKS.load(Ordering::Relaxed),
        failed()
    );
}
