//! 异步环验收演练：用户态程序端到端验证 + 内核侧验证用户态构造不出的情形。
//! Acceptance drill for asynchronous rings: an end-to-end user program plus kernel-side cases.
//!
//! # 用户态（`user/ring`，ELF 装载运行）
//! 请求 ID 单调、重复标签、`cq_full` 原子失败、信用耗尽时同步取消、信用在消费时归还、取消结果表、
//! 历史窗口淘汰、等待请求的取消与自然完成、Ring 句柄不可带 TRANSFER、非法提交被拒、关闭后操作失败。
//! 程序以退出码 0 表示全部通过（否则退出码 = 失败的步骤编号）。
//!
//! # 内核侧
//! 1. **closing 时各类请求的收尾**：排队中 ⇒ 立即取消并销毁；可中止 ⇒ 取消、等后端静止；不可中止 ⇒ 继续到自然结束；
//!    未消费的完成被丢弃；最后一个控制块销毁后 Ring 才被清理过程销毁
//! 2. **访问缓冲区的请求**：取消后完成在后端静止前不可见（「已裁决未发布」），此时再取消得到 `already_completed`
//! 3. **进程已退出后提交原子失败**，配额不变
//! 4. **Ring 句柄不可跨进程转移**
//! 5. **配额**：每进程 Ring 数、跨 Ring 的在飞请求数；超额原子失败；回收后全部归还
//!
//! 最后对象数、清理队列、空闲帧回到基线。

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::async_ring::Exec;
use kernel_core::frame::FRAME_SIZE;
use kernel_core::object::{HandleError, Rights};
use kernel_core::paging::MapFlags;
use kernel_core::ring_abi::Sqe;

use crate::kobj;
use crate::mm::frame;
use crate::proc::{self, ProcError, ProcState, ResourceQuota};
use crate::ring::{self, MAX_IN_FLIGHT_PER_PROCESS, MAX_RINGS_PER_PROCESS};
use crate::syscall::{err, table as abi, SyscallSet};
use crate::{arch, kprintln, sched};

static CHECKS: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);

/// 断言：失败时打印 `[JSR-RING-FAIL]`，继续后续用例。
fn check(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-RING-FAIL] {}", what);
    }
}

/// 失败断言数。
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

/// 用户程序 `user/ring` 的 ELF 镜像（构建期由 `kernel/build.rs` 产出并嵌入）。
static USER_RING: &[u8] = include_bytes!(env!("JSR_USER_RING"));

/// 用户栈顶（私有窗口内）与栈页数。
const STACK_TOP_OFF: u64 = 0xC0_0000;
const STACK_PAGES: u64 = 4;

/// 运行全部演练。
pub fn run() {
    let free0 = frame::free_frames();
    let (live0, _, _) = kobj::stats();
    user_program();
    closing_and_buffer();
    transfer_denied();
    quotas();
    kobj::run_cleanup(usize::MAX);
    let (live1, pending1, _) = kobj::stats();
    let reclaimed = frame::free_frames() == free0;
    check(live1 == live0 && pending1 == 0 && reclaimed, "异步环演练后对象或页帧未回到基线");
    kprintln!(
        "[JSR-RING] objects_live={}/{} pending={} reclaimed={} checks={} failed={}",
        live1,
        live0,
        pending1,
        reclaimed,
        CHECKS.load(Ordering::Relaxed),
        failed()
    );
}

/// 用户态端到端：装载并运行 `user/ring`。
fn user_program() {
    let allowed = SyscallSet::of(&[
        abi::SYSTEM_MEMORY_BUFFER_CREATE,
        abi::SYSTEM_MEMORY_BUFFER_DESTROY,
        abi::SYSTEM_EXECUTION_RESTRICTED_CREATE,
        abi::SYSTEM_TASK_INTERRUPT_SEND,
        abi::SYSTEM_MEMORY_DMA_MAP,
        abi::SYSTEM_IO_SEGMENT_SUBMIT,
        abi::SYSTEM_TASK_SYSCALLS_SET,
        abi::SYSTEM_MEMORY_OBJECT_CREATE,
        abi::SYSTEM_MEMORY_OBJECT_MAP,
        abi::SYSTEM_MEMORY_OBJECT_UNMAP,
        abi::SYSTEM_ASYNC_RING_CREATE,
        abi::SYSTEM_ASYNC_RING_ENTER,
        abi::SYSTEM_ASYNC_RING_DEADLINE_ENTER,
        abi::SYSTEM_ASYNC_CANCEL,
        abi::SYSTEM_TIME_NOW,
        abi::SYSTEM_TIME_WAIT,
        abi::SYSTEM_CONSOLE_WRITE,
        abi::SYSTEM_HANDLE_DUPLICATE,
        abi::SYSTEM_HANDLE_CLOSE,
        abi::SYSTEM_TASK_EXIT,
    ]);
    let Ok(pid) = proc::create("user-ring", allowed) else {
        check(false, "进程创建失败");
        return;
    };
    let base = arch::USER_WINDOW.0;
    let loaded = (|| {
        let entry = proc::load_elf(pid, USER_RING).map_err(|_| ProcError::Map(kernel_core::paging::MapError::InvalidAddress))?;
        for i in 1..=STACK_PAGES {
            proc::map_new(pid, base + STACK_TOP_OFF - i * FRAME_SIZE, MapFlags::USER | MapFlags::WRITE)?;
        }
        proc::spawn_thread(pid, "user-ring", entry, base + STACK_TOP_OFF, 0, 0)
    })();
    check(loaded.is_ok(), "user-ring 装载失败");
    if loaded.is_ok() {
        sched::run();
    }
    let st = proc::state(pid);
    check(st == Some(ProcState::Exited { code: 0 }), "user-ring 未以退出码 0 结束（退出码 = 失败步骤）");
    kobj::run_cleanup(usize::MAX); // 关闭句柄后 Ring 已入清理队列：销毁并归还配额
    let quota = proc::ring_quota(pid);
    check(quota == Some(ResourceQuota { rings: 0, in_flight: 0, endpoints: 0, ipc_bytes: 0 }), "user-ring 退出后 Ring 配额未归还");
    kprintln!("[JSR-RING] user exit={:?} quota_after={:?}", st, quota);
    proc::reap(pid);
    kobj::run_cleanup(usize::MAX);
}

/// closing 时各类请求的收尾 + 访问缓冲区请求的「已裁决未发布」+ 进程退出后提交原子失败。
fn closing_and_buffer() {
    let Ok(pid) = proc::create("ring-close", SyscallSet::of(&[abi::SYSTEM_TIME_NOW])) else {
        check(false, "进程创建失败");
        return;
    };
    let Ok(h) = ring::create_for(pid, 8) else {
        check(false, "Ring 创建失败");
        return;
    };
    let Some(rid) = ring::ring_of(pid, h) else {
        check(false, "Ring 句柄解析失败");
        return;
    };
    // 访问缓冲区的可中止请求：取消后，完成要等后端静止才可见
    let buf = ring::submit_manual(pid, h, 1, Some(Exec::Abortable), Some((0, 0)));
    let first = buf.map(|id| ring::cancel_for(pid, h, id));
    let v1 = ring::view(rid);
    let again = buf.map(|id| ring::cancel_for(pid, h, id));
    let hidden = matches!(v1, Some(v) if v.ready == 0 && v.decided_unpublished == 1);
    let quiesced = buf.map(|id| ring::manual_quiesce(rid, id)).unwrap_or(false);
    let v2 = ring::view(rid);
    let visible = matches!(v2, Some(v) if v.ready == 1 && v.decided_unpublished == 0);
    check(first == Ok(0) && hidden && again == Ok(err(abi::SYSTEM_ASYNC_ERROR_ALREADY_COMPLETED)) && quiesced && visible, "访问缓冲区的请求：静止前完成不可见");
    kprintln!(
        "[JSR-RING] buffer cancel={:?} hidden_before_quiesce={} cancel_again={:?} visible_after_quiesce={}",
        first,
        hidden,
        again,
        visible
    );

    // closing：排队中 / 可中止 / 不可中止 / 已发布未消费
    let queued = ring::submit_manual(pid, h, 2, None, None);
    let abortable = ring::submit_manual(pid, h, 3, Some(Exec::Abortable), None);
    let nonab = ring::submit_manual(pid, h, 4, Some(Exec::NonAbortable), None);
    let now = ring::submit_for(pid, h, &Sqe { op: abi::SYSTEM_TIME_NOW, flags: 0, user_tag: 5, arg0: 0, arg1: 0 });
    check(queued.is_ok() && abortable.is_ok() && nonab.is_ok() && now.is_ok(), "closing 用例提交失败");
    let before = ring::view(rid);
    let quota_before = proc::ring_quota(pid);
    check(proc::exit_idle(pid, 0), "无线程进程未能退出"); // 关闭句柄表 ⇒ Ring 外部所有权归零 ⇒ closing
    let after = ring::view(rid);
    let closing_ok = matches!(after, Some(v) if v.closing && v.ready == 0 && v.in_flight == 2);
    // 进程已退出：提交原子失败，配额不变
    let late = ring::submit_for(pid, h, &Sqe { op: abi::SYSTEM_TIME_NOW, flags: 0, user_tag: 6, arg0: 0, arg1: 0 });
    let quota_mid = proc::ring_quota(pid);
    let late_ok = late.is_err() && quota_mid == Some(ResourceQuota { rings: 1, in_flight: 2, endpoints: 0, ipc_bytes: 0 });
    let (live_mid, _, _) = kobj::stats();
    // 收尾：可中止的报告静止；不可中止的自然结束 ⇒ 最后一个控制块销毁 ⇒ Ring 死亡入清理队列
    let q1 = abortable.map(|id| ring::manual_quiesce(rid, id)).unwrap_or(false);
    let still = ring::view(rid).map(|v| v.in_flight);
    let f1 = nonab.map(|id| ring::manual_finish(rid, id, 7)).unwrap_or(false);
    let gone_before_cleanup = ring::view(rid).is_none();
    kobj::run_cleanup(usize::MAX);
    let (live_end, pending_end, _) = kobj::stats();
    let quota_end = proc::ring_quota(pid);
    let drained = q1 && f1 && still == Some(1) && gone_before_cleanup && live_end + 1 == live_mid && pending_end == 0 && quota_end == Some(ResourceQuota::default());
    check(closing_ok, "closing 后状态不正确");
    check(late_ok, "进程退出后的提交未原子失败或配额被改动");
    check(drained, "closing 收尾或 Ring 销毁不正确");
    kprintln!(
        "[JSR-RING] closing before={:?} after_in_flight={:?} dropped_ready={} submit_after_exit={:?} quota={:?}->{:?}",
        before.map(|v| (v.ready, v.in_flight)),
        after.map(|v| v.in_flight),
        matches!(after, Some(v) if v.ready == 0),
        late.err(),
        quota_before.map(|q| q.in_flight),
        quota_mid.map(|q| q.in_flight)
    );
    kprintln!(
        "[JSR-RING] closing abortable_quiesced={} nonabortable_finished={} ring_destroyed_after_last_request={} quota_returned={}",
        q1,
        f1,
        gone_before_cleanup && live_end + 1 == live_mid,
        quota_end == Some(ResourceQuota::default())
    );
    proc::reap(pid);
    kobj::run_cleanup(usize::MAX);
}

/// Ring 句柄不可跨进程转移（句柄不带 TRANSFER；类型也不是叶子对象）。
fn transfer_denied() {
    let (Ok(a), Ok(b)) = (proc::create("ring-a", SyscallSet::EMPTY), proc::create("ring-b", SyscallSet::EMPTY)) else {
        check(false, "进程创建失败");
        return;
    };
    let h = ring::create_for(a, 4);
    let r = h.map(|h| (proc::transfer(a, h, b), proc::handle_info(a, h).map(|(_, r)| r)));
    let ok = matches!(r, Ok((Err(ProcError::Handle(HandleError::RightsDenied)), Some(rights))) if !rights.contains(Rights::TRANSFER));
    check(ok, "Ring 句柄不应可转移");
    kprintln!("[JSR-RING] transfer result={:?}", r.as_ref().map(|(x, _)| *x));
    check(proc::exit_idle(a, 0) && proc::exit_idle(b, 0), "无线程进程未能退出");
    proc::reap(a);
    proc::reap(b);
    kobj::run_cleanup(usize::MAX);
}

/// 配额：每进程 Ring 数与跨 Ring 的在飞请求数；超额原子失败；回收后归还。
fn quotas() {
    let Ok(pid) = proc::create("ring-quota", SyscallSet::EMPTY) else {
        check(false, "进程创建失败");
        return;
    };
    let mut handles = [None; MAX_RINGS_PER_PROCESS as usize];
    for slot in handles.iter_mut() {
        *slot = ring::create_for(pid, 64).ok();
    }
    let all_created = handles.iter().all(|h| h.is_some());
    let ninth = ring::create_for(pid, 64);
    let rings_ok = all_created && ninth == Err(err(abi::SYSTEM_ERROR_QUOTA_EXCEEDED));
    // 在飞上限：前 4 个 Ring 各排队 64 个请求 = 256
    let mut accepted = 0u32;
    for h in handles.iter().take(4).flatten() {
        for _ in 0..64 {
            if ring::submit_manual(pid, *h, 0, None, None).is_ok() {
                accepted += 1;
            }
        }
    }
    let before = proc::ring_quota(pid);
    let over = handles[4].map(|h| ring::submit_manual(pid, h, 0, None, None));
    let after = proc::ring_quota(pid);
    let inflight_ok = accepted == MAX_IN_FLIGHT_PER_PROCESS
        && over == Some(Err(err(abi::SYSTEM_ERROR_QUOTA_EXCEEDED)))
        && before == after
        && after == Some(ResourceQuota { rings: MAX_RINGS_PER_PROCESS, in_flight: MAX_IN_FLIGHT_PER_PROCESS, endpoints: 0, ipc_bytes: 0 });
    check(rings_ok, "Ring 数配额不正确");
    check(inflight_ok, "在飞请求配额不正确或超额时改动了记账");
    // 进程退出 ⇒ 全部 Ring closing ⇒ 排队请求全部取消销毁 ⇒ Ring 销毁 ⇒ 配额归还
    check(proc::exit_idle(pid, 0), "无线程进程未能退出");
    kobj::run_cleanup(usize::MAX);
    let returned = proc::ring_quota(pid) == Some(ResourceQuota::default());
    check(returned, "进程退出后配额未归还");
    kprintln!(
        "[JSR-RING] quota rings={} ninth={:?} in_flight={} over={:?} unchanged_on_reject={} returned={}",
        handles.iter().filter(|h| h.is_some()).count(),
        ninth.err(),
        accepted,
        over.and_then(|r| r.err()),
        before == after,
        returned
    );
    proc::reap(pid);
    kobj::run_cleanup(usize::MAX);
}
