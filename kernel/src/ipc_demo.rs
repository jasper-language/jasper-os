//! IPC Channel 验收演练：用户态程序端到端 + 内核侧验证用户态构造不出的情形。
//! Acceptance drill for IPC channels: user programs end to end plus kernel-side cases.
//!
//! # 用户态（`user/ipc`，ELF 装载运行）
//! * 单进程语义：ring 收发、缓冲区不足（消息保留、返回所需大小）、句柄随消息移动、无 TRANSFER / 非叶子被拒、
//!   两阶段 send 复制失败无副作用、队列满、取消与交付的先后、本端关闭取消在飞 recv、对端关闭
//! * 跨进程往返：ping 把消息与线程句柄发给 pong，pong 原样送回
//!
//! # 内核侧
//! 1. **recv 进行中取消映射缓冲区**：映射消失、帧保持固定（空闲帧不增加），交付照常写入被固定的帧，请求结束后帧才归还
//! 2. **共享缓冲区**：两个 recv 用同一缓冲区，第一个完成后帧仍被第二个固定；两者都结束后才归还
//! 3. **延迟后端**：取消一个后端尚未静止的、访问缓冲区的请求 ⇒ 静止前完成不可见、帧固定；静止后完成可见、帧归还
//! 4. **消息携带叶子、接收方退出**：队列中的消息被销毁，叶子对象的所有权释放（对象被回收）
//! 5. **接收方句柄表满**：recv 以 `table_full` 结束，消息留在队列，接收方句柄表不变
//!
//! 最后对象数、清理队列、空闲帧、固定帧全部回到基线。

use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::async_ring::Exec;
use kernel_core::frame::FRAME_SIZE;
use kernel_core::object::{HandleId, ObjectType, Rights};
use kernel_core::objtable::ObjId;
use kernel_core::paging::{MapError, MapFlags};
use kernel_core::ring_abi::MsgDesc;

use crate::kobj::{self, KObject};
use crate::mm::{frame, pin};
use crate::proc::{self, ProcError, ProcState};
use crate::syscall::{err, table as abi, SyscallSet};
use crate::{arch, ipc, kprintln, ring, sched};

static CHECKS: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);

fn check(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-IPC-FAIL] {}", what);
    }
}

/// 失败断言数。
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

/// 用户程序 `user/ipc` 的 ELF 镜像（构建期由 `kernel/build.rs` 产出并嵌入）。
static USER_IPC: &[u8] = include_bytes!(env!("JSR_USER_IPC"));

const STACK_TOP_OFF: u64 = 0xC0_0000;
const STACK_PAGES: u64 = 4;
const BUF_OFF: u64 = 0x80_0000;
const DESC_OFF: u64 = 0x90_0000;

/// 用户程序可用的系统调用。
fn user_calls() -> SyscallSet {
    SyscallSet::of(&[
        abi::SYSTEM_CHANNEL_CREATE,
        abi::SYSTEM_CHANNEL_SEND,
        abi::SYSTEM_CHANNEL_RECV,
        abi::SYSTEM_ASYNC_RING_CREATE,
        abi::SYSTEM_ASYNC_RING_ENTER,
        abi::SYSTEM_ASYNC_CANCEL,
        abi::SYSTEM_TIME_WAIT,
        abi::SYSTEM_TASK_SPAWN,
        abi::SYSTEM_HANDLE_DUPLICATE,
        abi::SYSTEM_HANDLE_CLOSE,
        abi::SYSTEM_CONSOLE_WRITE,
        abi::SYSTEM_TASK_EXIT,
    ])
}

/// 装载 `user/ipc` 到进程 `pid` 并创建主线程（入口参数 `role`、`endpoint`）。
fn start(pid: ObjId, name: &'static str, role: u64, endpoint: u64) -> bool {
    let base = arch::USER_WINDOW.0;
    let r = (|| {
        let entry = proc::load_elf(pid, USER_IPC).map_err(|_| ProcError::Map(MapError::InvalidAddress))?;
        for i in 1..=STACK_PAGES {
            proc::map_new(pid, base + STACK_TOP_OFF - i * FRAME_SIZE, MapFlags::USER | MapFlags::WRITE)?;
        }
        proc::spawn_thread(pid, name, entry, base + STACK_TOP_OFF, role, endpoint)
    })();
    r.is_ok()
}

/// 运行全部演练。
pub fn run() {
    let free0 = frame::free_frames();
    let (live0, _, _) = kobj::stats();
    user_semantics();
    user_cross_process();
    pinned_buffers();
    leaf_released_on_receiver_exit();
    receiver_table_full();
    kobj::run_cleanup(usize::MAX);
    let (live1, pending1, _) = kobj::stats();
    let pins = pin::stats();
    let reclaimed = frame::free_frames() == free0;
    check(live1 == live0 && pending1 == 0 && reclaimed && pins == (0, 0), "IPC 演练后对象、页帧或固定未回到基线");
    kprintln!(
        "[JSR-IPC] objects_live={}/{} pending={} pinned={:?} reclaimed={} checks={} failed={}",
        live1,
        live0,
        pending1,
        pins,
        reclaimed,
        CHECKS.load(Ordering::Relaxed),
        failed()
    );
}

/// 用户态单进程语义。
fn user_semantics() {
    let Ok(pid) = proc::create("user-ipc", user_calls()) else {
        check(false, "进程创建失败");
        return;
    };
    let ok = start(pid, "user-ipc", 0, 0);
    check(ok, "user-ipc 装载失败");
    if ok {
        sched::run();
    }
    let st = proc::state(pid);
    check(st == Some(ProcState::Exited { code: 0 }), "user-ipc 未以退出码 0 结束（退出码 = 失败步骤）");
    kobj::run_cleanup(usize::MAX);
    let q = proc::ring_quota(pid);
    check(q == Some(proc::ResourceQuota::default()), "user-ipc 退出后配额未归还");
    kprintln!("[JSR-IPC] user exit={:?} quota_after={:?}", st, q);
    proc::reap(pid);
    kobj::run_cleanup(usize::MAX);
}

/// 用户态跨进程往返（端点由创建方分别放入两个进程的句柄表）。
fn user_cross_process() {
    let (Ok(a), Ok(b)) = (proc::create("ipc-ping", user_calls()), proc::create("ipc-pong", user_calls())) else {
        check(false, "进程创建失败");
        return;
    };
    let Ok((ha, hb)) = ipc::create_pair(a, b) else {
        check(false, "跨进程端点创建失败");
        return;
    };
    let ok = start(b, "ipc-pong", 2, hb.raw() as u64) && start(a, "ipc-ping", 1, ha.raw() as u64);
    check(ok, "ping/pong 装载失败");
    if ok {
        sched::run();
    }
    let (sa, sb) = (proc::state(a), proc::state(b));
    let both = sa == Some(ProcState::Exited { code: 0 }) && sb == Some(ProcState::Exited { code: 0 });
    check(both, "ping/pong 未都以退出码 0 结束");
    kprintln!("[JSR-IPC] cross_process ping={:?} pong={:?}", sa, sb);
    proc::reap(a);
    proc::reap(b);
    kobj::run_cleanup(usize::MAX);
}

/// 在进程内存 `va` 处写入一份接收描述并返回它。
fn put_desc(pid: ObjId, va: u64, data: u64, len: u32, handles: u64, cap: u32) -> MsgDesc {
    let d = MsgDesc { data_ptr: data, handles_ptr: handles, data_len: len, handles_cap: cap, ..MsgDesc::default() };
    let _ = proc::write(pid, va, &d.encode());
    d
}

/// 1–3：固定的缓冲区在取消映射、共享、延迟后端下的生命周期。
fn pinned_buffers() {
    let Ok(pid) = proc::create("ipc-pin", SyscallSet::of(&[abi::SYSTEM_CHANNEL_SEND, abi::SYSTEM_CHANNEL_RECV])) else {
        check(false, "进程创建失败");
        return;
    };
    let base = arch::USER_WINDOW.0;
    let (Ok((ha, hb)), Ok(rh)) = (ipc::create_pair(pid, pid), ring::create_for(pid, 8)) else {
        check(false, "端点或 Ring 创建失败");
        return;
    };
    let rid = ring::ring_of(pid, rh);
    let desc_va = base + DESC_OFF;
    let mapped = proc::map_new(pid, desc_va, MapFlags::USER | MapFlags::WRITE).is_ok();
    check(mapped, "描述页映射失败");

    // 1. recv 进行中取消映射缓冲区
    let buf1 = base + BUF_OFF;
    let _ = proc::map_new(pid, buf1, MapFlags::USER | MapFlags::WRITE);
    let d1 = put_desc(pid, desc_va, buf1, 64, desc_va + 0x100, 2);
    let req1 = ring::submit_recv_for(pid, rh, hb, desc_va, &d1);
    let before = frame::free_frames();
    let unmapped = proc::unmap_page(pid, buf1).is_ok();
    let held = frame::free_frames() == before && pin::stats().1 == 1; // 缓冲区帧已成孤儿但仍被固定
    let sent = ring::submit_send_for(pid, rh, ha, b"pinned-delivery".to_vec(), vec![]);
    let done = rid.map(|r| ring::reap_kernel(r, 8)).unwrap_or_default();
    let delivered = req1.map(|id| done.contains(&(id, 15))).unwrap_or(false);
    let out_len = proc::read_u64(pid, desc_va + 24).map(|v| v as u32);
    let returned = frame::free_frames() == before + 1 && pin::stats() == (0, 0);
    check(req1.is_ok() && unmapped && held && sent.is_ok() && delivered && out_len == Some(15) && returned, "recv 进行中取消映射：帧应固定至请求结束");
    kprintln!(
        "[JSR-IPC] unmap_during_recv frame_held={} delivered={} out_len={:?} frame_returned_after={}",
        held,
        delivered,
        out_len,
        returned
    );

    // 2. 共享缓冲区：两个 recv 用同一缓冲区
    let buf2 = base + BUF_OFF + 0x1000;
    let _ = proc::map_new(pid, buf2, MapFlags::USER | MapFlags::WRITE);
    let d2 = put_desc(pid, desc_va, buf2, 64, desc_va + 0x100, 2);
    let r1 = ring::submit_recv_for(pid, rh, hb, desc_va, &d2);
    let r2 = ring::submit_recv_for(pid, rh, hb, desc_va, &d2);
    let before = frame::free_frames();
    let _ = proc::unmap_page(pid, buf2);
    let _ = ring::submit_send_for(pid, rh, ha, b"first".to_vec(), vec![]);
    let after_first = frame::free_frames() == before && pin::stats().0 >= 1;
    let c2 = r2.map(|id| ring::cancel_for(pid, rh, id));
    let after_both = frame::free_frames() == before + 1;
    let _ = rid.map(|r| ring::reap_kernel(r, 8));
    check(r1.is_ok() && r2.is_ok() && after_first && c2 == Ok(0) && after_both, "共享缓冲区：两个请求都结束后才归还帧");
    kprintln!("[JSR-IPC] shared_buffer held_after_first={} returned_after_both={}", after_first, after_both);

    // 3. 延迟后端：访问缓冲区的请求被取消，静止前完成不可见、帧固定
    let buf3 = base + BUF_OFF + 0x2000;
    let _ = proc::map_new(pid, buf3, MapFlags::USER | MapFlags::WRITE);
    let m = ring::submit_manual(pid, rh, 0, Some(Exec::Abortable), Some((buf3, 64)));
    let c = m.map(|id| ring::cancel_for(pid, rh, id));
    let v1 = rid.and_then(ring::view);
    let before = frame::free_frames();
    let _ = proc::unmap_page(pid, buf3);
    let hidden = matches!(v1, Some(v) if v.ready == 0 && v.decided_unpublished == 1) && frame::free_frames() == before;
    let q = match (rid, m) {
        (Some(r), Ok(id)) => ring::manual_quiesce(r, id),
        _ => false,
    };
    let v2 = rid.and_then(ring::view);
    let visible = matches!(v2, Some(v) if v.ready == 1 && v.decided_unpublished == 0) && frame::free_frames() == before + 1;
    let _ = rid.map(|r| ring::reap_kernel(r, 8));
    check(c == Ok(0) && hidden && q && visible, "延迟后端：静止前完成不可见、帧固定");
    kprintln!("[JSR-IPC] delayed_backend hidden_and_pinned={} visible_and_returned_after_quiesce={}", hidden, visible);

    check(proc::exit_idle(pid, 0), "无线程进程未能退出");
    proc::reap(pid);
    kobj::run_cleanup(usize::MAX);
}

/// 4：消息携带叶子，接收方退出 ⇒ 消息销毁，叶子对象被回收。
fn leaf_released_on_receiver_exit() {
    let calls = SyscallSet::of(&[abi::SYSTEM_CHANNEL_SEND]);
    let (Ok(s), Ok(r)) = (proc::create("ipc-sender", calls), proc::create("ipc-receiver", calls)) else {
        check(false, "进程创建失败");
        return;
    };
    let (Ok((hs, _hr)), Ok(rh)) = (ipc::create_pair(s, r), ring::create_for(s, 4)) else {
        check(false, "端点或 Ring 创建失败");
        return;
    };
    let (live_before_event, _, _) = kobj::stats();
    let ev = proc::grant_new(s, KObject::Event { signaled: false }, ObjectType::Event, Rights::WAIT.union(Rights::TRANSFER));
    let sent = ev.map(|h| ring::submit_send_for(s, rh, hs, b"leaf".to_vec(), vec![h.raw()]));
    let moved = ev.map(|h| proc::handle_info(s, h).is_none()).unwrap_or(false);
    let (live_with_event, _, _) = kobj::stats();
    check(proc::exit_idle(r, 0), "接收方未能退出"); // 关闭接收端点 ⇒ 队列中的消息被销毁
    kobj::run_cleanup(usize::MAX);
    let (live_after, _, _) = kobj::stats();
    // 接收方退出后：事件对象与接收端点都已销毁（进程对象本身仍由创建者持有）
    let released = live_with_event == live_before_event + 1 && live_after + 2 == live_with_event;
    check(matches!(sent, Ok(Ok(_))) && moved && released, "接收方退出后消息中的叶子未被回收");
    kprintln!(
        "[JSR-IPC] leaf_in_queue_released_on_receiver_exit={} sender_handle_moved={} live={}/{}/{}",
        released,
        moved,
        live_before_event,
        live_with_event,
        live_after
    );
    check(proc::exit_idle(s, 0), "发送方未能退出");
    proc::reap(s);
    proc::reap(r);
    kobj::run_cleanup(usize::MAX);
}

/// 5：接收方句柄表满 ⇒ recv 以 table_full 结束，消息保留，接收方无变化。
fn receiver_table_full() {
    let calls = SyscallSet::of(&[abi::SYSTEM_CHANNEL_SEND, abi::SYSTEM_CHANNEL_RECV]);
    let (Ok(s), Ok(r)) = (proc::create("ipc-s2", calls), proc::create("ipc-r2", calls)) else {
        check(false, "进程创建失败");
        return;
    };
    let base = arch::USER_WINDOW.0;
    let (Ok((hs, hr)), Ok(srh), Ok(rrh)) = (ipc::create_pair(s, r), ring::create_for(s, 4), ring::create_for(r, 4)) else {
        check(false, "端点或 Ring 创建失败");
        return;
    };
    let desc_va = base + DESC_OFF;
    let _ = proc::map_new(r, desc_va, MapFlags::USER | MapFlags::WRITE);
    let _ = proc::map_new(r, base + BUF_OFF, MapFlags::USER | MapFlags::WRITE);
    let ev = proc::grant_new(s, KObject::Event { signaled: false }, ObjectType::Event, Rights::WAIT.union(Rights::TRANSFER));
    let sent = ev.map(|h| ring::submit_send_for(s, srh, hs, b"with-handle".to_vec(), vec![h.raw()]));
    // 填满接收方句柄表
    let mut fillers: Vec<HandleId> = Vec::new();
    while proc::free_handle_slots(r) > 0 {
        match proc::grant_new(r, KObject::Event { signaled: false }, ObjectType::Event, Rights::WAIT) {
            Ok(h) => fillers.push(h),
            Err(_) => break,
        }
    }
    let d = put_desc(r, desc_va, base + BUF_OFF, 64, desc_va + 0x100, 2);
    let req = ring::submit_recv_for(r, rrh, hr, desc_va, &d);
    let done = ring::ring_of(r, rrh).map(|x| ring::reap_kernel(x, 4)).unwrap_or_default();
    let table_full = req.map(|id| done.contains(&(id, err(abi::SYSTEM_HANDLE_ERROR_TABLE_FULL)))).unwrap_or(false);
    let kept = ipc::queued(r, hr) == Some(1) && proc::free_handle_slots(r) == 0;
    check(matches!(sent, Ok(Ok(_))) && table_full && kept, "接收方句柄表满：recv 应以 table_full 结束且消息保留");
    kprintln!("[JSR-IPC] receiver_table_full result_table_full={} message_kept={} fillers={}", table_full, kept, fillers.len());
    check(proc::exit_idle(r, 0) && proc::exit_idle(s, 0), "进程未能退出");
    proc::reap(r);
    proc::reap(s);
    kobj::run_cleanup(usize::MAX);
}
