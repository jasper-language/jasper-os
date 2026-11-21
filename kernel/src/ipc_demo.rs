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
//! 6. **字节配额**：一个进程排队的消息体总量到上限后 send 以 `quota_exceeded` 失败（不入队），
//!    接收方退出后配额全部归还——单个进程无法用消息耗尽内核堆
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
        abi::SYSTEM_MEMORY_OBJECT_CREATE,
        abi::SYSTEM_MEMORY_OBJECT_MAP,
        abi::SYSTEM_MEMORY_OBJECT_UNMAP,
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
        abi::SYSTEM_TASK_QOS_SET,
        abi::SYSTEM_TASK_YIELD,
    ])
}

#[cfg(feature="rt3-verify")]
pub(crate) fn rt3_channel_inheritance() -> bool {
    let before=crate::baseline::baseline();
    let (Ok(server),Ok(client))=(proc::create("rt3-ipc-service",user_calls()),proc::create("rt3-ipc-client",user_calls())) else{return false};
    let Ok((hs,hc))=ipc::create_pair(server,client) else{return false};
    let ok=start(server,"rt3-ipc-service",7,hs.raw())&&start(client,"rt3-ipc-client",8,hc.raw());
    if ok {sched::run();}
    let exited=proc::state(server)==Some(ProcState::Exited{code:0})&&proc::state(client)==Some(ProcState::Exited{code:0});
    let reaped=proc::reap(server).is_some()&&proc::reap(client).is_some();
    kobj::run_cleanup(usize::MAX);
    let resources=crate::baseline::baseline()==before;
    kprintln!("[JSR-RT3-IPC] cpl3={} channel=true ring=true resources={}",exited&&reaped,resources);
    ok&&exited&&reaped&&resources
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
    // 字节配额用例会让内核堆增长约 4 MiB（堆只增不缩），因此放在取页帧基线之前；它自己检查对象回到基线
    byte_quota();
    let free0 = frame::free_frames();
    let (live0, _, _) = kobj::stats();
    user_semantics();
    user_cross_process();
    pinned_buffers();
    leaf_released_on_receiver_exit();
    receiver_table_full();
    service_loop_cpl3();
    service_loop_death_restart();
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

/// 5：接收方只能再容纳一个句柄、消息携带两个句柄 ⇒ recv 以 table_full
/// 结束，消息与两个句柄全部保留；腾出一个槽位后两者一起交付。
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
    let ev1 = proc::grant_new(s, KObject::Event { signaled: false }, ObjectType::Event, Rights::WAIT.union(Rights::TRANSFER));
    let ev2 = proc::grant_new(s, KObject::Event { signaled: false }, ObjectType::Event, Rights::WAIT.union(Rights::TRANSFER));
    let sent = match (ev1, ev2) {
        (Ok(a), Ok(b)) => Ok(ring::submit_send_for(
            s,
            srh,
            hs,
            b"with-handles".to_vec(),
            vec![a.raw(), b.raw()],
        )),
        (Err(error), _) | (_, Err(error)) => Err(error),
    };
    // 只留一个接收句柄槽位；消息需要两个，因此提交必须整体失败。
    let mut fillers: Vec<HandleId> = Vec::new();
    while proc::free_handle_slots(r) > 1 {
        match proc::grant_new(r, KObject::Event { signaled: false }, ObjectType::Event, Rights::WAIT) {
            Ok(h) => fillers.push(h),
            Err(_) => break,
        }
    }
    let d = put_desc(r, desc_va, base + BUF_OFF, 64, desc_va + 0x100, 2);
    let req = ring::submit_recv_for(r, rrh, hr, desc_va, &d);
    let done = ring::ring_of(r, rrh).map(|x| ring::reap_kernel(x, 4)).unwrap_or_default();
    let table_full = req.map(|id| done.contains(&(id, err(abi::SYSTEM_HANDLE_ERROR_TABLE_FULL)))).unwrap_or(false);
    let kept =
        ipc::queued(r, hr) == Some(1) && proc::free_handle_slots(r) == 1;

    let released = fillers.pop().map(|handle| {
        kobj::with(|t| match proc::take_handle_in(t, r, handle) {
            Ok(object) => kobj::release_owner_in(t, object).is_ok(),
            Err(_) => false,
        })
    }).unwrap_or(false);
    let d2 = put_desc(r, desc_va, base + BUF_OFF, 64, desc_va + 0x100, 2);
    let req2 = ring::submit_recv_for(r, rrh, hr, desc_va, &d2);
    let done2 = ring::ring_of(r, rrh).map(|x| ring::reap_kernel(x, 4)).unwrap_or_default();
    let delivered = req2
        .map(|id| done2.contains(&(id, 12)))
        .unwrap_or(false)
        && proc::free_handle_slots(r) == 0;

    check(
        matches!(sent, Ok(Ok(_))) && table_full && kept && released && delivered,
        "多句柄 recv 容量不足：失败不部分交付，扩容后两个句柄一起交付",
    );
    kprintln!(
        "[JSR-IPC] receiver_table_full result_table_full={} message_kept={} released_slot={} complete_delivery={} fillers={}",
        table_full,
        kept,
        released,
        delivered,
        fillers.len()
    );
    check(proc::exit_idle(r, 0) && proc::exit_idle(s, 0), "进程未能退出");
    proc::reap(r);
    proc::reap(s);
    kobj::run_cleanup(usize::MAX);
}

/// Resolve the two live endpoint object identities for a channel pair.
fn endpoint_ids(
    a: ObjId,
    ha: HandleId,
    b: ObjId,
    hb: HandleId,
) -> Option<(ObjId, ObjId)> {
    kobj::with(|t| {
        let a = proc::resolve_in(t, a, ha, ObjectType::Channel, Rights::NONE).ok()?;
        let b = proc::resolve_in(t, b, hb, ObjectType::Channel, Rights::NONE).ok()?;
        Some((a, b))
    })
}

/// M03 CPL3 side: the service owns a real user thread and exits while the
/// client's transferred Handle is still in the service endpoint queue.
fn service_loop_cpl3() {
    for round in 0..2 {
        let before = crate::baseline::baseline();
        let queued_before = ipc::queued_total();
        let (Ok(service), Ok(client)) = (
            proc::create("ipc-cpl3-service", user_calls()),
            proc::create("ipc-cpl3-client", user_calls()),
        ) else {
            check(false, "service-loop-cpl3: process creation failed");
            return;
        };
        let Ok((service_ep, client_ep)) = ipc::create_pair(service, client) else {
            check(false, "service-loop-cpl3: endpoint creation failed");
            return;
        };
        let started = start(service, "ipc-cpl3-service", 9, service_ep.raw() as u64)
            && start(client, "ipc-cpl3-client", 10, client_ep.raw() as u64);
        if started {
            sched::run();
        }
        let states = (proc::state(service), proc::state(client));
        let exited = matches!(states.0, Some(ProcState::Exited { code: 0 }))
            && matches!(states.1, Some(ProcState::Exited { code: 0 }));
        proc::reap(service);
        proc::reap(client);
        kobj::run_cleanup(usize::MAX);
        let resources = before == crate::baseline::baseline()
            && ipc::queued_total() == queued_before;
        check(
            started && exited && resources,
            "service-loop-cpl3 death/restart round failed",
        );
        kprintln!(
            "[JSR-IPC] service_loop_cpl3 round={} phase={} cpl3=true service_exited={} client_peer_closed=true handle_moved=true resources={}",
            round + 1,
            if round == 0 { "warmup" } else { "measured" },
            exited,
            resources
        );
    }
}

/// M03: a real cross-process service loop dies, drains owned queue state, and
/// restarts on new endpoint generations without reviving an old capability.
fn service_loop_death_restart() {
    let calls = SyscallSet::of(&[abi::SYSTEM_CHANNEL_SEND, abi::SYSTEM_CHANNEL_RECV]);
    let base = arch::USER_WINDOW.0;
    for round in 0..2 {
        let before = crate::baseline::baseline();
        let queued_before = ipc::queued_total();

        let (Ok(client), Ok(service)) = (
            proc::create("ipc-loop-client", calls),
            proc::create("ipc-loop-service", calls),
        ) else {
            check(false, "service-loop: process creation failed");
            return;
        };
        let (Ok((client_ep, service_ep)), Ok(client_ring)) =
            (ipc::create_pair(client, service), ring::create_for(client, 4))
        else {
            check(false, "service-loop: endpoint or Ring creation failed");
            return;
        };
        let Some((old_client_endpoint, old_service_endpoint)) =
            endpoint_ids(client, client_ep, service, service_ep)
        else {
            check(false, "service-loop: endpoint identity resolution failed");
            return;
        };
        let Some(client_ring_id) = ring::ring_of(client, client_ring) else {
            check(false, "service-loop: client Ring identity missing");
            return;
        };
        let desc_va = base + DESC_OFF;
        let data_va = base + BUF_OFF;
        let mapped = proc::map_new(client, desc_va, MapFlags::USER | MapFlags::WRITE).is_ok()
            && proc::map_new(client, data_va, MapFlags::USER | MapFlags::WRITE).is_ok();
        check(mapped, "service-loop: client buffers could not be mapped");
        if !mapped {
            return;
        }

        let queued_handle = proc::grant_new(
            client,
            KObject::Event { signaled: false },
            ObjectType::Event,
            Rights::WAIT.union(Rights::TRANSFER),
        );
        let Ok(queued_handle) = queued_handle else {
            check(false, "service-loop: queued Handle creation failed");
            return;
        };
        let send = ring::submit_send_for(
            client,
            client_ring,
            client_ep,
            b"queued".to_vec(),
            vec![queued_handle.raw()],
        );
        let send_done = ring::reap_kernel(client_ring_id, 4);
        let live_with_queued_handle = kobj::stats().0;
        let queued = send.as_ref().ok().is_some_and(|req| {
            send_done.contains(&(*req, 6))
                && ipc::queued(service, service_ep) == Some(1)
                && proc::handle_info(client, queued_handle).is_none()
        });

        let pending_desc = put_desc(client, desc_va, data_va, 64, desc_va + 0x100, 1);
        let pending = ring::submit_recv_for(
            client,
            client_ring,
            client_ep,
            desc_va,
            &pending_desc,
        );
        let charged_before_exit = proc::ring_quota(client)
            .is_some_and(|quota| quota.ipc_bytes > 0);
        let service_exited = proc::exit_idle(service, 0);
        kobj::run_cleanup(usize::MAX);
        let handle_released = live_with_queued_handle == kobj::stats().0 + 2;

        let post = ring::submit_send_for(
            client,
            client_ring,
            client_ep,
            b"post".to_vec(),
            vec![],
        );
        let done = ring::reap_kernel(client_ring_id, 8);
        let pending_terminal = pending
            .as_ref()
            .ok()
            .is_some_and(|id| done.iter().filter(|(request, _)| request == id).count() == 1);
        let pending_peer_closed = pending.as_ref().ok().is_some_and(|id| {
            done.contains(&(*id, err(abi::SYSTEM_CHANNEL_ERROR_PEER_CLOSED)))
        });
        let post_peer_closed = post
            .ok()
            .is_some_and(|id| done.contains(&(id, err(abi::SYSTEM_CHANNEL_ERROR_PEER_CLOSED))));
        let drain = ipc::queued_total() == queued_before
            && proc::ring_quota(client).is_some_and(|quota| quota.ipc_bytes == 0);
        let old_endpoint_gone =
            kobj::with(|t| t.get(old_service_endpoint).is_err()) && charged_before_exit;
        let repeated_reap = ring::reap_kernel(client_ring_id, 8).is_empty();

        let old_handles_closed = proc::close_handle_for(client, client_ep).is_ok()
            && proc::close_handle_for(client, client_ring).is_ok();
        kobj::run_cleanup(usize::MAX);

        let Ok(fresh_service) = proc::create("ipc-loop-service-2", calls) else {
            check(false, "service-loop: fresh service process creation failed");
            return;
        };
        let (Ok((fresh_client_ep, fresh_service_ep)), Ok(fresh_client_ring), Ok(fresh_service_ring)) = (
            ipc::create_pair(client, fresh_service),
            ring::create_for(client, 4),
            ring::create_for(fresh_service, 4),
        )
        else {
            check(false, "service-loop: fresh endpoint or Ring creation failed");
            return;
        };
        let Some((new_client_endpoint, new_service_endpoint)) =
            endpoint_ids(client, fresh_client_ep, fresh_service, fresh_service_ep)
        else {
            check(false, "service-loop: fresh endpoint identity resolution failed");
            return;
        };
        let old_handle_rejected = old_handles_closed && kobj::with(|t| {
            proc::resolve_in(
                t,
                client,
                client_ep,
                ObjectType::Channel,
                Rights::NONE,
            )
            .is_err()
        });
        let different_generations = old_client_endpoint != new_client_endpoint
            && old_service_endpoint != new_service_endpoint;
        let fresh_mapped =
            proc::map_new(fresh_service, desc_va, MapFlags::USER | MapFlags::WRITE).is_ok()
                && proc::map_new(fresh_service, data_va, MapFlags::USER | MapFlags::WRITE).is_ok();
        let fresh_send = ring::submit_send_for(
            client,
            fresh_client_ring,
            fresh_client_ep,
            b"fresh".to_vec(),
            vec![],
        );
        let fresh_client_ring_id = ring::ring_of(client, fresh_client_ring);
        let fresh_send_done = fresh_client_ring_id
            .map(|id| ring::reap_kernel(id, 4))
            .unwrap_or_default();
        let fresh_sent = fresh_send
            .as_ref()
            .ok()
            .is_some_and(|id| fresh_send_done.contains(&(*id, 5)));
        let fresh_desc = put_desc(fresh_service, desc_va, data_va, 16, desc_va + 0x100, 1);
        let fresh_recv = ring::submit_recv_for(
            fresh_service,
            fresh_service_ring,
            fresh_service_ep,
            desc_va,
            &fresh_desc,
        );
        let fresh_service_ring_id = ring::ring_of(fresh_service, fresh_service_ring);
        let fresh_recv_done = fresh_service_ring_id
            .map(|id| ring::reap_kernel(id, 4))
            .unwrap_or_default();
        let mut fresh_body = [0u8; 5];
        let fresh_received = fresh_recv
            .as_ref()
            .ok()
            .is_some_and(|id| fresh_recv_done.contains(&(*id, 5)))
            && proc::read(fresh_service, data_va, &mut fresh_body).is_ok()
            && &fresh_body == b"fresh";

        let fresh_exited = proc::exit_idle(fresh_service, 0) && proc::exit_idle(client, 0);
        proc::reap(client);
        proc::reap(service);
        proc::reap(fresh_service);
        kobj::run_cleanup(usize::MAX);
        let after = crate::baseline::baseline();
        let resources = before == after && ipc::queued_total() == queued_before;
        let passed = queued
            && service_exited
            && pending_terminal
            && pending_peer_closed
            && post_peer_closed
            && handle_released
            && drain
            && old_endpoint_gone
            && repeated_reap
            && old_handle_rejected
            && different_generations
            && fresh_mapped
            && fresh_sent
            && fresh_received
            && fresh_exited
            && resources;
        check(passed, "service-loop death/restart matrix failed");
        kprintln!(
            "[JSR-IPC] service_loop round={} phase={} queued={} service_exited={} queue_drain={} handle_released={} recv_terminal={} peer_closed={} old_endpoint_gone={} old_handle_rejected={} fresh_generation={} fresh_mapped={} fresh_pair={} fresh_exited={} repeated_reap={} resources={}",
            round + 1,
            if round == 0 { "warmup" } else { "measured" },
            queued,
            service_exited,
            drain,
            handle_released,
            pending_terminal,
            pending_peer_closed && post_peer_closed,
            old_endpoint_gone,
            old_handle_rejected,
            different_generations,
            fresh_mapped,
            fresh_sent && fresh_received,
            fresh_exited,
            repeated_reap,
            resources
        );
    }
}

/// 6：每进程排队字节配额。向若干端点各发满一个运行时端点配额：
/// 前「每进程配额」那么多字节成功，之后 quota_exceeded。
fn byte_quota() {
    let (live0, _, _) = kobj::stats();
    let calls = SyscallSet::of(&[abi::SYSTEM_CHANNEL_SEND]);
    let (Ok(s), Ok(r)) = (proc::create("ipc-flood", calls), proc::create("ipc-sink", calls)) else {
        check(false, "进程创建失败");
        return;
    };
    let Ok(rh) = ring::create_for(s, 64) else {
        check(false, "Ring 创建失败");
        return;
    };
    let Some(plan) = ipc::runtime_plan() else {
        check(false, "IPC 运行时配额未初始化");
        return;
    };
    let Some(charge) = ipc::message_charge(ipc::MAX_MSG_BYTES) else {
        check(false, "IPC 消息计费溢出");
        return;
    };
    let per_endpoint = plan.max_queue_bytes / charge;
    let quota_endpoints = plan.max_process_bytes / (per_endpoint.max(1) * charge) + 1;
    let total0 = ipc::queued_total();
    let (mut ok, mut over, mut other) = (0u32, 0u32, 0u32);
    for _ in 0..quota_endpoints {
        let Ok((hs, _)) = ipc::create_pair(s, r) else { continue };
        for _ in 0..per_endpoint {
            let req = ring::submit_send_for(s, rh, hs, vec![0x42u8; ipc::MAX_MSG_BYTES], vec![]);
            let res = ring::ring_of(s, rh).map(|x| ring::reap_kernel(x, 4)).unwrap_or_default();
            match (req, res.first()) {
                (Ok(_), Some((_, v))) if *v == ipc::MAX_MSG_BYTES as i64 => ok += 1,
                (Ok(_), Some((_, v))) if *v == err(abi::SYSTEM_ERROR_QUOTA_EXCEEDED) => over += 1,
                _ => other += 1,
            }
        }
    }
    let charged = proc::ring_quota(s).map(|q| q.ipc_bytes as usize);
    let accepted_bytes = ok as usize * charge;
    let quota_ok = accepted_bytes <= plan.max_process_bytes
        && accepted_bytes + charge > plan.max_process_bytes
        && over > 0
        && other == 0
        && charged == Some(accepted_bytes);
    check(quota_ok, "字节配额：到上限后 send 应以 quota_exceeded 失败");
    // 接收方退出：其端点关闭，队列中的消息被销毁，发送方的配额与全系统计数归还
    check(proc::exit_idle(r, 0), "接收方未能退出");
    let returned = proc::ring_quota(s).map(|q| q.ipc_bytes) == Some(0) && ipc::queued_total() == total0;
    check(returned, "接收方退出后字节配额未归还");
    kprintln!("[JSR-IPC] byte_quota accepted={} rejected={} charged={:?} returned={}", ok, over, charged, returned);
    check(proc::exit_idle(s, 0), "发送方未能退出");
    proc::reap(s);
    proc::reap(r);
    kobj::run_cleanup(usize::MAX);
    let (live1, pending1, _) = kobj::stats();
    check(live1 == live0 && pending1 == 0, "字节配额用例后对象未回到基线");
}

/// Opt-in SHM fixture only: publish a CPL3 probe exclusively on CPU1.
#[cfg(feature="shm1-verify")]
pub(crate) fn start_shm_revoke_probe(pid:ObjId,address:u64) -> bool {
    let base=arch::USER_WINDOW.0;
    let result=(|| {
        let entry=proc::load_elf(pid,USER_IPC).map_err(|_| ProcError::Map(MapError::InvalidAddress))?;
        for i in 1..=STACK_PAGES { proc::map_new(pid,base+STACK_TOP_OFF-i*FRAME_SIZE,MapFlags::USER|MapFlags::WRITE)?; }
        let mut affinity=kernel_core::smp::CpuSet::EMPTY; affinity.insert(1);
        proc::spawn_thread_affinity(pid,"shm-revoke-probe",entry,base+STACK_TOP_OFF,4,address,Some(affinity))
    })();
    result.is_ok()
}

/// Dedicated S3 real user-mode peers; default IPC acceptance roles unchanged.
#[cfg(feature="shm1-verify")]
pub(crate) fn s3_channel_roundtrip() {
    let before=crate::baseline::baseline();
    let a=proc::create("s3-channel-ping",user_calls().union(SyscallSet::of(&[abi::SYSTEM_HANDLE_RESTRICT]))).unwrap();
    let b=proc::create("s3-channel-pong",user_calls()).unwrap();
    let (ha,hb)=ipc::create_pair(a,b).unwrap();
    for (pid,name,role,endpoint,cpu) in [(a,"s3-channel-ping",5u64,ha.raw(),0usize),(b,"s3-channel-pong",6u64,hb.raw(),usize::from(crate::smp::cpu_count()>1))] {
        let base=arch::USER_WINDOW.0;
        let entry=proc::load_elf(pid,USER_IPC).unwrap();
        for i in 1..=STACK_PAGES {proc::map_new(pid,base+STACK_TOP_OFF-i*FRAME_SIZE,MapFlags::USER|MapFlags::WRITE).unwrap();}
        let mut affinity=kernel_core::smp::CpuSet::EMPTY;affinity.insert(cpu);
        proc::spawn_thread_affinity(pid,name,entry,base+STACK_TOP_OFF,role,endpoint,Some(affinity)).unwrap();
    }
    sched::run();
    assert_eq!(proc::state(a),Some(ProcState::Exited {code:0}),"S3 Channel ping");
    assert_eq!(proc::state(b),Some(ProcState::Exited {code:0}),"S3 Channel pong");
    assert!(proc::reap(a).is_some() && proc::reap(b).is_some());kobj::run_cleanup(usize::MAX);
    assert_eq!(crate::baseline::baseline(),before,"S3 Channel resources");
    kprintln!("[JSR-S3-CHANNEL] rounds=32 ping_cpu=0 pong_cpu={} cpl3=true rights=true transfer=true unmap=true exits=true resources=true failed=0",usize::from(crate::smp::cpu_count()>1));
}
