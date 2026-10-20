//! DRV-0 演练：进程的应用身份（装载时写入、进程不可改）与通道消息上的发送方身份章。
//! DRV-0 drill: process application identity, bound at load time, and the sender identity stamp on messages.
//!
//! # 覆盖
//! 1. 新进程的身份为 0（未绑定）；
//! 2. 装载时绑定一次后可以读到；
//! 3. 再次绑定被拒（身份不可改）；
//! 4. 非法身份（0）被拒；
//! 5. 已绑定身份的进程发送消息，接收方读到的 `out_sender` / `out_sender_app` 都是内核写入的真实值；
//! 6. 发送方与接收方预填的输出字段被内核覆盖，伪造无效；
//! 7. 未绑定身份的进程发出的消息章为 0（接收方可据此拒绝匿名来源）；
//! 8. 二次绑定被拒后，后续消息仍是首次绑定的身份；
//! 9. 发送方在接收前退出并被回收，消息上的章仍是发送时的身份；
//! 10. 接收缓冲区不足：输出字段已盖章、消息留在队列，随后用够大的缓冲区收到同一条消息。
//!
//! # 边界
//! 这里只验证"身份事实"的写入、不可变性以及消息上的身份章；身份如何用于授权由服务接口阶段决定。
//! 演练使用内核侧提交入口（与用户态 ring 提交走同一套交付路径），不需要用户态程序参与。

use core::sync::atomic::{AtomicU32, Ordering};

use alloc::vec;

use kernel_core::object::HandleId;
use kernel_core::objtable::ObjId;
use kernel_core::paging::MapFlags;
use kernel_core::ring_abi::MsgDesc;

use crate::kobj;
use crate::mm::{frame, pin};
use crate::proc::{self, ProcError};
use crate::syscall::table as abi;
use crate::syscall::{err, SyscallSet};
use crate::{arch, ipc, kprintln, ring};

static CHECKS: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);

fn check(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-APPID-FAIL] {}", what);
    }
}

/// 本演练的失败断言数。
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

/// 演练用的系统调用集合：内核侧提交仍经过同一条权限检查，因此进程必须被授予收发操作。
fn calls() -> SyscallSet {
    SyscallSet::of(&[abi::SYSTEM_CHANNEL_SEND, abi::SYSTEM_CHANNEL_RECV])
}

const DESC_OFF: u64 = 0x90_0000;
const BUF_OFF: u64 = 0x80_0000;
const DESC_STRIDE: u64 = 0x40;

/// 一次收发演练所需的进程、端点、Ring 与已映射的用户内存。
struct Fixture {
    /// 发送方进程。
    sender: ObjId,
    /// 接收方进程。
    receiver: ObjId,
    /// 发送方持有的端点。
    send_ep: HandleId,
    /// 接收方持有的端点。
    recv_ep: HandleId,
    /// 发送方的 Ring。
    send_ring: HandleId,
    /// 接收方的 Ring。
    recv_ring: HandleId,
    /// 发送方进程中的描述页（用于验证"预填被忽略"）。
    send_desc_va: u64,
    /// 接收方进程中的描述页（可放两份描述）。
    recv_desc_va: u64,
    /// 接收方的消息缓冲区。
    buf_va: u64,
}

/// 接收描述的输出字段（内核写回后读出的值）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Outputs {
    data_len: u32,
    handles: u32,
    sender: u32,
    sender_app: u32,
}

/// 建立一套演练资源：两个无线程进程、一对端点、两个 Ring，以及描述页与缓冲区。
/// 失败返回 `None`；调用方以一次失败断言记录，不继续使用半成品。
fn fixture(app: Option<u32>) -> Option<Fixture> {
    let sender = proc::create("appid-sender", calls()).ok()?;
    let receiver = proc::create("appid-receiver", calls()).ok()?;
    if let Some(a) = app {
        proc::set_app(sender, a).ok()?;
    }
    let base = arch::USER_WINDOW.0;
    let send_desc_va = base + DESC_OFF;
    let recv_desc_va = base + DESC_OFF + 0x100;
    let buf_va = base + BUF_OFF;
    proc::map_new(sender, send_desc_va, MapFlags::USER | MapFlags::WRITE).ok()?;
    proc::map_new(receiver, recv_desc_va, MapFlags::USER | MapFlags::WRITE).ok()?;
    proc::map_new(receiver, buf_va, MapFlags::USER | MapFlags::WRITE).ok()?;
    let (send_ep, recv_ep) = ipc::create_pair(sender, receiver).ok()?;
    let send_ring = ring::create_for(sender, 8).ok()?;
    let recv_ring = ring::create_for(receiver, 8).ok()?;
    Some(Fixture { sender, receiver, send_ep, recv_ep, send_ring, recv_ring, send_desc_va, recv_desc_va, buf_va })
}

/// 退出并回收两个进程（进程没有线程，可直接进入 exited），随后运行清理过程。
fn teardown(fx: &Fixture) {
    check(proc::exit_idle(fx.sender, 0) && proc::exit_idle(fx.receiver, 0), "演练进程未能退出");
    proc::reap(fx.sender);
    proc::reap(fx.receiver);
    kobj::run_cleanup(usize::MAX);
}

/// 构造一份接收描述；`prefill` 非空时把两个身份输出字段预填为该值（模拟用户态伪造）。
fn recv_desc(buf_va: u64, cap: u32, prefill: Option<u32>) -> MsgDesc {
    let v = prefill.unwrap_or(0);
    MsgDesc {
        data_ptr: buf_va,
        handles_ptr: 0,
        data_len: cap,
        handles_cap: 0,
        out_data_len: 0,
        out_handles: 0,
        out_sender: v,
        out_sender_app: v,
    }
}

/// 把描述写进进程内存。
fn put_desc(pid: ObjId, va: u64, d: &MsgDesc) -> bool {
    proc::write(pid, va, &d.encode()).is_ok()
}

/// 读出描述中的四个输出字段（两个 64 位读取，覆盖偏移 24..40）。
fn outputs(pid: ObjId, va: u64) -> Outputs {
    let lo = proc::read_u64(pid, va + 24).unwrap_or(0);
    let hi = proc::read_u64(pid, va + 32).unwrap_or(0);
    Outputs {
        data_len: lo as u32,
        handles: (lo >> 32) as u32,
        sender: hi as u32,
        sender_app: (hi >> 32) as u32,
    }
}

/// 取指定请求的完成结果（收取并消费该 Ring 的完成记录）。
fn result(pid: ObjId, ring_h: HandleId, req: u64) -> Option<i64> {
    let r = ring::ring_of(pid, ring_h)?;
    ring::reap_kernel(r, 8).into_iter().find(|(id, _)| *id == req).map(|(_, v)| v)
}

/// 先提交接收、再提交发送，返回两边的完成结果。
fn exchange(fx: &Fixture, body: &[u8], cap: u32, prefill: Option<u32>) -> (Option<i64>, Option<i64>, Outputs) {
    let d = recv_desc(fx.buf_va, cap, prefill);
    if !put_desc(fx.receiver, fx.recv_desc_va, &d) {
        return (None, None, outputs(fx.receiver, fx.recv_desc_va));
    }
    let recv_req = ring::submit_recv_for(fx.receiver, fx.recv_ring, fx.recv_ep, fx.recv_desc_va, &d).ok();
    let send_req = ring::submit_send_for(fx.sender, fx.send_ring, fx.send_ep, body.to_vec(), vec![]).ok();
    let recv_ret = recv_req.and_then(|r| result(fx.receiver, fx.recv_ring, r));
    let send_ret = send_req.and_then(|r| result(fx.sender, fx.send_ring, r));
    (recv_ret, send_ret, outputs(fx.receiver, fx.recv_desc_va))
}

/// 已绑定身份：接收方读到真实的应用身份与发送方进程标识。
fn case_bound() {
    let Some(fx) = fixture(Some(0x5157)) else {
        check(false, "bound 用例资源创建失败");
        return;
    };
    let body = b"stamp-bound";
    let (recv_ret, send_ret, out) = exchange(&fx, body, 64, None);
    let pid_match = out.sender == fx.sender.raw() as u32;
    let delivered = recv_ret == Some(body.len() as i64) && send_ret == Some(body.len() as i64);
    check(delivered, "bound：消息应成功送达且完成记录为消息体长度");
    check(out.data_len == body.len() as u32 && out.handles == 0, "bound：输出长度与句柄数不正确");
    check(out.sender_app == 0x5157, "bound：out_sender_app 应为发送方身份");
    check(pid_match, "bound：out_sender 应为发送方进程标识低 32 位");
    let ok = delivered && out.data_len == body.len() as u32 && out.handles == 0 && out.sender_app == 0x5157 && pid_match;
    kprintln!(
        "[JSR-APPID] stamp case=bound app=0x5157 out_sender_app={:#x} pid_match={} ok={}",
        out.sender_app,
        pid_match,
        ok
    );
    teardown(&fx);
}

/// 伪造：发送方与接收方都预填 0xdead，内核写回的真实值覆盖预填。
fn case_forged() {
    let Some(fx) = fixture(Some(0x5157)) else {
        check(false, "forged 用例资源创建失败");
        return;
    };
    // 发送方在自己的描述里写下伪造值；提交路径只复制消息体，输出字段从不作为输入。
    let forged = MsgDesc { out_sender: 0xdead, out_sender_app: 0xdead, ..MsgDesc::default() };
    check(put_desc(fx.sender, fx.send_desc_va, &forged), "forged：发送方预填描述写入失败");
    let body = b"stamp-forged";
    let (recv_ret, send_ret, out) = exchange(&fx, body, 64, Some(0xdead));
    let delivered = recv_ret == Some(body.len() as i64) && send_ret == Some(body.len() as i64);
    check(delivered, "forged：消息应成功送达");
    check(out.sender_app == 0x5157 && out.sender_app != 0xdead, "forged：预填的应用身份必须被内核覆盖");
    check(out.sender == fx.sender.raw() as u32 && out.sender != 0xdead, "forged：预填的进程标识必须被内核覆盖");
    let ok = delivered && out.sender_app == 0x5157 && out.sender == fx.sender.raw() as u32;
    kprintln!(
        "[JSR-APPID] stamp case=forged prefilled=0xdead out_sender_app={:#x} ok={}",
        out.sender_app,
        ok
    );
    teardown(&fx);
}

/// 未绑定身份：消息章为 0。
fn case_unbound() {
    let Some(fx) = fixture(None) else {
        check(false, "unbound 用例资源创建失败");
        return;
    };
    check(proc::app(fx.sender) == Some(0), "unbound：发送方应未绑定身份");
    let body = b"stamp-unbound";
    let (recv_ret, send_ret, out) = exchange(&fx, body, 64, None);
    let delivered = recv_ret == Some(body.len() as i64) && send_ret == Some(body.len() as i64);
    check(delivered, "unbound：消息应成功送达");
    check(out.sender_app == 0, "unbound：未绑定发送方的身份章应为 0");
    check(out.sender == fx.sender.raw() as u32, "unbound：进程标识仍应写入");
    let ok = delivered && out.sender_app == 0 && out.sender == fx.sender.raw() as u32;
    kprintln!("[JSR-APPID] stamp case=unbound out_sender_app={:#x} ok={}", out.sender_app, ok);
    teardown(&fx);
}

/// 二次绑定被拒：身份保持不变，之后的消息仍带首次绑定的身份。
fn case_rebind_refused() {
    let Some(fx) = fixture(Some(0x5157)) else {
        check(false, "rebind_refused 用例资源创建失败");
        return;
    };
    let refused = proc::set_app(fx.sender, 0x9999) == Err(ProcError::BadApp);
    let unchanged = proc::app(fx.sender) == Some(0x5157);
    check(refused, "rebind_refused：二次绑定必须返回 BadApp");
    check(unchanged, "rebind_refused：被拒后身份应保持不变");
    let body = b"stamp-rebind";
    let (recv_ret, send_ret, out) = exchange(&fx, body, 64, None);
    let delivered = recv_ret == Some(body.len() as i64) && send_ret == Some(body.len() as i64);
    check(delivered, "rebind_refused：消息应成功送达");
    check(out.sender_app == 0x5157, "rebind_refused：消息章仍应为首次绑定的身份");
    let ok = refused && unchanged && delivered && out.sender_app == 0x5157;
    kprintln!("[JSR-APPID] stamp case=rebind_refused app={:#x} ok={}", out.sender_app, ok);
    teardown(&fx);
}

/// 发送后退出：消息上的章在发送时定格，发送方被回收后仍可读到。
fn case_after_exit() {
    let Some(fx) = fixture(Some(0x7001)) else {
        check(false, "after_exit 用例资源创建失败");
        return;
    };
    let sender_pid = fx.sender.raw() as u32;
    let body = b"stamp-after-exit";
    let send_req = ring::submit_send_for(fx.sender, fx.send_ring, fx.send_ep, body.to_vec(), vec![]).ok();
    let sent = send_req.and_then(|r| result(fx.sender, fx.send_ring, r)) == Some(body.len() as i64);
    check(sent, "after_exit：发送方发送应成功");
    check(ipc::queued(fx.receiver, fx.recv_ep) == Some(1), "after_exit：消息应留在接收方队列中");
    // 发送方退出并被回收：其进程对象、端点与 Ring 都被销毁。
    check(proc::exit_idle(fx.sender, 0), "after_exit：发送方未能退出");
    check(proc::reap(fx.sender).is_some(), "after_exit：发送方未能被回收");
    kobj::run_cleanup(usize::MAX);
    // 接收方随后才收：章仍是发送时的身份。
    let d = recv_desc(fx.buf_va, 64, None);
    check(put_desc(fx.receiver, fx.recv_desc_va, &d), "after_exit：接收描述写入失败");
    let recv_req = ring::submit_recv_for(fx.receiver, fx.recv_ring, fx.recv_ep, fx.recv_desc_va, &d).ok();
    let delivered = recv_req.and_then(|r| result(fx.receiver, fx.recv_ring, r)) == Some(body.len() as i64);
    let out = outputs(fx.receiver, fx.recv_desc_va);
    check(delivered, "after_exit：发送方退出后接收应仍成功");
    check(out.sender_app == 0x7001, "after_exit：章应为发送时的身份");
    check(out.sender == sender_pid, "after_exit：进程标识应为发送时的值");
    let ok = sent && delivered && out.sender_app == 0x7001 && out.sender == sender_pid;
    kprintln!("[JSR-APPID] stamp case=after_exit app={:#x} out_sender_app={:#x} ok={}", 0x7001, out.sender_app, ok);
    check(proc::exit_idle(fx.receiver, 0), "after_exit：接收方未能退出");
    proc::reap(fx.receiver);
    kobj::run_cleanup(usize::MAX);
}

/// 缓冲区不足：被拒时输出字段已盖章、消息仍在队列；随后用够大的缓冲区收到同一条消息。
fn case_too_small() {
    let Some(fx) = fixture(Some(0x5157)) else {
        check(false, "too_small 用例资源创建失败");
        return;
    };
    let body = b"stamp-too-small";
    let send_req = ring::submit_send_for(fx.sender, fx.send_ring, fx.send_ep, body.to_vec(), vec![]).ok();
    let sent = send_req.and_then(|r| result(fx.sender, fx.send_ring, r)) == Some(body.len() as i64);
    check(sent && ipc::queued(fx.receiver, fx.recv_ep) == Some(1), "too_small：发送后消息应在队列中");
    let small = recv_desc(fx.buf_va, 8, Some(0xdead));
    check(put_desc(fx.receiver, fx.recv_desc_va, &small), "too_small：小缓冲区描述写入失败");
    let first = ring::submit_recv_for(fx.receiver, fx.recv_ring, fx.recv_ep, fx.recv_desc_va, &small).ok();
    let rejected = first.and_then(|r| result(fx.receiver, fx.recv_ring, r)) == Some(err(abi::SYSTEM_CHANNEL_ERROR_BUFFER_TOO_SMALL));
    let out = outputs(fx.receiver, fx.recv_desc_va);
    let stamped = out.sender_app == 0x5157 && out.sender == fx.sender.raw() as u32 && out.data_len == body.len() as u32;
    let kept = ipc::queued(fx.receiver, fx.recv_ep) == Some(1);
    check(rejected, "too_small：小缓冲区应被拒（buffer_too_small）且无交付");
    check(stamped, "too_small：被拒时输出字段应已盖章");
    check(kept, "too_small：被拒后消息必须仍在队列中");
    // 同一份缓冲区换成足够大的容量，再收：同一条消息成功交付。
    let big = recv_desc(fx.buf_va, 64, None);
    check(put_desc(fx.receiver, fx.recv_desc_va + DESC_STRIDE, &big), "too_small：大缓冲区描述写入失败");
    let second = ring::submit_recv_for(fx.receiver, fx.recv_ring, fx.recv_ep, fx.recv_desc_va + DESC_STRIDE, &big).ok();
    let delivered = second.and_then(|r| result(fx.receiver, fx.recv_ring, r)) == Some(body.len() as i64);
    let out2 = outputs(fx.receiver, fx.recv_desc_va + DESC_STRIDE);
    let drained = ipc::queued(fx.receiver, fx.recv_ep) == Some(0);
    check(delivered && drained, "too_small：够大的缓冲区应收到同一条消息且队列清空");
    check(out2.sender_app == 0x5157 && out2.sender == fx.sender.raw() as u32, "too_small：第二次交付的身份应一致");
    let ok = sent && rejected && stamped && kept && delivered && drained && out2.sender_app == 0x5157;
    kprintln!(
        "[JSR-APPID] stamp case=too_small app=0x5157 out_sender_app={:#x} kept={} ok={}",
        out.sender_app,
        kept,
        ok
    );
    teardown(&fx);
}

/// 演练入口。
pub fn run() {
    let (live0, _, _) = kobj::stats();
    let free0 = frame::free_frames();
    let Ok(pid) = proc::create("appid-demo", SyscallSet::EMPTY) else {
        check(false, "创建进程失败");
        kprintln!("[JSR-APPID] summary checks={} failed={}", CHECKS.load(Ordering::Relaxed), failed());
        return;
    };
    check(proc::app(pid) == Some(0), "新进程的身份应为未绑定");
    check(proc::set_app(pid, 0).is_err(), "身份 0 应被拒绝");
    check(proc::set_app(pid, 0x5157).is_ok(), "首次绑定应成功");
    check(proc::app(pid) == Some(0x5157), "绑定后应能读到身份");
    check(proc::set_app(pid, 0x9999) == Err(ProcError::BadApp), "二次绑定必须被拒");
    check(proc::app(pid) == Some(0x5157), "被拒后身份保持不变");
    // 收尾：进程没有任何线程，先让它进入 exited 再回收（否则对象会留在表里）。
    check(proc::exit_idle(pid, 0), "无线程进程应能进入 exited");
    check(proc::reap(pid).is_some(), "exited 的进程应能被回收");
    kobj::run_cleanup(usize::MAX);

    // 消息上的发送方身份章：成功与失败路径都覆盖。
    case_bound();
    case_forged();
    case_unbound();
    case_rebind_refused();
    case_after_exit();
    case_too_small();

    // 收尾：对象表、页帧与固定全部回到演练前基线。
    kobj::run_cleanup(usize::MAX);
    let (live1, pending1, _) = kobj::stats();
    let reclaimed = live1 == live0 && pending1 == 0 && frame::free_frames() == free0 && pin::stats() == (0, 0);
    check(reclaimed, "身份章演练后对象、页帧或固定未回到基线");
    kprintln!("[JSR-APPID] stamp reclaimed={}", reclaimed);
    kprintln!(
        "[JSR-APPID] summary pid={:#x} app={:#x} checks={} failed={}",
        pid.raw(),
        0x5157,
        CHECKS.load(Ordering::Relaxed),
        failed()
    );
}
