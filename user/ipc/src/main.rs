//! user-ipc：IPC Channel 的用户态验收程序。
//! User-mode acceptance program for IPC channels.
//!
//! 入口参数 `(role, endpoint)`：
//! * `role = 0`：单进程语义验证（自建一对端点），逐步检查，失败以步骤编号退出；
//! * `role = 1`（ping）/ `role = 2`（pong）：跨进程往返——ping 把消息与一个线程句柄发给 pong，
//!   pong 收到后把同一个句柄随回复送回；`endpoint` 是创建方放进本进程句柄表的端点。
#![no_std]
#![no_main]

use core::arch::asm;
use core::fmt::Write as _;

use kernel_core::ring_abi::{Cqe, EnterArgs, MsgDesc, Sqe};

/// 系统调用号（构建期从登记表生成）。
#[allow(dead_code)]
mod ids {
    include!(concat!(env!("OUT_DIR"), "/ids.rs"));
}

const fn e(id: u64) -> i64 {
    -(id as i64)
}

const CANCELLED: i64 = e(ids::SYSTEM_ASYNC_ERROR_CANCELLED);
const ALREADY_COMPLETED: i64 = e(ids::SYSTEM_ASYNC_ERROR_ALREADY_COMPLETED);
const PEER_CLOSED: i64 = e(ids::SYSTEM_CHANNEL_ERROR_PEER_CLOSED);
const QUEUE_FULL: i64 = e(ids::SYSTEM_CHANNEL_ERROR_QUEUE_FULL);
const BUFFER_TOO_SMALL: i64 = e(ids::SYSTEM_CHANNEL_ERROR_BUFFER_TOO_SMALL);
const HANDLE_INVALID: i64 = e(ids::SYSTEM_HANDLE_ERROR_INVALID);
const HANDLE_RIGHTS_DENIED: i64 = e(ids::SYSTEM_HANDLE_ERROR_RIGHTS_DENIED);
const INVALID_ADDRESS: i64 = e(ids::SYSTEM_MEMORY_ERROR_INVALID_ADDRESS);

/// 句柄权限位（与内核 Rights 一致）。
const WAIT: u64 = 1 << 3;

/// 发起系统调用（x86_64：rax=ID，rdi/rsi/rdx=参数，rcx/r11 被占用）。
///
/// # Safety
/// 参数必须符合该调用的约定（指针须指向本进程内存）。
unsafe fn syscall3(id: u64, a: u64, b: u64, c: u64) -> i64 {
    let ret: i64;
    asm!(
        "syscall",
        inlateout("rax") id as i64 => ret,
        in("rdi") a,
        in("rsi") b,
        in("rdx") c,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack)
    );
    ret
}

fn sys(id: u64, a: u64, b: u64) -> i64 {
    // SAFETY：调用者传入的指针都指向本进程内存。
    unsafe { syscall3(id, a, b, 0) }
}

fn write(text: &str) -> i64 {
    sys(ids::SYSTEM_CONSOLE_WRITE, text.as_ptr() as u64, text.len() as u64)
}

fn exit(code: u64) -> ! {
    sys(ids::SYSTEM_TASK_EXIT, code, 0);
    loop {}
}

/// 栈上的定长文本缓冲（不用堆）。
struct Line {
    buf: [u8; 192],
    len: usize,
}

impl core::fmt::Write for Line {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let b = s.as_bytes();
        if self.len + b.len() > self.buf.len() {
            return Err(core::fmt::Error);
        }
        self.buf[self.len..self.len + b.len()].copy_from_slice(b);
        self.len += b.len();
        Ok(())
    }
}

macro_rules! say {
    ($($t:tt)*) => {{
        let mut l = Line { buf: [0; 192], len: 0 };
        let _ = write!(l, "ipc: ");
        let _ = write!(l, $($t)*);
        if let Ok(s) = core::str::from_utf8(&l.buf[..l.len]) {
            write(s);
        }
    }};
}

fn check(ok: bool, step: u64) {
    if !ok {
        say!("FAIL step={}", step);
        exit(step);
    }
}

/// 一次 enter 的结果。
struct Entered {
    args: EnterArgs,
    ids: [u64; 4],
    cqes: [Cqe; 4],
}

fn enter(ring: i64, sq: &[Sqe], cq_max: u32, wait_min: u32) -> Entered {
    let mut out = Entered { args: EnterArgs::default(), ids: [0; 4], cqes: [Cqe::default(); 4] };
    out.args = EnterArgs {
        sq_ptr: sq.as_ptr() as u64,
        cq_ptr: out.cqes.as_mut_ptr() as u64,
        id_ptr: out.ids.as_mut_ptr() as u64,
        sq_count: sq.len() as u32,
        cq_max,
        wait_min,
        ..EnterArgs::default()
    };
    let r = sys(ids::SYSTEM_ASYNC_RING_ENTER, ring as u64, &mut out.args as *mut EnterArgs as u64);
    if r != 0 {
        out.args.first_error = r;
    }
    out
}

fn send_sqe(ep: i64, d: &MsgDesc, tag: u64) -> Sqe {
    Sqe { op: ids::SYSTEM_CHANNEL_SEND as u32, flags: 0, user_tag: tag, arg0: ep as u64, arg1: d as *const MsgDesc as u64 }
}

fn recv_sqe(ep: i64, d: &MsgDesc, tag: u64) -> Sqe {
    Sqe { op: ids::SYSTEM_CHANNEL_RECV as u32, flags: 0, user_tag: tag, arg0: ep as u64, arg1: d as *const MsgDesc as u64 }
}

fn msg(data: &[u8], handles: &[u32]) -> MsgDesc {
    MsgDesc { data_ptr: data.as_ptr() as u64, handles_ptr: handles.as_ptr() as u64, data_len: data.len() as u32, handles_cap: handles.len() as u32, ..MsgDesc::default() }
}

fn rbuf(data: &mut [u8], handles: &mut [u32]) -> MsgDesc {
    MsgDesc { data_ptr: data.as_mut_ptr() as u64, handles_ptr: handles.as_mut_ptr() as u64, data_len: data.len() as u32, handles_cap: handles.len() as u32, ..MsgDesc::default() }
}

/// 同步 send（返回 send 的终态）。
fn send_now(ep: i64, d: &MsgDesc) -> i64 {
    sys(ids::SYSTEM_CHANNEL_SEND, ep as u64, d as *const MsgDesc as u64)
}

/// 同步 recv（阻塞到交付 / 对端关闭 / 本端关闭）。
fn recv_now(ep: i64, d: &mut MsgDesc) -> i64 {
    sys(ids::SYSTEM_CHANNEL_RECV, ep as u64, d as *mut MsgDesc as u64)
}

fn close(h: i64) -> i64 {
    sys(ids::SYSTEM_HANDLE_CLOSE, h as u64, 0)
}

/// 工作线程：什么都不做，立即退出（用来取得一个可转移的线程句柄）。
extern "C" fn worker(_: u64) -> ! {
    exit(0)
}

static mut WORKER_STACK: [u8; 4096] = [0; 4096];

/// 创建一个立即退出的线程，返回其句柄（带 TRANSFER）。随后等待两个时钟 tick 让它运行并退出：
/// 所有工作线程共用一块栈，同一时刻只能有一个在运行，也避免占满调度器槽位。
fn spawn_worker() -> i64 {
    // SAFETY：只取地址，不形成引用。
    let top = unsafe { core::ptr::addr_of_mut!(WORKER_STACK) as u64 + 4096 };
    // SAFETY：entry 指向本程序代码，栈位于本进程可写内存。
    let h = unsafe { syscall3(ids::SYSTEM_TASK_SPAWN, worker as usize as u64, top, 0) };
    sys(ids::SYSTEM_TIME_WAIT, 2, 0);
    h
}

/// 单进程语义验证。
fn semantics() -> ! {
    // 1. 创建端点与 Ring
    let mut pair = [0u32; 2];
    check(sys(ids::SYSTEM_CHANNEL_CREATE, pair.as_mut_ptr() as u64, 0) == 0, 1);
    let (a, b) = (pair[0] as i64, pair[1] as i64);
    let ring = sys(ids::SYSTEM_ASYNC_RING_CREATE, 16, 0);
    check(a > 0 && b > 0 && ring > 0, 1);

    // 2. 经 ring 发送 / 接收（UTF-8 中文消息体）
    let text = "你好，通道".as_bytes();
    let d = msg(text, &[]);
    let r = enter(ring, &[send_sqe(a, &d, 1)], 4, 1);
    check(r.args.submitted == 1 && r.args.reaped == 1 && r.cqes[0].result == text.len() as i64, 2);
    let mut buf = [0u8; 64];
    let mut hs = [0u32; 2];
    let rd = rbuf(&mut buf, &mut hs);
    let r = enter(ring, &[recv_sqe(b, &rd, 2)], 4, 1);
    let got = r.args.reaped == 1 && r.cqes[0].result == text.len() as i64 && &buf[..text.len()] == text;
    // SAFETY：rd 在本栈帧内，内核已写回输出字段。
    let out_len = unsafe { core::ptr::read_volatile(&rd.out_data_len) };
    check(got && out_len == text.len() as u32, 2);
    say!("roundtrip bytes={} text_ok={}", text.len(), got);

    // 3. 缓冲区不足：消息保留，返回所需大小；换大缓冲区后收到
    let big = [0x5Au8; 100];
    check(send_now(a, &msg(&big, &[])) == 100, 3);
    let mut small = [0u8; 10];
    let mut sd = rbuf(&mut small, &mut hs);
    let too_small = recv_now(b, &mut sd);
    let needed = sd.out_data_len;
    let mut large = [0u8; 128];
    let mut ld = rbuf(&mut large, &mut hs);
    let ok = recv_now(b, &mut ld);
    check(too_small == BUFFER_TOO_SMALL && needed == 100 && ok == 100 && large[..100].iter().all(|&x| x == 0x5A), 3);
    say!("buffer_too_small={} needed={} retained_then_received={}", too_small, needed, ok == 100);

    // 4. 句柄随消息移动；无 TRANSFER / 非叶子被拒且不移动
    let t = spawn_worker();
    check(t > 0, 4);
    let tv = [t as u32];
    check(send_now(a, &msg(b"handle", &tv)) == 6, 4);
    let moved_away = close(t) == HANDLE_INVALID;
    let mut hb = [0u32; 2];
    let mut hd = rbuf(&mut buf, &mut hb);
    let n = recv_now(b, &mut hd);
    let received = n == 6 && hd.out_handles == 1 && hb[0] != 0;
    let usable = close(hb[0] as i64) == 0;
    check(moved_away && received && usable, 4);
    let t2 = spawn_worker();
    let t2_wait = sys(ids::SYSTEM_HANDLE_DUPLICATE, t2 as u64, WAIT);
    let no_right = send_now(a, &msg(b"x", &[t2_wait as u32]));
    let non_leaf = send_now(a, &msg(b"x", &[ring as u32]));
    let kept = close(t2_wait) == 0 && close(t2) == 0 && enter(ring, &[], 0, 0).args.first_error == 0;
    check(no_right == HANDLE_RIGHTS_DENIED && non_leaf == HANDLE_RIGHTS_DENIED && kept, 4);
    say!("handle moved={} received={} no_transfer_right={} ring_handle={} kept_on_failure={}", moved_away, received, no_right, non_leaf, kept);

    // 5. 两阶段 send：复制失败（消息体指向内核地址）⇒ 不入队、句柄不动
    let t3 = spawn_worker();
    let t3_vals = [t3 as u32];
    let bad = MsgDesc { data_ptr: 0xFFFF_8000_0000_0000, handles_ptr: t3_vals.as_ptr() as u64, data_len: 8, handles_cap: 1, ..MsgDesc::default() };
    let bad_send = send_now(a, &bad);
    let t3_kept = sys(ids::SYSTEM_HANDLE_DUPLICATE, t3 as u64, WAIT);
    check(bad_send == INVALID_ADDRESS && t3_kept > 0 && close(t3_kept) == 0 && close(t3) == 0, 5);
    say!("two_phase copy_fail={} handle_untouched=true", bad_send);

    // 6. 队列满 ⇒ queue_full，句柄不移出；排空
    let mut sent = 0;
    while send_now(a, &msg(b"q", &[])) == 1 {
        sent += 1;
        if sent > 100 {
            break;
        }
    }
    let t4 = spawn_worker();
    let full = send_now(a, &msg(b"q", &[t4 as u32]));
    let t4_kept = close(t4) == 0;
    let mut drained = 0;
    for _ in 0..sent {
        let mut d = rbuf(&mut buf, &mut hs);
        if recv_now(b, &mut d) == 1 {
            drained += 1;
        }
    }
    check(sent == 64 && full == QUEUE_FULL && t4_kept && drained == 64, 6);
    say!("queue capacity={} full={} handle_kept={} drained={}", sent, full, t4_kept, drained);

    // 7. 取消与交付：先取消 ⇒ 消息不被消费；先交付 ⇒ 取消得到 already_completed
    let mut cbuf = [0u8; 16];
    let cd = rbuf(&mut cbuf, &mut hs);
    let p = enter(ring, &[recv_sqe(b, &cd, 7)], 0, 0);
    let pending_id = p.ids[0];
    let c1 = sys(ids::SYSTEM_ASYNC_CANCEL, ring as u64, pending_id);
    check(send_now(a, &msg(b"after-cancel", &[])) == 12, 7);
    let r = enter(ring, &[], 4, 1);
    let cancelled = r.args.reaped == 1 && r.cqes[0].request_id == pending_id && r.cqes[0].result == CANCELLED;
    let mut kbuf = [0u8; 16];
    let mut kd = rbuf(&mut kbuf, &mut hs);
    let kept_msg = recv_now(b, &mut kd) == 12 && &kbuf[..12] == b"after-cancel";
    check(c1 == 0 && cancelled && kept_msg, 7);
    check(send_now(a, &msg(b"first", &[])) == 5, 7);
    let mut dbuf = [0u8; 16];
    let dd = rbuf(&mut dbuf, &mut hs);
    let r = enter(ring, &[recv_sqe(b, &dd, 8)], 4, 1);
    let c2 = sys(ids::SYSTEM_ASYNC_CANCEL, ring as u64, r.ids[0]);
    check(r.cqes[0].result == 5 && c2 == ALREADY_COMPLETED, 7);
    say!("cancel_then_send cancelled={} message_kept={} deliver_then_cancel={}", cancelled, kept_msg, c2);

    // 8. 本端点关闭 ⇒ 其上在飞的 recv 以 cancelled 结束
    let mut pair2 = [0u32; 2];
    check(sys(ids::SYSTEM_CHANNEL_CREATE, pair2.as_mut_ptr() as u64, 0) == 0, 8);
    let (c, dd2) = (pair2[0] as i64, pair2[1] as i64);
    let mut ebuf = [0u8; 8];
    let ed = rbuf(&mut ebuf, &mut hs);
    let p = enter(ring, &[recv_sqe(dd2, &ed, 9)], 0, 0);
    check(close(dd2) == 0, 8);
    let r = enter(ring, &[], 4, 1);
    let own_closed = r.args.reaped == 1 && r.cqes[0].request_id == p.ids[0] && r.cqes[0].result == CANCELLED;
    check(own_closed && send_now(c, &msg(b"x", &[])) == PEER_CLOSED, 8);
    say!("own_close_cancels_recv={} send_to_closed_peer={}", own_closed, PEER_CLOSED);

    // 9. 对端关闭 ⇒ 在飞 recv 与之后的 recv 都以 peer_closed 结束；send 得到 peer_closed
    let mut fbuf = [0u8; 8];
    let fd = rbuf(&mut fbuf, &mut hs);
    let p = enter(ring, &[recv_sqe(b, &fd, 10)], 0, 0);
    check(close(a) == 0, 9);
    let r = enter(ring, &[], 4, 1);
    let pending_peer = r.args.reaped == 1 && r.cqes[0].request_id == p.ids[0] && r.cqes[0].result == PEER_CLOSED;
    let mut gd = rbuf(&mut fbuf, &mut hs);
    let later = recv_now(b, &mut gd);
    check(pending_peer && later == PEER_CLOSED, 9);
    say!("peer_close pending_recv={} later_recv={}", if pending_peer { PEER_CLOSED } else { 0 }, later);

    check(close(b) == 0 && close(c) == 0 && close(ring) == 0, 10);
    say!("all checks passed");
    exit(0)
}

/// 跨进程 ping：发送 "ping" + 一个线程句柄，等待 "pong" 与同一个句柄（新的句柄值）。
fn ping(ep: i64) -> ! {
    let ring = sys(ids::SYSTEM_ASYNC_RING_CREATE, 4, 0);
    let t = spawn_worker();
    check(ring > 0 && t > 0, 21);
    let r = enter(ring, &[send_sqe(ep, &msg(b"ping", &[t as u32]), 1)], 4, 1);
    check(r.cqes[0].result == 4 && close(t) == HANDLE_INVALID, 22);
    let mut buf = [0u8; 16];
    let mut hs = [0u32; 1];
    let d = rbuf(&mut buf, &mut hs);
    let r = enter(ring, &[recv_sqe(ep, &d, 2)], 4, 1);
    let back = r.cqes[0].result == 4 && &buf[..4] == b"pong" && hs[0] != 0;
    check(back && close(hs[0] as i64) == 0, 23);
    say!("ping got=pong handle_returned=true");
    exit(0)
}

/// 跨进程 pong：收到 "ping" 与句柄后，把同一个句柄随 "pong" 送回。
fn pong(ep: i64) -> ! {
    let ring = sys(ids::SYSTEM_ASYNC_RING_CREATE, 4, 0);
    check(ring > 0, 31);
    let mut buf = [0u8; 16];
    let mut hs = [0u32; 1];
    let d = rbuf(&mut buf, &mut hs);
    let r = enter(ring, &[recv_sqe(ep, &d, 1)], 4, 1);
    check(r.cqes[0].result == 4 && &buf[..4] == b"ping" && hs[0] != 0, 32);
    let r = enter(ring, &[send_sqe(ep, &msg(b"pong", &[hs[0]]), 2)], 4, 1);
    check(r.cqes[0].result == 4, 33);
    say!("pong got=ping forwarded_handle=true");
    exit(0)
}

/// 程序入口（链接脚本把它放在代码段最前面）。
#[no_mangle]
#[link_section = ".text._start"]
pub extern "C" fn _start(role: u64, endpoint: u64) -> ! {
    match role {
        0 => semantics(),
        1 => ping(endpoint as i64),
        _ => pong(endpoint as i64),
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    exit(101)
}
