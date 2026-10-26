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

use kernel_core::memory_abi::MapArgs;
use core::sync::atomic::{AtomicU64,Ordering};
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
#[cfg(target_arch = "x86_64")]
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

/// 发起系统调用（AArch64：x8=ID，x0/x1/x2=参数，`svc #0`；返回值在 x0，其余寄存器由内核保留）。
///
/// # Safety
/// 参数必须符合该调用的约定（指针须指向本进程内存）。
#[cfg(target_arch = "aarch64")]
unsafe fn syscall3(id: u64, a: u64, b: u64, c: u64) -> i64 {
    let ret: i64;
    asm!(
        "svc #0",
        in("x8") id,
        inlateout("x0") a as i64 => ret,
        in("x1") b,
            in("x2") c,
        options(nostack)
    );
    ret
}

/// 发起系统调用（RISC-V：a7=ID，a0/a1/a2=参数，`ecall`；返回值在 a0，其余寄存器由内核保留）。
///
/// # Safety
/// 参数必须符合该调用的约定（指针须指向本进程内存）。
#[cfg(target_arch = "riscv64")]
unsafe fn syscall3(id: u64, a: u64, b: u64, c: u64) -> i64 {
    let ret: i64;
    asm!(
        "ecall",
        in("a7") id,
        inlateout("a0") a as i64 => ret,
        in("a1") b,
        in("a2") c,
        options(nostack)
    );
    ret
}

/// 发起系统调用（RISC-V32 的 32 位用户 ABI：a7=ID；每个 64 位参数拆成两半，低半依次在 a0/a1/a2、
/// 高半依次在 a3/a4/a5；`ecall`；返回值低半在 a0、高半在 a1，其余寄存器由内核保留）。
///
/// # Safety
/// 参数必须符合该调用的约定（指针须指向本进程内存）。
#[cfg(target_arch = "riscv32")]
unsafe fn syscall3(id: u64, a: u64, b: u64, c: u64) -> i64 {
    let (lo, hi): (u32, u32);
    asm!(
        "ecall",
        in("a7") id as u32,
        inlateout("a0") a as u32 => lo,
        inlateout("a1") b as u32 => hi,
        in("a2") c as u32,
        in("a3") (a >> 32) as u32,
        in("a4") (b >> 32) as u32,
        in("a5") (c >> 32) as u32,
        options(nostack)
    );
    ((hi as u64) << 32 | lo as u64) as i64
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

fn msg(data: &[u8], handles: &[u64]) -> MsgDesc {
    MsgDesc { data_ptr: data.as_ptr() as u64, handles_ptr: handles.as_ptr() as u64, data_len: data.len() as u32, handles_cap: handles.len() as u32, ..MsgDesc::default() }
}

fn rbuf(data: &mut [u8], handles: &mut [u64]) -> MsgDesc {
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
    let mut pair = [0u64; 2];
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
    let mut hs = [0u64; 2];
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
    let tv = [t as u64];
    check(send_now(a, &msg(b"handle", &tv)) == 6, 4);
    let moved_away = close(t) == HANDLE_INVALID;
    let mut hb = [0u64; 2];
    let mut hd = rbuf(&mut buf, &mut hb);
    let n = recv_now(b, &mut hd);
    let received = n == 6 && hd.out_handles == 1 && hb[0] != 0;
    let usable = close(hb[0] as i64) == 0;
    check(moved_away && received && usable, 4);
    let t2 = spawn_worker();
    let t2_wait = sys(ids::SYSTEM_HANDLE_DUPLICATE, t2 as u64, WAIT);
    let no_right = send_now(a, &msg(b"x", &[t2_wait as u64]));
    let non_leaf = send_now(a, &msg(b"x", &[ring as u64]));
    let kept = close(t2_wait) == 0 && close(t2) == 0 && enter(ring, &[], 0, 0).args.first_error == 0;
    check(no_right == HANDLE_RIGHTS_DENIED && non_leaf == HANDLE_RIGHTS_DENIED && kept, 4);
    say!("handle moved={} received={} no_transfer_right={} ring_handle={} kept_on_failure={}", moved_away, received, no_right, non_leaf, kept);

    // 5. 两阶段 send：复制失败（消息体指向内核地址）⇒ 不入队、句柄不动
    let t3 = spawn_worker();
    let t3_vals = [t3 as u64];
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
    let full = send_now(a, &msg(b"q", &[t4 as u64]));
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
    let mut pair2 = [0u64; 2];
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

fn shared_address() -> u64 {
    let arch=if cfg!(target_arch="x86_64") { "x86_64" } else if cfg!(target_arch="aarch64") { "aarch64" }
        else if cfg!(target_arch="riscv64") { "riscv64" } else { "riscv32" };
    kernel_core::user_layout::window_base(arch).unwrap()+0x200000
}
fn shared_map(h:i64) -> i64 {
    let args=MapArgs::new(shared_address(),0,1,true);
    sys(ids::SYSTEM_MEMORY_OBJECT_MAP,h as u64,&args as *const MapArgs as u64)
}

/// 跨进程 ping：发送 "ping" + 一个线程句柄，等待 "pong" 与同一个句柄（新的句柄值）。
fn ping(ep: i64) -> ! {
    let ring = sys(ids::SYSTEM_ASYNC_RING_CREATE, 4, 0);
    let t = spawn_worker();
    check(ring > 0 && t > 0, 21);
    let r = enter(ring, &[send_sqe(ep, &msg(b"ping", &[t as u64]), 1)], 4, 1);
    check(r.cqes[0].result == 4 && close(t) == HANDLE_INVALID, 22);
    let mut buf = [0u8; 16];
    let mut hs = [0u64; 1];
    let d = rbuf(&mut buf, &mut hs);
    let r = enter(ring, &[recv_sqe(ep, &d, 2)], 4, 1);
    let back = r.cqes[0].result == 4 && &buf[..4] == b"pong" && hs[0] != 0;
    check(back && close(hs[0] as i64) == 0, 23);
    say!("ping got=pong handle_returned=true");
    let memory=sys(ids::SYSTEM_MEMORY_OBJECT_CREATE,1,0);
    check(memory>0 && shared_map(memory)==0,24);
    // SAFETY: Memory syscall established a page aligned shared RAM view. Atomic values are valid zero bits.
    let value=unsafe { &*(shared_address() as *const AtomicU64) };
    value.store(0x53484d3150494e47,Ordering::Release);
    let sent=enter(ring,&[send_sqe(ep,&msg(b"shm1",&[memory as u64]),3)],4,1);
    check(sent.cqes[0].result==4 && close(memory)==HANDLE_INVALID,25);
    let mut data=[0u8;8]; let mut handles=[0u64;1]; let desc=rbuf(&mut data,&mut handles);
    let received=enter(ring,&[recv_sqe(ep,&desc,4)],4,1);
    check(received.cqes[0].result==4 && &data[..4]==b"shm2" && handles[0]!=0,26);
    check(value.load(Ordering::Acquire)==0x53484d31504f4e47,27);
    check(close(handles[0] as i64)==0 && sys(ids::SYSTEM_MEMORY_OBJECT_UNMAP,shared_address(),1)==0,28);
    say!("shm ping channel_handle=true peer_write_visible=true resources_released=true");
    exit(0)
}

/// 跨进程 pong：收到 "ping" 与句柄后，把同一个句柄随 "pong" 送回。
fn pong(ep: i64) -> ! {
    let ring = sys(ids::SYSTEM_ASYNC_RING_CREATE, 4, 0);
    check(ring > 0, 31);
    let mut buf = [0u8; 16];
    let mut hs = [0u64; 1];
    let d = rbuf(&mut buf, &mut hs);
    let r = enter(ring, &[recv_sqe(ep, &d, 1)], 4, 1);
    check(r.cqes[0].result == 4 && &buf[..4] == b"ping" && hs[0] != 0, 32);
    let r = enter(ring, &[send_sqe(ep, &msg(b"pong", &[hs[0]]), 2)], 4, 1);
    check(r.cqes[0].result == 4, 33);
    say!("pong got=ping forwarded_handle=true");
    let mut data=[0u8;8]; let mut handles=[0u64;1]; let desc=rbuf(&mut data,&mut handles);
    let received=enter(ring,&[recv_sqe(ep,&desc,3)],4,1);
    check(received.cqes[0].result==4 && &data[..4]==b"shm1" && handles[0]!=0,34);
    check(shared_map(handles[0] as i64)==0,35);
    // SAFETY: validated writable Memory mapping; use atomic shared accesses across processes.
    let value=unsafe { &*(shared_address() as *const AtomicU64) };
    check(value.load(Ordering::Acquire)==0x53484d3150494e47,36);
    value.store(0x53484d31504f4e47,Ordering::Release);
    let sent=enter(ring,&[send_sqe(ep,&msg(b"shm2",&handles),4)],4,1);
    check(sent.cqes[0].result==4 && close(handles[0] as i64)==HANDLE_INVALID,37);
    check(sys(ids::SYSTEM_MEMORY_OBJECT_UNMAP,shared_address(),1)==0,38);
    say!("shm pong channel_handle=true shared_rw=true transfer_back=true");
    exit(0)
}

// S-3: real CPL3 peers repeatedly move one Memory handle through Channel.
fn s3_channel_ping(ep:i64)->! {
    let ring=sys(ids::SYSTEM_ASYNC_RING_CREATE,4,0);
    let mut memory=sys(ids::SYSTEM_MEMORY_OBJECT_CREATE,1,0);
    check(ring>0 && memory>0,100);
    for round in 0..32u64 {
        check(shared_map(memory)==0,101);
        unsafe { (&*(shared_address() as *const AtomicU64)).store(round*2,Ordering::Release); }
        let ro=syscall_duplicate_ro(memory);
        let write=MapArgs::new(shared_address()+0x2000,0,1,true);
        check(ro>0 && sys(ids::SYSTEM_MEMORY_OBJECT_MAP,ro as u64,&write as *const MapArgs as u64)==HANDLE_RIGHTS_DENIED,102);
        check(sys(ids::SYSTEM_HANDLE_RESTRICT,ro as u64,1)==0,103);
        let read=MapArgs::new(shared_address()+0x2000,0,1,false);
        check(sys(ids::SYSTEM_MEMORY_OBJECT_MAP,ro as u64,&read as *const MapArgs as u64)==HANDLE_RIGHTS_DENIED,103);
        check(close(ro)==0,103);
        let sent=enter(ring,&[send_sqe(ep,&msg(b"s3rq",&[memory as u64]),round*2)],4,1);
        check(sent.cqes[0].result==4 && close(memory)==HANDLE_INVALID,104);
        if round%2==0 { check(sys(ids::SYSTEM_MEMORY_OBJECT_UNMAP,shared_address(),1)==0,105); }
        let mut data=[0u8;8];let mut handles=[0u64;1];let desc=rbuf(&mut data,&mut handles);
        let received=enter(ring,&[recv_sqe(ep,&desc,round*2+1)],4,1);
        check(received.cqes[0].result==4 && &data[..4]==b"s3ok" && handles[0]!=0,106);
        memory=handles[0] as i64;
        if round%2==0 { check(shared_map(memory)==0,107); }
        check(unsafe { (&*(shared_address() as *const AtomicU64)).load(Ordering::Acquire) }==round*2+1,108);
        check(sys(ids::SYSTEM_MEMORY_OBJECT_UNMAP,shared_address(),1)==0,109);
    }
    check(close(memory)==0 && close(ring)==0,110);
    say!("s3 ping rounds=32 channel=true readonly_denied=true stale=true alternating_unmap=true shared=true");exit(0)
}
fn syscall_duplicate_ro(memory:i64)->i64 { sys(ids::SYSTEM_HANDLE_DUPLICATE,memory as u64,(1<<0)|(1<<7)) }
fn s3_channel_pong(ep:i64)->! {
    let ring=sys(ids::SYSTEM_ASYNC_RING_CREATE,4,0);check(ring>0,111);
    for round in 0..32u64 {
        let mut data=[0u8;8];let mut handles=[0u64;1];let desc=rbuf(&mut data,&mut handles);
        let received=enter(ring,&[recv_sqe(ep,&desc,round*2)],4,1);
        check(received.cqes[0].result==4 && &data[..4]==b"s3rq" && handles[0]!=0,112);
        let memory=handles[0] as i64;check(shared_map(memory)==0,113);
        check(unsafe { (&*(shared_address() as *const AtomicU64)).load(Ordering::Acquire) }==round*2,114);
        unsafe { (&*(shared_address() as *const AtomicU64)).store(round*2+1,Ordering::Release); }
        check(sys(ids::SYSTEM_MEMORY_OBJECT_UNMAP,shared_address(),1)==0,115);
        let sent=enter(ring,&[send_sqe(ep,&msg(b"s3ok",&[memory as u64]),round*2+1)],4,1);
        check(sent.cqes[0].result==4 && close(memory)==HANDLE_INVALID,116);
    }
    check(close(ring)==0,117);say!("s3 pong rounds=32 channel=true shared=true stale=true views_released=true");exit(0)
}

// RT-3: a low-QoS service receives through a Ring. The high-QoS client waits
// through its own Ring, allowing the kernel to donate across the Channel.
fn rt3_service(ep:i64)->! {
    check(sys(ids::SYSTEM_TASK_QOS_SET,3,0)==0,120); // Background
    let ring=sys(ids::SYSTEM_ASYNC_RING_CREATE,4,0);check(ring>0,121);
    let mut data=[0u8;8];let mut handles=[];let desc=rbuf(&mut data,&mut handles);
    let warm=enter(ring,&[recv_sqe(ep,&desc,1)],4,1);check(warm.cqes[0].result==4&&&data[..4]==b"warm",122);
    // Arm the measured receive without waiting, so this task is published as
    // the endpoint service before the acknowledgement lets the client issue
    // its request. This is the request/reply binding point used by PI.
    let pending=enter(ring,&[recv_sqe(ep,&desc,3)],0,0);check(pending.args.submitted==1,123);
    let ack=enter(ring,&[send_sqe(ep,&msg(b"ack!",&[]),2)],4,1);check(ack.cqes[0].result==4,123);
    let req=enter(ring,&[],4,1);check(req.cqes[0].result==4&&&data[..4]==b"work",124);
    // Give the high client an explicit chance to enter its Ring wait before
    // producing the reply. The service is Background here, so the first
    // yield runs the client; once it blocks, the donation brings us back.
    for _ in 0..4 { let _=sys(ids::SYSTEM_TASK_YIELD,0,0); }
    let reply=enter(ring,&[send_sqe(ep,&msg(b"done",&[]),4)],4,1);check(reply.cqes[0].result==4,125);
    check(close(ring)==0&&close(ep)==0,126);say!("rt3 service ring=true reply=true");exit(0)
}

fn rt3_client(ep:i64)->! {
    let ring=sys(ids::SYSTEM_ASYNC_RING_CREATE,4,0);check(ring>0,127);
    let warm=enter(ring,&[send_sqe(ep,&msg(b"warm",&[]),1)],4,1);check(warm.cqes[0].result==4,128);
    let mut data=[0u8;8];let mut handles=[];let desc=rbuf(&mut data,&mut handles);
    let ack=enter(ring,&[recv_sqe(ep,&desc,2)],4,1);check(ack.cqes[0].result==4&&&data[..4]==b"ack!",129);
    let req=enter(ring,&[send_sqe(ep,&msg(b"work",&[]),3)],4,1);check(req.cqes[0].result==4,130);
    let reply=enter(ring,&[recv_sqe(ep,&desc,4)],4,1);check(reply.cqes[0].result==4&&&data[..4]==b"done",131);
    check(close(ring)==0&&close(ep)==0,132);say!("rt3 client ring=true reply=true");exit(0)
}

// Dedicated SHM fixture role: fill a user TLB, wait for remote revoke acknowledgement,
// then access the revoked address. Correct execution ends in a page fault, never exit(90).
fn revoke_probe(address:u64) -> ! {
    let data=unsafe { &*(address as *const AtomicU64) };
    let phase=unsafe { &*((address+4096) as *const AtomicU64) };
    check(data.load(Ordering::Acquire)==0x53484d315245564f,80);
    phase.store(1,Ordering::Release);
    while phase.load(Ordering::Acquire)!=2 { core::hint::spin_loop(); }
    let stale=data.load(Ordering::Acquire);
    say!("shm REVOKE FAILED stale={:#x}",stale);
    exit(90)
}

/// 程序入口（链接脚本把它放在代码段最前面）。内核把两个参数各放进一个寄存器，因此按寄存器宽度（`usize`）接收。
#[no_mangle]
#[link_section = ".text._start"]
pub extern "C" fn _start(role: usize, endpoint: usize) -> ! {
    let endpoint = endpoint as u64;
    match role {
        7 => rt3_service(endpoint as i64),
        8 => rt3_client(endpoint as i64),
        5 => s3_channel_ping(endpoint as i64),
        6 => s3_channel_pong(endpoint as i64),
        4 => revoke_probe(endpoint),
        0 => semantics(),
        1 => ping(endpoint as i64),
        _ => pong(endpoint as i64),
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    exit(101)
}
