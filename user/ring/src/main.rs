//! user-ring：异步环的用户态验收程序。
//! User-mode acceptance program for the asynchronous ring.
//!
//! 依次验证（每一步失败都以该步编号作为退出码结束，并输出 `ring: FAIL step=<n>`）：
//! 1. 创建：容量越界被拒；合法容量返回句柄
//! 2. 请求 ID 单调递增；三个请求使用同一用户标签，完成记录照样一一对应（标签不参与匹配）
//! 3. 完成信用耗尽 ⇒ 提交被拒（`cq_full`），且不消耗请求 ID
//! 4. 信用耗尽时同步取消仍可用；已发布未消费的完成仍占信用；消费后信用归还
//! 5. 取消结果：已完成（窗口内）⇒ `already_completed`；窗口外 / 从未存在 ⇒ `not_found`
//! 6. 等待请求被取消 ⇒ 完成为 `cancelled`；未取消的等待请求在时钟到达后自然完成
//! 7. Ring 句柄不带 TRANSFER：试图复制出带 TRANSFER 的句柄被拒；同权限复制可行
//! 8. 不支持的操作、非法标志被拒且不产生请求
//! 9. 关闭句柄（仍有在飞请求）⇒ Ring closing；之后经该句柄的提交与取消都失败
#![no_std]
#![no_main]

use core::arch::asm;
use core::fmt::Write as _;

use kernel_core::memory_abi::MapArgs;
use kernel_core::ring_abi::{Cqe, EnterArgs, EnterUntilArgs, Sqe};

/// 系统调用号（构建期从登记表生成）。
#[allow(dead_code)]
mod ids {
    include!(concat!(env!("OUT_DIR"), "/ids.rs"));
}

/// 错误码 ID → 系统调用返回值。
const fn e(id: u64) -> i64 {
    -(id as i64)
}

const CANCELLED: i64 = e(ids::SYSTEM_ASYNC_ERROR_CANCELLED);
const ALREADY_COMPLETED: i64 = e(ids::SYSTEM_ASYNC_ERROR_ALREADY_COMPLETED);
const NOT_FOUND: i64 = e(ids::SYSTEM_ASYNC_ERROR_NOT_FOUND);
const CQ_FULL: i64 = e(ids::SYSTEM_ASYNC_ERROR_CQ_FULL);
const INVALID_ARGUMENT: i64 = e(ids::SYSTEM_ERROR_INVALID_ARGUMENT);
const UNSUPPORTED: i64 = e(ids::SYSTEM_ERROR_UNSUPPORTED);
const HANDLE_INVALID: i64 = e(ids::SYSTEM_HANDLE_ERROR_INVALID);
const HANDLE_RIGHTS_DENIED: i64 = e(ids::SYSTEM_HANDLE_ERROR_RIGHTS_DENIED);

/// 句柄权限位（与内核 Rights 一致）。
const WAIT: u64 = 1 << 3;
const TRANSFER: u64 = 1 << 6;

/// 一个「永远等不到」的等待时长（tick）。
const FOREVER: u64 = 1 << 40;

/// 发起一个两参数的系统调用（x86_64：rax=ID，rdi/rsi=参数，rcx/r11 被占用）。
///
/// # Safety
/// 参数必须符合该调用的约定（指针须指向本进程内存）。
#[cfg(target_arch = "x86_64")]
unsafe fn syscall2(id: u64, a: u64, b: u64) -> i64 {
    let ret: i64;
    asm!(
        "syscall",
        inlateout("rax") id as i64 => ret,
        in("rdi") a,
        in("rsi") b,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack)
    );
    ret
}

/// 发起系统调用（AArch64：x8=ID，x0/x1=参数，`svc #0`；返回值在 x0，其余寄存器由内核保留）。
///
/// # Safety
/// 参数必须符合该调用的约定（指针须指向本进程内存）。
#[cfg(target_arch = "aarch64")]
unsafe fn syscall2(id: u64, a: u64, b: u64) -> i64 {
    let ret: i64;
    asm!(
        "svc #0",
        in("x8") id,
        inlateout("x0") a as i64 => ret,
        in("x1") b,
        options(nostack)
    );
    ret
}

/// 发起系统调用（RISC-V：a7=ID，a0/a1=参数，`ecall`；返回值在 a0，其余寄存器由内核保留）。
///
/// # Safety
/// 参数必须符合该调用的约定（指针须指向本进程内存）。
#[cfg(target_arch = "riscv64")]
unsafe fn syscall2(id: u64, a: u64, b: u64) -> i64 {
    let ret: i64;
    asm!(
        "ecall",
        in("a7") id,
        inlateout("a0") a as i64 => ret,
        in("a1") b,
        options(nostack)
    );
    ret
}

/// 发起系统调用（RISC-V32 的 32 位用户 ABI：a7=ID；每个 64 位参数拆成两半，低半在 a0/a1、高半在 a3/a4，
/// 未用的第三个参数两半为 0；`ecall`；返回值低半在 a0、高半在 a1，其余寄存器由内核保留）。
///
/// # Safety
/// 参数必须符合该调用的约定（指针须指向本进程内存）。
#[cfg(target_arch = "riscv32")]
unsafe fn syscall2(id: u64, a: u64, b: u64) -> i64 {
    let (lo, hi): (u32, u32);
    asm!(
        "ecall",
        in("a7") id as u32,
        inlateout("a0") a as u32 => lo,
        inlateout("a1") b as u32 => hi,
        in("a2") 0u32,
        in("a3") (a >> 32) as u32,
        in("a4") (b >> 32) as u32,
        in("a5") 0u32,
        options(nostack)
    );
    ((hi as u64) << 32 | lo as u64) as i64
}

/// 输出一段 UTF-8 文本。
fn write(text: &str) -> i64 {
    // SAFETY：text 位于本进程内存。
    unsafe { syscall2(ids::SYSTEM_CONSOLE_WRITE, text.as_ptr() as u64, text.len() as u64) }
}

/// 以退出码结束本线程（不返回）。
fn exit(code: u64) -> ! {
    // SAFETY：task.exit 不访问用户内存。
    unsafe { syscall2(ids::SYSTEM_TASK_EXIT, code, 0) };
    loop {}
}

/// 栈上的定长文本缓冲（不用堆）。
struct Line {
    buf: [u8; 160],
    len: usize,
}

impl Line {
    fn new() -> Self {
        Line { buf: [0; 160], len: 0 }
    }
    fn emit(&self) {
        // 只追加过完整的 UTF-8 片段，因此整体仍是合法 UTF-8
        if let Ok(s) = core::str::from_utf8(&self.buf[..self.len]) {
            write(s);
        }
    }
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

/// 输出一行 `ring: …`。
macro_rules! say {
    ($($t:tt)*) => {{
        let mut l = Line::new();
        let _ = write!(l, "ring: ");
        let _ = write!(l, $($t)*);
        l.emit();
    }};
}

/// 断言：失败时输出步骤编号并以它作为退出码结束。
fn check(ok: bool, step: u64) {
    if !ok {
        say!("FAIL step={}", step);
        exit(step);
    }
}

fn now(tag: u64) -> Sqe {
    Sqe { op: ids::SYSTEM_TIME_NOW as u32, flags: 0, user_tag: tag, arg0: 0, arg1: 0 }
}

fn wait(tag: u64, ticks: u64) -> Sqe {
    Sqe { op: ids::SYSTEM_TIME_WAIT as u32, flags: 0, user_tag: tag, arg0: ticks, arg1: 0 }
}

/// 一次 enter 的结果。
struct Entered {
    ret: i64,
    args: EnterArgs,
    ids: [u64; 8],
    cqes: [Cqe; 8],
}

/// 提交 `sq` 并收取至多 `cq_max` 条完成（至少等 `wait_min` 条）。
fn enter(h: i64, sq: &[Sqe], cq_max: u32, wait_min: u32) -> Entered {
    let mut out = Entered { ret: 0, args: EnterArgs::default(), ids: [0; 8], cqes: [Cqe::default(); 8] };
    out.args = EnterArgs {
        sq_ptr: sq.as_ptr() as u64,
        cq_ptr: out.cqes.as_mut_ptr() as u64,
        id_ptr: out.ids.as_mut_ptr() as u64,
        sq_count: sq.len() as u32,
        cq_max,
        wait_min,
        ..EnterArgs::default()
    };
    // SAFETY：参数块、提交数组、ID 数组与完成缓冲区都在本栈帧内且足够大（≤ 8 条）。
    out.ret = unsafe { syscall2(ids::SYSTEM_ASYNC_RING_ENTER, h as u64, &mut out.args as *mut EnterArgs as u64) };
    out
}

/// Author: chatgpt。真实CPL3调用独立deadline入口，检查超时仍回写提交/收取结果。
fn until(h: i64, sq: &[Sqe], cq_max: u32, wait_min: u32, deadline: u64) -> Entered {
    let mut out = Entered { ret:0, args:EnterArgs::default(), ids:[0;8], cqes:[Cqe::default();8] };
    let mut descriptor = EnterUntilArgs { version:1, bytes:72, deadline, enter:EnterArgs {
        sq_ptr:sq.as_ptr() as u64, cq_ptr:out.cqes.as_mut_ptr() as u64,
        id_ptr:out.ids.as_mut_ptr() as u64, sq_count:sq.len() as u32, cq_max, wait_min,
        ..EnterArgs::default()
    }};
    // SAFETY：独立72字节参数块和各个数组存活覆盖整个调用，不转型旧56字节参数。
    out.ret = unsafe { syscall2(ids::SYSTEM_ASYNC_RING_DEADLINE_ENTER,h as u64,&mut descriptor as *mut EnterUntilArgs as u64) };
    out.args = descriptor.enter; out
}

fn cancel(h: i64, req: u64) -> i64 {
    // SAFETY：cancel 不访问用户内存。
    unsafe { syscall2(ids::SYSTEM_ASYNC_CANCEL, h as u64, req) }
}

fn create(capacity: u64) -> i64 {
    // SAFETY：create 不访问用户内存。
    unsafe { syscall2(ids::SYSTEM_ASYNC_RING_CREATE, capacity, 0) }
}

// Real CPL3 object ABI: two aliases retain one backing after last handle close.
fn shared_memory_contract() {
    let target=if cfg!(target_arch="x86_64") { "x86_64" } else if cfg!(target_arch="aarch64") { "aarch64" }
        else if cfg!(target_arch="riscv64") { "riscv64" } else { "riscv32" };
    let va=kernel_core::user_layout::window_base(target).unwrap()+0x200000;
    let vb=va+0x1000;
    let h=unsafe { syscall2(ids::SYSTEM_MEMORY_OBJECT_CREATE,1,0) };
    check(h>0,30);
    let mut args=MapArgs::new(va,0,1,true);
    args.reserved=1;
    check(unsafe { syscall2(ids::SYSTEM_MEMORY_OBJECT_MAP,h as u64,&args as *const MapArgs as u64) }==INVALID_ARGUMENT,31);
    args.reserved=0;
    check(unsafe { syscall2(ids::SYSTEM_MEMORY_OBJECT_MAP,h as u64,&args as *const MapArgs as u64) }==0,32);
    // SAFETY: the successful syscall mapped this page readable/writable in this process.
    check(unsafe { core::ptr::read_volatile(va as *const u64) }==0,33);
    unsafe { core::ptr::write_volatile(va as *mut u64,0x53484d3155534552); }
    let ro=unsafe { syscall2(ids::SYSTEM_HANDLE_DUPLICATE,h as u64,1 | 128) };
    check(ro>0,34);
    args=MapArgs::new(vb,0,1,true);
    check(unsafe { syscall2(ids::SYSTEM_MEMORY_OBJECT_MAP,ro as u64,&args as *const MapArgs as u64) }==HANDLE_RIGHTS_DENIED,35);
    args.flags=0;
    check(unsafe { syscall2(ids::SYSTEM_MEMORY_OBJECT_MAP,ro as u64,&args as *const MapArgs as u64) }==0,36);
    check(unsafe { core::ptr::read_volatile(vb as *const u64) }==0x53484d3155534552,37);
    check(unsafe { syscall2(ids::SYSTEM_HANDLE_CLOSE,h as u64,0) }==0 && unsafe { syscall2(ids::SYSTEM_HANDLE_CLOSE,ro as u64,0) }==0,38);
    check(unsafe { core::ptr::read_volatile(va as *const u64) }==0x53484d3155534552,39);
    check(unsafe { syscall2(ids::SYSTEM_MEMORY_OBJECT_UNMAP,va,1) }==0,40);
    check(unsafe { core::ptr::read_volatile(vb as *const u64) }==0x53484d3155534552,41);
    check(unsafe { syscall2(ids::SYSTEM_MEMORY_OBJECT_UNMAP,vb,1) }==0,42);
    check(unsafe { syscall2(ids::SYSTEM_MEMORY_OBJECT_MAP,h as u64,&args as *const MapArgs as u64) }==HANDLE_INVALID,43);
    say!("shm zeroed=true alias=true readonly_denied=true handle_close_retains=true unmap=true stale_handle=true");
    // Reserved ABI-R calls must not dereference even invalid descriptor addresses.
    for id in [ids::SYSTEM_MEMORY_BUFFER_CREATE, ids::SYSTEM_MEMORY_BUFFER_DESTROY, ids::SYSTEM_EXECUTION_RESTRICTED_CREATE, ids::SYSTEM_TASK_INTERRUPT_SEND, ids::SYSTEM_MEMORY_DMA_MAP, ids::SYSTEM_IO_SEGMENT_SUBMIT, ids::SYSTEM_TASK_SYSCALLS_SET] {
        check(unsafe { syscall2(id,u64::MAX,u64::MAX) } == UNSUPPORTED,44);
    }
    say!("abir reserved_unsupported=7 invalid_pointer_untouched=true");
}

/// 程序入口（链接脚本把它放在代码段最前面）。
#[no_mangle]
#[link_section = ".text._start"]
pub extern "C" fn _start(mode:u64,target:u64) -> ! {
    if mode==2 {event_subscription_program(target);}
    shared_memory_contract();
    // 1. 创建
    let bad0 = create(0);
    let bad65 = create(65);
    check(bad0 == INVALID_ARGUMENT && bad65 == INVALID_ARGUMENT, 1);
    let h = create(4);
    check(h > 0, 1);
    say!("create capacity=4 handle_ok=true bad_capacity={}", bad0);

    // 2. 请求 ID 单调；重复标签不影响对应
    let r = enter(h, &[now(7), now(7), now(7)], 8, 3);
    check(r.ret == 0 && r.args.submitted == 3 && r.args.reaped == 3 && r.args.first_error == 0, 2);
    let (a0, a1, a2) = (r.ids[0], r.ids[1], r.ids[2]);
    let monotonic = a0 < a1 && a1 < a2;
    let matched = (0..3).all(|i| r.cqes[i].request_id == r.ids[i] && r.cqes[i].user_tag == 7 && r.cqes[i].result >= 0);
    check(monotonic && matched, 2);
    say!("ids monotonic={} same_tag_matched={} first={}", monotonic, matched, a0);

    // 3. 信用耗尽 ⇒ cq_full，且不消耗请求 ID
    let r = enter(h, &[wait(1, FOREVER), wait(2, FOREVER), wait(3, FOREVER), wait(4, FOREVER)], 0, 0);
    check(r.ret == 0 && r.args.submitted == 4, 3);
    let w = [r.ids[0], r.ids[1], r.ids[2], r.ids[3]];
    let full = enter(h, &[now(9)], 0, 0);
    check(full.ret == 0 && full.args.submitted == 0 && full.args.first_error == CQ_FULL, 3);
    say!("cq_full submitted={} error={}", full.args.submitted, full.args.first_error);

    // 4. 信用耗尽时同步取消仍可用；已发布未消费仍占信用；消费后归还
    let c0 = cancel(h, w[0]);
    check(c0 == 0, 4);
    let still_full = enter(h, &[now(9)], 0, 0);
    check(still_full.args.submitted == 0 && still_full.args.first_error == CQ_FULL, 4);
    let reap = enter(h, &[], 1, 1);
    check(reap.args.reaped == 1 && reap.cqes[0].request_id == w[0] && reap.cqes[0].result == CANCELLED, 4);
    let after = enter(h, &[now(10)], 1, 1);
    check(after.args.submitted == 1 && after.args.reaped == 1, 4);
    let next_id = after.ids[0];
    let no_id_consumed = next_id == w[3] + 1;
    check(no_id_consumed, 4);
    say!(
        "sync_cancel_without_credit={} published_holds_credit={} credit_returned_on_consume=true rejected_ids_consumed={}",
        c0 == 0,
        still_full.args.first_error == CQ_FULL,
        !no_id_consumed
    );

    // 5. 取消结果：已发布顺序 a0,a1,a2,w0,next → 窗口（容量 4）保留 a1,a2,w0,next
    let again = cancel(h, w[0]);
    let in_window = cancel(h, a1);
    let evicted = cancel(h, a0);
    let never = cancel(h, 999_999);
    check(again == ALREADY_COMPLETED && in_window == ALREADY_COMPLETED && evicted == NOT_FOUND && never == NOT_FOUND, 5);
    say!("cancel again={} in_window={} evicted={} never={}", again, in_window, evicted, never);

    // 6. 取消其余等待请求；新的短等待自然完成
    check(cancel(h, w[1]) == 0 && cancel(h, w[2]) == 0 && cancel(h, w[3]) == 0, 6);
    let reap = enter(h, &[], 8, 3);
    let all_cancelled = reap.args.reaped == 3 && (0..3).all(|i| reap.cqes[i].result == CANCELLED);
    check(all_cancelled, 6);
    let short = enter(h, &[wait(11, 3)], 1, 1);
    let natural = short.args.submitted == 1 && short.args.reaped == 1 && short.cqes[0].result == 0 && short.cqes[0].user_tag == 11;
    check(natural, 6);
    say!("wait cancelled={} natural_completion={}", all_cancelled, natural);

    // 7. Ring 句柄不可传递：复制出带 TRANSFER 的句柄被拒；同权限复制可行
    // SAFETY：duplicate / close 不访问用户内存。
    let dup_transfer = unsafe { syscall2(ids::SYSTEM_HANDLE_DUPLICATE, h as u64, WAIT | TRANSFER) };
    let dup_wait = unsafe { syscall2(ids::SYSTEM_HANDLE_DUPLICATE, h as u64, WAIT) };
    let closed_dup = unsafe { syscall2(ids::SYSTEM_HANDLE_CLOSE, dup_wait as u64, 0) };
    check(dup_transfer == HANDLE_RIGHTS_DENIED && dup_wait > 0 && closed_dup == 0, 7);
    say!("handle dup_with_transfer={} dup_without_transfer_ok={}", dup_transfer, dup_wait > 0);

    // 8. 不支持的操作、非法标志
    let bad_op = enter(h, &[Sqe { op: ids::SYSTEM_CONSOLE_WRITE as u32, ..now(12) }], 0, 0);
    let bad_flags = enter(h, &[Sqe { flags: 1, ..now(13) }], 0, 0);
    check(bad_op.args.submitted == 0 && bad_op.args.first_error == UNSUPPORTED, 8);
    check(bad_flags.args.submitted == 0 && bad_flags.args.first_error == INVALID_ARGUMENT, 8);
    let reserved_flags = enter(h, &[Sqe { flags: kernel_core::extension_abi::SQE_REGISTERED_BUFFER, ..now(13) }], 0, 0);
    check(reserved_flags.args.submitted == 0 && reserved_flags.args.first_error == UNSUPPORTED, 8);
    say!("abir registered_buffer_unsupported=true no_submission=true legacy_flags_preserved=true");
    say!("reject bad_op={} bad_flags={}", bad_op.args.first_error, bad_flags.args.first_error);

    // Author: chatgpt。截止已到时：已可见完成优先；超时不抹掉submitted/ID，不取消请求。
    let ready = until(h, &[now(20)], 1, 1, 0);
    check(ready.ret == 0 && ready.args.submitted == 1 && ready.args.reaped == 1, 10);
    let timed = until(h, &[wait(21, FOREVER)], 1, 1, 0);
    check(timed.ret == e(ids::SYSTEM_ASYNC_ERROR_TIMED_OUT) && timed.args.submitted == 1 && timed.args.reaped == 0 && timed.ids[0] != 0, 11);
    check(cancel(h,timed.ids[0]) == 0, 11);
    let cancelled = enter(h,&[],1,1);
    check(cancelled.args.reaped == 1 && cancelled.cqes[0].result == CANCELLED, 11);
    let partial = until(h,&[now(22),wait(23,FOREVER)],2,2,0);
    check(partial.ret == e(ids::SYSTEM_ASYNC_ERROR_TIMED_OUT) && partial.args.submitted == 2 && partial.args.reaped == 1 && partial.args.first_error == 0, 12);
    check(cancel(h,partial.ids[1]) == 0, 12);
    check(enter(h,&[],1,1).args.reaped == 1, 12);
    // 真正阻塞至显式期限：只要求不早于期限，不将TCG耗时当物理延迟上界。
    let tick = unsafe { syscall2(ids::SYSTEM_TIME_NOW,0,0) } as u64;
    let future = tick.checked_add(3).unwrap();
    let expired = until(h,&[wait(24,FOREVER)],1,1,future);
    let after = unsafe { syscall2(ids::SYSTEM_TIME_NOW,0,0) } as u64;
    check(expired.ret == e(ids::SYSTEM_ASYNC_ERROR_TIMED_OUT) && expired.args.submitted == 1 && expired.args.reaped == 0 && after >= future, 13);
    check(cancel(h,expired.ids[0]) == 0 && enter(h,&[],1,1).args.reaped == 1, 13);
    let tick = unsafe { syscall2(ids::SYSTEM_TIME_NOW,0,0) } as u64;
    let early = until(h,&[wait(25,1)],1,1,tick.checked_add(20).unwrap());
    check(early.ret == 0 && early.args.submitted == 1 && early.args.reaped == 1 && early.cqes[0].result == 0, 14);
    say!("deadline ready_first=true timeout_preserves_submission=true partial_cq=true future_timeout=true backend_first=true");

    // 9. 关闭仍有在飞请求的 Ring ⇒ closing；之后经该句柄的操作失败
    let pending = enter(h, &[wait(14, FOREVER)], 0, 0);
    check(pending.args.submitted == 1, 9);
    // SAFETY：close 不访问用户内存。
    let closed = unsafe { syscall2(ids::SYSTEM_HANDLE_CLOSE, h as u64, 0) };
    let after_close = enter(h, &[now(15)], 0, 0);
    let cancel_after = cancel(h, pending.ids[0]);
    check(closed == 0 && after_close.ret == HANDLE_INVALID && cancel_after == HANDLE_INVALID, 9);
    say!("closed_with_pending=true enter_after_close={} cancel_after_close={}", after_close.ret, cancel_after);

    say!("all checks passed");
    exit(0)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    exit(101)
}

fn event_subscription_program(target:u64)->! {
 let mut source=[0u8;24];source[..2].copy_from_slice(&1u16.to_le_bytes());source[2..4].copy_from_slice(&24u16.to_le_bytes());source[8..16].copy_from_slice(&target.to_le_bytes());
 source[16]=1;
 check(unsafe {syscall2(ids::SYSTEM_EVENT_SOURCE_CREATE,source.as_ptr() as u64,0)}==INVALID_ARGUMENT,71);source[16]=0;
 let handle=unsafe {syscall2(ids::SYSTEM_EVENT_SOURCE_CREATE,source.as_ptr() as u64,0)};check(handle>0,72);
 let mut subscribe=[0u8;32];subscribe[..2].copy_from_slice(&1u16.to_le_bytes());subscribe[2..4].copy_from_slice(&32u16.to_le_bytes());subscribe[4..8].copy_from_slice(&1u32.to_le_bytes());subscribe[8..12].copy_from_slice(&16u32.to_le_bytes());
 let sub=unsafe {syscall2(ids::SYSTEM_EVENT_SUBSCRIPTION_CREATE,handle as u64,subscribe.as_mut_ptr() as u64)};check(sub>0,73);
 check(u64::from_le_bytes(subscribe[16..24].try_into().unwrap())==0,74);
 let ring=create(4);check(ring>0,75);let mut records=[[0u64;4];4];
 let mut wait=[0u8;24];wait[..2].copy_from_slice(&1u16.to_le_bytes());wait[2..4].copy_from_slice(&24u16.to_le_bytes());wait[4..8].copy_from_slice(&4u32.to_le_bytes());wait[8..16].copy_from_slice(&(records.as_mut_ptr() as u64).to_le_bytes());
 check(unsafe {syscall2(ids::SYSTEM_EVENT_SUBSCRIPTION_WAIT,sub as u64,wait.as_ptr() as u64)}==UNSUPPORTED,76);
 let sq=Sqe {op:ids::SYSTEM_EVENT_SUBSCRIPTION_WAIT as u32,flags:0,user_tag:91,arg0:sub as u64,arg1:wait.as_ptr() as u64};
 let queued=enter(ring,&[sq],0,0);check(queued.ret==0 && queued.args.submitted==1,77);
 let completed=enter(ring,&[],4,1);check(completed.ret==0 && completed.args.reaped==1 && completed.cqes[0].result==1,78);
 check(records[0]==[1,1,1,37],79);
 let late=unsafe {syscall2(ids::SYSTEM_EVENT_SUBSCRIPTION_CREATE,handle as u64,subscribe.as_mut_ptr() as u64)};check(late>0,80);
 check(u64::from_le_bytes(subscribe[16..24].try_into().unwrap())==1 && u64::from_le_bytes(subscribe[24..32].try_into().unwrap())==37,81);
 check(unsafe {syscall2(ids::SYSTEM_HANDLE_RESTRICT,handle as u64,1)}==0,82);
 check(unsafe {syscall2(ids::SYSTEM_EVENT_SUBSCRIPTION_CREATE,handle as u64,subscribe.as_mut_ptr() as u64)}==HANDLE_RIGHTS_DENIED,83);
 public_spawn_events(ring);
 for h in [late,sub,handle,ring] {check(unsafe {syscall2(ids::SYSTEM_HANDLE_CLOSE,h as u64,0)}==0,84);}
 say!("evt2 cpl3=true source=true snapshot=true parked=true batch=true late_snapshot=true rights=true failed=0");exit(0)
}

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

#[repr(align(16))]
struct EventThreadStack([u8;16384]);
static mut EVENT_THREAD_STACK:EventThreadStack=EventThreadStack([0;16384]);
static EVENT_THREAD_RELEASE:core::sync::atomic::AtomicU64=core::sync::atomic::AtomicU64::new(0);
extern "C" fn event_child(_:u64,_:u64)->! {
 while EVENT_THREAD_RELEASE.load(core::sync::atomic::Ordering::Acquire)==0 {unsafe {syscall2(ids::SYSTEM_TASK_YIELD,0,0);}}
 exit(49)
}
fn observe_spawned_exit(ring:i64,target:u64,kind:u32,expected:u64) {
 let mut source=[0u8;24];source[..2].copy_from_slice(&1u16.to_le_bytes());source[2..4].copy_from_slice(&24u16.to_le_bytes());source[4..8].copy_from_slice(&kind.to_le_bytes());source[8..16].copy_from_slice(&target.to_le_bytes());
 let handle=unsafe {syscall2(ids::SYSTEM_EVENT_SOURCE_CREATE,source.as_ptr() as u64,0)};check(handle>0,85);
 let mut args=[0u8;32];args[..2].copy_from_slice(&1u16.to_le_bytes());args[2..4].copy_from_slice(&32u16.to_le_bytes());args[4..8].copy_from_slice(&1u32.to_le_bytes());args[8..12].copy_from_slice(&16u32.to_le_bytes());
 let sub=unsafe {syscall2(ids::SYSTEM_EVENT_SUBSCRIPTION_CREATE,handle as u64,args.as_mut_ptr() as u64)};check(sub>0,86);
 let version=u64::from_le_bytes(args[16..24].try_into().unwrap());
 if kind==1 {check(version==0,87);EVENT_THREAD_RELEASE.store(1,core::sync::atomic::Ordering::Release);}
 if version==0 {
  let mut record=[0u64;4];let mut wait=[0u8;24];wait[..2].copy_from_slice(&1u16.to_le_bytes());wait[2..4].copy_from_slice(&24u16.to_le_bytes());wait[4..8].copy_from_slice(&1u32.to_le_bytes());wait[8..16].copy_from_slice(&(record.as_mut_ptr() as u64).to_le_bytes());
  let result=enter(ring,&[Sqe {op:ids::SYSTEM_EVENT_SUBSCRIPTION_WAIT as u32,flags:0,user_tag:92,arg0:sub as u64,arg1:wait.as_ptr() as u64}],1,1);
  check(result.ret==0 && result.args.reaped==1 && result.cqes[0].result==1,88);check(record==[1,1,1,expected],89);
 } else {check(version==1 && u64::from_le_bytes(args[24..32].try_into().unwrap())==expected,90);}
 for h in [sub,handle] {check(unsafe {syscall2(ids::SYSTEM_HANDLE_CLOSE,h as u64,0)}==0,91);}
}
fn public_spawn_events(ring:i64) {
 EVENT_THREAD_RELEASE.store(0,core::sync::atomic::Ordering::Release);
 let top=unsafe {core::ptr::addr_of_mut!(EVENT_THREAD_STACK.0).cast::<u8>().add(16384) as u64};
 let task=unsafe {syscall3(ids::SYSTEM_TASK_SPAWN,event_child as *const () as u64,top,0)};check(task>0,92);
 observe_spawned_exit(ring,task as u64,1,49);check(unsafe {syscall2(ids::SYSTEM_HANDLE_CLOSE,task as u64,0)}==0,93);
 #[cfg(target_arch="x86_64")]
 public_process_spawn_event(ring);
 say!("evt2 public_task_spawn=true public_process_spawn={} source_rights=true exit_event=true",cfg!(target_arch="x86_64"));
}
#[cfg(target_arch="x86_64")]
fn public_process_spawn_event(ring:i64) {
 // A minimal real static ELF fixture, passed through the public process.spawn syscall.
 // It waits briefly then exits51. Snapshot-or-event accepts either actual scheduling order.
 let mut image=[0u8;4096+26];image[..7].copy_from_slice(&[0x7f,b'E',b'L',b'F',2,1,1]);
 image[16..18].copy_from_slice(&2u16.to_le_bytes());image[18..20].copy_from_slice(&62u16.to_le_bytes());image[20..24].copy_from_slice(&1u32.to_le_bytes());
 let address=kernel_core::user_layout::window_base("x86_64").unwrap()+0x200000;
 image[24..32].copy_from_slice(&address.to_le_bytes());image[32..40].copy_from_slice(&64u64.to_le_bytes());image[52..54].copy_from_slice(&64u16.to_le_bytes());image[54..56].copy_from_slice(&56u16.to_le_bytes());image[56..58].copy_from_slice(&1u16.to_le_bytes());
 image[64..68].copy_from_slice(&1u32.to_le_bytes());image[68..72].copy_from_slice(&5u32.to_le_bytes());image[72..80].copy_from_slice(&4096u64.to_le_bytes());image[80..88].copy_from_slice(&address.to_le_bytes());image[96..104].copy_from_slice(&26u64.to_le_bytes());image[104..112].copy_from_slice(&26u64.to_le_bytes());image[112..120].copy_from_slice(&4096u64.to_le_bytes());
 let code=&mut image[4096..];code[0]=0xb8;code[1..5].copy_from_slice(&(ids::SYSTEM_TIME_WAIT as u32).to_le_bytes());code[5]=0xbf;code[6..10].copy_from_slice(&3u32.to_le_bytes());code[10..12].copy_from_slice(&[0x0f,0x05]);code[12]=0xb8;code[13..17].copy_from_slice(&(ids::SYSTEM_TASK_EXIT as u32).to_le_bytes());code[17]=0xbf;code[18..22].copy_from_slice(&51u32.to_le_bytes());code[22..26].copy_from_slice(&[0x0f,0x05,0x0f,0x0b]);
 let desc=kernel_core::spawn_abi::SpawnDesc {image_ptr:image.as_ptr() as u64,image_len:image.len() as u64,calls:(1u64<<ids::SYSTEM_TASK_EXIT)|(1u64<<ids::SYSTEM_TIME_WAIT),arg:0,cpu_limit_permille:kernel_core::spawn_abi::CPU_UNLIMITED,..Default::default()};let mut raw=desc.encode();
 check(unsafe {syscall2(ids::SYSTEM_PROCESS_SPAWN,raw.as_mut_ptr() as u64,0)}==0,94);
 let output=kernel_core::spawn_abi::SpawnDesc::decode(&raw);observe_spawned_exit(ring,output.out_process,0,51);
 for handle in [output.out_process,output.out_channel] {check(unsafe {syscall2(ids::SYSTEM_HANDLE_CLOSE,handle,0)}==0,95);}
}
