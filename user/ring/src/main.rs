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

use kernel_core::ring_abi::{Cqe, EnterArgs, Sqe};

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

fn cancel(h: i64, req: u64) -> i64 {
    // SAFETY：cancel 不访问用户内存。
    unsafe { syscall2(ids::SYSTEM_ASYNC_CANCEL, h as u64, req) }
}

fn create(capacity: u64) -> i64 {
    // SAFETY：create 不访问用户内存。
    unsafe { syscall2(ids::SYSTEM_ASYNC_RING_CREATE, capacity, 0) }
}

/// 程序入口（链接脚本把它放在代码段最前面）。
#[no_mangle]
#[link_section = ".text._start"]
pub extern "C" fn _start() -> ! {
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
    say!("reject bad_op={} bad_flags={}", bad_op.args.first_error, bad_flags.args.first_error);

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
