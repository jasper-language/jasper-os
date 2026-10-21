//! user-irqprobe：DRV-2C-1 的用户态演练程序——设备中断经中断对象与异步环交付。
//! DRV-2C-1 user-space probe: device interrupts delivered through interrupt objects and a ring.
//!
//! # 入口参数
//! `cpu_mask`：在线处理器位图；`bdf`：virtio-rng 的打包设备地址（由内核演练给出）。
//!
//! # 流程
//! 1. 打开设备（带 `CONTROL` 与只读各一个句柄）、建立 Ring；先验证无控制权限、表项越界、处理器不在线三种绑定被拒。
//! 2. 逐轮把表项 0 绑定到一个处理器（多处理器时每个在线处理器一轮，单处理器时两轮），经 Ring 提交等待并进入等待；
//!    内核驱动看到等待后让设备产生中断。每轮必须恰好收到一条完成、结果为 1，之后关闭中断句柄。
//!    第一轮另验证重复绑定与同步调用等待被拒。
//! 3. 未完成等待时再提交一个被拒（忙）；关闭中断句柄 ⇒ 未完成的等待以「已关闭」终态完成。
//! 4. 降权掉 `WAIT` 的句柄提交等待被拒。
//! 5. 取消一个等待后停在一个长时间的时间等待上，由内核在确认中断已记为待交付后放行；
//!    随后提交的等待必须立刻以 1 完成（取消不丢已到达的中断）。
//!
//! # 输出与退出码
//! 每个断言输出 `[JSR-IRQPROBE] case=… ok=true|false`，最后输出 `[JSR-IRQPROBE] summary …`。
//! 退出码按位交回内核演练：位 0–7 通过的拒绝数、8–15 拒绝总数、16–23 成功轮数、
//! 位 24 取消语义成立、位 25 关闭语义成立、位 26 有断言失败。
#![no_std]
#![no_main]

use core::arch::asm;
use core::fmt::{self, Write as _};

use kernel_core::object::Rights;
use kernel_core::ring_abi::{Cqe, EnterArgs, Sqe};

/// 系统调用号与错误码（构建期从登记表生成）。
#[allow(dead_code)]
mod ids {
    include!(concat!(env!("OUT_DIR"), "/ids.rs"));
}

const fn e(id: u64) -> i64 {
    -(id as i64)
}

const RIGHTS_DENIED: i64 = e(ids::SYSTEM_HANDLE_ERROR_RIGHTS_DENIED);
const ENTRY_OUT_OF_RANGE: i64 = e(ids::SYSTEM_DEVICE_ERROR_ENTRY_OUT_OF_RANGE);
const CPU_OFFLINE: i64 = e(ids::SYSTEM_DEVICE_ERROR_CPU_OFFLINE);
const ALREADY_BOUND: i64 = e(ids::SYSTEM_DEVICE_ERROR_ALREADY_BOUND);
const INTERRUPT_BUSY: i64 = e(ids::SYSTEM_DEVICE_ERROR_INTERRUPT_BUSY);
const INTERRUPT_CLOSED: i64 = e(ids::SYSTEM_DEVICE_ERROR_INTERRUPT_CLOSED);
const RING_ONLY: i64 = e(ids::SYSTEM_ASYNC_ERROR_RING_ONLY);
const CANCELLED: i64 = e(ids::SYSTEM_ASYNC_ERROR_CANCELLED);

/// virtio-rng 队列 0 的 MSI-X 表项。
const ENTRY: u64 = 0;
/// 明显越界的表项下标。
const BAD_ENTRY: u64 = 4096;
/// 停车用的时间等待时长（远超演练时长；由内核取消放行，不靠它到期）。
const PARK_TICKS: u64 = 1 << 40;
/// Ring 完成队列容量。
const RING_CAPACITY: u64 = 8;

/// 退出码字段（与内核演练一致）。
const EXIT_REJECTS_TOTAL_SHIFT: u32 = 8;
const EXIT_ROUNDS_SHIFT: u32 = 16;
const EXIT_CANCEL_OK: u64 = 1 << 24;
const EXIT_CLOSE_OK: u64 = 1 << 25;
const EXIT_FAILED: u64 = 1 << 26;

/// 断言计数（单线程程序，只在本文件的宏与函数里修改）。
static mut CHECKS: u32 = 0;
static mut FAILED: u32 = 0;
static mut REJECTS_OK: u32 = 0;
static mut REJECTS_TOTAL: u32 = 0;

/// 发起一个三参数系统调用（x86_64：rax=ID，rdi/rsi/rdx=参数，rcx/r11 被占用）。
///
/// # Safety
/// 参数必须符合该调用的约定；作为指针传入的值须指向本进程内、在调用期间有效的内存。
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

#[cfg(not(target_arch = "x86_64"))]
compile_error!("user-irqprobe 只支持 x86_64（DRV-2C 的验收范围；其它指令集冻结）");

/// 一行输出缓冲区。
struct Line {
    buf: [u8; 224],
    len: usize,
}

impl Line {
    fn new() -> Line {
        Line { buf: [0; 224], len: 0 }
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

impl fmt::Write for Line {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        if self.len + bytes.len() > self.buf.len() {
            return Err(fmt::Error);
        }
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        Ok(())
    }
}

/// 输出一行（越界时截断，不影响断言本身）。
fn log(args: fmt::Arguments<'_>) {
    let mut line = Line::new();
    let _ = line.write_fmt(args);
    let text = line.as_str();
    // SAFETY：text 位于本栈帧内。
    unsafe { syscall3(ids::SYSTEM_CONSOLE_WRITE, text.as_ptr() as u64, text.len() as u64, 0) };
}

/// 记录一个断言并输出一行；失败时额外输出 `[JSR-IRQPROBE-FAIL]`。
macro_rules! emit {
    ($ok:expr, $($t:tt)*) => {{
        let ok = $ok;
        // SAFETY：单线程程序，计数器只在这里与 `reject` 中修改。
        unsafe {
            CHECKS += 1;
            if !ok {
                FAILED += 1;
            }
        }
        log(format_args!("[JSR-IRQPROBE] {} ok={}", format_args!($($t)*), ok));
        if !ok {
            log(format_args!("[JSR-IRQPROBE-FAIL] {}", format_args!($($t)*)));
        }
        ok
    }};
}

/// 记录一个拒绝路径：返回值必须恰好是期望的错误码。
fn reject(ret: i64, want: i64, what: &str) {
    let ok = emit!(ret == want, "case=reject_{} ret={} want={}", what, ret, want);
    // SAFETY：同 `emit!`。
    unsafe {
        REJECTS_TOTAL += 1;
        if ok {
            REJECTS_OK += 1;
        }
    }
}

fn exit(code: u64) -> ! {
    // SAFETY：task.exit 不访问用户内存。
    unsafe {
        syscall3(ids::SYSTEM_TASK_EXIT, code, 0, 0);
    }
    loop {
        core::hint::spin_loop();
    }
}

fn open(bdf: u64, rights: Rights) -> i64 {
    // SAFETY：参数全是整数，内核自行校验。
    unsafe { syscall3(ids::SYSTEM_DEVICE_OPEN, bdf, rights.bits() as u64, 0) }
}

fn bind(device: i64, entry: u64, cpu: u64) -> i64 {
    // SAFETY：参数全是整数，内核自行校验。
    unsafe { syscall3(ids::SYSTEM_DEVICE_INTERRUPT_CREATE, device as u64, entry, cpu) }
}

/// 以同步系统调用的形式调用等待（必须被拒）。
fn sync_wait(h: i64) -> i64 {
    // SAFETY：参数是句柄值。
    unsafe { syscall3(ids::SYSTEM_DEVICE_INTERRUPT_WAIT, h as u64, 0, 0) }
}

fn close(h: i64) -> i64 {
    // SAFETY：参数是句柄值。
    unsafe { syscall3(ids::SYSTEM_HANDLE_CLOSE, h as u64, 0, 0) }
}

fn restrict(h: i64, rights: Rights) -> i64 {
    // SAFETY：参数是句柄值与权限位。
    unsafe { syscall3(ids::SYSTEM_HANDLE_RESTRICT, h as u64, rights.bits() as u64, 0) }
}

fn ring_create(capacity: u64) -> i64 {
    // SAFETY：create 不访问用户内存。
    unsafe { syscall3(ids::SYSTEM_ASYNC_RING_CREATE, capacity, 0, 0) }
}

fn cancel(ring: i64, req: u64) -> i64 {
    // SAFETY：cancel 不访问用户内存。
    unsafe { syscall3(ids::SYSTEM_ASYNC_CANCEL, ring as u64, req, 0) }
}

fn wait_sqe(h: i64, tag: u64) -> Sqe {
    Sqe { op: ids::SYSTEM_DEVICE_INTERRUPT_WAIT as u32, flags: 0, user_tag: tag, arg0: h as u64, arg1: 0 }
}

fn park_sqe(tag: u64) -> Sqe {
    Sqe { op: ids::SYSTEM_TIME_WAIT as u32, flags: 0, user_tag: tag, arg0: PARK_TICKS, arg1: 0 }
}

/// 一次 enter 的结果。
struct Entered {
    ret: i64,
    args: EnterArgs,
    ids: [u64; 8],
    cqes: [Cqe; 8],
}

impl Entered {
    /// 恰好收到一条完成，且标签与结果符合期望。
    fn one(&self, tag: u64, result: i64) -> bool {
        self.ret == 0 && self.args.reaped == 1 && self.cqes[0].user_tag == tag && self.cqes[0].result == result
    }
}

/// 提交 `sq` 并收取至多 8 条完成（至少等 `wait_min` 条）。
fn enter(ring: i64, sq: &[Sqe], wait_min: u32) -> Entered {
    let mut out = Entered { ret: 0, args: EnterArgs::default(), ids: [0; 8], cqes: [Cqe::default(); 8] };
    out.args = EnterArgs {
        sq_ptr: sq.as_ptr() as u64,
        cq_ptr: out.cqes.as_mut_ptr() as u64,
        id_ptr: out.ids.as_mut_ptr() as u64,
        sq_count: sq.len() as u32,
        cq_max: 8,
        wait_min,
        ..EnterArgs::default()
    };
    // SAFETY：参数块、提交数组、ID 数组与完成缓冲区都在本栈帧内且足够大（≤ 8 条）。
    out.ret = unsafe {
        syscall3(ids::SYSTEM_ASYNC_RING_ENTER, ring as u64, &mut out.args as *mut EnterArgs as u64, 0)
    };
    out
}

/// 位图中第 `n` 个置位的下标。
fn nth_cpu(mask: u64, n: u32) -> u64 {
    let mut m = mask;
    for _ in 0..n {
        m &= m - 1;
    }
    m.trailing_zeros() as u64
}

/// 逐轮绑定、等待、核对；返回成功的轮数。
fn rounds(device: i64, ring: i64, mask: u64) -> u32 {
    let cpus = mask.count_ones();
    let total = if cpus == 1 { 2 } else { cpus };
    let mut ok_rounds = 0;
    for round in 0..total {
        let cpu = if cpus == 1 { nth_cpu(mask, 0) } else { nth_cpu(mask, round) };
        let h = bind(device, ENTRY, cpu);
        if !emit!(h >= 0, "case=bind round={} cpu={} ret={}", round, cpu, h) {
            break;
        }
        if round == 0 {
            reject(bind(device, ENTRY, cpu), ALREADY_BOUND, "already_bound");
            reject(sync_wait(h), RING_ONLY, "sync_wait");
        }
        let tag = 100 + round as u64;
        let got = enter(ring, &[wait_sqe(h, tag)], 1);
        let extra = enter(ring, &[], 0);
        let ok = emit!(
            got.args.submitted == 1 && got.one(tag, 1) && extra.ret == 0 && extra.args.reaped == 0,
            "case=round round={} cpu={} result={} reaped={} extra={}",
            round,
            cpu,
            got.cqes[0].result,
            got.args.reaped,
            extra.args.reaped
        );
        emit!(close(h) == 0, "case=close round={}", round);
        if ok {
            ok_rounds += 1;
        } else {
            break;
        }
    }
    ok_rounds
}

/// 未完成等待时再提交被拒（忙）；关闭句柄 ⇒ 未完成的等待以「已关闭」终态完成。返回关闭语义是否成立。
fn busy_and_close(device: i64, ring: i64, cpu: u64) -> bool {
    let h = bind(device, ENTRY, cpu);
    if !emit!(h >= 0, "case=bind_close ret={}", h) {
        return false;
    }
    let first = enter(ring, &[wait_sqe(h, 200)], 0);
    let parked = emit!(first.ret == 0 && first.args.submitted == 1 && first.args.reaped == 0, "case=park_first");
    let second = enter(ring, &[wait_sqe(h, 201)], 0);
    reject(second.args.first_error, INTERRUPT_BUSY, "busy");
    emit!(second.args.submitted == 0, "case=busy_not_submitted");
    let closed = close(h);
    let done = enter(ring, &[], 1);
    emit!(
        parked && closed == 0 && done.one(200, INTERRUPT_CLOSED),
        "case=close_cancels_wait result={} reaped={}",
        done.cqes[0].result,
        done.args.reaped
    )
}

/// 降权掉 `WAIT` 的句柄提交等待被拒。
fn no_wait_right(device: i64, ring: i64, cpu: u64) {
    let h = bind(device, ENTRY, cpu);
    if !emit!(h >= 0, "case=bind_restrict ret={}", h) {
        return;
    }
    emit!(restrict(h, Rights::CONTROL) == 0, "case=restrict");
    let r = enter(ring, &[wait_sqe(h, 300)], 0);
    reject(r.args.first_error, RIGHTS_DENIED, "no_wait_right");
    emit!(r.args.submitted == 0, "case=no_wait_right_not_submitted");
    emit!(close(h) == 0, "case=close_restricted");
}

/// 取消不丢已到达的中断：取消等待 → 停在时间等待上（内核产生中断并确认待交付后放行）→ 新等待立刻以 1 完成。
fn cancel_keeps_arrival(device: i64, ring: i64, cpu: u64) -> bool {
    let h = bind(device, ENTRY, cpu);
    if !emit!(h >= 0, "case=bind_cancel ret={}", h) {
        return false;
    }
    let w = enter(ring, &[wait_sqe(h, 400)], 0);
    let parked = emit!(w.ret == 0 && w.args.submitted == 1 && w.args.reaped == 0, "case=park_cancel");
    let c = cancel(ring, w.ids[0]);
    let cancelled = enter(ring, &[], 1);
    let c_ok = emit!(c == 0 && cancelled.one(400, CANCELLED), "case=cancel_wait ret={} result={}", c, cancelled.cqes[0].result);
    let park = enter(ring, &[park_sqe(401)], 1);
    let released = emit!(park.one(401, CANCELLED), "case=kernel_released result={}", park.cqes[0].result);
    let again = enter(ring, &[wait_sqe(h, 402)], 0);
    let immediate = emit!(
        again.args.submitted == 1 && again.one(402, 1),
        "case=pending_after_cancel result={} reaped={}",
        again.cqes[0].result,
        again.args.reaped
    );
    emit!(close(h) == 0, "case=close_cancel");
    parked && c_ok && released && immediate
}

fn counters() -> (u32, u32, u32, u32) {
    // SAFETY：只读取单线程写入的计数器。
    unsafe { (CHECKS, FAILED, REJECTS_OK, REJECTS_TOTAL) }
}

/// 程序入口（链接脚本把它放在代码段最前面）；参数由内核演练给出。
/// Program entry (placed first in the text segment by the linker).
#[no_mangle]
#[link_section = ".text._start"]
pub extern "C" fn _start(cpu_mask: usize, bdf: usize) -> ! {
    let mask = cpu_mask as u64;
    let first = nth_cpu(mask, 0);
    let offline = (!mask).trailing_zeros() as u64;
    let device = open(bdf as u64, Rights::READ.union(Rights::CONTROL));
    let read_only = open(bdf as u64, Rights::READ);
    let ring = ring_create(RING_CAPACITY);
    let ready = emit!(
        mask != 0 && device >= 0 && read_only >= 0 && ring >= 0,
        "case=setup device={} read_only={} ring={}",
        device,
        read_only,
        ring
    );
    let (mut done_rounds, mut close_ok, mut cancel_ok) = (0, false, false);
    if ready {
        reject(bind(read_only, ENTRY, first), RIGHTS_DENIED, "no_control");
        reject(bind(device, BAD_ENTRY, first), ENTRY_OUT_OF_RANGE, "entry_out_of_range");
        reject(bind(device, ENTRY, offline), CPU_OFFLINE, "cpu_offline");
        done_rounds = rounds(device, ring, mask);
        close_ok = busy_and_close(device, ring, first);
        no_wait_right(device, ring, first);
        cancel_ok = cancel_keeps_arrival(device, ring, first);
    }
    emit!(close(device) == 0 && close(read_only) == 0 && close(ring) == 0, "case=close_all");
    let (checks, failed, rejects_ok, rejects_total) = counters();
    log(format_args!(
        "[JSR-IRQPROBE] summary checks={} failed={} rounds={} rejects={}/{} cancel={} close={}",
        checks, failed, done_rounds, rejects_ok, rejects_total, cancel_ok, close_ok
    ));
    let mut code = rejects_ok as u64 | (rejects_total as u64) << EXIT_REJECTS_TOTAL_SHIFT | (done_rounds as u64) << EXIT_ROUNDS_SHIFT;
    if cancel_ok {
        code |= EXIT_CANCEL_OK;
    }
    if close_ok {
        code |= EXIT_CLOSE_OK;
    }
    if failed != 0 {
        code |= EXIT_FAILED;
    }
    exit(code)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    exit(EXIT_FAILED)
}
