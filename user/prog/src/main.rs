//! user-prog：最小非特权程序（M5.1 验收）。入口参数 `(role, arg)` 选择要验证的行为：
//! Minimal unprivileged program for the final Phase 1 acceptance; `role` selects the behaviour.
//!
//! | role | 行为 | 预期 |
//! |---|---|---|
//! | 0 | 证明运行在非特权级（x86_64 读代码段选择子 = 3；AArch64 见 `privilege`），输出问候后正常退出 | 退出码 0 |
//! | 1 | 读内核地址 `arg` | 该进程被终止（故障），内核继续运行 |
//! | 2 | 执行特权指令 | 该进程被终止 |
//! | 3 | 执行无效指令（用户态异常） | 该进程被终止 |
//! | 4 | 以内核地址作为系统调用指针 | 调用被拒（`invalid_address`），随后正常退出 |
//! | 5 | 子进程：创建一个在用户态死循环的线程，稍候调用 `system.process.exit(9)` | 循环线程在下一个调度点被停止，退出码 9 |
//! | 6 | 父进程：`arg` 是子进程句柄；经 ring 提交两个 wait，取消其中一个，关闭子进程句柄后等待另一个完成 | 一个 `cancelled`、一个得到 9 |
//! | 7 | 内核内阻塞时终止：创建一个停在内核等待里的线程（`arg` 选择等待方式：0 同步 time.wait、1 同步 recv、
//! |   | 2 ring enter 等待完成、3 同步 task.wait 另一个阻塞线程），稍候调用 `system.process.exit(7)` | 阻塞的线程被打断并停止，退出码 7 |
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

const CANCELLED: i64 = -(ids::SYSTEM_ASYNC_ERROR_CANCELLED as i64);
const INVALID_ADDRESS: i64 = -(ids::SYSTEM_MEMORY_ERROR_INVALID_ADDRESS as i64);

/// 发起系统调用（x86_64：rax=ID，rdi/rsi/rdx=参数，rcx/r11 被占用）。
///
/// # Safety
/// 参数必须符合该调用的约定。
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

fn sys(id: u64, a: u64, b: u64) -> i64 {
    // SAFETY：调用者传入的指针都指向本进程内存（role 4 故意传入内核地址，由内核拒绝）。
    unsafe { syscall3(id, a, b, 0) }
}

fn write(text: &str) -> i64 {
    sys(ids::SYSTEM_CONSOLE_WRITE, text.as_ptr() as u64, text.len() as u64)
}

fn exit(code: u64) -> ! {
    sys(ids::SYSTEM_TASK_EXIT, code, 0);
    loop {}
}

struct Line {
    buf: [u8; 160],
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
        let mut l = Line { buf: [0; 160], len: 0 };
        let _ = write!(l, "prog: ");
        let _ = write!(l, $($t)*);
        if let Ok(s) = core::str::from_utf8(&l.buf[..l.len]) {
            write(s);
        }
    }};
}

/// 死循环线程：只在用户态空转，从不发起系统调用（只能在被时钟中断时停止）。
extern "C" fn spinner(_: u64) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

static mut SPIN_STACK: [u8; 4096] = [0; 4096];

/// 阻塞线程用的栈（role 7 最多两个阻塞线程，各占一页）。
static mut BLOCK_STACKS: [[u8; 4096]; 2] = [[0; 4096]; 2];

/// 足够长、在验收期间不可能自然到期的等待（tick 数）。
const FOREVER: u64 = 1_000_000_000;

/// 同步 recv 用的接收缓冲区与描述（端点永远收不到消息）。
static mut RECV_BUF: [u8; 64] = [0; 64];
static mut RECV_DESC: MsgDesc = MsgDesc { data_ptr: 0, handles_ptr: 0, data_len: 0, handles_cap: 0, out_data_len: 0, out_handles: 0 };

/// 停在内核等待里的线程：`arg` 的低 8 位选择等待方式，高位是附带的句柄（端点或线程句柄）。
/// 正常情况下这些调用都不会返回——进程终止时内核打断等待并停止本线程。返回则说明打断失败，以 `exit(5)` 标记。
extern "C" fn blocker(arg: u64) -> ! {
    let (kind, h) = (arg & 0xFF, arg >> 8);
    match kind {
        0 => {
            sys(ids::SYSTEM_TIME_WAIT, FOREVER, 0);
        }
        1 => {
            // SAFETY：只取静态缓冲区与描述的地址；本进程内只有这一个线程使用它们。
            let d = unsafe {
                let d = &mut *core::ptr::addr_of_mut!(RECV_DESC);
                d.data_ptr = core::ptr::addr_of_mut!(RECV_BUF) as u64;
                d.data_len = 64;
                d as *mut MsgDesc as u64
            };
            sys(ids::SYSTEM_CHANNEL_RECV, h, d);
        }
        2 => {
            let ring = sys(ids::SYSTEM_ASYNC_RING_CREATE, 4, 0);
            let w = Sqe { op: ids::SYSTEM_TIME_WAIT as u32, flags: 0, user_tag: 1, arg0: FOREVER, arg1: 0 };
            let mut cq = [Cqe::default(); 1];
            enter(ring, &[w], &mut cq, 1);
        }
        _ => {
            sys(ids::SYSTEM_TASK_WAIT, h, 0);
        }
    }
    say!("LEAK blocked wait returned kind={}", kind);
    exit(5)
}

/// 在第 `slot` 个阻塞栈上创建阻塞线程，返回线程句柄。
fn spawn_blocker(slot: usize, arg: u64) -> i64 {
    // SAFETY：只取地址；slot 只取 0 或 1。
    let top = unsafe { core::ptr::addr_of_mut!(BLOCK_STACKS[slot]) as u64 + 4096 };
    // SAFETY：entry 指向本程序代码，栈位于本进程可写内存且每个线程独占一个。
    unsafe { syscall3(ids::SYSTEM_TASK_SPAWN, blocker as usize as u64, top, arg) }
}

/// 当前特权级的名字与取值，以及它是否为非特权级。
///
/// x86_64：代码段选择子的低两位（3 = 用户态）。
#[cfg(target_arch = "x86_64")]
fn privilege() -> (&'static str, u16, bool) {
    let cs: u16;
    // SAFETY：只读段寄存器。
    unsafe { asm!("mov {0:x}, cs", out(reg) cs, options(nomem, nostack, preserves_flags)) };
    ("cpl", cs & 3, cs & 3 == 3)
}

/// 当前特权级的名字与取值，以及它是否为非特权级。
///
/// AArch64：EL0 读不到 `CurrentEL`（读它本身就是无效指令，见 role 2/3 的同类验证），因此这里不读寄存器，
/// 而以结构性事实为证：本程序的输出只能经 `svc` 送出，内核只把来自 EL0 的 `svc` 当作系统调用分发
/// （EL1 发出的 `svc` 走当前特权级的向量并被当作致命错误）。问候文本出现在控制台上即证明运行在 EL0。
#[cfg(target_arch = "aarch64")]
fn privilege() -> (&'static str, u16, bool) {
    ("el", 0, true)
}

/// 当前特权级的名字与取值，以及它是否为非特权级。
///
/// RISC-V：用户态读不到当前特权级（访问任何监管态 CSR 都是非法指令，见 role 2 的同类验证），与 AArch64 相同，
/// 以结构性事实为证：本程序的输出只能经 `ecall` 送出，内核只把来自用户态的 `ecall` 当作系统调用分发。
/// 问候文本出现在控制台上即证明运行在用户态（U = 0）。
#[cfg(target_arch = "riscv64")]
fn privilege() -> (&'static str, u16, bool) {
    ("mode", 0, true)
}

/// 提交并收取；返回（参数块的输出，第一条被接受提交的请求 ID）。
fn enter(ring: i64, sq: &[Sqe], cq: &mut [Cqe], wait_min: u32) -> (EnterArgs, u64) {
    let mut ids_out = [0u64; 4];
    let mut a = EnterArgs {
        sq_ptr: sq.as_ptr() as u64,
        cq_ptr: cq.as_mut_ptr() as u64,
        id_ptr: ids_out.as_mut_ptr() as u64,
        sq_count: sq.len() as u32,
        cq_max: cq.len() as u32,
        wait_min,
        ..EnterArgs::default()
    };
    let r = sys(ids::SYSTEM_ASYNC_RING_ENTER, ring as u64, &mut a as *mut EnterArgs as u64);
    if r != 0 {
        a.first_error = r;
    }
    (a, ids_out[0])
}

/// 程序入口（链接脚本把它放在代码段最前面）。
#[no_mangle]
#[link_section = ".text._start"]
pub extern "C" fn _start(role: u64, arg: u64) -> ! {
    match role {
        0 => {
            let (name, level, user) = privilege();
            say!("hello {}={}", name, level);
            exit(if user { 0 } else { 2 })
        }
        1 => {
            say!("reading kernel address");
            // SAFETY：故意读内核地址，预期在此处被终止。
            let v = unsafe { core::ptr::read_volatile(arg as *const u64) };
            say!("LEAK value={:#x}", v);
            exit(3)
        }
        2 => {
            say!("executing privileged instruction");
            // SAFETY：故意执行特权指令，预期在此处被终止。
            // x86_64：hlt（#GP）；AArch64：改写中断屏蔽位（SCTLR_EL1.UMA = 0 ⇒ EL0 执行即陷入）；
            // RISC-V：置位监管态中断使能（用户态访问监管态 CSR ⇒ 非法指令）
            #[cfg(target_arch = "x86_64")]
            unsafe { asm!("hlt", options(nomem, nostack)) };
            #[cfg(target_arch = "aarch64")]
            unsafe { asm!("msr daifset, #2", options(nomem, nostack)) };
            #[cfg(target_arch = "riscv64")]
            unsafe { asm!("csrsi sstatus, 2", options(nomem, nostack)) };
            say!("LEAK privileged instruction executed");
            exit(3)
        }
        3 => {
            say!("executing invalid instruction");
            // SAFETY：故意触发无效指令异常，预期在此处被终止。
            #[cfg(target_arch = "x86_64")]
            unsafe { asm!("ud2", options(nomem, nostack)) };
            #[cfg(target_arch = "aarch64")]
            unsafe { asm!("udf #0", options(nomem, nostack)) };
            #[cfg(target_arch = "riscv64")]
            unsafe { asm!("unimp", options(nomem, nostack)) };
            exit(3)
        }
        4 => {
            let r = sys(ids::SYSTEM_CONSOLE_WRITE, arg, 16);
            say!("bad_pointer result={}", r);
            exit(if r == INVALID_ADDRESS { 0 } else { 3 })
        }
        5 => {
            // SAFETY：只取地址。
            let top = unsafe { core::ptr::addr_of_mut!(SPIN_STACK) as u64 + 4096 };
            // SAFETY：entry 指向本程序代码，栈位于本进程可写内存。
            let t = unsafe { syscall3(ids::SYSTEM_TASK_SPAWN, spinner as usize as u64, top, 0) };
            say!("child spinner={} exiting", t > 0);
            sys(ids::SYSTEM_TIME_WAIT, 10, 0); // 让父进程先登记等待、让循环线程先跑起来
            sys(ids::SYSTEM_PROCESS_EXIT, 9, 0);
            exit(3) // 不应到达
        }
        7 => {
            let spawned = match arg {
                1 => {
                    let mut pair = [0u32; 2];
                    let r = sys(ids::SYSTEM_CHANNEL_CREATE, pair.as_mut_ptr() as u64, 0);
                    r == 0 && spawn_blocker(0, 1 | (pair[1] as u64) << 8) > 0
                }
                3 => {
                    // 第一个线程阻塞在 time.wait，第二个阻塞在等待第一个退出
                    let first = spawn_blocker(0, 0);
                    first > 0 && spawn_blocker(1, 3 | (first as u64) << 8) > 0
                }
                k => spawn_blocker(0, k) > 0,
            };
            say!("blocked variant={} spawned={} exiting", arg, spawned);
            sys(ids::SYSTEM_TIME_WAIT, 10, 0); // 让阻塞线程先进入内核等待
            sys(ids::SYSTEM_PROCESS_EXIT, if spawned { 7 } else { 6 }, 0);
            exit(3) // 不应到达
        }
        _ => {
            let ring = sys(ids::SYSTEM_ASYNC_RING_CREATE, 4, 0);
            let wait = Sqe { op: ids::SYSTEM_PROCESS_WAIT as u32, flags: 0, user_tag: 1, arg0: arg, arg1: 0 };
            let mut cq = [Cqe::default(); 4];
            let (a, first) = enter(ring, &[wait], &mut cq[..0], 0);
            let (b, second) = enter(ring, &[Sqe { user_tag: 2, ..wait }], &mut cq[..0], 0);
            let cancel = sys(ids::SYSTEM_ASYNC_CANCEL, ring as u64, first);
            // 关闭子进程句柄：已登记的 wait 持有退出状态，仍能取得退出码
            let closed = sys(ids::SYSTEM_HANDLE_CLOSE, arg, 0);
            let (r, _) = enter(ring, &[], &mut cq[..2], 2);
            let (mut cancelled, mut code) = (false, -1i64);
            for c in &cq[..r.reaped as usize] {
                if c.request_id == first {
                    cancelled = c.result == CANCELLED;
                }
                if c.request_id == second {
                    code = c.result;
                }
            }
            say!("parent submitted={} cancel={} handle_closed={} cancelled_wait={} exit_code={}", a.submitted + b.submitted, cancel, closed, cancelled, code);
            exit(if a.submitted == 1 && b.submitted == 1 && cancel == 0 && closed == 0 && cancelled && code == 9 { 0 } else { 4 })
        }
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    exit(101)
}
