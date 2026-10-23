//! user-robust：S-1 系统调用健壮性回归程序。
//!
//! 目的：在真实用户态（独立页表、真实陷入路径）用**有界、固定种子**的参数组合反复调用系统接口，
//! 检查内核在大量非法或边界参数下仍然：
//! * 不崩溃、不把错误参数当成合法请求（由本程序的逐次返回值检查发现）；
//! * 不泄漏资源（由内核侧演练在进程回收后比较空闲页帧 / 对象 / 固定帧基线发现）。
//!
//! 设计边界：
//! * 固定 22 类探测，每类都只做一次系统调用，总计 [`TOTAL_CALLS`] 次；没有无界循环、没有后台线程、
//!   不调用会终止进程或永久阻塞的接口（`task.exit` / `process.exit` / 无限等待）。
//! * 句柄参数一律带第 32 位（超过 `u32`），内核必须按无效句柄拒绝，而不是截断成低 32 位。
//! * 指针与页区间只在专用 scratch 区或明确的窗口外地址上挑选；代码、初始栈与只读数据列入保护区，
//!   正确的内核即使照办合法请求也不会破坏本程序。
//! * 最后 32 次是真实的 `memory.map` → 写入 → `memory.unmap`，证明正常路径仍然可用且资源可回收。
//!
//! 这不是随机破坏工具：种子固定、调用次数固定、参数来源与预期结果都在本文件内写死，可完全复现。
#![no_std]
#![no_main]

use core::arch::asm;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::argcase::{AddressPlan, Prng, Span};
use kernel_core::ring_abi::{EnterArgs, MsgDesc};

/// 系统调用号（构建期从登记表生成）。
#[allow(dead_code)]
mod ids {
    include!(concat!(env!("OUT_DIR"), "/ids.rs"));
}

/// 页大小。
const PAGE: u64 = 4096;
/// 固定种子：同一构建在任何指令集上都走同一串参数。
const SEED: u64 = 0x5eed_2026_1018;
/// 有界调用次数（不包含收尾的输出与退出）。
const TOTAL_CALLS: u64 = 20_000;
/// 一个进程私有窗口的起点（按目标指令集取内核与运行时共用的常量）。
#[cfg(target_arch = "x86_64")]
const WINDOW_BASE: u64 = kernel_core::user_layout::WINDOW_BASE_X86_64;
#[cfg(target_arch = "aarch64")]
const WINDOW_BASE: u64 = kernel_core::user_layout::WINDOW_BASE_AARCH64;
#[cfg(target_arch = "riscv64")]
const WINDOW_BASE: u64 = kernel_core::user_layout::WINDOW_BASE_RISCV64;
#[cfg(target_arch = "riscv32")]
const WINDOW_BASE: u64 = kernel_core::user_layout::WINDOW_BASE_RISCV32;

/// 本程序固定装载地址（窗口起点 + 4 MiB）。
const IMAGE_BASE: u64 = WINDOW_BASE + kernel_core::user_layout::IMAGE_OFFSET;

/// 受保护区间：本程序的映像（留足 4 MiB）、内核为初始线程映射的栈及其下方一页保护区。
const PROTECTED: [Span; 2] = [
    Span::new(IMAGE_BASE, 4 << 20),
    Span::new(WINDOW_BASE + 0x00c0_0000 - 0x1_0000, 0x1_0000),
];
/// 专用目标区间：scratch 用于真实的 map/unmap 循环，hole 永远不映射、只用于验证拒绝路径。
const TARGETS: [Span; 2] = [
    Span::new(WINDOW_BASE + 0x3000_0000, 16 * PAGE),
    Span::new(WINDOW_BASE + 0x3100_0000, 16 * PAGE),
];
/// 真实 map/unmap 循环使用的地址（TARGETS[0] 的起点）。
const SCRATCH: u64 = TARGETS[0].start;
/// 只用于验证拒绝路径的未映射区间起点（TARGETS[1] 的起点）。
const HOLE: u64 = TARGETS[1].start;

/// 非 UTF-8 字节：`console.write` 必须先完整复制再校验，预计返回 `invalid_argument`。
static BAD_UTF8: [u8; 8] = [0xff; 8];

/// 累计检查数（每检查一个返回值加一）。
static CHECKS: AtomicU32 = AtomicU32::new(0);
/// 失败数。
static FAILED: AtomicU32 = AtomicU32::new(0);
/// 已打印的失败详情数（避免一次错误刷屏）。
static PRINTED: AtomicU32 = AtomicU32::new(0);

const ERR_UNSUPPORTED: i64 = -(ids::SYSTEM_ERROR_UNSUPPORTED as i64);
const ERR_RIGHTS_DENIED: i64 = -(ids::SYSTEM_ERROR_RIGHTS_DENIED as i64);
const ERR_INVALID_ARGUMENT: i64 = -(ids::SYSTEM_ERROR_INVALID_ARGUMENT as i64);
const ERR_INVALID_ADDRESS: i64 = -(ids::SYSTEM_MEMORY_ERROR_INVALID_ADDRESS as i64);
const ERR_HANDLE_INVALID: i64 = -(ids::SYSTEM_HANDLE_ERROR_INVALID as i64);

/// 发起系统调用（x86_64：rax=ID，rdi/rsi/rdx=参数，rcx/r11 被占用）。
///
/// # Safety
/// 参数必须符合该调用的约定；本程序只在明确的用户内存或窗口外地址上调用。
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

/// 发起系统调用（AArch64：x8=ID，x0/x1/x2=参数，`svc #0`）。
///
/// # Safety
/// 同 x86_64 版本。
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

/// 发起系统调用（RISC-V：a7=ID，a0/a1/a2=参数，`ecall`）。
///
/// # Safety
/// 同 x86_64 版本。
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

/// 发起一次系统调用；参数可以是整数、明确的用户内存地址或窗口外地址。
fn sys(id: u64, a: u64, b: u64, c: u64) -> i64 {
    // SAFETY：调用者只传整数、本进程内存地址或明确的窗口外地址；内核负责完整校验。
    unsafe { syscall3(id, a, b, c) }
}

/// 以退出码结束本线程（本程序只有主线程，因此也结束进程）。
fn exit(code: u64) -> ! {
    sys(ids::SYSTEM_TASK_EXIT, code, 0, 0);
    loop {
        core::hint::spin_loop();
    }
}

/// 输出一段 UTF-8 文本。
fn write(text: &str) -> i64 {
    sys(ids::SYSTEM_CONSOLE_WRITE, text.as_ptr() as u64, text.len() as u64, 0)
}

/// 栈上的定长格式化缓冲（避免堆分配）。
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

/// 输出一行带 `robust: ` 前缀的诊断文本。
macro_rules! say {
    ($($arg:tt)*) => {{
        let mut line = Line { buf: [0; 192], len: 0 };
        let _ = line.write_str("robust: ");
        let _ = write!(&mut line, $($arg)*);
        if let Ok(text) = core::str::from_utf8(&line.buf[..line.len]) {
            write(text);
        }
    }};
}

/// 记录一次失败（只打印前 16 条，避免错误参数导致串口刷屏）。
fn fail(label: &str, got: i64, want: i64) {
    FAILED.fetch_add(1, Ordering::Relaxed);
    if PRINTED.fetch_add(1, Ordering::Relaxed) < 16 {
        say!("FAIL {} got={} want={}", label, got, want);
    }
}

/// 检查返回值等于期望值。
fn expect(label: &str, got: i64, want: i64) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if got != want {
        fail(label, got, want);
    }
}

/// 检查返回值非负（成功路径）。
fn expect_nonneg(label: &str, got: i64) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if got < 0 {
        fail(label, got, 0);
    }
}

/// 生成一个一定超过 32 位的句柄值：内核必须整值判为无效，不能截断成低 32 位。
fn invalid_handle(rng: &mut Prng) -> u64 {
    (1u64 << 32) | rng.below(1 << 31)
}

/// 一个所有字段为零的合法消息描述：数据 / 句柄长度均为 0，因此不会解引用任何指针。
fn empty_desc() -> MsgDesc {
    MsgDesc::default()
}

/// 22 类有界探测之一。每类只发起一次系统调用并检查返回值。
fn probe(rng: &mut Prng, plan: &AddressPlan<'_>) {
    let h = invalid_handle(rng);
    match rng.below(22) {
        // 未登记的调用号：必须稳定返回 unsupported，而不是按低 32 位猜一个已登记操作。
        0 => {
            let id = rng.next_u64();
            expect("unknown.id", sys(id, rng.next_u64(), rng.next_u64(), rng.next_u64()), ERR_UNSUPPORTED);
        }
        // 无参数的成功路径。
        1 => expect_nonneg("time.now", sys(ids::SYSTEM_TIME_NOW, 0, 0, 0)),
        2 => expect("task.yield", sys(ids::SYSTEM_TASK_YIELD, 0, 0, 0), 0),
        // 句柄参数超过 32 位：四种句柄操作都必须报无效句柄（权限位非法时先报参数非法）。
        3 => expect("handle.close", sys(ids::SYSTEM_HANDLE_CLOSE, h, 0, 0), ERR_HANDLE_INVALID),
        4 => {
            let rights = if rng.chance(50) { 0 } else { 1u64 << 31 };
            let want = if rights == 0 { ERR_HANDLE_INVALID } else { ERR_INVALID_ARGUMENT };
            expect("handle.duplicate", sys(ids::SYSTEM_HANDLE_DUPLICATE, h, rights, 0), want);
        }
        5 => {
            let rights = if rng.chance(50) { 0 } else { 1u64 << 31 };
            let want = if rights == 0 { ERR_HANDLE_INVALID } else { ERR_INVALID_ARGUMENT };
            expect("handle.restrict", sys(ids::SYSTEM_HANDLE_RESTRICT, h, rights, 0), want);
        }
        // 等待类操作在无效句柄上必须立即失败，不能进入等待。
        6 => expect("task.wait", sys(ids::SYSTEM_TASK_WAIT, h, 0, 0), ERR_HANDLE_INVALID),
        7 => expect("process.wait", sys(ids::SYSTEM_PROCESS_WAIT, h, 0, 0), ERR_HANDLE_INVALID),
        // 异步环 / 通道：先给一个合法参数块，再让句柄解析失败；不会阻塞。
        8 => expect("async.cancel", sys(ids::SYSTEM_ASYNC_CANCEL, h, rng.next_u64(), 0), ERR_HANDLE_INVALID),
        9 => {
            let mut enter = EnterArgs::default();
            expect("ring.enter", sys(ids::SYSTEM_ASYNC_RING_ENTER, h, &mut enter as *mut _ as u64, 0), ERR_HANDLE_INVALID);
        }
        10 => {
            let mut desc = empty_desc();
            expect("channel.send", sys(ids::SYSTEM_CHANNEL_SEND, h, &mut desc as *mut _ as u64, 0), ERR_HANDLE_INVALID);
        }
        11 => {
            let mut desc = empty_desc();
            expect("channel.recv", sys(ids::SYSTEM_CHANNEL_RECV, h, &mut desc as *mut _ as u64, 0), ERR_HANDLE_INVALID);
        }
        // 控制台：窗口外指针必须报地址非法；合法内存里的非 UTF-8 字节必须报参数非法。
        12 => {
            let ptr = [WINDOW_BASE - 1, 0, u64::MAX - 8][rng.below(3) as usize];
            let len = 1 + rng.below(64);
            expect("console.bad_ptr", sys(ids::SYSTEM_CONSOLE_WRITE, ptr, len, 0), ERR_INVALID_ADDRESS);
        }
        13 => {
            let len = 1 + rng.below(BAD_UTF8.len() as u64);
            expect("console.bad_utf8", sys(ids::SYSTEM_CONSOLE_WRITE, BAD_UTF8.as_ptr() as u64, len, 0), ERR_INVALID_ARGUMENT);
        }
        // 内存：hole 永远未映射，unmap/protect 必须全有或全无地拒绝。
        14 => {
            let va = HOLE + rng.below(16) * PAGE;
            expect("memory.unmap_hole", sys(ids::SYSTEM_MEMORY_UNMAP, va, 1 + rng.below(3), 0), ERR_INVALID_ADDRESS);
        }
        15 => {
            let va = HOLE + rng.below(16) * PAGE;
            let (flags, want) = if rng.chance(25) { (3, ERR_INVALID_ARGUMENT) } else { (0, ERR_INVALID_ADDRESS) };
            expect("memory.protect_hole", sys(ids::SYSTEM_MEMORY_PROTECT, va, 1, flags), want);
        }
        16 => {
            let (va, pages, flags, want) = match rng.below(3) {
                0 => (HOLE + 1, 1, 0, ERR_INVALID_ADDRESS), // 未对齐
                1 => (HOLE, 0, 0, ERR_INVALID_ADDRESS),     // 零页
                _ => (HOLE, 1, 2, ERR_INVALID_ARGUMENT),    // 可执行位不被 map 接受
            };
            expect("memory.map_invalid", sys(ids::SYSTEM_MEMORY_MAP, va, pages, flags), want);
        }
        // QoS：未定义档位必须拒绝；已定义档位允许成功或按上限拒绝。
        17 => {
            let raw = rng.below(8);
            let got = sys(ids::SYSTEM_TASK_QOS_SET, raw, 0, 0);
            if raw > 3 {
                expect("task.qos.invalid", got, ERR_INVALID_ARGUMENT);
            } else {
                CHECKS.fetch_add(1, Ordering::Relaxed);
                if got != 0 && got != ERR_RIGHTS_DENIED {
                    fail("task.qos.defined", got, 0);
                }
            }
        }
        // 创建类接口的拒绝路径：不产生任何对象。
        18 => {
            let cap = if rng.chance(50) { 0 } else { u64::MAX };
            expect("ring.create_invalid", sys(ids::SYSTEM_ASYNC_RING_CREATE, cap, 0, 0), ERR_INVALID_ARGUMENT);
        }
        19 => expect("channel.create_invalid", sys(ids::SYSTEM_CHANNEL_CREATE, 0, 0, 0), ERR_INVALID_ADDRESS),
        // 线程创建：入口与栈都为 0，必须在分配任务槽之前被拒绝。
        20 => expect("task.spawn_invalid", sys(ids::SYSTEM_TASK_SPAWN, 0, 0, 0), ERR_INVALID_ADDRESS),
        // 等待：0 立即返回；u64::MAX 无法表示截止时刻，必须拒绝。
        _ => {
            let ticks = if rng.chance(50) { 0 } else { u64::MAX };
            let want = if ticks == 0 { 0 } else { ERR_INVALID_ARGUMENT };
            expect("time.wait", sys(ids::SYSTEM_TIME_WAIT, ticks, 0, 0), want);
        }
    }
    // 让编译器知道 plan 在签名里被使用；地址规划本身由下面的真实 map/unmap 循环使用。
    let _ = plan.page();
}

/// 真实路径：映射 scratch 一页、写一个字节、再取消映射。重复 32 次，证明正常路径未因加固而失效。
fn map_cycles(plan: &AddressPlan<'_>) {
    for _ in 0..32 {
        let r = sys(ids::SYSTEM_MEMORY_MAP, SCRATCH, 1, 1);
        expect("memory.map_scratch", r, 0);
        if r == 0 {
            // SAFETY：内核刚返回成功，SCRATCH 是本月进程内已映射、可写的一页；只写第一字节。
            unsafe { (SCRATCH as *mut u8).write_volatile(0x5a) };
            expect("memory.unmap_scratch", sys(ids::SYSTEM_MEMORY_UNMAP, SCRATCH, 1, 0), 0);
        }
    }
    // 规划器保证上面使用的区间不属于代码、初始栈等保护区。
    expect_nonneg("plan.pages", plan.page() as i64);
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    exit(101)
}

/// 程序入口（链接脚本把它放在代码段最前面）。
#[no_mangle]
#[link_section = ".text._start"]
pub extern "C" fn _start(packed: u64) -> ! {
    // Worker 0 preserves S-1. For S-2 the low 32 bits select the worker and the
    // high 32 bits carry that worker's probe count; zero keeps the default share.
    let worker = packed & 0xffff_ffff;
    let requested = packed >> 32;
    let (seed, total) = if worker == 0 { (SEED, TOTAL_CALLS) } else {
        match kernel_core::argcase::s2_seed(worker) {
            Some(seed) => {
                let total = if requested == 0 { kernel_core::argcase::S2_PROBES } else { requested };
                (seed, total)
            }
            None => exit(3),
        }
    };
    let plan = match AddressPlan::new(&PROTECTED, &TARGETS, PAGE) {
        Ok(p) => p,
        Err(_) => {
            say!("FAIL address_plan");
            exit(2);
        }
    };
    let mut rng = Prng::new(seed);
    for _ in 0..total {
        probe(&mut rng, &plan);
    }
    map_cycles(&plan);

    let checks = CHECKS.load(Ordering::Relaxed) as u64;
    let failed = FAILED.load(Ordering::Relaxed) as u64;
    say!("done calls={} checks={} failed={} seed={:#x}", total, checks, failed, seed);
    exit(if failed == 0 && checks >= total { 0 } else { 1 });
}
