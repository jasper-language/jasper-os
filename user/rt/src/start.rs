//! 程序启动与 panic 处理。
//! Program start-up and panic handling.
//!
//! 内核以 `(参数 0, 参数 1)` 进入 `_start`，此时栈顶按页对齐。`_start` 先把栈对齐到 16 字节再 call，
//! 使 Rust 代码看到的栈与「被正常调用」一致。
//!
//! 创建者给的初始栈可能很小（常见 Rust 库的单次调用就可能用掉几十 KiB），所以运行时随即映射自己的主线程栈
//! （[`sys::MAIN_STACK_PAGES`] 页，其下为未映射的保护区）并切换过去，再调用 `main`；
//! `main` 返回后以其返回值终止整个进程。映射失败时输出原因并以 102 终止，不在小栈上冒险运行。

use core::panic::PanicInfo;

use crate::{mem, sys, task};

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".pushsection .text._start,\"ax\"",
    ".global _start",
    "_start:",
    "    and rsp, -16",
    "    call {start}",
    "    ud2",
    ".popsection",
    start = sym rt_start,
);

// AArch64：参数已在 x0/x1；sp 必须 16 字节对齐（页对齐的栈顶天然满足，这里仍显式对齐）。
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".pushsection .text._start,\"ax\"",
    ".global _start",
    "_start:",
    "    mov x9, sp",
    "    and sp, x9, #-16",
    "    bl {start}",
    "    udf #0",
    ".popsection",
    start = sym rt_start,
);

extern "C" {
    /// 由 [`crate::entry!`] 生成。
    fn __jsr_main(a: u64, b: u64) -> i32;
}

/// 主线程栈映射失败时的退出码。
pub const NO_STACK_CODE: u64 = 102;

extern "C" fn rt_start(a: u64, b: u64) -> ! {
    let base = sys::MAIN_STACK_TOP - sys::MAIN_STACK_PAGES * sys::PAGE;
    if let Err(e) = mem::map(base, sys::MAIN_STACK_PAGES, mem::WRITE) {
        crate::println!("rt: main stack map failed: {}", e);
        task::exit_process(NO_STACK_CODE)
    }
    // SAFETY：[base, MAIN_STACK_TOP) 刚映射为可写、只归主线程使用；栈顶 16 字节对齐，call 之后满足调用约定。
    // 旧栈此后不再使用（run_main 不返回）。
    unsafe { switch_stack(a, b) }
}

/// 切到主线程栈并调用 `run_main(a, b)`（不返回）。
///
/// # Safety
/// [`sys::MAIN_STACK_TOP`] 之下的主线程栈必须已映射为可写且只归主线程使用。
#[cfg(target_arch = "x86_64")]
unsafe fn switch_stack(a: u64, b: u64) -> ! {
    core::arch::asm!(
        "mov rsp, {top}",
        "call {main}",
        "ud2",
        top = in(reg) sys::MAIN_STACK_TOP,
        main = sym run_main,
        in("rdi") a,
        in("rsi") b,
        options(noreturn)
    )
}

/// 切到主线程栈并调用 `run_main(a, b)`（不返回）。
///
/// # Safety
/// [`sys::MAIN_STACK_TOP`] 之下的主线程栈必须已映射为可写且只归主线程使用。
#[cfg(target_arch = "aarch64")]
unsafe fn switch_stack(a: u64, b: u64) -> ! {
    core::arch::asm!(
        "mov sp, {top}",
        "bl {main}",
        "udf #0",
        top = in(reg) sys::MAIN_STACK_TOP,
        main = sym run_main,
        in("x0") a,
        in("x1") b,
        options(noreturn)
    )
}

extern "C" fn run_main(a: u64, b: u64) -> ! {
    // SAFETY：程序须用 entry! 声明入口；签名由该宏固定。
    let code = unsafe { __jsr_main(a, b) };
    task::exit_process(code as u32 as u64)
}

/// panic 时输出位置与信息，以退出码 101 终止整个进程。
#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    crate::println!("panic: {}", info);
    task::exit_process(101)
}
