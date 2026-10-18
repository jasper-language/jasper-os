//! 程序启动与 panic 处理。
//! Program start-up and panic handling.
//!
//! 内核以 `(参数 0, 参数 1)` 进入 `_start`，此时栈顶按页对齐。`_start` 先把栈对齐到 16 字节再 call，
//! 使 Rust 代码看到的栈与「被正常调用」一致；`main` 返回后以其返回值终止整个进程。

use core::panic::PanicInfo;

use crate::task;

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

extern "C" {
    /// 由 [`crate::entry!`] 生成。
    fn __jsr_main(a: u64, b: u64) -> i32;
}

extern "C" fn rt_start(a: u64, b: u64) -> ! {
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
