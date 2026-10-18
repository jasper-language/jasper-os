//! user-hello：jasper-os 上第一个由 ELF 装载的用户程序。
//! The first user program loaded from an ELF image on jasper-os.
//!
//! 做三件事：
//! 1. 检查 BSS（跨两页的零初始化数组）确实被装载器清零
//! 2. 经 `system.console.write` 输出一行中文问候与检查结果
//! 3. 经 `system.task.exit` 以退出码 0 结束（BSS 检查失败时退出码 3）
#![no_std]
#![no_main]

use core::arch::asm;

/// 系统调用号（构建期从登记表生成；只用到其中几个）。
#[allow(dead_code)]
mod ids {
    include!(concat!(env!("OUT_DIR"), "/ids.rs"));
}

/// 跨页的零初始化数组：放在 BSS，用于验证装载器清零了 `memsz > filesz` 的部分。
static mut ZEROED: [u8; 8192] = [0; 8192];

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

/// 输出一段 UTF-8 文本，返回内核写入的字节数（负数为错误码）。
fn write(text: &str) -> i64 {
    // SAFETY：text 位于本进程的只读数据或栈上。
    unsafe { syscall2(ids::SYSTEM_CONSOLE_WRITE, text.as_ptr() as u64, text.len() as u64) }
}

/// 以退出码结束本线程（不返回）。
fn exit(code: u64) -> ! {
    // SAFETY：task.exit 不访问用户内存。
    unsafe { syscall2(ids::SYSTEM_TASK_EXIT, code, 0) };
    loop {}
}

/// 程序入口（链接脚本把它放在代码段最前面）。
#[no_mangle]
#[link_section = ".text._start"]
pub extern "C" fn _start() -> ! {
    // 逐字节 volatile 读取：阻止编译器根据「从未写入」把检查常量折叠掉，必须真的读装载器清零的内存。
    // SAFETY：单线程程序，只读访问，下标在数组范围内。
    let bss_zero = unsafe {
        let base = core::ptr::addr_of!(ZEROED) as *const u8;
        (0..8192).all(|i| core::ptr::read_volatile(base.add(i)) == 0)
    };
    let n = write("你好，来自 ELF 装载的用户程序（user-hello）");
    write(if bss_zero { "bss_zero=true" } else { "bss_zero=false" });
    exit(if n > 0 && bss_zero { 0 } else { 3 })
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    exit(101)
}
