//! Minimal unmodified-toolchain Linux x86_64 syscall-ABI probe.
//!
//! 这是没有 Jasper ABI 章的静态 Linux ET_EXEC fixture，用来证明兼容入口、
//! 参数复制、返回约定、权限拒绝和进程退出路径；不代表 libc/Wine 已完成。
//! This is a static Linux ET_EXEC fixture without Jasper ABI metadata.

#![no_std]
#![no_main]

use core::arch::asm;

const SYS_WRITE: u64 = 1;
const SYS_GETPID: u64 = 39;
const SYS_GETPPID: u64 = 110;
const SYS_GETTID: u64 = 186;
const SYS_EXIT_GROUP: u64 = 231;

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn syscall1(number: u64, arg0: u64) -> i64 {
    let result: i64;
    asm!(
        "syscall",
        inlateout("rax") number as i64 => result,
        in("rdi") arg0,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack)
    );
    result
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn syscall3(number: u64, arg0: u64, arg1: u64, arg2: u64) -> i64 {
    let result: i64;
    asm!(
        "syscall",
        inlateout("rax") number as i64 => result,
        in("rdi") arg0,
        in("rsi") arg1,
        in("rdx") arg2,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack)
    );
    result
}

#[cfg(target_arch = "x86_64")]
unsafe fn exit(code: u64) -> ! {
    syscall1(SYS_EXIT_GROUP, code);
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    const MESSAGE: &[u8] = b"linux-abi: fd1 raw x86_64 ET_EXEC entered\n";
    const STDERR_MESSAGE: &[u8] = b"linux-abi: fd2 raw bytes accepted\n";
    // SAFETY: static immutable bytes and fd 1/2 map to the compatibility console.
    let written = unsafe {
        syscall3(
            SYS_WRITE,
            1,
            MESSAGE.as_ptr() as u64,
            MESSAGE.len() as u64,
        )
    };
    if written != MESSAGE.len() as i64 {
        unsafe { exit(90) }
    }
    let written_err = unsafe {
        syscall3(
            SYS_WRITE,
            2,
            STDERR_MESSAGE.as_ptr() as u64,
            STDERR_MESSAGE.len() as u64,
        )
    };
    if written_err != STDERR_MESSAGE.len() as i64 {
        unsafe { exit(94) }
    }
    // Linux write(fd, invalid_ptr, 0) succeeds without dereferencing the pointer.
    let zero = unsafe { syscall3(SYS_WRITE, 1, 0, 0) };
    if zero != 0 {
        unsafe { exit(95) }
    }
    // Non-empty writes still require a readable user range and return -EFAULT.
    let fault = unsafe { syscall3(SYS_WRITE, 1, 0, 1) };
    if fault != -14 {
        unsafe { exit(96) }
    }
    // SAFETY: identity syscalls take no pointers.
    let pid = unsafe { syscall1(SYS_GETPID, 0) };
    let tid = unsafe { syscall1(SYS_GETTID, 0) };
    if pid <= 0 || tid <= 0 {
        unsafe { exit(91) }
    }
    // getppid is intentionally not granted in this first compatibility profile.
    let denied = unsafe { syscall1(SYS_GETPPID, 0) };
    if denied != -1 {
        unsafe { exit(92) }
    }
    unsafe { exit(0) }
}

#[cfg(not(target_arch = "x86_64"))]
#[panic_handler]
fn unsupported(_: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(target_arch = "x86_64")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { exit(93) }
}
