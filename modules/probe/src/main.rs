//! jaso-probe：隔离边界的探测模块。
//! A probe module for testing the isolation boundary and quiescent unloading.
//!
//! 除 `jaso_bind` 外，导出一律遵守字节调用约定 `(输入, 输入长度, 输出, 输出容量) -> 输出长度或负的错误码`：
//!
//! | 导出 | 说明 |
//! |---|---|
//! | `jaso_bind(能力名, 长度, 句柄值)` | 记下宿主授予的句柄值（只接受 `system.task.wait` 名下的一个），返回 0 |
//! | `probe_sum` | 输出输入各字节之和（8 字节小端） |
//! | `probe_wait` | 经宿主接口表输出 `probe: waiting` 后返回 0（宿主可在回调里阻塞，制造「线程停在模块内」） |
//! | `probe_syscall` | 输入 4 个 `u64`（调用号与 3 个参数）：直接执行系统调用指令，输出返回值（8 字节） |
//! | `probe_bound` | 输出已绑定的句柄值（8 字节）；未绑定返回 -1 |
//! | `probe_poke` | 输入（地址, 值）：向该地址写入值并读回，输出读回值（地址不可写即故障） |
//! | `probe_spin` | 永不返回的忙循环（占满处理器） |
//!
//! 为什么要直接执行系统调用指令：隔离的意义在于「模块即使不守约定、自己发起系统调用」也越不过授权；
//! 只经宿主接口表做事的模块证明不了这一点。
#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU32, Ordering};

use jaso_module::log;

/// 已绑定的句柄值（0 = 未绑定）。
static BOUND: AtomicU32 = AtomicU32::new(0);

/// 原始系统调用（与运行时相同的寄存器约定；返回值非负 = 成功值，负数 = `-(错误 ID)`）。
#[cfg(target_arch = "x86_64")]
unsafe fn raw_call(id: u64, a: u64, b: u64, c: u64) -> i64 {
    let ret: i64;
    core::arch::asm!("syscall", inlateout("rax") id as i64 => ret, in("rdi") a, in("rsi") b, in("rdx") c,
                     lateout("rcx") _, lateout("r11") _, options(nostack));
    ret
}

#[cfg(target_arch = "aarch64")]
unsafe fn raw_call(id: u64, a: u64, b: u64, c: u64) -> i64 {
    let ret: i64;
    core::arch::asm!("svc #0", in("x8") id, inlateout("x0") a as i64 => ret, in("x1") b, in("x2") c, options(nostack));
    ret
}

#[cfg(target_arch = "riscv64")]
unsafe fn raw_call(id: u64, a: u64, b: u64, c: u64) -> i64 {
    let ret: i64;
    core::arch::asm!("ecall", in("a7") id, inlateout("a0") a as i64 => ret, in("a1") b, in("a2") c, options(nostack));
    ret
}

#[cfg(target_arch = "riscv32")]
unsafe fn raw_call(id: u64, a: u64, b: u64, c: u64) -> i64 {
    let lo: u32;
    let hi: u32;
    core::arch::asm!("ecall", in("a7") id as u32, inlateout("a0") a as u32 => lo, inlateout("a1") b as u32 => hi,
                     in("a2") c as u32, in("a3") (a >> 32) as u32, in("a4") (b >> 32) as u32, in("a5") (c >> 32) as u32,
                     options(nostack));
    ((hi as u64) << 32 | lo as u64) as i64
}

/// 读输入中第 `i` 个小端 `u64`。
unsafe fn word(input: *const u8, i: usize) -> u64 {
    let mut v = [0u8; 8];
    core::ptr::copy_nonoverlapping(input.add(i * 8), v.as_mut_ptr(), 8);
    u64::from_le_bytes(v)
}

/// 把 8 字节写到输出；容量不足返回 -1。
unsafe fn put8(out: *mut u8, cap: usize, v: u64) -> isize {
    if cap < 8 {
        return -1;
    }
    core::ptr::copy_nonoverlapping(v.to_le_bytes().as_ptr(), out, 8);
    8
}

/// 绑定宿主授予的句柄。
///
/// # Safety
/// `name` 可读 `len` 字节。
#[no_mangle]
pub unsafe extern "C" fn jaso_bind(name: *const u8, len: usize, handle: u32) -> i32 {
    let n = core::slice::from_raw_parts(name, len);
    if n != b"system.task.wait" || handle == 0 {
        return 1;
    }
    BOUND.store(handle, Ordering::Relaxed);
    0
}

/// 输入字节之和。
///
/// # Safety
/// 输入可读 `len` 字节；输出可写 `cap` 字节。
#[no_mangle]
pub unsafe extern "C" fn probe_sum(input: *const u8, len: usize, out: *mut u8, cap: usize) -> isize {
    let s = core::slice::from_raw_parts(input, len).iter().map(|&b| b as u64).sum();
    put8(out, cap, s)
}

/// 经宿主输出一行后返回 0。
///
/// # Safety
/// 无额外要求。
#[no_mangle]
pub unsafe extern "C" fn probe_wait(_input: *const u8, _len: usize, _out: *mut u8, _cap: usize) -> isize {
    log("probe: waiting");
    0
}

/// 原始系统调用。
///
/// # Safety
/// 输入可读 32 字节；输出可写 `cap` 字节。系统调用参数由调用者负责。
#[no_mangle]
pub unsafe extern "C" fn probe_syscall(input: *const u8, len: usize, out: *mut u8, cap: usize) -> isize {
    if len != 32 {
        return -1;
    }
    let r = raw_call(word(input, 0), word(input, 1), word(input, 2), word(input, 3));
    put8(out, cap, r as u64)
}

/// 已绑定的句柄值。
///
/// # Safety
/// 输出可写 `cap` 字节。
#[no_mangle]
pub unsafe extern "C" fn probe_bound(_input: *const u8, _len: usize, out: *mut u8, cap: usize) -> isize {
    match BOUND.load(Ordering::Relaxed) {
        0 => -1,
        h => put8(out, cap, h as u64),
    }
}

/// 向任意地址写入并读回。
///
/// # Safety
/// 输入可读 16 字节；目标地址不可写时触发故障（这正是它的用途）。
#[no_mangle]
pub unsafe extern "C" fn probe_poke(input: *const u8, len: usize, out: *mut u8, cap: usize) -> isize {
    if len != 16 {
        return -1;
    }
    let at = word(input, 0) as usize as *mut u64;
    at.write_volatile(word(input, 1));
    put8(out, cap, at.read_volatile())
}

/// 永不返回的忙循环。
///
/// # Safety
/// 无额外要求。
#[no_mangle]
pub unsafe extern "C" fn probe_spin(_input: *const u8, _len: usize, _out: *mut u8, _cap: usize) -> isize {
    loop {
        core::hint::spin_loop();
    }
}
