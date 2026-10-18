//! 系统调用指令（按指令集实现）与私有窗口内的地址布局。
//! The system-call instruction and the runtime's address layout, per ISA.
//!
//! 约定（与内核一致）：调用号与最多三个参数经寄存器传入；返回值非负 = 成功值，负数 = `-(错误 ID)`。

#[cfg(target_arch = "x86_64")]
mod imp {
    use core::arch::asm;

    /// 发起系统调用（x86_64：rax = 调用号，rdi/rsi/rdx = 参数；`syscall` 指令占用 rcx/r11）。
    ///
    /// # Safety
    /// 参数必须符合该调用的约定：作为指针传入的值须指向本进程内、在调用期间有效的内存。
    #[inline]
    pub unsafe fn call3(id: u64, a: u64, b: u64, c: u64) -> i64 {
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

    /// 读取周期计数器（x86_64：时间戳计数器，用户态可读）。单调递增，单位须由调用者自行校准。
    #[inline]
    pub fn cycles() -> u64 {
        // SAFETY：rdtsc 没有副作用；内核不禁止用户态读取它。
        unsafe { core::arch::x86_64::_rdtsc() }
    }

    /// 本进程私有窗口的起点（x86_64：顶级页表项 32 起，即 `0x1000_0000_0000`）。
    pub const WINDOW_BASE: u64 = kernel_core::user_layout::WINDOW_BASE_X86_64;
}

#[cfg(target_arch = "aarch64")]
mod imp {
    use core::arch::asm;

    /// 发起系统调用（AArch64：x8 = 调用号，x0/x1/x2 = 参数，`svc #0`；返回值在 x0，其余寄存器由内核保留）。
    ///
    /// # Safety
    /// 参数必须符合该调用的约定：作为指针传入的值须指向本进程内、在调用期间有效的内存。
    #[inline]
    pub unsafe fn call3(id: u64, a: u64, b: u64, c: u64) -> i64 {
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

    /// 读取周期计数器（AArch64：虚拟计数器 `cntvct_el0`，内核允许用户态读取）。单调递增，频率固定，
    /// 单位须由调用者自行校准。
    #[inline]
    pub fn cycles() -> u64 {
        let v: u64;
        // SAFETY：读虚拟计数器没有副作用；isb 保证读取不被提前到之前的指令之前。
        unsafe { asm!("isb", "mrs {}, cntvct_el0", out(reg) v, options(nomem, nostack, preserves_flags)) };
        v
    }

    /// 本进程私有窗口的起点（AArch64：TTBR0 顶级表项 32 起，与 x86_64 相同的 `0x1000_0000_0000`）。
    pub const WINDOW_BASE: u64 = kernel_core::user_layout::WINDOW_BASE_AARCH64;
}

#[cfg(target_arch = "riscv64")]
mod imp {
    use core::arch::asm;

    /// 发起系统调用（RISC-V：a7 = 调用号，a0/a1/a2 = 参数，`ecall`；返回值在 a0，其余寄存器由内核保留）。
    ///
    /// # Safety
    /// 参数必须符合该调用的约定：作为指针传入的值须指向本进程内、在调用期间有效的内存。
    #[inline]
    pub unsafe fn call3(id: u64, a: u64, b: u64, c: u64) -> i64 {
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

    /// 读取周期计数器（RISC-V：`time` 计数器，内核只允许用户态读取它）。单调递增，频率固定，
    /// 单位须由调用者自行校准。
    #[inline]
    pub fn cycles() -> u64 {
        let v: u64;
        // SAFETY：读计数器没有副作用。
        unsafe { asm!("rdtime {}", out(reg) v, options(nomem, nostack, preserves_flags)) };
        v
    }

    /// 本进程私有窗口的起点（RISC-V Sv39：顶级表项 32 起，即 `0x8_0000_0000`；窗口长 32 GiB）。
    pub const WINDOW_BASE: u64 = kernel_core::user_layout::WINDOW_BASE_RISCV64;
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64")))]
compile_error!("jasper-rt 目前只实现了 x86_64、AArch64 与 RISC-V64 的系统调用与地址布局；其它指令集随内核移植加入");

pub use imp::{call3, cycles, WINDOW_BASE};

/// 堆区间：私有窗口起点 + 4 GiB 起，最多 256 MiB（实际可用量受进程帧配额限制）。
pub const HEAP_BASE: u64 = WINDOW_BASE + 0x1_0000_0000;
/// 堆区间的长度上限。
pub const HEAP_LIMIT: u64 = 256 << 20;
/// 主线程栈：私有窗口起点 + 6 GiB 处为栈顶，向下映射 [`MAIN_STACK_PAGES`] 页，其下未映射（保护区）。
/// 运行时启动时切换到这里，不依赖创建者给的初始栈有多大。
pub const MAIN_STACK_TOP: u64 = WINDOW_BASE + 0x1_8000_0000;
/// 主线程栈的页数（256 KiB）。
pub const MAIN_STACK_PAGES: u64 = 64;
/// 线程栈区间：私有窗口起点 + 8 GiB 起，每个槽位 [`STACK_STRIDE`] 字节，只映射顶部 [`STACK_PAGES`] 页（其下为未映射的保护区）。
pub const STACKS_BASE: u64 = WINDOW_BASE + 0x2_0000_0000;
/// 线程栈槽位间距。
pub const STACK_STRIDE: u64 = 0x4_0000;
/// 每个线程栈映射的页数（64 KiB）。
pub const STACK_PAGES: u64 = 16;
/// 线程栈槽位数。
pub const STACK_SLOTS: u32 = 64;
/// 模块区间：私有窗口起点 + 24 GiB 起，每个槽位 [`MODULE_STRIDE`] 字节（= `.jaso` 映像大小上限），共 2 GiB。
/// 整个布局落在 32 GiB 之内——各指令集中最小的私有窗口（RISC-V Sv39）也装得下。
pub const MODULES_BASE: u64 = WINDOW_BASE + 0x6_0000_0000;
/// 模块槽位间距（64 MiB）。
pub const MODULE_STRIDE: u64 = 64 << 20;
/// 模块槽位数。
pub const MODULE_SLOTS: u32 = 32;
/// 页大小。
pub const PAGE: u64 = 4096;

// 整个布局（模块区间是最高的一段）必须落在最小的私有窗口之内，否则在该指令集上映射会被内核拒绝。
const _: () = assert!(MODULES_BASE + MODULE_SLOTS as u64 * MODULE_STRIDE - WINDOW_BASE <= kernel_core::user_layout::MIN_WINDOW_SIZE);

/// 无指针参数的系统调用（安全封装：参数全是整数，内核自行校验）。
#[inline]
pub fn call(id: u64, a: u64, b: u64, c: u64) -> i64 {
    // SAFETY：调用者只传整数参数（不是指针），内核对其做完整校验，不会因此访问本进程内存。
    unsafe { call3(id, a, b, c) }
}
