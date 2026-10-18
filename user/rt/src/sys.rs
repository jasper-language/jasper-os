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

#[cfg(target_arch = "riscv32")]
mod imp {
    use core::arch::asm;

    /// 发起系统调用（RISC-V32 的 32 位用户 ABI：a7 = 调用号；每个 64 位参数拆成两半，低 32 位依次在 a0/a1/a2，
    /// 高 32 位依次在 a3/a4/a5；`ecall`；64 位返回值低半在 a0、高半在 a1，其余寄存器由内核保留）。
    /// 高半总是显式给出，因此时长、请求标识等完整 64 位的参数不会被截断。
    ///
    /// # Safety
    /// 参数必须符合该调用的约定：作为指针传入的值须指向本进程内、在调用期间有效的内存。
    #[inline]
    pub unsafe fn call3(id: u64, a: u64, b: u64, c: u64) -> i64 {
        let lo: u32;
        let hi: u32;
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

    /// 读取周期计数器（RISC-V32：`time` 计数器的高低两半，内核只允许用户态读取它）。先读高半、再读低半、
    /// 再读高半，两次高半不同说明低半在其间回绕，重读——保证得到一致的 64 位值。单调递增，频率固定。
    #[inline]
    pub fn cycles() -> u64 {
        loop {
            let (h1, lo, h2): (u32, u32, u32);
            // SAFETY：读计数器没有副作用。
            unsafe {
                asm!("rdtimeh {0}", "rdtime {1}", "rdtimeh {2}", out(reg) h1, out(reg) lo, out(reg) h2,
                     options(nomem, nostack, preserves_flags))
            };
            if h1 == h2 {
                return (h1 as u64) << 32 | lo as u64;
            }
        }
    }

    /// 本进程私有窗口的起点（RISC-V32 Sv32：顶级表项 1 起，即 `0x0040_0000`；窗口止于 `0x4000_0000`）。
    pub const WINDOW_BASE: u64 = kernel_core::user_layout::WINDOW_BASE_RISCV32;
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64", target_arch = "riscv32")))]
compile_error!("jasper-rt 目前只实现了 x86_64、AArch64、RISC-V64 与 RISC-V32 的系统调用与地址布局；其它指令集随内核移植加入");

pub use imp::{call3, cycles, WINDOW_BASE};

// 布局（相对私有窗口起点，各指令集相同）：用户程序映像 4 MiB 起；堆 64 MiB 起；主线程栈顶 336 MiB；
// 线程栈 352 MiB 起；模块 384 MiB 起到 896 MiB。整体落在最小的私有窗口（Sv32 的 1020 MiB）之内。

/// 堆区间：私有窗口起点 + 64 MiB 起，最多 256 MiB（实际可用量受进程帧配额限制）。
pub const HEAP_BASE: u64 = WINDOW_BASE + (64 << 20);
/// 堆区间的长度上限。
pub const HEAP_LIMIT: u64 = 256 << 20;
/// 主线程栈：私有窗口起点 + 336 MiB 处为栈顶，向下映射 [`MAIN_STACK_PAGES`] 页，其下未映射（保护区，也隔开堆的上限）。
/// 运行时启动时切换到这里，不依赖创建者给的初始栈有多大。
pub const MAIN_STACK_TOP: u64 = WINDOW_BASE + (336 << 20);
/// 主线程栈的页数（256 KiB）。
pub const MAIN_STACK_PAGES: u64 = 64;
/// 线程栈区间：私有窗口起点 + 352 MiB 起，每个槽位 [`STACK_STRIDE`] 字节，只映射顶部 [`STACK_PAGES`] 页（其下为未映射的保护区）。
pub const STACKS_BASE: u64 = WINDOW_BASE + (352 << 20);
/// 线程栈槽位间距。
pub const STACK_STRIDE: u64 = 0x4_0000;
/// 每个线程栈映射的页数（64 KiB）。
pub const STACK_PAGES: u64 = 16;
/// 线程栈槽位数（槽位占用位图是一个 32 位原子字：32 位指令集也有原生的 32 位原子操作）。
pub const STACK_SLOTS: u32 = 32;
/// 模块区间：私有窗口起点 + 384 MiB 起，每个槽位 [`MODULE_STRIDE`] 字节（= `.jaso` 映像大小上限），共 512 MiB。
pub const MODULES_BASE: u64 = WINDOW_BASE + (384 << 20);
/// 模块槽位间距（64 MiB）。
pub const MODULE_STRIDE: u64 = 64 << 20;
/// 模块槽位数。
pub const MODULE_SLOTS: u32 = 8;
/// 页大小。
pub const PAGE: u64 = 4096;
/// 布局可用的上限（不含）：各指令集中最小的私有窗口的末端。程序自选的固定地址也应落在它之下。
/// End of the usable layout: the end of the smallest private window over all ISAs.
pub const LAYOUT_END: u64 = WINDOW_BASE + kernel_core::user_layout::MIN_WINDOW_SIZE;

// 各区间互不重叠且依次排列；模块区间是最高的一段，必须落在最小的私有窗口之内，否则在该指令集上映射会被内核拒绝。
const _: () = assert!(WINDOW_BASE + kernel_core::user_layout::IMAGE_OFFSET < HEAP_BASE);
const _: () = assert!(HEAP_BASE + HEAP_LIMIT < MAIN_STACK_TOP - MAIN_STACK_PAGES * PAGE);
const _: () = assert!(MAIN_STACK_TOP <= STACKS_BASE);
const _: () = assert!(STACKS_BASE + STACK_SLOTS as u64 * STACK_STRIDE <= MODULES_BASE);
const _: () = assert!(MODULE_STRIDE == jaso::MAX_IMAGE as u64);
const _: () = assert!(MODULES_BASE + MODULE_SLOTS as u64 * MODULE_STRIDE <= LAYOUT_END);

/// 无指针参数的系统调用（安全封装：参数全是整数，内核自行校验）。
#[inline]
pub fn call(id: u64, a: u64, b: u64, c: u64) -> i64 {
    // SAFETY：调用者只传整数参数（不是指针），内核对其做完整校验，不会因此访问本进程内存。
    unsafe { call3(id, a, b, c) }
}
