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

    /// 本进程私有窗口的起点（x86_64：顶级页表项 32 起，即 `0x1000_0000_0000`）。
    pub const WINDOW_BASE: u64 = 0x1000_0000_0000;
}

#[cfg(not(target_arch = "x86_64"))]
compile_error!("jasper-rt 目前只实现了 x86_64 的系统调用与地址布局；其它指令集随内核移植加入");

pub use imp::{call3, WINDOW_BASE};

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
/// 模块区间：私有窗口起点 + 32 GiB 起，每个槽位 [`MODULE_STRIDE`] 字节（= `.jaso` 映像大小上限）。
pub const MODULES_BASE: u64 = WINDOW_BASE + 0x8_0000_0000;
/// 模块槽位间距（64 MiB）。
pub const MODULE_STRIDE: u64 = 64 << 20;
/// 模块槽位数。
pub const MODULE_SLOTS: u32 = 32;
/// 页大小。
pub const PAGE: u64 = 4096;

/// 无指针参数的系统调用（安全封装：参数全是整数，内核自行校验）。
#[inline]
pub fn call(id: u64, a: u64, b: u64, c: u64) -> i64 {
    // SAFETY：调用者只传整数参数（不是指针），内核对其做完整校验，不会因此访问本进程内存。
    unsafe { call3(id, a, b, c) }
}
