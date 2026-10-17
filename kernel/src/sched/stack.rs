//! 内核栈池：为每个任务槽位提供一块静态、16 字节对齐的内核栈。
//!
//! 职责边界：只管「栈内存在哪」。新任务首次切入帧的形状属于 ISA 细节，
//! 由 `arch::init_task_frame` 负责（x86_64 见 `arch/x86_64/context.rs`）。
//!
//! 为什么用静态栈：此阶段还没有内核堆（M2.2 才有），静态栈放 `.bss`，由引导器清零并映射。

use core::ptr::addr_of_mut;

use crate::arch::TaskContext;

/// 单个任务内核栈大小。
pub const STACK_SIZE: usize = 16 * 1024;

/// 16 字节对齐的栈内存块（SysV ABI 要求）。
#[repr(C, align(16))]
pub struct Stack([u8; STACK_SIZE]);

impl Stack {
    /// 全零栈（供静态初始化）。
    pub const fn zeroed() -> Self {
        Stack([0; STACK_SIZE])
    }
}

/// 槽位数固定的静态栈池。
pub struct StackPool<const N: usize> {
    stacks: [Stack; N],
}

impl<const N: usize> StackPool<N> {
    /// 构造全零栈池（`const`，可放进 `static`）。
    pub const fn new() -> Self {
        StackPool { stacks: [const { Stack::zeroed() }; N] }
    }

    /// `slot` 的栈顶地址（中断从用户态进入内核时，CPU 切到这里；见 `arch::set_kernel_stack`）。
    pub fn top(&self, slot: usize) -> u64 {
        core::ptr::addr_of!(self.stacks[slot]) as u64 + STACK_SIZE as u64
    }

    /// 在 `slot` 的栈顶伪造首次切入帧，返回该任务的初始上下文。
    ///
    /// 帧的具体形状（压哪些寄存器、对齐方式）由 `arch::init_task_frame` 决定——
    /// 栈池只负责「栈在哪」，与 ISA 无关。
    ///
    /// # Safety
    /// 调用者保证该槽位此刻没有任务在其栈上运行。
    pub unsafe fn prepare_initial_frame(&mut self, slot: usize, entry: extern "C" fn() -> !) -> TaskContext {
        let base = addr_of_mut!(self.stacks[slot]) as *mut u8;
        crate::arch::init_task_frame(base.add(STACK_SIZE), entry)
    }
}
