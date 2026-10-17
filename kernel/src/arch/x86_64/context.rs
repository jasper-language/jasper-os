//! x86_64 任务上下文与协作式切换汇编。
//!
//! `switch_context(old, new)`：把 callee-saved 寄存器（rbp rbx r12–r15）压到**当前栈**，
//! 把栈指针存进 `old.rsp`，再从 `new.rsp` 取出新栈指针、按相反顺序弹出并 `ret`。
//! 因为寄存器都压在各任务自己的栈上，上下文里真正需要持久化的只有 `rsp`。
//!
//! caller-saved 寄存器无需保存：`switch_context` 对调用者而言就是一次普通函数调用，
//! 编译器已在调用点处理它们；中断路径则由 `x86-interrupt` ABI 保存全部寄存器。

use core::arch::global_asm;

/// x86_64 任务上下文：只保存栈指针（其余 callee-saved 寄存器压在任务栈上）。
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TaskContext {
    /// 切走时的栈指针（`switch_context` 依赖它是第一个字段，偏移 0）。
    pub rsp: u64,
}

impl TaskContext {
    /// 空上下文。
    pub const fn empty() -> Self {
        TaskContext { rsp: 0 }
    }
}

extern "C" {
    /// 保存当前执行流到 `old`，切到 `new`（实现见下方汇编）。
    pub fn switch_context(old: *mut TaskContext, new: *const TaskContext);
}

// rdi = old, rsi = new（System V 调用约定）。
// 注意是 `mov rsp, [rsi]`（取 new.rsp 的值），不是 `mov rsp, rsi`（那是指针本身）——
// 后者正是 M1.3 之前骨架里的致命缺陷。
global_asm!(
    r#"
    .global switch_context
    switch_context:
        push rbp
        push rbx
        push r12
        push r13
        push r14
        push r15
        mov  [rdi], rsp
        mov  rsp, [rsi]
        pop  r15
        pop  r14
        pop  r13
        pop  r12
        pop  rbx
        pop  rbp
        ret
    "#
);

/// 在栈顶伪造首次切入帧。
///
/// 帧布局（自低地址向高地址）：`r15 r14 r13 r12 rbx rbp`（全 0）| `entry` | `0`。
/// `switch_context` 弹出 6 个寄存器后 `ret` 到 `entry`；末尾的 0 充当 `entry` 的伪返回地址，
/// 使 `entry` 入口处 `rsp ≡ 8 (mod 16)`，与「被 call 进来」一致，满足 SysV ABI 的对齐要求。
///
/// # Safety
/// `stack_top` 必须 16 字节对齐，且其下至少 64 字节可写、此刻无人使用。
pub unsafe fn init_task_frame(stack_top: *mut u8, entry: extern "C" fn() -> !) -> TaskContext {
    let top = stack_top as *mut u64;
    let frame = top.sub(8);
    for i in 0..6 {
        frame.add(i).write(0);
    }
    frame.add(6).write(entry as *const () as usize as u64);
    frame.add(7).write(0);
    TaskContext { rsp: frame as u64 }
}
