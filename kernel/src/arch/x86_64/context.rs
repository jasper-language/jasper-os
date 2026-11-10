//! x86_64 任务上下文与协作式切换汇编。
//!
//! `switch_context(old, new)`：把 x87/SSE 状态保存到任务控制块，把 callee-saved 寄存器
//! （rbp rbx r12–r15）压到**当前栈**，把栈指针存进 `old.rsp`，再恢复新任务的
//! FXSAVE 状态与栈指针、按相反顺序弹出并 `ret`。
//! 因为寄存器都压在各任务自己的栈上，上下文里真正需要持久化的只有 `rsp`。
//!
//! caller-saved 寄存器无需保存：`switch_context` 对调用者而言就是一次普通函数调用，
//! 编译器已在调用点处理它们；中断路径则由 `x86-interrupt` ABI 保存全部寄存器。

use core::arch::global_asm;

/// x86_64 任务上下文：保存 512 字节 FXSAVE 映像与栈指针。
///
/// x86_64 Linux 用户态依赖 SSE2；任务切换必须保存 XMM 寄存器，避免跨任务泄漏。
/// `fpu_state` 位于偏移 0 且上下文按 16 字节对齐，满足 FXSAVE/FXRSTOR 要求。
/// x86_64 task context with a 512-byte FXSAVE image and stack pointer. SSE2 is part of the
/// x86_64 Linux baseline, so user-visible XMM state must never leak across task switches.
#[repr(C, align(16))]
#[derive(Debug, Clone, Copy)]
pub struct TaskContext {
    /// FXSAVE/FXRSTOR 映像。 / FXSAVE/FXRSTOR image.
    pub fpu_state: [u8; 512],
    /// 切走时的栈指针。 / Stack pointer captured by `switch_context`.
    pub rsp: u64,
    /// IA32_FS_BASE，Linux x86_64 TLS 的线程指针基址。
    /// IA32_FS_BASE used by x86_64 Linux TLS.
    pub fs_base: u64,
}

impl TaskContext {
    /// 空上下文。
    pub const fn empty() -> Self {
        TaskContext {
            fpu_state: [0; 512],
            rsp: 0,
            fs_base: 0,
        }
    }
}

extern "C" {
    /// 保存当前执行流到 `old`，切到 `new`（实现见下方汇编）。
    pub fn switch_context(old: *mut TaskContext, new: *const TaskContext);
}

// rdi = old, rsi = new（System V 调用约定）。FPU 映像在偏移 0，rsp 在 512，
// FS_BASE 在 520。rax/rdx 是 caller-saved，可被 MSR 读写临时占用。
// 注意是 `mov rsp, [rsi]`（取 new.rsp 的值），不是 `mov rsp, rsi`（那是指针本身）——
// 后者正是 M1.3 之前骨架里的致命缺陷。
global_asm!(
    r#"
    .global switch_context
    switch_context:
        fxsave64 [rdi]
        mov  ecx, 0xc0000100
        rdmsr
        shl  rdx, 32
        or   rax, rdx
        mov  [rdi + 520], rax
        mov  rax, [rsi + 520]
        mov  rdx, rax
        shr  rdx, 32
        wrmsr
        push rbp
        push rbx
        push r12
        push r13
        push r14
        push r15
        mov  [rdi + 512], rsp
        fxrstor64 [rsi]
        mov  rsp, [rsi + 512]
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
    let mut context = TaskContext {
        fpu_state: [0; 512],
        rsp: frame as u64,
        fs_base: 0,
    };
    // FXSAVE: x87 control word at 0 and MXCSR at 24. Use the architectural defaults so a new
    // task cannot inherit another task's exception masks, stack pointers or SIMD registers.
    context.fpu_state[0..2].copy_from_slice(&0x037fu16.to_le_bytes());
    context.fpu_state[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
    context.fpu_state[28..32].copy_from_slice(&0xffffu32.to_le_bytes());
    context
}
