//! AArch64 任务上下文与协作式切换汇编。
//! AArch64 task context and the cooperative switch routine.
//!
//! `switch_context(old, new)`：把 callee-saved 寄存器（x19–x28、帧指针 x29、返回地址 x30）压到**当前栈**，
//! 把栈指针存进 `old.sp`，再从 `new.sp` 取出新栈指针、恢复同一组寄存器并 `ret`。
//! 内核按软浮点目标编译，不使用浮点 / SIMD 寄存器，因此 d8–d15 无需保存。
//! caller-saved 寄存器由编译器在调用点处理；中断路径由异常入口保存完整寄存器帧（见 `vectors.rs`）。

use core::arch::global_asm;

/// 切换时压栈的字节数（12 个寄存器，保持 16 字节对齐）。
const FRAME_BYTES: usize = 96;

/// AArch64 任务上下文：只保存栈指针（其余 callee-saved 寄存器压在任务栈上）。
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TaskContext {
    /// 切走时的栈指针（汇编依赖它位于偏移 0）。
    pub sp: u64,
}

impl TaskContext {
    /// 空上下文。
    pub const fn empty() -> Self {
        TaskContext { sp: 0 }
    }
}

extern "C" {
    /// 保存当前执行流到 `old`，切到 `new`（实现见下方汇编）。
    pub fn switch_context(old: *mut TaskContext, new: *const TaskContext);
}

// x0 = old，x1 = new（AAPCS64）。栈上布局（自低向高）：x19 x20 … x28 x29 x30。
global_asm!(
    r#"
    .section .text.jsr_switch_context, "ax"
    .global switch_context
    .balign 4
switch_context:
    sub sp, sp, #{frame}
    stp x19, x20, [sp, #0]
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    stp x25, x26, [sp, #48]
    stp x27, x28, [sp, #64]
    stp x29, x30, [sp, #80]
    mov x9, sp
    str x9, [x0]
    ldr x9, [x1]
    mov sp, x9
    ldp x19, x20, [sp, #0]
    ldp x21, x22, [sp, #16]
    ldp x23, x24, [sp, #32]
    ldp x25, x26, [sp, #48]
    ldp x27, x28, [sp, #64]
    ldp x29, x30, [sp, #80]
    add sp, sp, #{frame}
    ret
    .previous
    "#,
    frame = const FRAME_BYTES,
);

/// 在栈顶伪造首次切入帧：12 个寄存器槽位全 0，只有 x30（返回地址）= `entry`。
/// `switch_context` 恢复后 `ret` 到 `entry`，此时栈指针回到 `stack_top`（16 字节对齐），x29 = 0 结束帧链。
///
/// # Safety
/// `stack_top` 必须 16 字节对齐，且其下至少 [`FRAME_BYTES`] 字节可写、此刻无人使用。
pub unsafe fn init_task_frame(stack_top: *mut u8, entry: extern "C" fn() -> !) -> TaskContext {
    let frame = stack_top.sub(FRAME_BYTES) as *mut u64;
    for i in 0..FRAME_BYTES / 8 {
        frame.add(i).write(0);
    }
    frame.add(11).write(entry as *const () as usize as u64);
    TaskContext { sp: frame as u64 }
}
