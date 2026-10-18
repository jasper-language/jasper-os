//! RISC-V 任务上下文与协作式切换汇编。
//! RISC-V task context and the cooperative switch routine.
//!
//! `switch_context(old, new)`：把 callee-saved 寄存器（返回地址 ra、s0–s11）压到**当前栈**，
//! 把栈指针存进 `old.sp`，再从 `new.sp` 取出新栈指针、恢复同一组寄存器并 `ret`。
//! 内核按软浮点目标编译且浮点单元关闭，不使用浮点寄存器，因此 fs0–fs11 无需保存。
//! caller-saved 寄存器由编译器在调用点处理；中断路径由陷入入口保存完整寄存器帧（见 `trap.rs`）。

use core::arch::global_asm;

/// 切换时压栈的字节数（13 个寄存器，向上取整保持 16 字节对齐）。
const FRAME_BYTES: usize = 112;

/// RISC-V 任务上下文：只保存栈指针（其余 callee-saved 寄存器压在任务栈上）。
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

// a0 = old，a1 = new。栈上布局（自低向高）：ra s0 s1 … s11。
global_asm!(
    r#"
    .section .text.jsr_switch_context, "ax"
    .global switch_context
    .balign 4
switch_context:
    addi sp, sp, -{frame}
    sd ra, 0(sp)
    sd s0, 8(sp)
    sd s1, 16(sp)
    sd s2, 24(sp)
    sd s3, 32(sp)
    sd s4, 40(sp)
    sd s5, 48(sp)
    sd s6, 56(sp)
    sd s7, 64(sp)
    sd s8, 72(sp)
    sd s9, 80(sp)
    sd s10, 88(sp)
    sd s11, 96(sp)
    sd sp, 0(a0)
    ld sp, 0(a1)
    ld ra, 0(sp)
    ld s0, 8(sp)
    ld s1, 16(sp)
    ld s2, 24(sp)
    ld s3, 32(sp)
    ld s4, 40(sp)
    ld s5, 48(sp)
    ld s6, 56(sp)
    ld s7, 64(sp)
    ld s8, 72(sp)
    ld s9, 80(sp)
    ld s10, 88(sp)
    ld s11, 96(sp)
    addi sp, sp, {frame}
    ret
    .previous
    "#,
    frame = const FRAME_BYTES,
);

/// 在栈顶伪造首次切入帧：寄存器槽位全 0，只有 ra（返回地址）= `entry`。
/// `switch_context` 恢复后 `ret` 到 `entry`，此时栈指针回到 `stack_top`（16 字节对齐），s0 = 0 结束帧链。
///
/// # Safety
/// `stack_top` 必须 16 字节对齐，且其下至少 [`FRAME_BYTES`] 字节可写、此刻无人使用。
pub unsafe fn init_task_frame(stack_top: *mut u8, entry: extern "C" fn() -> !) -> TaskContext {
    let frame = stack_top.sub(FRAME_BYTES) as *mut u64;
    for i in 0..FRAME_BYTES / 8 {
        frame.add(i).write(0);
    }
    frame.write(entry as *const () as usize as u64);
    TaskContext { sp: frame as u64 }
}
