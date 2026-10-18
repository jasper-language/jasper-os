//! RISC-V 任务上下文与协作式切换汇编。
//! RISC-V task context and the cooperative switch routine.
//!
//! `switch_context(old, new)`：把 callee-saved 寄存器（返回地址 ra、s0–s11）压到**当前栈**，
//! 把栈指针存进 `old.sp`，再从 `new.sp` 取出新栈指针、恢复同一组寄存器并 `ret`。
//! 内核按软浮点目标编译且浮点单元关闭，不使用浮点寄存器，因此 fs0–fs11 无需保存。
//! caller-saved 寄存器由编译器在调用点处理；中断路径由陷入入口保存完整寄存器帧（见 `trap.rs`）。
//! 寄存器宽度（RV32 / RV64）经 `mode` 的汇编宏 `SX` / `LX` 与槽宽 `WB` 参数化，两种宽度共用同一段汇编。

use core::arch::global_asm;

use super::mode::{xlen_asm_begin, xlen_asm_end};

/// 一个寄存器槽的字节数（XLEN / 8）。
const WB: usize = core::mem::size_of::<usize>();
/// 切换时压栈的字节数（13 个寄存器，向上取整保持 16 字节对齐）。
const FRAME_BYTES: usize = (13 * WB + 15) & !15;

/// RISC-V 任务上下文：只保存栈指针（其余 callee-saved 寄存器压在任务栈上）。
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TaskContext {
    /// 切走时的栈指针（汇编依赖它位于偏移 0）。
    pub sp: usize,
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

// a0 = old，a1 = new。栈上布局（自低向高，每槽 WB 字节）：ra s0 s1 … s11。
global_asm!(
    xlen_asm_begin!(),
    r#"
    .section .text.jsr_switch_context, "ax"
    .global switch_context
    .balign 4
switch_context:
    addi sp, sp, -{frame}
    SX ra, 0*{wb}, sp
    SX s0, 1*{wb}, sp
    SX s1, 2*{wb}, sp
    SX s2, 3*{wb}, sp
    SX s3, 4*{wb}, sp
    SX s4, 5*{wb}, sp
    SX s5, 6*{wb}, sp
    SX s6, 7*{wb}, sp
    SX s7, 8*{wb}, sp
    SX s8, 9*{wb}, sp
    SX s9, 10*{wb}, sp
    SX s10, 11*{wb}, sp
    SX s11, 12*{wb}, sp
    SX sp, 0, a0
    LX sp, 0, a1
    LX ra, 0*{wb}, sp
    LX s0, 1*{wb}, sp
    LX s1, 2*{wb}, sp
    LX s2, 3*{wb}, sp
    LX s3, 4*{wb}, sp
    LX s4, 5*{wb}, sp
    LX s5, 6*{wb}, sp
    LX s6, 7*{wb}, sp
    LX s7, 8*{wb}, sp
    LX s8, 9*{wb}, sp
    LX s9, 10*{wb}, sp
    LX s10, 11*{wb}, sp
    LX s11, 12*{wb}, sp
    addi sp, sp, {frame}
    ret
    .previous
    "#,
    xlen_asm_end!(),
    frame = const FRAME_BYTES,
    wb = const WB,
);

/// 在栈顶伪造首次切入帧：寄存器槽位全 0，只有 ra（返回地址）= `entry`。
/// `switch_context` 恢复后 `ret` 到 `entry`，此时栈指针回到 `stack_top`（16 字节对齐），s0 = 0 结束帧链。
///
/// # Safety
/// `stack_top` 必须 16 字节对齐，且其下至少 [`FRAME_BYTES`] 字节可写、此刻无人使用。
pub unsafe fn init_task_frame(stack_top: *mut u8, entry: extern "C" fn() -> !) -> TaskContext {
    let frame = stack_top.sub(FRAME_BYTES) as *mut usize;
    for i in 0..FRAME_BYTES / WB {
        frame.add(i).write(0);
    }
    frame.write(entry as *const () as usize);
    TaskContext { sp: frame as usize }
}
