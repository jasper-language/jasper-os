//! LoongArch64 协作式任务上下文切换。
//!
//! 只保存 ABI 规定的 callee-saved 寄存器：`ra`、`fp`、`s0-s8`；其余寄存器由
//! 调用点或异常入口保存。内核使用 soft-float 目标，因此不保存浮点/向量状态。

use core::arch::global_asm;

/// 12 个 8 字节槽，保持 16 字节栈对齐。
const FRAME_BYTES: usize = 96;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TaskContext {
    pub sp: u64,
}

impl TaskContext {
    pub const fn empty() -> Self {
        Self { sp: 0 }
    }
}

extern "C" {
    pub fn switch_context(old: *mut TaskContext, new: *const TaskContext);
}

global_asm!(
    r#"
    .section .text.jsr_loongarch64_switch_context, "ax"
    .global switch_context
    .balign 4
switch_context:
    li.d   $t0, {frame_bytes}
    sub.d  $sp, $sp, $t0
    st.d   $ra, $sp, 0
    st.d   $fp, $sp, 8
    st.d   $s0, $sp, 16
    st.d   $s1, $sp, 24
    st.d   $s2, $sp, 32
    st.d   $s3, $sp, 40
    st.d   $s4, $sp, 48
    st.d   $s5, $sp, 56
    st.d   $s6, $sp, 64
    st.d   $s7, $sp, 72
    st.d   $s8, $sp, 80
    st.d   $sp, $a0, 0
    ld.d   $sp, $a1, 0
    ld.d   $ra, $sp, 0
    ld.d   $fp, $sp, 8
    ld.d   $s0, $sp, 16
    ld.d   $s1, $sp, 24
    ld.d   $s2, $sp, 32
    ld.d   $s3, $sp, 40
    ld.d   $s4, $sp, 48
    ld.d   $s5, $sp, 56
    ld.d   $s6, $sp, 64
    ld.d   $s7, $sp, 72
    ld.d   $s8, $sp, 80
    li.d   $t0, {frame_bytes}
    add.d  $sp, $sp, $t0
    jirl   $zero, $ra, 0
    .previous
    "#,
    frame_bytes = const FRAME_BYTES,
);

/// Prepare a first-entry frame whose return address is `entry`.
///
/// # Safety
/// `stack_top` must be 16-byte aligned and have at least [`FRAME_BYTES`] writable bytes below it.
pub unsafe fn init_task_frame(stack_top: *mut u8, entry: extern "C" fn() -> !) -> TaskContext {
    let frame = stack_top.sub(FRAME_BYTES) as *mut u64;
    core::ptr::write_bytes(frame, 0, FRAME_BYTES / 8);
    frame.write(entry as *const () as usize as u64);
    TaskContext { sp: frame as u64 }
}
