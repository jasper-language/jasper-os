//! x86_64 用户态：进入 Ring 3（`iretq`）与用户态探针程序。
//!
//! # 进入用户态
//! 在当前内核栈上伪造一个中断返回帧（SS / RSP / RFLAGS / CS / RIP），执行 `iretq`，
//! CPU 即切到 CPL=3 从 `entry` 开始执行。RFLAGS 置 IF（用户态可被定时器中断）与保留位 1。
//! 这是单向的：回到内核只能经中断/异常（以及 M3.2 的 syscall）。
//!
//! # 探针程序（M3.1 验收用）
//! 用汇编器生成机器码放在内核的只读数据里，运行时**复制**到用户页再执行——
//! 不手写字节、也不在内核态执行它们。约定：`rdi` = 用户数据页地址，`rsi` = 参数。

use core::arch::{asm, global_asm};

use super::gdt;
use crate::arch::UserProbe;

/// 进入用户态（永不返回）。
///
/// # Safety
/// 当前地址空间里 `entry` 必须映射为用户可执行、`stack` 之下必须映射为用户可写；
/// 调用前 TSS.rsp0 必须已指向当前任务的内核栈顶。
pub unsafe fn enter(entry: u64, stack: u64, arg0: u64, arg1: u64) -> ! {
    let sel = gdt::selectors();
    let cs = sel.user_code.0 as u64;
    let ss = sel.user_data.0 as u64;
    let rflags: u64 = 0x202; // IF | 保留位 1
    asm!(
        "push {ss}",
        "push {stack}",
        "push {rflags}",
        "push {cs}",
        "push {entry}",
        "iretq",
        ss = in(reg) ss,
        stack = in(reg) stack,
        rflags = in(reg) rflags,
        cs = in(reg) cs,
        entry = in(reg) entry,
        in("rdi") arg0,
        in("rsi") arg1,
        options(noreturn)
    );
}

// 探针机器码（只读数据，不在内核态执行）。
global_asm!(
    r#"
    .section .rodata.jsr_user_probes, "a"
    .global jsr_probe_cpl_start
    .global jsr_probe_cpl_end
jsr_probe_cpl_start:
    mov ax, cs
    movzx eax, ax
    mov [rdi], rax
    mov qword ptr [rdi + 8], 0x55aa
    ud2
jsr_probe_cpl_end:

    .global jsr_probe_read_start
    .global jsr_probe_read_end
jsr_probe_read_start:
    mov rax, [rsi]
    mov [rdi], rax
    mov qword ptr [rdi + 8], 0x1eaf
    ud2
jsr_probe_read_end:

    .global jsr_probe_priv_start
    .global jsr_probe_priv_end
jsr_probe_priv_start:
    mov qword ptr [rdi + 8], 0x7e57
    hlt
    mov qword ptr [rdi + 16], 0xbad
    ud2
jsr_probe_priv_end:
    .previous
    "#
);

extern "C" {
    static jsr_probe_cpl_start: u8;
    static jsr_probe_cpl_end: u8;
    static jsr_probe_read_start: u8;
    static jsr_probe_read_end: u8;
    static jsr_probe_priv_start: u8;
    static jsr_probe_priv_end: u8;
}

/// 取某个探针的机器码。
pub fn probe(p: UserProbe) -> &'static [u8] {
    // SAFETY：符号由上面的 global_asm 定义，start ≤ end 且位于同一只读段。
    unsafe {
        let (s, e) = match p {
            UserProbe::ReportPrivilege => (&jsr_probe_cpl_start as *const u8, &jsr_probe_cpl_end as *const u8),
            UserProbe::ReadAddress => (&jsr_probe_read_start as *const u8, &jsr_probe_read_end as *const u8),
            UserProbe::Privileged => (&jsr_probe_priv_start as *const u8, &jsr_probe_priv_end as *const u8),
        };
        core::slice::from_raw_parts(s, e as usize - s as usize)
    }
}
