//! AArch64 用户态：进入 EL0（`eret`）、内核栈顶记录与用户态探针程序。
//! AArch64 user mode: entering EL0, the kernel-stack top and the user probe programs.
//!
//! # 进入用户态
//! 把 SP_EL1 置为当前任务的内核栈顶，在其下构造一个全零的陷入帧（只填入口、用户栈、两个参数，
//! SPSR = EL0t 且不屏蔽中断），然后走与异常返回相同的路径（`jsr_trap_return`）`eret`。
//! 其余通用寄存器全部为 0：内核寄存器里的值不会泄漏给用户程序。这是单向的：回到内核只能经异常或系统调用。
//!
//! # 系统调用约定（AArch64）
//! `x8` = 操作 ID，参数依次为 `x0`–`x5`，`svc #0` 陷入；返回值在 `x0`（非负 = 成功值，负数 = `-(错误码 ID)`）；
//! 其余寄存器全部保留。
//!
//! # 探针程序
//! 用汇编器生成机器码放在内核只读数据里，运行时**复制**到用户页再执行。约定：`x0` = 用户数据页地址，`x1` = 参数。
//! 系统调用编号与权限位以 `const` 操作数取自生成的登记表常量，探针里不出现手写编号。

use core::arch::{asm, global_asm};
use core::sync::atomic::{AtomicU64, Ordering};

use super::vectors::FRAME_BYTES;
use crate::arch::UserProbe;

/// 当前任务的内核栈顶（调度器每次切换任务时经 `set_kernel_stack` 更新）。
static KERNEL_STACK_TOP: AtomicU64 = AtomicU64::new(0);

/// 记录当前任务的内核栈顶。
pub fn set_kernel_stack(top: u64) {
    KERNEL_STACK_TOP.store(top, Ordering::Relaxed);
}

/// 进入用户态（永不返回）。
///
/// # Safety
/// 当前地址空间里 `entry` 必须映射为用户可执行、`stack` 之下必须映射为用户可写；
/// 当前任务的内核栈顶必须已经设置（调度器在切入任务时完成）。
pub unsafe fn enter(entry: u64, stack: u64, arg0: u64, arg1: u64) -> ! {
    let top = KERNEL_STACK_TOP.load(Ordering::Relaxed);
    assert!(top != 0 && top % 16 == 0, "进入用户态前未设置内核栈顶");
    asm!(
        "mov sp, x4",
        "sub sp, sp, #{frame}",
        "mov x9, sp",
        "mov x10, #{words}",
        "1:",
        "str xzr, [x9], #8",
        "subs x10, x10, #1",
        "b.ne 1b",
        "str x0, [sp, #0]",
        "str x1, [sp, #8]",
        "str x2, [sp, #248]",
        "str x3, [sp, #256]",
        "b jsr_trap_return",
        frame = const FRAME_BYTES,
        words = const FRAME_BYTES / 8,
        in("x0") arg0,
        in("x1") arg1,
        in("x2") stack,
        in("x3") entry,
        in("x4") top,
        options(noreturn)
    );
}

// 探针机器码（只读数据，不在内核态执行）。JSR_A64_MOVC 用 movz/movk 装入 32 位常量。
global_asm!(
    r#"
    .macro JSR_A64_MOVC reg, val
        movz \reg, #((\val) & 0xffff)
        movk \reg, #(((\val) >> 16) & 0xffff), lsl #16
    .endm

    .section .rodata.jsr_user_probes, "a"
    .balign 4

    // 上报特权级：先写入「无特权」的值 3 与标记，再读 CurrentEL。EL0 不可读它 ⇒ 在此作为无效指令被终止，
    // [0] 保持 3；若在 EL1 运行则读出 4 覆盖 [0]（低两位为 0），验收即失败。
    .global jsr_probe_cpl_start
    .global jsr_probe_cpl_end
jsr_probe_cpl_start:
    mov x2, #3
    str x2, [x0]
    JSR_A64_MOVC x2, 0x55aa
    str x2, [x0, #8]
    mrs x2, CurrentEL
    str x2, [x0]
    udf #0
jsr_probe_cpl_end:

    .global jsr_probe_read_start
    .global jsr_probe_read_end
jsr_probe_read_start:
    ldr x2, [x1]
    str x2, [x0]
    JSR_A64_MOVC x2, 0x1eaf
    str x2, [x0, #8]
    udf #0
jsr_probe_read_end:

    // 特权指令：EL0 执行 WFI 被捕获（SCTLR_EL1.nTWI = 0），之后的标记不得出现。
    .global jsr_probe_priv_start
    .global jsr_probe_priv_end
jsr_probe_priv_start:
    JSR_A64_MOVC x2, 0x7e57
    str x2, [x0, #8]
    wfi
    JSR_A64_MOVC x2, 0xbad
    str x2, [x0, #16]
    udf #0
jsr_probe_priv_end:

    .global jsr_probe_sys_start
    .global jsr_probe_sys_end
jsr_probe_sys_start:
    JSR_A64_MOVC x19, 0x1234abcd
    mov x20, x0
    JSR_A64_MOVC x8, {now}
    svc #0
    str x0, [x20]
    JSR_A64_MOVC x8, 0xffff
    svc #0
    str x0, [x20, #8]
    JSR_A64_MOVC x8, {yield_}
    svc #0
    str x0, [x20, #16]
    str x19, [x20, #24]
    str x20, [x20, #32]
    mov x0, #42
    JSR_A64_MOVC x8, {exit}
    svc #0
    JSR_A64_MOVC x2, 0xbad
    str x2, [x20, #40]
    udf #0
jsr_probe_sys_end:

    .global jsr_probe_ptr_start
    .global jsr_probe_ptr_end
jsr_probe_ptr_start:
    mov x20, x0
    mov x21, x1
    JSR_A64_MOVC x8, {write}
    add x0, x20, #0x100
    ldr x1, [x20, #0xf8]
    svc #0
    str x0, [x20]
    mov x0, x21
    mov x1, #8
    svc #0
    str x0, [x20, #8]
    add x0, x20, #0x100, lsl #12
    mov x1, #8
    svc #0
    str x0, [x20, #16]
    add x0, x20, #0xffc
    mov x1, #16
    svc #0
    str x0, [x20, #24]
    add x0, x20, #0x100
    mov x1, #0x10000
    svc #0
    str x0, [x20, #32]
    add x0, x20, #0x200
    mov x1, #2
    svc #0
    str x0, [x20, #40]
    mov x0, #0
    JSR_A64_MOVC x8, {exit}
    svc #0
    udf #0
jsr_probe_ptr_end:

    .global jsr_probe_proc_start
    .global jsr_probe_proc_end
jsr_probe_proc_start:
    mov x20, x0
    mov x21, x1
    adr x0, jsr_a64_proc_worker
    mov x1, x21
    mov x2, x20
    JSR_A64_MOVC x8, {spawn}
    svc #0
    str x0, [x20]
    mov x22, x0
    JSR_A64_MOVC x23, 10000
1:
    ldr x2, [x20, #16]
    cmp x2, #1
    b.eq 2f
    JSR_A64_MOVC x8, {yield_}
    svc #0
    subs x23, x23, #1
    b.ne 1b
2:
    JSR_A64_MOVC x2, 0x4d41494e
    str x2, [x20, #24]
    mov x0, x22
    JSR_A64_MOVC x8, {close}
    svc #0
    str x0, [x20, #32]
    mov x0, x22
    svc #0
    str x0, [x20, #40]
    mov x0, #7
    JSR_A64_MOVC x8, {exit}
    svc #0
    udf #0
jsr_a64_proc_worker:
    JSR_A64_MOVC x2, 0x574f524b
    str x2, [x0, #8]
    mov x2, #1
    str x2, [x0, #16]
    mov x0, #0
    JSR_A64_MOVC x8, {exit}
    svc #0
    udf #0
jsr_probe_proc_end:

    .global jsr_probe_rights_start
    .global jsr_probe_rights_end
jsr_probe_rights_start:
    mov x20, x0
    mov x21, x1
    adr x0, jsr_a64_rights_worker
    mov x1, x21
    mov x2, x20
    JSR_A64_MOVC x8, {spawn}
    svc #0
    str x0, [x20]
    mov x22, x0
    mov x0, x22
    JSR_A64_MOVC x1, {r_wait_dup}
    JSR_A64_MOVC x8, {dup}
    svc #0
    str x0, [x20, #8]
    mov x23, x0
    mov x0, x23
    JSR_A64_MOVC x1, {r_wait_tr}
    JSR_A64_MOVC x8, {dup}
    svc #0
    str x0, [x20, #16]
    mov x0, x23
    JSR_A64_MOVC x1, {r_wait}
    JSR_A64_MOVC x8, {restrict}
    svc #0
    str x0, [x20, #24]
    mov x0, x23
    JSR_A64_MOVC x1, {r_wait}
    JSR_A64_MOVC x8, {dup}
    svc #0
    str x0, [x20, #32]
    mov x0, x23
    JSR_A64_MOVC x1, {r_wait_ctl}
    JSR_A64_MOVC x8, {restrict}
    svc #0
    str x0, [x20, #40]
    mov x0, x23
    JSR_A64_MOVC x8, {close}
    svc #0
    mov x0, x22
    svc #0
    mov x0, #0
    JSR_A64_MOVC x8, {exit}
    svc #0
    udf #0
jsr_a64_rights_worker:
    mov x0, #0
    JSR_A64_MOVC x8, {exit}
    svc #0
    udf #0
jsr_probe_rights_end:
    .previous
    "#,
    now = const crate::syscall::table::SYSTEM_TIME_NOW,
    yield_ = const crate::syscall::table::SYSTEM_TASK_YIELD,
    exit = const crate::syscall::table::SYSTEM_TASK_EXIT,
    write = const crate::syscall::table::SYSTEM_CONSOLE_WRITE,
    spawn = const crate::syscall::table::SYSTEM_TASK_SPAWN,
    close = const crate::syscall::table::SYSTEM_HANDLE_CLOSE,
    dup = const crate::syscall::table::SYSTEM_HANDLE_DUPLICATE,
    restrict = const crate::syscall::table::SYSTEM_HANDLE_RESTRICT,
    r_wait = const kernel_core::object::Rights::WAIT.bits(),
    r_wait_dup = const kernel_core::object::Rights::WAIT.union(kernel_core::object::Rights::DUPLICATE).bits(),
    r_wait_tr = const kernel_core::object::Rights::WAIT.union(kernel_core::object::Rights::TRANSFER).bits(),
    r_wait_ctl = const kernel_core::object::Rights::WAIT.union(kernel_core::object::Rights::CONTROL).bits(),
);

extern "C" {
    static jsr_probe_cpl_start: u8;
    static jsr_probe_cpl_end: u8;
    static jsr_probe_read_start: u8;
    static jsr_probe_read_end: u8;
    static jsr_probe_priv_start: u8;
    static jsr_probe_priv_end: u8;
    static jsr_probe_sys_start: u8;
    static jsr_probe_sys_end: u8;
    static jsr_probe_ptr_start: u8;
    static jsr_probe_ptr_end: u8;
    static jsr_probe_proc_start: u8;
    static jsr_probe_proc_end: u8;
    static jsr_probe_rights_start: u8;
    static jsr_probe_rights_end: u8;
}

/// 取某个探针的机器码。
pub fn probe(p: UserProbe) -> &'static [u8] {
    // SAFETY：符号由上面的 global_asm 定义，start ≤ end 且位于同一只读段。
    unsafe {
        let (s, e) = match p {
            UserProbe::ReportPrivilege => (&jsr_probe_cpl_start as *const u8, &jsr_probe_cpl_end as *const u8),
            UserProbe::ReadAddress => (&jsr_probe_read_start as *const u8, &jsr_probe_read_end as *const u8),
            UserProbe::Privileged => (&jsr_probe_priv_start as *const u8, &jsr_probe_priv_end as *const u8),
            UserProbe::SyscallSmoke => (&jsr_probe_sys_start as *const u8, &jsr_probe_sys_end as *const u8),
            UserProbe::UserPointers => (&jsr_probe_ptr_start as *const u8, &jsr_probe_ptr_end as *const u8),
            UserProbe::ProcessThreads => (&jsr_probe_proc_start as *const u8, &jsr_probe_proc_end as *const u8),
            UserProbe::HandleRights => (&jsr_probe_rights_start as *const u8, &jsr_probe_rights_end as *const u8),
        };
        core::slice::from_raw_parts(s, e as usize - s as usize)
    }
}
