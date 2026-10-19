//! RISC-V 用户态：进入用户态（`sret`）、内核栈顶记录与用户态探针程序。
//! RISC-V user mode: entering U-mode, the kernel-stack top and the user probe programs.
//!
//! # 进入用户态
//! 在当前任务的内核栈顶下构造一个全零的陷入帧（只填入口、用户栈、两个参数与 sstatus：SPP = 用户态、
//! SPIE = 1 即回到用户态后开中断、SUM = 0、浮点关闭），然后走与陷入返回相同的路径（`jsr_trap_return`）`sret`；
//! 返回路径顺带把 sscratch 置为该内核栈顶，之后每次从用户态陷入都从这里压帧。
//! 其余通用寄存器全部为 0：内核寄存器里的值不会泄漏给用户程序。这是单向的：回到内核只能经陷入。
//!
//! # 系统调用约定（RISC-V）
//! `a7` = 操作 ID，`ecall` 陷入。参数：RV64 依次为 `a0`–`a5`；RV32 最多 3 个 64 位参数，低 32 位在 `a0`–`a2`、
//! 高 32 位在 `a3`–`a5`（探针只用低半，高半寄存器从进入用户态起即为 0）；
//! 返回值为 64 位（非负 = 成功值，负数 = `-(错误码 ID)`）：RV64 在 `a0`，RV32 在 `a0`（低 32 位）+ `a1`（高 32 位）；
//! 其余寄存器全部保留。
//!
//! # 探针程序
//! 用汇编器生成机器码放在内核只读数据里，运行时**复制**到用户页再执行，因此只用与位置无关的指令
//! （跳转与取地址全部相对 pc，且关闭链接器松弛）。约定：`a0` = 用户数据页地址，`a1` = 参数。
//! 系统调用编号与权限位以 `const` 操作数取自生成的登记表常量，探针里不出现手写编号。
//! 数据页的结果槽一律 8 字节：探针经 `mode` 的汇编宏 `SD64`（零扩展存值）与 `SRET`（存 64 位返回值）写入，
//! 内核按 64 位读出，因此同一份探针源码在 RV32 与 RV64 上得到相同的结果布局。

use core::arch::{asm, global_asm};
use core::sync::atomic::{AtomicUsize, Ordering};

use super::cpu::{self, read_csr};
use super::mode::{xlen_asm_begin, xlen_asm_end};
use super::trap::{FRAME_BYTES, SEPC_OFF, SSTATUS_OFF, WB};
use crate::arch::UserProbe;
use kernel_core::smp::MAX_CPUS;

/// 每个处理器当前任务的内核栈顶（下标 = 逻辑下标；调度器每次切换任务时经 `set_kernel_stack` 更新本核一项）。
static KERNEL_STACK_TOP: [AtomicUsize; MAX_CPUS] = [const { AtomicUsize::new(0) }; MAX_CPUS];

/// 本处理器的内核栈顶记录。
fn this_cpu_top() -> &'static AtomicUsize {
    &KERNEL_STACK_TOP[super::smp::cpu_index().min(MAX_CPUS - 1)]
}

/// 记录本处理器当前任务的内核栈顶。
pub fn set_kernel_stack(top: u64) {
    this_cpu_top().store(top as usize, Ordering::Relaxed);
}

/// 本处理器登记的内核栈顶。
pub fn kernel_stack() -> u64 {
    this_cpu_top().load(Ordering::Relaxed) as u64
}

/// 进入用户态时的 sstatus：清 SPP（回到用户态）、SIE、SUM、FS，置 SPIE（回到用户态后开中断）。
fn user_sstatus() -> u64 {
    let s = read_csr!("sstatus");
    (s & !(cpu::SSTATUS_SPP | cpu::SSTATUS_SIE | cpu::SSTATUS_SUM | cpu::SSTATUS_FS)) | cpu::SSTATUS_SPIE
}

/// 进入用户态（永不返回）。
///
/// # Safety
/// 当前地址空间里 `entry` 必须映射为用户可执行、`stack` 之下必须映射为用户可写；
/// 当前任务的内核栈顶必须已经设置（调度器在切入任务时完成）。
pub unsafe fn enter(entry: u64, stack: u64, arg0: u64, arg1: u64) -> ! {
    let top = this_cpu_top().load(Ordering::Relaxed);
    assert!(top != 0 && top % 16 == 0, "进入用户态前未设置内核栈顶");
    let sstatus = user_sstatus() as usize;
    asm!(
        xlen_asm_begin!(),
        "csrci sstatus, {sie}",
        "mv sp, a5",
        "addi sp, sp, -{frame}",
        "mv t0, sp",
        "li t1, {words}",
        "1:",
        "SX zero, 0, t0",
        "addi t0, t0, {wb}",
        "addi t1, t1, -1",
        "bnez t1, 1b",
        "SX a0, 10*{wb}, sp",
        "SX a1, 11*{wb}, sp",
        "SX a2, 2*{wb}, sp",
        "SX a3, {sepc}, sp",
        "SX a4, {sstatus}, sp",
        xlen_asm_end!(),
        "j jsr_trap_return",
        sie = const cpu::SSTATUS_SIE,
        frame = const FRAME_BYTES,
        words = const FRAME_BYTES / WB,
        wb = const WB,
        sepc = const SEPC_OFF,
        sstatus = const SSTATUS_OFF,
        in("a0") arg0 as usize,
        in("a1") arg1 as usize,
        in("a2") stack as usize,
        in("a3") entry as usize,
        in("a4") sstatus,
        in("a5") top,
        options(noreturn)
    );
}

// 探针机器码（只读数据，不在内核态执行）。`.2byte 0` 是规定的非法指令（全零编码）。
global_asm!(
    xlen_asm_begin!(),
    r#"
    .section .rodata.jsr_user_probes, "a"
    .option push
    .option norelax
    .balign 4

    // 上报特权级：先写入「无特权」的值 3 与标记，再读 sstatus。用户态不可访问它 ⇒ 在此作为无效指令被终止，
    // [0] 保持 3；若在监管态运行则读出的 sstatus 覆盖 [0]（低两位不可能为 3），验收即失败。
    .global jsr_probe_cpl_start
    .global jsr_probe_cpl_end
jsr_probe_cpl_start:
    li t0, 3
    SD64 t0, 0, a0
    li t0, 0x55aa
    SD64 t0, 8, a0
    csrr t0, sstatus
    SD64 t0, 0, a0
    .2byte 0
jsr_probe_cpl_end:

    .balign 4
    .global jsr_probe_read_start
    .global jsr_probe_read_end
jsr_probe_read_start:
    LX t0, 0, a1
    SD64 t0, 0, a0
    li t0, 0x1eaf
    SD64 t0, 8, a0
    .2byte 0
jsr_probe_read_end:

    // 特权指令：用户态执行 wfi 被拒绝（非法指令异常，按特权指令归类为保护错误），之后的标记不得出现。
    .balign 4
    .global jsr_probe_priv_start
    .global jsr_probe_priv_end
jsr_probe_priv_start:
    li t0, 0x7e57
    SD64 t0, 8, a0
    wfi
    li t0, 0xbad
    SD64 t0, 16, a0
    .2byte 0
jsr_probe_priv_end:

    .balign 4
    .global jsr_probe_sys_start
    .global jsr_probe_sys_end
jsr_probe_sys_start:
    li s1, 0x1234abcd
    mv s2, a0
    li a7, {now}
    ecall
    SRET 0, s2
    li a7, 0xffff
    ecall
    SRET 8, s2
    li a7, {yield_}
    ecall
    SRET 16, s2
    SD64 s1, 24, s2
    SD64 s2, 32, s2
    li a0, 42
    li a7, {exit}
    ecall
    li t0, 0xbad
    SD64 t0, 40, s2
    .2byte 0
jsr_probe_sys_end:

    .balign 4
    .global jsr_probe_ptr_start
    .global jsr_probe_ptr_end
jsr_probe_ptr_start:
    mv s2, a0
    mv s3, a1
    li a7, {write}
    addi a0, s2, 0x100
    LX a1, 0xf8, s2
    ecall
    SRET 0, s2
    mv a0, s3
    li a1, 8
    ecall
    SRET 8, s2
    li t0, 0x100000
    add a0, s2, t0
    li a1, 8
    ecall
    SRET 16, s2
    li t0, 0xffc
    add a0, s2, t0
    li a1, 16
    ecall
    SRET 24, s2
    addi a0, s2, 0x100
    li a1, 0x10000
    ecall
    SRET 32, s2
    addi a0, s2, 0x200
    li a1, 2
    ecall
    SRET 40, s2
    li a0, 0
    li a7, {exit}
    ecall
    .2byte 0
jsr_probe_ptr_end:

    .balign 4
    .global jsr_probe_proc_start
    .global jsr_probe_proc_end
jsr_probe_proc_start:
    mv s2, a0
    mv s3, a1
    lla a0, jsr_rv_proc_worker
    mv a1, s3
    mv a2, s2
    li a7, {spawn}
    ecall
    SRET 0, s2
    mv s4, a0
    li s5, 10000
1:
    LX t0, 16, s2
    li t1, 1
    beq t0, t1, 2f
    li a7, {yield_}
    ecall
    addi s5, s5, -1
    bnez s5, 1b
2:
    li t0, 0x4d41494e
    SD64 t0, 24, s2
    mv a0, s4
    li a7, {close}
    ecall
    SRET 32, s2
    mv a0, s4
    ecall
    SRET 40, s2
    li a0, 7
    li a7, {exit}
    ecall
    .2byte 0
    .balign 4
jsr_rv_proc_worker:
    li t0, 0x574f524b
    SD64 t0, 8, a0
    li t0, 1
    SD64 t0, 16, a0
    li a0, 0
    li a7, {exit}
    ecall
    .2byte 0
jsr_probe_proc_end:

    .balign 4
    .global jsr_probe_rights_start
    .global jsr_probe_rights_end
jsr_probe_rights_start:
    mv s2, a0
    mv s3, a1
    lla a0, jsr_rv_rights_worker
    mv a1, s3
    mv a2, s2
    li a7, {spawn}
    ecall
    SRET 0, s2
    mv s4, a0
    mv a0, s4
    li a1, {r_wait_dup}
    li a7, {dup}
    ecall
    SRET 8, s2
    mv s5, a0
    mv a0, s5
    li a1, {r_wait_tr}
    li a7, {dup}
    ecall
    SRET 16, s2
    mv a0, s5
    li a1, {r_wait}
    li a7, {restrict}
    ecall
    SRET 24, s2
    mv a0, s5
    li a1, {r_wait}
    li a7, {dup}
    ecall
    SRET 32, s2
    mv a0, s5
    li a1, {r_wait_ctl}
    li a7, {restrict}
    ecall
    SRET 40, s2
    mv a0, s5
    li a7, {close}
    ecall
    mv a0, s4
    ecall
    li a0, 0
    li a7, {exit}
    ecall
    .2byte 0
    .balign 4
jsr_rv_rights_worker:
    li a0, 0
    li a7, {exit}
    ecall
    .2byte 0
jsr_probe_rights_end:
    .option pop
    .previous
    "#,
    xlen_asm_end!(),
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
