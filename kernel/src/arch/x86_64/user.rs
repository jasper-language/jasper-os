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
//! 系统调用编号以 `const` 操作数取自生成的登记表常量，探针里不出现手写编号。

use core::arch::{asm, global_asm};
use core::cell::UnsafeCell;

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

/// Enters a freshly exec-replaced image with zeroed general registers.
/// 以清零的通用寄存器进入刚由 exec 替换的新映像。
pub unsafe fn enter_exec(entry: u64, stack: u64) -> ! {
    let sel = gdt::selectors();
    jsr_enter_exec(
        entry,
        stack,
        sel.user_code.0 as u64,
        sel.user_data.0 as u64,
    )
}

extern "C" {
    fn jsr_enter_exec(entry: u64, stack: u64, cs: u64, ss: u64) -> !;
}

global_asm!(
    r#"
    .global jsr_enter_exec
jsr_enter_exec:
    mov r8, rdi
    mov r9, rsi
    push rcx
    push r9
    push 0x202
    push rdx
    push r8
    xor eax, eax
    xor ebx, ebx
    xor ecx, ecx
    xor edx, edx
    xor esi, esi
    xor edi, edi
    xor ebp, ebp
    xor r8d, r8d
    xor r9d, r9d
    xor r10d, r10d
    xor r11d, r11d
    xor r12d, r12d
    xor r13d, r13d
    xor r14d, r14d
    xor r15d, r15d
    iretq
    "#
);

/// 进入克隆子线程：用户 RIP/栈取自 `clone`，`rax=0` 表示 syscall 子进程返回。
/// Enters a cloned child with `rax=0`, the Linux syscall child-return convention.
pub unsafe fn enter_syscall_return(
    entry: u64,
    stack: u64,
    preserved: [u64; 6],
    arg_regs: [u64; 6],
    clone_rdx: u64,
    clone_r8: u64,
) -> ! {
    let sel = gdt::selectors();
    let cs = sel.user_code.0 as u64;
    let ss = sel.user_data.0 as u64;
    let rflags: u64 = 0x202;
    let frame = SyscallReturnFrame {
        entry,
        stack,
        cs,
        ss,
        rflags,
        clone_rdx,
        clone_r8,
        preserved,
        arg_regs,
    };
    let _ = crate::arch::irq_save_disable();
    let scratch = &SYSCALL_RETURN_FRAMES[crate::arch::cpu_index()];
    // SAFETY: interrupts are disabled, so this CPU cannot re-enter the bounded
    // syscall-return frame before `iretq` transfers to user mode.
    unsafe { *scratch.0.get() = frame; }
    jsr_enter_syscall_return_regs(scratch.0.get())
}

#[derive(Clone, Copy)]
#[repr(C)]
struct SyscallReturnFrame {
    entry: u64,
    stack: u64,
    cs: u64,
    ss: u64,
    rflags: u64,
    clone_rdx: u64,
    clone_r8: u64,
    preserved: [u64; 6],
    arg_regs: [u64; 6],
}

impl SyscallReturnFrame {
    const ZERO: Self = Self {
        entry: 0,
        stack: 0,
        cs: 0,
        ss: 0,
        rflags: 0,
        clone_rdx: 0,
        clone_r8: 0,
        preserved: [0; 6],
        arg_regs: [0; 6],
    };
}

struct SyncFrame(UnsafeCell<SyscallReturnFrame>);
// SAFETY: each CPU owns exactly one array entry and interrupts are disabled
// across its write and non-returning `iretq` use.
unsafe impl Sync for SyncFrame {}

static SYSCALL_RETURN_FRAMES: [SyncFrame; kernel_core::smp::MAX_CPUS] =
    [const { SyncFrame(UnsafeCell::new(SyscallReturnFrame::ZERO)) }; kernel_core::smp::MAX_CPUS];

extern "C" {
    fn jsr_enter_syscall_return_regs(frame: *const SyscallReturnFrame) -> !;
}

global_asm!(
    r#"
    .global jsr_enter_syscall_return_regs
jsr_enter_syscall_return_regs:
    mov r9, rdi
    mov rbx, qword ptr [r9 + 56]
    mov rbp, qword ptr [r9 + 64]
    mov r12, qword ptr [r9 + 72]
    mov r13, qword ptr [r9 + 80]
    mov r14, qword ptr [r9 + 88]
    mov r15, qword ptr [r9 + 96]
    push qword ptr [r9 + 24]
    push qword ptr [r9 + 8]
    push qword ptr [r9 + 32]
    push qword ptr [r9 + 16]
    push qword ptr [r9]
    mov rdi, qword ptr [r9 + 104]
    mov rsi, qword ptr [r9 + 112]
    mov rdx, qword ptr [r9 + 120]
    mov r10, qword ptr [r9 + 128]
    mov r8, qword ptr [r9 + 136]
    mov r9, qword ptr [r9 + 144]
    xor eax, eax
    iretq
    "#
);

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

    .global jsr_probe_sys_start
    .global jsr_probe_sys_end
jsr_probe_sys_start:
    mov r12, 0x1234abcd
    mov rbx, rdi
    mov eax, {now}
    syscall
    mov [rbx], rax
    mov eax, 0xffff
    syscall
    mov [rbx + 8], rax
    mov eax, {yield_}
    syscall
    mov [rbx + 16], rax
    mov [rbx + 24], r12
    mov [rbx + 32], rbx
    mov edi, 42
    mov eax, {exit}
    syscall
    mov qword ptr [rbx + 40], 0xbad
    ud2
jsr_probe_sys_end:

    .global jsr_probe_ptr_start
    .global jsr_probe_ptr_end
jsr_probe_ptr_start:
    mov rbx, rdi
    mov r12, rsi
    lea rdi, [rbx + 0x100]
    mov rsi, [rbx + 0xf8]
    mov eax, {write}
    syscall
    mov [rbx], rax
    mov rdi, r12
    mov esi, 8
    mov eax, {write}
    syscall
    mov [rbx + 8], rax
    lea rdi, [rbx + 0x100000]
    mov esi, 8
    mov eax, {write}
    syscall
    mov [rbx + 16], rax
    lea rdi, [rbx + 0xffc]
    mov esi, 16
    mov eax, {write}
    syscall
    mov [rbx + 24], rax
    lea rdi, [rbx + 0x100]
    mov esi, 0x10000
    mov eax, {write}
    syscall
    mov [rbx + 32], rax
    lea rdi, [rbx + 0x200]
    mov esi, 2
    mov eax, {write}
    syscall
    mov [rbx + 40], rax
    xor edi, edi
    mov eax, {exit}
    syscall
    ud2
jsr_probe_ptr_end:

    .global jsr_probe_proc_start
    .global jsr_probe_proc_end
jsr_probe_proc_start:
    mov rbx, rdi
    mov r13, rsi
    lea rdi, [rip + jsr_proc_worker]
    mov rsi, r13
    mov rdx, rbx
    mov eax, {spawn}
    syscall
    mov [rbx], rax
    mov r14, rax
    mov r15, 10000
jsr_proc_wait:
    cmp qword ptr [rbx + 16], 1
    je jsr_proc_done
    mov eax, {yield_}
    syscall
    dec r15
    jnz jsr_proc_wait
jsr_proc_done:
    mov qword ptr [rbx + 24], 0x4d41494e
    mov rdi, r14
    mov eax, {close}
    syscall
    mov [rbx + 32], rax
    mov rdi, r14
    mov eax, {close}
    syscall
    mov [rbx + 40], rax
    mov edi, 7
    mov eax, {exit}
    syscall
    ud2
jsr_proc_worker:
    mov qword ptr [rdi + 8], 0x574f524b
    mov qword ptr [rdi + 16], 1
    xor edi, edi
    mov eax, {exit}
    syscall
    ud2
jsr_probe_proc_end:

    .global jsr_probe_rights_start
    .global jsr_probe_rights_end
jsr_probe_rights_start:
    mov rbx, rdi
    mov r13, rsi
    lea rdi, [rip + jsr_rights_worker]
    mov rsi, r13
    mov rdx, rbx
    mov eax, {spawn}
    syscall
    mov [rbx], rax
    mov r14, rax
    mov rdi, r14
    mov esi, {r_wait_dup}
    mov eax, {dup}
    syscall
    mov [rbx + 8], rax
    mov r15, rax
    mov rdi, r15
    mov esi, {r_wait_tr}
    mov eax, {dup}
    syscall
    mov [rbx + 16], rax
    mov rdi, r15
    mov esi, {r_wait}
    mov eax, {restrict}
    syscall
    mov [rbx + 24], rax
    mov rdi, r15
    mov esi, {r_wait}
    mov eax, {dup}
    syscall
    mov [rbx + 32], rax
    mov rdi, r15
    mov esi, {r_wait_ctl}
    mov eax, {restrict}
    syscall
    mov [rbx + 40], rax
    mov rdi, r15
    mov eax, {close}
    syscall
    mov rdi, r14
    mov eax, {close}
    syscall
    xor edi, edi
    mov eax, {exit}
    syscall
    ud2
jsr_rights_worker:
    xor edi, edi
    mov eax, {exit}
    syscall
    ud2
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
