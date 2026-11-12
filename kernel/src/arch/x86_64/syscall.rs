//! x86_64 系统调用入口：`syscall` / `sysretq`。
//! x86_64 system-call entry via `syscall` / `sysretq`.
//!
//! # 寄存器约定（Jasper 系统调用 ABI，x86_64）
//! * `rax` = 操作 ID；参数依次为 `rdi rsi rdx r10 r8 r9`
//! * 返回值在 `rax`（非负 = 成功值，负数 = `-(错误码 ID)`）
//! * `rcx`、`r11` 被硬件占用（返回地址与标志位），调用后不保留；其余寄存器全部保留
//!
//! # 入口流程
//! `syscall` 不切栈：入口用 `swapgs` 换到本处理器的入口块（IA32_KERNEL_GS_BASE 指向它，每核一份），
//! 把用户栈指针存进块内暂存位、换到块内登记的当前任务内核栈、把用户栈指针压栈，再 `swapgs` 换回——
//! GS 只在这几条指令的窗口里指向内核，其余时间（包括中断与异常入口）始终是用户的 GS，因此中断入口不需要 `swapgs`。
//! 然后把寄存器压成 [`RawFrame`]，调用 Rust 分发，再按相反顺序恢复并 `sysretq`。
//! SFMASK 清 IF/DF/TF：窗口期间关中断，暂存位只被本处理器使用，多处理器下互不干扰。
//!
//! # 安全细节
//! `sysretq` 遇到非规范的返回地址会在**内核态**触发 #GP（Intel 已知问题）。因此返回前检查
//! 用户 RIP 是否规范；不规范则按用户故障终止该任务，绝不执行这条 `sysretq`。

use core::arch::global_asm;
use core::sync::atomic::{AtomicU64, Ordering};

use kernel_core::smp::MAX_CPUS;

use x86_64::registers::model_specific::{Efer, EferFlags, Msr};

use crate::fault::{self, UserFault, UserFaultKind};
use crate::syscall::{self, SyscallArgs, XSAVE_BYTES};

/// 每核系统调用入口块（字段偏移必须与下方汇编一致）。
#[repr(C, align(64))]
struct EntryBlock {
    /// 偏移 0：当前任务的内核栈顶（调度器每次切换任务时经 `set_kernel_stack` 更新，与本核 TSS.rsp0 相同）。
    kstack: AtomicU64,
    /// 偏移 8：用户栈指针暂存位（只在入口窗口内、关中断时使用）。
    user_rsp: AtomicU64,
    /// 偏移 16：返回 RIP 暂存位，只用于 FXSAVE 帧恢复后换回用户栈。
    return_rip: AtomicU64,
    /// 偏移 24：该 CPU 是否启用了 AVX 所需的 XSAVE/XCR0。
    xsave: AtomicU64,
    /// 偏移 32：设置 XSAVE 状态掩码时暂存的用户 RAX。
    scratch_rax: AtomicU64,
    /// 偏移 40：设置 XSAVE 状态掩码时暂存的用户 RDX。
    scratch_rdx: AtomicU64,
}

/// 全部处理器的入口块（下标 = 逻辑下标）。
static BLOCKS: [EntryBlock; MAX_CPUS] =
    [const {
        EntryBlock {
            kstack: AtomicU64::new(0),
            user_rsp: AtomicU64::new(0),
            return_rip: AtomicU64::new(0),
            xsave: AtomicU64::new(0),
            scratch_rax: AtomicU64::new(0),
            scratch_rdx: AtomicU64::new(0),
        }
    }; MAX_CPUS];

/// 入口压栈后的寄存器帧（自低地址向高地址，顺序必须与下方汇编一致）。
#[repr(C)]
pub struct RawFrame {
    rbx: u64,
    rbp: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rax: u64,
    rdi: u64,
    rsi: u64,
    rdx: u64,
    r10: u64,
    r8: u64,
    r9: u64,
    r11: u64,
    rcx: u64,
    user_rsp: u64,
    fxstate: [u8; XSAVE_BYTES],
}

const MSR_STAR: u32 = 0xC000_0081;
const MSR_LSTAR: u32 = 0xC000_0082;
const MSR_SFMASK: u32 = 0xC000_0084;
const MSR_KERNEL_GS_BASE: u32 = 0xC000_0102;

extern "C" {
    fn jsr_syscall_entry();
}

global_asm!(
    r#"
    .global jsr_syscall_entry
jsr_syscall_entry:
    swapgs
    mov qword ptr gs:[8], rsp
    mov rsp, qword ptr gs:[0]
    sub rsp, {xsave_bytes}
    and rsp, -64
    cmp qword ptr gs:[24], 0
    je 1f
    mov qword ptr gs:[32], rax
    mov qword ptr gs:[40], rdx
    // XSAVE preserves XSTATE_BV bits outside the requested mask.  Clear the
    // standard header so stale kernel-stack data cannot poison XRSTOR.
    // XSAVE 会保留请求掩码之外的 XSTATE_BV 位；先清零标准头部，避免复用的
    // 内核栈旧数据使 XRSTOR 拒绝恢复。
    mov qword ptr [rsp + 512], 0
    mov qword ptr [rsp + 520], 0
    mov qword ptr [rsp + 528], 0
    mov eax, 7
    xor edx, edx
    xsave64 [rsp]
    mov rax, qword ptr gs:[32]
    mov rdx, qword ptr gs:[40]
    jmp 2f
1:
    fxsave64 [rsp]
2:
    push qword ptr gs:[8]
    swapgs
    push rcx
    push r11
    push r9
    push r8
    push r10
    push rdx
    push rsi
    push rdi
    push rax
    push r15
    push r14
    push r13
    push r12
    push rbp
    push rbx
    mov rdi, rsp
    call jsr_syscall_dispatch
    pop rbx
    pop rbp
    pop r12
    pop r13
    pop r14
    pop r15
    mov rax, qword ptr [rsp]
    add rsp, 8
    pop rdi
    pop rsi
    pop rdx
    pop r10
    pop r8
    pop r9
    pop r11
    pop rcx
    swapgs
    mov qword ptr gs:[16], rcx
    cmp qword ptr gs:[24], 0
    je 3f
    mov qword ptr gs:[32], rax
    mov qword ptr gs:[40], rdx
    mov eax, 7
    xor edx, edx
    xrstor64 [rsp + 8]
    mov rax, qword ptr gs:[32]
    mov rdx, qword ptr gs:[40]
    jmp 4f
3:
    fxrstor64 [rsp + 8]
4:
    mov rcx, qword ptr [rsp]
    mov rsp, rcx
    mov rcx, qword ptr gs:[16]
    swapgs
    sysretq
    "#,
    xsave_bytes = const XSAVE_BYTES,
);

/// 汇编入口调用的 Rust 分发桥：整理参数 → Core 分发 → 返回前做 RIP 规范性检查。
#[no_mangle]
extern "C" fn jsr_syscall_dispatch(frame: &mut RawFrame) -> u64 {
    let args = SyscallArgs {
        id: frame.rax,
        args: [frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9],
        user_ip: Some((frame.rcx, frame.user_rsp)),
        user_preserved: [frame.rbx, frame.rbp, frame.r12, frame.r13, frame.r14, frame.r15],
        fxstate: Some(&mut frame.fxstate),
    };
    let outcome = syscall::on_entry(&args);
    frame.rax = outcome.value as u64;
    if let Some(user) = outcome.redirect {
        frame.rax = user.rax;
        frame.rdi = user.rdi;
        frame.rsi = user.rsi;
        frame.rdx = user.rdx;
        frame.r10 = user.r10;
        frame.r8 = user.r8;
        frame.r9 = user.r9;
        frame.r11 = user.r11;
        frame.rcx = user.rcx;
        frame.user_rsp = user.user_rsp;
    }
    if let Some(exec) = outcome.exec_redirect {
        frame.rax = 0;
        frame.rdi = 0;
        frame.rsi = 0;
        frame.rdx = 0;
        frame.r10 = 0;
        frame.r8 = 0;
        frame.r9 = 0;
        frame.rbx = 0;
        frame.rbp = 0;
        frame.r12 = 0;
        frame.r13 = 0;
        frame.r14 = 0;
        frame.r15 = 0;
        frame.r11 = 0x202;
        frame.rcx = exec.entry;
        frame.user_rsp = exec.user_rsp;
    }
    let rip = frame.rcx;
    if ((rip << 16) as i64 >> 16) as u64 != rip {
        fault::on_user_fault(UserFault { kind: UserFaultKind::ProtectionFault, ip: rip, addr: 0 });
    }
    outcome.value as u64
}

/// 在本处理器上启用 `syscall` 指令、设置入口，并让 IA32_KERNEL_GS_BASE 指向逻辑下标为 `index` 的入口块
/// （需在 GDT 加载之后调用；每个处理器各调用一次）。
///
/// STAR：进入时 CS = 内核代码段（0x08），SS = 其后的内核数据段；
/// 返回时 CS = 基址 0x10 + 16 = 用户代码段（0x20|3），SS = 0x10 + 8 = 用户数据段（0x18|3）。
/// 这正是 gdt.rs 中「用户数据段排在用户代码段之前」的原因。
pub fn init(index: usize, xsave: bool) {
    let block_ref = &BLOCKS[index.min(MAX_CPUS - 1)];
    block_ref.xsave.store(u64::from(xsave), Ordering::Relaxed);
    let block = block_ref as *const EntryBlock as u64;
    let sel = super::gdt::selectors();
    let kernel_cs = sel.kernel_code.0 as u64;
    let sysret_base = (sel.user_data.0 as u64 & !3) - 8;
    // SAFETY：写入的是标准 MSR，值与当前 GDT 布局一致；入口地址指向上面的汇编。
    unsafe {
        Efer::update(|f| f.insert(EferFlags::SYSTEM_CALL_EXTENSIONS));
        Msr::new(MSR_STAR).write((sysret_base << 48) | (kernel_cs << 32));
        Msr::new(MSR_LSTAR).write(jsr_syscall_entry as *const () as u64);
        Msr::new(MSR_SFMASK).write(0x0200 | 0x0400 | 0x0100); // IF | DF | TF
        Msr::new(MSR_KERNEL_GS_BASE).write(block);
    }
}

/// 更新本处理器系统调用入口使用的内核栈顶（与本核 TSS.rsp0 同步）。
pub fn set_kernel_stack(top: u64) {
    if let Some(b) = BLOCKS.get(super::smp::cpu_index()) {
        b.kstack.store(top, Ordering::Relaxed);
    }
}

/// 经 IA32_KERNEL_GS_BASE 读出本处理器入口块登记的内核栈顶（入口实际使用的就是这个值）。
pub fn kernel_stack() -> u64 {
    // SAFETY：读标准 MSR；它在本处理器的 `init` 中被设为 BLOCKS 内某一项的地址，或在 init 之前为 0。
    let block = unsafe { Msr::new(MSR_KERNEL_GS_BASE).read() } as *const EntryBlock;
    if block.is_null() {
        return 0;
    }
    // SAFETY：非零时指向静态的入口块。
    unsafe { (*block).kstack.load(Ordering::Relaxed) }
}
