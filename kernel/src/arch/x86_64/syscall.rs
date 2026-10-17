//! x86_64 系统调用入口：`syscall` / `sysretq`。
//! x86_64 system-call entry via `syscall` / `sysretq`.
//!
//! # 寄存器约定（Jasper 系统调用 ABI，x86_64）
//! * `rax` = 操作 ID；参数依次为 `rdi rsi rdx r10 r8 r9`
//! * 返回值在 `rax`（非负 = 成功值，负数 = `-(错误码 ID)`）
//! * `rcx`、`r11` 被硬件占用（返回地址与标志位），调用后不保留；其余寄存器全部保留
//!
//! # 入口流程
//! `syscall` 不切栈：入口先把用户栈指针存进单 CPU 暂存位，换到当前任务的内核栈，
//! 把寄存器压成 [`RawFrame`]，调用 Rust 分发，再按相反顺序恢复并 `sysretq`。
//! SFMASK 清 IF/DF/TF：分发期间关中断（单 CPU 下暂存位因此安全）。
//!
//! # 安全细节
//! `sysretq` 遇到非规范的返回地址会在**内核态**触发 #GP（Intel 已知问题）。因此返回前检查
//! 用户 RIP 是否规范；不规范则按用户故障终止该任务，绝不执行这条 `sysretq`。

use core::arch::global_asm;

use x86_64::registers::model_specific::{Efer, EferFlags, Msr};

use crate::fault::{self, UserFault, UserFaultKind};
use crate::syscall::{self, SyscallArgs};

/// 入口用的内核栈顶（调度器每次切换任务时经 `set_kernel_stack` 更新，与 TSS.rsp0 相同）。
#[no_mangle]
static mut JSR_SYSCALL_KSTACK: u64 = 0;
/// 用户栈指针暂存位（单 CPU、入口关中断期间使用）。
#[no_mangle]
static mut JSR_SYSCALL_USER_RSP: u64 = 0;

/// 入口压栈后的寄存器帧（自低地址向高地址，顺序必须与下方汇编一致）。
#[repr(C)]
pub struct RawFrame {
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
}

const MSR_STAR: u32 = 0xC000_0081;
const MSR_LSTAR: u32 = 0xC000_0082;
const MSR_SFMASK: u32 = 0xC000_0084;

extern "C" {
    fn jsr_syscall_entry();
}

global_asm!(
    r#"
    .global jsr_syscall_entry
jsr_syscall_entry:
    mov [rip + JSR_SYSCALL_USER_RSP], rsp
    mov rsp, [rip + JSR_SYSCALL_KSTACK]
    push qword ptr [rip + JSR_SYSCALL_USER_RSP]
    push rcx
    push r11
    push r9
    push r8
    push r10
    push rdx
    push rsi
    push rdi
    push rax
    mov rdi, rsp
    call jsr_syscall_dispatch
    add rsp, 8
    pop rdi
    pop rsi
    pop rdx
    pop r10
    pop r8
    pop r9
    pop r11
    pop rcx
    pop rsp
    sysretq
    "#
);

/// 汇编入口调用的 Rust 分发桥：整理参数 → Core 分发 → 返回前做 RIP 规范性检查。
#[no_mangle]
extern "C" fn jsr_syscall_dispatch(frame: &mut RawFrame) -> u64 {
    let args = SyscallArgs {
        id: frame.rax,
        args: [frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9],
    };
    let ret = syscall::on_syscall(&args);
    let rip = frame.rcx;
    if ((rip << 16) as i64 >> 16) as u64 != rip {
        fault::on_user_fault(UserFault { kind: UserFaultKind::ProtectionFault, ip: rip, addr: 0 });
    }
    ret as u64
}

/// 启用 `syscall` 指令并设置入口（需在 GDT 加载之后调用）。
///
/// STAR：进入时 CS = 内核代码段（0x08），SS = 其后的内核数据段；
/// 返回时 CS = 基址 0x10 + 16 = 用户代码段（0x20|3），SS = 0x10 + 8 = 用户数据段（0x18|3）。
/// 这正是 gdt.rs 中「用户数据段排在用户代码段之前」的原因。
pub fn init() {
    let sel = super::gdt::selectors();
    let kernel_cs = sel.kernel_code.0 as u64;
    let sysret_base = (sel.user_data.0 as u64 & !3) - 8;
    // SAFETY：写入的是标准 MSR，值与当前 GDT 布局一致；入口地址指向上面的汇编。
    unsafe {
        Efer::update(|f| f.insert(EferFlags::SYSTEM_CALL_EXTENSIONS));
        Msr::new(MSR_STAR).write((sysret_base << 48) | (kernel_cs << 32));
        Msr::new(MSR_LSTAR).write(jsr_syscall_entry as *const () as u64);
        Msr::new(MSR_SFMASK).write(0x0200 | 0x0400 | 0x0100); // IF | DF | TF
    }
}

/// 更新系统调用入口使用的内核栈顶（与 TSS.rsp0 同步）。
pub fn set_kernel_stack(top: u64) {
    // SAFETY：单 CPU、调度器在关中断临界区内写；入口只在关中断时读。
    unsafe { JSR_SYSCALL_KSTACK = top };
}
