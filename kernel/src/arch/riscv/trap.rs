//! RISC-V 陷入入口与分发：同步异常（断点、系统调用、缺页、非法指令）、中断（定时器、外部）、致命异常。
//! RISC-V trap entry and dispatch.
//!
//! # 入口与栈
//! stvec 为直接模式，所有陷入都进 `jsr_trap_entry`。用 sscratch 区分来源：
//! * 在**用户态**运行期间 sscratch = 本任务的内核栈顶；入口交换 sp 与 sscratch 即切到内核栈；
//! * 在**监管态**运行期间 sscratch = 0；入口交换后得到 0，再换回来，继续用当前内核栈。
//!
//! 入口在栈上压完整寄存器帧（x1–x31、sepc、sstatus，见 [`TrapFrame`]；槽宽 = XLEN，RV32 与 RV64 共用同一段汇编），并把 sscratch 清零（此后在内核里）；
//! 返回路径 `jsr_trap_return` 若要回到用户态，就把 sscratch 重新置为「弹出本帧之后的栈顶」= 本任务的内核栈顶。
//! 帧保存在各任务自己的内核栈上，因此处理过程中切换任务（抢占、阻塞的系统调用）是安全的。
//! 来源以 sstatus.SPP 判定，而不是以用户 sp 是否为 0 判定（用户可以把 sp 置成任意值）。
//!
//! # 与 Core 的边界
//! 陷入原因编号（scause）与中断源编号只在这里出现；交给 Core 的是中立的 [`UserFault`]、[`SyscallArgs`](crate::syscall::SyscallArgs)
//! 与逻辑中断线 [`IrqLine`]。

use core::arch::global_asm;

use super::cpu::{self, read_csr};
use super::mode::{self, xlen_asm_begin, xlen_asm_end};
use super::{plic, timer};
use crate::console;
use crate::fault::{self, UserFault, UserFaultKind};
use crate::irq::{self, IrqLine};
use crate::syscall;

/// 陷入时保存的寄存器帧（布局必须与下方汇编一致：36 个寄存器宽度的槽，RV64 288 字节、RV32 144 字节，16 字节对齐）。
#[repr(C)]
pub struct TrapFrame {
    /// 通用寄存器 x0–x31（x0 槽位不使用，保持下标与寄存器号一致）。
    pub x: [usize; 32],
    /// 陷入返回地址。
    pub sepc: usize,
    /// 陷入时的状态寄存器（含 SPP / SPIE，返回时原样恢复）。
    pub sstatus: usize,
    /// 填充到 16 字节的整数倍（栈指针在陷入期间保持 16 字节对齐）。
    _pad: [usize; 2],
}

/// 一个寄存器槽的字节数（XLEN / 8）。
pub const WB: usize = core::mem::size_of::<usize>();
/// 帧大小（字节）。
pub const FRAME_BYTES: usize = core::mem::size_of::<TrapFrame>();
const _: () = assert!(FRAME_BYTES == 36 * WB && FRAME_BYTES % 16 == 0);
/// 帧内 sepc 与 sstatus 的偏移（汇编使用）。
pub const SEPC_OFF: usize = 32 * WB;
pub const SSTATUS_OFF: usize = 33 * WB;

/// scause 最高位（XLEN - 1）：中断。
const CAUSE_INTERRUPT: u64 = 1 << (usize::BITS - 1);
/// 中断原因：监管态定时器、监管态外部中断。
const IRQ_S_TIMER: u64 = 5;
const IRQ_S_EXTERNAL: u64 = 9;
/// 异常原因。
const EXC_ILLEGAL_INSTRUCTION: u64 = 2;
const EXC_BREAKPOINT: u64 = 3;
const EXC_ECALL_U: u64 = 8;
const EXC_INST_PAGE_FAULT: u64 = 12;
const EXC_LOAD_PAGE_FAULT: u64 = 13;
const EXC_STORE_PAGE_FAULT: u64 = 15;

/// 指令编码：SYSTEM 主操作码，以及其中 funct3 = 0 的特权指令组（wfi、sret、sfence.vma 等）。
const OPCODE_MASK: u64 = 0x7f;
const OPCODE_SYSTEM: u64 = 0x73;
const FUNCT3_SHIFT: u64 = 12;

global_asm!(
    xlen_asm_begin!(),
    r#"
    .section .text.jsr_trap, "ax"
    .balign 4
    .global jsr_trap_entry
jsr_trap_entry:
    csrrw sp, sscratch, sp
    bnez sp, 1f
    csrrw sp, sscratch, sp
1:
    addi sp, sp, -{frame}
    SX x1, 1*{wb}, sp
    SX x3, 3*{wb}, sp
    SX x4, 4*{wb}, sp
    SX x5, 5*{wb}, sp
    SX x6, 6*{wb}, sp
    SX x7, 7*{wb}, sp
    SX x8, 8*{wb}, sp
    SX x9, 9*{wb}, sp
    SX x10, 10*{wb}, sp
    SX x11, 11*{wb}, sp
    SX x12, 12*{wb}, sp
    SX x13, 13*{wb}, sp
    SX x14, 14*{wb}, sp
    SX x15, 15*{wb}, sp
    SX x16, 16*{wb}, sp
    SX x17, 17*{wb}, sp
    SX x18, 18*{wb}, sp
    SX x19, 19*{wb}, sp
    SX x20, 20*{wb}, sp
    SX x21, 21*{wb}, sp
    SX x22, 22*{wb}, sp
    SX x23, 23*{wb}, sp
    SX x24, 24*{wb}, sp
    SX x25, 25*{wb}, sp
    SX x26, 26*{wb}, sp
    SX x27, 27*{wb}, sp
    SX x28, 28*{wb}, sp
    SX x29, 29*{wb}, sp
    SX x30, 30*{wb}, sp
    SX x31, 31*{wb}, sp
    csrrw t0, sscratch, zero
    csrr t1, sstatus
    andi t2, t1, {spp}
    beqz t2, 2f
    addi t0, sp, {frame}
2:
    SX t0, 2*{wb}, sp
    csrr t2, sepc
    SX t2, {sepc}, sp
    SX t1, {sstatus}, sp
    mv a0, sp
    call jsr_riscv_trap

    .global jsr_trap_return
jsr_trap_return:
    csrci sstatus, {sie}
    LX t0, {sepc}, sp
    csrw sepc, t0
    LX t0, {sstatus}, sp
    csrw sstatus, t0
    andi t0, t0, {spp}
    bnez t0, 3f
    addi t1, sp, {frame}
    csrw sscratch, t1
3:
    LX x1, 1*{wb}, sp
    LX x3, 3*{wb}, sp
    LX x4, 4*{wb}, sp
    LX x5, 5*{wb}, sp
    LX x6, 6*{wb}, sp
    LX x7, 7*{wb}, sp
    LX x8, 8*{wb}, sp
    LX x9, 9*{wb}, sp
    LX x10, 10*{wb}, sp
    LX x11, 11*{wb}, sp
    LX x12, 12*{wb}, sp
    LX x13, 13*{wb}, sp
    LX x14, 14*{wb}, sp
    LX x15, 15*{wb}, sp
    LX x16, 16*{wb}, sp
    LX x17, 17*{wb}, sp
    LX x18, 18*{wb}, sp
    LX x19, 19*{wb}, sp
    LX x20, 20*{wb}, sp
    LX x21, 21*{wb}, sp
    LX x22, 22*{wb}, sp
    LX x23, 23*{wb}, sp
    LX x24, 24*{wb}, sp
    LX x25, 25*{wb}, sp
    LX x26, 26*{wb}, sp
    LX x27, 27*{wb}, sp
    LX x28, 28*{wb}, sp
    LX x29, 29*{wb}, sp
    LX x30, 30*{wb}, sp
    LX x31, 31*{wb}, sp
    LX x2, 2*{wb}, sp
    sret
    .previous
    "#,
    xlen_asm_end!(),
    frame = const FRAME_BYTES,
    wb = const WB,
    sepc = const SEPC_OFF,
    sstatus = const SSTATUS_OFF,
    spp = const cpu::SSTATUS_SPP,
    sie = const cpu::SSTATUS_SIE,
);

extern "C" {
    /// 陷入入口（4 字节对齐，直接模式）。
    static jsr_trap_entry: u8;
}

/// 安装陷入入口；sscratch 清零（此刻在监管态）。
pub fn init() {
    // SAFETY：入口由上方汇编定义并按 4 字节对齐（stvec 低两位 = 0 即直接模式）。
    unsafe {
        let base = core::ptr::addr_of!(jsr_trap_entry) as usize;
        cpu::write_csr!("sscratch", 0u64);
        cpu::write_csr!("stvec", base);
    }
}

/// 打印致命异常并停机（内核态出错、或不应出现的原因）。
fn fatal(what: &str, frame: &TrapFrame) -> ! {
    console::_print(format_args!(
        "[JSR-EXC] {} scause={:#x} sepc={:#x} stval={:#x} sstatus={:#x}\n",
        what,
        read_csr!("scause"),
        frame.sepc,
        read_csr!("stval"),
        frame.sstatus
    ));
    crate::arch::halt_forever()
}

/// 位于 `pc` 的指令长度：低两位为 `11` 的是 4 字节指令，其余为 2 字节压缩指令。
///
/// # Safety
/// `pc` 必须指向可读的内核代码。
unsafe fn instruction_len(pc: usize) -> usize {
    if (pc as *const u16).read_volatile() & 3 == 3 {
        4
    } else {
        2
    }
}

/// 处理外部中断：逐个认领 → 完成；本内核尚未为任何设备驱动登记外部中断，出现即报告。
fn handle_external() {
    loop {
        let source = plic::claim();
        if source == 0 {
            return;
        }
        plic::complete(source);
        console::_print(format_args!("[JSR-IRQ] unexpected external interrupt source={}\n", source));
    }
}

/// 非法指令按中立种类归类：SYSTEM 操作码中 funct3 = 0 的特权指令（wfi、sret、sfence.vma 等）为保护错误；
/// 其余（含访问用户态不可见的 CSR、无法解码的编码）为无效指令——与 AArch64 上的分类一致。
fn classify_illegal(stval: u64) -> UserFaultKind {
    if stval & OPCODE_MASK == OPCODE_SYSTEM && (stval >> FUNCT3_SHIFT) & 7 == 0 {
        UserFaultKind::ProtectionFault
    } else {
        UserFaultKind::InvalidInstruction
    }
}

/// 来自用户态的同步异常：系统调用交给 Core 分发；其余按中立的故障种类终止该任务。
fn handle_user_exception(frame: &mut TrapFrame, cause: u64) {
    if cause == EXC_ECALL_U {
        // ecall 固定 4 字节：先越过它，Core 在处理中切换任务或终止任务都不影响返回地址
        frame.sepc += 4;
        // 参数按各寄存器宽度的约定组合为 Core 的 64 位参数（RV32：低半 a0–a2、高半 a3–a5）
        let args = mode::syscall_args(&frame.x);
        mode::set_syscall_return(&mut frame.x, syscall::on_syscall(&args));
        return;
    }
    let stval = read_csr!("stval");
    let (kind, addr) = match cause {
        EXC_INST_PAGE_FAULT | EXC_LOAD_PAGE_FAULT | EXC_STORE_PAGE_FAULT => (UserFaultKind::PageFault, stval),
        EXC_ILLEGAL_INSTRUCTION => (classify_illegal(stval), 0),
        // 断点、未对齐访问、访问错误（物理内存保护）等
        _ => (UserFaultKind::ProtectionFault, 0),
    };
    fault::on_user_fault(UserFault { kind, ip: frame.sepc as u64, addr })
}

/// 汇编入口调用的 Rust 分发。
#[no_mangle]
extern "C" fn jsr_riscv_trap(frame: &mut TrapFrame) {
    let cause = read_csr!("scause");
    let from_user = frame.sstatus as u64 & cpu::SSTATUS_SPP == 0;
    if cause & CAUSE_INTERRUPT != 0 {
        match cause & !CAUSE_INTERRUPT {
            IRQ_S_TIMER => {
                timer::rearm();
                irq::on_hardware_irq(IrqLine::Timer, from_user);
            }
            IRQ_S_EXTERNAL => handle_external(),
            _ => fatal("unexpected interrupt", frame),
        }
    } else if from_user {
        handle_user_exception(frame, cause);
    } else if cause == EXC_BREAKPOINT {
        console::write_str("[JSR-EXC] breakpoint handler verified\n");
        // SAFETY：断点停在 ebreak 指令本身，位于内核代码中。
        frame.sepc += unsafe { instruction_len(frame.sepc) };
    } else {
        fatal("kernel exception", frame);
    }
}
