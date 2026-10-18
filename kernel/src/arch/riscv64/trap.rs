//! RISC-V 陷入入口与分发：同步异常（断点、系统调用、缺页、非法指令）、中断（定时器、外部）、致命异常。
//! RISC-V trap entry and dispatch.
//!
//! # 入口与栈
//! stvec 为直接模式，所有陷入都进 `jsr_trap_entry`。用 sscratch 区分来源：
//! * 在**用户态**运行期间 sscratch = 本任务的内核栈顶；入口交换 sp 与 sscratch 即切到内核栈；
//! * 在**监管态**运行期间 sscratch = 0；入口交换后得到 0，再换回来，继续用当前内核栈。
//!
//! 入口在栈上压完整寄存器帧（x1–x31、sepc、sstatus，见 [`TrapFrame`]），并把 sscratch 清零（此后在内核里）；
//! 返回路径 `jsr_trap_return` 若要回到用户态，就把 sscratch 重新置为「弹出本帧之后的栈顶」= 本任务的内核栈顶。
//! 帧保存在各任务自己的内核栈上，因此处理过程中切换任务（抢占、阻塞的系统调用）是安全的。
//! 来源以 sstatus.SPP 判定，而不是以用户 sp 是否为 0 判定（用户可以把 sp 置成任意值）。
//!
//! # 与 Core 的边界
//! 陷入原因编号（scause）与中断源编号只在这里出现；交给 Core 的是中立的 [`UserFault`]、[`SyscallArgs`]
//! 与逻辑中断线 [`IrqLine`]。

use core::arch::global_asm;

use super::cpu::{self, read_csr};
use super::{plic, timer};
use crate::console;
use crate::fault::{self, UserFault, UserFaultKind};
use crate::irq::{self, IrqLine};
use crate::syscall::{self, SyscallArgs};

/// 陷入时保存的寄存器帧（布局必须与下方汇编一致：共 272 字节，16 字节对齐）。
#[repr(C)]
pub struct TrapFrame {
    /// 通用寄存器 x0–x31（x0 槽位不使用，保持下标与寄存器号一致）。
    pub x: [u64; 32],
    /// 陷入返回地址。
    pub sepc: u64,
    /// 陷入时的状态寄存器（含 SPP / SPIE，返回时原样恢复）。
    pub sstatus: u64,
}

/// 帧大小（字节）。
pub const FRAME_BYTES: usize = core::mem::size_of::<TrapFrame>();
const _: () = assert!(FRAME_BYTES == 272 && FRAME_BYTES % 16 == 0);
/// 帧内 sepc 与 sstatus 的偏移（汇编使用）。
pub const SEPC_OFF: usize = 256;
pub const SSTATUS_OFF: usize = 264;

/// scause 最高位：中断。
const CAUSE_INTERRUPT: u64 = 1 << 63;
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
    sd x1, 8(sp)
    sd x3, 24(sp)
    sd x4, 32(sp)
    sd x5, 40(sp)
    sd x6, 48(sp)
    sd x7, 56(sp)
    sd x8, 64(sp)
    sd x9, 72(sp)
    sd x10, 80(sp)
    sd x11, 88(sp)
    sd x12, 96(sp)
    sd x13, 104(sp)
    sd x14, 112(sp)
    sd x15, 120(sp)
    sd x16, 128(sp)
    sd x17, 136(sp)
    sd x18, 144(sp)
    sd x19, 152(sp)
    sd x20, 160(sp)
    sd x21, 168(sp)
    sd x22, 176(sp)
    sd x23, 184(sp)
    sd x24, 192(sp)
    sd x25, 200(sp)
    sd x26, 208(sp)
    sd x27, 216(sp)
    sd x28, 224(sp)
    sd x29, 232(sp)
    sd x30, 240(sp)
    sd x31, 248(sp)
    csrrw t0, sscratch, zero
    csrr t1, sstatus
    andi t2, t1, {spp}
    beqz t2, 2f
    addi t0, sp, {frame}
2:
    sd t0, 16(sp)
    csrr t2, sepc
    sd t2, {sepc}(sp)
    sd t1, {sstatus}(sp)
    mv a0, sp
    call jsr_riscv64_trap

    .global jsr_trap_return
jsr_trap_return:
    csrci sstatus, {sie}
    ld t0, {sepc}(sp)
    csrw sepc, t0
    ld t0, {sstatus}(sp)
    csrw sstatus, t0
    andi t0, t0, {spp}
    bnez t0, 3f
    addi t1, sp, {frame}
    csrw sscratch, t1
3:
    ld x1, 8(sp)
    ld x3, 24(sp)
    ld x4, 32(sp)
    ld x5, 40(sp)
    ld x6, 48(sp)
    ld x7, 56(sp)
    ld x8, 64(sp)
    ld x9, 72(sp)
    ld x10, 80(sp)
    ld x11, 88(sp)
    ld x12, 96(sp)
    ld x13, 104(sp)
    ld x14, 112(sp)
    ld x15, 120(sp)
    ld x16, 128(sp)
    ld x17, 136(sp)
    ld x18, 144(sp)
    ld x19, 152(sp)
    ld x20, 160(sp)
    ld x21, 168(sp)
    ld x22, 176(sp)
    ld x23, 184(sp)
    ld x24, 192(sp)
    ld x25, 200(sp)
    ld x26, 208(sp)
    ld x27, 216(sp)
    ld x28, 224(sp)
    ld x29, 232(sp)
    ld x30, 240(sp)
    ld x31, 248(sp)
    ld x2, 16(sp)
    sret
    .previous
    "#,
    frame = const FRAME_BYTES,
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
        let base = core::ptr::addr_of!(jsr_trap_entry) as u64;
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
unsafe fn instruction_len(pc: u64) -> u64 {
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
        let x = &frame.x;
        let args = SyscallArgs { id: x[17], args: [x[10], x[11], x[12], x[13], x[14], x[15]] };
        frame.x[10] = syscall::on_syscall(&args) as u64;
        return;
    }
    let stval = read_csr!("stval");
    let (kind, addr) = match cause {
        EXC_INST_PAGE_FAULT | EXC_LOAD_PAGE_FAULT | EXC_STORE_PAGE_FAULT => (UserFaultKind::PageFault, stval),
        EXC_ILLEGAL_INSTRUCTION => (classify_illegal(stval), 0),
        // 断点、未对齐访问、访问错误（物理内存保护）等
        _ => (UserFaultKind::ProtectionFault, 0),
    };
    fault::on_user_fault(UserFault { kind, ip: frame.sepc, addr })
}

/// 汇编入口调用的 Rust 分发。
#[no_mangle]
extern "C" fn jsr_riscv64_trap(frame: &mut TrapFrame) {
    let cause = read_csr!("scause");
    let from_user = frame.sstatus & cpu::SSTATUS_SPP == 0;
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
