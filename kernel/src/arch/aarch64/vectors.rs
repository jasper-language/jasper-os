//! AArch64 异常向量表与陷入分发：同步异常（断点、系统调用、缺页、非法指令）、IRQ（定时器）、致命异常。
//! AArch64 exception vectors and trap dispatch.
//!
//! # 入口
//! 每个向量把完整寄存器帧（x0–x30、SP_EL0、ELR_EL1、SPSR_EL1，见 [`TrapFrame`]）压到当前的 SP_EL1 上，
//! 带上向量种类调用 [`jsr_aarch64_trap`]，返回后按原样恢复并 `eret`。帧保存在各任务自己的内核栈上，
//! 因此处理过程中切换任务（抢占、阻塞的系统调用）是安全的。
//!
//! # 从 EL0 进入时用哪个栈
//! 内核始终在 SP_EL1 上运行。进入用户态（`user.rs`）时把 SP_EL1 置为当前任务的内核栈顶再 `eret`，
//! 之后每次从 EL0 陷入都从该栈顶压帧、返回时弹回原处——SP_EL1 在用户态期间始终等于本任务的内核栈顶。
//!
//! # 与 Core 的边界
//! 异常类别（ESR 的 EC 字段）与中断号只在这里出现；交给 Core 的是中立的 [`UserFault`]、[`SyscallArgs`]
//! 与逻辑中断线 [`IrqLine`]。

use core::arch::global_asm;

use super::{cpu::read_sysreg, gic, timer};
use crate::console;
use crate::fault::{self, UserFault, UserFaultKind};
use crate::irq::{self, IrqLine};
use crate::syscall::{self, SyscallArgs};

/// 陷入时保存的寄存器帧（布局必须与下方汇编一致：共 272 字节，16 字节对齐）。
#[repr(C)]
pub struct TrapFrame {
    /// 通用寄存器 x0–x30。
    pub x: [u64; 31],
    /// 用户栈指针。
    pub sp_el0: u64,
    /// 异常返回地址。
    pub elr: u64,
    /// 异常返回时恢复的处理器状态。
    pub spsr: u64,
}

/// 帧大小（字节）。
pub const FRAME_BYTES: usize = core::mem::size_of::<TrapFrame>();
const _: () = assert!(FRAME_BYTES == 272 && FRAME_BYTES % 16 == 0);

/// 向量种类（由汇编传入）。
const KIND_CUR_SYNC: u64 = 0;
const KIND_CUR_IRQ: u64 = 1;
const KIND_CUR_FATAL: u64 = 2;
const KIND_LOW_SYNC: u64 = 3;
const KIND_LOW_IRQ: u64 = 4;
const KIND_LOW_FATAL: u64 = 5;
const KIND_UNEXPECTED: u64 = 6;

/// ESR 异常类别（EC）。
const EC_UNKNOWN: u64 = 0x00;
const EC_SVC64: u64 = 0x15;
const EC_INST_ABORT_LOW: u64 = 0x20;
const EC_DATA_ABORT_LOW: u64 = 0x24;
const EC_BRK64: u64 = 0x3c;

extern "C" {
    /// 向量表起点（2 KiB 对齐）。
    static jsr_vectors: u8;
}

global_asm!(
    r#"
    .macro JSR_A64_VEC kind
        .balign 0x80
        sub sp, sp, #{frame}
        stp x0, x1, [sp, #0]
        mov x1, #\kind
        b jsr_trap_common
    .endm

    .section .text.jsr_vectors, "ax"
    .balign 0x800
    .global jsr_vectors
jsr_vectors:
    JSR_A64_VEC {unexpected}
    JSR_A64_VEC {unexpected}
    JSR_A64_VEC {unexpected}
    JSR_A64_VEC {unexpected}
    JSR_A64_VEC {cur_sync}
    JSR_A64_VEC {cur_irq}
    JSR_A64_VEC {cur_fatal}
    JSR_A64_VEC {cur_fatal}
    JSR_A64_VEC {low_sync}
    JSR_A64_VEC {low_irq}
    JSR_A64_VEC {low_fatal}
    JSR_A64_VEC {low_fatal}
    JSR_A64_VEC {unexpected}
    JSR_A64_VEC {unexpected}
    JSR_A64_VEC {unexpected}
    JSR_A64_VEC {unexpected}

    .balign 4
jsr_trap_common:
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    stp x8, x9, [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x16, x17, [sp, #128]
    stp x18, x19, [sp, #144]
    stp x20, x21, [sp, #160]
    stp x22, x23, [sp, #176]
    stp x24, x25, [sp, #192]
    stp x26, x27, [sp, #208]
    stp x28, x29, [sp, #224]
    mrs x9, sp_el0
    stp x30, x9, [sp, #240]
    mrs x10, elr_el1
    mrs x11, spsr_el1
    stp x10, x11, [sp, #256]
    mov x0, sp
    bl jsr_aarch64_trap

    .global jsr_trap_return
jsr_trap_return:
    ldp x10, x11, [sp, #256]
    msr elr_el1, x10
    msr spsr_el1, x11
    ldp x30, x9, [sp, #240]
    msr sp_el0, x9
    ldp x0, x1, [sp, #0]
    ldp x2, x3, [sp, #16]
    ldp x4, x5, [sp, #32]
    ldp x6, x7, [sp, #48]
    ldp x8, x9, [sp, #64]
    ldp x10, x11, [sp, #80]
    ldp x12, x13, [sp, #96]
    ldp x14, x15, [sp, #112]
    ldp x16, x17, [sp, #128]
    ldp x18, x19, [sp, #144]
    ldp x20, x21, [sp, #160]
    ldp x22, x23, [sp, #176]
    ldp x24, x25, [sp, #192]
    ldp x26, x27, [sp, #208]
    ldp x28, x29, [sp, #224]
    add sp, sp, #{frame}
    eret
    .previous
    "#,
    frame = const FRAME_BYTES,
    cur_sync = const KIND_CUR_SYNC,
    cur_irq = const KIND_CUR_IRQ,
    cur_fatal = const KIND_CUR_FATAL,
    low_sync = const KIND_LOW_SYNC,
    low_irq = const KIND_LOW_IRQ,
    low_fatal = const KIND_LOW_FATAL,
    unexpected = const KIND_UNEXPECTED,
);

/// 安装向量表。
pub fn init() {
    // SAFETY：向量表由上方汇编定义并按 2 KiB 对齐；写 VBAR_EL1 后同步。
    unsafe {
        let base = core::ptr::addr_of!(jsr_vectors) as u64;
        super::cpu::write_sysreg!("vbar_el1", base);
    }
    super::cpu::isb();
}

/// 打印致命异常并停机（内核态出错、或不应出现的向量）。
fn fatal(what: &str, frame: &TrapFrame) -> ! {
    let esr = read_sysreg!("esr_el1");
    let far = read_sysreg!("far_el1");
    console::_print(format_args!(
        "[JSR-EXC] {} ec={:#x} esr={:#x} elr={:#x} far={:#x} spsr={:#x}\n",
        what,
        esr >> 26,
        esr,
        frame.elr,
        far,
        frame.spsr
    ));
    crate::arch::halt_forever()
}

/// 处理一个 IRQ：应答 → 定时器则重装 → 结束中断 → 交给 Core。
///
/// 先结束中断再交给 Core（与 x86_64 相同的顺序）：Core 可能在这里直接切到别的任务，
/// 结束放在后面的话，切回本任务之前 GIC 不会再送来同优先级的中断，时钟就停了。
fn handle_irq(from_user: bool) {
    let iar = gic::acknowledge();
    let id = gic::interrupt_id(iar);
    if id == gic::SPURIOUS {
        return;
    }
    if Some(id) == timer::interrupt() {
        timer::rearm();
        gic::end(iar);
        irq::on_hardware_irq(IrqLine::Timer, from_user);
    } else {
        gic::end(iar);
        console::_print(format_args!("[JSR-IRQ] unexpected interrupt id={}\n", id));
    }
}

/// 来自 EL0 的同步异常：系统调用交给 Core 分发；其余按中立的故障种类终止该任务。
fn handle_user_sync(frame: &mut TrapFrame) {
    let esr = read_sysreg!("esr_el1");
    let ec = esr >> 26;
    if ec == EC_SVC64 {
        let x = &frame.x;
        let args = SyscallArgs { id: x[8], args: [x[0], x[1], x[2], x[3], x[4], x[5]] };
        frame.x[0] = syscall::on_syscall(&args) as u64;
        return;
    }
    let (kind, addr) = match ec {
        EC_DATA_ABORT_LOW | EC_INST_ABORT_LOW => (UserFaultKind::PageFault, read_sysreg!("far_el1")),
        EC_UNKNOWN => (UserFaultKind::InvalidInstruction, 0),
        // 被捕获的 WFI/WFE、系统寄存器访问、浮点 / SIMD 访问、对齐错误、非法执行状态、断点等
        _ => (UserFaultKind::ProtectionFault, 0),
    };
    fault::on_user_fault(UserFault { kind, ip: frame.elr, addr })
}

/// 汇编入口调用的 Rust 分发。
#[no_mangle]
extern "C" fn jsr_aarch64_trap(frame: &mut TrapFrame, kind: u64) {
    match kind {
        KIND_CUR_SYNC => {
            let esr = read_sysreg!("esr_el1");
            if esr >> 26 == EC_BRK64 {
                // 断点停在 brk 指令本身：越过它（固定 4 字节）后返回
                console::write_str("[JSR-EXC] breakpoint handler verified\n");
                frame.elr += 4;
            } else {
                fatal("kernel sync exception", frame);
            }
        }
        KIND_CUR_IRQ => handle_irq(false),
        KIND_LOW_SYNC => handle_user_sync(frame),
        KIND_LOW_IRQ => handle_irq(true),
        KIND_CUR_FATAL => fatal("kernel fiq/serror", frame),
        KIND_LOW_FATAL => fatal("user fiq/serror", frame),
        _ => fatal("unexpected vector", frame),
    }
}
