//! LoongArch64 异常入口与分发。
//!
//! 入口保存全部 32 个通用寄存器以及 ERA/PRMD。用户态陷入时先用 KS0 切换回
//! 该任务的內核栈；内核态陷入继续使用当前内核栈。定时器、断点、系统调用和
//! 用户地址错误都走真实硬件异常，而不是 host 模拟。

use core::arch::global_asm;

use super::cpu::{self, read_csr, write_csr};
use super::{timer};
use crate::console;
use crate::fault::{self, UserFault, UserFaultKind};
use crate::irq::{self, IrqLine};
use crate::syscall::{self, SyscallArgs};

#[repr(C)]
pub struct TrapFrame {
    pub x: [u64; 32],
    pub era: u64,
    pub prmd: u64,
}

pub const FRAME_BYTES: usize = core::mem::size_of::<TrapFrame>();
const _: () = assert!(FRAME_BYTES == 272 && FRAME_BYTES % 16 == 0);

extern "C" {
    static jsr_loongarch64_trap_entry: u8;
}

global_asm!(
    r#"
    .section .text.jsr_loongarch64_trap, "ax"
    .balign 4
    .global jsr_loongarch64_trap_entry
jsr_loongarch64_trap_entry:
    csrwr $t0, 0x31
    csrwr $t1, 0x32
    csrrd $t0, 0x1
    move  $t1, $sp
    andi  $t0, $t0, 3
    beqz  $t0, 1f
    csrrd $sp, 0x30
1:
    li.d   $t0, {frame_bytes}
    sub.d  $sp, $sp, $t0
    st.d   $zero, $sp, 0*8
    st.d   $ra,   $sp, 1*8
    st.d   $tp,   $sp, 2*8
    st.d   $t1,   $sp, 3*8
    st.d   $a0,   $sp, 4*8
    st.d   $a1,   $sp, 5*8
    st.d   $a2,   $sp, 6*8
    st.d   $a3,   $sp, 7*8
    st.d   $a4,   $sp, 8*8
    st.d   $a5,   $sp, 9*8
    st.d   $a6,   $sp, 10*8
    st.d   $a7,   $sp, 11*8
    csrrd  $t0, 0x31
    st.d   $t0,   $sp, 12*8
    csrrd  $t0, 0x32
    st.d   $t0,   $sp, 13*8
    st.d   $t2,   $sp, 14*8
    st.d   $t3,   $sp, 15*8
    st.d   $t4,   $sp, 16*8
    st.d   $t5,   $sp, 17*8
    st.d   $t6,   $sp, 18*8
    st.d   $t7,   $sp, 19*8
    st.d   $t8,   $sp, 20*8
    st.d   $r21,  $sp, 21*8
    st.d   $fp,   $sp, 22*8
    st.d   $s0,   $sp, 23*8
    st.d   $s1,   $sp, 24*8
    st.d   $s2,   $sp, 25*8
    st.d   $s3,   $sp, 26*8
    st.d   $s4,   $sp, 27*8
    st.d   $s5,   $sp, 28*8
    st.d   $s6,   $sp, 29*8
    st.d   $s7,   $sp, 30*8
    st.d   $s8,   $sp, 31*8
    csrrd  $t0, 0x6
    st.d   $t0,   $sp, 32*8
    csrrd  $t0, 0x1
    st.d   $t0,   $sp, 33*8
    move   $a0,   $sp
    bl     jsr_loongarch64_trap

    .global jsr_loongarch64_trap_return
jsr_loongarch64_trap_return:
    ld.d   $t0, $sp, 32*8
    csrwr  $t0, 0x6
    ld.d   $t0, $sp, 33*8
    csrwr  $t0, 0x1
    ld.d   $t0, $sp, 12*8
    ld.d   $t1, $sp, 13*8
    ld.d   $ra, $sp, 1*8
    ld.d   $tp, $sp, 2*8
    ld.d   $a0, $sp, 4*8
    ld.d   $a1, $sp, 5*8
    ld.d   $a2, $sp, 6*8
    ld.d   $a3, $sp, 7*8
    ld.d   $a4, $sp, 8*8
    ld.d   $a5, $sp, 9*8
    ld.d   $a6, $sp, 10*8
    ld.d   $a7, $sp, 11*8
    ld.d   $t2, $sp, 14*8
    ld.d   $t3, $sp, 15*8
    ld.d   $t4, $sp, 16*8
    ld.d   $t5, $sp, 17*8
    ld.d   $t6, $sp, 18*8
    ld.d   $t7, $sp, 19*8
    ld.d   $t8, $sp, 20*8
    ld.d   $r21, $sp, 21*8
    ld.d   $fp, $sp, 22*8
    ld.d   $s0, $sp, 23*8
    ld.d   $s1, $sp, 24*8
    ld.d   $s2, $sp, 25*8
    ld.d   $s3, $sp, 26*8
    ld.d   $s4, $sp, 27*8
    ld.d   $s5, $sp, 28*8
    ld.d   $s6, $sp, 29*8
    ld.d   $s7, $sp, 30*8
    ld.d   $s8, $sp, 31*8
    // x[3] is the interrupted stack pointer. ERTN resumes with that pointer,
    // so the trap frame is abandoned below it rather than popped a second time.
    ld.d   $sp, $sp, 3*8
    ertn
    .previous
    "#,
    frame_bytes = const FRAME_BYTES,
);

/// Install the exception entry and clear the user-mode kernel-stack slot.
pub fn init() {
    // SAFETY: entry is a 4-byte aligned function from the assembly above.
    unsafe {
        write_csr!("0x30", 0u64);
        write_csr!("0xc", core::ptr::addr_of!(jsr_loongarch64_trap_entry) as u64);
    }
    cpu::data_barrier();
}

/// Register the current task's kernel stack top for user-to-kernel transitions.
pub fn set_kernel_stack(top: u64) {
    // SAFETY: writes this processor's kernel scratch register.
    unsafe { write_csr!("0x30", top) };
}

pub fn kernel_stack() -> u64 {
    read_csr!("0x30")
}

fn fatal(what: &str, frame: &TrapFrame, estat: u64) -> ! {
    let badv = read_csr!("0x7");
    let mapped = unsafe {
        super::space::translate(
            super::space::current(),
            super::mmu::PHYS_OFFSET,
            badv & !0xfff,
        )
    };
    console::emergency_print(format_args!(
        "[JSR-EXC] {} cpu={} hw={} estat={:#x} exc={} era={:#x} badv={:#x} prmd={:#x} mapped={:?}\n",
        what,
        super::smp::cpu_index(),
        cpu::cpuid(),
        estat,
        (estat >> cpu::ESTAT_EXC_SHIFT) & cpu::ESTAT_EXC_MASK,
        frame.era,
        badv,
        frame.prmd,
        mapped
    ));
    crate::arch::halt_forever()
}

fn timer_interrupt(from_user: bool) {
    // SAFETY: clear only this processor's local timer condition.
    unsafe { write_csr!("0x44", 1u64) };
    timer::rearm();
    let line = if super::smp::cpu_index() == 0 {
        IrqLine::Timer
    } else {
        IrqLine::LocalTimer
    };
    irq::on_hardware_irq(line, from_user);
}

fn user_fault(frame: &TrapFrame, exc: u64) -> ! {
    let badv = read_csr!("0x7");
    let kind = match exc {
        cpu::EXC_TLB_LOAD
        | cpu::EXC_TLB_STORE
        | cpu::EXC_TLB_INSTRUCTION
        | cpu::EXC_TLB_PRIVILEGE
        | cpu::EXC_ADDRESS_ERROR => UserFaultKind::PageFault,
        cpu::EXC_INVALID_INSTRUCTION => UserFaultKind::InvalidInstruction,
        _ => UserFaultKind::ProtectionFault,
    };
    fault::on_user_fault(UserFault { kind, ip: frame.era, addr: badv });
}

#[no_mangle]
extern "C" fn jsr_loongarch64_trap(frame: &mut TrapFrame) {
    let estat = read_csr!("0x5");
    let from_user = frame.prmd & cpu::CRMD_PLV != 0;
    let interrupted = estat & 0x7fff != 0;
    if interrupted {
        if estat & cpu::ESTAT_TIMER != 0 {
            timer_interrupt(from_user);
            return;
        }
        if super::smp::ipi_pending() {
            super::smp::handle_ipi();
            return;
        }
        fatal("unexpected interrupt", frame, estat);
    }
    let exc = (estat >> cpu::ESTAT_EXC_SHIFT) & cpu::ESTAT_EXC_MASK;
    if exc == cpu::EXC_SYSCALL {
        // Linux LoongArch ABI: a7 carries the syscall number, a0-a5 the arguments.
        let args = SyscallArgs {
            id: frame.x[11],
            args: [frame.x[4], frame.x[5], frame.x[6], frame.x[7], frame.x[8], frame.x[9]],
            user_ip: None,
        };
        frame.era += 4;
        let result = syscall::on_syscall(&args);
        frame.x[4] = result as u64;
        // Keep the optional high return half consistent with the signed i64
        // result. LoongArch's native ABI uses a0 for the normal 64-bit return,
        // while a1 is reserved for the high half of a 128-bit value.
        frame.x[5] = ((result as i128) >> 64) as u64;
        return;
    }
    if from_user {
        user_fault(frame, exc);
    }
    if exc == cpu::EXC_BREAKPOINT {
        console::write_str("[JSR-EXC] breakpoint handler verified\n");
        frame.era += 4;
    } else {
        fatal("kernel exception", frame, estat);
    }
}
