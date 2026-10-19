//! IDT：x86 异常处理与硬件中断入口。
//!
//! 已接：断点（#BP，用于证明 IDT 生效）、双重错误（独立 IST 栈）、缺页、定时器（IRQ0）、
//! 本地 APIC 的本地定时器与三类核间中断、伪中断。
//! 处理程序使用 `extern "x86-interrupt"` ABI（nightly `abi_x86_interrupt`），
//! 由编译器负责保存/恢复全部寄存器并以 `iretq` 返回。
//!
//! 与 Core 的边界：硬件中断在这里被翻译成**逻辑中断线**（[`crate::irq::IrqLine`]），
//! 再交给 `crate::irq::on_hardware_irq`；Core 永远看不到向量号。

use spin::Once;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

use kernel_core::smp::IpiKind;

use super::{apic, gdt, pic};
use crate::console;
use crate::fault::{self, UserFault, UserFaultKind};
use crate::irq::{self, IrqLine};

/// IDT 必须有 `'static` 生命周期（`load` 的要求），故放在 `Once` 里。
static IDT: Once<InterruptDescriptorTable> = Once::new();

/// 构建并加载 IDT。
pub fn init() {
    let idt = IDT.call_once(|| {
        let mut idt = InterruptDescriptorTable::new();
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        // SAFETY：IST 索引对应 gdt.rs 中已为双重错误准备的独立栈。
        unsafe {
            idt.double_fault
                .set_handler_fn(double_fault_handler)
                .set_stack_index(gdt::DOUBLE_FAULT_IST_INDEX);
        }
        idt.page_fault.set_handler_fn(page_fault_handler);
        idt.general_protection_fault.set_handler_fn(general_protection_handler);
        idt.invalid_opcode.set_handler_fn(invalid_opcode_handler);
        idt[pic::TIMER_VECTOR].set_handler_fn(timer_interrupt_handler);
        idt[apic::LOCAL_TIMER_VECTOR].set_handler_fn(local_timer_handler);
        idt[apic::IPI_RESCHEDULE_VECTOR].set_handler_fn(ipi_reschedule_handler);
        idt[apic::IPI_SHOOTDOWN_VECTOR].set_handler_fn(ipi_shootdown_handler);
        idt[apic::IPI_CALL_VECTOR].set_handler_fn(ipi_call_handler);
        idt[apic::SPURIOUS_VECTOR].set_handler_fn(spurious_handler);
        idt
    });
    idt.load();
}

/// 在其他处理器上加载同一张 IDT（所有处理器共享，表本身只读）。
pub fn load() {
    if let Some(idt) = IDT.get() {
        idt.load();
    }
}

/// 断点异常：打印验证标记后返回（`int3` 是陷阱类异常，返回到下一条指令）。
extern "x86-interrupt" fn breakpoint_handler(_frame: InterruptStackFrame) {
    console::write_str("[JSR-EXC] breakpoint handler verified\n");
}

/// 双重错误：不可恢复，打印后停机。在独立 IST 栈上运行，内核栈溢出时也能执行。
extern "x86-interrupt" fn double_fault_handler(_frame: InterruptStackFrame, _code: u64) -> ! {
    console::write_str("[JSR-EXC] double fault\n");
    crate::arch::halt_forever()
}

/// 异常是否来自用户态（被打断的代码段选择子 RPL = 3）。
fn from_user(frame: &InterruptStackFrame) -> bool {
    frame.code_segment.0 & 3 == 3
}

/// 缺页：来自用户态 ⇒ 只终止该任务；来自内核态 ⇒ 缺陷，打印后停机（目前没有按需分页）。
extern "x86-interrupt" fn page_fault_handler(frame: InterruptStackFrame, _code: PageFaultErrorCode) {
    let addr = x86_64::registers::control::Cr2::read_raw();
    if from_user(&frame) {
        fault::on_user_fault(UserFault { kind: UserFaultKind::PageFault, ip: frame.instruction_pointer.as_u64(), addr });
    }
    console::_print(format_args!("[JSR-EXC] page fault ip={:#x} addr={:#x}\n", frame.instruction_pointer.as_u64(), addr));
    crate::arch::halt_forever()
}

/// 一般保护错误：用户态执行特权指令等 ⇒ 终止该任务；内核态 ⇒ 停机。
extern "x86-interrupt" fn general_protection_handler(frame: InterruptStackFrame, _code: u64) {
    if from_user(&frame) {
        fault::on_user_fault(UserFault { kind: UserFaultKind::ProtectionFault, ip: frame.instruction_pointer.as_u64(), addr: 0 });
    }
    console::_print(format_args!("[JSR-EXC] general protection ip={:#x}\n", frame.instruction_pointer.as_u64()));
    crate::arch::halt_forever()
}

/// 无效指令：用户态 ⇒ 终止该任务；内核态 ⇒ 停机。
extern "x86-interrupt" fn invalid_opcode_handler(frame: InterruptStackFrame) {
    if from_user(&frame) {
        fault::on_user_fault(UserFault { kind: UserFaultKind::InvalidInstruction, ip: frame.instruction_pointer.as_u64(), addr: 0 });
    }
    console::_print(format_args!("[JSR-EXC] invalid opcode ip={:#x}\n", frame.instruction_pointer.as_u64()));
    crate::arch::halt_forever()
}

/// 定时器中断：**先 EOI，再交给 Core**。
///
/// 顺序不可颠倒：Core 可能在这里直接抢占、切到别的任务；EOI 若放在后面，
/// 在切回本任务之前 PIC 不会再投递 IRQ0，整个系统的时钟就停了。
extern "x86-interrupt" fn timer_interrupt_handler(frame: InterruptStackFrame) {
    // SAFETY：当前正在处理的正是定时器向量。
    unsafe { pic::end_of_interrupt(pic::TIMER_VECTOR) };
    irq::on_hardware_irq(IrqLine::Timer, from_user(&frame));
}

/// 本地 APIC 定时器（每个处理器各自计时）：先 EOI，再交给 Core。
extern "x86-interrupt" fn local_timer_handler(frame: InterruptStackFrame) {
    apic::eoi();
    irq::on_hardware_irq(IrqLine::LocalTimer, from_user(&frame));
}

/// 「重新调度」核间中断。
extern "x86-interrupt" fn ipi_reschedule_handler(frame: InterruptStackFrame) {
    apic::eoi();
    irq::on_hardware_irq(IrqLine::Ipi(IpiKind::Reschedule), from_user(&frame));
}

/// 「TLB 击落」核间中断。
extern "x86-interrupt" fn ipi_shootdown_handler(frame: InterruptStackFrame) {
    apic::eoi();
    irq::on_hardware_irq(IrqLine::Ipi(IpiKind::TlbShootdown), from_user(&frame));
}

/// 「跨核调用」核间中断。
extern "x86-interrupt" fn ipi_call_handler(frame: InterruptStackFrame) {
    apic::eoi();
    irq::on_hardware_irq(IrqLine::Ipi(IpiKind::Call), from_user(&frame));
}

/// 伪中断：按规范不发 EOI，直接返回。
extern "x86-interrupt" fn spurious_handler(_frame: InterruptStackFrame) {}
