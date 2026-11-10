//! LoongArch64 (`loongarch64-unknown-none-softfloat`) platform implementation.
//!
//! Initial slices provide a real QEMU `virt` boot, 16550 console, exception entry,
//! local timer, four-level software page tables, address spaces and cooperative
//! context switching. User-probe ABI, firmware discovery and SMP bring-up remain
//! explicit follow-up slices rather than fabricated support.

mod boot;
mod context;
mod cpu;
mod mmu;
mod pci;
mod paging;
mod smp;
mod space;
mod testdev;
mod timer;
mod tlb_refill;
mod trap;
mod uart;
mod user;

use super::{CpuDiscovery, ExitStatus, PciAccess, Platform, UserProbe};

pub struct LoongArch64;

impl Platform for LoongArch64 {
    type TaskContext = context::TaskContext;
    type Mapper = paging::La64Mapper;
    type SpaceRoot = space::SpaceRoot;

    const EMPTY_CONTEXT: Self::TaskContext = context::TaskContext::empty();
    const NAME: &'static str = "loongarch64";
    const ELF_MACHINE: u16 = 258;
    const ELF_CLASS: kernel_core::elf::ElfClass = kernel_core::elf::ElfClass::Elf64;
    const USER_WINDOW: (u64, u64) = space::USER_WINDOW;
    const KERNEL_PART_ENTRIES: usize = space::KERNEL_LAST - space::KERNEL_FIRST;
    const KERNEL_HEAP_BASE: u64 = 0x0000_4444_4444_0000;
    const KERNEL_PROBE_VA: u64 = 0x0000_4000_0000_0000;
    // With VALEN=48, bit 48 set while bit 47 is clear is non-canonical.
    const INVALID_VA: u64 = 0x0001_0000_0000_0000;

    fn console_init() {
        uart::init_mapped();
    }

    fn early_init() {
        trap::init();
        crate::console::write_str("[JSR-VEC] ok\n");
    }

    fn irq_init(timer_hz: u32) {
        timer::init(timer_hz);
    }

    fn timer_stretch(ticks: u32) -> bool {
        timer::stretch(ticks)
    }

    fn timer_resume() {
        timer::rearm()
    }

    fn console_write_byte(byte: u8) {
        uart::write_byte(byte)
    }

    #[inline(always)]
    fn irq_save_disable() -> bool {
        let enabled = cpu::irq_enabled();
        cpu::irq_mask();
        enabled
    }

    #[inline(always)]
    fn irq_restore(was_enabled: bool) {
        if was_enabled {
            cpu::irq_unmask();
        }
    }

    #[inline(always)]
    fn irq_enable() {
        cpu::irq_unmask()
    }

    #[inline(always)]
    fn irq_disable() {
        cpu::irq_mask()
    }

    fn wait_for_interrupt() {
        // SAFETY: CRMD.IE is expected to be set by the caller's idle path.
        unsafe { core::arch::asm!("idle 0", options(nostack, preserves_flags)) };
    }

    fn halt_forever() -> ! {
        loop {
            cpu::irq_mask();
            // SAFETY: interrupts are masked; wait for a debugger/NMI only.
            unsafe { core::arch::asm!("idle 0", options(nostack, preserves_flags)) };
        }
    }

    fn debug_breakpoint() {
        // SAFETY: the installed exception entry advances ERA past this instruction.
        unsafe { core::arch::asm!("break 0", options(nostack)) };
    }

    #[inline(always)]
    unsafe fn switch_context(old: *mut Self::TaskContext, new: *const Self::TaskContext) {
        context::switch_context(old, new)
    }

    unsafe fn init_task_frame(
        stack_top: *mut u8,
        entry: extern "C" fn() -> !,
    ) -> Self::TaskContext {
        context::init_task_frame(stack_top, entry)
    }

    fn exit_emulator(status: ExitStatus) -> ! {
        let code = match status {
            ExitStatus::Success => 33,
            ExitStatus::TimingOnly => 37,
            ExitStatus::Failure => 35,
        };
        crate::console::_print(format_args!("[JSR-EXIT-CODE] code={}\n", code));
        testdev::stop(code)
    }

    fn pci_access(_boot: &crate::boot::BootSpec) -> Option<PciAccess> {
        Some(pci::access())
    }

    fn mmio_window() -> Option<(u64, u64)> {
        Some((0x0000_5000_0000_0000, 2 * 1024 * 1024))
    }

    unsafe fn active_mapper(phys_offset: u64) -> Self::Mapper {
        mmu::active_mapper(phys_offset)
    }

    fn current_space() -> Self::SpaceRoot {
        space::current()
    }

    unsafe fn create_space(
        template: Self::SpaceRoot,
        phys_offset: u64,
        frames: &mut dyn kernel_core::frame::FrameAllocator,
    ) -> Result<Self::SpaceRoot, kernel_core::paging::MapError> {
        space::create(template, phys_offset, frames)
    }

    unsafe fn space_mapper(root: Self::SpaceRoot, phys_offset: u64) -> Self::Mapper {
        paging::La64Mapper::for_root(root.0, phys_offset)
    }

    unsafe fn translate_in(
        root: Self::SpaceRoot,
        phys_offset: u64,
        va: u64,
    ) -> Option<(kernel_core::frame::PhysFrame, kernel_core::paging::MapFlags)> {
        space::translate(root, phys_offset, va)
    }

    unsafe fn switch_space(root: Self::SpaceRoot) {
        space::switch(root)
    }

    unsafe fn destroy_space(
        root: Self::SpaceRoot,
        phys_offset: u64,
        frames: &mut dyn kernel_core::frame::FrameAllocator,
    ) {
        space::destroy(root, phys_offset, frames)
    }

    unsafe fn prepare_kernel_space(
        root: Self::SpaceRoot,
        phys_offset: u64,
        frames: &mut dyn kernel_core::frame::FrameAllocator,
    ) -> Result<usize, kernel_core::paging::MapError> {
        space::prealloc_kernel_part(root, phys_offset, frames)
    }

    unsafe fn empty_space_root(
        frame: kernel_core::frame::PhysFrame,
        phys_offset: u64,
    ) -> Self::SpaceRoot {
        space::empty_root(frame, phys_offset)
    }

    unsafe fn kernel_part_used(root: Self::SpaceRoot, phys_offset: u64) -> usize {
        space::kernel_part_used(root, phys_offset)
    }

    fn set_kernel_stack(top: u64) {
        user::set_kernel_stack(top)
    }

    fn kernel_stack() -> u64 {
        user::kernel_stack()
    }

    unsafe fn enter_user(entry: u64, stack: u64, arg0: u64, arg1: u64) -> ! {
        user::enter(entry, stack, arg0, arg1)
    }

    fn user_probe(probe: UserProbe) -> &'static [u8] {
        user::probe(probe)
    }

    fn cycle_counter() -> u64 {
        timer::counter()
    }

    const CPU_START_FRAME_LIMIT: Option<u64> = None;

    fn cpu_init_boot(_boot: &crate::boot::BootSpec) -> CpuDiscovery {
        smp::enable_ipi();
        smp::init_boot()
    }

    unsafe fn cpu_start(
        start: &super::CpuStart<Self::SpaceRoot>,
        _frame: Option<kernel_core::frame::PhysFrame>,
    ) -> Result<(), kernel_core::smp::SmpError> {
        smp::start_cpu(start)
    }

    fn cpu_index() -> usize {
        smp::cpu_index()
    }

    fn send_ipi(
        cpu: usize,
        kind: kernel_core::smp::IpiKind,
    ) -> Result<(), kernel_core::smp::SmpError> {
        smp::send_ipi(cpu, kind)
    }

    fn tlb_flush_local(va: u64, pages: u64) {
        smp::tlb_flush_local(va, pages)
    }

    fn device_irq_count() -> usize {
        0
    }

    fn device_irq_name(_line: usize) -> &'static str {
        "unavailable"
    }

    fn device_irq_route(
        _line: usize,
        _cpu: usize,
    ) -> Result<(), kernel_core::irq::IrqError> {
        Err(kernel_core::irq::IrqError::NoLine)
    }

    fn device_irq_set_masked(_line: usize, _masked: bool) {}

    fn device_irq_ack(_line: usize) {}

    fn device_irq_self_trigger(
        _line: usize,
        _on: bool,
    ) -> Result<(), kernel_core::irq::IrqError> {
        Err(kernel_core::irq::IrqError::NoLine)
    }
}
