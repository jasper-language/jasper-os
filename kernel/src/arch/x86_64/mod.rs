//! x86_64 平台实现：把 [`Platform`] 契约落到具体硬件上。
//!
//! 子模块各管一类硬件，彼此不互相调用（由本文件编排）：
//! * `port`    —— `in`/`out` 端口 I/O 原语
//! * `uart`    —— COM1 16550 串口（控制台）
//! * `gdt`     —— GDT + TSS + 双重错误 IST 栈
//! * `idt`     —— IDT：异常处理与定时器中断入口
//! * `pic`     —— 8259 PIC 重映射与 EOI
//! * `pit`     —— 8253/8254 PIT 周期定时器
//! * `context` —— 任务上下文与 `switch_context` 汇编
//! * `paging`  —— 4 级页表实现的 `PageMapper`
//! * `space`   —— 地址空间（PML4）的创建、CR3 切换与销毁
//! * `user`    —— `iretq` 进入 Ring 3 与用户态探针机器码
//! * `syscall` —— `syscall`/`sysretq` 入口：MSR 设置、换栈、寄存器帧、返回前 RIP 规范性检查
//! * `apic`    —— 本地 APIC：核间中断、本地定时器（以 PIT 校准）、EOI
//! * `msi`     —— 设备 MSI：向量范围、IDT 入口、消息编码与投递
//! * `pci`     —— PCI 配置空间：传统端口机制与 ACPI MCFG ECAM（不可缓存 MMIO）
//! * `smp`     —— 多处理器：MADT 发现、实模式启动代码、INIT/启动序列、其他处理器入口
//!
//! 与 Core 的回调方向：中断入口调用 `crate::irq::on_hardware_irq`（见 `idt.rs`）；
//! 其他处理器完成平台初始化后调用 `crate::smp::secondary_main`（见 `smp.rs`）。

#[cfg(feature = "bm1-vm")]
mod bm1;
#[cfg(feature = "bm1-vm")]
pub use bm1::init as bm1_init;
mod apic;
mod context;
mod paging;
mod gdt;
mod idt;
mod ioapic;
mod msi;
mod pci;
mod pic;
mod pit;
mod space;
mod syscall;
mod port;
mod smp;
pub(crate) use smp::tlb_flush_all_local as flush_all_local_tlb;
mod uart;
mod user;

use super::{ExitStatus, PciAccess, Platform, UserProbe};

/// 设备寄存器窗口在内核高半区的位置与大小（PML4 下标 352；启动期已预分配顶级表项）。
/// 不与 ECAM 窗口（下标 288）、堆（低半区）或用户窗口重叠；2 MiB 范围内共享同一组下级页表。
const MMIO_WINDOW_BASE: u64 = 0xFFFF_B000_0000_0000;
/// 设备寄存器窗口字节数。
const MMIO_WINDOW_SIZE: u64 = 2 * 1024 * 1024;

/// x86_64 平台（零大小类型，仅作为 trait 实现的载体）。
pub struct X86_64;

impl Platform for X86_64 {
    type TaskContext = context::TaskContext;
    type Mapper = paging::X86Mapper;
    type SpaceRoot = space::SpaceRoot;

    const EMPTY_CONTEXT: Self::TaskContext = context::TaskContext::empty();

    const NAME: &'static str = "x86_64";

    /// EM_X86_64。
    const ELF_MACHINE: u16 = 62;
    const ELF_CLASS: kernel_core::elf::ElfClass = kernel_core::elf::ElfClass::Elf64;

    const USER_WINDOW: (u64, u64) = space::USER_WINDOW;

    /// 高半区：PML4 下标 256..512。
    const KERNEL_PART_ENTRIES: usize = 256;

    /// 低半区 PML4 第 136 项内（私有窗口之外；堆在创建任何用户地址空间之前建立，因而被所有空间共享）。
    const KERNEL_HEAP_BASE: u64 = 0x0000_4444_4444_0000;

    /// 低半区 PML4 第 128 项的起点（私有窗口之外，平时不映射）。
    const KERNEL_PROBE_VA: u64 = 0x0000_4000_0000_0000;

    /// 第一个非规范地址（48 位低半区之上）。
    const INVALID_VA: u64 = 0x0000_8000_0000_0000;

    fn console_init() {
        uart::init();
    }

    fn early_init() {
        gdt::init();
        crate::console::write_str("[JSR-GDT] ok\n");
        idt::init();
        crate::console::write_str("[JSR-IDT] ok\n");
        syscall::init(0);
    }

    fn timer_stretch(ticks: u32) -> bool {
        apic::arm_oneshot(ticks)
    }

    fn timer_cancel_local(){apic::cancel_local_timer()}

    unsafe fn timer_arm_after_ns(delay_ns:u64)->bool {unsafe {apic::arm_after_ns(delay_ns)}}

    fn timer_resume() {
        apic::resume_periodic();
    }

    fn irq_init(timer_hz: u32) {
        pic::init();
        pit::init(timer_hz);
    }

    fn console_write_byte(byte: u8) {
        uart::write_byte(byte);
        #[cfg(feature = "bm1-vm")]
        bm1::write_byte(byte);
    }

    #[inline(always)]
    fn irq_save_disable() -> bool {
        let was_enabled = ::x86_64::instructions::interrupts::are_enabled();
        ::x86_64::instructions::interrupts::disable();
        was_enabled
    }

    #[inline(always)]
    fn irq_restore(was_enabled: bool) {
        if was_enabled {
            ::x86_64::instructions::interrupts::enable();
        }
    }

    #[inline(always)]
    fn irq_enable() {
        ::x86_64::instructions::interrupts::enable();
    }

    #[inline(always)]
    fn irq_disable() {
        ::x86_64::instructions::interrupts::disable();
    }

    fn wait_for_interrupt() {
        // `sti; hlt` 原子组合：避免「开中断后、hlt 前」到达的中断被错过而永久睡死。
        ::x86_64::instructions::interrupts::enable_and_hlt();
    }

    fn halt_forever() -> ! {
        ::x86_64::instructions::interrupts::disable();
        loop {
            ::x86_64::instructions::hlt();
        }
    }

    fn debug_breakpoint() {
        // SAFETY：int3 只会进入已安装的断点处理程序，处理完即返回。
        unsafe { core::arch::asm!("int3", options(nomem, nostack)) };
    }

    #[inline(always)]
    unsafe fn switch_context(old: *mut Self::TaskContext, new: *const Self::TaskContext) {
        context::switch_context(old, new)
    }

    unsafe fn init_task_frame(stack_top: *mut u8, entry: extern "C" fn() -> !) -> Self::TaskContext {
        context::init_task_frame(stack_top, entry)
    }

    fn exit_emulator(status: ExitStatus) -> ! {
        #[cfg(feature = "bm1-vm")]
        bm1::finish(status);
        // QEMU `isa-debug-exit`（iobase=0xf4）：写入值 v，QEMU 以 (v << 1) | 1 退出。
        // 0x10 → 33 = 成功；0x12 → 37 = 功能全过、只有计时类断言超界；0x11 → 35 = 失败。
        #[cfg(not(feature = "bm1-vm"))]
        {
        let code: u32 = match status {
            ExitStatus::Success => 0x10,
            ExitStatus::TimingOnly => 0x12,
            ExitStatus::Failure => 0x11,
        };
        // SAFETY：0xf4 是 QEMU 调试退出设备的端口；真机上无设备，写入无副作用。
        unsafe { port::outl(0xf4, code) };
        Self::halt_forever()
        }
    }

    unsafe fn active_mapper(phys_offset: u64) -> Self::Mapper {
        paging::X86Mapper::active(phys_offset)
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
        paging::X86Mapper::for_root(root.0, phys_offset)
    }

    unsafe fn translate_in(
        root: Self::SpaceRoot,
        phys_offset: u64,
        va: u64,
    ) -> Option<(kernel_core::frame::PhysFrame, kernel_core::paging::MapFlags)> {
        paging::translate_raw(root.0, phys_offset, va)
    }

    unsafe fn switch_space(root: Self::SpaceRoot) {
        space::switch(root)
    }

    unsafe fn destroy_space(root: Self::SpaceRoot, phys_offset: u64, frames: &mut dyn kernel_core::frame::FrameAllocator) {
        space::destroy(root, phys_offset, frames)
    }

    unsafe fn prepare_kernel_space(
        root: Self::SpaceRoot,
        phys_offset: u64,
        frames: &mut dyn kernel_core::frame::FrameAllocator,
    ) -> Result<usize, kernel_core::paging::MapError> {
        space::prealloc_kernel_half(root, phys_offset, frames)
    }

    unsafe fn empty_space_root(frame: kernel_core::frame::PhysFrame, phys_offset: u64) -> Self::SpaceRoot {
        space::empty_root(frame, phys_offset)
    }

    unsafe fn kernel_part_used(root: Self::SpaceRoot, phys_offset: u64) -> usize {
        space::kernel_half_used(root, phys_offset)
    }

    fn set_kernel_stack(top: u64) {
        gdt::set_kernel_stack(top);
        syscall::set_kernel_stack(top);
    }

    fn kernel_stack() -> u64 {
        syscall::kernel_stack()
    }

    unsafe fn enter_user(entry: u64, stack: u64, arg0: u64, arg1: u64) -> ! {
        user::enter(entry, stack, arg0, arg1)
    }

    fn user_probe(probe: UserProbe) -> &'static [u8] {
        user::probe(probe)
    }

    const CPU_START_FRAME_LIMIT: Option<u64> = Some(smp::START_FRAME_LIMIT);

    fn cpu_init_boot(boot: &crate::boot::BootSpec) -> super::CpuDiscovery {
        smp::init_boot(boot)
    }

    fn pci_access(boot: &crate::boot::BootSpec) -> Option<PciAccess> {
        pci::access(boot)
    }

    unsafe fn cpu_start(
        start: &super::CpuStart<Self::SpaceRoot>,
        frame: Option<kernel_core::frame::PhysFrame>,
    ) -> Result<(), kernel_core::smp::SmpError> {
        smp::start(start, frame)
    }

    #[inline(always)]
    fn cpu_index() -> usize {
        smp::cpu_index()
    }

    fn send_ipi(cpu: usize, kind: kernel_core::smp::IpiKind) -> Result<(), kernel_core::smp::SmpError> {
        smp::send_ipi(cpu, kind)
    }

    fn tlb_flush_local(va: u64, pages: u64) {
        smp::tlb_flush_local(va, pages)
    }

    fn device_irq_count() -> usize {
        ioapic::count()
    }

    fn device_irq_name(line: usize) -> &'static str {
        ioapic::name(line)
    }

    fn device_irq_route(line: usize, cpu: usize) -> Result<(), kernel_core::irq::IrqError> {
        ioapic::route(line, cpu)
    }

    fn device_irq_set_masked(line: usize, masked: bool) {
        ioapic::set_masked(line, masked)
    }

    fn device_irq_ack(line: usize) {
        ioapic::ack(line)
    }

    fn device_irq_self_trigger(line: usize, on: bool) -> Result<(), kernel_core::irq::IrqError> {
        ioapic::self_trigger(line, on)
    }

    fn msi_vector_range() -> Option<super::MsiRange> {
        Some(msi::range())
    }

    fn msi_message(cpu: usize, vector: u8) -> Option<super::MsiMessage> {
        msi::message(cpu, vector)
    }

    fn msi_trigger(cpu: usize, vector: u8) -> Result<(), kernel_core::msi::MsiError> {
        msi::trigger(cpu, vector)
    }

    fn mmio_window() -> Option<(u64, u64)> {
        Some((MMIO_WINDOW_BASE, MMIO_WINDOW_SIZE))
    }

    #[inline(always)]
    fn cycle_counter() -> u64 {
        // 时间戳计数器（TSC）：单调递增；不是序列化指令，单次读数可能有几十个周期的乱序误差，
        // 基准取大量样本的中位数，这点误差可以忽略。
        // SAFETY：rdtsc 在内核态总是可用，没有副作用。
        unsafe { core::arch::x86_64::_rdtsc() }
    }
}

/// Poll the exclusively owned test UART between soak rounds.
#[cfg(feature = "krn1-soak")]
pub fn soak_stop_requested() -> bool {
    uart::try_read_byte() == Some(b'S')
}

#[cfg(feature="rt2-verify")]
pub(crate) fn verify_ns_programming()->bool {apic::verify_ns_programming()}
