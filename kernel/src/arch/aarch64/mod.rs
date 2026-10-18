//! AArch64 平台实现：把 [`Platform`] 契约落到 ARMv8-A（QEMU `virt` 机型）上。
//! AArch64 implementation of the `Platform` contract (ARMv8-A, QEMU `virt`).
//!
//! 子模块各管一类硬件，彼此只经本文件编排（`vectors` 调用 `gic` / `timer` 处理中断是唯一的横向依赖）：
//! * `boot`     —— 入口 `_start`、EL2→EL1、BSS、设备树 → `BootSpec`，然后进入内核主流程
//! * `mmu`      —— 早期页表（内核映像恒等映射 + 全物理内存映射）与 MMU 启用
//! * `paging`   —— 描述符位格式 + 通用遍历器实现的 `PageMapper`
//! * `space`    —— 地址空间（顶级表）的创建、TTBR0 切换与销毁
//! * `vectors`  —— 异常向量表与陷入分发（断点、系统调用、用户故障、IRQ）
//! * `gic`      —— GICv2 中断控制器
//! * `timer`    —— 通用定时器（虚拟定时器）
//! * `uart`     —— PL011 串口（控制台）
//! * `context`  —— 任务上下文与 `switch_context` 汇编
//! * `user`     —— 进入 EL0 与用户态探针机器码
//! * `semihost` —— 半主机退出（仿真器退出码）
//! * `cpu`      —— 系统寄存器、中断屏蔽位、屏障的最小封装
//!
//! 与 Core 的回调方向：中断入口调用 `crate::irq::on_hardware_irq`，系统调用入口调用 `crate::syscall::on_syscall`，
//! 用户故障调用 `crate::fault::on_user_fault`（均在 `vectors.rs`）；引导适配层调用 `crate::kmain::start`。

mod boot;
mod context;
mod cpu;
mod gic;
mod mmu;
mod paging;
mod semihost;
mod space;
mod timer;
mod uart;
mod user;
mod vectors;

use super::{ExitStatus, Platform, UserProbe};

/// AArch64 平台（零大小类型，仅作为 trait 实现的载体）。
pub struct Aarch64;

/// 半主机退出码：与 x86_64 上 QEMU 调试退出设备产生的退出码一致（成功 33、失败 35）。
const EXIT_SUCCESS_CODE: u32 = 33;
const EXIT_FAILURE_CODE: u32 = 35;

impl Platform for Aarch64 {
    type TaskContext = context::TaskContext;
    type Mapper = paging::A64Mapper;
    type SpaceRoot = space::SpaceRoot;

    const EMPTY_CONTEXT: Self::TaskContext = context::TaskContext::empty();

    const NAME: &'static str = "aarch64";

    /// EM_AARCH64。
    const ELF_MACHINE: u16 = 183;

    const USER_WINDOW: (u64, u64) = space::USER_WINDOW;

    /// 顶级下标 128..256。
    const KERNEL_PART_ENTRIES: usize = space::KERNEL_LAST - space::KERNEL_FIRST;

    fn console_init() {
        uart::init();
    }

    fn early_init() {
        vectors::init();
        crate::console::write_str("[JSR-VEC] ok\n");
    }

    fn irq_init(timer_hz: u32) {
        let ppi = timer::interrupt();
        if !ppi.is_some_and(gic::init) {
            crate::console::write_str("[JSR-IRQ] interrupt controller or timer interrupt unavailable\n");
            Self::exit_emulator(ExitStatus::Failure);
        }
        timer::init(timer_hz);
    }

    fn console_write_byte(byte: u8) {
        uart::write_byte(byte);
    }

    #[inline(always)]
    fn irq_save_disable() -> bool {
        let was = cpu::irq_enabled();
        cpu::irq_mask();
        was
    }

    #[inline(always)]
    fn irq_restore(was_enabled: bool) {
        if was_enabled {
            cpu::irq_unmask();
        }
    }

    #[inline(always)]
    fn irq_enable() {
        cpu::irq_unmask();
    }

    #[inline(always)]
    fn irq_disable() {
        cpu::irq_mask();
    }

    fn wait_for_interrupt() {
        // 先屏蔽再 `wfi`：待处理的中断即使被屏蔽也会唤醒 `wfi`；随后解除屏蔽，中断在此被处理。
        // 因此「判断要等待」与「睡下」之间到达的中断不会被错过（等价于 x86 的 `sti; hlt`）。
        cpu::irq_mask();
        // SAFETY：wfi 只让处理器等待中断，没有其他副作用。
        unsafe { core::arch::asm!("wfi", options(nomem, nostack, preserves_flags)) };
        cpu::irq_unmask();
        cpu::isb();
    }

    fn halt_forever() -> ! {
        cpu::irq_mask();
        loop {
            // SAFETY：中断已屏蔽，wfi 只让处理器停在这里。
            unsafe { core::arch::asm!("wfi", options(nomem, nostack, preserves_flags)) };
        }
    }

    fn debug_breakpoint() {
        // SAFETY：brk 只会进入已安装的同步异常处理，处理程序越过本指令后返回。
        unsafe { core::arch::asm!("brk #0", options(nomem, nostack)) };
    }

    #[inline(always)]
    unsafe fn switch_context(old: *mut Self::TaskContext, new: *const Self::TaskContext) {
        context::switch_context(old, new)
    }

    unsafe fn init_task_frame(stack_top: *mut u8, entry: extern "C" fn() -> !) -> Self::TaskContext {
        context::init_task_frame(stack_top, entry)
    }

    fn exit_emulator(status: ExitStatus) -> ! {
        semihost::exit(match status {
            ExitStatus::Success => EXIT_SUCCESS_CODE,
            ExitStatus::Failure => EXIT_FAILURE_CODE,
        })
    }

    unsafe fn active_mapper(phys_offset: u64) -> Self::Mapper {
        paging::A64Mapper::for_root(space::current().0, phys_offset)
    }

    fn current_space() -> Self::SpaceRoot {
        space::current()
    }

    unsafe fn create_space(
        phys_offset: u64,
        frames: &mut dyn kernel_core::frame::FrameAllocator,
    ) -> Result<Self::SpaceRoot, kernel_core::paging::MapError> {
        space::create(phys_offset, frames)
    }

    unsafe fn space_mapper(root: Self::SpaceRoot, phys_offset: u64) -> Self::Mapper {
        paging::A64Mapper::for_root(root.0, phys_offset)
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

    unsafe fn destroy_space(root: Self::SpaceRoot, phys_offset: u64, frames: &mut dyn kernel_core::frame::FrameAllocator) {
        space::destroy(root, phys_offset, frames)
    }

    unsafe fn prepare_kernel_space(
        root: Self::SpaceRoot,
        phys_offset: u64,
        frames: &mut dyn kernel_core::frame::FrameAllocator,
    ) -> Result<usize, kernel_core::paging::MapError> {
        space::prealloc_kernel_part(root, phys_offset, frames)
    }

    unsafe fn empty_space_root(frame: kernel_core::frame::PhysFrame, phys_offset: u64) -> Self::SpaceRoot {
        space::empty_root(frame, phys_offset)
    }

    unsafe fn kernel_part_used(root: Self::SpaceRoot, phys_offset: u64) -> usize {
        space::kernel_part_used(root, phys_offset)
    }

    fn set_kernel_stack(top: u64) {
        user::set_kernel_stack(top);
    }

    unsafe fn enter_user(entry: u64, stack: u64, arg0: u64, arg1: u64) -> ! {
        user::enter(entry, stack, arg0, arg1)
    }

    fn user_probe(probe: UserProbe) -> &'static [u8] {
        user::probe(probe)
    }

    #[inline(always)]
    fn cycle_counter() -> u64 {
        // 虚拟计数器：单调递增、频率固定（见 cntfrq_el0），分辨率低于处理器周期；基准以 tick 校准后使用。
        timer::counter()
    }
}
