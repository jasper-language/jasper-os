//! RISC-V 平台实现（RV64 与 RV32 共用）：把 [`Platform`] 契约落到监管态 + SBI 固件（QEMU `virt` 机型）上。
//! RISC-V implementation of the `Platform` contract for RV64 and RV32 (S-mode on SBI firmware, QEMU `virt`).
//!
//! 两种寄存器宽度只在 `mode` 上不同：RV64 选 `rv64.rs`（Sv39），RV32 选 `rv32.rs`（Sv32）——地址布局、页表形状、
//! 早期建表、寄存器宽度的汇编宏与系统调用返回约定都在那里；其余模块对两者一视同仁（寄存器值用 `usize`，
//! 交给 Core 时零扩展为 `u64`）。
//!
//! 子模块各管一类硬件，彼此只经本文件编排（`trap` 调用 `plic` / `timer` / `smp` 处理中断是唯一的横向依赖）：
//! * `mode`    —— 寄存器宽度专有部分（见上）
//! * `boot`    —— 入口 `_start`、BSS、设备树 → `BootSpec`，然后进入内核主流程
//! * `mmu`     —— 早期页表（内核映像恒等映射 + 线性物理内存映射）与地址转换启用
//! * `paging`  —— 页表项位格式 + 通用遍历器实现的 `PageMapper`
//! * `space`   —— 地址空间（顶级表）的创建、satp 切换与销毁
//! * `trap`    —— 陷入入口与分发（断点、系统调用、用户故障、定时器与外部中断）
//! * `plic`    —— 平台级中断控制器
//! * `timer`   —— 经 SBI 的监管态定时器与 `time` 计数器
//! * `sbi`     —— 对机器态固件的调用
//! * `smp`     —— 多处理器：设备树处理器发现、SBI HSM 唤醒、其他处理器入口、逻辑下标（`tp`）与核间中断
//! * `uart`    —— NS16550A 串口（控制台）
//! * `context` —— 任务上下文与 `switch_context` 汇编
//! * `user`    —— 进入用户态与用户态探针机器码
//! * `testdev` —— 仿真器测试设备（仿真器退出码）
//! * `cpu`     —— CSR、中断使能位、屏障的最小封装
//!
//! 与 Core 的回调方向：中断入口调用 `crate::irq::on_hardware_irq`，系统调用入口调用 `crate::syscall::on_syscall`，
//! 用户故障调用 `crate::fault::on_user_fault`（均在 `trap.rs`）；引导适配层调用 `crate::kmain::start`。
//! 内核以不带浮点扩展的目标（`riscv64imac` / `riscv32imac`）构建并关闭浮点单元：内核与用户程序都不使用浮点寄存器，
//! 切换时无需保存。

#[cfg(target_arch = "riscv64")]
#[path = "rv64.rs"]
mod mode;
#[cfg(target_arch = "riscv32")]
#[path = "rv32.rs"]
mod mode;

mod boot;
mod context;
mod cpu;
mod mmu;
mod paging;
mod plic;
mod sbi;
mod smp;
mod space;
mod testdev;
mod timer;
mod trap;
mod uart;
mod user;

use super::{ExitStatus, Platform, UserProbe};

/// RISC-V 平台（零大小类型，仅作为 trait 实现的载体）。
pub struct Riscv;

/// 测试设备退出码：与 x86_64 上 QEMU 调试退出设备产生的退出码一致（成功 33、失败 35）。
const EXIT_SUCCESS_CODE: u16 = 33;
const EXIT_FAILURE_CODE: u16 = 35;

impl Platform for Riscv {
    type TaskContext = context::TaskContext;
    type Mapper = paging::RvMapper;
    type SpaceRoot = space::SpaceRoot;

    const EMPTY_CONTEXT: Self::TaskContext = context::TaskContext::empty();

    const NAME: &'static str = mode::NAME;

    /// EM_RISCV（RV32 与 RV64 相同，以 ELF 类别区分）。
    const ELF_MACHINE: u16 = 243;
    const ELF_CLASS: kernel_core::elf::ElfClass = mode::ELF_CLASS;

    const USER_WINDOW: (u64, u64) = space::USER_WINDOW;

    /// Sv39：顶级下标 128..256；Sv32：576..704。
    const KERNEL_PART_ENTRIES: usize = mode::KERNEL_LAST - mode::KERNEL_FIRST;

    const KERNEL_HEAP_BASE: u64 = mode::KERNEL_HEAP_BASE;

    const KERNEL_PROBE_VA: u64 = mode::KERNEL_PROBE_VA;

    const INVALID_VA: u64 = mode::INVALID_VA;

    fn console_init() {
        uart::init();
    }

    fn early_init() {
        trap::init();
        crate::console::write_str("[JSR-VEC] ok\n");
    }

    fn irq_init(timer_hz: u32) {
        if !timer::available() {
            crate::console::write_str("[JSR-IRQ] timer unavailable (no timebase-frequency or SBI TIME extension)\n");
            Self::exit_emulator(ExitStatus::Failure);
        }
        match plic::init() {
            Some(t) if t.claimed == t.source && t.drained => crate::console::_print(format_args!(
                "[JSR-PLIC] ok source={} claimed={} completed=true drained={}\n",
                t.source, t.claimed, t.drained
            )),
            Some(t) => {
                crate::console::_print(format_args!(
                    "[JSR-PLIC] self-test failed source={} claimed={} drained={}\n",
                    t.source, t.claimed, t.drained
                ));
                Self::exit_emulator(ExitStatus::Failure);
            }
            None => {
                crate::console::write_str("[JSR-PLIC] interrupt controller unavailable\n");
                Self::exit_emulator(ExitStatus::Failure);
            }
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
        // 先关中断再 `wfi`：sie 中已使能的中断挂起时，即使 sstatus.SIE = 0 也会唤醒 `wfi`；随后开中断，中断在此被处理。
        // 因此「判断要等待」与「睡下」之间到达的中断不会被错过（等价于 x86 的 `sti; hlt`）。
        cpu::irq_mask();
        // SAFETY：wfi 只让处理器等待中断，没有其他副作用。
        unsafe { core::arch::asm!("wfi", options(nomem, nostack, preserves_flags)) };
        cpu::irq_unmask();
    }

    fn halt_forever() -> ! {
        cpu::irq_mask();
        loop {
            // SAFETY：中断已关闭，wfi 只让处理器停在这里。
            unsafe { core::arch::asm!("wfi", options(nomem, nostack, preserves_flags)) };
        }
    }

    fn debug_breakpoint() {
        // SAFETY：ebreak 只会进入已安装的陷入处理，处理程序越过本指令后返回。
        unsafe { core::arch::asm!("ebreak", options(nomem, nostack)) };
    }

    #[inline(always)]
    unsafe fn switch_context(old: *mut Self::TaskContext, new: *const Self::TaskContext) {
        context::switch_context(old, new)
    }

    unsafe fn init_task_frame(stack_top: *mut u8, entry: extern "C" fn() -> !) -> Self::TaskContext {
        context::init_task_frame(stack_top, entry)
    }

    fn exit_emulator(status: ExitStatus) -> ! {
        testdev::exit(match status {
            ExitStatus::Success => EXIT_SUCCESS_CODE,
            ExitStatus::Failure => EXIT_FAILURE_CODE,
        })
    }

    unsafe fn active_mapper(phys_offset: u64) -> Self::Mapper {
        paging::RvMapper::for_root(space::current().0, phys_offset)
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
        paging::RvMapper::for_root(root.0, phys_offset)
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

    fn kernel_stack() -> u64 {
        user::kernel_stack()
    }

    unsafe fn enter_user(entry: u64, stack: u64, arg0: u64, arg1: u64) -> ! {
        user::enter(entry, stack, arg0, arg1)
    }

    fn user_probe(probe: UserProbe) -> &'static [u8] {
        user::probe(probe)
    }

    // ---- 多处理器 ----
    // 拓扑来自设备树处理器节点，唤醒经 SBI HSM hart_start，核间中断是经 SBI IPI 触发的监管态软件中断（见 `smp.rs`）。

    const CPU_START_FRAME_LIMIT: Option<u64> = None;

    fn cpu_init_boot(_boot: &crate::boot::BootSpec) -> super::CpuDiscovery {
        smp::init_boot(boot::BOOT_HART.load(core::sync::atomic::Ordering::Relaxed))
    }

    unsafe fn cpu_start(
        start: &super::CpuStart<Self::SpaceRoot>,
        _frame: Option<kernel_core::frame::PhysFrame>,
    ) -> Result<(), kernel_core::smp::SmpError> {
        smp::start(start)
    }

    #[inline(always)]
    fn cpu_index() -> usize {
        smp::cpu_index()
    }

    fn send_ipi(cpu: usize, kind: kernel_core::smp::IpiKind) -> Result<(), kernel_core::smp::SmpError> {
        smp::send_ipi(cpu, kind)
    }

    fn tlb_flush_local(va: u64, pages: u64) {
        for i in 0..pages {
            cpu::tlb_flush_page(va.wrapping_add(i * 4096));
        }
    }

    #[inline(always)]
    fn cycle_counter() -> u64 {
        // `time` 计数器：单调递增、频率固定（见设备树 timebase-frequency），分辨率低于处理器周期；基准以 tick 校准后使用。
        timer::counter()
    }
}
