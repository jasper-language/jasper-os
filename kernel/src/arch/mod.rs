//! 架构抽象层（arch）：内核 Core 与具体指令集之间的**唯一接缝**。
//!
//! 设计约束（设计约束「多指令集」）：
//! * x86_64 只是先行验证平台；aarch64、RISC-V 及未来自研芯片都是目标。
//! * 一切 ISA 相关代码（启动、描述符表 / 异常向量、中断控制器、定时器、上下文切换汇编、
//!   端口 I/O、串口、仿真器退出）只允许出现在 `arch/<isa>/` 下。
//! * Core 只通过本文件导出的函数与类型使用硬件，**不得**出现 `x86_64::`、`asm!`、端口号、
//!   具体中断向量号。`verify-m1.4b.sh` 用 grep 机械检查这一点。
//!
//! 结构：
//! * [`Platform`] trait —— 每个 ISA 必须实现的完整契约。用 trait 而不是「约定同名函数」，
//!   是为了让新增一个 ISA 时缺少任何一项都会**编译失败**，而不是运行时才发现。
//! * [`Current`] —— 按 `target_arch` 选出的当前实现（编译期选择，零运行时开销）。
//! * 下方的自由函数 —— 对 `Current` 的薄包装，让 Core 的调用点简短、且不必 `use` trait。
//!
//! 新增一个 ISA = 新建 `arch/<isa>/` 并 `impl Platform`，再在下面加一行 `cfg` 选择；Core 不改。

#[cfg(target_arch = "x86_64")]
pub mod x86_64;
#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(any(target_arch = "riscv64", target_arch = "riscv32"))]
pub mod riscv;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64", target_arch = "riscv32"))]
pub mod phys_tables;

/// 当前编译目标的平台实现。
#[cfg(target_arch = "x86_64")]
pub use self::x86_64::X86_64 as Current;
/// 当前编译目标的平台实现。
#[cfg(target_arch = "aarch64")]
pub use self::aarch64::Aarch64 as Current;
/// 当前编译目标的平台实现。
#[cfg(any(target_arch = "riscv64", target_arch = "riscv32"))]
pub use self::riscv::Riscv as Current;

/// 当前平台的任务上下文类型（切换时需要保存的寄存器集合）。
pub type TaskContext = <Current as Platform>::TaskContext;
/// 当前平台的页映射器类型。
pub type Mapper = <Current as Platform>::Mapper;
/// 当前平台的地址空间根类型。
pub type SpaceRoot = <Current as Platform>::SpaceRoot;
/// 每个地址空间私有的虚拟窗口，见 [`Platform::USER_WINDOW`]。
pub const USER_WINDOW: (u64, u64) = <Current as Platform>::USER_WINDOW;
/// 内核共享部分的顶级表项数，见 [`Platform::KERNEL_PART_ENTRIES`]。
pub const KERNEL_PART_ENTRIES: usize = <Current as Platform>::KERNEL_PART_ENTRIES;
/// 内核堆虚拟区起点，见 [`Platform::KERNEL_HEAP_BASE`]。
pub const KERNEL_HEAP_BASE: u64 = <Current as Platform>::KERNEL_HEAP_BASE;
/// 私有窗口之外的演练地址，见 [`Platform::KERNEL_PROBE_VA`]。
pub const KERNEL_PROBE_VA: u64 = <Current as Platform>::KERNEL_PROBE_VA;
/// 超出可用虚拟地址范围的地址，见 [`Platform::INVALID_VA`]。
pub const INVALID_VA: u64 = <Current as Platform>::INVALID_VA;

/// 用户态探针程序（M3.1 验收用的最小用户代码；每个 ISA 各自提供机器码）。
///
/// 约定：进入用户态时第一个参数寄存器 = 用户数据页地址，第二个 = 参数。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserProbe {
    /// 把当前代码段选择子（含特权级）写到数据页 `[0]`、标记 `[8]=0x55aa`，然后执行无效指令。
    ReportPrivilege,
    /// 读取参数给出的地址写到 `[0]`、标记 `[8]=0x1eaf`，然后执行无效指令（读内核地址时应在读处就被终止）。
    ReadAddress,
    /// 标记 `[8]=0x7e57` 后执行特权指令（应被终止，后续标记 `[16]` 不得出现）。
    Privileged,
    /// 系统调用冒烟：`[0]`=time.now 结果，`[8]`=未登记 ID 的返回值，`[16]`=未授权调用的返回值，
    /// `[24]`/`[32]`=调用前后应保留的寄存器值，最后以退出码 42 调用 task.exit（之后的指令不得执行）。
    SyscallSmoke,
    /// 用户指针：依次以 6 种指针调用 console.write，返回值写到 `[0..48)`，然后 task.exit(0)。
    /// 数据页 `0xF8` 处是合法文本长度、`0x100` 起是合法 UTF-8 文本、`0x200` 起是非法 UTF-8；参数 = 一个内核地址。
    UserPointers,
    /// 进程与线程：主线程经 task.spawn 在同一进程创建工作线程（参数 = 工作线程栈顶），
    /// 两者经共享数据页协作；主线程随后两次关闭线程句柄并以退出码 7 退出。
    /// 数据页：`[0]` 句柄、`[8]` 工作线程标记、`[16]` 完成标志、`[24]` 主线程标记、`[32]`/`[40]` 两次关闭的返回值。
    ProcessThreads,
    /// 句柄权限：经 task.spawn 取得线程句柄 h（WAIT|CONTROL|DUPLICATE|TRANSFER），依次：
    /// `[0]`=h，`[8]`=duplicate(h, WAIT|DUPLICATE)，`[16]`=duplicate(h2, WAIT|TRANSFER)（提权，应被拒），
    /// `[24]`=restrict(h2, WAIT)，`[32]`=duplicate(h2, WAIT)（已无 DUPLICATE，应被拒），
    /// `[40]`=restrict(h2, WAIT|CONTROL)（经 restrict 提权，应被拒）；随后关闭句柄并 task.exit(0)。
    HandleRights,
}

/// 处理器启动命令：Core 准备好资源，平台执行硬件启动序列。
/// Processor start command prepared by the Core and executed by the platform.
#[derive(Debug, Clone, Copy)]
pub struct CpuStart<S> {
    /// 逻辑下标（引导处理器为 0）。
    pub index: usize,
    /// 硬件标识。
    pub hw_id: u32,
    /// 该处理器空闲执行流的栈顶（Core 分配，16 字节对齐）。
    pub stack_top: u64,
    /// 启动后使用的地址空间（内核空间）。
    pub space: S,
    /// 本地定时器频率。
    pub timer_hz: u32,
}

/// 处理器发现结果。
/// Result of processor discovery.
#[derive(Debug, Clone, Copy)]
pub struct CpuDiscovery {
    /// 逻辑下标 ↔ 硬件标识（引导处理器在下标 0）。
    pub topology: kernel_core::smp::Topology,
    /// 信息来源或失败原因的规范名（例如固件表名、解析错误名）。
    pub source: &'static str,
}

/// 仿真器 / 测试退出状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    /// 验收成功（QEMU 退出码 33）。
    Success,
    /// 验收失败。
    Failure,
}

/// 每个指令集必须实现的平台契约。
///
/// 所有方法都是关联函数（无 `self`）：平台是全局唯一的硬件，不是可实例化的对象。
pub trait Platform {
    /// 任务上下文：该 ISA 在协作式切换时需要保存的寄存器（至少包含栈指针）。
    type TaskContext: Copy;

    /// 该 ISA 的页映射器（实现 Core 的 `PageMapper` 契约；x86_64 为 4 级页表）。
    type Mapper: kernel_core::paging::PageMapper + Send;

    /// 地址空间根的不透明句柄（x86_64 为 PML4 物理地址；Core 不解释它）。
    type SpaceRoot: Copy + Eq + Send + core::fmt::Debug;

    /// 每个地址空间私有的虚拟窗口 `[start, end)`；窗口外的映射在所有空间共享（内核部分）。
    const USER_WINDOW: (u64, u64);

    /// 内核共享部分（[`Platform::prepare_kernel_space`] 预分配的范围）的顶级表项数。
    /// Number of top-level entries in the shared kernel part.
    const KERNEL_PART_ENTRIES: usize;

    /// 内核堆虚拟区的起点（页对齐，位于私有窗口之外、所有地址空间共享的内核区域，且其后至少留出堆上限大小的空间）。
    /// 各 ISA 可用的虚拟地址位数不同（如 RISC-V Sv39 的低半区只有 256 GiB），因此由平台给出。
    /// Start of the kernel heap's virtual range, outside the private window.
    const KERNEL_HEAP_BASE: u64;

    /// 私有窗口之外一个平时不映射的页地址（映射演练与「私有窗口外」负向用例用），与堆区不重叠。
    /// An otherwise unused page address outside the private window (mapping self-tests).
    const KERNEL_PROBE_VA: u64;

    /// 超出本平台可用虚拟地址范围的地址：任何映射请求都必须以「无效地址」被拒绝。
    /// An address beyond the usable virtual range; every map request for it must be rejected.
    const INVALID_VA: u64;

    /// 空上下文（`const`，供静态任务表初始化）。
    const EMPTY_CONTEXT: Self::TaskContext;

    /// 架构名（横幅与诊断输出用），如 `"x86_64"`。
    const NAME: &'static str;

    /// 本架构可执行文件的 ELF `e_machine` 值（装载器据此拒绝其他架构的程序）。
    const ELF_MACHINE: u16;

    /// 本架构用户程序的 ELF 类别（32 位或 64 位，随用户态地址宽度而定；装载器拒绝另一种类别）。
    /// ELF class of this ISA's user programs.
    const ELF_CLASS: kernel_core::elf::ElfClass;

    /// 初始化早期控制台。之后即可打印（最先调用）。
    fn console_init();

    /// 早期初始化：描述符表 / 异常向量 / 系统调用入口。之后即可安全捕获异常，
    /// 用户态发起的系统调用一律交给 `crate::syscall::on_syscall`。
    fn early_init();

    /// 中断初始化：中断控制器与周期定时器（`timer_hz` 为目标频率）。不打开中断。
    fn irq_init(timer_hz: u32);

    /// 向控制台输出一个字节（阻塞直到设备可写）。调用者负责中断临界区。
    fn console_write_byte(byte: u8);

    /// 关中断并返回之前是否开着。
    fn irq_save_disable() -> bool;
    /// 按 [`Platform::irq_save_disable`] 的返回值恢复中断状态。
    fn irq_restore(was_enabled: bool);
    /// 开中断。
    fn irq_enable();
    /// 关中断。
    fn irq_disable();
    /// 原子地「开中断并休眠到下一个中断」（x86 `sti; hlt`），返回时中断仍开着。
    fn wait_for_interrupt();
    /// 关中断并永久停机。
    fn halt_forever() -> !;

    /// 主动触发一次调试断点异常（用于证明异常处理已接通）。
    fn debug_breakpoint();

    /// 保存当前 callee-saved 寄存器到 `old`，从 `new` 恢复并跳转。
    ///
    /// # Safety
    /// `old`/`new` 必须指向有效且在切换期间不会移动的上下文；`new` 必须来自
    /// [`Platform::init_task_frame`] 或上一次 `switch_context` 的保存。
    unsafe fn switch_context(old: *mut Self::TaskContext, new: *const Self::TaskContext);

    /// 在 `stack_top`（16 字节对齐的栈顶）上伪造首次切入帧，使切入后从 `entry` 开始执行。
    ///
    /// # Safety
    /// 该栈此刻不得有任何执行流在使用。
    unsafe fn init_task_frame(stack_top: *mut u8, entry: extern "C" fn() -> !) -> Self::TaskContext;

    /// 通知仿真器退出（真机上等同于停机）。
    fn exit_emulator(status: ExitStatus) -> !;

    /// 为**当前活动**地址空间建立页映射器。
    ///
    /// # Safety
    /// `phys_offset` 必须是引导器建立的全物理内存映射偏移；同一地址空间同时只能存在一个映射器。
    unsafe fn active_mapper(phys_offset: u64) -> Self::Mapper;

    /// 当前活动的地址空间。
    fn current_space() -> Self::SpaceRoot;

    /// 新建地址空间：私有窗口为空，窗口外共享模板空间 `template`（内核地址空间）的映射。
    ///
    /// 模板显式给出而不取「当前空间」：创建可能发生在用户进程的系统调用里（当前空间是该进程的），
    /// 那时当前空间的私有窗口并不为空。
    /// Creates an address space whose non-private part is shared with `template` (the kernel space).
    ///
    /// # Safety
    /// `phys_offset` 必须是全物理内存映射偏移；`template` 必须是有效的地址空间根，且私有窗口为空。
    unsafe fn create_space(
        template: Self::SpaceRoot,
        phys_offset: u64,
        frames: &mut dyn kernel_core::frame::FrameAllocator,
    ) -> Result<Self::SpaceRoot, kernel_core::paging::MapError>;

    /// 为任意地址空间（不必是活动的）建立映射器。只能用它修改**私有窗口**内的映射。
    ///
    /// # Safety
    /// 同 [`Platform::active_mapper`]；`root` 必须有效。
    unsafe fn space_mapper(root: Self::SpaceRoot, phys_offset: u64) -> Self::Mapper;

    /// 只读查询任意地址空间（不必是活动的）中 `va` 所在页的映射与**有效**权限。
    /// 实现不得为该空间构造可修改页表的映射器或可变引用（避免与其属主形成可变别名）。
    /// Read-only translation in any space; must not alias the owner's mutable mapper.
    ///
    /// # Safety
    /// `root` 必须有效，调用期间其页表不被并发修改。
    unsafe fn translate_in(
        root: Self::SpaceRoot,
        phys_offset: u64,
        va: u64,
    ) -> Option<(kernel_core::frame::PhysFrame, kernel_core::paging::MapFlags)>;

    /// 切换到 `root`。
    ///
    /// # Safety
    /// `root` 必须有效且包含当前代码与栈的映射（共享的内核部分满足这一点）。
    unsafe fn switch_space(root: Self::SpaceRoot);

    /// 销毁地址空间，释放其私有窗口内的页表帧与根表（叶子数据帧由所有者负责）。
    ///
    /// # Safety
    /// `root` 不能是活动空间，且此后不得再使用。
    unsafe fn destroy_space(root: Self::SpaceRoot, phys_offset: u64, frames: &mut dyn kernel_core::frame::FrameAllocator);

    /// 预分配 `root` 中内核共享部分的全部顶级表项，使之后新增的内核映射对所有地址空间可见。
    /// 必须**全有或全无**：失败时 `root` 不被修改，本次分配的帧全部归还。返回新安装的表项数。
    /// Pre-populate the shared kernel part of `root`; all-or-nothing.
    ///
    /// # Safety
    /// `root` 必须是有效的顶级表；对内核空间须在创建任何其他地址空间之前调用一次。
    unsafe fn prepare_kernel_space(
        root: Self::SpaceRoot,
        phys_offset: u64,
        frames: &mut dyn kernel_core::frame::FrameAllocator,
    ) -> Result<usize, kernel_core::paging::MapError>;

    /// 把一个独占的物理帧清零并当作空的顶级表（自检用的临时根，不会被激活）。
    /// Zero an exclusively owned frame and use it as an empty top-level table (self-test scratch root).
    ///
    /// # Safety
    /// `frame` 必须由调用者独占且未被任何页表引用。
    unsafe fn empty_space_root(frame: kernel_core::frame::PhysFrame, phys_offset: u64) -> Self::SpaceRoot;

    /// `root` 内核共享部分已使用的顶级表项数（自检用）。
    /// Number of used top-level entries in the shared kernel part of `root`.
    ///
    /// # Safety
    /// `root` 必须是有效的顶级表。
    unsafe fn kernel_part_used(root: Self::SpaceRoot, phys_offset: u64) -> usize;

    /// 设置**本处理器**「从用户态进入内核时使用的内核栈顶」（调度器在每次切换任务时调用；每核一份，互不覆盖）。
    fn set_kernel_stack(top: u64);

    /// 本处理器当前登记的内核栈顶（从入口实际读取的位置读出；未设置时为 0）。
    /// Kernel stack top currently registered for the executing processor.
    fn kernel_stack() -> u64;

    /// 进入用户态执行（永不返回；回到内核只能经中断、异常或系统调用）。
    ///
    /// # Safety
    /// 当前地址空间中 `entry` 必须为用户可执行、`stack` 之下为用户可写；内核栈顶必须已设置。
    unsafe fn enter_user(entry: u64, stack: u64, arg0: u64, arg1: u64) -> !;

    /// 取某个用户态探针程序的机器码。
    fn user_probe(probe: UserProbe) -> &'static [u8];

    /// 读取单调递增的周期计数器（基准测量用）。单位由平台决定，调用者须以定时器 tick 校准后才能换算成时间。
    /// Read a monotonically increasing cycle counter; calibrate against timer ticks before converting to time.
    fn cycle_counter() -> u64;

    // ---- 多处理器 ----

    /// 启动其他处理器需要的低端启动帧上限：`Some(limit)` 表示需要一个起始地址低于 `limit` 的物理帧，
    /// 启动期间由 Core 在内核空间中以「虚拟地址 = 物理地址」映射为可写可执行；`None` 表示不需要。
    /// Upper bound of the low start-up frame the platform needs, if any.
    const CPU_START_FRAME_LIMIT: Option<u64>;

    /// 在引导处理器上初始化核间中断控制器并发现全部处理器（只调用一次）。
    /// Initialise the boot processor's IPI controller and discover all processors.
    fn cpu_init_boot(boot: &crate::boot::BootSpec) -> CpuDiscovery;

    /// 启动一个处理器：它完成本处理器的平台初始化后调用 `crate::smp::secondary_main(index)`。
    /// 返回时启动命令已发出；是否报到由 Core 等待判定。
    ///
    /// # Safety
    /// `start.stack_top` 必须是专属于该处理器的有效栈；`frame` 满足 [`Platform::CPU_START_FRAME_LIMIT`]
    /// 并已按其要求映射；同一时刻只启动一个处理器。
    /// Start one processor.
    unsafe fn cpu_start(
        start: &CpuStart<Self::SpaceRoot>,
        frame: Option<kernel_core::frame::PhysFrame>,
    ) -> Result<(), kernel_core::smp::SmpError>;

    /// 当前处理器的逻辑下标（多处理器未初始化时为 0）。
    /// Logical index of the executing processor.
    fn cpu_index() -> usize;

    /// 向逻辑下标为 `cpu` 的处理器发送核间中断。
    /// Send an inter-processor interrupt to processor `cpu`.
    fn send_ipi(cpu: usize, kind: kernel_core::smp::IpiKind) -> Result<(), kernel_core::smp::SmpError>;

    /// 作废本处理器上 `[va, va + pages × 4 KiB)` 的 TLB 项（所有地址空间）。
    /// Invalidate local TLB entries for the given page range.
    fn tlb_flush_local(va: u64, pages: u64);

    // ---- 设备中断 ----
    // 设备中断线是平台给出的下标 0..device_irq_count()；它与具体中断号 / 输入线的对应只在平台内部。
    // 平台的中断入口对设备中断调用 `crate::irq::on_device_irq(line)`，**在 EOI / 完成之前**，且不在其中切换任务。

    /// 平台已发现并接好的可路由设备中断线数（未初始化或没有时为 0）。
    /// Number of routable device interrupt lines.
    fn device_irq_count() -> usize;

    /// 设备中断线的规范名（诊断输出用）。
    /// Canonical name of a device line.
    fn device_irq_name(line: usize) -> &'static str;

    /// 把设备中断线路由到逻辑下标为 `cpu` 的处理器（只改中断控制器的目标，不改屏蔽状态）。
    /// 线号不存在返回 `NoLine`；目标处理器不可寻址返回 `RouteFailed`，此时硬件不变。
    /// Route a device line to processor `cpu`.
    fn device_irq_route(line: usize, cpu: usize) -> Result<(), kernel_core::irq::IrqError>;

    /// 在中断控制器上屏蔽 / 解除屏蔽。解除时重新检查设备：屏蔽期间未送达的中断条件必须重新触发，不得丢失。
    /// 线号不存在时什么都不做。
    /// Mask or unmask a device line at the interrupt controller.
    fn device_irq_set_masked(line: usize, masked: bool);

    /// 设备侧确认（由 Core 在处理窗口内调用）：清除设备的中断条件；持续自触发打开时立即重新触发下一次。
    /// Acknowledge the interrupt condition at the device.
    fn device_irq_ack(line: usize);

    /// 打开 / 关闭设备的持续自触发：设备在每次确认之后立即再次请求中断（中断风暴演练与自检用）。
    /// Turn a device's continuous self-trigger on or off.
    fn device_irq_self_trigger(line: usize, on: bool) -> Result<(), kernel_core::irq::IrqError>;
}

// ---- Core 使用的薄包装（避免各处 `use Platform` 与冗长的 `<Current as Platform>::`）----

/// 当前架构名，见 [`Platform::NAME`]。
pub const NAME: &str = <Current as Platform>::NAME;
/// 当前架构的 ELF 机器类型，见 [`Platform::ELF_MACHINE`]。
pub const ELF_MACHINE: u16 = <Current as Platform>::ELF_MACHINE;
/// 当前架构用户程序的 ELF 类别，见 [`Platform::ELF_CLASS`]。
pub const ELF_CLASS: kernel_core::elf::ElfClass = <Current as Platform>::ELF_CLASS;
/// 当前架构的空任务上下文，见 [`Platform::EMPTY_CONTEXT`]。
pub const EMPTY_CONTEXT: TaskContext = <Current as Platform>::EMPTY_CONTEXT;

/// 见 [`Platform::console_init`]。
pub fn console_init() {
    Current::console_init()
}
/// 见 [`Platform::early_init`]。
pub fn early_init() {
    Current::early_init()
}
/// 见 [`Platform::irq_init`]。
pub fn irq_init(timer_hz: u32) {
    Current::irq_init(timer_hz)
}
/// 见 [`Platform::console_write_byte`]。
pub fn console_write_byte(byte: u8) {
    Current::console_write_byte(byte)
}
/// 见 [`Platform::irq_save_disable`]。
#[inline(always)]
pub fn irq_save_disable() -> bool {
    let was = Current::irq_save_disable();
    // WCET 证据：关中断窗口从这一刻开始计时（嵌套由 wcet 内部的深度计数处理）。
    crate::wcet::irq_off_enter();
    was
}
/// 见 [`Platform::irq_restore`]。
#[inline(always)]
pub fn irq_restore(was_enabled: bool) {
    // 与 `irq_save_disable` 严格配对：无论之前是否已关中断都要结算，
    // 否则嵌套深度会只增不减（上次实现就是这样导致样本数恒为 0）。
    crate::wcet::irq_off_exit();
    Current::irq_restore(was_enabled)
}
/// 见 [`Platform::irq_enable`]。
#[inline(always)]
pub fn irq_enable() {
    Current::irq_enable()
}
/// 见 [`Platform::irq_disable`]。
#[inline(always)]
pub fn irq_disable() {
    Current::irq_disable()
}
/// 在关中断状态下执行 `f`，结束后恢复原状态（单 CPU 临界区）。
#[inline(always)]
pub fn without_irq<R>(f: impl FnOnce() -> R) -> R {
    let was = irq_save_disable();
    let r = f();
    irq_restore(was);
    r
}
/// 见 [`Platform::wait_for_interrupt`]。
pub fn wait_for_interrupt() {
    Current::wait_for_interrupt()
}
/// 见 [`Platform::halt_forever`]。
pub fn halt_forever() -> ! {
    Current::halt_forever()
}
/// 见 [`Platform::debug_breakpoint`]。
pub fn debug_breakpoint() {
    Current::debug_breakpoint()
}
/// 见 [`Platform::switch_context`]。
///
/// # Safety
/// 同 [`Platform::switch_context`]。
#[inline(always)]
pub unsafe fn switch_context(old: *mut TaskContext, new: *const TaskContext) {
    Current::switch_context(old, new)
}
/// 见 [`Platform::init_task_frame`]。
///
/// # Safety
/// 同 [`Platform::init_task_frame`]。
pub unsafe fn init_task_frame(stack_top: *mut u8, entry: extern "C" fn() -> !) -> TaskContext {
    Current::init_task_frame(stack_top, entry)
}
/// 见 [`Platform::active_mapper`]。
///
/// # Safety
/// 同 [`Platform::active_mapper`]。
pub unsafe fn active_mapper(phys_offset: u64) -> Mapper {
    Current::active_mapper(phys_offset)
}
/// 见 [`Platform::current_space`]。
pub fn current_space() -> SpaceRoot {
    Current::current_space()
}
/// 见 [`Platform::create_space`]。
///
/// # Safety
/// 同 [`Platform::create_space`]。
pub unsafe fn create_space(
    template: SpaceRoot,
    phys_offset: u64,
    frames: &mut dyn kernel_core::frame::FrameAllocator,
) -> Result<SpaceRoot, kernel_core::paging::MapError> {
    Current::create_space(template, phys_offset, frames)
}
/// 见 [`Platform::space_mapper`]。
///
/// # Safety
/// 同 [`Platform::space_mapper`]。
pub unsafe fn space_mapper(root: SpaceRoot, phys_offset: u64) -> Mapper {
    Current::space_mapper(root, phys_offset)
}
/// 见 [`Platform::translate_in`]。
///
/// # Safety
/// 同 [`Platform::translate_in`]。
pub unsafe fn translate_in(
    root: SpaceRoot,
    phys_offset: u64,
    va: u64,
) -> Option<(kernel_core::frame::PhysFrame, kernel_core::paging::MapFlags)> {
    Current::translate_in(root, phys_offset, va)
}
/// 见 [`Platform::switch_space`]。
///
/// # Safety
/// 同 [`Platform::switch_space`]。
pub unsafe fn switch_space(root: SpaceRoot) {
    Current::switch_space(root)
}
/// 见 [`Platform::destroy_space`]。
///
/// # Safety
/// 同 [`Platform::destroy_space`]。
pub unsafe fn destroy_space(root: SpaceRoot, phys_offset: u64, frames: &mut dyn kernel_core::frame::FrameAllocator) {
    Current::destroy_space(root, phys_offset, frames)
}
/// 见 [`Platform::prepare_kernel_space`]。
///
/// # Safety
/// 同 [`Platform::prepare_kernel_space`]。
pub unsafe fn prepare_kernel_space(
    root: SpaceRoot,
    phys_offset: u64,
    frames: &mut dyn kernel_core::frame::FrameAllocator,
) -> Result<usize, kernel_core::paging::MapError> {
    Current::prepare_kernel_space(root, phys_offset, frames)
}
/// 见 [`Platform::empty_space_root`]。
///
/// # Safety
/// 同 [`Platform::empty_space_root`]。
pub unsafe fn empty_space_root(frame: kernel_core::frame::PhysFrame, phys_offset: u64) -> SpaceRoot {
    Current::empty_space_root(frame, phys_offset)
}
/// 见 [`Platform::kernel_part_used`]。
///
/// # Safety
/// 同 [`Platform::kernel_part_used`]。
pub unsafe fn kernel_part_used(root: SpaceRoot, phys_offset: u64) -> usize {
    Current::kernel_part_used(root, phys_offset)
}
/// 见 [`Platform::set_kernel_stack`]。
pub fn set_kernel_stack(top: u64) {
    Current::set_kernel_stack(top)
}
/// 见 [`Platform::kernel_stack`]。
pub fn kernel_stack() -> u64 {
    Current::kernel_stack()
}
/// 见 [`Platform::enter_user`]。
///
/// # Safety
/// 同 [`Platform::enter_user`]。
pub unsafe fn enter_user(entry: u64, stack: u64, arg0: u64, arg1: u64) -> ! {
    Current::enter_user(entry, stack, arg0, arg1)
}
/// 见 [`Platform::user_probe`]。
pub fn user_probe(probe: UserProbe) -> &'static [u8] {
    Current::user_probe(probe)
}
/// 见 [`Platform::cycle_counter`]。
#[inline(always)]
pub fn cycles() -> u64 {
    Current::cycle_counter()
}
/// 见 [`Platform::exit_emulator`]。
pub fn exit_emulator(status: ExitStatus) -> ! {
    Current::exit_emulator(status)
}

/// 见 [`Platform::CPU_START_FRAME_LIMIT`]。
pub const CPU_START_FRAME_LIMIT: Option<u64> = <Current as Platform>::CPU_START_FRAME_LIMIT;
/// 见 [`Platform::cpu_init_boot`]。
pub fn cpu_init_boot(boot: &crate::boot::BootSpec) -> CpuDiscovery {
    Current::cpu_init_boot(boot)
}
/// 见 [`Platform::cpu_start`]。
///
/// # Safety
/// 同 [`Platform::cpu_start`]。
pub unsafe fn cpu_start(
    start: &CpuStart<SpaceRoot>,
    frame: Option<kernel_core::frame::PhysFrame>,
) -> Result<(), kernel_core::smp::SmpError> {
    Current::cpu_start(start, frame)
}
/// 见 [`Platform::cpu_index`]。
#[inline(always)]
pub fn cpu_index() -> usize {
    Current::cpu_index()
}
/// 见 [`Platform::send_ipi`]。
pub fn send_ipi(cpu: usize, kind: kernel_core::smp::IpiKind) -> Result<(), kernel_core::smp::SmpError> {
    Current::send_ipi(cpu, kind)
}
/// 见 [`Platform::tlb_flush_local`]。
pub fn tlb_flush_local(va: u64, pages: u64) {
    Current::tlb_flush_local(va, pages)
}

/// 见 [`Platform::device_irq_count`]。
pub fn device_irq_count() -> usize {
    Current::device_irq_count()
}
/// 见 [`Platform::device_irq_name`]。
pub fn device_irq_name(line: usize) -> &'static str {
    Current::device_irq_name(line)
}
/// 见 [`Platform::device_irq_route`]。
pub fn device_irq_route(line: usize, cpu: usize) -> Result<(), kernel_core::irq::IrqError> {
    Current::device_irq_route(line, cpu)
}
/// 见 [`Platform::device_irq_set_masked`]。
pub fn device_irq_set_masked(line: usize, masked: bool) {
    Current::device_irq_set_masked(line, masked)
}
/// 见 [`Platform::device_irq_ack`]。
pub fn device_irq_ack(line: usize) {
    Current::device_irq_ack(line)
}
/// 见 [`Platform::device_irq_self_trigger`]。
pub fn device_irq_self_trigger(line: usize, on: bool) -> Result<(), kernel_core::irq::IrqError> {
    Current::device_irq_self_trigger(line, on)
}
