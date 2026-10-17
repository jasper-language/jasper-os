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

/// 当前编译目标的平台实现。
#[cfg(target_arch = "x86_64")]
pub use self::x86_64::X86_64 as Current;

/// 当前平台的任务上下文类型（切换时需要保存的寄存器集合）。
pub type TaskContext = <Current as Platform>::TaskContext;
/// 当前平台的页映射器类型。
pub type Mapper = <Current as Platform>::Mapper;
/// 当前平台的地址空间根类型。
pub type SpaceRoot = <Current as Platform>::SpaceRoot;
/// 每个地址空间私有的虚拟窗口，见 [`Platform::USER_WINDOW`]。
pub const USER_WINDOW: (u64, u64) = <Current as Platform>::USER_WINDOW;

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

    /// 空上下文（`const`，供静态任务表初始化）。
    const EMPTY_CONTEXT: Self::TaskContext;

    /// 架构名（横幅与诊断输出用），如 `"x86_64"`。
    const NAME: &'static str;

    /// 本架构可执行文件的 ELF `e_machine` 值（装载器据此拒绝其他架构的程序）。
    const ELF_MACHINE: u16;

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

    /// 新建地址空间：私有窗口为空，窗口外共享当前空间的映射。
    ///
    /// # Safety
    /// `phys_offset` 必须是全物理内存映射偏移。
    unsafe fn create_space(
        phys_offset: u64,
        frames: &mut dyn kernel_core::frame::FrameAllocator,
    ) -> Result<Self::SpaceRoot, kernel_core::paging::MapError>;

    /// 为任意地址空间（不必是活动的）建立映射器。只能用它修改**私有窗口**内的映射。
    ///
    /// # Safety
    /// 同 [`Platform::active_mapper`]；`root` 必须有效。
    unsafe fn space_mapper(root: Self::SpaceRoot, phys_offset: u64) -> Self::Mapper;

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

    /// 预分配内核共享部分的全部顶级表项，使之后新增的内核映射对所有地址空间可见。
    ///
    /// # Safety
    /// 在创建任何其他地址空间之前、于内核空间中调用一次。
    unsafe fn prepare_kernel_space(
        phys_offset: u64,
        frames: &mut dyn kernel_core::frame::FrameAllocator,
    ) -> Result<usize, kernel_core::paging::MapError>;

    /// 设置「从用户态进入内核时使用的内核栈顶」（调度器在每次切换任务时调用）。
    fn set_kernel_stack(top: u64);

    /// 进入用户态执行（永不返回；回到内核只能经中断、异常或系统调用）。
    ///
    /// # Safety
    /// 当前地址空间中 `entry` 必须为用户可执行、`stack` 之下为用户可写；内核栈顶必须已设置。
    unsafe fn enter_user(entry: u64, stack: u64, arg0: u64, arg1: u64) -> !;

    /// 取某个用户态探针程序的机器码。
    fn user_probe(probe: UserProbe) -> &'static [u8];
}

// ---- Core 使用的薄包装（避免各处 `use Platform` 与冗长的 `<Current as Platform>::`）----

/// 当前架构名，见 [`Platform::NAME`]。
pub const NAME: &str = <Current as Platform>::NAME;
/// 当前架构的 ELF 机器类型，见 [`Platform::ELF_MACHINE`]。
pub const ELF_MACHINE: u16 = <Current as Platform>::ELF_MACHINE;
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
    Current::irq_save_disable()
}
/// 见 [`Platform::irq_restore`]。
#[inline(always)]
pub fn irq_restore(was_enabled: bool) {
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
    phys_offset: u64,
    frames: &mut dyn kernel_core::frame::FrameAllocator,
) -> Result<SpaceRoot, kernel_core::paging::MapError> {
    Current::create_space(phys_offset, frames)
}
/// 见 [`Platform::space_mapper`]。
///
/// # Safety
/// 同 [`Platform::space_mapper`]。
pub unsafe fn space_mapper(root: SpaceRoot, phys_offset: u64) -> Mapper {
    Current::space_mapper(root, phys_offset)
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
    phys_offset: u64,
    frames: &mut dyn kernel_core::frame::FrameAllocator,
) -> Result<usize, kernel_core::paging::MapError> {
    Current::prepare_kernel_space(phys_offset, frames)
}
/// 见 [`Platform::set_kernel_stack`]。
pub fn set_kernel_stack(top: u64) {
    Current::set_kernel_stack(top)
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
/// 见 [`Platform::exit_emulator`]。
pub fn exit_emulator(status: ExitStatus) -> ! {
    Current::exit_emulator(status)
}
