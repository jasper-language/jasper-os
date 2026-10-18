//! 调度子系统门面（Facade 模式）。
//!
//! 结构（高内聚、低耦合）：
//! * `policy`    —— 调度策略（Strategy）：只决定「下一个是谁」
//! * `stack`     —— 静态内核栈池：只负责栈内存与首次切入帧
//! * `scheduler` —— 调度机制：任务表、状态迁移、切换准备、事件通知（Observer）
//! * `demo`      —— 里程碑演示任务（与机制分离，可整体删除）
//! * 本文件      —— 唯一的全局实例 + 对外 API（spawn / yield / run …），
//!   以及唯一调用 `switch_context` 的地方
//!
//! 前置条件：单 CPU。协作式（M1.3）与抢占式（M1.4）共用同一切换路径：
//! 抢占时由定时器中断在 EOI 之后调用 [`on_timer_interrupt`]，时间片（由策略给出）用完即
//! `yield_with_cause("tick")`。所有切换都在关中断临界区内完成。

pub mod demo;
pub mod policy;
pub mod scheduler;
pub mod stack;

use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::arch::{self as cpu, switch_context};
use crate::task::TaskId;

use policy::RoundRobin;
use scheduler::{Scheduler, SpawnError, SwitchObserver};

/// 槽位总数（含槽位 0 的引导线程）。
pub const MAX_TASKS: usize = 4;

/// 内核唯一的调度器实例。
///
/// 单 CPU、无抢占期间只会被当前执行流访问；所有访问都经下面的 `with`/`with_mut`，
/// 且借用不跨越栈切换。SMP 时需改为每 CPU 实例 + 锁（接口保持不变）。
static mut KERNEL_SCHED: Scheduler<RoundRobin, MAX_TASKS> = Scheduler::new(RoundRobin);

/// 以共享借用访问全局调度器。
fn with<R>(f: impl FnOnce(&Scheduler<RoundRobin, MAX_TASKS>) -> R) -> R {
    // SAFETY：单 CPU、关中断（或协作式）前提下没有并发访问；借用在闭包内结束。
    unsafe { f(&*addr_of!(KERNEL_SCHED)) }
}

/// 以独占借用访问全局调度器。
fn with_mut<R>(f: impl FnOnce(&mut Scheduler<RoundRobin, MAX_TASKS>) -> R) -> R {
    // SAFETY：同上；调用者不得在闭包内触发栈切换。
    unsafe { f(&mut *addr_of_mut!(KERNEL_SCHED)) }
}

/// 启动时的内核地址空间（第一次切换时记录；`space = None` 的任务都运行在它上面）。
static KERNEL_SPACE: spin::Once<cpu::SpaceRoot> = spin::Once::new();

/// 是否允许定时器抢占（默认关闭；协作式阶段与关键初始化期间保持关闭）。
static PREEMPTION: AtomicBool = AtomicBool::new(false);
/// 当前任务在本时间片内已经历的 tick 数。
static SLICE_TICKS: AtomicU32 = AtomicU32::new(0);
/// 调度器看到的定时器 tick 总数（在中断上下文中递增，任务可据此做基于时间的等待）。
static TIMER_TICKS: AtomicU64 = AtomicU64::new(0);

/// 新任务的公共入口：执行任务体，返回后标记退出并让出 CPU（永不返回）。
extern "C" fn task_trampoline() -> ! {
    // 新任务可能是在定时器中断里被首次切入的：那时 CPU 处于关中断状态，
    // 而这条路径不会经过 iretq 恢复标志位 ⇒ 抢占开启时必须在这里显式开中断，
    // 否则该任务将永远无法再被抢占。
    if PREEMPTION.load(Ordering::Relaxed) {
        cpu::irq_enable();
    }
    if let Some(entry) = with(|s| s.current_entry()) {
        entry();
    }
    with_mut(|s| s.mark_current_exited());
    yield_with_cause("exit");
    // 已退出的任务不会再被策略选中；走到这里说明调度器状态被破坏。
    panic!("exited task was resumed");
}

/// 安装切换观察者（例如串口日志）。
pub fn set_observer(observer: SwitchObserver) {
    with_mut(|s| s.set_observer(observer));
}

/// 新建内核任务。
pub fn spawn(id: TaskId, name: &'static str, entry: fn()) -> Result<usize, SpawnError> {
    with_mut(|s| s.spawn(id, name, entry, task_trampoline))
}

/// 主动让出 CPU（协作式）。
pub fn yield_now() {
    yield_with_cause("yield");
}

/// 带原因的让出：准备切换后在**没有任何借用**的情况下执行真正的栈切换。
///
/// 整个「准备 + 切换」在关中断临界区内完成：否则定时器中断可能在调度器状态改到一半时
/// 再次进入调度器（重入）。切换回来后恢复**本任务自己**被切走前的中断状态——
/// 每个任务的中断标志随它的栈一起保存/恢复，互不影响。
pub fn yield_with_cause(cause: &'static str) {
    let was_enabled = cpu::irq_save_disable();
    SLICE_TICKS.store(0, Ordering::Relaxed);
    let kernel_space = *KERNEL_SPACE.call_once(cpu::current_space);
    if let Some(plan) = with_mut(|s| s.prepare_switch(cause)) {
        // 下一个任务若从用户态被中断，CPU 要切到它自己的内核栈。
        if let Some(top) = plan.next_stack_top {
            cpu::set_kernel_stack(top);
        }
        // 地址空间跟随任务：只在不同时才切换（切换会刷新非全局 TLB 项）。
        let target = plan.next_space.unwrap_or(kernel_space);
        if cpu::current_space() != target {
            // SAFETY：任务记录的空间由其所有者保证在任务存活期间有效；内核空间始终有效。
            unsafe { cpu::switch_space(target) };
        }
        // SAFETY：old/new 指向全局调度器内的任务上下文，在切换期间保持有效；
        // new.rsp 要么由 StackPool 伪造，要么由上一次 switch_context 保存。
        unsafe { switch_context(plan.old, plan.new) };
    }
    cpu::irq_restore(was_enabled);
}

/// 等待外部进展（例如时钟前进）的一次让步：先把处理器让给其他就绪任务；回来后**开中断休眠到下一个中断**，
/// 再恢复调用前的中断状态。
///
/// 用于系统调用里的阻塞等待（系统调用分发期间默认关中断）：若只是循环 `yield_now`，在没有其他就绪任务时
/// 时钟中断永远进不来，等待永不结束。入口的用户栈暂存位只在切栈前使用，此后开中断是安全的。
/// One step of a blocking wait: yield, then sleep until the next interrupt with interrupts enabled.
pub fn pause() {
    yield_now();
    let was_enabled = cpu::irq_save_disable();
    cpu::wait_for_interrupt();
    cpu::irq_restore(was_enabled);
}

/// 当前任务的 id 与名字。
pub fn current() -> (TaskId, &'static str) {
    with(|s| s.current())
}

/// 累计切换次数。
pub fn switch_count() -> u64 {
    with(|s| s.switch_count())
}

/// 当前策略名。
pub fn policy_name() -> &'static str {
    with(|s| s.policy_name())
}

/// 当前策略的时间片（tick 数）。
pub fn quantum_ticks() -> u32 {
    with(|s| s.quantum_ticks())
}

/// 从引导线程启动调度：运行到所有工作任务退出后返回。
pub fn run() {
    yield_now();
}

/// 让当前任务运行在 `space` 上（`None` = 内核空间），并立即切换过去。
pub fn set_current_space(space: Option<cpu::SpaceRoot>) {
    cpu::without_irq(|| {
        with_mut(|s| s.set_current_space(space));
        let target = space.unwrap_or_else(|| *KERNEL_SPACE.call_once(cpu::current_space));
        if cpu::current_space() != target {
            // SAFETY：调用者保证 space 有效且包含内核共享映射。
            unsafe { cpu::switch_space(target) };
        }
    });
}

/// 授予当前任务一组可发起的系统调用（进入用户态之前由任务创建方设置）。
pub fn set_current_syscalls(set: crate::syscall::SyscallSet) {
    cpu::without_irq(|| with_mut(|s| s.set_current_syscalls(set)));
}

/// 当前任务的地址空间（`None` = 内核空间）。
pub fn current_space() -> Option<cpu::SpaceRoot> {
    with(|s| s.current_space())
}

/// 当前任务可发起的系统调用集合。
pub fn current_syscalls() -> crate::syscall::SyscallSet {
    with(|s| s.current_syscalls())
}

/// 结束当前任务（永不返回）：标记退出并切走。可在中断上下文调用（用户态异常的终止路径）。
pub fn exit_current(cause: &'static str) -> ! {
    with_mut(|s| s.mark_current_exited());
    yield_with_cause(cause);
    panic!("exited task was resumed");
}

/// 打开/关闭定时器抢占。
pub fn set_preemption(enabled: bool) {
    SLICE_TICKS.store(0, Ordering::Relaxed);
    PREEMPTION.store(enabled, Ordering::Relaxed);
}

/// 调度器看到的定时器 tick 总数。
pub fn timer_ticks() -> u64 {
    TIMER_TICKS.load(Ordering::Relaxed)
}

/// 以调度器 tick 为单位的单调时间源：把 [`timer_ticks`] 适配成 `kernel_core::wait::TimeSource`，
/// 让纯机制库的等待/超时逻辑跑在真实定时器上（Adapter 模式）。
pub struct TickClock;

impl kernel_core::wait::TimeSource for TickClock {
    fn now(&self) -> u64 {
        timer_ticks()
    }
}

/// 定时器中断入口（**在中断上下文中调用，且必须在向中断控制器发送 EOI 之后**）。
///
/// 时间片用完且抢占开启时，就在中断上下文里直接切换：被切走任务的中断帧留在它自己的栈上，
/// 将来切回时从这里返回、经 `iretq` 恢复它被打断的位置与中断标志。
/// EOI 必须先发，否则在切回本任务之前中断控制器不会再投递定时器中断。
pub fn on_timer_interrupt() {
    TIMER_TICKS.fetch_add(1, Ordering::Relaxed);
    if !PREEMPTION.load(Ordering::Relaxed) {
        return;
    }
    let used = SLICE_TICKS.fetch_add(1, Ordering::Relaxed) + 1;
    if used >= with(|s| s.quantum_ticks()) {
        yield_with_cause("tick");
    }
}
