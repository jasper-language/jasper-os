//! 调度子系统门面（Facade 模式）。
//!
//! 结构（高内聚、低耦合）：
//! * `policy`    —— 调度策略的选择点（Strategy）：策略本体是 `kernel_core::sched` 的纯决策
//! * `stack`     —— 内核栈池：静态栈 + 堆就绪后一次性预留的堆栈
//! * `scheduler` —— 调度机制：任务表、状态迁移、睡眠与唤醒、时钟记账、切换准备、事件通知（Observer）
//! * `turnstile` —— 会阻塞的内核锁 [`KMutex`]（等待者把档位借给持有者，放锁时直接交接）
//! * `demo`      —— 里程碑演示任务（与机制分离，可整体删除）
//! * 本文件      —— 唯一的全局实例 + 对外 API（spawn / yield / sleep / run …），
//!   以及唯一调用 `switch_context` 的地方
//!
//! 调度器状态由一把登记了级别的锁保护，任何处理器都可访问；目前只有引导处理器运行任务，
//! 其他处理器运行各自的空闲执行流。协作式让出、时间片抢占、唤醒抢占共用同一切换路径：
//! 定时器中断在 EOI 之后调用 [`on_timer_interrupt`]，由机制层记账并询问策略，需要时就地切换。
//! 所有对调度器状态的访问都在持锁、关中断的临界区内完成，全部切换在关中断下进行（时钟中断也会修改调度器状态）。
//!
//! # 抢占默认开启
//! 时间片抢占默认开启：吃满 CPU 的任务不能靠「不让出」独占处理器。需要可复现交错顺序的演练
//! （协作式调度演示）在演练期间临时关闭，结束后用 [`set_preemption`] 的返回值恢复。

pub mod demo;
pub mod policy;
pub mod scheduler;
pub mod stack;
pub mod turnstile;

pub use turnstile::{KMutex, KMutexGuard};

use core::sync::atomic::{AtomicBool, Ordering};

use crate::sync::{IrqSpinLock, IrqU64};
use crate::arch::{self as cpu, switch_context};
use crate::task::TaskId;

use policy::{kernel_policy, CpuLimitStats, KernelPolicy, LatencyHistogram, Qos, WatchdogLog};
use scheduler::{BlockError, Cause, CpuGroupId, GroupError, QosError, Scheduler, SpawnError, SwitchObserver, WATCHDOG_LOG};

/// 槽位总数上限（含槽位 0 的引导线程）。前 [`stack::STATIC_STACKS`] 个槽位在内核堆初始化前即可用，
/// 其余在 [`reserve_stacks`] 之后可用。
pub const MAX_TASKS: usize = crate::config::ACTIVE.sched.max_tasks;

/// 内核调度器实例，由登记了级别的关中断自旋锁保护（多处理器下任何处理器都可安全访问）。
///
/// 所有访问都经下面的 `with`/`with_mut`（持锁、关中断执行），借用与锁都不跨越栈切换：
/// 切换路径先在锁内算出切换计划、放锁，再执行栈切换。
/// 每核运行队列与跨核取任务属于后续的负载均衡；届时只替换本实例的内部结构，接口保持不变。
static KERNEL_SCHED: IrqSpinLock<Scheduler<KernelPolicy, MAX_TASKS>> =
    IrqSpinLock::ranked(crate::lockorder::SCHED, Scheduler::new(kernel_policy()));

/// 以共享借用访问调度器（持锁、关中断执行：时钟中断与其他处理器也会访问调度器状态）。
fn with<R>(f: impl FnOnce(&Scheduler<KernelPolicy, MAX_TASKS>) -> R) -> R {
    f(&KERNEL_SCHED.lock())
}

/// 以独占借用访问调度器（持锁、关中断执行）；调用者不得在闭包内触发栈切换。
fn with_mut<R>(f: impl FnOnce(&mut Scheduler<KernelPolicy, MAX_TASKS>) -> R) -> R {
    f(&mut KERNEL_SCHED.lock())
}

/// 调度器锁遇到占用的次数（多处理器同时访问调度器时增长）。
/// Contended acquisitions of the scheduler lock.
pub fn lock_contended() -> u32 {
    KERNEL_SCHED.contended()
}

/// 启动时的内核地址空间（第一次切换时记录；`space = None` 的任务都运行在它上面）。
static KERNEL_SPACE: spin::Once<cpu::SpaceRoot> = spin::Once::new();

/// 是否允许定时器抢占（默认开启，见模块文档）。
static PREEMPTION: AtomicBool = AtomicBool::new(true);
/// 调度器看到的定时器 tick 总数（在中断上下文中递增，任务可据此做基于时间的等待）。
static TIMER_TICKS: IrqU64 = IrqU64::new(0);

/// 新任务的公共入口：执行任务体，返回后标记退出并让出 CPU（永不返回）。
extern "C" fn task_trampoline() -> ! {
    // 新任务可能是在定时器中断里被首次切入的：那时 CPU 处于关中断状态，
    // 而这条路径不会经过中断返回来恢复标志位 ⇒ 抢占开启时必须在这里显式开中断，
    // 否则该任务将永远无法再被抢占。
    if PREEMPTION.load(Ordering::Relaxed) {
        cpu::irq_enable();
    }
    if let Some(entry) = with(|s| s.current_entry()) {
        entry();
    }
    exit_current(Cause::EXIT);
}

/// 安装切换观察者（例如串口日志）。
pub fn set_observer(observer: SwitchObserver) {
    with_mut(|s| s.set_observer(observer));
}

/// 堆就绪后为其余槽位预留内核栈（只调用一次；幂等）。返回可用槽位总数（含引导线程槽位）。
pub fn reserve_stacks() -> Result<usize, stack::ReserveError> {
    with_mut(|s| s.reserve_stacks())
}

/// 可用槽位总数（含引导线程槽位）。
pub fn capacity() -> usize {
    with(|s| s.capacity())
}

/// 新建内核任务（继承当前工作任务的 QoS 档位与上限）。
pub fn spawn(id: TaskId, name: &'static str, entry: fn()) -> Result<usize, SpawnError> {
    with_mut(|s| s.spawn(id, name, entry, task_trampoline))
}

/// 新建内核任务并放入 CPU 组 `group`（受该组上限约束）。组无效时拒绝。
pub fn spawn_in(id: TaskId, name: &'static str, entry: fn(), group: CpuGroupId) -> Result<usize, SpawnError> {
    with_mut(|s| s.spawn_in(id, name, entry, task_trampoline, Some(group)))
}

/// 新建 CPU 组（上限千分比，桶容量取默认值）；调用者持有一份引用，用完以 [`release_cpu_group`] 归还。
/// Creates a CPU group with the default burst.
pub fn create_cpu_group(limit_permille: u32) -> Result<CpuGroupId, GroupError> {
    with_mut(|s| s.create_group(limit_permille, policy::CPU_BURST_TICKS))
}

/// 归还 CPU 组的持有者引用（成员全部退出后组释放）。
pub fn release_cpu_group(g: CpuGroupId) -> Result<(), GroupError> {
    with_mut(|s| s.release_group(g))
}

/// 修改 CPU 组的上限（千分比）；非法值被拒且原上限不变。
pub fn set_cpu_group_limit(g: CpuGroupId, limit_permille: u32) -> Result<(), GroupError> {
    with_mut(|s| s.set_group_limit(g, limit_permille))
}

/// CPU 组的记账快照（组已释放时 `None`）。
pub fn cpu_group_stats(g: CpuGroupId) -> Option<CpuLimitStats> {
    with(|s| s.group_stats(g))
}

/// 把已存在的任务移入 CPU 组（`None` = 移出）。
pub fn assign_cpu_group(id: TaskId, g: Option<CpuGroupId>) -> Result<(), GroupError> {
    with_mut(|s| s.assign_group(id, g))
}

/// 仍存在的 CPU 组数。
pub fn live_cpu_groups() -> usize {
    with(|s| s.live_groups())
}

/// 看门狗报告日志（副本）。
pub fn watchdog_log() -> WatchdogLog<WATCHDOG_LOG> {
    with(|s| s.watchdog_log())
}

/// 清空看门狗报告日志。
pub fn clear_watchdog() {
    with_mut(|s| s.clear_watchdog());
}

/// 看门狗阈值（tick）。
pub fn watchdog_threshold() -> u32 {
    with(|s| s.watchdog_threshold())
}

/// 修改看门狗阈值（tick），返回旧值（演练结束时用它恢复）。
pub fn set_watchdog_threshold(ticks: u32) -> u32 {
    with_mut(|s| s.set_watchdog_threshold(ticks))
}

/// 主动让出 CPU。
pub fn yield_now() {
    yield_with_cause(Cause::YIELD);
}

/// 带原因的让出：准备切换后在**没有任何借用**的情况下执行真正的栈切换。
///
/// 整个「准备 + 切换」在关中断临界区内完成：否则定时器中断可能在调度器状态改到一半时
/// 再次进入调度器（重入）。切换回来后恢复**本任务自己**被切走前的中断状态——
/// 每个任务的中断标志随它的栈一起保存/恢复，互不影响。
pub fn yield_with_cause(cause: &'static str) {
    let was_enabled = cpu::irq_save_disable();
    let kernel_space = *KERNEL_SPACE.call_once(cpu::current_space);
    // 锁与借用都在本语句内结束，不跨越下面的栈切换（中断仍关着）。
    let plan = KERNEL_SCHED.lock().prepare_switch(cause);
    if let Some(plan) = plan {
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
        crate::smp::percpu::this().set_current(plan.next_slot);
        // SAFETY：old/new 指向全局调度器内的任务上下文，在切换期间保持有效；
        // new 要么由栈池伪造，要么由上一次 switch_context 保存。
        unsafe { switch_context(plan.old, plan.new) };
    }
    cpu::irq_restore(was_enabled);
}

/// 让当前工作任务睡眠到时刻 `deadline`（tick），期间不占用处理器；到期由时钟中断唤醒。
/// 已到期时立即返回。所属进程开始终止时会被 [`wake`] 提前唤醒——调用者醒来后须自行检查等待条件。
/// 在引导线程上调用时退化为「先让出、再休眠到下一个中断」（引导线程是空闲时的落脚点，不能睡眠）。
/// Sleeps the current worker until `deadline` (ticks) without consuming CPU.
pub fn sleep_until(deadline: u64) {
    let was_enabled = cpu::irq_save_disable();
    if timer_ticks() < deadline {
        if with_mut(|s| s.block_current(Some(deadline))) {
            yield_with_cause(Cause::SLEEP);
        } else {
            yield_now();
            cpu::wait_for_interrupt();
        }
    }
    cpu::irq_restore(was_enabled);
}

/// 等待外部进展的一步：睡到下一个 tick（期间处理器交给其他任务，包括低档任务）。
///
/// 用于系统调用里的阻塞等待（等完成、等消息、等退出）：这类等待的条件不由时钟决定，
/// 每个 tick 醒来检查一次。与「循环让出」不同，睡眠中的任务不可运行，低档任务因此能拿到处理器。
/// One step of a blocking wait: sleep until the next tick.
pub fn pause() {
    sleep_until(timer_ticks() + 1);
}

/// 「等任务退出」这一等待对象的标识（锁以自身地址为标识，地址按字对齐，不会与它重合）。
const JOIN_KEY: u64 = 1;

/// 阻塞到任务 `id` 退出；等待期间把当前任务的有效档位借给它（等一个低档任务做完时不被中档任务挡住）。
///
/// `id` 不存在或已退出时立即返回 `Ok`。等自己、或与对方互相等待（成环）时返回错误，状态不变。
/// 在引导线程上调用时不阻塞：让出并休眠到下一个中断，直到目标退出。
/// Blocks until task `id` exits, lending the caller's effective class to it meanwhile.
pub fn join(id: TaskId) -> Result<(), BlockError> {
    loop {
        let was_enabled = cpu::irq_save_disable();
        let step = with_mut(|s| {
            if !s.is_live(id) {
                Ok(None)
            } else if s.on_boot() {
                Ok(Some(false))
            } else {
                s.block_on(id, JOIN_KEY).map(|_| Some(true))
            }
        });
        match step {
            Ok(Some(true)) => yield_with_cause(Cause::BLOCK),
            Ok(Some(false)) => {
                yield_now();
                cpu::wait_for_interrupt();
            }
            Ok(None) => {
                cpu::irq_restore(was_enabled);
                return Ok(());
            }
            Err(e) => {
                cpu::irq_restore(was_enabled);
                return Err(e);
            }
        }
        cpu::irq_restore(was_enabled);
    }
}

/// 任务 `id` 的有效档位（含等待者借来的档位）；不存在、已退出或是引导线程时 `None`。
pub fn effective_qos(id: TaskId) -> Option<Qos> {
    with(|s| s.effective_qos(id))
}

/// 当前任务的有效档位（含借来的档位；引导线程为 `None`）。
pub fn current_effective_qos() -> Option<Qos> {
    with(|s| s.effective_qos(s.current().0))
}

/// 打开/关闭优先级继承，返回之前的设置（默认开启；关闭只用于对照测量，结束后用返回值恢复）。
pub fn set_inheritance(enabled: bool) -> bool {
    with_mut(|s| s.set_inheritance(enabled))
}

/// 唤醒睡眠中的任务 `id`（不在睡眠时无动作）。被唤醒者档位更高且抢占开启时，在下一个 tick 之前
/// 不会主动切换——调用者通常处在系统调用或内核路径中，由出口处的调度点或下一个 tick 完成切换。
pub fn wake(id: TaskId) {
    with_mut(|s| {
        s.wake(id);
    });
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

/// 默认档位的时间片（tick 数）。
pub fn quantum_ticks() -> u32 {
    with(|s| s.default_quantum())
}

/// 从引导线程启动调度：运行到所有工作任务退出后返回。
///
/// 引导线程是空闲时的落脚点：工作任务全部睡眠时，它开中断休眠到下一个中断；
/// 抢占开启时由时钟中断直接切到被唤醒的任务，关闭时由这里的循环让出。
pub fn run() {
    yield_now();
    while with(|s| s.live_workers()) > 0 {
        if with(|s| s.has_runnable_worker()) {
            yield_now();
        } else {
            let was_enabled = cpu::irq_save_disable();
            cpu::wait_for_interrupt();
            cpu::irq_restore(was_enabled);
        }
    }
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
    with_mut(|s| s.set_current_syscalls(set));
}

/// 当前任务的地址空间（`None` = 内核空间）。
pub fn current_space() -> Option<cpu::SpaceRoot> {
    with(|s| s.current_space())
}

/// 当前任务可发起的系统调用集合。
pub fn current_syscalls() -> crate::syscall::SyscallSet {
    with(|s| s.current_syscalls())
}

/// 当前任务的 QoS 档位（引导线程为 `None`）。
pub fn current_qos() -> Option<Qos> {
    with(|s| s.current_qos())
}

/// 修改当前任务的 QoS 档位（只能降低或不变；提升须在创建方授予的上限之内）。
/// 降档后若有更高档任务在等，立即让出。
pub fn set_current_qos(q: Qos) -> Result<(), QosError> {
    with_mut(|s| s.set_current_qos(q))?;
    if with(|s| s.has_runnable_worker()) {
        yield_with_cause(Cause::PREEMPT);
    }
    Ok(())
}

/// 授予当前任务 QoS 上限（创建方在任务进入用户态之前调用；`None` = 只能降不能升）。
pub fn set_current_qos_ceiling(ceiling: Option<Qos>) {
    with_mut(|s| s.set_current_qos_ceiling(ceiling));
}

/// 某档的唤醒延迟直方图（从被唤醒到被选中运行，单位 tick）。
pub fn latency(q: Qos) -> LatencyHistogram {
    with(|s| s.latency(q))
}

/// 清空全部唤醒延迟直方图。
pub fn reset_latency() {
    with_mut(|s| s.reset_latency());
}

/// 任务 `id` 累计运行的 tick 数。
pub fn cpu_ticks(id: TaskId) -> Option<u64> {
    with(|s| s.cpu_ticks(id))
}

/// 结束当前任务（永不返回）：标记退出并切走。可在中断上下文调用（用户态异常的终止路径）。
pub fn exit_current(cause: &'static str) -> ! {
    with_mut(|s| s.mark_current_exited());
    yield_with_cause(cause);
    // 已退出的任务不会再被策略选中；走到这里说明调度器状态被破坏。
    panic!("exited task was resumed");
}

/// 打开/关闭定时器抢占，返回之前的设置（演练结束时用它恢复）。
pub fn set_preemption(enabled: bool) -> bool {
    PREEMPTION.swap(enabled, Ordering::Relaxed)
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
/// 每个 tick：记账、唤醒到期的睡眠任务、询问策略是否抢占；需要时就在中断上下文里直接切换：
/// 被切走任务的中断帧留在它自己的栈上，将来切回时从这里返回、经中断返回恢复它被打断的位置与中断标志。
/// EOI 必须先发，否则在切回本任务之前中断控制器不会再投递定时器中断。
pub fn on_timer_interrupt() {
    let now = TIMER_TICKS.fetch_add(1, Ordering::Relaxed) + 1;
    let preemption = PREEMPTION.load(Ordering::Relaxed);
    if let Some(cause) = with_mut(|s| s.tick(now, preemption)) {
        yield_with_cause(cause);
    }
}
