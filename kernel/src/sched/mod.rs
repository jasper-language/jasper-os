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
//! 调度器状态由一把登记了级别的锁保护，任何处理器都可访问。每个处理器有自己的运行队列与当前任务，
//! 其他处理器在空闲执行流上等任务（[`idle_loop`]），被唤醒、被窃取或被均衡过来的任务在那里接手。
//! 协作式让出、时间片抢占、唤醒抢占共用同一切换路径：引导处理器的全局定时器中断在 EOI 之后调用
//! [`on_timer_interrupt`]（推进时刻、唤醒到期任务），其他处理器的本地定时器调用 [`on_local_timer`]，
//! 由机制层记账并询问本处理器的策略，需要时就地切换。
//!
//! 跨核协作：机制层只记下「哪些处理器需要重新调度」，本文件在放锁之后才对它们发核间中断
//! （持锁发中断会让对方一醒来就撞上同一把锁）。核间中断只置标志：空闲处理器醒来即取任务，
//! 忙碌处理器在下一个本地 tick 做决定（延迟至多一个 tick），因此中断处理程序里从不切换栈——
//! 同一中断入口里排在后面的击落请求不会被一次切换延后。
//!
//! 切换完成协议：新的执行流一开始执行（切换返回处、新任务入口）就调用机制层的 `finish_switch`，
//! 换下的任务此后才能被其他处理器选中——在那之前它的上下文可能还没保存完。
//! 所有对调度器状态的访问都在持锁、关中断的临界区内完成，全部切换在关中断下进行（时钟中断也会修改调度器状态）。
//!
//! # 抢占默认开启
//! 时间片抢占默认开启：吃满 CPU 的任务不能靠「不让出」独占处理器。需要可复现交错顺序的演练
//! （协作式调度演示）在演练期间临时关闭，结束后用 [`set_preemption`] 的返回值恢复。

pub mod demo;
pub mod policy;
pub mod scheduler;
pub mod slots;
pub mod stack;
pub mod turnstile;

pub use turnstile::{KMutex, KMutexGuard};

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::sync::{IrqSpinLock, IrqU64};
use crate::arch::{self as cpu, switch_context};
use crate::task::TaskId;

use kernel_core::smp::CpuSet;
use kernel_core::sync_origin::Origin;

use policy::{kernel_policy, CpuLimitStats, KernelPolicy, LatencyHistogram, Qos, WatchdogLog};
pub use scheduler::{AffinityError, CpuStats, NohzStats, ScanStats};
pub use scheduler::GrowError;
use scheduler::{BlockError, Cause, CpuGroupId, GroupError, IdleStep, QosError, Scheduler, SpawnError, SwitchObserver, WATCHDOG_LOG};

/// 内核调度器实例，由登记了级别的关中断自旋锁保护（多处理器下任何处理器都可安全访问）。
///
/// 所有访问都经下面的 `with`/`with_mut`（持锁、关中断执行），借用与锁都不跨越栈切换：
/// 切换路径先在锁内算出切换计划、放锁，再执行栈切换。
static KERNEL_SCHED: IrqSpinLock<Scheduler> =
    IrqSpinLock::ranked(crate::lockorder::SCHED, Scheduler::new(kernel_policy()));

// Author: chatgpt. Every scheduler access uses this guard, including switch
// preparation. Drop publishes after mutation, while the global IRQ lock remains
// held. Fast readers use the last committed snapshot until this publication;
// they never read mutable scheduler state. Owner switches cannot overlap an
// IRQ-masked fast call on that same CPU.
static YIELD_GATES: [kernel_core::yield_gate::YieldGate; kernel_core::smp::MAX_CPUS] =
    [const { kernel_core::yield_gate::YieldGate::new() }; kernel_core::smp::MAX_CPUS];
// Lock order: global scheduler -> CPU leaves in ascending order. Fast timer
// uses try_lock on its one leaf, drops it before any global fallback. IRQs are
// already masked in timer context. No allocation or callbacks in the leaf path.
static TICK_LEASES: [kernel_core::ticket::TicketLock<kernel_core::tick_lease::TickLease>; kernel_core::smp::MAX_CPUS] =
    [const { kernel_core::ticket::TicketLock::new(kernel_core::tick_lease::TickLease::new()) }; kernel_core::smp::MAX_CPUS];

const PI_MAILBOX_CAPACITY: usize = 16;
struct CpuInbox {
    wake: kernel_core::wake_mailbox::WakeMailbox<{ scheduler::WAKE_MAILBOX_CAPACITY }>,
    pi: kernel_core::percpu_migration::PiMailbox<PI_MAILBOX_CAPACITY>,
}
impl CpuInbox {
    const fn new() -> Self { Self { wake: kernel_core::wake_mailbox::WakeMailbox::new(), pi: kernel_core::percpu_migration::PiMailbox::new() } }
}
static CPU_INBOXES: [kernel_core::ticket::TicketLock<CpuInbox>; kernel_core::smp::MAX_CPUS] =
    [const { kernel_core::ticket::TicketLock::new(CpuInbox::new()) }; kernel_core::smp::MAX_CPUS];
static REMOTE_WAKES: AtomicU32 = AtomicU32::new(0);
static WAKE_FALLBACKS: AtomicU32 = AtomicU32::new(0);
static REMOTE_PI: AtomicU32 = AtomicU32::new(0);
static PI_FALLBACKS: AtomicU32 = AtomicU32::new(0);

pub(super) fn publish_wake_token(cpu: usize, token: kernel_core::task_index::Token) -> kernel_core::wake_mailbox::Enqueue {
    let mut inbox = CPU_INBOXES[cpu].lock();
    let result = inbox.wake.push(token);
    if !matches!(result, kernel_core::wake_mailbox::Enqueue::Full) { REMOTE_WAKES.fetch_add(1, Ordering::Relaxed); }
    else { WAKE_FALLBACKS.fetch_add(1, Ordering::Relaxed); }
    result
}

pub(super) fn publish_pi_message(cpu: usize, message: kernel_core::percpu_migration::PiMessage) {
    use kernel_core::percpu_migration::PiEnqueue;
    let result = CPU_INBOXES[cpu].lock().pi.push(message);
    match result {
        PiEnqueue::Queued | PiEnqueue::Replaced => { REMOTE_PI.fetch_add(1, Ordering::Relaxed); }
        PiEnqueue::Stale => {}
        PiEnqueue::Full => { PI_FALLBACKS.fetch_add(1, Ordering::Relaxed); }
    }
}

struct LocalInbox {
    wakes: [Option<kernel_core::task_index::Token>; scheduler::WAKE_MAILBOX_CAPACITY],
    pi: [Option<kernel_core::percpu_migration::PiMessage>; PI_MAILBOX_CAPACITY],
}
fn take_local_inbox(cpu: usize) -> LocalInbox {
    let mut out = LocalInbox { wakes: [None; scheduler::WAKE_MAILBOX_CAPACITY], pi: [None; PI_MAILBOX_CAPACITY] };
    let mut inbox = CPU_INBOXES[cpu].lock();
    for slot in &mut out.wakes { *slot = inbox.wake.pop(); if slot.is_none() { break; } }
    for slot in &mut out.pi { *slot = inbox.pi.pop(); if slot.is_none() { break; } }
    out
}
type TickGuard = kernel_core::ticket::TicketGuard<'static, kernel_core::tick_lease::TickLease>;
struct StateGuard(crate::sync::IrqSpinLockGuard<'static, Scheduler>,
    [Option<TickGuard>; kernel_core::smp::MAX_CPUS], bool);
impl core::ops::Deref for StateGuard {
    type Target = Scheduler;
    fn deref(&self) -> &Self::Target { &self.0 }
}
impl core::ops::DerefMut for StateGuard {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}
impl Drop for StateGuard {
    fn drop(&mut self) {
        // with_mut_from refreshes before extracting kicks. Repeating the full
        // task-table scan here doubled every mutating high-resolution timer
        // transaction and amplified multi-CPU wake contention. Direct guards
        // still refresh on drop.
        if !self.2 { self.0.refresh_ns_events(); }
        self.0.program_ns_local();
        let allow = self.0.fast_yield_cpus();
        for (c, gate) in YIELD_GATES.iter().enumerate() { gate.publish(allow.contains(c)); }
        let owners = self.0.tick_lease_owners();
        for (c, leaf) in self.1.iter_mut().enumerate() {
            // A BSP tick deliberately leaves ordinary AP leases untouched.
            // Only held leases were drained and may be republished here.
            if let Some(leaf) = leaf { leaf.publish(owners[c].0, owners[c].1); }
        }
        // Drop all leaves BEFORE the IRQ guard unlocks/restores interrupts.
        // Field-drop order alone would restore IRQs while leaves were held.
        for leaf in &mut self.1 { drop(leaf.take()); }
    }
}
// Author: chatgpt. Diagnostic-only per-CPU counters. Updates, reset and snapshot
// are serialized by the SAME global guard, never used to grant permissions.
// Columns: transactions, leaf acquisitions, acquisitions with observed nonzero
// spin waiting, spin iterations. The third is NOT a try_lock-failure count.
// Counters wrap at u32; only bounded, non-wrapping diagnostic windows are valid.
#[cfg(feature = "krn2-observe")]
static SYNC_WORK: [[core::sync::atomic::AtomicU32; 4]; kernel_core::smp::MAX_CPUS] =
    [const { [const { core::sync::atomic::AtomicU32::new(0) }; 4] }; kernel_core::smp::MAX_CPUS];
#[cfg(feature = "krn2-observe")]
pub fn sync_work_stats() -> [u32; 4] {
    let _state = lock_state(); // This observation transaction is included.
    let mut total = [0u32; 4];
    for row in &SYNC_WORK { for (sum, value) in total.iter_mut().zip(row) {
        *sum = sum.wrapping_add(value.load(core::sync::atomic::Ordering::Relaxed));
    }}
    total
}
// Direct diagnostic/reset/snapshot transactions are explicitly attributed.
fn lock_state() -> StateGuard { lock_state_from(Origin::Diagnostic) }
fn lock_state_from(_origin: Origin) -> StateGuard {
    // A CPU is the sole consumer of its inbox. Never retain this leaf while
    // taking KERNEL_SCHED: producers use global -> inbox ordering.
    let local_cpu = crate::arch::cpu_index();
    let inbox = cpu::without_irq(|| take_local_inbox(local_cpu));
    let mut s = KERNEL_SCHED.lock();
    // The resumed task has already released its predecessor's leaf-local
    // execution claim.  Retire the cold lifecycle attachment at the next
    // scheduler transaction instead of forcing every context switch to wait
    // for KERNEL_SCHED on its return path.
    let mut settle_cpus = s.online();
    settle_cpus.insert(local_cpu);
    for c in settle_cpus.iter() {
        if let Some(transition) = scheduler::take_leaf_transition(c) {
            s.settle_leaf_transition(transition);
        }
        if let Some(completed) = scheduler::take_leaf_switch_completion(c) {
            #[cfg(feature = "krn2-observe")]
            if let Some((token, end)) = completed.resume { s.note_raw_resume_for(token, end, 3); }
            s.finish_switch(c, Some((completed.prev, completed.token)));
        }
    }
    #[cfg(feature = "krn2-observe")]
    { s.origin_total.record(_origin); s.origin_window.record(_origin); }
    let mut leaves: [Option<TickGuard>; kernel_core::smp::MAX_CPUS] = [const { None }; kernel_core::smp::MAX_CPUS];
    // Author: chatgpt. Online membership only grows under this global lock.
    // Include the caller BEFORE its first cpu_online registration. Other offline
    // CPUs have never received permits; they cannot produce pending accounting.
    let mut participants = match _origin {
        Origin::BspTick => s.bsp_tick_lease_participants(),
        _ => s.online(),
    };
    participants.insert(crate::arch::cpu_index());
    #[cfg(feature = "krn2-observe")]
    let mut work = [1u32, 0, 0, 0];
    for (c, lock) in TICK_LEASES.iter().enumerate() {
        if participants.contains(c) {
            #[cfg(feature = "krn2-observe")]
            {
                let (guard, spins) = lock.lock_counted();
                work[1] += 1;
                work[2] += (spins != 0) as u32;
                work[3] = work[3].wrapping_add(spins);
                leaves[c] = Some(guard);
            }
            #[cfg(not(feature = "krn2-observe"))]
            { leaves[c] = Some(lock.lock()); }
        }
    }
    #[cfg(feature = "krn2-observe")]
    for (counter, value) in SYNC_WORK[crate::arch::cpu_index()].iter().zip(work) {
        counter.fetch_add(value, core::sync::atomic::Ordering::Relaxed);
    }
    // A pending voluntary yield forbids a new fast tick. Therefore a deferred
    // tick always precedes any still-pending yield; charge first, then reset the
    // Watchdog streak. This preserves order instead of treating resets as sums.
    for (c, leaf) in leaves.iter_mut().enumerate() {
        if let Some((owner, ticks)) = leaf.as_mut().and_then(|leaf| leaf.drain()) { s.drain_local_ticks(c, owner, ticks); }
    }
    for (c, gate) in YIELD_GATES.iter().enumerate() {
        if gate.take_yielded() { s.note_fast_yield(c); }
    }
    for token in inbox.wakes.into_iter().flatten() { s.consume_wake_token(token); }
    for message in inbox.pi.into_iter().flatten() { s.consume_pi_message(local_cpu, message); }
    if crate::hrtime::enabled(){s.settle_highres(crate::hrtime::now().expect("high-res monotonic clock"));}
    StateGuard(s, leaves, false)
}

/// 以共享借用访问调度器（持锁、关中断执行：时钟中断与其他处理器也会访问调度器状态）。
fn with<R>(f: impl FnOnce(&Scheduler) -> R) -> R {
    f(&lock_state_from(Origin::Read))
}

/// 以独占借用访问调度器（持锁、关中断执行）；调用者不得在闭包内触发栈切换。
/// 闭包期间记下的重新调度请求在放锁之后发出。
fn with_mut<R>(f: impl FnOnce(&mut Scheduler) -> R) -> R {
    with_mut_from(Origin::Mutation, f)
}
fn with_mut_from<R>(origin: Origin, f: impl FnOnce(&mut Scheduler) -> R) -> R {
    let started = crate::arch::cycles();
    let (r, kicks) = {
        let mut s = lock_state_from(origin);
        #[cfg(feature = "krn2-observe")]
        let (slot, generation) = s.raw_callback_identity();
        #[cfg(feature = "krn2-observe")]
        let start = kernel_core::raw_timing::Endpoint { cpu: cpu::cpu_index(), counter: cpu::cycles(), clock: kernel_core::raw_timing::ClockDomain::Raw };
        let r = f(&mut s);
        #[cfg(feature = "krn2-observe")]
        {
            let end = kernel_core::raw_timing::Endpoint { cpu: cpu::cpu_index(), counter: cpu::cycles(), clock: kernel_core::raw_timing::ClockDomain::Raw };
            // Path 1 = callback only, NOT wake latency. No wait round exists.
            let _ = s.raw_callbacks.push(kernel_core::raw_timing::Sample {
                path: 1, slot, generation, wait_round: 0, start, end,
            });
        }
        s.refresh_ns_events();
        s.2 = true;
        (r, s.take_kicks())
    };
    // Observed with_mut interval: includes global-lock waiting, leaf drain, callback,
    // publication and guard release; excludes send_kicks. Not pure lock hold time
    // or a proven WCET bound. Direct lock_state/with paths are not sampled here.
    crate::wcet::record_lock(crate::arch::cycles().wrapping_sub(started));
    send_kicks(kicks);
    r
}

/// 对需要重新调度的其他处理器发核间中断（不持任何锁时调用；目标不在线时忽略——它上线后自己会查队列）。
fn send_kicks(kicks: CpuSet) {
    let me = cpu::cpu_index();
    for c in kicks.iter().filter(|&c| c != me) {
        let _ = crate::smp::reschedule(c);
    }
}

#[cfg(feature = "krn2-observe")]
fn wake_endpoint() -> kernel_core::raw_timing::Endpoint {
    let cpu = cpu::cpu_index();
    if let Some(counter) = crate::hrtime::now() {
        kernel_core::raw_timing::Endpoint {
            cpu,
            counter,
            clock: kernel_core::raw_timing::ClockDomain::SharedNs,
        }
    } else {
        kernel_core::raw_timing::Endpoint {
            cpu,
            counter: cpu::cycles(),
            clock: kernel_core::raw_timing::ClockDomain::Raw,
        }
    }
}

/// 切换完成：在新执行流的开头（关中断时）调用，释放刚换下的任务并发出由此产生的重新调度请求。
fn finish_switch() {
    #[cfg(feature = "krn2-observe")]
    let end = wake_endpoint();
    // The resumed CPU owns this completion.  Consume the leaf-local switch
    // marker and release the saved execution owner before waiting for global
    // cold-state bookkeeping.
    #[cfg(feature = "krn2-observe")]
    let immediate = scheduler::finish_leaf_switch(cpu::cpu_index(), Some(end));
    #[cfg(not(feature = "krn2-observe"))]
    let immediate = scheduler::finish_leaf_switch(cpu::cpu_index(), None);
    if immediate {
        #[cfg(feature = "krn3-fast-tick-verify")]
        crate::kprintln!("[JSR-KRN3-COLD] cpu={} immediate=true", cpu::cpu_index());
        // Empty mutation: lock acquisition consumes the just-published cold
        // completion and sends any migration kick after releasing the guard.
        with_mut(|_| {});
    }
}

/// 调度器锁遇到占用的次数（多处理器同时访问调度器时增长）。
/// Contended acquisitions of the scheduler lock.
pub fn lock_contended() -> u32 {
    KERNEL_SCHED.contended()
}

/// 调度器锁的争用测量值。
/// Contention counters of the scheduler lock.
pub fn lock_stats() -> crate::sync::LockStats {
    KERNEL_SCHED.stats()
}

// Author: chatgpt. Test-only batching invokes the unmodified production wake
// handler while holding one scheduler transaction. No fake queue entries.
#[cfg(feature = "fault-inject")]
pub fn fault_wake_batch(ids: &[TaskId]) {
    assert!(ids.len() <= scheduler::WAKE_MAILBOX_CAPACITY + 1);
    with_mut(|s| { for &id in ids { s.wake(id); } });
}
#[cfg(feature = "fault-inject")]
pub fn fault_delay_deadline_timer(c: usize, enable: bool) { with_mut(|s| s.fault_delay_deadline_timer(c, enable)); }
#[cfg(feature = "fault-inject")]
pub fn fault_deadline_trace(c: usize) -> Option<scheduler::DeadlineTrace> { with(|s| s.fault_deadline_trace(c)) }
pub fn deadline_owners(id: TaskId) -> Option<(Option<usize>, Option<usize>)> { with(|s| s.deadline_owners(id)) }
pub fn deadline_stats() -> ([u32; kernel_core::smp::MAX_CPUS], [u32; kernel_core::smp::MAX_CPUS]) { with(|s| s.deadline_stats()) }
pub fn rt_utilisation()->u32 {with(|s|s.rt_utilisation())}
pub fn rt_state(id: TaskId) -> Option<(u32,u32,u64)> { with(|s| s.rt_state(id)) }
pub fn remote_wake_stats() -> (u32, u32) {
    (REMOTE_WAKES.load(Ordering::Relaxed), WAKE_FALLBACKS.load(Ordering::Relaxed))
}
pub fn remote_pi_stats() -> (u32, u32) {
    (REMOTE_PI.load(Ordering::Relaxed), PI_FALLBACKS.load(Ordering::Relaxed))
}

pub fn local_tick_bypasses() -> u32 {
    let state = lock_state();
    state.1.iter().flatten().fold(0u32, |n, leaf| n.wrapping_add(leaf.hits()))
}

#[cfg(feature = "krn3-fast-tick-verify")]
pub fn leaf_finish_count() -> u32 { scheduler::leaf_finish_count() }
#[cfg(feature = "krn3-fast-tick-verify")]
pub fn leaf_worker_finish_count() -> u32 { scheduler::leaf_worker_finish_count() }
#[cfg(feature = "krn3-fast-tick-verify")]
pub fn leaf_local_switch_count() -> u32 { scheduler::leaf_local_switch_count() }
#[cfg(feature = "krn3-fast-tick-verify")]
pub fn local_tick_batch_peak(cpu: usize) -> u8 { TICK_LEASES[cpu].lock().peak() }
#[cfg(feature = "krn3-fast-tick-verify")]
pub fn local_tick_hits(cpu: usize) -> u32 { TICK_LEASES[cpu].lock().hits() }

/// Diagnostic snapshot used by the isolated KRN-3 fast-tick contract.  The
/// global transaction drains any pending lease before reading the exact
/// generation-bound entity from its home leaf.
#[cfg(feature = "krn3-fast-tick-verify")]
pub fn task_cpu_ticks(id: TaskId) -> Option<u64> {
    with(|s| s.task_cpu_ticks(id))
}

/// 清零调度器锁的争用测量值。
pub fn reset_lock_stats() {
    #[cfg(feature = "krn2-observe")]
    {
        let mut state = lock_state();
        state.raw_callbacks = kernel_core::raw_timing::Samples::new();
        state.pi_window = kernel_core::pi_work::PiWork::EMPTY;
        state.origin_window.clear();
        KERNEL_SCHED.reset_stats();
        for row in &SYNC_WORK { for value in row {
            value.store(0, core::sync::atomic::Ordering::Relaxed);
        }}
    }
    #[cfg(not(feature = "krn2-observe"))]
    KERNEL_SCHED.reset_stats();
}

/// 选择路径的遍历量统计（见 [`scheduler::ScanStats`]）。
/// Selection-path scan statistics.
pub fn scan_stats() -> scheduler::ScanStats {
    with(|s| s.scan_stats())
}

/// 清零选择路径的遍历量统计。
pub fn reset_scan_stats() {
    with_mut(|s| s.reset_scan_stats());
}

/// 启动时的内核地址空间（第一次切换时记录；`space = None` 的任务都运行在它上面）。
static KERNEL_SPACE: spin::Once<cpu::SpaceRoot> = spin::Once::new();

/// 是否允许定时器抢占（默认开启，见模块文档）。
static PREEMPTION: AtomicBool = AtomicBool::new(true);
/// 调度器看到的定时器 tick 总数（在中断上下文中递增，任务可据此做基于时间的等待）。
static TIMER_TICKS: IrqU64 = IrqU64::new(0);

/// 新任务的公共入口：执行任务体，返回后标记退出并让出 CPU（永不返回）。
extern "C" fn task_trampoline() -> ! {
    // 先完成切换（仍在关中断下）：换下的那个任务从此才可被其他处理器选中
    finish_switch();
    // 新任务可能是在定时器中断里被首次切入的：那时 CPU 处于关中断状态，
    // 而这条路径不会经过中断返回来恢复标志位 ⇒ 抢占开启时必须在这里显式开中断，
    // 否则该任务将永远无法再被抢占。其他处理器上一律开中断：协作式演练只在引导处理器上进行，
    // 而其他处理器关着中断运行任务会收不到本地时钟与核间中断（该核从此不再参与调度）。
    if PREEMPTION.load(Ordering::Relaxed) || cpu::cpu_index() != 0 {
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

pub fn clear_observer() {
    with_mut(Scheduler::clear_observer);
}

/// 启动期扩容：任务槽位扩到 `slots`（启动期容量），并为新增槽位预留内核栈。
/// 只在堆就绪后、其他处理器上线前调用一次；返回有栈可用的槽位总数（含引导线程槽位）。
/// 前 [`stack::STATIC_STACKS`] 个槽位在内核堆初始化之前即可用。
pub fn grow(slots: usize) -> Result<usize, GrowError> {
    with_mut(|s| s.grow(slots))
}

/// 任务表的槽位总数（启动期扩容之前为内联槽位数）。
pub fn slots() -> usize {
    with(|s| s.slots())
}

/// 每个任务槽位在启动期占用的字节数（任务表与调度暂存各一项 + 内核栈），供启动期容量的内存预算使用。
pub const BYTES_PER_TASK: usize = scheduler::BYTES_PER_SLOT + stack::STACK_SIZE;

/// 可用槽位总数（含引导线程槽位）。
pub fn capacity() -> usize {
    with(|s| s.capacity())
}

/// 新建内核任务（继承当前工作任务的 QoS 档位与上限）。
pub fn spawn(id: TaskId, name: &'static str, entry: fn()) -> Result<usize, SpawnError> {
    with_mut(|s| s.spawn(id, name, entry, task_trampoline))
}

/// 新建内核任务并指定亲和集合（允许运行的处理器）；任务按负载放进其中某个处理器的运行队列。
/// 集合里没有在线处理器时拒绝（[`SpawnError::BadAffinity`]），状态不变。`group` 同 [`spawn_in`]。
/// Spawns a kernel task with an explicit affinity set.
pub fn spawn_on(id: TaskId, name: &'static str, entry: fn(), group: Option<CpuGroupId>, affinity: CpuSet) -> Result<usize, SpawnError> {
    with_mut(|s| s.spawn_on(id, name, entry, task_trampoline, group, Some(affinity)))
}

/// 修改任务 `id` 的亲和集合（立即生效：正在别处运行的会被那个处理器在下一个 tick 换下并迁移）。
/// 集合里没有在线处理器、任务无效时拒绝，状态不变。
/// Changes the affinity set of task `id`.
pub fn set_affinity(id: TaskId, set: CpuSet) -> Result<(), AffinityError> {
    let stay = with_mut(|s| s.set_affinity(id, set))?;
    if !stay {
        // 修改的正是当前任务、且本处理器已不在集合内：立即换下
        yield_with_cause(Cause::MIGRATE);
    }
    Ok(())
}

/// 任务 `id` 曾经运行过的处理器集合。
/// Processors task `id` has run on.
pub fn ran_on(id: TaskId) -> Option<CpuSet> {
    with(|s| s.ran_on(id))
}

/// 尚未退出的工作任务数（不含引导线程）。
/// Number of live worker tasks.
pub fn live_workers() -> usize {
    with(|s| s.live_workers())
}

/// 参与调度的处理器集合。
/// Processors taking part in scheduling.
pub fn online_cpus() -> CpuSet {
    with(|s| s.online())
}

/// 处理器 `c` 的调度统计（忙 / 闲 tick、空闲等待上界、窃取与均衡次数）。
/// Scheduling statistics of processor `c`.
pub fn cpu_stats(c: usize) -> CpuStats {
    with(|s| s.cpu_stats(c))
}

/// 清零全部处理器的调度统计（测量场景开始前调用）。
/// Reset all per-processor scheduling statistics.
pub fn reset_cpu_stats() {
    with_mut(|s| s.reset_cpu_stats());
}

/// 其他处理器的空闲执行流（由多处理器子系统在处理器报到后调用，永不返回）：加入调度，
/// 之后反复「关中断检查本处理器是否有事可做 → 有则切过去 → 没有则开中断休眠到下一个中断」。
/// 检查与休眠之间不会漏掉唤醒：休眠指令与开中断是原子组合。
///
/// 空闲停表：机制层允许时（[`Scheduler::idle_enter`] 返回 `Stop`），休眠前把本地定时器推迟若干 tick；
/// 无论被什么中断唤醒（核间中断、设备中断、推迟后的那次 tick），醒来第一件事就是结束停表并恢复周期 tick，
/// 因此本处理器一旦有事可做，记账与预算补充立刻回到每 tick 一次。平台不支持推迟时如实退回周期 tick。
/// Idle flow of a secondary processor, with tickless idle.
pub fn idle_loop(c: usize) -> ! {
    with_mut(|s| s.cpu_online(c));
    loop {
        let was_enabled = cpu::irq_save_disable();
        crate::smp::percpu::this().take_resched();
        if crate::hrtime::enabled() {
            let needs_tick=crate::irq::device::cpu_needs_tick();
            match with_mut(|s|s.highres_idle(c,needs_tick)) {
                IdleStep::Run(cause)=>yield_with_cause(cause),
                _=>{cpu::wait_for_interrupt();with_mut(|s|s.idle_exit(c));}
            }
            cpu::irq_restore(was_enabled);continue;
        }
        let needs_tick = crate::irq::device::cpu_needs_tick();
        match with_mut(|s| s.idle_enter(c, needs_tick)) {
            IdleStep::Run(cause) => yield_with_cause(cause),
            IdleStep::Sleep => cpu::wait_for_interrupt(),
            IdleStep::Stop(ticks) => {
                if cpu::timer_stretch(ticks) {
                    cpu::wait_for_interrupt();
                    // 先在机制层结束停表（补记空闲时长），再恢复每 tick 一次
                    with_mut(|s| s.idle_exit(c));
                    cpu::timer_resume();
                } else {
                    // 平台不支持推迟：撤销登记，按周期 tick 休眠
                    with_mut(|s| s.idle_exit(c));
                    cpu::wait_for_interrupt();
                }
            }
        }
        cpu::irq_restore(was_enabled);
        crate::smp::percpu::this().count_idle_wakeup();
    }
}

/// 按当前配置档设置空闲停表：功耗策略为 tickless 时以配置的空闲倍率停表，否则保持周期 tick。
/// 返回生效的倍率（< 2 表示未启用）。
/// Apply the profile's power policy to tickless idle; returns the active divisor.
pub fn configure_idle_tick() -> u32 {
    let policy = crate::config::ACTIVE.policy;
    let divisor = match policy.power {
        kernel_core::config::PowerPolicy::Tickless => policy.idle_tick_divisor,
        kernel_core::config::PowerPolicy::Periodic => 0,
    };
    with_mut(|s| s.set_idle_tick(divisor));
    divisor
}

/// 设置空闲停表的最大间隔（< 2 关闭），返回之前的设置（演练对照测量用，结束时以返回值恢复）。
/// Set the tickless-idle divisor; returns the previous one.
pub fn set_idle_tick(divisor: u32) -> u32 {
    with_mut(|s| s.set_idle_tick(divisor))
}

/// 空闲停表的统计快照。
/// Snapshot of tickless-idle statistics.
pub fn nohz_stats() -> NohzStats {
    with(|s| s.nohz_stats())
}

/// 新建内核任务并放入 CPU 组 `group`（受该组上限约束）。组无效时拒绝。
pub fn spawn_in(id: TaskId, name: &'static str, entry: fn(), group: CpuGroupId) -> Result<usize, SpawnError> {
    with_mut(|s| s.spawn_in(id, name, entry, task_trampoline, Some(group)))
}

/// 新建 CPU 组（上限千分比，桶容量取默认值）；调用者持有一份引用，用完以 [`release_cpu_group`] 归还。
/// Creates a CPU group with the default burst.
/// 用当前 Profile 的默认份额创建 CPU 组（份额来自配置档，不写死在调用点）。
pub fn create_cpu_group_default() -> Result<CpuGroupId, GroupError> {
    create_cpu_group(crate::config::ACTIVE.policy.group_share_permille)
}

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

pub fn fast_yield_count() -> u64 {
    YIELD_GATES.iter().map(|g| g.hits() as u64).sum()
}

/// 主动让出 CPU。
pub fn yield_now() {
    let was_enabled = cpu::irq_save_disable();
    let c = cpu::cpu_index();
    if !crate::smp::percpu::this().resched_pending() && YIELD_GATES[c].try_yield() {
        cpu::irq_restore(was_enabled);
        return;
    }
    yield_with_cause(Cause::YIELD);
    cpu::irq_restore(was_enabled);
}

/// 带原因的让出：准备切换后在**没有任何借用**的情况下执行真正的栈切换。
///
/// 整个「准备 + 切换」在关中断临界区内完成：否则定时器中断可能在调度器状态改到一半时
/// 再次进入调度器（重入）。切换回来后恢复**本任务自己**被切走前的中断状态——
/// 每个任务的中断标志随它的栈一起保存/恢复，互不影响。
pub fn yield_with_cause(cause: &'static str) {
    let was_enabled = cpu::irq_save_disable();
    // 锁与借用都在本块内结束，不跨越下面的栈切换（中断仍关着）。
    let (plan, kicks) = {
        let mut s = lock_state_from(Origin::Switch);
        let plan = s.prepare_switch(cause);
        (plan, s.take_kicks())
    };
    send_kicks(kicks);
    if let Some(plan) = plan {
        execute_switch_plan(plan);
    } else {
        #[cfg(feature = "krn2-observe")]
        {
            let end = wake_endpoint();
            with_mut(|s| s.note_raw_resume(end, 4)); // continued on the same context
        }
    }
    cpu::irq_restore(was_enabled);
}

/// Execute a plan prepared while interrupts were masked.  Timer paths prepare
/// the plan in the same global transaction that performed accounting, so they
/// do not reacquire `KERNEL_SCHED` between the decision and context switch.
fn execute_switch_plan(plan: scheduler::SwitchPlan) {
    let kernel_space = *KERNEL_SPACE.call_once(cpu::current_space);
    if let Some(top) = plan.next_stack_top {
        cpu::set_kernel_stack(top);
    }
    let target = plan.next_space.unwrap_or(kernel_space);
    if cpu::current_space() != target {
        // SAFETY：任务记录的空间由其所有者保证在任务存活期间有效；内核空间始终有效。
        unsafe { cpu::switch_space(target) };
    }
    crate::smp::percpu::this().set_space(plan.next_space);
    crate::smp::percpu::this().set_current(plan.next_slot);
    // SAFETY：old/new 指向全局调度器内的任务上下文，在切换期间保持有效；
    // new 要么由栈池伪造，要么由上一次 switch_context 保存。
    unsafe { switch_context(plan.old, plan.new) };
    finish_switch();
}

/// 让当前工作任务睡眠到时刻 `deadline`（tick），期间不占用处理器；到期由时钟中断唤醒。
/// 已到期时立即返回。所属进程开始终止时会被 [`wake`] 提前唤醒——调用者醒来后须自行检查等待条件。
/// 在引导线程上调用时退化为「先让出、再休眠到下一个中断」（引导线程是空闲时的落脚点，不能睡眠）。
/// Sleeps the current worker until `deadline` (ticks) without consuming CPU.
/// 设置任务的实时预算与周期（抢占式节流的入口）。
pub fn set_rt(id: crate::task::TaskId, quota: u32, period: u32) -> bool {
    let now = timer_ticks();
    with_mut(|s| s.set_rt(id, quota, period, now))
}

/// 累计因预算/资格不可运行而被换下的次数。
pub fn throttle_count() -> u32 {
    scheduler::throttle_count()
}

/// 打开/关闭类别仲裁（POL-5）；默认关闭，行为与接入前一致。
pub fn set_arbiter(on: bool) -> bool {
    with_mut(|s| s.set_arbiter(on))
}

/// Enable only after clock/LAPIC calibration and AP registration, before RT admission.
pub fn enable_highres()->bool {
    let Some(now)=crate::hrtime::now() else{return false;};
    with_mut(|s|{s.enable_highres(now);crate::hrtime::enable();});true
}
pub fn ns_sleeping(id:TaskId)->bool{with(|s|s.ns_sleeping(id))}
pub fn rt_ns_state(id:TaskId)->Option<kernel_core::ns_budget::Budget>{with(|s|s.rt_ns_state(id))}
pub fn set_rt_ns(id:TaskId,quota:u64,period:u64)->bool {with_mut(|s|s.set_rt_ns(id,quota,period))}
/// Absolute ns deadline. Spurious/exit wakes return to the caller to recheck.
pub(crate) fn reserve_sleep_ns(deadline:u64)->bool {with_mut(|s|s.block_current_ns(deadline))}
pub fn sleep_until_ns(deadline:u64)->Result<(),()> {
    if !crate::hrtime::enabled(){return Err(());}
    let irq=cpu::irq_save_disable();
    if with_mut(|s|s.block_current_ns(deadline)){yield_with_cause(Cause::SLEEP);}
    cpu::irq_restore(irq);Ok(())
}
pub fn on_highres_timer() {
    crate::smp::percpu::this().take_resched();
    // Keep the due publication, scheduling decision and switch publication in
    // one transaction.  The old path returned a cause and immediately took
    // KERNEL_SCHED again through yield_with_cause(), adding another queue wait
    // to every simultaneous per-CPU deadline fanout.
    let (credits,plan)=with_mut_from(Origin::ApFallback,|s| {
        let (credits,cause)=s.highres_event(PREEMPTION.load(Ordering::Relaxed));
        (credits,cause.and_then(|cause|s.prepare_switch(cause)))
    });
    if cpu::cpu_index()!=0 {crate::irq::on_elapsed_cpu_ticks(credits);}
    if let Some(plan)=plan {execute_switch_plan(plan);}
}

/// 睡到 tick `deadline`（已过则立即返回）。
/// Sleep until tick `deadline` (returns at once if it has passed).
pub fn sleep_until(deadline: u64) {
    let was_enabled = cpu::irq_save_disable();
    sleep_masked(deadline);
    cpu::irq_restore(was_enabled);
}

/// 从现在起睡 `ticks` 个 tick（`ticks` ≥ 1 时总是真的睡下，并在第 `ticks` 个全局 tick 被唤醒）。
///
/// 截止时刻在**调度器锁内**按调度器的时刻计算，并在同一次持锁内睡下：全局时钟由计时处理器在同一把锁内推进，
/// 因此「取时刻」与「睡下」之间不可能插进一个 tick。只关本处理器的中断不够——多处理器下计时处理器随时可能推进时钟，
/// 截止时刻在睡下之前就已过去会让这次睡眠变成空操作（RISC-V32 × 4 在较慢的宿主上实测出现）。
/// 不在工作任务上（引导线程）时退回「让出并休眠到下一个中断」。
/// Sleep for `ticks` ticks; the deadline is taken and the task blocked in one scheduler critical section.
pub fn sleep_ticks(ticks: u64) {
    if ticks == 0 {
        return;
    }
    let was_enabled = cpu::irq_save_disable();
    if with_mut(|s| s.block_current_for(ticks)) {
        yield_with_cause(Cause::SLEEP);
    } else {
        yield_now();
        cpu::wait_for_interrupt();
    }
    cpu::irq_restore(was_enabled);
}

/// 关中断状态下睡到 `deadline`（调用者负责关 / 恢复中断）。
fn sleep_masked(deadline: u64) {
    if timer_ticks() < deadline {
        if with_mut(|s| s.block_current(Some(deadline))) {
            yield_with_cause(Cause::SLEEP);
        } else {
            yield_now();
            cpu::wait_for_interrupt();
        }
    }
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

/// 任务 `waiter` 此刻是否阻塞在等待 `owner`（等它持有的锁或等它退出；诊断与验收用）。
/// Whether `waiter` is currently blocked on `owner`.
pub fn waits_on(waiter: TaskId, owner: TaskId) -> bool {
    with(|s| s.waits_on(waiter, owner))
}

/// Object-table callers use these three operations while holding the object
/// lock, preserving the existing object(4) -> scheduler(8) lock order. They
/// must release every guard before yielding.
pub(crate) fn block_on_owner(owner: TaskId, key: u64) -> Result<(), ()> {
    with_mut(|s| s.block_on(owner, key).map_err(|_| ()))
}

pub(crate) fn hand_off_object(key: u64) -> Option<TaskId> {
    with_mut(|s| s.hand_off(key))
}

pub(crate) fn cancel_object_waiters(owner: TaskId, key: u64) -> usize {
    with_mut(|s| s.cancel_waiters(owner, key))
}

pub(crate) fn task_is_live(id: TaskId) -> bool {
    with(|s| s.is_live(id))
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

/// Author: chatgpt。仅供对象锁内事件登记；返回后须先释放对象锁再yield。
pub fn enroll_event_wait(
    deadline: Option<u64>,
    donation: Option<(TaskId, u64)>,
) -> Result<Option<kernel_core::event_wait::Key>, ()> {
    with_mut(|s| s.enroll_event_wait(deadline, donation))
}
/// 事件通知携带完整凭据；不匹配时不产生TaskId-only后备唤醒。
pub fn wake_event_wait(key: kernel_core::event_wait::Key) {
    with_mut(|s| { s.wake_event_wait(key); });
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

/// 当前策略所属的调度类别。
/// Scheduling class of the built-in policy.
pub fn policy_class() -> policy::SchedClass {
    <KernelPolicy as policy::SchedPolicy>::CLASS
}

/// 核对任务表与各运行队列（入队计数、成员关系、被拒绝的钩子调用）。
/// Cross-check the task table against the per-CPU run queues.
pub fn queue_audit() -> scheduler::QueueAudit {
    with(|s| s.queue_audit())
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
    while !with(|s| s.workers_settled()) {
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
        crate::smp::percpu::this().set_space(space);
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
    // Full locked decision below consumes requests already published before it.
    crate::smp::percpu::this().take_resched();
    let now = TIMER_TICKS.fetch_add(1, Ordering::Relaxed) + 1;
    let preemption = PREEMPTION.load(Ordering::Relaxed);
    let plan = with_mut_from(Origin::BspTick, |s| {
        s.tick(now, preemption).and_then(|cause| s.prepare_switch(cause))
    });
    if let Some(plan) = plan { execute_switch_plan(plan); }
}

/// 其他处理器的本地定时器中断入口（中断上下文，EOI 之后）：给本处理器正在运行的任务记账、
/// 到检查点做周期均衡，需要时就地切换。空闲执行流被打断时不在这里切换（中断返回后空闲循环自己取任务）。
/// Local timer entry of a secondary processor.
pub fn on_local_timer() {
    let requested = crate::smp::percpu::this().take_resched();
    if !requested {
        let fast = {
            let c = cpu::cpu_index();
            TICK_LEASES[c].try_lock().and_then(|mut lease| {
                if YIELD_GATES[c].pending_yield() { return None; }
                let owner = lease.try_tick_owner()?;
                Some(match scheduler::fast_leaf_competing_tick(
                    c, owner, PREEMPTION.load(Ordering::Relaxed),
                ) {
                    scheduler::FastLeafTick::Rejected => {
                        scheduler::fast_leaf_tick(c, owner);
                        scheduler::FastLeafTick::Continued
                    }
                    result => result,
                })
            })
        }; // leaf released before any path can take the global scheduler lock
        match fast {
            Some(scheduler::FastLeafTick::Continued) => return,
            Some(scheduler::FastLeafTick::Switch(plan)) => {
                execute_switch_plan(plan);
                return;
            }
            _ => {}
        }
    }
    let preemption = PREEMPTION.load(Ordering::Relaxed);
    let idle = crate::smp::percpu::this().current() == crate::smp::percpu::IDLE_SLOT;
    let plan = with_mut_from(Origin::ApFallback, |s| {
        if idle { s.local_tick(preemption); None }
        else { s.local_tick(preemption).and_then(|cause| s.prepare_switch(cause)) }
    });
    if let Some(plan) = plan { execute_switch_plan(plan); }
}

// Author: chatgpt. Counts real tick-based AP RT and shared-group charges across
// both the owner-local lease path and the globally serialized fallback path.
pub fn budget_tick_stats() -> [u32; 2] { with(|s| s.budget_tick_stats()) }

// Author: chatgpt. Copy under the existing scheduler guard, print after release.
// No additional lock or scheduler decision consumes these diagnostic records.
#[cfg(feature = "krn2-observe")]
pub fn raw_callback_snapshot() -> kernel_core::raw_timing::Samples<64> {
    lock_state().raw_callbacks
}

// Author: chatgpt. Storage window only; pending starts may predate this reset.
#[cfg(feature = "krn2-observe")]
pub fn reset_raw_wakes() {
    let mut s = lock_state();
    s.raw_pending_at_reset = s.raw_pending_count();
    s.raw_wakes = kernel_core::raw_timing::Samples::new();
    s.wake_latency = kernel_core::raw_timing::NanoHistogram::new();
    s.deadline_to_runnable = kernel_core::raw_timing::NanoHistogram::new();
    s.deadline_to_resume = kernel_core::raw_timing::NanoHistogram::new();
    s.raw_wake_errors = [0; 3];
}
#[cfg(feature = "krn2-observe")]
pub fn raw_wake_snapshot() -> (kernel_core::raw_timing::Samples<64>, kernel_core::raw_timing::NanoSummary, [u64; 3], usize, usize) {
    let s = lock_state();
    (s.raw_wakes, s.wake_latency.summary(), s.raw_wake_errors, s.raw_pending_at_reset, s.raw_pending_count())
}
#[cfg(feature = "krn2-observe")]
pub fn raw_deadline_snapshot() -> (kernel_core::raw_timing::NanoSummary, kernel_core::raw_timing::NanoSummary) {
    let s = lock_state();
    (s.deadline_to_runnable.summary(), s.deadline_to_resume.summary())
}

/// Diagnostic counters are copied under the existing scheduler guard.
#[cfg(feature = "krn2-observe")]
pub fn pi_work_stats() -> (kernel_core::pi_work::PiWork, kernel_core::pi_work::PiWork) {
    with(|s| (s.pi_total, s.pi_window))
}

// Author: chatgpt. Snapshot counts and aggregate in one existing global guard.
// This diagnostic transaction is included; reset itself is cleared from window.
#[cfg(feature = "krn2-observe")]
pub fn global_origin_stats() -> (kernel_core::sync_origin::Counts, kernel_core::sync_origin::Counts, u64) {
    let s = lock_state();
    let aggregate = SYNC_WORK.iter().map(|row| row[0].load(core::sync::atomic::Ordering::Relaxed) as u64).sum();
    (s.origin_total, s.origin_window, aggregate)
}

#[cfg(feature="s3-nohz-verify")]
pub fn nohz_accounting(c:usize)->(u64,u64,u64,u64,bool) { with(|s|s.nohz_accounting(c)) }

/// Reference-clock residency, distinct from local timer interrupt counters.
pub fn cpu_residency(c:usize)->kernel_core::cpu_time::Totals { with(|s|s.cpu_residency(c)) }

/// Diagnostic observation only; does not alter admission or charging.
pub fn budget_window_arm(g:CpuGroupId,window:u64)->u64 { with_mut(|s|s.budget_window_arm(g,window)) }
pub fn budget_window_finish()->Option<(u64,u64,u64,u64,u64,u64,u64)> { with_mut(|s|s.budget_window_finish()) }

/// Return the current-task migration decision; caller must drop object guards
/// before yielding when false. with_mut already publishes reschedule IPIs.
pub(crate) fn set_affinity_deferred(id:TaskId,set:CpuSet)->Result<bool,AffinityError> {with_mut(|s|s.set_affinity(id,set))}
pub(crate) fn task_affinity(id:TaskId)->Option<CpuSet> {with(|s|s.task_affinity(id))}
