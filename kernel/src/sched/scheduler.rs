//! 调度机制（与策略无关的核心）：任务表、状态迁移、睡眠与唤醒、时钟记账、切换准备、切换事件通知。
//!
//! 职责：
//! * 维护任务表（槽位 0 = 引导线程，只在没有可运行工作任务时运行，不参与策略选择）
//! * 把「选谁、给多长时间片、要不要抢占」委托给策略 `P: SchedPolicy`（Strategy 模式），经 Core 的每核运行队列
//!   （`kernel_core::sched::queue::CoreQueue`）在每次状态迁移时调用策略钩子：新建 / 唤醒入队，睡眠 / 退出出队，
//!   被换下（让出、被抢占、预算耗尽）、派发、逐 tick 记账，以及换运行队列时的迁移；钩子调用被拒绝
//!   （成员关系不符）只计数、不改状态，由 [`Scheduler::queue_audit`] 报告
//! * 把「切换发生了」通知给观察者（Observer 模式，函数指针，零分配），
//!   调度器本身因此不依赖串口/日志模块
//! * 记录每档的唤醒延迟（从被唤醒到被选中运行的 tick 数），供过载下的响应性验收
//! * 维护 CPU 组（通常一组 = 一个进程的全部线程）：每组一份 CPU 上限令牌桶（`kernel_core::sched::limit`），
//!   被限速组的成员不参与选择，直到令牌回正——失控进程被限速而不是拖垮整机；借出档位的持有者豁免
//! * 看门狗：每个任务记录自上次**主动**放弃处理器以来连续占用的 tick，越过阈值即写入定长报告日志
//!   （`kernel_core::sched::watchdog`）；只记录，不处置
//! * 维护等待关系（谁在等谁：等锁、等任务退出）并据此重算有效档位（优先级继承，决策见
//!   `kernel_core::sched::inherit`）；策略只看有效档位，因此继承不改动选择与抢占逻辑
//! * **不直接执行**栈切换：`prepare_switch` 只返回新旧上下文的裸指针，
//!   由门面层（`mod.rs`）在放掉所有借用之后调用 `switch_context`。
//!   这样 `&mut Scheduler` 永远不会跨越一次栈切换存活（另一个任务会再次借用它）。
//!
//! * **多处理器**：每个处理器各有当前任务、时间片记账与一份策略实例（欠账、衰减纪元按核独立）；
//!   每个任务属于一个处理器的运行队列（`Task::home`），处理器只从自己的队列选任务。放置、空闲窃取与
//!   周期均衡的决定委托给 `kernel_core::sched::balance`（Strategy），亲和集合是硬约束。
//!   被选中的任务带 `on_cpu` 标记，直到换下它的切换保存完上下文（[`Scheduler::finish_switch`]）才清除，
//!   因此另一个处理器不会恢复一份尚未保存完的上下文。需要别的处理器立即重新调度时记入待发请求，
//!   由门面层放锁后发出核间中断。
//!
//! 可复用性：`Scheduler<P>` 不含任何全局状态，可在多实例场景中直接构造；处理器下标经平台的
//! `cpu_index` 取得（本文件不含指令集代码）。
//!
//! * **容量（启动期决定）**：任务槽位数不是编译期常量。堆就绪之前只有 [`INLINE_SLOTS`] 个内联槽位
//!   （与静态内核栈数相同）；堆就绪后 [`Scheduler::grow`] 在启动期一次性扩到启动容量记录给出的槽位数，
//!   槽位下标不变。扩容只允许在「只有引导线程在运行、只有引导处理器在线、没有切换在途」时进行，否则拒绝。
//!
//! * **规模化（选择路径不扫全表）**：每个运行队列的成员另按槽位号串成侵入式链表
//!   （`kernel_core::sched::runlist`），每次成员关系改变后由 [`Scheduler::relist`] 同步。
//!   选择、等待档位、类别仲裁、窃取 / 均衡候选、CPU 组的「有可运行成员」都只遍历这些链表，
//!   代价与可运行任务数成正比，与任务表容量无关；链表按槽位号有序，策略「同键取先者」的结果不变。
//!   每 tick 的到期唤醒与实时预算补充只在最早到期时刻到达时才扫描（缓存最早时刻）。

use crate::arch::TaskContext;
use crate::task::{Task, TaskId, TaskState};
use kernel_core::deadline::{Deadline, ABSENT as NO_DEADLINE};
use kernel_core::deadline_forest::DeadlineForest;
use kernel_core::task_index::{TaskIndex, Node as IndexNode};
use kernel_core::task_lifecycle::SlotLifecycle;

use kernel_core::object::{advance_generation, GENERATION_RETIRED};
use kernel_core::smp::{CpuSet, MAX_CPUS};
use kernel_core::tickless::{plan_with, StopBoard, TickPlan};

use super::policy::{
    inherit, migrate, new_entity, qos_change_allowed, BalanceParams, Balancer, Candidate, ClassMask, CoreLoad, CoreQueue, CpuLimit, CpuLimitStats,
    Dequeue, Enqueue, EntityState, LatencyHistogram, LimitError, Preempt, Qos, QueueError, Refusal, Requeue, SchedPolicy, Watchdog, WatchdogLog,
    WatchdogReport, QOS_CLASSES,
};
use super::slots::BootSlots;
use kernel_core::sched::{Link, RunLists};
use super::stack::{ReserveError, StackPool, STATIC_STACKS};

/// 堆就绪之前的内联槽位数（与静态内核栈数一致：那时只有这些槽位有栈）。
pub const INLINE_SLOTS: usize = STATIC_STACKS;
pub const WAKE_MAILBOX_CAPACITY: usize = 16;
#[cfg(feature = "fault-inject")]
#[derive(Clone, Copy, Debug)]
pub struct DeadlineTrace {
    pub token: kernel_core::task_index::Token,
    pub at: u64,
    pub requested_at: u64,
    pub stopped: bool,
    pub ipis_before: u32,
    pub ipis_after: u32,
    pub consumed_at: u64,
    pub consumer: usize,
    pub consumed: bool,
}
#[cfg(feature = "fault-inject")]
impl DeadlineTrace {
    const EMPTY: Self = Self { token: kernel_core::task_index::Token { slot: usize::MAX, generation: 0 },
        at: 0, requested_at: 0, stopped: false, ipis_before: 0, ipis_after: 0,
        consumed_at: 0, consumer: usize::MAX, consumed: false };
}


/// 每个槽位在各张随容量增长的表里占用的字节数（任务表、组表、组世代、调度暂存、栈指针表；不含栈本身）。
pub const BYTES_PER_SLOT: usize = core::mem::size_of::<Option<Task>>()
    + core::mem::size_of::<Option<CpuGroup>>()
    + core::mem::size_of::<u32>()
    + 2 * core::mem::size_of::<Option<Qos>>()
    + core::mem::size_of::<Option<usize>>()
    + core::mem::size_of::<bool>()
    + core::mem::size_of::<Link>()
    + core::mem::size_of::<*mut super::stack::Stack>();

/// 启动期扩容被拒绝的原因（被拒时调度器保持原样）。
/// Why the boot-time grow was refused (the scheduler is left unchanged).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrowError {
    /// 不是静止状态：还有引导线程之外的任务在运行、其他处理器已上线或有切换在途。
    NotQuiescent,
    /// 目标容量小于当前容量或小于内联槽位数（容量只增不减）。
    Shrink,
    /// 内核堆不足（任务表 / 调度暂存 / 内核栈）。`available` 是失败时可用的槽位数。
    OutOfMemory {
        /// 失败时有栈可用的槽位数。
        available: usize,
    },
}

/// 引导线程所在槽位（引导处理器的空闲落脚点）。
pub const BOOT_SLOT: usize = 0;
/// 其他处理器运行空闲执行流时的「当前槽位」取值（与每核数据的约定一致）。
/// Current-slot value of a secondary processor running its idle flow.
pub const IDLE: usize = crate::smp::percpu::IDLE_SLOT;

/// 槽位是否为工作任务（不是引导线程、也不是空闲执行流）。
const fn is_worker(slot: usize) -> bool {
    slot != BOOT_SLOT && slot != IDLE
}

/// 执行本代码的处理器下标（平台保证小于 `MAX_CPUS`；越界属平台缺陷，按引导处理器处理而不越界访问）。
fn this_cpu() -> usize {
    let c = crate::arch::cpu_index();
    if c < MAX_CPUS {
        c
    } else {
        0
    }
}

/// 处理器 `c` 没有工作可做时的落脚点：引导处理器回到引导线程，其他处理器回到各自的空闲执行流。
const fn idle_slot(c: usize) -> usize {
    if c == 0 {
        BOOT_SLOT
    } else {
        IDLE
    }
}

/// 一次切换的描述（交给观察者）。
#[derive(Debug, Clone, Copy)]
pub struct SwitchEvent {
    /// 被切走的任务名。
    pub from: &'static str,
    /// 被切入的任务名。
    pub to: &'static str,
    /// 累计切换序号（从 1 开始）。
    pub seq: u64,
    /// 切换原因（见 [`Cause`] 的各个名字）。
    pub cause: &'static str,
}

/// 切换原因的规范名（串口标记与验收脚本依赖这些字符串，改名须同步）。
pub struct Cause;

impl Cause {
    /// 任务主动让出。
    pub const YIELD: &'static str = "yield";
    /// 时间片用完。
    pub const TICK: &'static str = "tick";
    /// 有更高档的任务可运行。
    pub const PREEMPT: &'static str = "preempt";
    /// 低档欠账满一个 tick，补给它的最低份额。
    pub const SHARE: &'static str = "share";
    /// 睡眠任务到期被唤醒并立即抢占。
    pub const WAKE: &'static str = "wake";
    /// 任务进入睡眠。
    pub const SLEEP: &'static str = "sleep";
    /// 任务阻塞在等待关系上（等锁、等任务退出）。
    pub const BLOCK: &'static str = "block";
    /// 任务退出。
    pub const EXIT: &'static str = "exit";
    /// 所在 CPU 组用完了上限，被限速换下。
    pub const THROTTLE: &'static str = "throttle";
    /// 空闲处理器从其他处理器的队列窃取任务。
    pub const STEAL: &'static str = "steal";
    /// 正在运行的任务被移出本处理器（亲和集合不再包含本处理器）。
    pub const MIGRATE: &'static str = "migrate";

    /// 该原因是否表示任务**主动**放弃处理器（看门狗据此清零连续占用）。
    pub fn voluntary(cause: &str) -> bool {
        cause == Cause::YIELD || cause == Cause::SLEEP || cause == Cause::BLOCK || cause == Cause::EXIT
    }

    /// 策略的抢占原因 → 切换原因名。
    pub const fn of(p: Preempt) -> &'static str {
        match p {
            Preempt::Quantum => Cause::TICK,
            Preempt::Higher => Cause::PREEMPT,
            Preempt::Owed => Cause::SHARE,
        }
    }
}

/// 一次切换的执行计划：机制层算好，门面层在放掉借用后执行。
pub struct SwitchPlan {
    /// 保存当前上下文的位置。
    pub old: *mut TaskContext,
    /// 要恢复的上下文。
    pub new: *const TaskContext,
    /// 下一个任务的内核栈顶（引导线程为 `None`，它不会进入用户态）。
    pub next_stack_top: Option<u64>,
    /// 下一个任务的地址空间（`None` = 内核地址空间）。
    pub next_space: Option<crate::arch::SpaceRoot>,
    /// 下一个任务的槽位（记入本处理器的每核数据）。
    pub next_slot: usize,
}

/// 因预算/资格不可运行而被换下的次数（诊断用）。
static THROTTLES: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// 累计的节流换下次数。
pub fn throttle_count() -> u32 {
    THROTTLES.load(core::sync::atomic::Ordering::Relaxed)
}

/// 切换观察者：在真正换栈之前被调用。
pub type SwitchObserver = fn(&SwitchEvent);

/// 新建任务失败的原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnError {
    /// 没有带栈的空闲工作槽位。
    NoFreeSlot,
    /// 标签仍被活任务或尚未换下的退出任务占用。
    DuplicateId,
    /// 指定的 CPU 组无效。
    BadGroup,
    /// 亲和集合里没有在线处理器。
    BadAffinity,
}

/// 修改亲和集合失败的原因。失败时调度器状态不变。
/// Why an affinity change was refused; the scheduler is left unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AffinityError {
    /// 集合里没有在线处理器（含空集）。
    NoOnlineCpu,
    /// 任务不存在、已退出或是引导线程。
    NoTask,
}

/// 一个处理器的调度统计（负载均衡验收用）。
/// Per-processor scheduling statistics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CpuStats {
    /// 运行工作任务的本地 tick 数。
    pub busy_ticks: u64,
    /// 空闲（引导线程或空闲执行流）的本地 tick 数。
    pub idle_ticks: u64,
    /// 当前「空闲但有本可运行的任务在等」的连续 tick 数。
    pub idle_waiting: u32,
    /// 上一项的历史最大值（硬指标：某核队列非空时其他核空闲的时长上界）。
    pub max_idle_waiting: u32,
    /// 空闲窃取成功的次数。
    pub steals: u32,
    /// 周期均衡拉来任务的次数。
    pub pulls: u32,
    /// 周期均衡因缓存仍热而拒绝的次数。
    pub pull_hot: u32,
}

/// 修改 QoS 档位失败的原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QosError {
    /// 想要提升档位，但没有上限能力或超过了上限。
    RaiseDenied,
    /// 当前任务是引导线程（它不参与策略选择，没有档位可言）。
    NotAWorker,
}

/// 建立等待关系（等锁、等任务退出）失败的原因。失败时调度器状态不变。
/// Why blocking on an owner was refused; the scheduler is left unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockError {
    /// 当前任务是引导线程（它是空闲时的落脚点，不能阻塞）。
    NotAWorker,
    /// 持有者不存在或已退出。
    NoOwner,
    /// 等待图拒绝：自等、成环（死锁）或等待链过长。
    Refused(inherit::EdgeError),
}

/// CPU 组标识：槽位 + 世代（组被释放、槽位复用后旧标识失效，不会误指新组）。
/// CPU group identifier (slot + generation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuGroupId {
    slot: usize,
    gen: u32,
}

/// CPU 组操作失败的原因。失败时调度器状态不变。
/// Why a CPU-group operation was refused; the scheduler is left unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupError {
    /// 组表已满。
    NoFreeGroup,
    /// 标识无效（组已释放或从未存在）。
    Stale,
    /// 上限或桶容量不合法。
    Limit(LimitError),
    /// 任务不存在、已退出或是引导线程。
    NoTask,
}

/// 一个 CPU 组：上限记账 + 引用数（持有者 1 份 + 每个未退出的成员 1 份；归零即释放槽位）。
struct CpuGroup {
    gen: u32,
    limit: CpuLimit,
    refs: u32,
}

/// 任务表与运行队列的核对结果（见 [`Scheduler::queue_audit`]）。全部为 0 表示钩子调用与状态迁移一致。
/// Result of cross-checking the task table against the run queues.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueAudit {
    /// 各队列入队计数之和。
    pub queued: u32,
    /// 成员关系与状态不符的任务数（可运行却不在归属队列上，或睡眠 / 退出却仍在队列上）。
    pub misplaced: u32,
    /// 入队计数与任务表不符的队列数。
    pub count_mismatch: u32,
    /// 累计被拒绝的钩子调用次数。
    pub hook_errors: u32,
    /// 最近一次被拒绝的原因。
    pub last_hook_error: Option<QueueError>,
    /// 运行列表与运行队列不一致的处数（列表长度与入队计数不符的队列数 + 列表成员关系与实体队列字段不符的任务数）。
    pub list_mismatch: u32,
}

/// 选择路径的遍历量统计：每次选择只遍历本处理器的运行列表，这里记下遍历长度，
/// 供验收核对「遍历量与可运行任务数相当、与任务表容量无关」。
/// Selection-path scan statistics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScanStats {
    /// 选择次数（`prepare_switch` 调用数）。
    pub picks: u64,
    /// 累计遍历的列表项数。
    pub visited: u64,
    /// 单次选择遍历的最多项数。
    pub max_visited: u32,
    /// 统计期间实际执行的到期唤醒扫描次数（最早到期时刻到达时才扫描）。
    pub wake_scans: u64,
    /// 统计期间的全局 tick 数（对照：没有最早时刻缓存时每个 tick 都要扫描一次）。
    pub ticks: u64,
}

/// 实体从它所在的队列出队（睡眠或退出）；不在任何队列时拒绝。
fn dequeue_from<P: SchedPolicy>(queues: &mut [CoreQueue<P>], e: &mut kernel_core::sched::SchedEntity<P::State>, why: Dequeue) -> Result<(), QueueError> {
    match e.queue() {
        Some(q) if q < queues.len() => queues[q].dequeue(e, why),
        q => Err(QueueError::NotQueued(q)),
    }
}

/// 看门狗报告日志容量。
pub const WATCHDOG_LOG: usize = crate::config::ACTIVE.sched.watchdog_log;

/// 调度机制本体。槽位总数（含引导线程）在启动期决定，见 [`Scheduler::grow`]。
pub struct Scheduler<P: SchedPolicy> {
    #[cfg(feature = "krn2-observe")]
    pub(super) raw_callbacks: kernel_core::raw_timing::Samples<64>,
    #[cfg(feature = "krn2-observe")]
    pub(super) raw_wakes: kernel_core::raw_timing::Samples<64>,
    #[cfg(feature = "krn2-observe")]
    pub(super) raw_wake_errors: [u64; 3], // begin, finish, exit-with-pending
    #[cfg(feature = "krn2-observe")]
    pub(super) raw_pending_at_reset: usize,
    tasks: BootSlots<Option<Task>, INLINE_SLOTS>,
    // Author: chatgpt. One canonical generation state per slot; lock serialized.
    epochs: BootSlots<SlotLifecycle, INLINE_SLOTS>,
    id_index: Option<TaskIndex<BootSlots<IndexNode, { 2 * INLINE_SLOTS - 1 }>>>,
    stacks: StackPool,
    /// Successfully published, not-yet-exited workers (boot slot excluded).
    workers: usize,
    wake_mailboxes: [kernel_core::wake_mailbox::WakeMailbox<WAKE_MAILBOX_CAPACITY>; MAX_CPUS],
    remote_wakes: u32,
    wake_fallbacks: u32,
    limit_tick_drains: [u32; 2],
    /// 每个处理器的运行队列（各持一份策略实例；成员关系与入队计数由它维护）。
    queues: [CoreQueue<P>; MAX_CPUS],
    /// 每个运行队列的成员链表（表头与长度；链接在 `links` 里，与任务表同容量）。
    runs: RunLists<MAX_CPUS>,
    links: BootSlots<Link, INLINE_SLOTS>,
    /// 同步运行列表时被拒绝的次数（正常运行时恒为 0）。
    list_errors: u32,
    /// 睡眠任务中最早的定时唤醒时刻（`u64::MAX` = 没有；可能偏早，不会偏晚）。
    next_wake: [u64; MAX_CPUS],
    wake_heap: DeadlineForest<MAX_CPUS>,
    wake_entries: BootSlots<Deadline, {INLINE_SLOTS * MAX_CPUS}>,
    wake_positions: BootSlots<usize, INLINE_SLOTS>,
    wake_owners: BootSlots<usize, INLINE_SLOTS>,
    /// 实时任务中最早的预算补充时刻（`u64::MAX` = 没有；可能偏早，不会偏晚）。
    next_rt: [u64; MAX_CPUS],
    rt_heap: DeadlineForest<MAX_CPUS>,
    rt_entries: BootSlots<Deadline, {INLINE_SLOTS * MAX_CPUS}>,
    rt_positions: BootSlots<usize, INLINE_SLOTS>,
    rt_owners: BootSlots<usize, INLINE_SLOTS>,
    /// 选择路径的遍历量统计。
    scan: ScanStats,
    /// 被运行队列拒绝的钩子调用次数（成员关系不符；正常运行时恒为 0）与最近一次的原因。
    hook_errors: u32,
    last_hook_error: Option<QueueError>,
    /// 每个处理器的当前槽位（引导处理器起初为引导线程，其他处理器为空闲执行流）。
    current: [usize; MAX_CPUS],
    /// 其他处理器空闲执行流被切走时保存上下文的位置。
    idle_ctx: [TaskContext; MAX_CPUS],
    /// 每个处理器上一次切换换下的槽位（切换完成后由 [`Scheduler::finish_switch`] 清除其 `on_cpu`）。
    switching_from: [Option<usize>; MAX_CPUS],
    /// 参与调度的处理器（引导处理器总在其中；其他处理器进入空闲执行流时加入）。
    online: CpuSet,
    /// 放置 / 窃取 / 周期均衡的决定者。
    balancer: Balancer,
    /// 待发的重新调度请求（门面层放锁后对这些处理器发核间中断）。
    kicks: CpuSet,
    /// 每个处理器的调度统计。
    cpu_stats: [CpuStats; MAX_CPUS],
    deadline_wakes: [u32; MAX_CPUS],
    deadline_refills: [u32; MAX_CPUS],
    #[cfg(feature = "fault-inject")]
    delayed_deadline_timer: CpuSet,
    #[cfg(feature = "fault-inject")]
    deadline_trace: [DeadlineTrace; MAX_CPUS],
    /// 每个处理器的本地 tick 计数（周期均衡的检查点）。
    local_ticks: [u64; MAX_CPUS],
    switches: u64,
    observer: Option<SwitchObserver>,
    /// 调度器看到的当前时刻（tick；由 [`Scheduler::tick`] 推进）。
    now: u64,
    /// 每个处理器当前时间片已用的 tick 数与长度。
    slice_used: [u32; MAX_CPUS],
    slice_quantum: [u32; MAX_CPUS],
    /// 每档的唤醒延迟直方图。
    latency: [LatencyHistogram; QOS_CLASSES],
    /// 是否沿等待关系传播档位（默认开启；关闭只用于对照测量）。
    inherit: bool,
    /// 等待序号（同档等待者先来先得）。
    wait_seq: u64,
    /// CPU 组表（组数不会超过任务槽位数：每组至少要有一个持有者）。
    groups: BootSlots<Option<CpuGroup>, INLINE_SLOTS>,
    /// 各组槽位的下一个世代号。
    group_gen: BootSlots<u32, INLINE_SLOTS>,
    /// 优先级继承重算用的暂存（与任务表同容量；预先分配，持锁路径上不分配内存）。
    scratch_base: BootSlots<Option<Qos>, INLINE_SLOTS>,
    scratch_eff: BootSlots<Option<Qos>, INLINE_SLOTS>,
    scratch_waits: BootSlots<Option<usize>, INLINE_SLOTS>,
    /// CPU 组「本 tick 有可运行成员」的暂存（与组表同容量）。
    scratch_wants: BootSlots<bool, INLINE_SLOTS>,
    /// 看门狗判定器与报告日志。
    watchdog: Watchdog,
    watchdog_log: WatchdogLog<WATCHDOG_LOG>,
    /// 类别仲裁器（POL-5）：决定本 tick 归哪一类；关闭时行为与接入前完全一致。
    arbiter: kernel_core::arbiter::Arbiter,
    /// 每个处理器的类别用量窗口（按 tick 记账）。
    arb_windows: [kernel_core::arbiter::Window; MAX_CPUS],
    /// 是否启用类别仲裁（由演练显式打开，默认关闭）。
    arbiter_on: bool,
    /// 空闲停表的登记（计时处理器 = 引导处理器，永不停表）。
    nohz: StopBoard,
    /// 空闲停表时本地 tick 的最大间隔（tick；< 2 = 关闭停表，空闲处理器保持周期 tick）。
    nohz_divisor: u32,
    /// 计时处理器为停表处理器发出的重新调度请求次数（停表期间出现可接的工作）。
    nohz_kicks: u64,
}

/// 空闲执行流下一步该做什么（[`Scheduler::idle_enter`] 的结果）。
/// What an idle processor should do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdleStep {
    /// 有事可做：以该原因切换。
    Run(&'static str),
    /// 保持周期 tick 休眠到下一个中断。
    Sleep,
    /// 已登记停表：把本地定时器推迟到这么多个 tick 之后再休眠；醒来后必须调用 [`Scheduler::idle_exit`]。
    Stop(u32),
}

/// 空闲停表的统计快照。
/// Snapshot of tickless-idle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NohzStats {
    /// 停表时的最大间隔（< 2 = 关闭）。
    pub divisor: u32,
    /// 当前停表的处理器。
    pub stopped: CpuSet,
    /// 累计停表次数。
    pub stops: u64,
    /// 累计重新开表次数。
    pub restarts: u64,
    /// 计时处理器为停表处理器发出的重新调度请求次数。
    pub kicks: u64,
}

impl<P: SchedPolicy<State = EntityState>> Scheduler<P> {
    /// 构造调度器；槽位 0 预置为正在引导处理器上运行的引导线程，其他处理器起初在空闲执行流上。
    /// 起初只有 [`INLINE_SLOTS`] 个槽位，堆就绪后经 [`Scheduler::grow`] 扩到启动期容量。
    pub const fn new(policy: P) -> Self {
        let mut tasks = [const { None }; INLINE_SLOTS];
        let mut boot = Task::new(TaskId(0), "boot");
        boot.state = TaskState::Running;
        tasks[BOOT_SLOT] = Some(boot);
        let mut epochs = [const { SlotLifecycle::new(0) }; INLINE_SLOTS];
        let mut i = 0;
        while i < INLINE_SLOTS { epochs[i] = SlotLifecycle::new(i); i += 1; }
        epochs[BOOT_SLOT] = SlotLifecycle::initial(BOOT_SLOT, 0);
        let mut current = [IDLE; MAX_CPUS];
        current[0] = BOOT_SLOT;
        Scheduler {
            #[cfg(feature = "krn2-observe")]
            raw_callbacks: kernel_core::raw_timing::Samples::new(),
            #[cfg(feature = "krn2-observe")]
            raw_wakes: kernel_core::raw_timing::Samples::new(),
            #[cfg(feature = "krn2-observe")]
            raw_wake_errors: [0; 3],
            #[cfg(feature = "krn2-observe")]
            raw_pending_at_reset: 0,
            tasks: BootSlots::Inline(tasks),
            epochs: BootSlots::Inline(epochs),
            id_index: None,
            stacks: StackPool::new(),
            queues: CoreQueue::array(policy),
            runs: RunLists::new(),
            links: BootSlots::Inline([Link::EMPTY; INLINE_SLOTS]),
            list_errors: 0,
            workers: 0,
            wake_mailboxes: [const { kernel_core::wake_mailbox::WakeMailbox::new() }; MAX_CPUS],
            remote_wakes: 0,
            wake_fallbacks: 0,
            limit_tick_drains: [0; 2],
            next_wake: [u64::MAX; MAX_CPUS],
            wake_heap: DeadlineForest::new(),
            wake_entries: BootSlots::Inline([Deadline::EMPTY; INLINE_SLOTS * MAX_CPUS]),
            wake_positions: BootSlots::Inline([NO_DEADLINE; INLINE_SLOTS]),
            wake_owners: BootSlots::Inline([NO_DEADLINE; INLINE_SLOTS]),
            next_rt: [u64::MAX; MAX_CPUS],
            rt_heap: DeadlineForest::new(),
            rt_entries: BootSlots::Inline([Deadline::EMPTY; INLINE_SLOTS * MAX_CPUS]),
            rt_positions: BootSlots::Inline([NO_DEADLINE; INLINE_SLOTS]),
            rt_owners: BootSlots::Inline([NO_DEADLINE; INLINE_SLOTS]),
            scan: ScanStats { picks: 0, visited: 0, max_visited: 0, wake_scans: 0, ticks: 0 },
            hook_errors: 0,
            last_hook_error: None,
            current,
            idle_ctx: [const { crate::arch::EMPTY_CONTEXT }; MAX_CPUS],
            switching_from: [None; MAX_CPUS],
            online: CpuSet::first(1),
            balancer: Balancer::new(BalanceParams::DEFAULT),
            kicks: CpuSet::EMPTY,
            deadline_wakes: [0; MAX_CPUS],
            deadline_refills: [0; MAX_CPUS],
            #[cfg(feature = "fault-inject")]
            delayed_deadline_timer: CpuSet::EMPTY,
            #[cfg(feature = "fault-inject")]
            deadline_trace: [DeadlineTrace::EMPTY; MAX_CPUS],
            cpu_stats: [CpuStats { busy_ticks: 0, idle_ticks: 0, idle_waiting: 0, max_idle_waiting: 0, steals: 0, pulls: 0, pull_hot: 0 }; MAX_CPUS],
            local_ticks: [0; MAX_CPUS],
            switches: 0,
            observer: None,
            now: 0,
            slice_used: [0; MAX_CPUS],
            slice_quantum: [1; MAX_CPUS],
            latency: [const { LatencyHistogram::new() }; QOS_CLASSES],
            inherit: true,
            wait_seq: 0,
            groups: BootSlots::Inline([const { None }; INLINE_SLOTS]),
            group_gen: BootSlots::Inline([0; INLINE_SLOTS]),
            scratch_base: BootSlots::Inline([None; INLINE_SLOTS]),
            scratch_eff: BootSlots::Inline([None; INLINE_SLOTS]),
            scratch_waits: BootSlots::Inline([None; INLINE_SLOTS]),
            scratch_wants: BootSlots::Inline([false; INLINE_SLOTS]),
            watchdog: Watchdog::new(super::policy::WATCHDOG_THRESHOLD),
            watchdog_log: WatchdogLog::new(),
            arbiter: kernel_core::arbiter::Arbiter::new(kernel_core::arbiter::ArbiterParams::DEFAULT),
            arb_windows: [kernel_core::arbiter::Window { ticks: 0, realtime: 0, interactive: 0, batch: 0 }; MAX_CPUS],
            nohz: StopBoard::new(0),
            nohz_divisor: 0,
            nohz_kicks: 0,
            arbiter_on: false,
        }
    }

    /// 打开/关闭类别仲裁（返回之前的设置）。
    pub fn set_arbiter(&mut self, on: bool) -> bool {
        let prev = self.arbiter_on;
        self.arbiter_on = on;
        prev
    }

    /// 类别仲裁：选出本 tick 应运行的类别；该类没有候选时返回 `None`（不过滤）。
    fn pick_arb_class(&mut self, c: usize, prev: usize) -> Option<kernel_core::arbiter::Class> {
        use kernel_core::arbiter::{Class, Demand};
        if !self.arbiter_on {
            return None;
        }
        let mut demand = Demand::default();
        for (i, t) in self.listed(c) {
            if i == prev || t.state != TaskState::Runnable || t.home != c || t.on_cpu.is_some() {
                continue;
            }
            if !self.eligible(t) {
                continue;
            }
            match arb_class(t) {
                Class::RealTime => demand.realtime = true,
                Class::Interactive => demand.interactive = true,
                Class::Batch => demand.batch = true,
            }
        }
        let chosen = self.arbiter.pick(demand, &self.arb_windows[c])?;
        // 只有该类确实有候选时才过滤，否则退回不按类别过滤（避免选出空集）。
        let has = self.listed(c).any(|(i, t)| {
            i != prev && t.state == TaskState::Runnable && t.home == c && t.on_cpu.is_none() && self.eligible(t) && arb_class(t) == chosen
        });
        if !has {
            return None;
        }
        self.arb_windows[c].charge(chosen);
        Some(chosen)
    }

    /// 安装切换观察者（覆盖旧的）。
    pub fn set_observer(&mut self, observer: SwitchObserver) {
        self.observer = Some(observer);
    }

    /// 当前策略名。
    pub fn policy_name(&self) -> &'static str {
        self.queues[0].policy().name()
    }

    /// 默认档位的时间片（tick 数）。
    pub fn default_quantum(&self) -> u32 {
        self.queues[0].policy().default_quantum()
    }

    // Author: chatgpt. Diagnostic start identity; idle has no canonical Token.
    #[cfg(feature = "krn2-observe")]
    pub(super) fn raw_callback_identity(&self) -> (usize, u64) {
        let slot = self.cur();
        let generation = self.epochs.get(slot).and_then(|e| e.history()).map_or(0, |r| r.token().generation);
        (slot, generation)
    }

    /// 本处理器的当前槽位。
    fn cur(&self) -> usize {
        self.current[this_cpu()]
    }

    /// 槽位上的任务（越界或空槽位为 `None`；空闲执行流的取值越界，因此也是 `None`）。
    fn task(&self, slot: usize) -> Option<&Task> {
        self.tasks.get(slot).and_then(|t| t.as_ref())
    }

    /// 槽位上的任务（可变）。
    fn task_mut(&mut self, slot: usize) -> Option<&mut Task> {
        self.tasks.get_mut(slot).and_then(|t| t.as_mut())
    }

    /// 启动期扩容：把任务表（及组表、调度暂存）扩到 `slots` 个槽位，并为新增槽位分配内核栈。
    /// 返回有栈可用的槽位总数。
    ///
    /// 只能在静止状态下调用（只有引导线程在运行、只有引导处理器在线、没有切换在途）：
    /// 扩容会搬动任务记录，而切换路径会在锁外使用指向任务记录里上下文的指针。
    /// 表的扩容是全有或全无：任一存储分配失败，所有表都保持原样。
    /// Boot-time grow to `slots` task slots (all-or-nothing for the tables).
    pub fn grow(&mut self, slots: usize) -> Result<usize, GrowError> {
        if slots < self.tasks.len() || slots < INLINE_SLOTS {
            return Err(GrowError::Shrink);
        }
        let quiescent = self.online.len() == 1
            && self.current[0] == BOOT_SLOT
            && self.switching_from.iter().all(Option::is_none)
            && self.tasks.iter().enumerate().all(|(i, t)| {
                i == BOOT_SLOT || t.as_ref().is_none_or(|t| t.state == TaskState::Exited && t.on_cpu.is_none())
            });
        if !quiescent {
            return Err(GrowError::NotQuiescent);
        }
        let oom = |s: &Self| GrowError::OutOfMemory { available: s.stacks.available() };
        let tasks = self.tasks.prepare(slots, || None).ok_or_else(|| oom(self))?;
        let groups = self.groups.prepare(slots, || None).ok_or_else(|| oom(self))?;
        let group_gen = self.group_gen.prepare(slots, || 0).ok_or_else(|| oom(self))?;
        let base = self.scratch_base.prepare(slots, || None).ok_or_else(|| oom(self))?;
        let eff = self.scratch_eff.prepare(slots, || None).ok_or_else(|| oom(self))?;
        let waits = self.scratch_waits.prepare(slots, || None).ok_or_else(|| oom(self))?;
        let wants = self.scratch_wants.prepare(slots, || false).ok_or_else(|| oom(self))?;
        let links = self.links.prepare(slots, || Link::EMPTY).ok_or_else(|| oom(self))?;
        let deadline_count = slots.checked_mul(MAX_CPUS).ok_or_else(|| oom(self))?;
        let mut wake_entries = self.wake_entries.prepare(deadline_count, || Deadline::EMPTY).ok_or_else(|| oom(self))?;
        let mut wake_positions = self.wake_positions.prepare(slots, || NO_DEADLINE).ok_or_else(|| oom(self))?;
        let mut rt_entries = self.rt_entries.prepare(deadline_count, || Deadline::EMPTY).ok_or_else(|| oom(self))?;
        let mut rt_positions = self.rt_positions.prepare(slots, || NO_DEADLINE).ok_or_else(|| oom(self))?;
        let mut wake_owners = self.wake_owners.prepare(slots, || NO_DEADLINE).ok_or_else(|| oom(self))?;
        let mut wake_heap = DeadlineForest::<MAX_CPUS>::new();
        // New CPU strides differ: rebuild all live nodes before any commit.
        for c in 0..MAX_CPUS {
            for n in 0..self.wake_heap.len(c).unwrap() {
                let event = self.wake_entries[c*self.tasks.len()+n];
                wake_heap.set(&mut wake_entries, &mut wake_positions, &mut wake_owners, c, event)
                    .expect("preallocated deadline forest rebuild");
            }
        }
        let mut rt_owners = self.rt_owners.prepare(slots, || NO_DEADLINE).ok_or_else(|| oom(self))?;
        let mut rt_heap = DeadlineForest::<MAX_CPUS>::new();
        // New CPU strides differ: rebuild all live nodes before any commit.
        for c in 0..MAX_CPUS {
            for n in 0..self.rt_heap.len(c).unwrap() {
                let event = self.rt_entries[c*self.tasks.len()+n];
                rt_heap.set(&mut rt_entries, &mut rt_positions, &mut rt_owners, c, event)
                    .expect("preallocated deadline forest rebuild");
            }
        }
        let mut pos = 0;
        let epochs = self.epochs.prepare(slots, || { let e = SlotLifecycle::new(pos); pos += 1; e }).ok_or_else(|| oom(self))?;
        let index_count = slots.checked_mul(2).and_then(|n| n.checked_sub(1)).ok_or_else(|| oom(self))?;
        let storage = BootSlots::<IndexNode, {2 * INLINE_SLOTS - 1}>::Inline([IndexNode::Free(usize::MAX); 2 * INLINE_SLOTS - 1]);
        let nodes = storage.prepare(index_count, || IndexNode::Free(usize::MAX)).ok_or_else(|| oom(self))?;
        let mut index = TaskIndex::new(BootSlots::Heap(nodes));
        for e in self.epochs.iter() {
            if let Some(r) = e.history() { index.insert(r.label(), r.token()).expect("unique historical task labels"); }
        }
        self.epochs.commit(epochs);
        self.id_index = Some(index);
        self.tasks.commit(tasks);
        self.groups.commit(groups);
        self.group_gen.commit(group_gen);
        self.scratch_base.commit(base);
        self.scratch_eff.commit(eff);
        self.scratch_waits.commit(waits);
        self.scratch_wants.commit(wants);
        self.links.commit(links);
        self.wake_entries = BootSlots::Heap(wake_entries);
        self.wake_positions = BootSlots::Heap(wake_positions);
        self.wake_owners = BootSlots::Heap(wake_owners);
        self.wake_heap = wake_heap;
        self.rt_entries = BootSlots::Heap(rt_entries);
        self.rt_positions = BootSlots::Heap(rt_positions);
        self.rt_owners = BootSlots::Heap(rt_owners);
        self.rt_heap = rt_heap;
        self.stacks.reserve(slots).map_err(|ReserveError { available }| GrowError::OutOfMemory { available })
    }

    /// 有栈可用的槽位总数（含引导线程槽位）。
    pub fn capacity(&self) -> usize {
        self.stacks.available()
    }

    /// 任务表的槽位总数（含尚未分到栈的槽位；启动期扩容之前为 [`INLINE_SLOTS`]）。
    pub fn slots(&self) -> usize {
        self.tasks.len()
    }

    /// 新建任务：占用一个有栈的空工作槽位，伪造首次切入帧使其从 `trampoline` 开始执行。
    ///
    /// 新任务**继承创建者**（当前工作任务）的自身 QoS 档位与上限——线程不能靠创建新线程绕过降档，
    /// 也不能把临时借来的档位传给新任务；
    /// 引导线程创建的任务取默认档位（用户发起）、没有上限。
    /// `trampoline` 由门面层提供：它读取当前任务的 `entry` 并执行，返回后负责退出。
    pub fn spawn(
        &mut self,
        id: TaskId,
        name: &'static str,
        entry: fn(),
        trampoline: extern "C" fn() -> !,
    ) -> Result<usize, SpawnError> {
        self.spawn_in(id, name, entry, trampoline, None)
    }

    /// 同 [`Scheduler::spawn`]，但可指定新任务加入的 CPU 组（`None` = 与创建者同组，引导线程创建的任务不属于任何组）。
    /// 指定的组无效时拒绝，状态不变。
    /// Spawns into an explicit CPU group (or the creator's group when `None`).
    pub fn spawn_in(
        &mut self,
        id: TaskId,
        name: &'static str,
        entry: fn(),
        trampoline: extern "C" fn() -> !,
        group: Option<CpuGroupId>,
    ) -> Result<usize, SpawnError> {
        self.spawn_on(id, name, entry, trampoline, group, None)
    }

    /// 同 [`Scheduler::spawn_in`]，并可指定亲和集合（`None` = 继承创建者；引导线程创建的任务只在引导处理器上运行）。
    /// 新任务按负载放进某个允许的处理器的运行队列；组无效、集合里没有在线处理器、没有空槽位时拒绝，状态不变。
    /// Spawns with an explicit affinity set (or the creator's when `None`).
    pub fn spawn_on(
        &mut self,
        id: TaskId,
        name: &'static str,
        entry: fn(),
        trampoline: extern "C" fn() -> !,
        group: Option<CpuGroupId>,
        affinity: Option<CpuSet>,
    ) -> Result<usize, SpawnError> {
        let explicit = match group {
            Some(g) => Some(self.group_slot(g).ok_or(SpawnError::BadGroup)?),
            None => None,
        };
        let current = self.cur();
        let creator = if is_worker(current) { self.task(current) } else { None };
        let affinity = affinity.unwrap_or(creator.map(|c| c.affinity).unwrap_or(CpuSet::first(1)));
        let base = creator.map(|c| c.base_qos).unwrap_or(Qos::UserInitiated);
        let loads = self.loads();
        let home = self.balancer.place(affinity, None, base, None, self.now, &loads).map_err(|_| SpawnError::BadAffinity)?;
        // 空槽位或「已退出且已被完全换下」的槽位都可复用：
        // 已退出任务一旦被切走（`on_cpu` 清除），就再也不会在它的栈上执行，栈与 TCB 可以安全覆盖。
        self.ensure_id_index();
        let previous = self.historical_slot(id);
        if previous.is_some_and(|i| self.tasks[i].as_ref().is_some_and(|t| t.state != TaskState::Exited || t.on_cpu.is_some()) || i == current) {
            return Err(SpawnError::DuplicateId);
        }
        let mut candidates = previous.into_iter().chain((1..self.tasks.len()).filter(|i| Some(*i) != previous));
        let slot = candidates
            .find_map(|i| {
                let reusable = self.stacks.has_stack(i) && match self.tasks[i].as_ref() {
                    None => true,
                    Some(t) => t.state == TaskState::Exited && t.on_cpu.is_none() && i != current,
                };
                // Same-label historical slots cannot be bypassed: leaving two
                // historical entries for one label would make lookup ambiguous.
                if previous.is_some() && previous != Some(i) { return None; }
                if !reusable { return None; }
                self.epochs[i].reserve(id.0).ok().map(|r| (i, r))
            })
            .ok_or(SpawnError::NoFreeSlot)?;
        let (slot, reservation) = slot;
        // At most one label per slot, and 2*N-1 nodes. Preflight insertion
        // before changing task/group/stack state; failure aborts the reservation.
        let old = self.epochs[slot].history();
        if old.is_none_or(|r| r.label() != id.0) {
            // Remove the old identity first to free two nodes at full capacity.
            // Restoring it cannot fail, since no intervening publication exists.
            let index = self.id_index.as_mut().unwrap();
            if let Some(r) = old { assert_eq!(index.remove(r.label()), Some(r.token())); }
            if index.insert(id.0, reservation.token()).is_err() {
                if let Some(r) = old { index.insert(r.label(), r.token()).expect("restore historical label"); }
                self.epochs[slot].abort(reservation).expect("abort current reservation");
                return Err(SpawnError::NoFreeSlot);
            }
        } else {
            let index = self.id_index.as_mut().unwrap();
            assert_eq!(index.remove(id.0), old.map(|r| r.token()));
            index.insert(id.0, reservation.token()).expect("same label replacement capacity");
        }
        self.epochs[slot].publish(reservation).expect("publish current reservation");
        let creator = if is_worker(current) { self.task(current) } else { None };
        let mut task = Task::new(id, name);
        task.entry = Some(entry);
        if let Some(creator) = creator {
            task.sched = new_entity(creator.base_qos);
            task.base_qos = creator.base_qos;
            task.qos_ceiling = creator.qos_ceiling;
            task.cpu_group = creator.cpu_group;
        }
        task.affinity = affinity;
        task.home = home;
        if explicit.is_some() {
            task.cpu_group = explicit;
        }
        if let Some(g) = task.cpu_group {
            if let Some(grp) = self.groups[g].as_mut() {
                grp.refs += 1;
            }
        }
        // SAFETY：该槽位有栈且为空，没有任何任务在这块栈上运行。
        task.context = unsafe { self.stacks.prepare_initial_frame(slot, trampoline) };
        self.tasks[slot] = Some(task);
        self.workers += 1;
        if let Some(t) = self.tasks[slot].as_mut() {
            let r = self.queues[home].enqueue(&mut t.sched, Enqueue::Spawn);
            self.note(r);
        }
        self.relist(slot);
        if home != this_cpu() && loads[home].idle() {
            self.kicks.insert(home);
        }
        Ok(slot)
    }

    /// 当前运行任务的入口函数（trampoline 使用）。
    pub fn current_entry(&self) -> Option<fn()> {
        self.task(self.cur()).and_then(|t| t.entry)
    }

    /// 当前运行任务的 id 与名字。
    pub fn current(&self) -> (TaskId, &'static str) {
        self.task(self.cur())
            .map(|t| (t.id, t.name))
            .unwrap_or((TaskId(u64::MAX), "?"))
    }

    /// 当前是否在引导线程上运行。
    pub fn on_boot(&self) -> bool {
        !is_worker(self.cur())
    }

    /// 累计切换次数。
    pub fn switch_count(&self) -> u64 {
        self.switches
    }

    /// 设置当前任务的地址空间（`None` = 内核空间）。之后每次切回该任务都会切到这个空间。
    pub fn set_current_space(&mut self, space: Option<crate::arch::SpaceRoot>) {
        if let Some(t) = self.task_mut(self.cur()) {
            t.space = space;
        }
    }

    /// 设置当前任务可发起的系统调用集合。
    pub fn set_current_syscalls(&mut self, set: crate::syscall::SyscallSet) {
        if let Some(t) = self.task_mut(self.cur()) {
            t.syscalls = set;
        }
    }

    /// 当前任务的地址空间（`None` = 内核空间）。
    pub fn current_space(&self) -> Option<crate::arch::SpaceRoot> {
        self.task(self.cur()).and_then(|t| t.space)
    }

    /// 当前任务可发起的系统调用集合。
    pub fn current_syscalls(&self) -> crate::syscall::SyscallSet {
        self.task(self.cur()).map(|t| t.syscalls).unwrap_or(crate::syscall::SyscallSet::EMPTY)
    }

    /// 当前任务的自身 QoS 档位（不含借来的档位；引导线程为 `None`）。
    pub fn current_qos(&self) -> Option<Qos> {
        if !is_worker(self.cur()) {
            return None;
        }
        self.task(self.cur()).map(|t| t.base_qos)
    }

    /// 任务 `id` 的有效档位（含借来的档位；不存在、已退出或是引导线程时 `None`）。
    pub fn effective_qos(&self, id: TaskId) -> Option<Qos> {
        self.live_slot(id).filter(|&i| i != BOOT_SLOT).and_then(|i| self.tasks[i].as_ref()).map(|t| t.sched.qos)
    }

    /// 修改当前任务的 QoS 档位：降低或不变总是允许；提升须在上限之内（判定见 `qos_change_allowed`）。
    /// 成功后立即生效于下一次调度决策（降档后若有更高档任务在等，下一个 tick 就会被抢占）。
    pub fn set_current_qos(&mut self, q: Qos) -> Result<(), QosError> {
        if !is_worker(self.cur()) {
            return Err(QosError::NotAWorker);
        }
        let t = self.task_mut(self.cur()).ok_or(QosError::NotAWorker)?;
        if !qos_change_allowed(t.base_qos, q, t.qos_ceiling) {
            return Err(QosError::RaiseDenied);
        }
        t.base_qos = q;
        // 有效档位仍要算上等待者借来的档位（降档不会让正在等它的高档任务失去保障）。
        self.resolve_inheritance();
        Ok(())
    }

    /// 授予当前任务 QoS 上限（内核内的创建方在任务进入用户态之前调用；`None` = 收回）。
    pub fn set_current_qos_ceiling(&mut self, ceiling: Option<Qos>) {
        if let Some(t) = self.task_mut(self.cur()) {
            t.qos_ceiling = ceiling;
        }
    }

    /// 把当前任务标记为已退出（槽位在它被切走之后才可被 `spawn` 复用）。
    /// 正在等它的任务（等它退出、或等它持有的锁）全部被唤醒，借给它的档位随之归还。
    pub fn mark_current_exited(&mut self) {
        let cur = self.cur();
        let mut left = None;
        if is_worker(cur) && self.task(cur).is_some_and(|t| t.state != TaskState::Exited) {
            let r = self.epochs[cur].history().expect("exiting task identity");
            self.epochs[cur].exit(r.token()).expect("exit live identity");
        }
        if let Some(r) = self.epochs.get(cur).and_then(SlotLifecycle::history) {
            self.remove_wake_deadline(cur, r.token().generation);
            self.remove_rt_deadline(cur, r.token().generation);
        }
        if let Some(t) = self.tasks.get_mut(cur).and_then(|t| t.as_mut()) {
            if is_worker(cur) && t.state != TaskState::Exited {
                self.workers = self.workers.checked_sub(1).expect("live worker count underflow");
            }
            #[cfg(feature = "krn2-observe")]
            if t.raw_wake_round.take().is_some() {
                self.raw_wake_errors[2] = self.raw_wake_errors[2].saturating_add(1);
            }
            t.state = TaskState::Exited;
            t.waits_for = None;
            left = t.cpu_group.take();
            if is_worker(cur) {
                let r = dequeue_from(&mut self.queues, &mut t.sched, Dequeue::Exit);
                self.note(r);
            }
        }
        self.relist(cur);
        if let Some(g) = left {
            self.unref_group(g);
        }
        for i in 0..self.tasks.len() {
            if matches!(self.tasks[i].as_ref(), Some(t) if t.waits_for == Some(cur)) {
                self.make_runnable(i);
            }
        }
        self.resolve_inheritance();
    }

    fn ensure_id_index(&mut self) {
        if self.id_index.is_none() {
            let mut index = TaskIndex::new(BootSlots::Inline([IndexNode::Free(usize::MAX); 2 * INLINE_SLOTS - 1]));
            for e in self.epochs.iter() {
                if let Some(r) = e.history() { index.insert(r.label(), r.token()).expect("inline task label capacity"); }
            }
            self.id_index = Some(index);
        }
    }

    fn historical_slot(&self, id: TaskId) -> Option<usize> {
        let token = match self.id_index.as_ref() {
            Some(index) => index.get(id.0)?,
            None if id.0 == 0 => self.epochs[BOOT_SLOT].history()?.token(),
            None => return None,
        };
        let e = self.epochs.get(token.slot)?;
        let r = e.history()?;
        if r.token() != token || r.label() != id.0 { return None; }
        self.task(token.slot).filter(|t| t.id == id).map(|_| token.slot)
    }

    /// 任务 `id` 所在槽位（只找尚未退出的任务；引导线程也算）。
    fn live_slot(&self, id: TaskId) -> Option<usize> {
        self.historical_slot(id).filter(|&i| self.epochs[i].history().is_some_and(|r| self.epochs[i].live(r.token())))
    }

    /// 任务 `id` 是否存在且尚未退出。
    pub fn is_live(&self, id: TaskId) -> bool {
        self.live_slot(id).is_some()
    }

    /// 任务 `waiter` 此刻是否阻塞在等待 `owner`（等它持有的锁或等它退出；诊断与验收用）。
    /// Whether `waiter` is currently blocked on `owner`.
    pub fn waits_on(&self, waiter: TaskId, owner: TaskId) -> bool {
        let (Some(wi), Some(oi)) = (self.live_slot(waiter), self.live_slot(owner)) else { return false };
        matches!(self.tasks[wi].as_ref(), Some(t) if t.state == TaskState::Blocked && t.waits_for == Some(oi))
    }

    /// 打开/关闭优先级继承，返回之前的设置（只供对照测量；关闭后立即按自身档位重算）。
    pub fn set_inheritance(&mut self, enabled: bool) -> bool {
        let prev = core::mem::replace(&mut self.inherit, enabled);
        self.resolve_inheritance();
        prev
    }

    /// 按当前等待图重算全部任务的有效档位（整体重算，借出与归还不会残留）。
    fn resolve_inheritance(&mut self) {
        // 暂存与任务表同容量、预先分配（持锁路径上不分配内存，也不在栈上开与容量成比例的数组）。
        let (base, waits, eff) = (&mut self.scratch_base, &mut self.scratch_waits, &mut self.scratch_eff);
        base.fill(None);
        waits.fill(None);
        eff.fill(None);
        for (i, t) in self.tasks.iter().enumerate().skip(1) {
            if let Some(t) = t {
                if t.state != TaskState::Exited {
                    base[i] = Some(t.base_qos);
                    waits[i] = t.waits_for;
                }
            }
        }
        inherit::resolve(base, waits, self.inherit, eff);
        for (t, q) in self.tasks.iter_mut().zip(eff.iter()) {
            if let (Some(t), Some(q)) = (t.as_mut(), q) {
                t.sched.qos = *q;
            }
        }
    }

    /// 让当前工作任务阻塞，直到持有者 `owner` 把它唤醒（交出锁或退出）；期间把有效档位借给持有者。
    ///
    /// `key` 标识等待的对象（同一持有者可能被不同对象上的任务等待）。成功后调用者必须立即让出
    /// （`prepare_switch(Cause::BLOCK)`）；失败时不改动任何状态。
    pub fn block_on(&mut self, owner: TaskId, key: u64) -> Result<(), BlockError> {
        let cur = self.cur();
        if !is_worker(cur) {
            return Err(BlockError::NotAWorker);
        }
        let owner_slot = self.live_slot(owner).ok_or(BlockError::NoOwner)?;
        let waits = &mut self.scratch_waits;
        for (w, t) in waits.iter_mut().zip(self.tasks.iter()) {
            *w = t.as_ref().and_then(|t| t.waits_for);
        }
        inherit::check_edge(waits, cur, owner_slot).map_err(BlockError::Refused)?;
        self.wait_seq += 1;
        let seq = self.wait_seq;
        let t = self.tasks[cur].as_mut().ok_or(BlockError::NotAWorker)?;
        t.state = TaskState::Blocked;
        let r = dequeue_from(&mut self.queues, &mut t.sched, Dequeue::Block);
        t.wake_at = None;
        t.waits_for = Some(owner_slot);
        t.wait_key = key;
        t.wait_seq = seq;
        self.note(r);
        self.relist(cur);
        self.resolve_inheritance();
        Ok(())
    }

    /// 当前任务交出 `key` 标识的对象：在等它的任务中选出交接对象（有效档位最高、同档先来先得）并唤醒，
    /// 其余等待者改为等交接对象（档位随之借给新持有者）；当前任务借来的档位归还。返回交接对象。
    pub fn hand_off(&mut self, key: u64) -> Option<TaskId> {
        let cur = self.cur();
        let waiting_on = |t: &Task| t.state == TaskState::Blocked && t.waits_for == Some(cur) && t.wait_key == key;
        let successor = inherit::pick_successor(
            self.tasks.iter().enumerate().filter_map(|(i, t)| t.as_ref().filter(|t| waiting_on(t)).map(|t| (i, t.sched.qos, t.wait_seq))),
        );
        let Some(next) = successor else {
            self.resolve_inheritance();
            return None;
        };
        for (i, t) in self.tasks.iter_mut().enumerate() {
            if let Some(t) = t.as_mut().filter(|t| i != next && waiting_on(t)) {
                t.waits_for = Some(next);
            }
        }
        self.make_runnable(next);
        self.resolve_inheritance();
        self.tasks[next].as_ref().map(|t| t.id)
    }

    /// 是否有可运行任务的有效档位高于当前任务（引导线程上：是否有任何可运行任务）。
    /// 交出锁、归还借来的档位之后据此决定是否立即让出。
    pub fn outranked(&self) -> bool {
        let Some(top) = self.waiting(this_cpu()).highest() else { return false };
        match self.task(self.cur()) {
            Some(t) if is_worker(self.cur()) => self.queues[this_cpu()].policy().outranks(top, t.sched.qos),
            _ => true,
        }
    }

    /// 让当前工作任务睡眠到 `wake_at`（`None` = 只能被 [`Scheduler::wake`] 唤醒）。
    /// 调用者随后必须立即让出（`prepare_switch`）。引导线程不能睡眠（返回 `false`，状态不变）。
    pub fn block_current(&mut self, wake_at: Option<u64>) -> bool {
        if !is_worker(self.cur()) {
            return false;
        }
        let cur = self.cur();
        let Some(generation) = self.epochs.get(cur).and_then(SlotLifecycle::history).map(|r| r.token().generation) else { return false };
        if let Some(at) = wake_at {
            let home = self.task(cur).unwrap().home;
            self.set_wake_deadline(home, Deadline { at, slot: cur, generation });
        } else {
            self.remove_wake_deadline(cur, generation);
        }
        match self.tasks.get_mut(cur).and_then(|t| t.as_mut()) {
            Some(t) => {
                t.state = TaskState::Blocked;
                t.wake_at = wake_at;
                let r = dequeue_from(&mut self.queues, &mut t.sched, Dequeue::Block);
                self.note(r);
                self.relist(cur);
                true
            }
            None => false,
        }
    }

    /// 当前任务从调度器此刻起睡 `ticks` 个 tick（截止时刻 = 调度器时刻 + `ticks`，与阻塞在同一次持锁内完成）。
    /// 返回是否已阻塞（当前不是工作任务时为 `false`，状态不变）。
    /// Block the current task until `ticks` ticks after the scheduler's current time.
    pub fn block_current_for(&mut self, ticks: u64) -> bool {
        let deadline = self.now.saturating_add(ticks.max(1));
        self.block_current(Some(deadline))
    }

    /// 槽位 `i` 的睡眠任务变为可运行（记下唤醒时刻，按负载选运行队列，入队并通知策略）。
    /// 返回是否应立即抢占**本处理器**的当前任务；放到别的处理器且应抢占那里时记入待发的重新调度请求。
    fn make_runnable(&mut self, i: usize) -> bool {
        let now = self.now;
        if !self.task(i).is_some_and(|t| t.state == TaskState::Blocked) { return false; }
        let generation = self.epochs[i].history().expect("waking task identity").token().generation;
        self.remove_wake_deadline(i, generation);
        let t = self.tasks[i].as_mut().unwrap();
        #[cfg(feature = "krn2-observe")]
        {
            let token = kernel_core::task_index::Token { slot: i, generation };
            let start = kernel_core::raw_timing::Endpoint { cpu: this_cpu(), counter: crate::arch::cycles() };
            if let Some(round) = t.raw_wake.begin(token, start) { t.raw_wake_round = Some(round); }
            else { self.raw_wake_errors[0] = self.raw_wake_errors[0].saturating_add(1); }
        }
        t.state = TaskState::Runnable;
        t.wake_at = None;
        t.woken_at = Some(now);
        // 被任何途径唤醒都解除等待关系（例如所属进程开始终止）；醒来者自己重新检查等待条件。
        let had_edge = t.waits_for.take().is_some();
        if had_edge {
            self.resolve_inheritance();
        }
        self.replace(i);
        // 直接借字段（而不是经 task_mut）：同时要借运行队列
        if let Some(t) = self.tasks.get_mut(i).and_then(|t| t.as_mut()) {
            let home = t.home.min(MAX_CPUS - 1);
            let r = self.queues[home].enqueue(&mut t.sched, Enqueue::Wake);
            self.note(r);
        }
        self.relist(i);
        // 被限速组的成员醒来也不抢占：令牌回正之前它本来就不会被选中。
        let Some(t) = self.task(i).filter(|t| self.eligible(t)) else { return false };
        let (woken, home) = (t.sched.qos, t.home);
        let target = self.current[home];
        let running = if is_worker(target) { self.task(target).map(|t| t.sched.qos) } else { None };
        let preempts = self.queues[home].wake_preempts(woken, running);
        if home == this_cpu() {
            return preempts;
        }
        if preempts {
            self.kicks.insert(home);
        }
        false
    }

    /// 为可运行且未被任何处理器占用的任务 `i` 重新选运行队列（亲和集合内按负载与迁移代价）。
    fn replace(&mut self, i: usize) {
        let Some(t) = self.task(i) else { return };
        if t.on_cpu.is_some() {
            // 还在被换下：等切换完成后由目标处理器的下一次检查（或窃取）接手，仍按原队列记
            return;
        }
        let (affinity, prev, qos, last_ran) = (t.affinity, t.home, t.sched.qos, t.last_ran);
        let loads = self.loads();
        if let Ok(home) = self.balancer.place(affinity, Some(prev), qos, last_ran, self.now, &loads) {
            self.rehome(i, home);
        }
    }

    /// 把任务 `i` 的运行队列改为 `home`：它在某个队列上（可运行或运行中）时经迁移钩子换到新队列，
    /// 不在队列上（睡眠）时只改归属。
    fn rehome(&mut self, i: usize, home: usize) {
        let Some(t) = self.tasks.get_mut(i).and_then(|t| t.as_mut()) else { return };
        let r = match t.sched.queue() {
            Some(q) if q != home => migrate(&mut self.queues, q, home, &mut t.sched),
            _ => Ok(()),
        };
        t.home = home;
        let wake = t.wake_at;
        let rt = (t.rt_period != 0 && t.state != TaskState::Exited).then_some(t.rt_next_period);
        let generation = self.epochs[i].history().expect("migrating task identity").token().generation;
        if let Some(at) = wake { self.set_wake_deadline(home, Deadline { at, slot: i, generation }); }
        if let Some(at) = rt { self.set_rt_deadline(home, Deadline { at, slot: i, generation }); }
        self.note(r);
        self.relist(i);
    }

    /// 让槽位 `i` 的运行列表成员关系与它的实体队列字段一致（每次运行队列成员关系改变后调用）。
    fn relist(&mut self, i: usize) {
        let want = self.tasks.get(i).and_then(|t| t.as_ref()).and_then(|t| t.sched.queue());
        if self.runs.place(&mut self.links, i, want).is_err() {
            self.list_errors = self.list_errors.saturating_add(1);
        }
    }

    /// 处理器 `c` 运行列表上的任务（按槽位号升序；含运行中的任务）。
    fn listed(&self, c: usize) -> impl Iterator<Item = (usize, &Task)> + Clone + '_ {
        self.runs.iter(&self.links, c).filter_map(move |i| self.tasks.get(i).and_then(|t| t.as_ref()).map(|t| (i, t)))
    }

    /// 选择路径遍历量统计。
    /// Selection-path scan statistics.
    pub fn scan_stats(&self) -> ScanStats {
        self.scan
    }

    /// 清零选择路径遍历量统计。
    pub fn reset_scan_stats(&mut self) {
        self.scan = ScanStats::default();
    }

    /// 记下一次被运行队列拒绝的钩子调用（成员关系不符说明机制漏调或多调了钩子；只计数，不改状态）。
    fn note(&mut self, r: Result<(), QueueError>) {
        if let Err(e) = r {
            self.hook_errors = self.hook_errors.saturating_add(1);
            self.last_hook_error = Some(e);
        }
    }

    /// 核对任务表与各运行队列：每个处理器的入队计数是否等于任务表中「归属该处理器且可运行或运行中」的
    /// 工作任务数，每个这样的任务是否恰好记在它归属的队列上；以及累计被拒绝的钩子调用次数。
    /// Cross-check the task table against the per-CPU run queues.
    pub fn queue_audit(&self) -> QueueAudit {
        let mut expect = [0u32; MAX_CPUS];
        let mut misplaced = 0u32;
        for (i, t) in self.tasks.iter().enumerate() {
            let Some(t) = t.as_ref().filter(|_| is_worker(i)) else { continue };
            let live = matches!(t.state, TaskState::Runnable | TaskState::Running);
            match (live, t.sched.queue()) {
                (true, Some(q)) if q == t.home => expect[q.min(MAX_CPUS - 1)] += 1,
                (false, None) => {}
                _ => misplaced += 1,
            }
        }
        let mut queued = 0;
        let mut count_mismatch = 0;
        let mut list_mismatch = self.list_errors;
        for (c, (q, e)) in self.queues.iter().zip(expect).enumerate() {
            queued += q.queued();
            if q.queued() != e {
                count_mismatch += 1;
            }
            if self.runs.len(c) != q.queued() as usize {
                list_mismatch += 1;
            }
        }
        for (t, l) in self.tasks.iter().zip(self.links.iter()) {
            if t.as_ref().and_then(|t| t.sched.queue()) != l.queue() {
                list_mismatch += 1;
            }
        }
        QueueAudit { queued, misplaced, count_mismatch, hook_errors: self.hook_errors, last_hook_error: self.last_hook_error, list_mismatch }
    }

    /// 显式唤醒 `id`（例如所属进程开始终止时，让睡眠中的线程尽快观察到）。
    /// 返回是否应立即抢占当前任务；任务不存在或不在睡眠时返回 `false`。
    pub fn wake(&mut self, id: TaskId) -> bool {
        match self.live_slot(id).filter(|&i| is_worker(i)) {
            Some(i) => {
                let Some(t) = self.task(i).filter(|t| t.state == TaskState::Blocked) else { return false };
                let home = t.home;
                if home != this_cpu() {
                    let token = self.epochs[i].history().expect("woken task identity").token();
                    use kernel_core::wake_mailbox::Enqueue;
                    match self.wake_mailboxes[home].push(token) {
                        Enqueue::Queued | Enqueue::Coalesced => {
                            self.remote_wakes = self.remote_wakes.wrapping_add(1);
                            self.kicks.insert(home);
                            return false;
                        }
                        Enqueue::Full => self.wake_fallbacks = self.wake_fallbacks.wrapping_add(1),
                    }
                }
                self.make_runnable(i)
            }
            None => false,
        }
    }

    // Author: chatgpt. Bounded serialized delivery, not a lock-free consumer.
    // Run before any transaction mutation; revalidate generation and use actual
    // current affinity/home in make_runnable, rather than trusting routing data.
    pub fn drain_wake_mailboxes(&mut self) {
        for c in 0..MAX_CPUS {
            while let Some(token) = self.wake_mailboxes[c].pop() {
                if self.epochs.get(token.slot).is_some_and(|e| e.live(token)) {
                    self.make_runnable(token.slot);
                }
            }
        }
    }
    // Author: chatgpt. Deliberately program a later local timer so the real
    // BSP due-notification/IPI path, rather than the matching local expiry, runs.
    #[cfg(feature = "fault-inject")]
    pub fn fault_delay_deadline_timer(&mut self, c: usize, enable: bool) {
        assert!(c > 0 && c < MAX_CPUS);
        if enable { self.delayed_deadline_timer.insert(c); self.deadline_trace[c] = DeadlineTrace::EMPTY; }
        else { self.delayed_deadline_timer.remove(c); }
        self.kicks.insert(c);
    }
    #[cfg(feature = "fault-inject")]
    pub fn fault_deadline_trace(&self, c: usize) -> Option<DeadlineTrace> { self.deadline_trace.get(c).copied() }
    pub fn deadline_owners(&self, id: TaskId) -> Option<(Option<usize>, Option<usize>)> {
        let i = self.historical_slot(id)?;
        Some(((self.wake_owners[i] != NO_DEADLINE).then_some(self.wake_owners[i]),
            (self.rt_owners[i] != NO_DEADLINE).then_some(self.rt_owners[i])))
    }
    pub fn deadline_stats(&self) -> ([u32; MAX_CPUS], [u32; MAX_CPUS]) { (self.deadline_wakes, self.deadline_refills) }
    pub fn rt_state(&self, id: TaskId) -> Option<(u32,u32,u64)> {
        let t = self.task(self.live_slot(id)?)?;
        Some((t.rt_remaining,t.rt_period,t.rt_next_period))
    }
    pub fn limit_tick_stats(&self) -> [u32; 2] { self.limit_tick_drains }
    pub fn remote_wake_stats(&self) -> (u32, u32) { (self.remote_wakes, self.wake_fallbacks) }

    /// 尚未退出的工作任务数（可运行 + 运行中 + 睡眠）。
    pub fn live_workers(&self) -> usize {
        self.workers
    }

    /// 本处理器是否有可运行的工作任务可接（本队列中不含当前任务的，或可以从别的队列窃取的）。
    pub fn has_runnable_worker(&self) -> bool {
        let c = this_cpu();
        self.waiting(c) != ClassMask::EMPTY || (!is_worker(self.current[c]) && self.stealable(c))
    }

    /// Author: chatgpt. Conservative advisory permits, not a second scheduler.
    /// Any waiting/stealable task disables every fast path. Complex limit or
    /// arbitration state falls back to the original locked yield.
    pub fn fast_yield_cpus(&self) -> CpuSet {
        let mut allow = CpuSet::first(0);
        // No competing candidate means empty arbitration demand. Arbiter::pick
        // returns None without changing its aging state in that case; enabling
        // multi-mode alone must not disable this no-op optimization.
        if self.candidates().next().is_some() { return allow; }
        for c in self.online.iter() {
            if self.switching_from[c].is_some() { continue; }
            if let Some(t) = self.task(self.current[c]).filter(|_| is_worker(self.current[c])) {
                if t.state == TaskState::Running && t.home == c && t.cpu_group.is_none()
                    && t.rt_period == 0 && self.decide(c).is_none() {
                    allow.insert(c);
                }
            }
        }
        allow
    }
    // Author: chatgpt. Publish at most one AP credit, allocating a SINGLE
    // shared-group allowance across all leaves held by StateGuard. Yield's
    // limit-free predicate remains separate and unchanged.
    pub fn tick_lease_owners(&self) -> [Option<kernel_core::task_index::Token>; MAX_CPUS] {
        let mut owners = [None; MAX_CPUS];
        if self.candidates().next().is_some() { return owners; }
        for c in self.online.iter() {
            if c == 0 || self.switching_from[c].is_some()
                || self.now >= self.next_wake[c] || self.now >= self.next_rt[c]
                || self.slice_used[c].saturating_add(1) >= self.slice_quantum[c] { continue; }
            let slot = self.current[c];
            let Some(t) = self.task(slot).filter(|_| is_worker(slot)) else { continue };
            if t.state != TaskState::Running || t.home != c || self.decide(c).is_some()
                || (t.rt_period != 0 && t.rt_remaining <= 1)
                || t.sched.qos != t.base_qos { continue; }
            if let Some(group) = t.cpu_group {
                let Some(grp) = self.groups[group].as_ref() else { continue };
                let granted = owners.iter().flatten().filter(|owner: &&kernel_core::task_index::Token|
                    self.task(owner.slot).is_some_and(|peer| peer.cpu_group == Some(group))).count() as u32;
                if grp.limit.deferred_tick_credits(MAX_CPUS as u32) <= granted { continue; }
            }
            owners[c] = self.epochs.get(slot).and_then(SlotLifecycle::history).map(|r| r.token());
        }
        owners
    }
    pub fn drain_local_tick(&mut self, c: usize, owner: kernel_core::task_index::Token) {
        assert_eq!(self.current[c], owner.slot, "deferred tick changed owner before drain");
        assert!(self.epochs[owner.slot].live(owner), "deferred tick changed generation before drain");
        let t = self.task(owner.slot).expect("deferred tick task");
        assert_eq!(t.state, TaskState::Running);
        assert!(t.rt_period == 0 || t.rt_remaining > 1, "RT credit exhausted before drain");
        let group = t.cpu_group;
        self.account(c);
        // Debit only: consuming/refilling another CPU's RT heap here would
        // violate owner-local deadline processing. No deadline was due at grant.
        let t = self.tasks[owner.slot].as_mut().unwrap();
        if t.rt_period != 0 {
            t.rt_remaining -= 1;
            self.limit_tick_drains[0] = self.limit_tick_drains[0].wrapping_add(1);
        }
        if let Some(grp) = group.and_then(|g| self.groups[g].as_mut()) {
            assert!(grp.limit.eligible(), "shared credit oversubscribed");
            grp.limit.charge();
            self.limit_tick_drains[1] = self.limit_tick_drains[1].wrapping_add(1);
            assert!(grp.limit.eligible(), "shared credit must leave positive balance");
        }
    }
    pub fn note_fast_yield(&mut self, c: usize) {
        let wd = self.watchdog;
        if let Some(slot) = self.current.get(c).copied() {
            if let Some(t) = self.tasks.get_mut(slot).and_then(|t| t.as_mut()) {
                wd.yielded(&mut t.streak);
            }
        }
    }

    /// 处理器 `c` 的队列里、除它的当前任务之外还有可运行任务的档位集合。
    fn waiting(&self, c: usize) -> ClassMask {
        let mut m = ClassMask::EMPTY;
        for (i, t) in self.listed(c) {
            if i != self.current[c] && t.home == c && t.on_cpu.is_none() && t.state == TaskState::Runnable && self.eligible(t) {
                m.insert(t.sched.qos);
            }
        }
        m
    }

    /// 是否有别的队列里的任务可以被处理器 `c` 窃取（可运行、未被占用、未被限速、亲和集合含 `c`）。
    fn stealable(&self, c: usize) -> bool {
        self.online.contains(c) && self.candidates().any(|k| k.home != c && k.affinity.contains(c))
    }

    /// 可以被搬动的任务：可运行、未被任何处理器占用、未被限速（只遍历各运行列表：可运行任务一定在列表上）。
    fn candidates(&self) -> impl Iterator<Item = Candidate> + Clone + '_ {
        (0..MAX_CPUS).flat_map(move |q| self.listed(q)).filter_map(move |(i, t)| {
            (t.state == TaskState::Runnable && t.on_cpu.is_none() && self.eligible(t))
                .then_some(Candidate { slot: i, home: t.home, affinity: t.affinity, qos: t.sched.qos, last_ran: t.last_ran })
        })
    }

    /// 各处理器的负载快照。
    fn loads(&self) -> [CoreLoad; MAX_CPUS] {
        let mut l = [CoreLoad::OFFLINE; MAX_CPUS];
        for (c, load) in l.iter_mut().enumerate() {
            if self.online.contains(c) {
                let cur = self.current[c];
                load.online = true;
                load.running = if is_worker(cur) { self.task(cur).filter(|t| t.state == TaskState::Running).map(|t| t.sched.qos) } else { None };
            }
        }
        for k in self.candidates() {
            if let Some(load) = l.get_mut(k.home) {
                load.queued += 1;
            }
        }
        l
    }

    /// 处理器 `c` 参与调度（进入空闲执行流之前调用；重复调用无副作用）。
    /// Mark processor `c` as taking part in scheduling.
    pub fn cpu_online(&mut self, c: usize) {
        assert_eq!(c, this_cpu(), "a CPU must register itself while its leaf is held");
        if c < MAX_CPUS {
            self.online.insert(c);
        }
    }

    /// 参与调度的处理器集合。
    pub fn online(&self) -> CpuSet {
        self.online
    }

    /// 取走待发的重新调度请求（门面层放锁后对这些处理器发核间中断）。
    pub fn take_kicks(&mut self) -> CpuSet {
        core::mem::replace(&mut self.kicks, CpuSet::EMPTY)
    }

    /// 修改任务 `id` 的亲和集合。集合里没有在线处理器、任务无效时拒绝，状态不变。
    /// 任务所在队列不在新集合内时：可运行的立即改放；正在别处运行的由那个处理器在下一个检查点换下
    /// （记入重新调度请求），之后由新队列接手。返回任务现在是否仍可留在本处理器上运行。
    /// Change the affinity set of task `id`.
    pub fn set_affinity(&mut self, id: TaskId, set: CpuSet) -> Result<bool, AffinityError> {
        if (0..MAX_CPUS).all(|c| !(set.contains(c) && self.online.contains(c))) {
            return Err(AffinityError::NoOnlineCpu);
        }
        let i = self.live_slot(id).filter(|&i| i != BOOT_SLOT).ok_or(AffinityError::NoTask)?;
        let me = this_cpu();
        let (home, on_cpu) = {
            let t = self.task_mut(i).ok_or(AffinityError::NoTask)?;
            t.affinity = set;
            (t.home, t.on_cpu)
        };
        if set.contains(home) && self.online.contains(home) {
            return Ok(home == me || on_cpu != Some(me));
        }
        let loads = self.loads();
        let (qos, last_ran) = self.task(i).map(|t| (t.sched.qos, t.last_ran)).unwrap_or((Qos::Background, None));
        let new_home = self.balancer.place(set, None, qos, last_ran, self.now, &loads).map_err(|_| AffinityError::NoOnlineCpu)?;
        self.rehome(i, new_home);
        if let Some(c) = on_cpu.filter(|&c| c != me) {
            self.kicks.insert(c);
        }
        if new_home != me && loads[new_home].idle() {
            self.kicks.insert(new_home);
        }
        Ok(on_cpu != Some(me))
    }

    /// 任务 `id` 曾经运行过的处理器集合（不存在时 `None`）。
    pub fn ran_on(&self, id: TaskId) -> Option<CpuSet> {
        self.tasks.iter().flatten().find(|t| t.id == id).map(|t| t.ran_on)
    }

    /// 处理器 `c` 的调度统计。
    pub fn cpu_stats(&self, c: usize) -> CpuStats {
        self.cpu_stats.get(c).copied().unwrap_or_default()
    }

    /// 清零全部处理器的调度统计（每个测量场景开始前调用）。
    pub fn reset_cpu_stats(&mut self) {
        self.cpu_stats = [CpuStats::default(); MAX_CPUS];
    }

    // Author: chatgpt. Per-owner roots; no task-table scan or remote drain.
    fn refresh_wake(&mut self, c: usize) {
        self.next_wake[c] = self.wake_heap.peek(&self.wake_entries, &self.wake_positions, &self.wake_owners, c)
            .expect("wake forest coherence").map(|e| e.at).unwrap_or(u64::MAX);
    }
    fn refresh_rt(&mut self, c: usize) {
        self.next_rt[c] = self.rt_heap.peek(&self.rt_entries, &self.rt_positions, &self.rt_owners, c)
            .expect("RT forest coherence").map(|e| e.at).unwrap_or(u64::MAX);
    }
    fn set_wake_deadline(&mut self, c: usize, e: Deadline) {
        let old = self.wake_owners[e.slot];
        self.wake_heap.set(&mut self.wake_entries, &mut self.wake_positions, &mut self.wake_owners, c, e).expect("wake forest capacity/lifecycle");
        self.refresh_wake(c);
        if old != NO_DEADLINE && old != c { self.refresh_wake(old); }
        if e.at <= self.now { self.kicks.insert(c); }
    }
    fn set_rt_deadline(&mut self, c: usize, e: Deadline) {
        let old = self.rt_owners[e.slot];
        self.rt_heap.set(&mut self.rt_entries, &mut self.rt_positions, &mut self.rt_owners, c, e).expect("RT forest capacity/lifecycle");
        self.refresh_rt(c);
        if old != NO_DEADLINE && old != c { self.refresh_rt(old); }
        if e.at <= self.now { self.kicks.insert(c); }
    }
    fn remove_wake_deadline(&mut self, slot: usize, generation: u64) {
        let old = self.wake_owners[slot];
        self.wake_heap.remove(&mut self.wake_entries, &mut self.wake_positions, &mut self.wake_owners, slot, generation).expect("wake cancellation identity");
        if old != NO_DEADLINE { self.refresh_wake(old); }
    }
    fn remove_rt_deadline(&mut self, slot: usize, generation: u64) {
        let old = self.rt_owners[slot];
        self.rt_heap.remove(&mut self.rt_entries, &mut self.rt_positions, &mut self.rt_owners, slot, generation).expect("RT cancellation identity");
        if old != NO_DEADLINE { self.refresh_rt(old); }
    }
    fn wake_due(&mut self, c: usize, now: u64) -> bool {
        if now < self.next_wake[c] { return false; }
        self.scan.wake_scans += 1;
        let mut preempt = false;
        while let Some(event) = self.wake_heap.pop_due(&mut self.wake_entries, &mut self.wake_positions,
            &mut self.wake_owners, c, now).expect("wake forest coherence") {
            let valid = self.epochs.get(event.slot).and_then(SlotLifecycle::history)
                .is_some_and(|r| r.token().generation == event.generation)
                && self.task(event.slot).is_some_and(|t| t.home == c && t.state == TaskState::Blocked && t.wake_at == Some(event.at));
            if valid {
                #[cfg(feature = "fault-inject")]
                {
                    let trace = &mut self.deadline_trace[c];
                    if trace.token.slot == event.slot && trace.token.generation == event.generation && trace.at == event.at {
                        trace.ipis_after = crate::smp::percpu::get(c).unwrap().ipis(kernel_core::smp::IpiKind::Reschedule);
                        trace.consumed_at = now;
                        trace.consumer = this_cpu();
                        trace.consumed = true;
                    }
                }
                self.deadline_wakes[c] = self.deadline_wakes[c].wrapping_add(1);
                preempt |= self.make_runnable(event.slot);
            }
        }
        self.refresh_wake(c);
        preempt
    }

    /// 全局时钟 tick（在引导处理器的中断上下文、关中断状态下调用）：推进时刻 → 给刚运行完这个 tick 的任务记账 →
    /// 消费本处理器到期堆、对其他处理器到期根发请求 → 判断本处理器是否抢占。
    ///
    /// 返回需要切换时的原因（[`Cause`] 中的名字）；`preemption = false` 时只记账与唤醒、从不要求切换
    /// （被唤醒的任务等当前任务主动让出）。
    pub fn tick(&mut self, now: u64, preemption: bool) -> Option<&'static str> {
        self.now = now;
        let c = this_cpu();
        let cur = self.current[c];
        self.account(c);
        self.charge_groups(cur);
        self.charge_rt(cur, now);

        self.scan.ticks += 1;
        let cause = self.wake_due(c, now).then_some(Cause::WAKE);
        for target in self.online.iter().filter(|&target| target != c) {
            #[cfg(feature = "fault-inject")]
            if self.delayed_deadline_timer.contains(target) && now >= self.next_wake[target] {
                if let Some(event) = self.wake_heap.peek(&self.wake_entries, &self.wake_positions, &self.wake_owners, target).expect("trace heap coherence") {
                    let token = kernel_core::task_index::Token { slot: event.slot, generation: event.generation };
                    if self.deadline_trace[target].token != token || self.deadline_trace[target].at != event.at {
                        self.deadline_trace[target] = DeadlineTrace { token, at: event.at, requested_at: now,
                            stopped: self.nohz.stopped().contains(target),
                            ipis_before: crate::smp::percpu::get(target).unwrap().ipis(kernel_core::smp::IpiKind::Reschedule),
                            ..DeadlineTrace::EMPTY };
                    }
                }
            }
            if now >= self.next_wake[target] || now >= self.next_rt[target] { self.kicks.insert(target); }
        }
        self.kick_stopped();
        let cause = cause.or_else(|| self.decide(c));
        if preemption {
            cause
        } else {
            None
        }
    }

    /// 实时预算记账与周期补充（POL-4）。
    fn charge_rt(&mut self, cur: usize, now: u64) {
        if let Some(t) = self.tasks.get_mut(cur).and_then(|t| t.as_mut()) {
            if t.state == TaskState::Running && t.rt_period != 0 && t.rt_remaining > 0 {
                t.rt_remaining = t.rt_remaining.saturating_sub(1);
            }
        }
        self.refill_rt(this_cpu(), now);
    }
    fn refill_rt(&mut self, c: usize, now: u64) {
        if now < self.next_rt[c] { return; }
        while let Some(event) = self.rt_heap.pop_due(&mut self.rt_entries, &mut self.rt_positions,
            &mut self.rt_owners, c, now).expect("RT forest coherence") {
            let valid = self.epochs.get(event.slot).and_then(SlotLifecycle::history)
                .is_some_and(|r| r.token().generation == event.generation);
            let Some(t) = self.tasks.get_mut(event.slot).and_then(|t| t.as_mut()) else { continue };
            if !valid || t.home != c || t.rt_period == 0 || t.state == TaskState::Exited || t.rt_next_period != event.at { continue; }
            let next = kernel_core::deadline::next_period(now, t.rt_next_period, t.rt_period).expect("RT monotonic clock exhausted");
            t.rt_remaining = t.rt_quota;
            t.rt_next_period = next;
            self.deadline_refills[c] = self.deadline_refills[c].wrapping_add(1);
            self.set_rt_deadline(c, Deadline { at: next, ..event });
        }
        self.refresh_rt(c);
    }

    /// 设置任务的实时预算/周期（准入已由 kernel-core 判定）。
    pub fn set_rt(&mut self, id: TaskId, quota: u32, period: u32, now: u64) -> bool {
        let Some(slot) = self.live_slot(id) else { return false };
        let Some(next) = now.checked_add(period as u64) else { return false };
        if period == 0 {
            let generation = self.epochs[slot].history().unwrap().token().generation;
            self.remove_rt_deadline(slot, generation);
        } else {
            let generation = self.epochs[slot].history().unwrap().token().generation;
            let home = self.task(slot).unwrap().home;
            self.set_rt_deadline(home, Deadline { at: next, slot, generation });
        }
        if let Some(t) = self.tasks.get_mut(slot).and_then(|t| t.as_mut()) {
            t.rt_quota = quota;
            t.rt_period = period;
            t.rt_remaining = quota;
            t.rt_next_period = next;
            return true;
        }
        false
    }

    /// 其他处理器的本地时钟 tick（在该处理器的中断上下文、关中断状态下调用）：给本处理器正在运行的任务
    /// 记账（CPU组只扣费，组补充仍由全局tick做），处理本核RT补充/到期唤醒及周期均衡，再判断切换。
    /// Local tick of a secondary processor.
    pub fn local_tick(&mut self, preemption: bool) -> Option<&'static str> {
        let c = this_cpu();
        let cur = self.current[c];
        self.account(c);
        self.charge_rt(cur, self.now);
        let woke = self.wake_due(c, self.now);
        let group = match self.task(cur) {
            Some(t) if is_worker(cur) && t.state == TaskState::Running => t.cpu_group,
            _ => None,
        };
        if let Some(grp) = group.and_then(|g| self.groups[g].as_mut()) {
            grp.limit.charge();
        }
        let cause = self.decide(c).or(woke.then_some(Cause::WAKE));
        if preemption { cause } else { None }
    }

    /// 设置空闲停表的最大间隔（tick；< 2 关闭），返回之前的设置。关闭后已停表的处理器在下一次醒来时恢复周期 tick。
    /// Configure tickless idle (`divisor` < 2 disables it); returns the previous setting.
    pub fn set_idle_tick(&mut self, divisor: u32) -> u32 {
        core::mem::replace(&mut self.nohz_divisor, divisor)
    }

    /// 空闲停表的统计快照。
    /// Snapshot of tickless-idle statistics.
    pub fn nohz_stats(&self) -> NohzStats {
        let (stops, restarts) = self.nohz.counts();
        NohzStats { divisor: self.nohz_divisor, stopped: self.nohz.stopped(), stops, restarts, kicks: self.nohz_kicks }
    }

    /// 处理器 `c` 的空闲执行流（关中断）问下一步：有事可做 ⇒ 切换；否则在允许时登记停表。
    ///
    /// 停表的前提：已启用、不是计时处理器、本处理器没有按 tick 推进的工作（`needs_tick`，例如设备中断预算）。
    /// 判断与登记在同一次持锁内完成：之后才出现的工作由计时处理器的 tick 发现并叫醒它（见 `kick_stopped`）。
    /// Decide what idle processor `c` does next, registering a tick stop when allowed.
    pub fn idle_enter(&mut self, c: usize, needs_tick: bool) -> IdleStep {
        self.refill_rt(c, self.now);
        self.wake_due(c, self.now);
        if let Some(cause) = self.decide(c) {
            return IdleStep::Run(cause);
        }
        let at = self.next_wake[c].min(self.next_rt[c]);
        let deadline = (at != u64::MAX).then_some(at);
        #[cfg(feature = "fault-inject")]
        let deadline = if self.delayed_deadline_timer.contains(c) { None } else { deadline };
        match plan_with(self.now, deadline, self.nohz_divisor, needs_tick) {
            TickPlan::Periodic => IdleStep::Sleep,
            TickPlan::OneShot(n) => match self.nohz.stop(c, self.now, self.local_ticks[c]) {
                Ok(()) => IdleStep::Stop(n),
                Err(_) => IdleStep::Sleep,
            },
        }
    }

    /// 处理器 `c` 结束停表（醒来后、或平台不支持推迟时调用）：把停表期间本地 tick 没有记到的时长补记为空闲。
    /// 返回它是否确实停过表（调用者据此恢复周期定时器）；没停表时什么都不改。
    /// End a tick stop of processor `c`, accounting the idle time the local tick missed.
    pub fn idle_exit(&mut self, c: usize) -> bool {
        match self.nohz.restart(c, self.now, self.local_ticks[c]) {
            Some(missed) => {
                self.cpu_stats[c].idle_ticks += missed;
                true
            }
            None => false,
        }
    }

    /// 计时处理器的每个 tick：停表的处理器若有可接的工作（本队列有可运行任务、或可以窃取），记一次重新调度请求。
    ///
    /// 一次遍历全部候选任务（与可运行任务数成正比），每个候选最多叫醒一个停表处理器（优先它的归属处理器），
    /// 不会为一个任务叫醒一群处理器。被叫醒之前停表处理器看不到 tick，「空闲而有工作在等」由这里代为记账，
    /// 因此 [`CpuStats::max_idle_waiting`] 在停表时仍然如实。
    fn kick_stopped(&mut self) {
        let mut left = self.nohz.stopped().intersect(self.online);
        if left.is_empty() {
            return;
        }
        let mut wake = CpuSet::EMPTY;
        for k in self.candidates() {
            if left.is_empty() {
                break;
            }
            let pick = if left.contains(k.home) { Some(k.home) } else { k.affinity.intersect(left).iter().next() };
            if let Some(c) = pick {
                left.remove(c);
                wake.insert(c);
            }
        }
        for c in wake.iter() {
            self.kicks.insert(c);
            self.nohz_kicks += 1;
            let st = &mut self.cpu_stats[c];
            st.idle_waiting += 1;
            st.max_idle_waiting = st.max_idle_waiting.max(st.idle_waiting);
        }
    }

    /// 本处理器现在是否应切换（收到重新调度请求时调用；不记账）。
    /// Whether this processor should switch now (on a reschedule request).
    pub fn resched_check(&self) -> Option<&'static str> {
        self.decide(this_cpu())
    }

    /// 处理器 `c` 的每 tick 记账：策略记账、时间片、看门狗、统计、周期均衡。
    fn account(&mut self, c: usize) {
        let cur = self.current[c];
        let waiting = self.waiting(c);
        let worker = is_worker(cur) && self.task(cur).is_some_and(|t| t.state == TaskState::Running);
        let running = if worker { self.tasks[cur].as_mut().map(|t| &mut t.sched) } else { None };
        let r = match running {
            Some(e) if e.queue() == Some(c) => self.queues[c].tick(Some(e), waiting),
            // 迁移途中的一个 tick（亲和变更后、在下一个检查点换下之前）：它的私有状态已属于目标队列，
            // 本处理器的策略实例不为它记账，只记 Core 运行量
            Some(e) => {
                e.cpu_ticks += 1;
                self.queues[c].tick(None, waiting)
            }
            None => self.queues[c].tick(None, waiting),
        };
        self.note(r);
        self.slice_used[c] = self.slice_used[c].saturating_add(1);
        self.local_ticks[c] += 1;
        let now = self.now;
        self.charge_watchdog(cur, now);
        let waiting_work = !worker && (waiting != ClassMask::EMPTY || self.stealable(c));
        let st = &mut self.cpu_stats[c];
        if worker {
            st.busy_ticks += 1;
        } else {
            st.idle_ticks += 1;
        }
        if waiting_work {
            st.idle_waiting += 1;
            st.max_idle_waiting = st.max_idle_waiting.max(st.idle_waiting);
        } else {
            st.idle_waiting = 0;
        }
        if worker && self.balancer.due(self.local_ticks[c]) {
            let loads = self.loads();
            match self.balancer.pull(c, now, &loads, self.candidates()) {
                Ok(slot) => {
                    self.rehome(slot, c);
                    self.cpu_stats[c].pulls += 1;
                }
                Err(Refusal::AllHot) => self.cpu_stats[c].pull_hot += 1,
                Err(_) => {}
            }
        }
    }

    /// 处理器 `c` 现在是否应切换及原因：当前任务已不属于本处理器 → 迁移；被限速 → 限速；
    /// 否则询问本处理器的策略；空闲且本队列无事可做但可以窃取 → 窃取。
    fn decide(&self, c: usize) -> Option<&'static str> {
        let cur = self.current[c];
        let cur_task = self.task(cur).filter(|t| is_worker(cur) && t.state == TaskState::Running);
        if let Some(t) = cur_task {
            if t.home != c {
                return Some(Cause::MIGRATE);
            }
            if !self.eligible(t) {
                THROTTLES.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                return Some(Cause::THROTTLE);
            }
        }
        let p = self.queues[c].should_preempt(cur_task.map(|t| &t.sched), self.slice_used[c], self.slice_quantum[c], self.waiting(c));
        if let Some(p) = p {
            return Some(Cause::of(p));
        }
        if cur_task.is_none() && self.stealable(c) {
            return Some(Cause::STEAL);
        }
        None
    }

    /// 准备一次切换：更新状态、选出下一个任务、记账、通知观察者。
    ///
    /// `cause == Cause::YIELD`（主动让出）时先在**其他**任务中选：选出的不低于自己的档位（或是最低份额补给）
    /// 才切换，否则继续运行自己——让出不应把处理器交给更低档的任务，也不应因为自己用量少就选回自己。
    /// 其他原因让策略在全部可运行任务（含自己）中选。只在本处理器的队列中选；队列里什么都没有时先尝试
    /// 从别的队列窃取一个，仍没有则回到本处理器的空闲落脚点。
    ///
    /// 返回 `Some(plan)` 表示调用者必须**立即**执行 `switch_context(plan.old, plan.new)`，
    /// 切换回来（或新任务开始执行）后调用 [`Scheduler::finish_switch`]；返回 `None` 表示无需切换（下一个就是自己）。
    pub fn prepare_switch(&mut self, cause: &'static str) -> Option<SwitchPlan> {
        let c = this_cpu();
        let prev = self.current[c];
        let now = self.now;
        let requeue_hook = if cause == Cause::THROTTLE {
            None
        } else if cause == Cause::YIELD {
            Some(Requeue::Yield)
        } else {
            Some(Requeue::Preempted)
        };
        let prev_runnable = match self.tasks.get_mut(prev).and_then(|t| t.as_mut()) {
            Some(t) if t.state == TaskState::Running => {
                t.state = TaskState::Runnable;
                t.last_ran = Some(now);
                if is_worker(prev) {
                    // 被换下仍可运行：让出钩子（或预算钩子）交给它所在的队列（亲和变更后可能已不是本处理器）
                    let q = t.sched.queue().unwrap_or(c).min(MAX_CPUS - 1);
                    let r = match requeue_hook {
                        Some(why) => self.queues[q].requeue(&mut t.sched, why),
                        None => self.queues[q].throttled(&mut t.sched),
                    };
                    self.note(r);
                }
                is_worker(prev)
            }
            _ => false,
        };
        let yielding = cause == Cause::YIELD;
        if Cause::voluntary(cause) {
            let wd = self.watchdog;
            if let Some(t) = self.task_mut(prev) {
                wd.yielded(&mut t.streak);
            }
        }
        // 本队列（含刚换下、仍属于本处理器的自己）空了：空闲之前先窃取
        let own_empty = self.waiting(c) == ClassMask::EMPTY && !(prev_runnable && self.task(prev).is_some_and(|t| t.home == c && self.eligible(t)));
        if own_empty && self.online.contains(c) {
            let loads = self.loads();
            if let Ok(slot) = self.balancer.steal(c, now, &loads, self.candidates()) {
                self.rehome(slot, c);
                self.cpu_stats[c].steals += 1;
            }
        }

        // 类别仲裁在借用 tasks 之前完成（它会修改仲裁器状态）。
        let wanted = self.pick_arb_class(c, prev);
        // 只遍历本处理器的运行列表（与任务表容量无关）；记下遍历长度供验收核对
        let visited = self.runs.len(c) as u32;
        self.scan.picks += 1;
        self.scan.visited += visited as u64;
        self.scan.max_visited = self.scan.max_visited.max(visited);
        let choice = {
            let tasks = &self.tasks;
            let groups = &self.groups;
            let (runs, links) = (&self.runs, &self.links);
            let runnable = |skip_prev: bool| {
                runs.iter(links, c).filter_map(move |i| match tasks[i].as_ref() {
                    Some(t)
                        if t.state == TaskState::Runnable
                            && t.home == c
                            && (t.on_cpu.is_none() || i == prev)
                            && !(skip_prev && i == prev)
                            && wanted.is_none_or(|cl| arb_class(t) == cl)
                            && eligible_in(groups, t) =>
                    {
                        Some((i, &t.sched))
                    }
                    _ => None,
                })
            };
            let policy = &self.queues[c];
            let mut it = runnable(yielding);
            let mut ch = policy.choose(&mut it);
            if yielding && prev_runnable {
                let prev_qos = tasks[prev].as_ref().map(|t| t.sched.qos);
                let worse = |slot: usize| match (tasks[slot].as_ref(), prev_qos) {
                    (Some(t), Some(pq)) => policy.policy().outranks(pq, t.sched.qos),
                    _ => false,
                };
                if ch.is_none_or(|x| !x.rescued && worse(x.slot)) {
                    let mut only_prev = runnable(false).filter(|(i, _)| *i == prev);
                    ch = policy.choose(&mut only_prev);
                }
            }
            ch
        };

        let next = match choice {
            Some(ch) => {
                self.slice_quantum[c] = ch.quantum.max(1);
                ch.slot
            }
            None => {
                self.slice_quantum[c] = 1;
                idle_slot(c)
            }
        };
        self.slice_used[c] = 0;
        let mut latency = None;
        if let Some(t) = self.task_mut(next) {
            t.state = TaskState::Running;
            if is_worker(next) {
                t.on_cpu = Some(c);
                t.ran_on.insert(c);
                if let Some(w) = t.woken_at.take() {
                    latency = Some((t.sched.qos, now.saturating_sub(w)));
                }
            }
        }
        if is_worker(next) && next != prev {
            let r = self.epochs[next].history().expect("dispatched task identity");
            self.epochs[next].dispatch(r.token()).expect("dispatch detached live task");
        }
        if is_worker(next) {
            if let Some(t) = self.tasks[next].as_mut() {
                let r = self.queues[c].dispatched(&mut t.sched);
                self.note(r);
            }
        }
        if let Some((q, d)) = latency {
            self.latency[q.index()].record(d);
        }
        if next == prev {
            return None;
        }

        self.switches += 1;
        if let Some(observer) = self.observer {
            observer(&SwitchEvent {
                from: self.task(prev).map(|t| t.name).unwrap_or("idle"),
                to: self.task(next).map(|t| t.name).unwrap_or("idle"),
                seq: self.switches,
                cause,
            });
        }
        self.current[c] = next;
        self.switching_from[c] = Some(prev);

        let next_space = self.task(next).and_then(|t| t.space);
        let next_stack_top = if is_worker(next) { Some(self.stacks.top(next)) } else { None };
        let old: *mut TaskContext = match self.tasks.get_mut(prev).and_then(|t| t.as_mut()) {
            Some(t) => &mut t.context,
            None => &mut self.idle_ctx[c],
        };
        let new: *const TaskContext = match self.task(next) {
            Some(t) => &t.context,
            None => &self.idle_ctx[c],
        };
        Some(SwitchPlan { old, new, next_stack_top, next_space, next_slot: next })
    }

    // Author: chatgpt. Endpoint is captured on the resumed execution flow,
    // before acquiring this guard. IRQs remain masked, so current cannot migrate.
    #[cfg(feature = "krn2-observe")]
    pub(super) fn note_raw_resume(&mut self, end: kernel_core::raw_timing::Endpoint, path: u16) {
        let slot = self.cur();
        if !is_worker(slot) { return; }
        let token = self.epochs.get(slot).and_then(SlotLifecycle::history).map(|r| r.token());
        let completion = self.task_mut(slot).and_then(|t| {
            let round = t.raw_wake_round.take()?;
            Some(token.and_then(|token| t.raw_wake.finish(token, round, end)))
        });
        match completion {
            Some(Some(mut sample)) => { sample.path = path; let _ = self.raw_wakes.push(sample); }
            Some(None) => self.raw_wake_errors[1] = self.raw_wake_errors[1].saturating_add(1),
            None => {}
        }
    }
    #[cfg(feature = "krn2-observe")]
    pub(super) fn raw_pending_count(&self) -> usize {
        self.tasks.iter().flatten().filter(|t| t.raw_wake_round.is_some()).count()
    }

    /// 切换完成（在被切入的执行流上、关中断时调用）：本处理器上一次换下的任务已保存好上下文，
    /// 清除它的 `on_cpu`，此后其他处理器才可以选中它、它的槽位（若已退出）才可以复用。
    /// Complete a switch: the previous task's context is saved, release it.
    pub fn finish_switch(&mut self) {
        let c = this_cpu();
        if let Some(p) = self.switching_from[c].take() {
            if let Some(t) = self.task_mut(p).filter(|_| is_worker(p)) {
                if t.on_cpu == Some(c) {
                    t.on_cpu = None;
                }
            }
            if is_worker(p) {
                let r = self.epochs[p].history().expect("detached task identity");
                self.epochs[p].detach(r.token()).expect("detach executing task");
            }
            // 换下的任务若仍可运行但已不属于本处理器（迁移、亲和变更），叫醒它的新处理器接手
            if let Some(t) = self.task(p).filter(|t| is_worker(p) && t.state == TaskState::Runnable && t.home != c) {
                let home = t.home;
                if self.online.contains(home) {
                    self.kicks.insert(home);
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // CPU 组（每组一份上限令牌桶）
    // -----------------------------------------------------------------------

    /// 任务现在能否被选中：不属于任何组、组未被限速、或正持有借来的档位（优先级继承豁免限速，
    /// 否则被限速的持有者会把等它的高档任务一起拖住）。
    fn eligible(&self, t: &Task) -> bool {
        eligible_in(&self.groups, t)
    }

    /// 有效组标识对应的槽位。
    fn group_slot(&self, g: CpuGroupId) -> Option<usize> {
        match self.groups.get(g.slot) {
            Some(Some(grp)) if grp.gen == g.gen => Some(g.slot),
            _ => None,
        }
    }

    /// 组引用减一，归零时释放槽位。
    fn unref_group(&mut self, slot: usize) {
        if let Some(grp) = self.groups[slot].as_mut() {
            grp.refs = grp.refs.saturating_sub(1);
            if grp.refs == 0 {
                self.groups[slot] = None;
            }
        }
    }

    /// 新建 CPU 组（上限千分比、桶容量 tick），调用者持有一份引用，用完以 [`Scheduler::release_group`] 归还。
    /// Creates a CPU group; the caller holds one reference.
    pub fn create_group(&mut self, limit_permille: u32, burst_ticks: u32) -> Result<CpuGroupId, GroupError> {
        let limit = CpuLimit::new(limit_permille, burst_ticks).map_err(GroupError::Limit)?;
        // 代次用尽的槽位永久退役，不回绕（否则旧的组标识会在槽位复用后「复活」，指向新组）
        let slot = (0..self.groups.len())
            .find(|&i| self.groups[i].is_none() && self.group_gen[i] != GENERATION_RETIRED)
            .ok_or(GroupError::NoFreeGroup)?;
        let gen = self.group_gen[slot];
        self.group_gen[slot] = advance_generation(gen);
        self.groups[slot] = Some(CpuGroup { gen, limit, refs: 1 });
        Ok(CpuGroupId { slot, gen })
    }

    /// 归还持有者的引用；成员全部退出后组即释放（标识随之失效）。
    pub fn release_group(&mut self, g: CpuGroupId) -> Result<(), GroupError> {
        let slot = self.group_slot(g).ok_or(GroupError::Stale)?;
        self.unref_group(slot);
        Ok(())
    }

    /// 修改组的上限；非法值被拒且原上限不变。
    pub fn set_group_limit(&mut self, g: CpuGroupId, limit_permille: u32) -> Result<(), GroupError> {
        let slot = self.group_slot(g).ok_or(GroupError::Stale)?;
        let grp = self.groups[slot].as_mut().ok_or(GroupError::Stale)?;
        grp.limit.set_limit(limit_permille).map_err(GroupError::Limit)
    }

    /// 组的记账快照。
    pub fn group_stats(&self, g: CpuGroupId) -> Option<CpuLimitStats> {
        let slot = self.group_slot(g)?;
        self.groups[slot].as_ref().map(|grp| grp.limit.stats())
    }

    /// 仍存在的组数（诊断：组全部释放后应回到 0）。
    pub fn live_groups(&self) -> usize {
        self.groups.iter().flatten().count()
    }

    /// 把已存在的任务 `id` 移入组 `g`（`None` = 移出所有组）。任务或组无效时拒绝，状态不变。
    pub fn assign_group(&mut self, id: TaskId, g: Option<CpuGroupId>) -> Result<(), GroupError> {
        let new = match g {
            Some(g) => Some(self.group_slot(g).ok_or(GroupError::Stale)?),
            None => None,
        };
        let i = self.live_slot(id).filter(|&i| i != BOOT_SLOT).ok_or(GroupError::NoTask)?;
        let old = self.tasks[i].as_ref().and_then(|t| t.cpu_group);
        if old == new {
            return Ok(());
        }
        if let Some(n) = new {
            if let Some(grp) = self.groups[n].as_mut() {
                grp.refs += 1;
            }
        }
        if let Some(t) = self.tasks[i].as_mut() {
            t.cpu_group = new;
        }
        if let Some(o) = old {
            self.unref_group(o);
        }
        Ok(())
    }

    /// 每个 tick：给刚运行完这个 tick 的任务所在组扣费，全部组补充令牌并统计被限速的 tick。
    fn charge_groups(&mut self, cur: usize) {
        let ran_group = match self.task(cur) {
            Some(t) if is_worker(cur) && t.state == TaskState::Running => t.cpu_group,
            _ => None,
        };
        let wants = &mut self.scratch_wants;
        wants.fill(false);
        // 可运行或运行中的任务一定在某个运行列表上：只遍历列表
        for q in 0..MAX_CPUS {
            for i in self.runs.iter(&self.links, q) {
                if let Some(t) = self.tasks.get(i).and_then(|t| t.as_ref()) {
                    if let (Some(g), TaskState::Runnable | TaskState::Running) = (t.cpu_group, t.state) {
                        wants[g] = true;
                    }
                }
            }
        }
        for (slot, grp) in self.groups.iter_mut().enumerate() {
            if let Some(grp) = grp.as_mut() {
                grp.limit.on_tick(ran_group == Some(slot), wants[slot]);
            }
        }
    }

    // -----------------------------------------------------------------------
    // 看门狗
    // -----------------------------------------------------------------------

    /// 每个 tick：给正在运行的工作任务记一笔连续占用，越过阈值时写一条报告。
    fn charge_watchdog(&mut self, cur: usize, now: u64) {
        if !is_worker(cur) {
            return;
        }
        let wd = self.watchdog;
        let Some(t) = self.tasks.get_mut(cur).and_then(|t| t.as_mut()).filter(|t| t.state == TaskState::Running) else { return };
        if let Some(streak) = wd.charge(&mut t.streak) {
            let r = WatchdogReport { task: t.id.0, name: t.name, streak, at: now };
            self.watchdog_log.push(r);
        }
    }

    /// 看门狗报告日志（副本）。
    pub fn watchdog_log(&self) -> WatchdogLog<WATCHDOG_LOG> {
        self.watchdog_log
    }

    /// 清空看门狗报告日志（每个测量场景开始前调用）。
    pub fn clear_watchdog(&mut self) {
        self.watchdog_log.clear();
    }

    /// 看门狗阈值（tick）。
    pub fn watchdog_threshold(&self) -> u32 {
        self.watchdog.threshold()
    }

    /// 修改看门狗阈值（tick，0 视为 1），返回旧值；已在进行的连续占用按新阈值继续判定。
    pub fn set_watchdog_threshold(&mut self, ticks: u32) -> u32 {
        core::mem::replace(&mut self.watchdog, Watchdog::new(ticks)).threshold()
    }

    /// 某档的唤醒延迟直方图。
    pub fn latency(&self, q: Qos) -> LatencyHistogram {
        self.latency[q.index()]
    }

    /// 清空全部唤醒延迟直方图（每个测量场景开始前调用）。
    pub fn reset_latency(&mut self) {
        self.latency = [const { LatencyHistogram::new() }; QOS_CLASSES];
    }

    /// 任务 `id` 累计运行的 tick 数（不存在时 `None`）。
    pub fn cpu_ticks(&self, id: TaskId) -> Option<u64> {
        self.historical_slot(id).and_then(|i| self.task(i)).map(|t| t.sched.cpu_ticks)
    }
}

/// 任务 `t` 能否被选中（见 [`Scheduler::eligible`]）；独立成函数以便在借用任务表时同时借用组表。
/// 任务所属的仲裁类别：实时任务（有周期）优先归实时类；其余按 QoS 档位归并。
/// English: map a task to its arbitration class.
fn arb_class(t: &Task) -> kernel_core::arbiter::Class {
    use kernel_core::arbiter::Class;
    if t.rt_period != 0 {
        return Class::RealTime;
    }
    match t.sched.qos {
        Qos::Interactive | Qos::UserInitiated => Class::Interactive,
        Qos::Utility | Qos::Background => Class::Batch,
    }
}

fn eligible_in(groups: &[Option<CpuGroup>], t: &Task) -> bool {
    // 实时预算耗尽必须等归属CPU真正补充；仅时钟到下一周期不构成授权。
    if t.rt_period != 0 && t.rt_remaining == 0 {
        return false;
    }
    match t.cpu_group {
        None => true,
        Some(g) => t.sched.qos != t.base_qos || groups[g].as_ref().is_none_or(|grp| grp.limit.eligible()),
    }
}
