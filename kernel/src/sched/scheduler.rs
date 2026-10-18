//! 调度机制（与策略无关的核心）：任务表、状态迁移、睡眠与唤醒、时钟记账、切换准备、切换事件通知。
//!
//! 职责：
//! * 维护任务表（槽位 0 = 引导线程，只在没有可运行工作任务时运行，不参与策略选择）
//! * 把「选谁、给多长时间片、要不要抢占」委托给策略 `P: SchedPolicy`（Strategy 模式）
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
//! 可复用性：`Scheduler<P, N>` 不含任何全局状态，可在多实例场景中直接构造。

use crate::arch::TaskContext;
use crate::task::{Task, TaskId, TaskState};

use super::policy::{
    inherit, qos_change_allowed, ClassMask, CpuLimit, CpuLimitStats, LatencyHistogram, LimitError, Preempt, Qos, SchedPolicy, Watchdog, WatchdogLog,
    WatchdogReport, QOS_CLASSES,
};
use super::stack::{ReserveError, StackPool};

/// 引导线程所在槽位。
pub const BOOT_SLOT: usize = 0;

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
}

/// 切换观察者：在真正换栈之前被调用。
pub type SwitchObserver = fn(&SwitchEvent);

/// 新建任务失败的原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnError {
    /// 没有带栈的空闲工作槽位。
    NoFreeSlot,
    /// 指定的 CPU 组无效。
    BadGroup,
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

/// 看门狗报告日志容量。
pub const WATCHDOG_LOG: usize = crate::config::ACTIVE.sched.watchdog_log;

/// 调度机制本体。`N` 为槽位总数（含引导线程）。
pub struct Scheduler<P: SchedPolicy, const N: usize> {
    tasks: [Option<Task>; N],
    stacks: StackPool<N>,
    policy: P,
    current: usize,
    switches: u64,
    observer: Option<SwitchObserver>,
    /// 调度器看到的当前时刻（tick；由 [`Scheduler::tick`] 推进）。
    now: u64,
    /// 当前时间片已用的 tick 数与长度。
    slice_used: u32,
    slice_quantum: u32,
    /// 每档的唤醒延迟直方图。
    latency: [LatencyHistogram; QOS_CLASSES],
    /// 是否沿等待关系传播档位（默认开启；关闭只用于对照测量）。
    inherit: bool,
    /// 等待序号（同档等待者先来先得）。
    wait_seq: u64,
    /// CPU 组表（组数不会超过任务槽位数：每组至少要有一个持有者）。
    groups: [Option<CpuGroup>; N],
    /// 各组槽位的下一个世代号。
    group_gen: [u32; N],
    /// 看门狗判定器与报告日志。
    watchdog: Watchdog,
    watchdog_log: WatchdogLog<WATCHDOG_LOG>,
}

impl<P: SchedPolicy, const N: usize> Scheduler<P, N> {
    /// 构造调度器；槽位 0 预置为正在运行的引导线程。
    pub const fn new(policy: P) -> Self {
        let mut tasks = [const { None }; N];
        let mut boot = Task::new(TaskId(0), "boot");
        boot.state = TaskState::Running;
        tasks[BOOT_SLOT] = Some(boot);
        Scheduler {
            tasks,
            stacks: StackPool::new(),
            policy,
            current: BOOT_SLOT,
            switches: 0,
            observer: None,
            now: 0,
            slice_used: 0,
            slice_quantum: 1,
            latency: [const { LatencyHistogram::new() }; QOS_CLASSES],
            inherit: true,
            wait_seq: 0,
            groups: [const { None }; N],
            group_gen: [0; N],
            watchdog: Watchdog::new(super::policy::WATCHDOG_THRESHOLD),
            watchdog_log: WatchdogLog::new(),
        }
    }

    /// 安装切换观察者（覆盖旧的）。
    pub fn set_observer(&mut self, observer: SwitchObserver) {
        self.observer = Some(observer);
    }

    /// 当前策略名。
    pub fn policy_name(&self) -> &'static str {
        self.policy.name()
    }

    /// 默认档位的时间片（tick 数）。
    pub fn default_quantum(&self) -> u32 {
        self.policy.default_quantum()
    }

    /// 堆就绪后为其余槽位分配内核栈；返回可用槽位总数（含引导线程槽位）。
    pub fn reserve_stacks(&mut self) -> Result<usize, ReserveError> {
        self.stacks.reserve()
    }

    /// 可用槽位总数（含引导线程槽位）。
    pub fn capacity(&self) -> usize {
        self.stacks.available()
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
        let explicit = match group {
            Some(g) => Some(self.group_slot(g).ok_or(SpawnError::BadGroup)?),
            None => None,
        };
        // 空槽位或「已退出且不是当前任务」的槽位都可复用：
        // 已退出任务一旦被切走，就再也不会在它的栈上执行，栈与 TCB 可以安全覆盖。
        let current = self.current;
        let slot = (1..N)
            .find(|&i| {
                self.stacks.has_stack(i)
                    && match self.tasks[i].as_ref() {
                        None => true,
                        Some(t) => t.state == TaskState::Exited && i != current,
                    }
            })
            .ok_or(SpawnError::NoFreeSlot)?;
        let mut task = Task::new(id, name);
        task.entry = Some(entry);
        if current != BOOT_SLOT {
            if let Some(creator) = self.tasks[current].as_ref() {
                task.sched = super::policy::SchedEntity::new(creator.base_qos);
                task.base_qos = creator.base_qos;
                task.qos_ceiling = creator.qos_ceiling;
                task.cpu_group = creator.cpu_group;
            }
        }
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
        Ok(slot)
    }

    /// 当前运行任务的入口函数（trampoline 使用）。
    pub fn current_entry(&self) -> Option<fn()> {
        self.tasks[self.current].as_ref().and_then(|t| t.entry)
    }

    /// 当前运行任务的 id 与名字。
    pub fn current(&self) -> (TaskId, &'static str) {
        self.tasks[self.current]
            .as_ref()
            .map(|t| (t.id, t.name))
            .unwrap_or((TaskId(u64::MAX), "?"))
    }

    /// 当前是否在引导线程上运行。
    pub fn on_boot(&self) -> bool {
        self.current == BOOT_SLOT
    }

    /// 累计切换次数。
    pub fn switch_count(&self) -> u64 {
        self.switches
    }

    /// 设置当前任务的地址空间（`None` = 内核空间）。之后每次切回该任务都会切到这个空间。
    pub fn set_current_space(&mut self, space: Option<crate::arch::SpaceRoot>) {
        if let Some(t) = self.tasks[self.current].as_mut() {
            t.space = space;
        }
    }

    /// 设置当前任务可发起的系统调用集合。
    pub fn set_current_syscalls(&mut self, set: crate::syscall::SyscallSet) {
        if let Some(t) = self.tasks[self.current].as_mut() {
            t.syscalls = set;
        }
    }

    /// 当前任务的地址空间（`None` = 内核空间）。
    pub fn current_space(&self) -> Option<crate::arch::SpaceRoot> {
        self.tasks[self.current].as_ref().and_then(|t| t.space)
    }

    /// 当前任务可发起的系统调用集合。
    pub fn current_syscalls(&self) -> crate::syscall::SyscallSet {
        self.tasks[self.current].as_ref().map(|t| t.syscalls).unwrap_or(crate::syscall::SyscallSet::EMPTY)
    }

    /// 当前任务的自身 QoS 档位（不含借来的档位；引导线程为 `None`）。
    pub fn current_qos(&self) -> Option<Qos> {
        if self.current == BOOT_SLOT {
            return None;
        }
        self.tasks[self.current].as_ref().map(|t| t.base_qos)
    }

    /// 任务 `id` 的有效档位（含借来的档位；不存在、已退出或是引导线程时 `None`）。
    pub fn effective_qos(&self, id: TaskId) -> Option<Qos> {
        self.live_slot(id).filter(|&i| i != BOOT_SLOT).and_then(|i| self.tasks[i].as_ref()).map(|t| t.sched.qos)
    }

    /// 修改当前任务的 QoS 档位：降低或不变总是允许；提升须在上限之内（判定见 `qos_change_allowed`）。
    /// 成功后立即生效于下一次调度决策（降档后若有更高档任务在等，下一个 tick 就会被抢占）。
    pub fn set_current_qos(&mut self, q: Qos) -> Result<(), QosError> {
        if self.current == BOOT_SLOT {
            return Err(QosError::NotAWorker);
        }
        let t = self.tasks[self.current].as_mut().ok_or(QosError::NotAWorker)?;
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
        if let Some(t) = self.tasks[self.current].as_mut() {
            t.qos_ceiling = ceiling;
        }
    }

    /// 把当前任务标记为已退出（槽位在它被切走之后才可被 `spawn` 复用）。
    /// 正在等它的任务（等它退出、或等它持有的锁）全部被唤醒，借给它的档位随之归还。
    pub fn mark_current_exited(&mut self) {
        let cur = self.current;
        let mut left = None;
        if let Some(t) = self.tasks[cur].as_mut() {
            t.state = TaskState::Exited;
            t.waits_for = None;
            left = t.cpu_group.take();
        }
        if let Some(g) = left {
            self.unref_group(g);
        }
        for i in 0..N {
            if matches!(self.tasks[i].as_ref(), Some(t) if t.waits_for == Some(cur)) {
                self.make_runnable(i);
            }
        }
        self.resolve_inheritance();
    }

    /// 任务 `id` 所在槽位（只找尚未退出的任务；引导线程也算）。
    fn live_slot(&self, id: TaskId) -> Option<usize> {
        (0..N).find(|&i| matches!(self.tasks[i].as_ref(), Some(t) if t.id == id && t.state != TaskState::Exited))
    }

    /// 任务 `id` 是否存在且尚未退出。
    pub fn is_live(&self, id: TaskId) -> bool {
        self.live_slot(id).is_some()
    }

    /// 打开/关闭优先级继承，返回之前的设置（只供对照测量；关闭后立即按自身档位重算）。
    pub fn set_inheritance(&mut self, enabled: bool) -> bool {
        let prev = core::mem::replace(&mut self.inherit, enabled);
        self.resolve_inheritance();
        prev
    }

    /// 按当前等待图重算全部任务的有效档位（整体重算，借出与归还不会残留）。
    fn resolve_inheritance(&mut self) {
        let mut base = [None; N];
        let mut waits = [None; N];
        for (i, t) in self.tasks.iter().enumerate().skip(1) {
            if let Some(t) = t {
                if t.state != TaskState::Exited {
                    base[i] = Some(t.base_qos);
                    waits[i] = t.waits_for;
                }
            }
        }
        let mut eff = [None; N];
        inherit::resolve(&base, &waits, self.inherit, &mut eff);
        for (t, q) in self.tasks.iter_mut().zip(eff) {
            if let (Some(t), Some(q)) = (t.as_mut(), q) {
                t.sched.qos = q;
            }
        }
    }

    /// 让当前工作任务阻塞，直到持有者 `owner` 把它唤醒（交出锁或退出）；期间把有效档位借给持有者。
    ///
    /// `key` 标识等待的对象（同一持有者可能被不同对象上的任务等待）。成功后调用者必须立即让出
    /// （`prepare_switch(Cause::BLOCK)`）；失败时不改动任何状态。
    pub fn block_on(&mut self, owner: TaskId, key: u64) -> Result<(), BlockError> {
        let cur = self.current;
        if cur == BOOT_SLOT {
            return Err(BlockError::NotAWorker);
        }
        let owner_slot = self.live_slot(owner).ok_or(BlockError::NoOwner)?;
        let mut waits = [None; N];
        for (w, t) in waits.iter_mut().zip(self.tasks.iter()) {
            *w = t.as_ref().and_then(|t| t.waits_for);
        }
        inherit::check_edge(&waits, cur, owner_slot).map_err(BlockError::Refused)?;
        self.wait_seq += 1;
        let seq = self.wait_seq;
        let t = self.tasks[cur].as_mut().ok_or(BlockError::NotAWorker)?;
        t.state = TaskState::Blocked;
        t.wake_at = None;
        t.waits_for = Some(owner_slot);
        t.wait_key = key;
        t.wait_seq = seq;
        self.resolve_inheritance();
        Ok(())
    }

    /// 当前任务交出 `key` 标识的对象：在等它的任务中选出交接对象（有效档位最高、同档先来先得）并唤醒，
    /// 其余等待者改为等交接对象（档位随之借给新持有者）；当前任务借来的档位归还。返回交接对象。
    pub fn hand_off(&mut self, key: u64) -> Option<TaskId> {
        let cur = self.current;
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
        let Some(top) = self.waiting().highest() else { return false };
        match self.tasks[self.current].as_ref() {
            Some(t) if self.current != BOOT_SLOT => top.above(t.sched.qos),
            _ => true,
        }
    }

    /// 让当前工作任务睡眠到 `wake_at`（`None` = 只能被 [`Scheduler::wake`] 唤醒）。
    /// 调用者随后必须立即让出（`prepare_switch`）。引导线程不能睡眠（返回 `false`，状态不变）。
    pub fn block_current(&mut self, wake_at: Option<u64>) -> bool {
        if self.current == BOOT_SLOT {
            return false;
        }
        match self.tasks[self.current].as_mut() {
            Some(t) => {
                t.state = TaskState::Blocked;
                t.wake_at = wake_at;
                true
            }
            None => false,
        }
    }

    /// 槽位 `i` 的睡眠任务变为可运行（记下唤醒时刻，通知策略）。返回是否应立即抢占当前任务。
    fn make_runnable(&mut self, i: usize) -> bool {
        let now = self.now;
        let Some(t) = self.tasks[i].as_mut() else { return false };
        if t.state != TaskState::Blocked {
            return false;
        }
        t.state = TaskState::Runnable;
        t.wake_at = None;
        t.woken_at = Some(now);
        // 被任何途径唤醒都解除等待关系（例如所属进程开始终止）；醒来者自己重新检查等待条件。
        let had_edge = t.waits_for.take().is_some();
        self.policy.woken(&mut t.sched);
        if had_edge {
            self.resolve_inheritance();
        }
        // 被限速组的成员醒来也不抢占：令牌回正之前它本来就不会被选中。
        if !self.tasks[i].as_ref().is_some_and(|t| self.eligible(t)) {
            return false;
        }
        let woken = self.tasks[i].as_ref().map(|t| t.sched.qos).unwrap_or(Qos::Background);
        let current = if self.current == BOOT_SLOT { None } else { self.tasks[self.current].as_ref().map(|t| t.sched.qos) };
        self.policy.wake_preempts(woken, current)
    }

    /// 显式唤醒 `id`（例如所属进程开始终止时，让睡眠中的线程尽快观察到）。
    /// 返回是否应立即抢占当前任务；任务不存在或不在睡眠时返回 `false`。
    pub fn wake(&mut self, id: TaskId) -> bool {
        match (1..N).find(|&i| matches!(self.tasks[i].as_ref(), Some(t) if t.id == id)) {
            Some(i) => self.make_runnable(i),
            None => false,
        }
    }

    /// 尚未退出的工作任务数（可运行 + 运行中 + 睡眠）。
    pub fn live_workers(&self) -> usize {
        self.tasks[1..].iter().flatten().filter(|t| t.state != TaskState::Exited).count()
    }

    /// 是否有可运行的工作任务（不含当前任务）。
    pub fn has_runnable_worker(&self) -> bool {
        self.waiting() != ClassMask::EMPTY
    }

    /// 除当前任务之外、还有可运行工作任务的档位集合。
    fn waiting(&self) -> ClassMask {
        let mut m = ClassMask::EMPTY;
        for (i, t) in self.tasks.iter().enumerate().skip(1) {
            if let Some(t) = t {
                if i != self.current && t.state == TaskState::Runnable && self.eligible(t) {
                    m.insert(t.sched.qos);
                }
            }
        }
        m
    }

    /// 时钟 tick（在中断上下文、关中断状态下调用）：推进时刻 → 给刚运行完这个 tick 的任务记账 →
    /// 唤醒到期的睡眠任务 → 判断是否抢占。
    ///
    /// 返回需要切换时的原因（[`Cause`] 中的名字）；`preemption = false` 时只记账与唤醒、从不要求切换
    /// （被唤醒的任务等当前任务主动让出）。
    pub fn tick(&mut self, now: u64, preemption: bool) -> Option<&'static str> {
        self.now = now;
        let waiting = self.waiting();
        let cur = self.current;
        let running = match self.tasks[cur].as_mut() {
            Some(t) if cur != BOOT_SLOT && t.state == TaskState::Running => Some(&mut t.sched),
            _ => None,
        };
        self.policy.on_tick(running, waiting);
        self.slice_used = self.slice_used.saturating_add(1);
        self.charge_groups(cur);
        self.charge_watchdog(cur, now);

        let mut cause = None;
        for i in 1..N {
            let due = matches!(self.tasks[i].as_ref(), Some(t) if t.state == TaskState::Blocked && t.wake_at.is_some_and(|w| w <= now));
            if due && self.make_runnable(i) {
                cause = Some(Cause::WAKE);
            }
        }
        if cause.is_none() && self.tasks[cur].as_ref().is_some_and(|t| cur != BOOT_SLOT && t.state == TaskState::Running && !self.eligible(t)) {
            cause = Some(Cause::THROTTLE);
        }
        if cause.is_none() {
            let cur_entity = match self.tasks[cur].as_ref() {
                Some(t) if cur != BOOT_SLOT && t.state == TaskState::Running => Some(&t.sched),
                _ => None,
            };
            cause = self.policy.should_preempt(cur_entity, self.slice_used, self.slice_quantum, self.waiting()).map(Cause::of);
        }
        if preemption {
            cause
        } else {
            None
        }
    }

    /// 准备一次切换：更新状态、选出下一个任务、记账、通知观察者。
    ///
    /// `cause == Cause::YIELD`（主动让出）时先在**其他**任务中选：选出的不低于自己的档位（或是最低份额补给）
    /// 才切换，否则继续运行自己——让出不应把处理器交给更低档的任务，也不应因为自己用量少就选回自己。
    /// 其他原因让策略在全部可运行任务（含自己）中选。没有可运行的工作任务时选择引导线程。
    ///
    /// 返回 `Some(plan)` 表示调用者必须**立即**执行 `switch_context(plan.old, plan.new)`；
    /// 返回 `None` 表示无需切换（下一个就是自己）。
    pub fn prepare_switch(&mut self, cause: &'static str) -> Option<SwitchPlan> {
        let prev = self.current;
        let prev_runnable = match self.tasks[prev].as_mut() {
            Some(t) if t.state == TaskState::Running => {
                t.state = TaskState::Runnable;
                prev != BOOT_SLOT
            }
            _ => false,
        };
        let yielding = cause == Cause::YIELD;
        if Cause::voluntary(cause) {
            let wd = self.watchdog;
            if let Some(t) = self.tasks[prev].as_mut() {
                wd.yielded(&mut t.streak);
            }
        }

        let choice = {
            let tasks = &self.tasks;
            let groups = &self.groups;
            let runnable = |skip_prev: bool| {
                tasks.iter().enumerate().skip(1).filter_map(move |(i, t)| match t {
                    Some(t) if t.state == TaskState::Runnable && !(skip_prev && i == prev) && eligible_in(groups, t) => Some((i, &t.sched)),
                    _ => None,
                })
            };
            let mut it = runnable(yielding);
            let mut c = self.policy.choose(&mut it);
            if yielding && prev_runnable {
                let prev_qos = tasks[prev].as_ref().map(|t| t.sched.qos);
                let worse = |slot: usize| match (tasks[slot].as_ref(), prev_qos) {
                    (Some(t), Some(pq)) => pq.above(t.sched.qos),
                    _ => false,
                };
                if c.is_none_or(|ch| !ch.rescued && worse(ch.slot)) {
                    let mut only_prev = runnable(false).filter(|(i, _)| *i == prev);
                    c = self.policy.choose(&mut only_prev);
                }
            }
            c
        };

        let next = match choice {
            Some(c) => {
                self.slice_quantum = c.quantum.max(1);
                c.slot
            }
            None => {
                self.slice_quantum = 1;
                BOOT_SLOT
            }
        };
        self.slice_used = 0;
        let now = self.now;
        if let Some(t) = self.tasks[next].as_mut() {
            t.state = TaskState::Running;
            if next != BOOT_SLOT {
                self.policy.dispatched(&mut t.sched);
                if let Some(w) = t.woken_at.take() {
                    self.latency[t.sched.qos.index()].record(now.saturating_sub(w));
                }
            }
        }
        if next == prev {
            return None;
        }

        self.switches += 1;
        if let Some(observer) = self.observer {
            observer(&SwitchEvent {
                from: self.tasks[prev].as_ref().map(|t| t.name).unwrap_or("?"),
                to: self.tasks[next].as_ref().map(|t| t.name).unwrap_or("?"),
                seq: self.switches,
                cause,
            });
        }
        self.current = next;

        let next_space = self.tasks[next].as_ref().and_then(|t| t.space);
        let next_stack_top = if next == BOOT_SLOT { None } else { Some(self.stacks.top(next)) };
        let old: *mut TaskContext = &mut self.tasks[prev].as_mut()?.context;
        let new: *const TaskContext = &self.tasks[next].as_ref()?.context;
        Some(SwitchPlan { old, new, next_stack_top, next_space })
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
        let slot = self.groups.iter().position(|g| g.is_none()).ok_or(GroupError::NoFreeGroup)?;
        let gen = self.group_gen[slot];
        self.group_gen[slot] = gen.wrapping_add(1);
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
        let ran_group = match self.tasks[cur].as_ref() {
            Some(t) if cur != BOOT_SLOT && t.state == TaskState::Running => t.cpu_group,
            _ => None,
        };
        let mut wants = [false; N];
        for t in self.tasks.iter().skip(1).flatten() {
            if let (Some(g), TaskState::Runnable | TaskState::Running) = (t.cpu_group, t.state) {
                wants[g] = true;
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
        if cur == BOOT_SLOT {
            return;
        }
        let wd = self.watchdog;
        let Some(t) = self.tasks[cur].as_mut().filter(|t| t.state == TaskState::Running) else { return };
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
        self.tasks.iter().flatten().find(|t| t.id == id).map(|t| t.sched.cpu_ticks)
    }
}

/// 任务 `t` 能否被选中（见 [`Scheduler::eligible`]）；独立成函数以便在借用任务表时同时借用组表。
fn eligible_in<const N: usize>(groups: &[Option<CpuGroup>; N], t: &Task) -> bool {
    match t.cpu_group {
        None => true,
        Some(g) => t.sched.qos != t.base_qos || groups[g].as_ref().is_none_or(|grp| grp.limit.eligible()),
    }
}
