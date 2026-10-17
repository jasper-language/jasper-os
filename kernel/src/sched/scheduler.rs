//! 调度机制（与策略无关的核心）：任务表、状态迁移、切换准备、切换事件通知。
//!
//! 职责：
//! * 维护固定槽位的任务表（槽位 0 = 引导线程，不参与策略选择）
//! * 把「选谁」委托给策略 `P: SchedPolicy`（Strategy 模式）
//! * 把「切换发生了」通知给观察者（Observer 模式，函数指针，零分配），
//!   调度器本身因此不依赖串口/日志模块
//! * **不直接执行**栈切换：`prepare_switch` 只返回新旧上下文的裸指针，
//!   由门面层（`mod.rs`）在放掉所有借用之后调用 `switch_context`。
//!   这样 `&mut Scheduler` 永远不会跨越一次栈切换存活（另一个任务会再次借用它）。
//!
//! 可复用性：`Scheduler<P, N>` 不含任何全局状态，可在宿主测试或多实例场景中直接构造。

use crate::arch::TaskContext;
use crate::task::{Task, TaskId, TaskState};

use super::policy::SchedPolicy;
use super::stack::StackPool;

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
    /// 切换原因（"yield" / "tick" / "exit"）。
    pub cause: &'static str,
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
    /// 工作槽位已满。
    NoFreeSlot,
}

/// 调度机制本体。`N` 为槽位总数（含引导线程）。
pub struct Scheduler<P: SchedPolicy, const N: usize> {
    tasks: [Option<Task>; N],
    stacks: StackPool<N>,
    policy: P,
    current: usize,
    switches: u64,
    observer: Option<SwitchObserver>,
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

    /// 当前策略的时间片（tick 数）。
    pub fn quantum_ticks(&self) -> u32 {
        self.policy.quantum_ticks()
    }

    /// 新建任务：占用一个空工作槽位，伪造首次切入帧使其从 `trampoline` 开始执行。
    ///
    /// `trampoline` 由门面层提供：它读取当前任务的 `entry` 并执行，返回后负责退出。
    pub fn spawn(
        &mut self,
        id: TaskId,
        name: &'static str,
        entry: fn(),
        trampoline: extern "C" fn() -> !,
    ) -> Result<usize, SpawnError> {
        // 空槽位或「已退出且不是当前任务」的槽位都可复用：
        // 已退出任务一旦被切走，就再也不会在它的栈上执行，栈与 TCB 可以安全覆盖。
        let current = self.current;
        let slot = (1..N)
            .find(|&i| match self.tasks[i].as_ref() {
                None => true,
                Some(t) => t.state == TaskState::Exited && i != current,
            })
            .ok_or(SpawnError::NoFreeSlot)?;
        let mut task = Task::new(id, name);
        task.entry = Some(entry);
        // SAFETY：该槽位为空，没有任何任务在这块栈上运行。
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

    /// 把当前任务标记为已退出（槽位在它被切走之后才可被 `spawn` 复用）。
    pub fn mark_current_exited(&mut self) {
        if let Some(t) = self.tasks[self.current].as_mut() {
            t.state = TaskState::Exited;
        }
    }

    /// 准备一次让出：更新状态、选出下一个任务、通知观察者。
    ///
    /// 返回 `Some((old, new))` 表示调用者必须**立即**执行 `switch_context(old, new)`；
    /// 返回 `None` 表示无需切换（下一个就是自己）。
    /// 没有可运行的工作任务时选择引导线程。
    pub fn prepare_switch(&mut self, cause: &'static str) -> Option<SwitchPlan> {
        let prev = self.current;
        if let Some(t) = self.tasks[prev].as_mut() {
            if t.state == TaskState::Running {
                t.state = TaskState::Runnable;
            }
        }

        let tasks = &self.tasks;
        let is_runnable = |slot: usize| matches!(tasks[slot].as_ref(), Some(t) if t.state == TaskState::Runnable);
        let next = self.policy.pick_next(prev, N, &is_runnable).unwrap_or(BOOT_SLOT);

        if let Some(t) = self.tasks[next].as_mut() {
            t.state = TaskState::Running;
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
}
