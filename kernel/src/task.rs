//! 任务模型：任务控制块（上下文 + 入口 + 地址空间 + 调度属性）。栈与切换见 `sched/`。
//!
//! 调度属性（[`SchedEntity`]：有效 QoS 档位、所在运行队列与策略私有状态）经每核运行队列由策略读写；睡眠与唤醒延迟记账、
//! 自身档位与等待关系（优先级继承）由调度机制维护。

use kernel_core::smp::CpuSet;

use crate::sched::policy::{new_entity, Qos, RunStreak, SchedEntity};

/// 不透明的任务标识。
/// Opaque task identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaskId(pub u64);

/// 任务状态。
/// Task states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    /// 可运行，等待被选中。
    Runnable,
    /// 正在某个处理器上运行（每个处理器任一时刻至多一个）。
    Running,
    /// 睡眠：等到 `Task::wake_at` 指定的 tick（或被显式唤醒）才重新可运行。
    Blocked,
    /// 已退出：槽位在它被切走之后可复用。
    Exited,
}

/// 任务控制块：`context` 保存切走时的栈指针（callee-saved 寄存器压在该任务自己的栈上），
/// `entry` 是任务入口（槽位 0 的引导线程没有入口），`space` 是任务运行时应处于的地址空间
/// （`None` = 内核地址空间；调度器在切换任务时据此切换地址空间）。
pub struct Task {
    /// Author: chatgpt。事件等待轮次由原调度器锁串行化；任何唤醒均消费旧登记。
    pub event_wait: kernel_core::event_wait::Registration,
    // Author: chatgpt. Diagnostic only, serialized by the scheduler lock.
    #[cfg(feature = "krn2-observe")]
    pub raw_wake: kernel_core::raw_timing::WakePair,
    #[cfg(feature = "krn2-observe")]
    pub raw_wake_round: Option<u64>,
    /// Exact absolute ns deadline retained across Runnable until the resumed
    /// execution hook consumes it. Diagnostic only; early explicit wakes do
    /// not populate this field.
    #[cfg(feature = "krn2-observe")]
    pub raw_deadline_start: Option<kernel_core::raw_timing::Endpoint>,
    /// 任务标识。
    pub id: TaskId,
    /// 任务名（诊断输出）。
    pub name: &'static str,
    /// 当前状态。
    pub state: TaskState,
    /// 切走时保存的上下文。
    pub context: crate::arch::TaskContext,
    /// 入口函数（引导线程为 `None`）。
    pub entry: Option<fn()>,
    /// 运行时所在地址空间（`None` = 内核地址空间）。
    pub space: Option<crate::arch::SpaceRoot>,
    /// 该任务可以发起的系统调用集合（统一权限检查的依据；内核任务为空集）。
    pub syscalls: crate::syscall::SyscallSet,
    /// 调度属性（**有效** QoS 档位、近期用量、累计运行 tick）。有效档位 = 自身档位与等待者借来档位中的最高者。
    pub sched: SchedEntity,
    /// 自身 QoS 档位（经系统调用设置、被新任务继承的那一个；不含借来的档位）。
    pub base_qos: Qos,
    /// 正在等的持有者所在槽位（等锁、等任务退出时有值；优先级继承沿它传播）。
    pub waits_for: Option<usize>,
    /// Monotonic notification round for cross-CPU effective-priority changes.
    pub pi_round: u64,
    /// 等待对象的标识（锁的地址或「等退出」标记；`waits_for` 为 `None` 时无意义）。
    pub wait_key: u64,
    /// 开始等待的序号（同档等待者按先来后到交接）。
    pub wait_seq: u64,
    /// QoS 上限：创建方授予的「可提升到的最高档位」（`None` = 只能降不能升）。
    pub qos_ceiling: Option<Qos>,
    /// 睡眠到的 tick（`state == Blocked` 时有效；`None` = 只能被显式唤醒）。
    pub wake_at: Option<u64>,
    /// 被唤醒的 tick（尚未运行）；被选中时据此记录唤醒延迟。
    pub woken_at: Option<u64>,
    /// 所属 CPU 组的槽位（受该组的 CPU 上限约束；`None` = 不受限）。
    pub cpu_group: Option<usize>,
    /// 自上次主动放弃处理器以来连续占用的 tick（看门狗依据）。
    pub streak: RunStreak,
    /// 所在运行队列的处理器下标（只会被该处理器选中；负载均衡改写它即完成迁移）。
    pub home: usize,
    /// 亲和集合：允许运行的处理器（硬约束；`home` 总在其中）。
    pub affinity: CpuSet,
    /// 上次被换下的时刻（tick；迁移代价据此判断缓存是否仍热）。
    pub last_ran: Option<u64>,
    /// 正占用它的处理器：被选中时置位，换下它的那次切换**完成保存之后**才清除；
    /// 置位期间其他处理器不得选中它（否则会恢复一份尚未保存完的上下文），槽位也不得复用。
    pub on_cpu: Option<usize>,
    /// 曾经运行过它的处理器集合（诊断：亲和与迁移的验收依据）。
    pub ran_on: CpuSet,
    /// 实时预算（tick）；`rt_period == 0` 表示不是实时任务。
    /// Compatibility tick declaration; ns_budget is canonical when present.
    pub ns_budget: Option<kernel_core::ns_budget::Budget>,
    pub wake_ns: Option<u64>,
    pub rt_quota: u32,
    /// 实时周期（tick）。
    pub rt_period: u32,
    /// 本周期剩余预算。
    pub rt_remaining: u32,
    /// 本周期结束时刻（下一个截止期）。
    pub rt_next_period: u64,
}

impl Task {
    /// 新任务：可运行、默认档位「用户发起」、没有 QoS 上限、亲和集合只含引导处理器（创建方可放宽）。
    pub const fn new(id: TaskId, name: &'static str) -> Self {
        Task {
            event_wait: kernel_core::event_wait::Registration::new(),
            #[cfg(feature = "krn2-observe")]
            raw_wake: kernel_core::raw_timing::WakePair::new(),
            #[cfg(feature = "krn2-observe")]
            raw_wake_round: None,
            #[cfg(feature = "krn2-observe")]
            raw_deadline_start: None,
            id,
            name,
            state: TaskState::Runnable,
            context: crate::arch::EMPTY_CONTEXT,
            entry: None,
            space: None,
            syscalls: crate::syscall::SyscallSet::EMPTY,
            sched: new_entity(Qos::UserInitiated),
            base_qos: Qos::UserInitiated,
            waits_for: None,
            pi_round: 0,
            wait_key: 0,
            wait_seq: 0,
            qos_ceiling: None,
            wake_at: None,
            woken_at: None,
            cpu_group: None,
            streak: RunStreak::new(),
            home: 0,
            affinity: CpuSet::first(1),
            last_ran: None,
            on_cpu: None,
            ran_on: CpuSet::EMPTY,
            ns_budget: None,
            wake_ns: None,
            rt_quota: 0,
            rt_period: 0,
            rt_remaining: 0,
            rt_next_period: 0,
        }
    }
}
