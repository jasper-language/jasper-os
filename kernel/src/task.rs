//! 任务模型：任务控制块（上下文 + 入口 + 地址空间 + 调度属性）。栈与切换见 `sched/`。
//!
//! 调度属性（[`SchedEntity`]：有效 QoS 档位、近期用量……）由策略读写；睡眠与唤醒延迟记账、
//! 自身档位与等待关系（优先级继承）由调度机制维护。

use crate::sched::policy::{Qos, SchedEntity};

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
    /// 正在处理器上运行（任一时刻恰有一个）。
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
}

impl Task {
    /// 新任务：可运行、默认档位「用户发起」、没有 QoS 上限。
    pub const fn new(id: TaskId, name: &'static str) -> Self {
        Task {
            id,
            name,
            state: TaskState::Runnable,
            context: crate::arch::EMPTY_CONTEXT,
            entry: None,
            space: None,
            syscalls: crate::syscall::SyscallSet::EMPTY,
            sched: SchedEntity::new(Qos::UserInitiated),
            base_qos: Qos::UserInitiated,
            waits_for: None,
            wait_key: 0,
            wait_seq: 0,
            qos_ceiling: None,
            wake_at: None,
            woken_at: None,
        }
    }
}
