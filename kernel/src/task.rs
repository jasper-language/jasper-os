//! 任务模型 —— M1.3：真 TCB（上下文 + 入口），栈与切换见 `sched.rs` / `context.rs`。
//!
//! 对应 Java 原型的 `Task`/`TaskId`/`TaskState`；比原型多一个 `Running` 态。

/// Opaque task identifier (newtype over the prototype's integer id).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaskId(pub u64);

/// Runnable states. `Running` is tracked even though the Java prototype only
/// had 3 states (spec notes this as a prototype simplification).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Runnable,
    Running,
    Blocked,
    Exited,
}

/// 任务控制块：`context` 保存切走时的栈指针（callee-saved 寄存器压在该任务自己的栈上），
/// `entry` 是任务入口（槽位 0 的引导线程没有入口），`space` 是任务运行时应处于的地址空间
/// （`None` = 内核地址空间；调度器在切换任务时据此切换地址空间）。
pub struct Task {
    pub id: TaskId,
    pub name: &'static str,
    pub state: TaskState,
    pub context: crate::arch::TaskContext,
    pub entry: Option<fn()>,
    pub space: Option<crate::arch::SpaceRoot>,
}

impl Task {
    pub const fn new(id: TaskId, name: &'static str) -> Self {
        Task {
            id,
            name,
            state: TaskState::Runnable,
            context: crate::arch::EMPTY_CONTEXT,
            entry: None,
            space: None,
        }
    }
}
