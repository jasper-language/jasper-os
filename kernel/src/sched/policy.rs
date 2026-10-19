//! 调度策略的构建期选择点（Strategy 模式）。
//! Build-time selection point for the scheduling policy.
//!
//! 职责：只决定内核用**哪一个**策略实现；策略本身（「下一个是谁、给多长时间片、要不要抢占」以及
//! 入队 / 出队 / 让出 / 迁移 / 预算钩子）是纯决策，位于与硬件无关的 `kernel_core::sched`，能在宿主上
//! 做确定性模拟测试。机制层（`scheduler.rs`）对策略泛型化，经 Core 的每核运行队列调用钩子：
//! 换策略只改本文件的 [`KernelPolicy`]，不改任务表、切换路径、时钟中断与负载均衡。
//!
//! 可选策略（构建期特性）：
//! * 默认：分时策略（QoS 四档严格优先 + 档内用量衰减 + 各档最低份额 + 后台限速）
//! * `sched-rr`：纯轮转（不分级、固定时间片；时间片取配置档里默认档位的时间片）
//!
//! 约定：槽位 0 是引导线程（空闲时的落脚点），**不交给策略选择**；策略只在工作任务中挑选。

pub use kernel_core::sched::balance::{BalanceParams, Balancer, Candidate, CoreLoad, PlaceError, Refusal};
pub use kernel_core::sched::class::{Arbiter, SchedClass, StrictOrder};
pub use kernel_core::sched::limit::{CpuLimit, CpuLimitStats, LimitError};
pub use kernel_core::sched::queue::{migrate, CoreQueue, QueueError};
pub use kernel_core::sched::watchdog::{RunStreak, Watchdog, WatchdogLog, WatchdogReport};
pub use kernel_core::sched::{
    inherit, qos_change_allowed, Choice, ClassMask, Dequeue, Enqueue, LatencyHistogram, Preempt, Qos, QosParams, Requeue, SchedPolicy, QOS_CLASSES,
};

/// 内核采用的调度策略：分时策略（默认构建）。
#[cfg(not(feature = "sched-rr"))]
pub type KernelPolicy = kernel_core::sched::TimeSharePolicy;

/// 内核采用的调度策略：纯轮转（`sched-rr` 构建）。
#[cfg(feature = "sched-rr")]
pub type KernelPolicy = kernel_core::sched::RoundRobin;

/// 构造内核策略（`const`，用于静态初始化）。参数取生效配置档。
#[cfg(not(feature = "sched-rr"))]
pub const fn kernel_policy() -> KernelPolicy {
    kernel_core::sched::TimeSharePolicy::new(crate::config::ACTIVE.sched.qos)
}

/// 构造内核策略（`const`，用于静态初始化）。时间片取配置档里默认档位（用户发起）的时间片。
#[cfg(feature = "sched-rr")]
pub const fn kernel_policy() -> KernelPolicy {
    kernel_core::sched::RoundRobin::new(crate::config::ACTIVE.sched.qos.quantum[Qos::UserInitiated.index()])
}

/// 策略私有的每实体状态（任务表据此定长保存，不需要堆）。
pub type EntityState = <KernelPolicy as SchedPolicy>::State;

/// 任务表里的调度属性。
pub type SchedEntity = kernel_core::sched::SchedEntity<EntityState>;

/// 新任务的调度属性（`const`：任务表可静态初始化）。
pub const fn new_entity(qos: Qos) -> SchedEntity {
    SchedEntity::new(qos, <KernelPolicy as SchedPolicy>::INITIAL)
}

/// 内核的类别仲裁器：构建期只选一个策略，仲裁器只接纳该策略的类别（启动时校验）。
pub const KERNEL_ARBITER: StrictOrder = StrictOrder::single(<KernelPolicy as SchedPolicy>::CLASS);

/// 看门狗阈值（tick，取自配置档）：连续占用处理器这么久而不主动让出的任务被记录（两个配置档下均约 0.5 秒）。
pub const WATCHDOG_THRESHOLD: u32 = crate::config::ACTIVE.sched.watchdog_ticks;
/// CPU 组的默认桶容量（tick，取自配置档）：允许的短突发长度。
pub const CPU_BURST_TICKS: u32 = crate::config::ACTIVE.sched.cpu_burst_ticks;
