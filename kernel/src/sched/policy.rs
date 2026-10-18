//! 调度策略的选择点（Strategy 模式）。
//!
//! 职责：只决定内核用**哪一个**策略实现；策略本身（「下一个是谁、给多长时间片、要不要抢占」）
//! 是纯决策，位于与硬件无关的 `kernel_core::sched`，因此能在宿主上做确定性模拟测试。
//! 机制层（`scheduler.rs`）对 [`SchedPolicy`] 泛型化：换策略只改本文件的 [`KernelPolicy`]，
//! 不需要改任务表、切换路径或时钟中断处理。
//!
//! 约定：槽位 0 是引导线程（空闲时的落脚点），**不交给策略选择**；策略只在工作任务中挑选。

pub use kernel_core::sched::limit::{CpuLimit, CpuLimitStats, LimitError};
pub use kernel_core::sched::watchdog::{RunStreak, Watchdog, WatchdogLog, WatchdogReport};
pub use kernel_core::sched::{inherit, qos_change_allowed, Choice, ClassMask, LatencyHistogram, Preempt, Qos, QosParams, QosPolicy, SchedEntity, SchedPolicy, QOS_CLASSES};

/// 内核采用的调度策略：QoS 分级（四档严格优先 + 档内用量衰减 + 各档最低份额 + 后台限速）。
pub type KernelPolicy = QosPolicy;

/// 构造内核策略（`const`，用于静态初始化）。参数取默认配置档。
pub const fn kernel_policy() -> KernelPolicy {
    QosPolicy::new(QosParams::DEFAULT)
}

/// 看门狗阈值（tick）：连续占用处理器这么久而不主动让出的任务被记录（100 Hz 下为 0.5 秒）。
pub const WATCHDOG_THRESHOLD: u32 = 50;
/// CPU 组的默认桶容量（tick）：允许的短突发长度。
pub const CPU_BURST_TICKS: u32 = 4;
