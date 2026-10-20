//! 实时任务的预算、周期与准入控制（POL-4 的第一块）。
//! Real-time quota, period and admission control (first slice of POL-4).
//!
//! # 职责
//! 纯算术与状态机：一份预算/周期声明能不能被接纳、运行中预算耗尽怎么办、
//! 下一个周期何时补充。不碰调度器、不创建任务，因此可在宿主上把边界跑遍。
//!
//! # 为什么先做准入
//! 实时任务失控的根源不是"优先级不够高"，而是**总利用率超过 1**：
//! 一旦所有 RT 任务加起来跑不完，任何调度算法都只能选择"谁错过截止期"。
//! 所以在创建之前拒绝，比事后补救诚实得多。
//!
//! # 边界
//! * 不使用堆分配：在册表的存储由内核在**启动期**按配置容量分配后经 [`RtSet::install`] 交进来，
//!   安装之前容量为 0，准入一律返回 [`RtError::Full`]；
//! * 只做预算记账与准入，不做实际抢占（由调度器的 RT 类接入）。

pub use crate::capacity::InstallError;

/// 默认准入上限：总利用率不得超过 90%（留出中断与内核开销）。
pub const DEFAULT_UTILISATION_PERMILLE: u32 = 900;

/// 准入或记账失败的原因。
/// Admission or accounting failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtError {
    /// 预算或周期为 0，或预算大于周期。
    BadShape,
    /// 任务 ID 重复。
    Duplicate,
    /// 在册任务已满。
    Full,
    /// 加入后总利用率会超过上限。
    OverUtilised,
    /// 任务不存在。
    Unknown,
    /// 当前 Profile 没有声明实时能力。
    NotPermitted,
}

impl RtError {
    /// 稳定文本名。
    pub const fn as_str(self) -> &'static str {
        match self {
            RtError::BadShape => "bad_shape",
            RtError::Duplicate => "duplicate",
            RtError::Full => "full",
            RtError::OverUtilised => "over_utilised",
            RtError::Unknown => "unknown",
            RtError::NotPermitted => "not_permitted",
        }
    }
}

/// 一次记账的结果。
/// Result of charging runtime to a task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charge {
    /// 仍在预算内。
    Within,
    /// 本次用尽预算，任务应被节流到下一个周期。
    Exhausted,
}

/// 一个实时任务的预算/周期声明。
/// One real-time task's quota and period.
#[derive(Debug, Clone, Copy)]
pub struct RtTask {
    /// 任务 ID。
    pub id: u32,
    /// 每周期的运行预算（tick）。
    pub quota: u32,
    /// 周期（tick）。
    pub period: u32,
    /// 本周期剩余预算。
    pub remaining: u32,
    /// 下一个周期的起点（tick）。
    pub next_period: u64,
    /// 被节流的次数（诊断用）。
    pub throttles: u32,
}

/// 实时任务在册表（容量在启动期由 [`RtSet::install`] 决定）。
/// Real-time task table whose capacity is fixed at boot.
#[derive(Debug)]
pub struct RtSet {
    tasks: &'static mut [Option<RtTask>],
    limit_permille: u32,
}

impl RtSet {
    /// 用给定准入上限构造尚未安装存储的空表（容量 0）。
    pub const fn new(limit_permille: u32) -> Self {
        Self { tasks: &mut [], limit_permille }
    }

    /// 安装在册表存储（只能一次；必须全部为空）。被拒时表保持为空。
    /// Install the boot-time storage (once; all entries must be empty).
    pub fn install(&mut self, storage: &'static mut [Option<RtTask>]) -> Result<usize, InstallError> {
        if !self.tasks.is_empty() {
            return Err(InstallError::AlreadyInstalled);
        }
        if storage.is_empty() {
            return Err(InstallError::Empty);
        }
        if storage.iter().any(Option::is_some) {
            return Err(InstallError::NotVacant);
        }
        self.tasks = storage;
        Ok(self.tasks.len())
    }

    /// 容量（安装之前为 0）。
    pub fn capacity(&self) -> usize {
        self.tasks.len()
    }

    /// 宿主测试用：泄漏一份容量为 `n` 的存储并安装。
    #[cfg(test)]
    pub(crate) fn for_test(limit_permille: u32, n: usize) -> Self {
        let mut set = Self::new(limit_permille);
        set.install(Box::leak(vec![None; n].into_boxed_slice())).expect("测试存储应可安装");
        set
    }

    /// 准入上限（千分比）。
    pub const fn limit_permille(&self) -> u32 {
        self.limit_permille
    }

    /// 当前总利用率（千分比，向上取整，宁可多算一点）。
    /// 为什么向上取整：准入判定必须保守，不能因为截断把 1.001 当成 1.000。
    pub fn utilisation_permille(&self) -> u32 {
        let mut total = 0u32;
        for task in self.tasks.iter().flatten() {
            total += (task.quota as u64 * 1000).div_ceil(task.period as u64) as u32;
        }
        total
    }

    /// 加入一个实时任务。
    ///
    /// 拒绝条件：预算为 0、预算大于周期、ID 重复、表满、总利用率超上限。
    /// English: admit a task; refuse anything that would break the utilisation bound.
    pub fn admit(&mut self, id: u32, quota: u32, period: u32, now: u64) -> Result<(), RtError> {
        if quota == 0 || period == 0 || quota > period {
            return Err(RtError::BadShape);
        }
        if self.tasks.iter().flatten().any(|t| t.id == id) {
            return Err(RtError::Duplicate);
        }
        let Some(slot) = self.tasks.iter().position(|t| t.is_none()) else {
            return Err(RtError::Full);
        };
        let added = (quota as u64 * 1000).div_ceil(period as u64) as u32;
        if self.utilisation_permille() + added > self.limit_permille {
            return Err(RtError::OverUtilised);
        }
        self.tasks[slot] = Some(RtTask {
            id,
            quota,
            period,
            remaining: quota,
            next_period: now + period as u64,
            throttles: 0,
        });
        Ok(())
    }

    /// 退出一个实时任务，释放它的利用率额度。
    pub fn release(&mut self, id: u32) -> Result<(), RtError> {
        let Some(slot) = self.slot_of(id) else {
            return Err(RtError::Unknown);
        };
        self.tasks[slot] = None;
        Ok(())
    }

    /// 记账：任务运行了 `ticks` 个 tick。
    ///
    /// 预算用完时返回 [`Charge::Exhausted`] 并把剩余量归零——
    /// 调用方据此把任务节流到下一个周期，而不是让它继续跑。
    /// English: charge runtime; exhausting the quota returns `Exhausted`.
    pub fn charge(&mut self, id: u32, ticks: u32) -> Result<Charge, RtError> {
        let slot = self.slot_of(id).ok_or(RtError::Unknown)?;
        let task = self.tasks[slot].as_mut().expect("slot_of 只返回已占用的槽位");
        if ticks >= task.remaining {
            task.remaining = 0;
            task.throttles += 1;
            return Ok(Charge::Exhausted);
        }
        task.remaining -= ticks;
        Ok(Charge::Within)
    }

    /// 周期补充：到期的任务重置剩余预算。
    ///
    /// 返回本次被补充的任务数。补偿策略是"重置到预算"而不是"累加"，
    /// 避免长时间被节流后攒出一大笔预算、随后长时间独占处理器。
    /// English: replenish expired periods; reset (never accumulate) the quota.
    pub fn replenish(&mut self, now: u64) -> usize {
        let mut count = 0;
        for task in self.tasks.iter_mut().flatten() {
            while now >= task.next_period {
                task.remaining = task.quota;
                task.next_period += task.period as u64;
                count += 1;
            }
        }
        count
    }

    /// 某个任务的快照。
    pub fn get(&self, id: u32) -> Option<RtTask> {
        self.tasks.iter().flatten().copied().find(|t| t.id == id)
    }

    /// 在册任务数。
    pub fn len(&self) -> usize {
        self.tasks.iter().flatten().count()
    }

    /// 按最早截止期选出一个可运行的实时任务（EDF）。
    ///
    /// 规则：
    /// * 只看**本周期还有预算**的任务（预算为 0 的已被节流，不参与选择）；
    /// * 截止期取 `next_period`（本周期结束时刻），先到先跑；
    /// * 截止期相同则按任务 ID 升序，保证结果确定、可复现。
    ///
    /// 为什么要有 EDF：固定优先级在「周期短但优先级低」的任务上会持续错过截止期，
    /// EDF 在总利用率 ≤ 1 时可证明不漏；两者都保留，由 Profile 选择。
    /// English: pick the earliest-deadline runnable real-time task (EDF).
    pub fn pick_edf(&self, _now: u64) -> Option<u32> {
        self.tasks
            .iter()
            .flatten()
            .filter(|t| t.remaining > 0)
            .min_by_key(|t| (t.next_period, t.id))
            .map(|t| t.id)
    }

    /// 按固定优先级选出一个可运行的实时任务。
    ///
    /// 优先级由**预算占周期的比例**决定（预算越大越优先），相同则 ID 升序。
    /// 这是占位语义：真正的外部优先级在接入调度器时由调用方给出。
    /// English: pick by quota ratio as a stand-in for a fixed priority.
    pub fn pick_priority(&self) -> Option<u32> {
        self.tasks
            .iter()
            .flatten()
            .filter(|t| t.remaining > 0)
            .max_by_key(|t| {
                let ratio = (t.quota as u64) * 1_000_000 / t.period as u64;
                (ratio, core::cmp::Reverse(t.id))
            })
            .map(|t| t.id)
    }

    fn slot_of(&self, id: u32) -> Option<usize> {
        self.tasks.iter().position(|t| t.is_some_and(|task| task.id == id))
    }
}

#[cfg(test)]
mod tests;
