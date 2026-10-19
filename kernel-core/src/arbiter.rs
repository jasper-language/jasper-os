//! 调度类别仲裁：同一实体内同时存在分时、批处理、实时线程时，决定下一个 tick 归谁。
//! Class arbitration: decide which scheduling class gets the next tick.
//!
//! # 为什么要单独一个仲裁器
//! 各策略各自"公平"不等于整体公平：实时线程按预算跑满后仍可能占住处理器，
//! 批处理在交互负载下被无限推迟，最终表现为"某类永远轮不到"。
//! 仲裁器只回答一个问题：**此刻该跑哪一类**，并且保证三条硬约束：
//! 1. 实时类不超过它预留的份额（超了就得让出，不能挤占其他类）；
//! 2. 批处理有最低份额，长时间没被选中时必须被补偿（避免饿死）；
//! 3. 判定是纯函数：同样的输入必然得到同样的结论，便于复现与测试。
//!
//! # 边界
//! 纯算术 + 状态，不创建任务、不碰队列、不感知处理器数量；真正的派发由调度器完成。

/// 调度类别。
/// Scheduling classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Class {
    /// 实时：有截止期与预算，优先级最高但受预留份额约束。
    RealTime = 0,
    /// 交互：直接响应用户操作。
    Interactive = 1,
    /// 批处理：只用剩余容量，但有最低份额。
    Batch = 2,
}

impl Class {
    /// 稳定文本名。
    pub const fn as_str(self) -> &'static str {
        match self {
            Class::RealTime => "realtime",
            Class::Interactive => "interactive",
            Class::Batch => "batch",
        }
    }
}

/// 仲裁参数。
/// Arbitration parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArbiterParams {
    /// 实时类在窗口内最多可占的千分比（预留上限）。
    pub rt_reserve_permille: u32,
    /// 批处理类在窗口内应拿到的最低千分比。
    pub batch_floor_permille: u32,
    /// 批处理连续多少个 tick 没被选中就强制补偿一次。
    pub batch_aging_ticks: u32,
}

impl ArbiterParams {
    /// 默认：实时最多 300‰、批处理保底 100‰、连续 100 tick 未运行即补偿。
    pub const DEFAULT: ArbiterParams = ArbiterParams {
        rt_reserve_permille: 300,
        batch_floor_permille: 100,
        batch_aging_ticks: 100,
    };
}

/// 当前各类是否有人可运行。
/// Which classes are currently runnable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Demand {
    /// 有实时任务可运行。
    pub realtime: bool,
    /// 有交互任务可运行。
    pub interactive: bool,
    /// 有批处理任务可运行。
    pub batch: bool,
}

/// 一个窗口内的用量记账（千分比，按 tick 累计）。
/// Per-window usage accounting in permille.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Window {
    /// 窗口内已过的 tick 数。
    pub ticks: u32,
    /// 实时类已用 tick。
    pub realtime: u32,
    /// 交互类已用 tick。
    pub interactive: u32,
    /// 批处理类已用 tick。
    pub batch: u32,
}

impl Window {
    /// 某类在窗口内的占比（千分比）；窗口为空时返回 0。
    pub fn share_permille(&self, class: Class) -> u32 {
        if self.ticks == 0 {
            return 0;
        }
        let used = match class {
            Class::RealTime => self.realtime,
            Class::Interactive => self.interactive,
            Class::Batch => self.batch,
        };
        (used as u64 * 1000 / self.ticks as u64) as u32
    }

    /// 记账一个 tick。
    pub fn charge(&mut self, class: Class) {
        self.ticks += 1;
        match class {
            Class::RealTime => self.realtime += 1,
            Class::Interactive => self.interactive += 1,
            Class::Batch => self.batch += 1,
        }
    }
}

/// 仲裁器状态。
/// Arbiter state.
#[derive(Debug, Clone, Copy)]
pub struct Arbiter {
    params: ArbiterParams,
    /// 距批处理上次被选中过了多少 tick。
    batch_wait: u32,
}

impl Arbiter {
    /// 用给定参数构造。
    pub const fn new(params: ArbiterParams) -> Self {
        Self { params, batch_wait: 0 }
    }

    /// 参数。
    pub const fn params(&self) -> ArbiterParams {
        self.params
    }

    /// 批处理已等待的 tick 数（诊断）。
    pub const fn batch_wait(&self) -> u32 {
        self.batch_wait
    }

    /// 选出下一个 tick 归属的类别；没有任何类的需求时返回 `None`。
    ///
    /// 判定顺序（每一步都写死了理由，便于复核）：
    /// 1. 批处理饥饿补偿：可运行且等待超过阈值 ⇒ 必须给它；
    /// 2. 实时：可运行且本窗口用量仍低于预留 ⇒ 给它（截止期优先）；
    /// 3. 交互：可运行 ⇒ 给它（低延迟优先）；
    /// 4. 批处理：可运行 ⇒ 兜底给空闲容量；
    /// 5. 否则 `None`（空闲）。
    ///
    /// English: pick the class for the next tick; deterministic and starvation-free.
    pub fn pick(&mut self, demand: Demand, window: &Window) -> Option<Class> {
        let batch_starved =
            demand.batch && self.batch_wait >= self.params.batch_aging_ticks && self.params.batch_aging_ticks > 0;
        let choice = if batch_starved {
            Some(Class::Batch)
        } else if demand.realtime && window.share_permille(Class::RealTime) < self.params.rt_reserve_permille {
            Some(Class::RealTime)
        } else if demand.interactive {
            Some(Class::Interactive)
        } else if demand.batch {
            Some(Class::Batch)
        } else if demand.realtime {
            // 实时用量已到预留上限，但没有别的类可运行：仍让它跑，避免处理器空转。
            Some(Class::RealTime)
        } else {
            None
        };
        match choice {
            Some(Class::Batch) => self.batch_wait = 0,
            Some(_) if demand.batch => self.batch_wait = self.batch_wait.saturating_add(1),
            _ => {}
        }
        choice
    }

    /// 批处理保底份额是否被满足（诊断用）。
    pub fn batch_floor_met(&self, window: &Window) -> bool {
        window.ticks == 0 || window.share_permille(Class::Batch) >= self.params.batch_floor_permille
    }
}

#[cfg(test)]
mod tests;
