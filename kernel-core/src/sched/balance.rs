//! 多核负载均衡的纯决策：新任务 / 被唤醒任务放到哪个处理器的运行队列、空闲处理器从谁那里窃取任务、
//! 忙碌处理器之间何时周期性地搬一个任务。
//! Pure multi-core balancing decisions: placement, idle stealing and periodic pulling.
//!
//! # 职责
//! 只做决定，不碰任务表：调用者把各处理器的负载快照（[`CoreLoad`]）与候选任务（[`Candidate`]）交进来，
//! 本模块返回处理器下标或槽位，或者说明为什么不搬（[`Refusal`]）。
//!
//! # 边界与原因
//! * 与指令集、锁、任务表的具体结构无关，因此能在宿主上做确定性测试；内核的调度机制层负责采样与执行。
//! * 亲和性是硬约束：任何决定都不会把任务放到它的亲和集合之外。
//! * 迁移代价用「最近运行过的任务缓存仍热」近似：刚运行过不到 `migration_cost` 个 tick 的任务，
//!   周期均衡不搬它；但处理器**空闲**时宁可付一次迁移代价也不围观——空闲窃取只是优先挑冷的任务。
//! * 交互性优先于均衡：被唤醒的任务优先去空闲处理器，其次去正在运行更低档任务的处理器（随后由调用者
//!   发出重新调度请求让它立即抢占），这样高档任务的唤醒延迟不受其他处理器负载的影响。

use crate::sched::Qos;
use crate::smp::CpuSet;

/// 一个处理器的负载快照。
/// Load snapshot of one processor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreLoad {
    /// 是否参与调度（离线处理器的快照被忽略）。
    pub online: bool,
    /// 运行队列中等待的任务数（不含正在运行的那个）。
    pub queued: u32,
    /// 正在运行的工作任务的有效档位（`None` = 空闲）。
    pub running: Option<Qos>,
}

impl CoreLoad {
    /// 离线处理器的快照。
    /// Snapshot of an offline processor.
    pub const OFFLINE: CoreLoad = CoreLoad { online: false, queued: 0, running: None };

    /// 负载数：等待数 + 正在运行的工作任务（0 或 1）。
    /// Load figure: queued tasks plus the running worker.
    pub const fn load(&self) -> u32 {
        self.queued + if self.running.is_some() { 1 } else { 0 }
    }

    /// 是否空闲（在线且没有运行工作任务、队列为空）。
    /// Whether the processor is idle.
    pub const fn idle(&self) -> bool {
        self.online && self.running.is_none() && self.queued == 0
    }
}

/// 一个可以被搬动的候选任务（调用者只交「可运行、未在任何处理器上、未被限速」的任务）。
/// A movable candidate task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    /// 调用者定义的槽位编号。
    pub slot: usize,
    /// 当前所在运行队列的处理器下标。
    pub home: usize,
    /// 亲和集合（允许运行的处理器）。
    pub affinity: CpuSet,
    /// 有效档位。
    pub qos: Qos,
    /// 上次被换下的时刻（tick；`None` = 从未运行过，缓存一定是冷的）。
    pub last_ran: Option<u64>,
}

/// 均衡参数。
/// Balancing parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BalanceParams {
    /// 迁移代价（tick）：换下不到这么久的任务视为缓存仍热，周期均衡不搬它。
    pub migration_cost: u64,
    /// 周期均衡的间隔（tick）：每个处理器每隔这么多个本地 tick 检查一次是否该拉一个任务过来。
    pub balance_interval: u64,
    /// 触发周期均衡的最小负载差（最忙处理器与本处理器的负载数之差至少为它才搬）。
    pub imbalance: u32,
}

impl BalanceParams {
    /// 默认参数：迁移代价 2 tick、每 4 tick 检查一次、负载差至少 2。
    /// Defaults: 2-tick migration cost, check every 4 ticks, imbalance of at least 2.
    pub const DEFAULT: BalanceParams = BalanceParams { migration_cost: 2, balance_interval: 4, imbalance: 2 };
}

/// 放置失败的原因。
/// Why a placement was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaceError {
    /// 亲和集合里没有在线处理器。
    NoAllowedCpu,
}

/// 不搬任务的原因（周期均衡与窃取的拒绝路径）。
/// Why no task was moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// 本处理器离线或下标越界。
    Offline,
    /// 负载差不到阈值（已经均衡）。
    Balanced,
    /// 没有亲和集合允许搬到本处理器的候选任务。
    NoCandidate,
    /// 候选任务的缓存都还热（周期均衡不付迁移代价）。
    AllHot,
}

/// 负载均衡器（Strategy：调度机制层只依赖这几个决定，换算法只换本类型）。
/// Load balancer used by the scheduling mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Balancer {
    params: BalanceParams,
}

impl Balancer {
    /// 以给定参数构造。
    /// Construct with `params`.
    pub const fn new(params: BalanceParams) -> Self {
        Balancer { params }
    }

    /// 生效参数。
    /// Effective parameters.
    pub const fn params(&self) -> BalanceParams {
        self.params
    }

    /// 任务的缓存在 `now` 时是否仍热。
    /// Whether the task's cache is still hot at `now`.
    pub fn hot(&self, last_ran: Option<u64>, now: u64) -> bool {
        last_ran.is_some_and(|t| now.saturating_sub(t) < self.params.migration_cost)
    }

    /// 本处理器的本地 tick 数 `local_ticks` 是否到了周期均衡的检查点。
    /// Whether this local tick is a periodic-balance checkpoint.
    pub const fn due(&self, local_ticks: u64) -> bool {
        self.params.balance_interval > 0 && local_ticks % self.params.balance_interval == 0
    }

    /// 为一个变为可运行的任务选运行队列。
    ///
    /// 顺序：上次所在处理器空闲 → 留在原处；否则任一空闲处理器（下标最小）；否则正在运行比它低档任务的
    /// 处理器（运行档位最低者）；否则缓存仍热且允许时留在原处；否则负载数最小者（相等时偏向原处）。
    /// 亲和集合中没有在线处理器时拒绝。
    /// Choose the run queue for a task that became runnable.
    pub fn place(
        &self,
        affinity: CpuSet,
        prev: Option<usize>,
        qos: Qos,
        last_ran: Option<u64>,
        now: u64,
        loads: &[CoreLoad],
    ) -> Result<usize, PlaceError> {
        let allowed = |c: usize| affinity.contains(c) && loads.get(c).is_some_and(|l| l.online);
        let prev = prev.filter(|&p| allowed(p));
        if let Some(p) = prev {
            if loads[p].idle() {
                return Ok(p);
            }
        }
        let cpus = || (0..loads.len()).filter(|&c| allowed(c));
        if let Some(c) = cpus().find(|&c| loads[c].idle()) {
            return Ok(c);
        }
        // 正在运行更低档任务、且队列里没有不低于它的等待者时，放过去能立即抢占（取运行档位最低者）
        let mut victim: Option<(usize, Qos)> = None;
        for c in cpus() {
            if let Some(r) = loads[c].running {
                if qos.above(r) && loads[c].queued == 0 && victim.is_none_or(|(_, v)| v.above(r)) {
                    victim = Some((c, r));
                }
            }
        }
        if let Some((c, _)) = victim {
            return Ok(c);
        }
        if let Some(p) = prev {
            if self.hot(last_ran, now) {
                return Ok(p);
            }
        }
        let mut best: Option<usize> = None;
        for c in cpus() {
            let better = match best {
                None => true,
                Some(b) => loads[c].load() < loads[b].load(),
            };
            if better {
                best = Some(c);
            }
        }
        match (best, prev) {
            (Some(b), Some(p)) if loads[p].load() == loads[b].load() => Ok(p),
            (Some(b), _) => Ok(b),
            (None, _) => Err(PlaceError::NoAllowedCpu),
        }
    }

    /// 空闲处理器 `thief` 窃取一个任务：只考虑亲和集合含 `thief` 的候选；先挑最高档，
    /// 同档挑所在队列最长者，再优先冷的任务。返回候选的槽位。空闲时缓存热也照样搬（空闲比迁移更浪费）。
    /// An idle processor steals one task.
    pub fn steal(
        &self,
        thief: usize,
        now: u64,
        loads: &[CoreLoad],
        candidates: impl Iterator<Item = Candidate>,
    ) -> Result<usize, Refusal> {
        if !loads.get(thief).is_some_and(|l| l.online) {
            return Err(Refusal::Offline);
        }
        let mut best: Option<Candidate> = None;
        for c in candidates.filter(|c| c.home != thief && c.affinity.contains(thief)) {
            let better = match best {
                None => true,
                Some(b) => self.rank(&c, now, loads) > self.rank(&b, now, loads),
            };
            if better {
                best = Some(c);
            }
        }
        best.map(|c| c.slot).ok_or(Refusal::NoCandidate)
    }

    /// 周期均衡：处理器 `me` 的负载比最忙的处理器少至少 `imbalance` 时，从最忙的队列拉一个**冷**任务过来。
    /// 已均衡、没有允许的候选、候选全热时分别拒绝。
    /// Periodic balancing: pull one cold task from the busiest processor.
    pub fn pull(
        &self,
        me: usize,
        now: u64,
        loads: &[CoreLoad],
        candidates: impl Iterator<Item = Candidate> + Clone,
    ) -> Result<usize, Refusal> {
        let Some(mine) = loads.get(me).filter(|l| l.online) else { return Err(Refusal::Offline) };
        let busiest = (0..loads.len())
            .filter(|&c| c != me && loads[c].online)
            .max_by_key(|&c| (loads[c].load(), core::cmp::Reverse(c)));
        let Some(src) = busiest else { return Err(Refusal::Balanced) };
        if loads[src].load() < mine.load() + self.params.imbalance {
            return Err(Refusal::Balanced);
        }
        let allowed = candidates.filter(move |c| c.home == src && c.affinity.contains(me));
        if allowed.clone().next().is_none() {
            return Err(Refusal::NoCandidate);
        }
        let mut best: Option<Candidate> = None;
        for c in allowed.filter(|c| !self.hot(c.last_ran, now)) {
            if best.is_none_or(|b| c.qos.above(b.qos)) {
                best = Some(c);
            }
        }
        best.map(|c| c.slot).ok_or(Refusal::AllHot)
    }

    /// 窃取时的排序键：档位越高越先（0 = 最高档取反后最大）、所在队列越长越先、冷的先。
    fn rank(&self, c: &Candidate, now: u64, loads: &[CoreLoad]) -> (u8, u32, bool) {
        let class = (crate::sched::QOS_CLASSES - c.qos.index()) as u8;
        let queued = loads.get(c.home).map(|l| l.queued).unwrap_or(0);
        (class, queued, !self.hot(c.last_ran, now))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const B: Balancer = Balancer::new(BalanceParams::DEFAULT);

    fn busy(q: Qos, queued: u32) -> CoreLoad {
        CoreLoad { online: true, queued, running: Some(q) }
    }
    const IDLE: CoreLoad = CoreLoad { online: true, queued: 0, running: None };
    const ALL4: CpuSet = CpuSet::first(4);

    fn cand(slot: usize, home: usize, qos: Qos, last_ran: Option<u64>) -> Candidate {
        Candidate { slot, home, affinity: ALL4, qos, last_ran }
    }

    #[test]
    fn place_prefers_idle_prev_then_any_idle() {
        let loads = [busy(Qos::Utility, 1), IDLE, IDLE, IDLE];
        assert_eq!(B.place(ALL4, Some(2), Qos::Utility, None, 10, &loads), Ok(2));
        assert_eq!(B.place(ALL4, Some(0), Qos::Utility, None, 10, &loads), Ok(1));
        assert_eq!(B.place(ALL4, None, Qos::Utility, None, 10, &loads), Ok(1));
    }

    #[test]
    fn place_goes_where_it_can_preempt_lowest_class() {
        let loads = [busy(Qos::Utility, 0), busy(Qos::Background, 0), busy(Qos::Background, 2), busy(Qos::Interactive, 0)];
        // 交互任务被唤醒：去运行后台档且队列空的 1 号核（2 号核队列不空，3 号核运行同档）
        assert_eq!(B.place(ALL4, Some(3), Qos::Interactive, Some(9), 10, &loads), Ok(1));
    }

    #[test]
    fn place_keeps_hot_prev_else_least_loaded() {
        let loads = [busy(Qos::Utility, 3), busy(Qos::Utility, 0), busy(Qos::Utility, 1), busy(Qos::Utility, 1)];
        assert_eq!(B.place(ALL4, Some(0), Qos::Utility, Some(9), 10, &loads), Ok(0), "缓存仍热：留在原处");
        assert_eq!(B.place(ALL4, Some(0), Qos::Utility, Some(1), 10, &loads), Ok(1), "缓存已冷：去负载最小的核");
        assert_eq!(B.place(ALL4, Some(2), Qos::Utility, None, 10, &[busy(Qos::Utility, 1); 4]), Ok(2), "负载相等时偏向原处");
    }

    #[test]
    fn place_respects_affinity_and_rejects_empty_or_offline() {
        let loads = [busy(Qos::Utility, 5), IDLE, IDLE, CoreLoad::OFFLINE];
        let only0 = CpuSet::first(1);
        assert_eq!(B.place(only0, Some(0), Qos::Interactive, None, 0, &loads), Ok(0), "亲和只含 0 号核：再忙也只能去 0 号");
        assert_eq!(B.place(CpuSet::EMPTY, None, Qos::Utility, None, 0, &loads), Err(PlaceError::NoAllowedCpu));
        let mut only3 = CpuSet::EMPTY;
        only3.insert(3);
        assert_eq!(B.place(only3, Some(3), Qos::Utility, None, 0, &loads), Err(PlaceError::NoAllowedCpu), "唯一允许的核离线");
    }

    #[test]
    fn steal_takes_highest_class_then_longest_queue_then_cold() {
        let loads = [busy(Qos::Utility, 3), busy(Qos::Utility, 1), IDLE, IDLE];
        let cs = [cand(10, 1, Qos::Utility, None), cand(11, 0, Qos::Utility, Some(9)), cand(12, 0, Qos::Utility, None)];
        assert_eq!(B.steal(2, 10, &loads, cs.into_iter()), Ok(12), "同档：队列长的 0 号核里冷的那个");
        let cs2 = [cand(10, 1, Qos::Interactive, Some(9)), cand(12, 0, Qos::Utility, None)];
        assert_eq!(B.steal(2, 10, &loads, cs2.into_iter()), Ok(10), "高档优先，即使缓存热");
        let hot_only = [cand(11, 0, Qos::Utility, Some(10))];
        assert_eq!(B.steal(2, 10, &loads, hot_only.into_iter()), Ok(11), "空闲时热任务也搬");
    }

    #[test]
    fn steal_refuses_affinity_own_queue_and_offline() {
        let loads = [busy(Qos::Utility, 2), IDLE, IDLE, CoreLoad::OFFLINE];
        let pinned = Candidate { affinity: CpuSet::first(1), ..cand(5, 0, Qos::Utility, None) };
        assert_eq!(B.steal(1, 10, &loads, [pinned].into_iter()), Err(Refusal::NoCandidate), "亲和不含窃取者");
        assert_eq!(B.steal(1, 10, &loads, [cand(6, 1, Qos::Utility, None)].into_iter()), Err(Refusal::NoCandidate), "已在自己队列");
        assert_eq!(B.steal(3, 10, &loads, [cand(7, 0, Qos::Utility, None)].into_iter()), Err(Refusal::Offline));
        assert_eq!(B.steal(9, 10, &loads, [cand(7, 0, Qos::Utility, None)].into_iter()), Err(Refusal::Offline), "下标越界");
    }

    #[test]
    fn pull_moves_one_cold_task_from_busiest() {
        let loads = [busy(Qos::Utility, 3), busy(Qos::Utility, 0), busy(Qos::Utility, 1), busy(Qos::Utility, 0)];
        let cs = [cand(20, 0, Qos::Utility, Some(9)), cand(21, 0, Qos::Background, None), cand(22, 0, Qos::Utility, Some(1)), cand(23, 2, Qos::Interactive, None)];
        assert_eq!(B.pull(1, 10, &loads, cs.iter().copied()), Ok(22), "只从最忙的 0 号核拉；冷的里挑最高档");
    }

    #[test]
    fn pull_refusals_balanced_all_hot_no_candidate() {
        let even = [busy(Qos::Utility, 1), busy(Qos::Utility, 0), busy(Qos::Utility, 1), busy(Qos::Utility, 1)];
        assert_eq!(B.pull(1, 10, &even, [cand(1, 0, Qos::Utility, None)].iter().copied()), Err(Refusal::Balanced), "差 1 不搬");
        let skew = [busy(Qos::Utility, 3), busy(Qos::Utility, 0), IDLE, IDLE];
        let hot = [cand(1, 0, Qos::Utility, Some(9)), cand(2, 0, Qos::Utility, Some(10))];
        assert_eq!(B.pull(1, 10, &skew, hot.iter().copied()), Err(Refusal::AllHot));
        let pinned = [Candidate { affinity: CpuSet::first(1), ..cand(3, 0, Qos::Utility, None) }];
        assert_eq!(B.pull(1, 10, &skew, pinned.iter().copied()), Err(Refusal::NoCandidate));
        assert_eq!(B.pull(1, 10, &[busy(Qos::Utility, 3), CoreLoad::OFFLINE], hot.iter().copied()), Err(Refusal::Offline));
        assert_eq!(B.pull(0, 10, &[busy(Qos::Utility, 3)], hot.iter().copied()), Err(Refusal::Balanced), "只有一个核");
    }

    #[test]
    fn hot_and_due_boundaries() {
        assert!(B.hot(Some(9), 10));
        assert!(!B.hot(Some(8), 10), "恰好满迁移代价即视为冷");
        assert!(!B.hot(None, 10));
        assert!(B.due(8) && !B.due(9));
        assert!(!Balancer::new(BalanceParams { balance_interval: 0, ..BalanceParams::DEFAULT }).due(0), "间隔 0 = 关闭周期均衡");
    }
}
