//! 批处理作业队列：作业身份、依赖、优先级、生命周期与结果收集。
//! Batch job queue: identity, dependencies, priority, lifecycle and results.
//!
//! # 职责
//! 纯状态机：谁能跑、谁在等、跑完记什么。不创建任务、不碰调度器、不做 IO，
//! 因此可以在宿主上把全部边界情况跑一遍。
//!
//! # 边界
//! * 不使用堆分配（本 crate 会被极小的用户态程序链接），全部是定长数组；
//! * 只回答"下一个该跑谁"，真正的创建与取消由内核的作业服务完成；
//! * 队列表满、依赖成环、重复提交、依赖未完成而试图开始，一律拒绝并给出原因。
//!
//! # 探索阶段说明
//! 演示阶段的字段与语义会继续调整；已经实现的行为是真实的，但不构成冻结契约。

/// 队列容量。
pub const MAX_JOBS: usize = 8;
/// 单个作业的最大依赖数。
pub const MAX_DEPS: usize = 4;

/// 作业状态。
/// Job state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    /// 已提交，等待依赖满足。
    Submitted,
    /// 依赖已满足，可以运行。
    Runnable,
    /// 正在运行。
    Running,
    /// 正常结束（记录退出码）。
    Completed,
    /// 异常结束。
    Failed,
    /// 被取消。
    Cancelled,
}

impl JobState {
    /// 稳定文本名（进入结构化输出）。
    pub const fn as_str(self) -> &'static str {
        match self {
            JobState::Submitted => "submitted",
            JobState::Runnable => "runnable",
            JobState::Running => "running",
            JobState::Completed => "completed",
            JobState::Failed => "failed",
            JobState::Cancelled => "cancelled",
        }
    }

    /// 是否已经结束（终态）。
    pub const fn is_terminal(self) -> bool {
        matches!(self, JobState::Completed | JobState::Failed | JobState::Cancelled)
    }
}

/// 作业优先级：数值越大越先运行。
/// Job priority: larger runs first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum JobPriority {
    /// 低。
    Low = 0,
    /// 普通。
    Normal = 1,
    /// 高。
    High = 2,
}

/// 队列拒绝原因。
/// Why a queue operation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobError {
    /// 队列已满。
    Full,
    /// 作业 ID 重复。
    Duplicate,
    /// 依赖指向自己。
    SelfDependency,
    /// 作业不存在。
    Unknown,
    /// 依赖尚未全部完成。
    DependencyNotMet,
    /// 作业不在可取消的状态。
    NotCancellable,
    /// 作业不在运行状态。
    NotRunning,
    /// 当前 Profile 没有声明批处理能力。
    NotPermitted,
}

impl JobError {
    /// 稳定文本名。
    pub const fn as_str(self) -> &'static str {
        match self {
            JobError::Full => "full",
            JobError::Duplicate => "duplicate",
            JobError::SelfDependency => "self_dependency",
            JobError::Unknown => "unknown",
            JobError::DependencyNotMet => "dependency_not_met",
            JobError::NotCancellable => "not_cancellable",
            JobError::NotRunning => "not_running",
            JobError::NotPermitted => "not_permitted",
        }
    }
}

/// 一条作业记录。
/// One job record.
#[derive(Debug, Clone, Copy)]
pub struct Job {
    /// 作业 ID（调用方分配，队列内唯一）。
    pub id: u32,
    /// 状态。
    pub state: JobState,
    /// 优先级。
    pub priority: JobPriority,
    /// 依赖的作业 ID（全部完成才可运行）。
    pub deps: [u32; MAX_DEPS],
    /// 依赖条数。
    pub dep_count: usize,
    /// 退出码（仅 Completed / Failed 有意义）。
    pub exit_code: i32,
    /// 提交顺序（同一优先级下按此先来先跑）。
    pub sequence: u32,
}

/// 队列统计快照。
/// Queue statistics snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct JobStats {
    /// 已提交（含已结束）。
    pub total: usize,
    /// 等待依赖。
    pub submitted: usize,
    /// 可运行。
    pub runnable: usize,
    /// 运行中。
    pub running: usize,
    /// 完成。
    pub completed: usize,
    /// 失败。
    pub failed: usize,
    /// 取消。
    pub cancelled: usize,
}

/// 定长作业队列。
/// Fixed-capacity job queue.
#[derive(Debug, Clone, Copy)]
pub struct JobQueue {
    jobs: [Option<Job>; MAX_JOBS],
    sequence: u32,
}

impl JobQueue {
    /// 空队列。
    pub const fn new() -> Self {
        Self { jobs: [None; MAX_JOBS], sequence: 0 }
    }

    /// 提交一个作业。依赖必须已经存在且不构成环。
    /// English: submit a job; dependencies must exist and stay acyclic.
    pub fn submit(&mut self, id: u32, priority: JobPriority, deps: &[u32]) -> Result<(), JobError> {
        if deps.len() > MAX_DEPS {
            return Err(JobError::Full);
        }
        if self.find(id).is_some() {
            return Err(JobError::Duplicate);
        }
        for dep in deps {
            if *dep == id {
                return Err(JobError::SelfDependency);
            }
            if self.find(*dep).is_none() {
                return Err(JobError::Unknown);
            }
        }
        let Some(slot) = self.free_slot() else {
            return Err(JobError::Full);
        };
        let mut table = [0u32; MAX_DEPS];
        table[..deps.len()].copy_from_slice(deps);
        self.jobs[slot] = Some(Job {
            id,
            // 依赖为空则可运行；否则等依赖完成后再由 `refresh` 提升。
            state: if deps.is_empty() { JobState::Runnable } else { JobState::Submitted },
            priority,
            deps: table,
            dep_count: deps.len(),
            exit_code: 0,
            sequence: self.sequence,
        });
        self.sequence += 1;
        Ok(())
    }

    /// 选择一个可运行作业：优先级高者优先，同级先提交者优先。
    /// English: pick the highest-priority runnable job, FIFO within a priority.
    pub fn pick(&self) -> Option<u32> {
        let mut best: Option<&Job> = None;
        for job in self.jobs.iter().flatten() {
            if job.state != JobState::Runnable {
                continue;
            }
            best = match best {
                None => Some(job),
                Some(current) => {
                    let better = job.priority > current.priority
                        || (job.priority == current.priority && job.sequence < current.sequence);
                    Some(if better { job } else { current })
                }
            };
        }
        best.map(|job| job.id)
    }

    /// 把作业标为运行中。
    pub fn start(&mut self, id: u32) -> Result<(), JobError> {
        let job = self.job_mut(id).ok_or(JobError::Unknown)?;
        if job.state != JobState::Runnable {
            return Err(JobError::DependencyNotMet);
        }
        job.state = JobState::Running;
        Ok(())
    }

    /// 记录作业结束（退出码 0 = 成功）。
    pub fn finish(&mut self, id: u32, exit_code: i32) -> Result<(), JobError> {
        let job = self.job_mut(id).ok_or(JobError::Unknown)?;
        if job.state != JobState::Running {
            return Err(JobError::NotRunning);
        }
        job.exit_code = exit_code;
        job.state = if exit_code == 0 { JobState::Completed } else { JobState::Failed };
        self.refresh();
        Ok(())
    }

    /// 取消作业：等待中或运行中都可以取消。
    pub fn cancel(&mut self, id: u32) -> Result<JobState, JobError> {
        let job = self.job_mut(id).ok_or(JobError::Unknown)?;
        if job.state.is_terminal() {
            return Err(JobError::NotCancellable);
        }
        let previous = job.state;
        job.state = JobState::Cancelled;
        self.refresh();
        Ok(previous)
    }

    /// 重新计算"依赖已满足"的等待作业。
    fn refresh(&mut self) {
        for index in 0..MAX_JOBS {
            let Some(job) = self.jobs[index] else { continue };
            if job.state != JobState::Submitted {
                continue;
            }
            let ready = (0..job.dep_count).all(|i| {
                self.find(job.deps[i])
                    .is_some_and(|dep| dep.state == JobState::Completed)
            });
            if ready {
                if let Some(slot) = self.jobs[index].as_mut() {
                    slot.state = JobState::Runnable;
                }
            }
        }
    }

    /// 按 ID 取作业。
    pub fn get(&self, id: u32) -> Option<&Job> {
        self.find(id)
    }

    /// 统计快照。
    pub fn stats(&self) -> JobStats {
        let mut stats = JobStats::default();
        for job in self.jobs.iter().flatten() {
            stats.total += 1;
            match job.state {
                JobState::Submitted => stats.submitted += 1,
                JobState::Runnable => stats.runnable += 1,
                JobState::Running => stats.running += 1,
                JobState::Completed => stats.completed += 1,
                JobState::Failed => stats.failed += 1,
                JobState::Cancelled => stats.cancelled += 1,
            }
        }
        stats
    }

    fn find(&self, id: u32) -> Option<&Job> {
        self.jobs.iter().flatten().find(|job| job.id == id)
    }

    fn job_mut(&mut self, id: u32) -> Option<&mut Job> {
        self.jobs.iter_mut().flatten().find(|job| job.id == id)
    }

    fn free_slot(&self) -> Option<usize> {
        self.jobs.iter().position(|slot| slot.is_none())
    }
}

#[cfg(test)]
mod tests;
