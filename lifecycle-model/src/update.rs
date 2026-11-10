//! 更新事务的单一权威状态机。
//! The single authoritative update-transaction state machine.

/// 更新协调器的持久阶段；`Idle` 表示尚无交易，不是交易终态。
/// Persistent update-coordinator phase; `Idle` means no transaction and is not a transaction outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum UpdateStage {
    /// 没有活动事务。No transaction is active.
    Idle = 0,
    /// 已发现候选版本。A candidate release was discovered.
    Discovered = 1,
    /// 清单、签名、摘要、平台与反回滚均已通过。Manifest, signature, digest, platform, and anti-rollback passed.
    Verified = 2,
    /// 下载、依赖、空间与迁移预检已通过，等待持久提交。Payload, dependency, space, and migration checks passed.
    Prepared = 3,
    /// 非活动槽、切换记录和试启动预算已持久提交。The inactive slot, switch record, and trial budget are durable.
    Committed = 4,
    /// 新槽正在有界试启动。The new slot is in its bounded trial boot.
    Trial = 5,
    /// 关键健康集合已通过，但清理尚未完成。Critical health passed, but cleanup is not complete.
    Confirmed = 6,
    /// 新槽已确认并完成事务清理。The new slot is confirmed and transaction cleanup completed.
    Complete = 7,
    /// 持久提交前取消或失败。Cancelled or failed before the durable switch commit.
    Aborted = 8,
    /// 提交后健康失败，正在回到旧槽。Post-commit health failed and recovery is selecting the old slot.
    Rollback = 9,
    /// 旧槽重新健康运行，回滚已持久提交。The old slot is healthy again and rollback is durable.
    RolledBack = 10,
}

/// 更新事务事件。
/// Events accepted by the update transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdateEvent {
    /// 记录候选。Record a discovered candidate.
    Discover,
    /// 独立验证成功。Independent verification succeeded.
    Verify,
    /// 下载和全部预检查成功。Payload acquisition and all preflight checks succeeded.
    Prepare,
    /// 写入非活动槽并持久提交切换记录。Write the inactive slot and durably commit the switch record.
    Commit,
    /// 启动管理器进入候选试启动。The boot manager enters the candidate trial.
    BeginTrial,
    /// 关键健康集合通过。The critical health set passed.
    ConfirmHealth,
    /// 完成新槽确认后的清理。Finish cleanup after confirming the new slot.
    Finalize,
    /// 关键健康集合失败。The critical health set failed.
    FailHealth,
    /// 旧槽重新通过健康确认。The previous slot passed health again.
    FinishRollback,
    /// 在持久提交前取消。Cancel before the durable switch commit.
    Cancel,
}

/// 状态机拒绝事件的原因。
/// Why the state machine rejected an event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitionError {
    /// 事件的发起阶段不正确。The event is invalid in the current phase.
    InvalidPhase {
        /// 当前阶段。Current phase.
        current: UpdateStage,
        /// 被拒绝的事件。Rejected event.
        event: UpdateEvent,
    },
    /// 事务已经进入终态。The transaction already reached a terminal phase.
    Terminal(UpdateStage),
    /// 状态机记录世代耗尽。The state-machine generation is exhausted.
    GenerationExhausted,
}

/// 从持久记录恢复状态机时的错误。
/// Error while restoring a state machine from a persistent record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestoreError {
    /// 阶段与世代组合不可能由状态机产生。The stage/generation pair cannot be produced by the state machine.
    InvalidState,
}

/// 一个更新事务的持久状态。
/// Persistent state of one update transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpdateMachine {
    stage: UpdateStage,
    generation: u64,
}

impl UpdateMachine {
    /// 创建空闲状态机。Create an idle state machine.
    pub const fn idle() -> Self {
        Self {
            stage: UpdateStage::Idle,
            generation: 0,
        }
    }

    /// 当前阶段。Current phase.
    pub const fn stage(self) -> UpdateStage {
        self.stage
    }

    /// 每次成功迁移后严格递增的记录世代。Strictly increasing record generation after each transition.
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// 从经过完整性和状态校验的持久字段恢复状态机。
    /// Restores a state machine from validated persistent fields.
    pub const fn restore(stage: UpdateStage, generation: u64) -> Result<Self, RestoreError> {
        let valid = match stage {
            UpdateStage::Idle => generation == 0,
            UpdateStage::Discovered => generation == 1,
            UpdateStage::Verified => generation == 2,
            UpdateStage::Prepared => generation == 3,
            UpdateStage::Committed => generation == 4,
            UpdateStage::Trial => generation == 5,
            UpdateStage::Confirmed => generation == 6,
            UpdateStage::Complete => generation == 7,
            UpdateStage::Aborted => generation >= 1 && generation <= 4,
            UpdateStage::Rollback => generation == 6,
            UpdateStage::RolledBack => generation == 7,
        };
        if !valid {
            return Err(RestoreError::InvalidState);
        }
        Ok(Self { stage, generation })
    }

    /// 判断事务是否进入不可继续推进的终态。
    /// Returns whether the transaction has reached a terminal phase.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self.stage,
            UpdateStage::Complete | UpdateStage::Aborted | UpdateStage::RolledBack
        )
    }

    /// 应用一个事件；失败不改变状态机。
    /// Applies one event; rejection leaves the machine unchanged.
    pub fn apply(&mut self, event: UpdateEvent) -> Result<UpdateStage, TransitionError> {
        if self.is_terminal() {
            return Err(TransitionError::Terminal(self.stage));
        }
        let next = match (self.stage, event) {
            (UpdateStage::Idle, UpdateEvent::Discover) => UpdateStage::Discovered,
            (UpdateStage::Discovered, UpdateEvent::Verify) => UpdateStage::Verified,
            (UpdateStage::Verified, UpdateEvent::Prepare) => UpdateStage::Prepared,
            (UpdateStage::Prepared, UpdateEvent::Commit) => UpdateStage::Committed,
            (UpdateStage::Committed, UpdateEvent::BeginTrial) => UpdateStage::Trial,
            (UpdateStage::Trial, UpdateEvent::ConfirmHealth) => UpdateStage::Confirmed,
            (UpdateStage::Confirmed, UpdateEvent::Finalize) => UpdateStage::Complete,
            (UpdateStage::Trial, UpdateEvent::FailHealth) => UpdateStage::Rollback,
            (UpdateStage::Rollback, UpdateEvent::FinishRollback) => UpdateStage::RolledBack,
            (
                UpdateStage::Idle
                | UpdateStage::Discovered
                | UpdateStage::Verified
                | UpdateStage::Prepared,
                UpdateEvent::Cancel,
            ) => UpdateStage::Aborted,
            (current, event) => return Err(TransitionError::InvalidPhase { current, event }),
        };
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(TransitionError::GenerationExhausted)?;
        self.stage = next;
        self.generation = generation;
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_update_follows_the_frozen_order() {
        let mut machine = UpdateMachine::idle();
        for event in [
            UpdateEvent::Discover,
            UpdateEvent::Verify,
            UpdateEvent::Prepare,
            UpdateEvent::Commit,
            UpdateEvent::BeginTrial,
            UpdateEvent::ConfirmHealth,
            UpdateEvent::Finalize,
        ] {
            machine.apply(event).unwrap();
        }
        assert_eq!(machine.stage(), UpdateStage::Complete);
        assert_eq!(machine.generation(), 7);
        assert_eq!(
            machine.apply(UpdateEvent::FailHealth),
            Err(TransitionError::Terminal(UpdateStage::Complete))
        );
    }

    #[test]
    fn precommit_failure_is_distinct_from_postcommit_rollback() {
        let mut cancelled = UpdateMachine::idle();
        cancelled.apply(UpdateEvent::Discover).unwrap();
        cancelled.apply(UpdateEvent::Cancel).unwrap();
        assert_eq!(cancelled.stage(), UpdateStage::Aborted);

        let mut rolled_back = UpdateMachine::idle();
        for event in [
            UpdateEvent::Discover,
            UpdateEvent::Verify,
            UpdateEvent::Prepare,
            UpdateEvent::Commit,
            UpdateEvent::BeginTrial,
            UpdateEvent::FailHealth,
            UpdateEvent::FinishRollback,
        ] {
            rolled_back.apply(event).unwrap();
        }
        assert_eq!(rolled_back.stage(), UpdateStage::RolledBack);
    }

    #[test]
    fn committed_and_trial_are_not_success_states() {
        let mut machine = UpdateMachine::idle();
        for event in [
            UpdateEvent::Discover,
            UpdateEvent::Verify,
            UpdateEvent::Prepare,
            UpdateEvent::Commit,
        ] {
            machine.apply(event).unwrap();
        }
        assert_eq!(machine.stage(), UpdateStage::Committed);
        assert!(!machine.is_terminal());
        machine.apply(UpdateEvent::BeginTrial).unwrap();
        assert_eq!(machine.stage(), UpdateStage::Trial);
        assert!(!machine.is_terminal());
    }

    #[test]
    fn invalid_event_has_no_side_effect() {
        let mut machine = UpdateMachine::idle();
        let before = machine;
        assert_eq!(
            machine.apply(UpdateEvent::Commit),
            Err(TransitionError::InvalidPhase {
                current: UpdateStage::Idle,
                event: UpdateEvent::Commit,
            })
        );
        assert_eq!(machine, before);
    }

    #[test]
    fn restore_rejects_impossible_idle_and_non_idle_generations() {
        assert!(UpdateMachine::restore(UpdateStage::Idle, 0).is_ok());
        assert!(UpdateMachine::restore(UpdateStage::Prepared, 3).is_ok());
        assert_eq!(
            UpdateMachine::restore(UpdateStage::Idle, 1),
            Err(RestoreError::InvalidState)
        );
        assert_eq!(
            UpdateMachine::restore(UpdateStage::Prepared, 0),
            Err(RestoreError::InvalidState)
        );
        assert_eq!(
            UpdateMachine::restore(UpdateStage::Discovered, 3),
            Err(RestoreError::InvalidState)
        );
    }
}
