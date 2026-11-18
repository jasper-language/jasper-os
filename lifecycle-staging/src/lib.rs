//! LC-2 更新工件的已验签、持久化暂存边界。
//! Verified durable artifact-staging boundary for LC-2 updates.
//!
//! 本 crate 通过统一的在线/离线来源接口获取清单与工件，在清单签名、信任和
//! 反回滚验证通过后才请求工件；两种传输随后进入同一暂存、事务和启动控制路径。
//! 它不把 URL 或来源身份当作信任根，也不把暂存当作激活成功。
//! This crate acquires manifests and artifacts through one online/offline source
//! interface, authenticates the manifest before requesting declared artifacts, and
//! sends both transports through the same staging, transaction and boot-control path.
//! Transport identity is never a trust root, and staging is never activation success.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod archive_store;
pub mod control;
pub mod gpt_layout;
pub mod p0_control;
pub mod source;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use jasper_lifecycle_model::archive::ArchiveError;
use jasper_lifecycle_model::boot::{
    BootControlError, BootDecision, BootReason, Candidate, ControlBlock, Slot, SlotState,
};
use jasper_lifecycle_model::manifest::{
    authorize_install, LocalInstallGrant, ManifestError, ThresholdTrustPolicy, TrustPolicy,
    UpdateTarget,
};
use jasper_lifecycle_model::manifest_cbor::{
    ArtifactKind, VerifiedArtifact, VerifiedCborManifest, MAX_MANIFEST_CBOR_BYTES,
};
use jasper_lifecycle_model::transaction::{recover, TransactionError, TransactionRecord};
use jasper_lifecycle_model::update::{TransitionError, UpdateEvent, UpdateMachine, UpdateStage};
use sha2::{Digest, Sha256};

use crate::archive_store::FileArchiveStore;
use crate::control::{ControlStoreError, FileControlStore};
use crate::source::{
    materialize_verified, materialize_verified_threshold, MaterializedUpdate, SourceError,
    UpdateBundleSource,
};

const MANIFEST_FILE: &str = "manifest.cbor";
const ARTIFACT_DIR: &str = "artifacts";
const TRANSACTION_COPIES: [&str; 2] = ["transaction.0", "transaction.1"];
const COPY_BUFFER_BYTES: usize = 64 * 1024;

/// 本地制品来源；名称必须与已验签清单中的工件名称精确匹配。
/// Local artifact source; the name must exactly match an artifact in the verified manifest.
#[derive(Clone, Copy, Debug)]
pub struct ArtifactSource<'a> {
    /// 清单工件名。Manifest artifact name.
    pub name: &'a str,
    /// 本地普通文件路径。Local regular-file path.
    pub path: &'a Path,
}

/// 已完成复制、刷新和读回复核的工件。
/// Artifact that passed copy, flush and read-back verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedArtifact {
    /// 工件类别。Artifact kind.
    pub kind: ArtifactKind,
    /// 工件名称。Artifact name.
    pub name: String,
    /// 字节数。Size in bytes.
    pub size: u64,
    /// 内容 SHA-256。Content SHA-256.
    pub sha256: [u8; 32],
    /// 相对暂存根目录的路径。Path relative to the staging root.
    pub relative_path: PathBuf,
}

/// 暂存成功回执；不代表激活成功。
/// Successful staging receipt; this is not an activation success.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagingReceipt {
    /// 新建的暂存根目录。Fresh staging root.
    pub root: PathBuf,
    /// 完整清单 SHA-256。Complete manifest SHA-256.
    pub manifest_sha256: [u8; 32],
    /// 清单 CBOR 字节数。Manifest CBOR size.
    pub manifest_bytes: u64,
    /// 所有工件字节数。Total artifact bytes.
    pub artifact_bytes: u64,
    /// 已完成复核的工件。Artifacts that passed verification.
    pub artifacts: Vec<StagedArtifact>,
}

/// 导入前磁盘预算结果。
/// Disk-budget result produced before import.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiskBudget {
    /// 文件系统当前可用字节。Currently available filesystem bytes.
    pub available_bytes: u64,
    /// 清单、工件和调用方元数据余量所需字节。Required bytes for manifest, artifacts and caller metadata headroom.
    pub required_bytes: u64,
    /// 采用的文件系统块大小。Filesystem allocation block size.
    pub block_size: u64,
}

/// 已完成授权、依赖预检、磁盘预算和持久暂存的更新准备事实。
///
/// 该值包含持久 `Prepared` 交易记录，但不是提交成功，也不包含启动槽切换。
/// Prepared update after authorization, dependency preflight, disk budgeting and durable staging.
/// It contains a durable `Prepared` transaction record but is not a commit and contains no slot switch.
#[derive(Debug)]
pub struct PreparedUpdate {
    /// 已验签清单。Verified manifest.
    pub manifest: VerifiedCborManifest,
    /// 磁盘预算。Disk budget.
    pub budget: DiskBudget,
    /// 持久暂存回执。Durable staging receipt.
    pub staging: StagingReceipt,
    /// 持久 Prepared 交易记录。Durable Prepared transaction record.
    pub record: TransactionRecord,
}

/// 更新协调器在持久提交前持有的单一状态机。
///
/// Coordinator state machine before the durable slot switch. Staging completion
/// is recorded as `Prepared`; it is not a commit or activation claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpdateCoordinator {
    machine: UpdateMachine,
}

/// Prepared update plus the coordinator state that produced it.
#[derive(Debug)]
pub struct CoordinatedPreparedUpdate {
    /// Coordinator at `Prepared`.
    pub coordinator: UpdateCoordinator,
    /// Verified, authorized and durably staged update.
    pub update: PreparedUpdate,
}

/// Immutable audit copy of a terminal update transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchivedTransaction {
    /// Archive root.
    pub root: PathBuf,
    /// Manifest digest bound to the transaction.
    pub manifest_sha256: [u8; 32],
    /// Terminal transaction record.
    pub record: TransactionRecord,
}

/// Coordinator failure.
#[derive(Debug)]
pub enum CoordinatorError {
    /// The update state machine rejected the transition.
    Transition(TransitionError),
    /// Staging, authorization or dependency preflight failed.
    Staging(StagingError),
    /// The online or offline update source failed verification or acquisition.
    Source(SourceError),
    /// Prepared transaction recovery failed or does not match the machine.
    Transaction(TransactionError),
    /// The candidate cannot be admitted into boot control.
    Control(BootControlError),
    /// The dual-copy boot-control commit failed.
    ControlStore(ControlStoreError),
    /// No candidate trial is available for the current transaction.
    TrialUnavailable,
    /// Recovered transaction and coordinator phase disagree.
    InconsistentStage {
        /// Required coordinator phase.
        expected: UpdateStage,
        /// Actual recovered phase.
        actual: UpdateStage,
    },
}

impl fmt::Display for CoordinatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transition(error) => write!(formatter, "update transition failed: {error:?}"),
            Self::Staging(error) => write!(formatter, "{error}"),
            Self::Source(error) => write!(formatter, "update source failed: {error}"),
            Self::Transaction(error) => write!(formatter, "prepared transaction failed: {error:?}"),
            Self::Control(error) => write!(formatter, "boot-control admission failed: {error:?}"),
            Self::ControlStore(error) => write!(formatter, "boot-control commit failed: {error}"),
            Self::TrialUnavailable => write!(formatter, "candidate trial is unavailable"),
            Self::InconsistentStage { expected, actual } => write!(
                formatter,
                "coordinator stage mismatch: expected {expected:?}, got {actual:?}"
            ),
        }
    }
}

impl std::error::Error for CoordinatorError {}

impl UpdateCoordinator {
    /// Create an idle coordinator.
    pub const fn idle() -> Self {
        Self {
            machine: UpdateMachine::idle(),
        }
    }

    /// Current authoritative update phase.
    pub const fn stage(self) -> UpdateStage {
        self.machine.stage()
    }

    /// Authorize, preflight and durably stage a verified manifest.
    ///
    /// The coordinator publishes `Prepared` only after every staging side effect
    /// succeeds. A failure leaves the previous coordinator phase unchanged.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        &mut self,
        manifest: VerifiedCborManifest,
        manifest_bytes: &[u8],
        grant: LocalInstallGrant,
        now: u64,
        installed_dependencies: &[String],
        sources: &[ArtifactSource<'_>],
        staging_root: &Path,
        metadata_headroom: u64,
    ) -> Result<PreparedUpdate, CoordinatorError> {
        let mut next = self.machine;
        next.apply(UpdateEvent::Discover)
            .map_err(CoordinatorError::Transition)?;
        next.apply(UpdateEvent::Verify)
            .map_err(CoordinatorError::Transition)?;
        next.apply(UpdateEvent::Prepare)
            .map_err(CoordinatorError::Transition)?;
        let update = prepare_update(
            manifest,
            manifest_bytes,
            grant,
            now,
            installed_dependencies,
            sources,
            staging_root,
            metadata_headroom,
        )
        .map_err(CoordinatorError::Staging)?;
        if update.record.stage() != next.stage() {
            return Err(CoordinatorError::InconsistentStage {
                expected: next.stage(),
                actual: update.record.stage(),
            });
        }
        self.machine = next;
        Ok(update)
    }

    /// Acquire, authenticate, materialize and stage one online or offline bundle.
    ///
    /// Both transports enter this method through [`UpdateBundleSource`]. Manifest
    /// trust is verified before declared artifacts are fetched, and the normal
    /// staging path remains the only authority for dependency, capacity, digest,
    /// journal and cleanup effects.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_from_source<S: UpdateBundleSource + ?Sized>(
        &mut self,
        policy: TrustPolicy<'_>,
        target: UpdateTarget,
        source: &S,
        grant: LocalInstallGrant,
        now: u64,
        installed_dependencies: &[String],
        staging_root: &Path,
        metadata_headroom: u64,
    ) -> Result<PreparedUpdate, CoordinatorError> {
        let spool = Self::source_spool(staging_root)?;
        let materialized: MaterializedUpdate = materialize_verified(source, policy, target, &spool)
            .map_err(CoordinatorError::Source)?;
        self.prepare_materialized_source(
            materialized,
            grant,
            now,
            installed_dependencies,
            staging_root,
            metadata_headroom,
        )
    }

    /// Acquire and stage one bundle through a production threshold policy.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_from_source_threshold<S: UpdateBundleSource + ?Sized>(
        &mut self,
        policy: ThresholdTrustPolicy<'_>,
        target: UpdateTarget,
        source: &S,
        grant: LocalInstallGrant,
        now: u64,
        installed_dependencies: &[String],
        staging_root: &Path,
        metadata_headroom: u64,
    ) -> Result<PreparedUpdate, CoordinatorError> {
        let spool = Self::source_spool(staging_root)?;
        let materialized = materialize_verified_threshold(source, policy, target, &spool)
            .map_err(CoordinatorError::Source)?;
        self.prepare_materialized_source(
            materialized,
            grant,
            now,
            installed_dependencies,
            staging_root,
            metadata_headroom,
        )
    }

    fn source_spool(staging_root: &Path) -> Result<PathBuf, CoordinatorError> {
        staging_root
            .parent()
            .ok_or(CoordinatorError::Source(SourceError::InvalidSpoolPath(
                staging_root.to_path_buf(),
            )))
            .map(|parent| parent.join(format!(".source-{}", uuid::Uuid::new_v4())))
    }

    fn prepare_materialized_source(
        &mut self,
        materialized: MaterializedUpdate,
        grant: LocalInstallGrant,
        now: u64,
        installed_dependencies: &[String],
        staging_root: &Path,
        metadata_headroom: u64,
    ) -> Result<PreparedUpdate, CoordinatorError> {
        let mut next = self.machine;
        next.apply(UpdateEvent::Discover)
            .map_err(CoordinatorError::Transition)?;
        next.apply(UpdateEvent::Verify)
            .map_err(CoordinatorError::Transition)?;
        next.apply(UpdateEvent::Prepare)
            .map_err(CoordinatorError::Transition)?;
        let sources = materialized.artifact_sources();
        let update = prepare_update(
            materialized.manifest.clone(),
            &materialized.manifest_bytes,
            grant,
            now,
            installed_dependencies,
            &sources,
            staging_root,
            metadata_headroom,
        )
        .map_err(CoordinatorError::Staging)?;
        if update.record.stage() != next.stage() {
            return Err(CoordinatorError::InconsistentStage {
                expected: next.stage(),
                actual: update.record.stage(),
            });
        }
        self.machine = next;
        Ok(update)
    }

    /// Recover a coordinator from a durable Prepared transaction.
    pub fn recover_prepared(
        staging_root: &Path,
        manifest_sha256: [u8; 32],
    ) -> Result<Self, CoordinatorError> {
        let record = load_prepared_transaction(staging_root, manifest_sha256)
            .map_err(CoordinatorError::Staging)?;
        let mut machine = UpdateMachine::idle();
        machine
            .apply(UpdateEvent::Discover)
            .map_err(CoordinatorError::Transition)?;
        machine
            .apply(UpdateEvent::Verify)
            .map_err(CoordinatorError::Transition)?;
        machine
            .apply(UpdateEvent::Prepare)
            .map_err(CoordinatorError::Transition)?;
        if record.stage() != machine.stage() {
            return Err(CoordinatorError::InconsistentStage {
                expected: machine.stage(),
                actual: record.stage(),
            });
        }
        Ok(Self { machine })
    }

    /// Recover the coordinator using both the transaction journal and boot control.
    ///
    /// A crash after the durable boot-control commit but before the transaction
    /// journal update is repaired only when the control candidate digest exactly
    /// matches this transaction.
    pub fn recover_with_control(
        staging_root: &Path,
        manifest_sha256: [u8; 32],
        control: &FileControlStore,
    ) -> Result<Self, CoordinatorError> {
        let record = load_transaction_record(staging_root).map_err(CoordinatorError::Staging)?;
        if record.manifest_sha256() != manifest_sha256 {
            return Err(CoordinatorError::Transaction(
                TransactionError::InvalidDigest,
            ));
        }
        let current = control.current();
        let candidate = current
            .candidate()
            .filter(|(_, candidate)| candidate.digest() == manifest_sha256);
        let confirmed = [Slot::A, Slot::B].into_iter().any(|slot| {
            let record = current.slot(slot);
            record.digest() == manifest_sha256 && record.state() == SlotState::Confirmed
        });
        let failed = [Slot::A, Slot::B].into_iter().any(|slot| {
            let record = current.slot(slot);
            record.digest() == manifest_sha256 && record.state() == SlotState::Failed
        });
        let record_stage = record.stage();
        let terminal = match current.terminal() {
            jasper_lifecycle_model::boot::TransactionTerminal::None => None,
            jasper_lifecycle_model::boot::TransactionTerminal::Complete => {
                if current.transaction_digest() == Some(manifest_sha256) {
                    Some(UpdateStage::Complete)
                } else if update_stage_rank(record_stage) <= update_stage_rank(UpdateStage::Prepared)
                {
                    // A prepared journal is newer than the last completed
                    // control transaction. Its terminal belongs to the
                    // previous transaction and must not be rebound to this
                    // manifest.
                    None
                } else {
                    return Err(CoordinatorError::Control(
                        BootControlError::TerminalIdentityMismatch,
                    ));
                }
            }
            jasper_lifecycle_model::boot::TransactionTerminal::RolledBack => {
                if current.transaction_digest() == Some(manifest_sha256) {
                    Some(UpdateStage::RolledBack)
                } else if update_stage_rank(record_stage) <= update_stage_rank(UpdateStage::Prepared)
                {
                    None
                } else {
                    return Err(CoordinatorError::Control(
                        BootControlError::TerminalIdentityMismatch,
                    ));
                }
            }
        };
        let mut target = record_stage;
        if failed && update_stage_rank(record_stage) < update_stage_rank(UpdateStage::Rollback) {
            target = UpdateStage::Rollback;
        } else if confirmed
            && update_stage_rank(record_stage) < update_stage_rank(UpdateStage::Confirmed)
        {
            target = UpdateStage::Confirmed;
        } else if let Some((_, candidate)) = candidate {
            if candidate.attempts() > 0
                && update_stage_rank(record_stage) < update_stage_rank(UpdateStage::Trial)
            {
                target = UpdateStage::Trial;
            } else if update_stage_rank(record_stage) < update_stage_rank(UpdateStage::Committed) {
                target = UpdateStage::Committed;
            }
        }
        if let Some(terminal) = terminal {
            if update_stage_rank(target) > update_stage_rank(terminal) {
                return Err(CoordinatorError::InconsistentStage {
                    expected: terminal,
                    actual: target,
                });
            }
            target = terminal;
        }
        let mut machine = UpdateMachine::idle();
        advance_update_machine(&mut machine, record_stage).map_err(CoordinatorError::Transition)?;
        let upgrade =
            advance_update_machine(&mut machine, target).map_err(CoordinatorError::Transition)?;
        if !upgrade.is_empty() {
            let mut repaired = record;
            for event in upgrade {
                repaired
                    .apply(event)
                    .map_err(CoordinatorError::Transaction)?;
            }
            persist_transaction_record(staging_root, repaired)
                .map_err(CoordinatorError::Staging)?;
        }
        Ok(Self { machine })
    }

    /// Cancel a prepared update before durable commit and remove its staging tree.
    pub fn cancel_prepared(&mut self, staging_root: &Path) -> Result<(), CoordinatorError> {
        let mut next = self.machine;
        next.apply(UpdateEvent::Cancel)
            .map_err(CoordinatorError::Transition)?;
        fs::remove_dir_all(staging_root).map_err(|source| {
            CoordinatorError::Staging(io_error("cancel prepared staging", staging_root, source))
        })?;
        self.machine = next;
        Ok(())
    }

    /// Commit a staged candidate into the inactive slot and dual-copy control store.
    ///
    /// The coordinator publishes `Committed` only after control flush and readback
    /// succeed. This does not enter a trial boot or claim the candidate is healthy.
    pub fn commit_prepared(
        &mut self,
        prepared: &PreparedUpdate,
        control: &mut FileControlStore,
        slot: Slot,
        transaction_id: u64,
    ) -> Result<ControlBlock, CoordinatorError> {
        if self.stage() != UpdateStage::Prepared {
            return Err(CoordinatorError::InconsistentStage {
                expected: UpdateStage::Prepared,
                actual: self.stage(),
            });
        }
        let mut next = control.current();
        next.stage_candidate(
            slot,
            Candidate {
                release: prepared.manifest.manifest.release_sequence,
                digest: prepared.manifest.manifest.manifest_sha256,
                transaction_id,
                security_epoch: prepared.manifest.manifest.security_epoch,
                data_schema_min: prepared.manifest.data_schema.0,
                data_schema_max: prepared.manifest.data_schema.1,
            },
        )
        .map_err(CoordinatorError::Control)?;
        let mut machine = self.machine;
        machine
            .apply(UpdateEvent::Commit)
            .map_err(CoordinatorError::Transition)?;
        control
            .commit_next(next)
            .map_err(CoordinatorError::ControlStore)?;
        let mut record = prepared.record;
        record
            .apply(UpdateEvent::Commit)
            .map_err(CoordinatorError::Transaction)?;
        persist_transaction_record(&prepared.staging.root, record)
            .map_err(CoordinatorError::Staging)?;
        self.machine = machine;
        Ok(next)
    }

    /// Persist the next candidate boot attempt and enter `Trial`.
    pub fn begin_trial(
        &mut self,
        control: &mut FileControlStore,
        staging_root: &Path,
    ) -> Result<BootDecision, CoordinatorError> {
        if self.stage() != UpdateStage::Committed {
            return Err(CoordinatorError::InconsistentStage {
                expected: UpdateStage::Committed,
                actual: self.stage(),
            });
        }
        let mut next = control.current();
        let decision = next.prepare_boot().map_err(CoordinatorError::Control)?;
        if decision.reason != BootReason::CandidateTrial {
            return Err(CoordinatorError::TrialUnavailable);
        }
        let mut machine = self.machine;
        machine
            .apply(UpdateEvent::BeginTrial)
            .map_err(CoordinatorError::Transition)?;
        control
            .commit_next(next)
            .map_err(CoordinatorError::ControlStore)?;
        let mut record =
            load_transaction_record(staging_root).map_err(CoordinatorError::Staging)?;
        record
            .apply(UpdateEvent::BeginTrial)
            .map_err(CoordinatorError::Transaction)?;
        persist_transaction_record(staging_root, record).map_err(CoordinatorError::Staging)?;
        self.machine = machine;
        Ok(decision)
    }

    /// Persist candidate health and advance to `Confirmed` or `Rollback`.
    pub fn report_candidate_health(
        &mut self,
        control: &mut FileControlStore,
        staging_root: &Path,
        healthy: bool,
    ) -> Result<(), CoordinatorError> {
        if self.stage() != UpdateStage::Trial {
            return Err(CoordinatorError::InconsistentStage {
                expected: UpdateStage::Trial,
                actual: self.stage(),
            });
        }
        let Some((slot, _)) = control.current().candidate() else {
            return Err(CoordinatorError::TrialUnavailable);
        };
        let mut next = control.current();
        next.report_health(slot, healthy)
            .map_err(CoordinatorError::Control)?;
        let event = if healthy {
            UpdateEvent::ConfirmHealth
        } else {
            UpdateEvent::FailHealth
        };
        let mut machine = self.machine;
        machine.apply(event).map_err(CoordinatorError::Transition)?;
        control
            .commit_next(next)
            .map_err(CoordinatorError::ControlStore)?;
        let mut record =
            load_transaction_record(staging_root).map_err(CoordinatorError::Staging)?;
        record.apply(event).map_err(CoordinatorError::Transaction)?;
        persist_transaction_record(staging_root, record).map_err(CoordinatorError::Staging)?;
        self.machine = machine;
        Ok(())
    }

    /// Finalize a health-confirmed update without deleting its audit journal.
    pub fn finalize_confirmed(
        &mut self,
        control: &mut FileControlStore,
        staging_root: &Path,
    ) -> Result<(), CoordinatorError> {
        if self.stage() != UpdateStage::Confirmed {
            return Err(CoordinatorError::InconsistentStage {
                expected: UpdateStage::Confirmed,
                actual: self.stage(),
            });
        }
        let mut machine = self.machine;
        machine
            .apply(UpdateEvent::Finalize)
            .map_err(CoordinatorError::Transition)?;
        let mut record =
            load_transaction_record(staging_root).map_err(CoordinatorError::Staging)?;
        let mut next = control.current();
        next.record_terminal(
            jasper_lifecycle_model::boot::TransactionTerminal::Complete,
            next.transaction_id(),
            record.manifest_sha256(),
        )
        .map_err(CoordinatorError::Control)?;
        control
            .commit_next(next)
            .map_err(CoordinatorError::ControlStore)?;
        record
            .apply(UpdateEvent::Finalize)
            .map_err(CoordinatorError::Transaction)?;
        persist_transaction_record(staging_root, record).map_err(CoordinatorError::Staging)?;
        self.machine = machine;
        Ok(())
    }

    /// Confirm the previous known-good slot after a failed candidate trial.
    pub fn finish_rollback(
        &mut self,
        control: &mut FileControlStore,
        staging_root: &Path,
    ) -> Result<Slot, CoordinatorError> {
        if self.stage() != UpdateStage::Rollback {
            return Err(CoordinatorError::InconsistentStage {
                expected: UpdateStage::Rollback,
                actual: self.stage(),
            });
        }
        let mut next = control.current();
        let slot = next.active_slot();
        next.report_health(slot, true)
            .map_err(CoordinatorError::Control)?;
        let mut record =
            load_transaction_record(staging_root).map_err(CoordinatorError::Staging)?;
        next = next
            .with_terminal(
                jasper_lifecycle_model::boot::TransactionTerminal::RolledBack,
                next.transaction_id(),
                record.manifest_sha256(),
            )
            .map_err(CoordinatorError::Control)?;
        let mut machine = self.machine;
        machine
            .apply(UpdateEvent::FinishRollback)
            .map_err(CoordinatorError::Transition)?;
        control
            .commit_next(next)
            .map_err(CoordinatorError::ControlStore)?;
        record
            .apply(UpdateEvent::FinishRollback)
            .map_err(CoordinatorError::Transaction)?;
        persist_transaction_record(staging_root, record).map_err(CoordinatorError::Staging)?;
        self.machine = machine;
        Ok(slot)
    }
}

/// 暂存失败原因。
/// Staging failure.
#[derive(Debug)]
pub enum StagingError {
    /// 文件系统操作失败。Filesystem operation failed.
    Io {
        /// 失败操作。Failed operation.
        operation: &'static str,
        /// 目标路径。Target path.
        path: PathBuf,
        /// 底层错误。Underlying error.
        source: io::Error,
    },
    /// 验签类型内部字段不一致。Verified type contains inconsistent fields.
    InconsistentManifest(&'static str),
    /// 来源集合缺失、重复或多余。Source set is missing, duplicated or has extras.
    SourceSet(&'static str),
    /// 来源不是普通文件。Source is not a regular file.
    SourceNotRegular(String),
    /// 工件大小不符。Artifact size mismatch.
    Size {
        /// 工件名。Artifact name.
        name: String,
        /// 清单声明大小。Declared size.
        expected: u64,
        /// 实际大小。Actual size.
        actual: u64,
    },
    /// 工件摘要不符。Artifact digest mismatch.
    Digest {
        /// 工件名。Artifact name.
        name: String,
    },
    /// 清单摘要不符。Manifest digest mismatch.
    ManifestDigest,
    /// 暂存目录已存在。Staging path already exists.
    AlreadyExists(PathBuf),
    /// 清理未完成的暂存目录失败。Failed to remove a partially staged directory.
    Cleanup {
        /// 原始失败。Original failure.
        cause: Box<StagingError>,
        /// 清理失败。Cleanup failure.
        cleanup: io::Error,
    },
    /// The transaction is not in a terminal success/rollback state.
    NotTerminal(UpdateStage),
    /// The audit archive does not match the staging transaction.
    ArchiveMismatch,
    /// 磁盘可用空间不足。Available disk space is insufficient.
    InsufficientSpace {
        /// 当前可用字节。Available bytes.
        available: u64,
        /// 所需字节。Required bytes.
        required: u64,
    },
    /// 磁盘预算算术溢出。Disk-budget arithmetic overflowed.
    BudgetOverflow,
    /// 目标文件系统返回不可用几何参数。Destination filesystem returned unusable geometry.
    InvalidFilesystem(&'static str),
    /// 本地安装授权或清单安全验证失败。Local install authorization or manifest security verification failed.
    Manifest(ManifestError),
    /// 清单声明的直接依赖不在当前本地快照中。A declared direct dependency is absent from the local snapshot.
    MissingDependency(String),
    /// 依赖快照包含空名或重复名。Dependency snapshot contains an empty or duplicate name.
    InvalidDependencySnapshot,
    /// 交易记录损坏或状态不一致。Transaction record is corrupt or inconsistent.
    Transaction(TransactionError),
}

impl fmt::Display for StagingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io {
                operation,
                path,
                source,
            } => write!(
                formatter,
                "{operation} failed for {}: {source}",
                path.display()
            ),
            Self::InconsistentManifest(reason) => {
                write!(formatter, "inconsistent verified manifest: {reason}")
            }
            Self::SourceSet(reason) => write!(formatter, "invalid artifact source set: {reason}"),
            Self::SourceNotRegular(name) => {
                write!(formatter, "artifact source is not a regular file: {name}")
            }
            Self::Size {
                name,
                expected,
                actual,
            } => write!(
                formatter,
                "artifact {name} size mismatch: expected {expected}, got {actual}"
            ),
            Self::Digest { name } => write!(formatter, "artifact {name} digest mismatch"),
            Self::ManifestDigest => write!(formatter, "verified manifest bytes digest mismatch"),
            Self::AlreadyExists(path) => {
                write!(formatter, "staging path already exists: {}", path.display())
            }
            Self::Cleanup { cause, cleanup } => {
                write!(formatter, "{cause}; staging cleanup failed: {cleanup}")
            }
            Self::NotTerminal(stage) => {
                write!(formatter, "transaction is not terminal: {stage:?}")
            }
            Self::ArchiveMismatch => write!(formatter, "archive does not match staging journal"),
            Self::InsufficientSpace {
                available,
                required,
            } => write!(
                formatter,
                "insufficient staging space: available {available}, required {required}"
            ),
            Self::BudgetOverflow => write!(formatter, "staging disk budget overflowed"),
            Self::InvalidFilesystem(reason) => {
                write!(
                    formatter,
                    "invalid destination filesystem geometry: {reason}"
                )
            }
            Self::Manifest(error) => write!(formatter, "manifest verification failed: {error:?}"),
            Self::MissingDependency(name) => {
                write!(formatter, "manifest dependency is not installed: {name}")
            }
            Self::InvalidDependencySnapshot => {
                write!(
                    formatter,
                    "dependency snapshot contains an empty or duplicate name"
                )
            }
            Self::Transaction(error) => write!(formatter, "transaction record failed: {error:?}"),
        }
    }
}

impl std::error::Error for StagingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Cleanup { cleanup, .. } => Some(cleanup),
            _ => None,
        }
    }
}

/// 建立新的暂存目录，写入精确清单和全部来源工件，刷新并读回复核。
///
/// 目标目录必须不存在；本函数不会覆盖现有目录。任何失败都会删除本次新建的目录。
/// Creates a fresh staging directory, writes the exact manifest and every source artifact,
/// flushes and reads them back. The destination must not exist and is removed on failure.
pub fn stage_verified_artifacts(
    manifest: &VerifiedCborManifest,
    manifest_bytes: &[u8],
    sources: &[ArtifactSource<'_>],
    staging_root: &Path,
) -> Result<StagingReceipt, StagingError> {
    if manifest_bytes.is_empty() || manifest_bytes.len() > MAX_MANIFEST_CBOR_BYTES {
        return Err(StagingError::InconsistentManifest(
            "manifest CBOR length is out of bounds",
        ));
    }
    if Sha256::digest(manifest_bytes).as_slice() != manifest.manifest.manifest_sha256.as_slice() {
        return Err(StagingError::ManifestDigest);
    }
    validate_declared_total(manifest)?;
    match fs::symlink_metadata(staging_root) {
        Ok(_) => return Err(StagingError::AlreadyExists(staging_root.to_path_buf())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(io_error(
                "inspect staging destination",
                staging_root,
                source,
            ))
        }
    }
    let parent = staging_root
        .parent()
        .ok_or(StagingError::InconsistentManifest(
            "staging root has no parent directory",
        ))?;
    check_disk_budget(manifest, manifest_bytes.len() as u64, parent, 0)?;
    let sources = source_map(sources, &manifest.artifacts)?;

    fs::create_dir(staging_root)
        .map_err(|source| io_error("create staging root", staging_root, source))?;
    let result = write_staging(manifest, manifest_bytes, &sources, staging_root);
    match result {
        Ok(receipt) => Ok(receipt),
        Err(cause) => match fs::remove_dir_all(staging_root) {
            Ok(()) => Err(cause),
            Err(cleanup) => Err(StagingError::Cleanup {
                cause: Box::new(cause),
                cleanup,
            }),
        },
    }
}

/// 串联本地安装授权、直接依赖、磁盘预算和持久暂存。
///
/// `manifest` 必须来自规范 CBOR 和签名验证。成功只表示可进入非活动暂存，不表示
/// 交易已提交、槽位已激活或系统可启动。
/// Chains local install authorization, direct dependencies, disk budget and durable staging.
/// The manifest must originate from canonical-CBOR and signature verification. Success only
/// means the payload may remain staged; it is not a commit, activation or bootability claim.
#[allow(clippy::too_many_arguments)]
pub fn prepare_update(
    manifest: VerifiedCborManifest,
    manifest_bytes: &[u8],
    grant: LocalInstallGrant,
    now: u64,
    installed_dependencies: &[String],
    sources: &[ArtifactSource<'_>],
    staging_root: &Path,
    metadata_headroom: u64,
) -> Result<PreparedUpdate, StagingError> {
    authorize_install(manifest.manifest, grant, now).map_err(StagingError::Manifest)?;
    check_dependency_snapshot(&manifest.dependencies, installed_dependencies)?;
    let destination_parent = staging_root
        .parent()
        .ok_or(StagingError::InconsistentManifest(
            "staging root has no parent directory",
        ))?;
    let budget = check_disk_budget(
        &manifest,
        manifest_bytes.len() as u64,
        destination_parent,
        metadata_headroom,
    )?;
    let staging = stage_verified_artifacts(&manifest, manifest_bytes, sources, staging_root)?;
    let record = match persist_prepared_transaction(staging_root, manifest.manifest.manifest_sha256)
    {
        Ok(record) => record,
        Err(error) => {
            return match fs::remove_dir_all(staging_root) {
                Ok(()) => Err(error),
                Err(cleanup) => Err(StagingError::Cleanup {
                    cause: Box::new(error),
                    cleanup,
                }),
            }
        }
    };
    Ok(PreparedUpdate {
        manifest,
        budget,
        staging,
        record,
    })
}

/// 验证清单的直接依赖全部存在于当前本地已安装名称快照。
/// Verifies that every direct manifest dependency exists in the local installed-name snapshot.
pub fn check_dependency_snapshot(
    required: &[String],
    installed: &[String],
) -> Result<(), StagingError> {
    let mut unique = BTreeSet::new();
    for name in installed {
        if name.is_empty() || !unique.insert(name.as_str()) {
            return Err(StagingError::InvalidDependencySnapshot);
        }
    }
    for dependency in required {
        if !unique.contains(dependency.as_str()) {
            return Err(StagingError::MissingDependency(dependency.clone()));
        }
    }
    Ok(())
}

/// 把 Prepared 交易的相同完整记录写入两份副本并刷新目录。
/// Writes the same complete Prepared record to both copies and flushes the directory.
pub fn persist_prepared_transaction(
    staging_root: &Path,
    manifest_sha256: [u8; 32],
) -> Result<TransactionRecord, StagingError> {
    let record = TransactionRecord::prepared(manifest_sha256).map_err(StagingError::Transaction)?;
    let bytes = record.encode();
    for name in TRANSACTION_COPIES {
        write_new(&staging_root.join(name), &bytes)?;
    }
    sync_directory(staging_root)?;
    let first = read_file(&staging_root.join(TRANSACTION_COPIES[0]))?;
    let second = read_file(&staging_root.join(TRANSACTION_COPIES[1]))?;
    let recovered = recover(Some(&first), Some(&second)).map_err(StagingError::Transaction)?;
    if recovered != record {
        return Err(StagingError::Transaction(
            TransactionError::EqualGenerationMismatch,
        ));
    }
    Ok(recovered)
}

/// 恢复并验证指定清单的 Prepared 交易；单副本损坏时使用另一份完整副本。
/// Recovers and validates the Prepared transaction for one manifest, using the intact copy
/// when one copy is torn.
pub fn load_prepared_transaction(
    staging_root: &Path,
    manifest_sha256: [u8; 32],
) -> Result<TransactionRecord, StagingError> {
    let first = read_optional_file(&staging_root.join(TRANSACTION_COPIES[0]))?;
    let second = read_optional_file(&staging_root.join(TRANSACTION_COPIES[1]))?;
    let record = recover(first.as_deref(), second.as_deref()).map_err(StagingError::Transaction)?;
    if record.stage() != UpdateStage::Prepared || record.manifest_sha256() != manifest_sha256 {
        return Err(StagingError::Transaction(TransactionError::InvalidState));
    }
    Ok(record)
}

/// Recover the newest transaction record without requiring a specific phase.
pub fn load_transaction_record(staging_root: &Path) -> Result<TransactionRecord, StagingError> {
    let first = read_optional_file(&staging_root.join(TRANSACTION_COPIES[0]))?;
    let second = read_optional_file(&staging_root.join(TRANSACTION_COPIES[1]))?;
    recover(first.as_deref(), second.as_deref()).map_err(StagingError::Transaction)
}

/// Atomically replace journal copies with one validated transaction record.
pub fn persist_transaction_record(
    staging_root: &Path,
    record: TransactionRecord,
) -> Result<(), StagingError> {
    let bytes = record.encode();
    for name in TRANSACTION_COPIES {
        let target = staging_root.join(name);
        let temporary = staging_root.join(format!(".{name}.tmp-{}", now_nanos()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|source| io_error("create transaction journal", &temporary, source))?;
        if let Err(source) = file.write_all(&bytes).and_then(|_| file.sync_all()) {
            drop(file);
            let _ = fs::remove_file(&temporary);
            return Err(io_error("write transaction journal", &temporary, source));
        }
        drop(file);
        if let Err(source) = fs::rename(&temporary, &target) {
            let _ = fs::remove_file(&temporary);
            return Err(io_error("replace transaction journal", &target, source));
        }
    }
    sync_directory(staging_root)
}

/// Archive the exact manifest and dual journal of a terminal update.
pub fn archive_completed_transaction(
    staging_root: &Path,
    archive_root: &Path,
) -> Result<ArchivedTransaction, StagingError> {
    let record = load_transaction_record(staging_root)?;
    if !matches!(
        record.stage(),
        UpdateStage::Complete | UpdateStage::RolledBack
    ) {
        return Err(StagingError::NotTerminal(record.stage()));
    }
    match fs::symlink_metadata(archive_root) {
        Ok(_) => return Err(StagingError::AlreadyExists(archive_root.to_path_buf())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(io_error(
                "inspect transaction archive",
                archive_root,
                source,
            ))
        }
    }
    fs::create_dir(archive_root)
        .map_err(|source| io_error("create transaction archive", archive_root, source))?;
    let result = (|| {
        let manifest = read_file(&staging_root.join(MANIFEST_FILE))?;
        if Sha256::digest(&manifest).as_slice() != record.manifest_sha256() {
            return Err(StagingError::ArchiveMismatch);
        }
        write_new(&archive_root.join(MANIFEST_FILE), &manifest)?;
        for name in TRANSACTION_COPIES {
            let bytes = read_file(&staging_root.join(name))?;
            write_new(&archive_root.join(name), &bytes)?;
        }
        sync_directory(archive_root)
    })();
    if let Err(error) = result {
        let _ = fs::remove_dir_all(archive_root);
        return Err(error);
    }
    Ok(ArchivedTransaction {
        root: archive_root.to_path_buf(),
        manifest_sha256: record.manifest_sha256(),
        record,
    })
}

/// Reopen an already-published terminal transaction archive.
pub fn load_archived_transaction(archive_root: &Path) -> Result<ArchivedTransaction, StagingError> {
    let record = load_transaction_record(archive_root)?;
    if !matches!(
        record.stage(),
        UpdateStage::Complete | UpdateStage::RolledBack
    ) {
        return Err(StagingError::NotTerminal(record.stage()));
    }
    let manifest = read_file(&archive_root.join(MANIFEST_FILE))?;
    if Sha256::digest(&manifest).as_slice() != record.manifest_sha256() {
        return Err(StagingError::ArchiveMismatch);
    }
    Ok(ArchivedTransaction {
        root: archive_root.to_path_buf(),
        manifest_sha256: record.manifest_sha256(),
        record,
    })
}

/// Remove staging only after the terminal journal is archived byte-for-byte.
pub fn cleanup_staged_transaction(
    staging_root: &Path,
    archive: &ArchivedTransaction,
) -> Result<(), StagingError> {
    let staged = load_transaction_record(staging_root)?;
    let archived = load_transaction_record(&archive.root)?;
    if staged != archive.record
        || archived != archive.record
        || staged.manifest_sha256() != archive.manifest_sha256
    {
        return Err(StagingError::ArchiveMismatch);
    }
    let manifest = read_file(&archive.root.join(MANIFEST_FILE))?;
    if Sha256::digest(&manifest).as_slice() != archive.manifest_sha256 {
        return Err(StagingError::ArchiveMismatch);
    }
    let parent = staging_root
        .parent()
        .ok_or(StagingError::InconsistentManifest(
            "staging root has no parent",
        ))?;
    fs::remove_dir_all(staging_root)
        .map_err(|source| io_error("remove staged transaction", staging_root, source))?;
    sync_directory(parent)
}

/// 按实际文件系统块大小检查暂存预算；`metadata_headroom` 由协调器显式提供。
/// Checks staging capacity using real filesystem blocks; metadata headroom is explicit.
pub fn check_disk_budget(
    manifest: &VerifiedCborManifest,
    manifest_bytes: u64,
    destination_parent: &Path,
    metadata_headroom: u64,
) -> Result<DiskBudget, StagingError> {
    validate_declared_total(manifest)?;
    if manifest_bytes == 0 || manifest_bytes > MAX_MANIFEST_CBOR_BYTES as u64 {
        return Err(StagingError::InconsistentManifest(
            "manifest CBOR length is out of bounds",
        ));
    }
    let stats = rustix::fs::statvfs(destination_parent).map_err(|source| {
        io_error(
            "read destination filesystem capacity",
            destination_parent,
            source.into(),
        )
    })?;
    if stats.f_frsize == 0 {
        return Err(StagingError::InvalidFilesystem(
            "filesystem block size is zero",
        ));
    }
    let block_size = stats.f_frsize;
    let available_bytes = stats
        .f_bavail
        .checked_mul(block_size)
        .ok_or(StagingError::BudgetOverflow)?;
    let mut required_bytes = round_up(manifest_bytes, block_size)?;
    for artifact in &manifest.artifacts {
        required_bytes = required_bytes
            .checked_add(round_up(artifact.size, block_size)?)
            .ok_or(StagingError::BudgetOverflow)?;
    }
    required_bytes = required_bytes
        .checked_add(metadata_headroom)
        .ok_or(StagingError::BudgetOverflow)?;
    if available_bytes < required_bytes {
        return Err(StagingError::InsufficientSpace {
            available: available_bytes,
            required: required_bytes,
        });
    }
    Ok(DiskBudget {
        available_bytes,
        required_bytes,
        block_size,
    })
}

fn validate_declared_total(manifest: &VerifiedCborManifest) -> Result<(), StagingError> {
    let declared_total = manifest
        .artifacts
        .iter()
        .try_fold(0u64, |total, artifact| total.checked_add(artifact.size))
        .ok_or(StagingError::InconsistentManifest(
            "artifact byte sum overflowed",
        ))?;
    if declared_total != manifest.artifact_bytes {
        return Err(StagingError::InconsistentManifest(
            "artifact byte sum does not match the receipt",
        ));
    }
    Ok(())
}

fn round_up(value: u64, block_size: u64) -> Result<u64, StagingError> {
    if value == 0 {
        return Ok(0);
    }
    value
        .checked_add(block_size - 1)
        .map(|rounded| rounded / block_size * block_size)
        .ok_or(StagingError::BudgetOverflow)
}

fn source_map<'a>(
    sources: &'a [ArtifactSource<'_>],
    artifacts: &[VerifiedArtifact],
) -> Result<BTreeMap<&'a str, &'a Path>, StagingError> {
    if sources.len() != artifacts.len() {
        return Err(StagingError::SourceSet(
            "source and manifest artifact counts differ",
        ));
    }
    let mut result = BTreeMap::new();
    for source in sources {
        if result.insert(source.name, source.path).is_some() {
            return Err(StagingError::SourceSet("duplicate source name"));
        }
    }
    for artifact in artifacts {
        if !result.contains_key(artifact.name.as_str()) {
            return Err(StagingError::SourceSet("source name is missing"));
        }
    }
    Ok(result)
}

fn write_staging(
    manifest: &VerifiedCborManifest,
    manifest_bytes: &[u8],
    sources: &BTreeMap<&str, &Path>,
    staging_root: &Path,
) -> Result<StagingReceipt, StagingError> {
    let artifact_root = staging_root.join(ARTIFACT_DIR);
    fs::create_dir(&artifact_root)
        .map_err(|source| io_error("create artifact directory", &artifact_root, source))?;

    let manifest_path = staging_root.join(MANIFEST_FILE);
    write_new(&manifest_path, manifest_bytes)?;
    let manifest_readback = read_file(&manifest_path)?;
    if Sha256::digest(&manifest_readback).as_slice() != manifest.manifest.manifest_sha256.as_slice()
    {
        return Err(StagingError::ManifestDigest);
    }

    let mut staged = Vec::with_capacity(manifest.artifacts.len());
    for artifact in &manifest.artifacts {
        let source_path = sources
            .get(artifact.name.as_str())
            .ok_or(StagingError::SourceSet("source name is missing"))?;
        let relative_path = PathBuf::from(ARTIFACT_DIR).join(&artifact.name);
        let destination = staging_root.join(&relative_path);
        copy_exact_artifact(source_path, &destination, artifact)?;
        verify_readback(&destination, artifact)?;
        staged.push(StagedArtifact {
            kind: artifact.kind,
            name: artifact.name.clone(),
            size: artifact.size,
            sha256: artifact.sha256,
            relative_path,
        });
    }
    sync_directory(&artifact_root)?;
    sync_directory(staging_root)?;
    let parent = staging_root
        .parent()
        .ok_or(StagingError::InconsistentManifest(
            "staging root has no parent directory",
        ))?;
    sync_directory(parent)?;
    Ok(StagingReceipt {
        root: staging_root.to_path_buf(),
        manifest_sha256: manifest.manifest.manifest_sha256,
        manifest_bytes: manifest_bytes.len() as u64,
        artifact_bytes: manifest.artifact_bytes,
        artifacts: staged,
    })
}

fn copy_exact_artifact(
    source_path: &Path,
    destination: &Path,
    artifact: &VerifiedArtifact,
) -> Result<(), StagingError> {
    let metadata = fs::symlink_metadata(source_path)
        .map_err(|source| io_error("inspect artifact source", source_path, source))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(StagingError::SourceNotRegular(artifact.name.clone()));
    }
    let mut source = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(source_path)
        .map_err(|source| io_error("open artifact source", source_path, source))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|source| io_error("create staged artifact", destination, source))?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; COPY_BUFFER_BYTES];
    loop {
        let count = source
            .read(&mut buffer)
            .map_err(|source| io_error("read artifact source", source_path, source))?;
        if count == 0 {
            break;
        }
        total = total.checked_add(count as u64).ok_or(StagingError::Size {
            name: artifact.name.clone(),
            expected: artifact.size,
            actual: u64::MAX,
        })?;
        if total > artifact.size {
            return Err(StagingError::Size {
                name: artifact.name.clone(),
                expected: artifact.size,
                actual: total,
            });
        }
        hasher.update(&buffer[..count]);
        output
            .write_all(&buffer[..count])
            .map_err(|source| io_error("write staged artifact", destination, source))?;
    }
    if total != artifact.size {
        return Err(StagingError::Size {
            name: artifact.name.clone(),
            expected: artifact.size,
            actual: total,
        });
    }
    if hasher.finalize().as_slice() != artifact.sha256.as_slice() {
        return Err(StagingError::Digest {
            name: artifact.name.clone(),
        });
    }
    output
        .sync_all()
        .map_err(|source| io_error("flush staged artifact", destination, source))
}

fn verify_readback(path: &Path, artifact: &VerifiedArtifact) -> Result<(), StagingError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| io_error("open staged artifact", path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| io_error("inspect staged artifact", path, source))?;
    if !metadata.is_file() || metadata.len() != artifact.size {
        return Err(StagingError::Size {
            name: artifact.name.clone(),
            expected: artifact.size,
            actual: metadata.len(),
        });
    }
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; COPY_BUFFER_BYTES];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|source| io_error("read staged artifact", path, source))?;
        if count == 0 {
            break;
        }
        total += count as u64;
        hasher.update(&buffer[..count]);
    }
    if total != artifact.size {
        return Err(StagingError::Size {
            name: artifact.name.clone(),
            expected: artifact.size,
            actual: total,
        });
    }
    if hasher.finalize().as_slice() != artifact.sha256.as_slice() {
        return Err(StagingError::Digest {
            name: artifact.name.clone(),
        });
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), StagingError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| io_error("create staged file", path, source))?;
    file.write_all(bytes)
        .map_err(|source| io_error("write staged file", path, source))?;
    file.sync_all()
        .map_err(|source| io_error("flush staged file", path, source))
}

fn read_file(path: &Path) -> Result<Vec<u8>, StagingError> {
    fs::read(path).map_err(|source| io_error("read staged file", path, source))
}

fn read_optional_file(path: &Path) -> Result<Option<Vec<u8>>, StagingError> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(io_error("read staged file", path, source)),
    }
}

fn sync_directory(path: &Path) -> Result<(), StagingError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error("flush directory", path, source))
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> StagingError {
    StagingError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

/// One active transaction held by the lifecycle update service.
struct ServiceUpdate {
    generation: u64,
    coordinator: UpdateCoordinator,
    prepared: Option<PreparedUpdate>,
    staging_root: PathBuf,
    manifest_sha256: [u8; 32],
    recovery_required: bool,
}

/// Stable service-level status for one update operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceStatus {
    /// Service command generation; every prepare or recovery advances it.
    pub generation: u64,
    /// Coordinator stage, or `None` when no update is active.
    pub stage: Option<UpdateStage>,
    /// Active transaction digest.
    pub manifest_sha256: Option<[u8; 32]>,
    /// Active staging root.
    pub staging_root: Option<PathBuf>,
    /// Control-store active slot.
    pub active_slot: Slot,
    /// Candidate slot, if the control record contains one.
    pub candidate_slot: Option<Slot>,
    /// Current control transaction id.
    pub transaction_id: u64,
    /// A mutating operation may have crossed a durable control/journal boundary.
    pub recovery_required: bool,
}

/// Path-free identity of the service's currently active transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionBinding {
    /// Service generation bound to the active transaction.
    pub generation: u64,
    /// Authoritative boot-control transaction identifier.
    pub transaction_id: u64,
    /// Verified manifest digest bound to the active transaction.
    pub manifest_sha256: [u8; 32],
}

/// Service lifecycle error.
#[derive(Debug)]
pub enum ServiceError {
    /// Another transaction is already active.
    Busy,
    /// No transaction is active.
    NoActive,
    /// The caller used a stale service generation.
    StaleGeneration {
        /// Generation expected by the service.
        expected: u64,
        /// Generation supplied by the caller.
        actual: u64,
    },
    /// The operation is not valid in the current coordinator stage.
    WrongStage {
        /// Required coordinator stage.
        expected: UpdateStage,
        /// Actual coordinator stage.
        actual: UpdateStage,
    },
    /// The prepared transaction value is no longer available.
    PreparedUnavailable,
    /// Recovery arguments do not match the active faulted transaction.
    RecoveryTargetMismatch,
    /// No trusted archive root was configured for this service instance.
    ArchiveRootUnavailable,
    /// The durable terminal-archive receipt store failed.
    Archive(ArchiveError),
    /// Underlying coordinator operation failed.
    Coordinator(CoordinatorError),
    /// Terminal transaction archiving failed.
    Staging(StagingError),
}

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Busy => write!(formatter, "an update transaction is already active"),
            Self::NoActive => write!(formatter, "no update transaction is active"),
            Self::StaleGeneration { expected, actual } => {
                write!(
                    formatter,
                    "stale service generation: expected {expected}, got {actual}"
                )
            }
            Self::WrongStage { expected, actual } => {
                write!(
                    formatter,
                    "wrong update stage: expected {expected:?}, got {actual:?}"
                )
            }
            Self::PreparedUnavailable => write!(formatter, "prepared transaction is unavailable"),
            Self::RecoveryTargetMismatch => {
                write!(
                    formatter,
                    "recovery target does not match the active transaction"
                )
            }
            Self::ArchiveRootUnavailable => {
                write!(formatter, "no archive root is configured for this service")
            }
            Self::Archive(error) => write!(formatter, "terminal archive receipt failed: {error:?}"),
            Self::Coordinator(error) => write!(formatter, "{error}"),
            Self::Staging(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for ServiceError {}

impl From<CoordinatorError> for ServiceError {
    fn from(value: CoordinatorError) -> Self {
        Self::Coordinator(value)
    }
}

/// Stateful system-service facade over the single update coordinator and control store.
///
/// The facade does not create another authorization or trust path. Prepare calls still
/// require a `LocalInstallGrant`, online/offline sources still pass the same manifest
/// verification, and every mutating method delegates durable effects to
/// [`UpdateCoordinator`] and [`FileControlStore`].
pub struct UpdateService {
    control: FileControlStore,
    active: Option<ServiceUpdate>,
    next_generation: u64,
    archive_root: Option<PathBuf>,
    archive_ledger_root: Option<PathBuf>,
}

impl UpdateService {
    /// Open an existing dual-copy control store without creating a transaction.
    pub fn open(control_root: impl Into<PathBuf>) -> Result<Self, CoordinatorError> {
        let control =
            FileControlStore::open(control_root).map_err(CoordinatorError::ControlStore)?;
        let next_generation = control.current().generation().saturating_add(1);
        Ok(Self {
            control,
            active: None,
            next_generation,
            archive_root: None,
            archive_ledger_root: None,
        })
    }

    /// Initialize a fresh service control store.
    pub fn initialize(
        control_root: impl Into<PathBuf>,
        block: ControlBlock,
    ) -> Result<Self, CoordinatorError> {
        let control = FileControlStore::initialize(control_root, block)
            .map_err(CoordinatorError::ControlStore)?;
        let next_generation = control.current().generation().saturating_add(1);
        Ok(Self {
            control,
            active: None,
            next_generation,
            archive_root: None,
            archive_ledger_root: None,
        })
    }

    /// Open a managed service whose archive destination is configured by the
    /// trusted operator rather than by individual action callers.
    pub fn open_managed(
        control_root: impl Into<PathBuf>,
        archive_root: impl Into<PathBuf>,
    ) -> Result<Self, CoordinatorError> {
        let mut service = Self::open(control_root)?;
        service.archive_root = Some(archive_root.into());
        Ok(service)
    }

    /// Configure the trusted dual-copy archive-receipt ledger.
    ///
    /// The path is operator configuration, not part of an action request. The
    /// destination must already exist and is checked before any transaction can
    /// publish an archive receipt.
    pub fn configure_archive_ledger(
        &mut self,
        root: impl Into<PathBuf>,
    ) -> Result<(), ServiceError> {
        let root = root.into();
        FileArchiveStore::open(&root).map_err(ServiceError::Archive)?;
        self.archive_ledger_root = Some(root);
        Ok(())
    }

    /// Return a stable snapshot of the active transaction and control state.
    pub fn status(&self) -> ServiceStatus {
        let current = self.control.current();
        let candidate_slot = current.candidate().map(|(slot, _)| slot);
        match self.active.as_ref() {
            Some(active) => ServiceStatus {
                generation: active.generation,
                stage: Some(active.coordinator.stage()),
                manifest_sha256: Some(active.manifest_sha256),
                staging_root: Some(active.staging_root.clone()),
                active_slot: current.active_slot(),
                candidate_slot,
                transaction_id: current.transaction_id(),
                recovery_required: active.recovery_required,
            },
            None => ServiceStatus {
                generation: self.next_generation.saturating_sub(1),
                stage: None,
                manifest_sha256: None,
                staging_root: None,
                active_slot: current.active_slot(),
                candidate_slot,
                transaction_id: current.transaction_id(),
                recovery_required: false,
            },
        }
    }

    /// Return the active transaction identity without exposing internal paths.
    pub fn binding(&self) -> Result<TransactionBinding, ServiceError> {
        let active = self.active.as_ref().ok_or(ServiceError::NoActive)?;
        Ok(TransactionBinding {
            generation: active.generation,
            transaction_id: self.control.current().transaction_id(),
            manifest_sha256: active.manifest_sha256,
        })
    }

    /// Authorize, preflight and stage a verified manifest through the service.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        &mut self,
        manifest: VerifiedCborManifest,
        manifest_bytes: &[u8],
        grant: LocalInstallGrant,
        now: u64,
        installed_dependencies: &[String],
        sources: &[ArtifactSource<'_>],
        staging_root: &Path,
        metadata_headroom: u64,
    ) -> Result<ServiceStatus, ServiceError> {
        self.require_idle()?;
        let generation = self.peek_generation()?;
        let mut coordinator = UpdateCoordinator::idle();
        let prepared = coordinator.prepare(
            manifest,
            manifest_bytes,
            grant,
            now,
            installed_dependencies,
            sources,
            staging_root,
            metadata_headroom,
        )?;
        let manifest_sha256 = prepared.manifest.manifest.manifest_sha256;
        self.publish_active(
            generation,
            coordinator,
            prepared,
            staging_root,
            manifest_sha256,
        )?;
        Ok(self.status())
    }

    /// Acquire and stage one authenticated online or offline update bundle.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_from_source<S: UpdateBundleSource + ?Sized>(
        &mut self,
        policy: TrustPolicy<'_>,
        target: UpdateTarget,
        source: &S,
        grant: LocalInstallGrant,
        now: u64,
        installed_dependencies: &[String],
        staging_root: &Path,
        metadata_headroom: u64,
    ) -> Result<ServiceStatus, ServiceError> {
        self.require_idle()?;
        let generation = self.peek_generation()?;
        let mut coordinator = UpdateCoordinator::idle();
        let prepared = coordinator.prepare_from_source(
            policy,
            target,
            source,
            grant,
            now,
            installed_dependencies,
            staging_root,
            metadata_headroom,
        )?;
        let manifest_sha256 = prepared.manifest.manifest.manifest_sha256;
        self.publish_active(
            generation,
            coordinator,
            prepared,
            staging_root,
            manifest_sha256,
        )?;
        Ok(self.status())
    }

    /// Commit the prepared candidate into the inactive slot and dual-copy control store.
    pub fn commit(
        &mut self,
        generation: u64,
        slot: Slot,
        transaction_id: u64,
    ) -> Result<ServiceStatus, ServiceError> {
        let active = Self::require_generation(&mut self.active, generation)?;
        let expected = UpdateStage::Prepared;
        if active.coordinator.stage() != expected {
            return Err(ServiceError::WrongStage {
                expected,
                actual: active.coordinator.stage(),
            });
        }
        let prepared = active
            .prepared
            .as_ref()
            .ok_or(ServiceError::PreparedUnavailable)?;
        if let Err(error) =
            active
                .coordinator
                .commit_prepared(prepared, &mut self.control, slot, transaction_id)
        {
            active.recovery_required = true;
            return Err(ServiceError::Coordinator(error));
        }
        active.prepared = None;
        Ok(self.status())
    }

    /// Persist the next trial attempt and return the boot decision.
    pub fn begin_trial(&mut self, generation: u64) -> Result<BootDecision, ServiceError> {
        let active = Self::require_generation(&mut self.active, generation)?;
        Self::require_stage(active, UpdateStage::Committed)?;
        let decision = active
            .coordinator
            .begin_trial(&mut self.control, &active.staging_root);
        match decision {
            Ok(decision) => Ok(decision),
            Err(error) => {
                active.recovery_required = true;
                Err(ServiceError::Coordinator(error))
            }
        }
    }

    /// Record candidate health and advance to Confirmed or Rollback.
    pub fn report_health(
        &mut self,
        generation: u64,
        healthy: bool,
    ) -> Result<ServiceStatus, ServiceError> {
        let active = Self::require_generation(&mut self.active, generation)?;
        Self::require_stage(active, UpdateStage::Trial)?;
        if let Err(error) = active.coordinator.report_candidate_health(
            &mut self.control,
            &active.staging_root,
            healthy,
        ) {
            active.recovery_required = true;
            return Err(ServiceError::Coordinator(error));
        }
        Ok(self.status())
    }

    /// Finalize a confirmed candidate while retaining the audit journal.
    pub fn finalize_confirmed(&mut self, generation: u64) -> Result<ServiceStatus, ServiceError> {
        let active = Self::require_generation(&mut self.active, generation)?;
        Self::require_stage(active, UpdateStage::Confirmed)?;
        if let Err(error) = active
            .coordinator
            .finalize_confirmed(&mut self.control, &active.staging_root)
        {
            active.recovery_required = true;
            return Err(ServiceError::Coordinator(error));
        }
        Ok(self.status())
    }

    /// Confirm the previous known-good slot after a failed candidate.
    pub fn finish_rollback(&mut self, generation: u64) -> Result<Slot, ServiceError> {
        let active = Self::require_generation(&mut self.active, generation)?;
        Self::require_stage(active, UpdateStage::Rollback)?;
        match active
            .coordinator
            .finish_rollback(&mut self.control, &active.staging_root)
        {
            Ok(slot) => Ok(slot),
            Err(error) => {
                active.recovery_required = true;
                Err(ServiceError::Coordinator(error))
            }
        }
    }

    /// Cancel a prepared update before commit.
    pub fn cancel_prepared(&mut self, generation: u64) -> Result<ServiceStatus, ServiceError> {
        let active = Self::require_generation(&mut self.active, generation)?;
        Self::require_stage(active, UpdateStage::Prepared)?;
        active.coordinator.cancel_prepared(&active.staging_root)?;
        self.active = None;
        Ok(self.status())
    }

    /// Recover the active transaction from journal plus boot-control state.
    ///
    /// Repeating recovery with the exact same stable target is idempotent: an
    /// already recovered transaction is not replayed into a new service
    /// generation. A different target still fails closed.
    pub fn recover(
        &mut self,
        staging_root: &Path,
        manifest_sha256: [u8; 32],
    ) -> Result<ServiceStatus, ServiceError> {
        let generation = self.peek_generation()?;
        if let Some(active) = self.active.as_ref() {
            if active.staging_root != staging_root || active.manifest_sha256 != manifest_sha256 {
                return Err(ServiceError::RecoveryTargetMismatch);
            }
            if !active.recovery_required {
                return Ok(self.status());
            }
        }
        let coordinator =
            UpdateCoordinator::recover_with_control(staging_root, manifest_sha256, &self.control)?;
        self.publish_recovered(generation, coordinator, staging_root, manifest_sha256)?;
        Ok(self.status())
    }

    /// Recover the active transaction by stable identity without caller paths.
    pub fn recover_bound(
        &mut self,
        binding: TransactionBinding,
    ) -> Result<ServiceStatus, ServiceError> {
        let active = self.active.as_ref().ok_or(ServiceError::NoActive)?;
        if active.generation != binding.generation
            || active.manifest_sha256 != binding.manifest_sha256
            || self.control.current().transaction_id() != binding.transaction_id
        {
            return Err(ServiceError::RecoveryTargetMismatch);
        }
        let staging_root = active.staging_root.clone();
        self.recover(&staging_root, binding.manifest_sha256)
    }

    /// Archive and remove a Complete or RolledBack staging tree.
    pub fn archive_and_cleanup(
        &mut self,
        generation: u64,
        archive_root: &Path,
    ) -> Result<ArchivedTransaction, ServiceError> {
        let active = Self::require_generation(&mut self.active, generation)?;
        match active.coordinator.stage() {
            UpdateStage::Complete | UpdateStage::RolledBack => {}
            actual => {
                return Err(ServiceError::WrongStage {
                    expected: UpdateStage::Complete,
                    actual,
                })
            }
        }
        let archive = match fs::symlink_metadata(archive_root) {
            Ok(metadata) if metadata.is_dir() => {
                load_archived_transaction(archive_root).map_err(ServiceError::Staging)?
            }
            Ok(_) => {
                return Err(ServiceError::Staging(StagingError::AlreadyExists(
                    archive_root.to_path_buf(),
                )))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                archive_completed_transaction(&active.staging_root, archive_root)
                    .map_err(ServiceError::Staging)?
            }
            Err(source) => {
                return Err(ServiceError::Staging(io_error(
                    "inspect transaction archive",
                    archive_root,
                    source,
                )))
            }
        };
        if archive.manifest_sha256 != active.manifest_sha256 {
            return Err(ServiceError::Staging(StagingError::ArchiveMismatch));
        }
        if let Some(root) = self.archive_ledger_root.as_ref() {
            let terminal_stage = active.coordinator.stage();
            FileArchiveStore::open(root)
                .map_err(ServiceError::Archive)?
                .commit_next(
                    self.control.current().transaction_id(),
                    active.manifest_sha256,
                    terminal_stage,
                )
                .map_err(ServiceError::Archive)?;
        }
        cleanup_staged_transaction(&active.staging_root, &archive)
            .map_err(ServiceError::Staging)?;
        self.active = None;
        Ok(archive)
    }

    /// Archive the active terminal transaction through the operator-configured
    /// destination and stable transaction identity.
    pub fn archive_bound(
        &mut self,
        binding: TransactionBinding,
    ) -> Result<ArchivedTransaction, ServiceError> {
        let active = self.active.as_ref().ok_or(ServiceError::NoActive)?;
        if active.generation != binding.generation
            || active.manifest_sha256 != binding.manifest_sha256
            || self.control.current().transaction_id() != binding.transaction_id
        {
            return Err(ServiceError::RecoveryTargetMismatch);
        }
        let archive_root = self
            .archive_root
            .as_ref()
            .cloned()
            .ok_or(ServiceError::ArchiveRootUnavailable)?;
        self.archive_and_cleanup(binding.generation, &archive_root)
    }

    fn require_idle(&self) -> Result<(), ServiceError> {
        if self.active.is_some() {
            Err(ServiceError::Busy)
        } else {
            Ok(())
        }
    }

    fn peek_generation(&self) -> Result<u64, ServiceError> {
        self.next_generation
            .checked_add(1)
            .map(|_| self.next_generation)
            .ok_or(ServiceError::Coordinator(CoordinatorError::Staging(
                StagingError::BudgetOverflow,
            )))
    }

    fn require_generation(
        active: &mut Option<ServiceUpdate>,
        generation: u64,
    ) -> Result<&mut ServiceUpdate, ServiceError> {
        let active = active.as_mut().ok_or(ServiceError::NoActive)?;
        if active.generation != generation {
            return Err(ServiceError::StaleGeneration {
                expected: active.generation,
                actual: generation,
            });
        }
        Ok(active)
    }

    fn require_stage(active: &ServiceUpdate, expected: UpdateStage) -> Result<(), ServiceError> {
        let actual = active.coordinator.stage();
        if actual == expected {
            Ok(())
        } else {
            Err(ServiceError::WrongStage { expected, actual })
        }
    }

    fn publish_active(
        &mut self,
        generation: u64,
        coordinator: UpdateCoordinator,
        prepared: PreparedUpdate,
        staging_root: &Path,
        manifest_sha256: [u8; 32],
    ) -> Result<(), ServiceError> {
        self.active = Some(ServiceUpdate {
            generation,
            coordinator,
            prepared: Some(prepared),
            staging_root: staging_root.to_path_buf(),
            manifest_sha256,
            recovery_required: false,
        });
        self.next_generation = generation + 1;
        Ok(())
    }

    fn publish_recovered(
        &mut self,
        generation: u64,
        coordinator: UpdateCoordinator,
        staging_root: &Path,
        manifest_sha256: [u8; 32],
    ) -> Result<(), ServiceError> {
        self.active = Some(ServiceUpdate {
            generation,
            coordinator,
            prepared: None,
            staging_root: staging_root.to_path_buf(),
            manifest_sha256,
            recovery_required: false,
        });
        self.next_generation = generation + 1;
        Ok(())
    }
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}

fn update_stage_rank(stage: UpdateStage) -> u8 {
    match stage {
        UpdateStage::Idle => 0,
        UpdateStage::Discovered => 1,
        UpdateStage::Verified => 2,
        UpdateStage::Prepared => 3,
        UpdateStage::Committed => 4,
        UpdateStage::Trial => 5,
        UpdateStage::Confirmed => 6,
        UpdateStage::Complete => 7,
        UpdateStage::Aborted => 8,
        UpdateStage::Rollback => 9,
        UpdateStage::RolledBack => 10,
    }
}

fn advance_update_machine(
    machine: &mut UpdateMachine,
    target: UpdateStage,
) -> Result<Vec<UpdateEvent>, TransitionError> {
    let mut events = Vec::new();
    while machine.stage() != target {
        let event = match machine.stage() {
            UpdateStage::Idle if target == UpdateStage::Aborted => UpdateEvent::Cancel,
            UpdateStage::Idle => UpdateEvent::Discover,
            UpdateStage::Discovered if target == UpdateStage::Aborted => UpdateEvent::Cancel,
            UpdateStage::Discovered => UpdateEvent::Verify,
            UpdateStage::Verified if target == UpdateStage::Aborted => UpdateEvent::Cancel,
            UpdateStage::Verified => UpdateEvent::Prepare,
            UpdateStage::Prepared if target == UpdateStage::Aborted => UpdateEvent::Cancel,
            UpdateStage::Prepared => UpdateEvent::Commit,
            UpdateStage::Committed => UpdateEvent::BeginTrial,
            UpdateStage::Trial
                if matches!(target, UpdateStage::Rollback | UpdateStage::RolledBack) =>
            {
                UpdateEvent::FailHealth
            }
            UpdateStage::Trial => UpdateEvent::ConfirmHealth,
            UpdateStage::Confirmed => UpdateEvent::Finalize,
            UpdateStage::Rollback => UpdateEvent::FinishRollback,
            current => {
                return Err(TransitionError::InvalidPhase {
                    current,
                    event: UpdateEvent::Commit,
                })
            }
        };
        match machine.apply(event) {
            Ok(_) => events.push(event),
            Err(error) => return Err(error),
        }
    }
    Ok(events)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use ciborium::value::Value;
    use ed25519_dalek::{Signer, SigningKey};
    use jasper_lifecycle_model::boot::SlotState;
    use jasper_lifecycle_model::manifest::{
        SignatureSet, ThresholdSignature, ThresholdTrustPolicy, VerifiedManifest,
        MANIFEST_SCHEMA_VERSION, SIGNATURE_DOMAIN,
    };
    use jasper_lifecycle_model::manifest_cbor::{Channel, MAX_MANIFEST_CBOR_BYTES};
    use sha2::{Digest, Sha256};

    use crate::source::{DirectoryBundle, UpdateBundleSource};

    use super::*;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(tag: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos());
            let path = std::env::temp_dir().join(format!(
                "jasper-lifecycle-staging-{tag}-{}-{nanos}-{}",
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn artifact(kind: ArtifactKind, name: &str, bytes: &[u8]) -> VerifiedArtifact {
        VerifiedArtifact {
            kind,
            name: name.into(),
            size: bytes.len() as u64,
            sha256: Sha256::digest(bytes).into(),
        }
    }

    fn manifest(manifest_bytes: &[u8], artifacts: Vec<VerifiedArtifact>) -> VerifiedCborManifest {
        VerifiedCborManifest {
            manifest: VerifiedManifest {
                release_sequence: 9,
                security_epoch: 4,
                target_profile: [0x42; 32],
                signer: [7; 32],
                manifest_sha256: Sha256::digest(manifest_bytes).into(),
            },
            channel: Channel::Stable,
            target_abi: (3, 3),
            data_schema: (1, 2),
            created_at: 100,
            expires_at: 200,
            migration_reversible: true,
            rollback_allowed: true,
            dependencies: Vec::new(),
            artifact_bytes: artifacts.iter().map(|artifact| artifact.size).sum(),
            artifacts,
        }
    }

    fn signed_cbor_bundle(
        artifact_bytes: &[u8],
    ) -> (Vec<u8>, [u8; 64], [u8; 32], Vec<u8>) {
        let key = SigningKey::from_bytes(&[7; 32]);
        let signer = key.verifying_key().to_bytes();
        let profile = [0x42; 32];
        let artifact_digest: [u8; 32] = Sha256::digest(artifact_bytes).into();
        let byte_array = |bytes: &[u8]| {
            Value::Array(
                bytes
                    .iter()
                    .map(|byte| Value::Integer(u64::from(*byte).into()))
                    .collect(),
            )
        };
        let artifact = Value::Map(vec![
            (Value::Text("kind".into()), Value::Text("kernel".into())),
            (Value::Text("name".into()), Value::Text("kernel".into())),
            (
                Value::Text("size".into()),
                Value::Integer((artifact_bytes.len() as u64).into()),
            ),
            (Value::Text("sha256".into()), byte_array(&artifact_digest)),
        ]);
        let wire = Value::Map(vec![
            (
                Value::Text("schema_version".into()),
                Value::Integer(u64::from(MANIFEST_SCHEMA_VERSION).into()),
            ),
            (Value::Text("channel".into()), Value::Text("stable".into())),
            (
                Value::Text("release_sequence".into()),
                Value::Integer(9u64.into()),
            ),
            (
                Value::Text("security_epoch".into()),
                Value::Integer(4u64.into()),
            ),
            (
                Value::Text("created_at".into()),
                Value::Integer(100u64.into()),
            ),
            (
                Value::Text("expires_at".into()),
                Value::Integer(200u64.into()),
            ),
            (
                Value::Text("target_abi_min".into()),
                Value::Integer(3u16.into()),
            ),
            (
                Value::Text("target_abi_max".into()),
                Value::Integer(3u16.into()),
            ),
            (
                Value::Text("data_schema_min".into()),
                Value::Integer(1u32.into()),
            ),
            (
                Value::Text("data_schema_max".into()),
                Value::Integer(2u32.into()),
            ),
            (
                Value::Text("migration_reversible".into()),
                Value::Bool(true),
            ),
            (Value::Text("rollback_allowed".into()), Value::Bool(true)),
            (Value::Text("target_profile".into()), byte_array(&profile)),
            (Value::Text("signer".into()), byte_array(&signer)),
            (Value::Text("dependencies".into()), Value::Array(Vec::new())),
            (
                Value::Text("artifacts".into()),
                Value::Array(vec![artifact]),
            ),
        ]);
        let mut manifest_bytes = Vec::new();
        ciborium::ser::into_writer(&wire, &mut manifest_bytes).unwrap();
        assert!(manifest_bytes.len() <= MAX_MANIFEST_CBOR_BYTES);
        let mut message = Vec::new();
        message.extend_from_slice(SIGNATURE_DOMAIN);
        message.extend_from_slice(&MANIFEST_SCHEMA_VERSION.to_le_bytes());
        message.extend_from_slice(&9u64.to_le_bytes());
        message.extend_from_slice(&4u64.to_le_bytes());
        message.extend_from_slice(&profile);
        message.extend_from_slice(&(manifest_bytes.len() as u64).to_le_bytes());
        message.extend_from_slice(&manifest_bytes);
        let signature = key.sign(&message).to_bytes();
        (manifest_bytes, signature, signer, message)
    }

    struct MemoryBundle {
        manifest: Vec<u8>,
        signature: [u8; 64],
        artifact: Vec<u8>,
    }

    impl UpdateBundleSource for MemoryBundle {
        fn read_manifest(&self) -> Result<Vec<u8>, crate::source::SourceError> {
            Ok(self.manifest.clone())
        }

        fn read_signature(&self) -> Result<[u8; 64], crate::source::SourceError> {
            Ok(self.signature)
        }

        fn copy_artifact(
            &self,
            name: &str,
            destination: &Path,
            max_bytes: u64,
        ) -> Result<(), crate::source::SourceError> {
            if name != "kernel" || self.artifact.len() as u64 != max_bytes {
                return Err(crate::source::SourceError::InvalidArtifactName);
            }
            fs::write(destination, &self.artifact).map_err(|source| {
                crate::source::SourceError::Io {
                    operation: "write in-memory artifact",
                    path: destination.to_path_buf(),
                    source,
                }
            })
        }
    }

    #[test]
    fn online_and_offline_sources_share_authentication_and_staging() {
        let temp = TestDir::new("source-parity");
        let artifact_bytes = b"identical-kernel-bytes";
        let (manifest_bytes, signature, signer, _) = signed_cbor_bundle(artifact_bytes);
        let profile = [0x42; 32];

        let offline_root = temp.path().join("offline-bundle");
        fs::create_dir_all(offline_root.join(crate::source::SOURCE_ARTIFACT_DIR)).unwrap();
        fs::write(
            offline_root.join(crate::source::SOURCE_MANIFEST_FILE),
            &manifest_bytes,
        )
        .unwrap();
        fs::write(
            offline_root.join(crate::source::SOURCE_SIGNATURE_FILE),
            signature,
        )
        .unwrap();
        fs::write(
            offline_root
                .join(crate::source::SOURCE_ARTIFACT_DIR)
                .join("kernel"),
            artifact_bytes,
        )
        .unwrap();

        let trusted = [signer];
        let revoked = [[0u8; 32]];
        let policy = TrustPolicy {
            trusted_keys: &trusted,
            revoked_keys: &revoked,
            minimum_security_epoch: 3,
        };
        let target = UpdateTarget {
            rollback_floor: 8,
            profile,
        };
        let manifest_sha256: [u8; 32] = Sha256::digest(&manifest_bytes).into();
        let grant = LocalInstallGrant {
            locally_authenticated: true,
            purpose: 1,
            manifest_sha256,
            profile,
            expires_at: 200,
        };

        let offline_staging = temp.path().join("offline-staging");
        let mut offline = UpdateCoordinator::idle();
        let offline_update = offline
            .prepare_from_source(
                policy,
                target,
                &DirectoryBundle::new(&offline_root),
                grant,
                150,
                &[],
                &offline_staging,
                4096,
            )
            .unwrap();

        let memory = MemoryBundle {
            manifest: manifest_bytes.clone(),
            signature,
            artifact: artifact_bytes.to_vec(),
        };
        let online_staging = temp.path().join("online-staging");
        let mut online = UpdateCoordinator::idle();
        let online_update = online
            .prepare_from_source(
                policy,
                target,
                &memory,
                grant,
                150,
                &[],
                &online_staging,
                4096,
            )
            .unwrap();

        assert_eq!(offline.stage(), UpdateStage::Prepared);
        assert_eq!(online.stage(), UpdateStage::Prepared);
        assert_eq!(
            offline_update.manifest, online_update.manifest,
            "offline and online transports must authenticate the same manifest"
        );
        assert_eq!(
            offline_update.manifest.manifest.manifest_sha256,
            manifest_sha256
        );
        assert_eq!(
            fs::read(offline_staging.join(ARTIFACT_DIR).join("kernel")).unwrap(),
            artifact_bytes
        );
        assert_eq!(
            fs::read(online_staging.join(ARTIFACT_DIR).join("kernel")).unwrap(),
            artifact_bytes
        );
        assert!(
            fs::read_dir(temp.path())
                .unwrap()
                .filter_map(Result::ok)
                .all(|entry| !entry.file_name().to_string_lossy().starts_with(".source-")),
            "source spools must be removed after staging completes"
        );
    }

    #[test]
    fn threshold_source_stages_two_distinct_signatures() {
        let temp = TestDir::new("threshold-source");
        let artifact_bytes = b"threshold-kernel-bytes";
        let (manifest_bytes, signature, signer, message) =
            signed_cbor_bundle(artifact_bytes);
        let second = SigningKey::from_bytes(&[8; 32]);
        let third = SigningKey::from_bytes(&[9; 32]);
        let trusted = [
            signer,
            second.verifying_key().to_bytes(),
            third.verifying_key().to_bytes(),
        ];
        let signatures = SignatureSet::new(&[
            ThresholdSignature {
                signer,
                signature,
            },
            ThresholdSignature {
                signer: second.verifying_key().to_bytes(),
                signature: second.sign(&message).to_bytes(),
            },
        ])
        .unwrap();
        let (signature_set, signature_set_len) = signatures.encode().unwrap();

        let bundle_root = temp.path().join("threshold-bundle");
        fs::create_dir_all(bundle_root.join(crate::source::SOURCE_ARTIFACT_DIR)).unwrap();
        fs::write(
            bundle_root.join(crate::source::SOURCE_MANIFEST_FILE),
            &manifest_bytes,
        )
        .unwrap();
        fs::write(
            bundle_root.join(crate::source::SOURCE_SIGNATURE_SET_FILE),
            &signature_set[..signature_set_len],
        )
        .unwrap();
        fs::write(
            bundle_root
                .join(crate::source::SOURCE_ARTIFACT_DIR)
                .join("kernel"),
            artifact_bytes,
        )
        .unwrap();

        let profile = [0x42; 32];
        let revoked = [[0u8; 32]];
        let policy = ThresholdTrustPolicy {
            trusted_keys: &trusted,
            revoked_keys: &revoked,
            minimum_security_epoch: 3,
            threshold: 2,
        };
        let target = UpdateTarget {
            rollback_floor: 8,
            profile,
        };
        let manifest_sha256: [u8; 32] = Sha256::digest(&manifest_bytes).into();
        let grant = LocalInstallGrant {
            locally_authenticated: true,
            purpose: 1,
            manifest_sha256,
            profile,
            expires_at: 200,
        };
        let staging_root = temp.path().join("threshold-staging");
        let mut coordinator = UpdateCoordinator::idle();
        let prepared = coordinator
            .prepare_from_source_threshold(
                policy,
                target,
                &DirectoryBundle::new(&bundle_root),
                grant,
                150,
                &[],
                &staging_root,
                4096,
            )
            .unwrap();
        assert_eq!(coordinator.stage(), UpdateStage::Prepared);
        assert_eq!(prepared.manifest.manifest.manifest_sha256, manifest_sha256);
        assert_eq!(
            fs::read(staging_root.join(ARTIFACT_DIR).join("kernel")).unwrap(),
            artifact_bytes
        );
    }

    #[test]
    fn exact_manifest_and_artifacts_are_flushed_and_read_back() {
        let temp = TestDir::new("success");
        let manifest_bytes = b"signed-canonical-cbor";
        let kernel = b"kernel-image";
        let driver = b"driver-image";
        let kernel_path = temp.path().join("kernel.source");
        let driver_path = temp.path().join("driver.source");
        fs::write(&kernel_path, kernel).unwrap();
        fs::write(&driver_path, driver).unwrap();
        let sources = [
            ArtifactSource {
                name: "kernel",
                path: &kernel_path,
            },
            ArtifactSource {
                name: "driver",
                path: &driver_path,
            },
        ];
        let manifest = manifest(
            manifest_bytes,
            vec![
                artifact(ArtifactKind::Kernel, "kernel", kernel),
                artifact(ArtifactKind::Driver, "driver", driver),
            ],
        );
        let root = temp.path().join("staging");
        let receipt = stage_verified_artifacts(&manifest, manifest_bytes, &sources, &root).unwrap();
        assert_eq!(receipt.artifacts.len(), 2);
        assert_eq!(receipt.artifact_bytes, (kernel.len() + driver.len()) as u64);
        assert_eq!(fs::read(root.join(MANIFEST_FILE)).unwrap(), manifest_bytes);
        assert_eq!(
            fs::read(root.join(ARTIFACT_DIR).join("kernel")).unwrap(),
            kernel
        );
        assert_eq!(
            fs::read(root.join(ARTIFACT_DIR).join("driver")).unwrap(),
            driver
        );
    }

    #[test]
    fn tampered_or_missing_sources_leave_no_staging_directory() {
        let temp = TestDir::new("tamper");
        let manifest_bytes = b"signed-canonical-cbor";
        let expected = b"expected";
        let manifest = manifest(
            manifest_bytes,
            vec![artifact(ArtifactKind::Kernel, "kernel", expected)],
        );
        let tampered_path = temp.path().join("tampered");
        fs::write(&tampered_path, b"tampered").unwrap();
        let tampered_source = ArtifactSource {
            name: "kernel",
            path: &tampered_path,
        };
        let root = temp.path().join("staging-tamper");
        assert!(matches!(
            stage_verified_artifacts(&manifest, manifest_bytes, &[tampered_source], &root),
            Err(StagingError::Digest { .. })
        ));
        assert!(!root.exists());

        let missing_root = temp.path().join("staging-missing");
        assert!(matches!(
            stage_verified_artifacts(&manifest, manifest_bytes, &[], &missing_root),
            Err(StagingError::SourceSet(_))
        ));
        assert!(!missing_root.exists());
    }

    #[test]
    fn symlink_source_and_existing_destination_are_rejected() {
        let temp = TestDir::new("symlink");
        let manifest_bytes = b"signed-canonical-cbor";
        let bytes = b"kernel";
        let target = temp.path().join("target");
        fs::write(&target, bytes).unwrap();
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let manifest = manifest(
            manifest_bytes,
            vec![artifact(ArtifactKind::Kernel, "kernel", bytes)],
        );
        let staging = temp.path().join("staging");
        assert!(matches!(
            stage_verified_artifacts(
                &manifest,
                manifest_bytes,
                &[ArtifactSource {
                    name: "kernel",
                    path: &link
                }],
                &staging
            ),
            Err(StagingError::SourceNotRegular(_))
        ));
        assert!(!staging.exists());

        fs::create_dir(&staging).unwrap();
        assert!(matches!(
            stage_verified_artifacts(
                &manifest,
                manifest_bytes,
                &[ArtifactSource {
                    name: "kernel",
                    path: &target
                }],
                &staging
            ),
            Err(StagingError::AlreadyExists(_))
        ));
        assert!(fs::read_dir(&staging).unwrap().next().is_none());
    }

    #[test]
    fn manifest_digest_mismatch_is_rejected_before_creating_staging() {
        let temp = TestDir::new("manifest-digest");
        let bytes = b"kernel";
        let manifest = manifest(
            b"authenticated-manifest",
            vec![artifact(ArtifactKind::Kernel, "kernel", bytes)],
        );
        let source = temp.path().join("kernel.source");
        fs::write(&source, bytes).unwrap();
        let staging = temp.path().join("staging");
        assert!(matches!(
            stage_verified_artifacts(
                &manifest,
                b"tampered-manifest!",
                &[ArtifactSource {
                    name: "kernel",
                    path: &source
                }],
                &staging
            ),
            Err(StagingError::ManifestDigest)
        ));
        assert!(!staging.exists());
    }

    #[test]
    fn disk_budget_uses_block_rounding_and_rejects_impossible_headroom() {
        let temp = TestDir::new("disk-budget");
        let manifest_bytes = b"signed-manifest";
        let bytes = [0x5a; 17];
        let manifest = manifest(
            manifest_bytes,
            vec![artifact(ArtifactKind::Kernel, "kernel", &bytes)],
        );
        let budget =
            check_disk_budget(&manifest, manifest_bytes.len() as u64, temp.path(), 0).unwrap();
        assert!(budget.block_size > 0);
        assert!(budget.required_bytes >= bytes.len() as u64 + manifest_bytes.len() as u64);
        assert!(matches!(
            check_disk_budget(
                &manifest,
                manifest_bytes.len() as u64,
                temp.path(),
                u64::MAX
            ),
            Err(StagingError::BudgetOverflow)
        ));
    }

    #[test]
    fn prepare_update_chains_authorization_dependencies_budget_and_staging() {
        let temp = TestDir::new("prepare-update");
        let manifest_bytes = b"signed-update-manifest";
        let bytes = b"kernel-image";
        let source_path = temp.path().join("kernel.source");
        fs::write(&source_path, bytes).unwrap();
        let mut manifest = manifest(
            manifest_bytes,
            vec![artifact(ArtifactKind::Kernel, "kernel", bytes)],
        );
        manifest.dependencies = vec![String::from("jasper.base")];
        let grant = LocalInstallGrant {
            locally_authenticated: true,
            purpose: 1,
            manifest_sha256: manifest.manifest.manifest_sha256,
            profile: manifest.manifest.target_profile,
            expires_at: 10,
        };
        let staging_root = temp.path().join("staging");
        let prepared = prepare_update(
            manifest,
            manifest_bytes,
            grant,
            9,
            &[String::from("jasper.base")],
            &[ArtifactSource {
                name: "kernel",
                path: &source_path,
            }],
            &staging_root,
            4096,
        )
        .unwrap();
        assert_eq!(prepared.staging.artifacts.len(), 1);
        assert!(prepared.budget.required_bytes >= 4096);
        assert_eq!(prepared.record.stage(), UpdateStage::Prepared);
        assert_eq!(
            load_prepared_transaction(&staging_root, prepared.manifest.manifest.manifest_sha256)
                .unwrap(),
            prepared.record
        );
        assert_eq!(
            fs::read(staging_root.join(ARTIFACT_DIR).join("kernel")).unwrap(),
            bytes
        );
    }

    #[test]
    fn coordinator_prepares_recovers_and_cancels_before_commit() {
        let temp = TestDir::new("coordinator");
        let manifest_bytes = b"signed-coordinator-manifest";
        let bytes = b"kernel-image";
        let source_path = temp.path().join("kernel.source");
        fs::write(&source_path, bytes).unwrap();
        let mut manifest = manifest(
            manifest_bytes,
            vec![artifact(ArtifactKind::Kernel, "kernel", bytes)],
        );
        manifest.dependencies = vec![String::from("jasper.base")];
        let grant = LocalInstallGrant {
            locally_authenticated: true,
            purpose: 1,
            manifest_sha256: manifest.manifest.manifest_sha256,
            profile: manifest.manifest.target_profile,
            expires_at: 10,
        };
        let staging_root = temp.path().join("coordinator-staging");
        let mut coordinator = UpdateCoordinator::idle();
        let prepared = coordinator
            .prepare(
                manifest,
                manifest_bytes,
                grant,
                9,
                &[String::from("jasper.base")],
                &[ArtifactSource {
                    name: "kernel",
                    path: &source_path,
                }],
                &staging_root,
                4096,
            )
            .unwrap();
        assert_eq!(coordinator.stage(), UpdateStage::Prepared);
        assert_eq!(prepared.record.stage(), UpdateStage::Prepared);

        let mut recovered = UpdateCoordinator::recover_prepared(
            &staging_root,
            prepared.manifest.manifest.manifest_sha256,
        )
        .unwrap();
        assert_eq!(recovered, coordinator);
        recovered.cancel_prepared(&staging_root).unwrap();
        assert_eq!(recovered.stage(), UpdateStage::Aborted);
        assert!(!staging_root.exists());
    }

    #[test]
    fn coordinator_commits_candidate_only_after_control_readback() {
        let temp = TestDir::new("coordinator-commit");
        let manifest_bytes = b"signed-commit-manifest";
        let bytes = b"kernel-image";
        let source_path = temp.path().join("kernel.source");
        fs::write(&source_path, bytes).unwrap();
        let verified_manifest = manifest(
            manifest_bytes,
            vec![artifact(ArtifactKind::Kernel, "kernel", bytes)],
        );
        let grant = LocalInstallGrant {
            locally_authenticated: true,
            purpose: 1,
            manifest_sha256: verified_manifest.manifest.manifest_sha256,
            profile: verified_manifest.manifest.target_profile,
            expires_at: 10,
        };
        let staging_root = temp.path().join("commit-staging");
        let mut coordinator = UpdateCoordinator::idle();
        let prepared = coordinator
            .prepare(
                verified_manifest,
                manifest_bytes,
                grant,
                9,
                &[],
                &[ArtifactSource {
                    name: "kernel",
                    path: &source_path,
                }],
                &staging_root,
                4096,
            )
            .unwrap();
        let control_root = temp.path().join("control");
        let initial = ControlBlock::initialize(Slot::A, 1, [1; 32], 1, 1, 1, 2).unwrap();
        let mut control = FileControlStore::initialize(&control_root, initial).unwrap();
        let committed = coordinator
            .commit_prepared(&prepared, &mut control, Slot::B, 2)
            .unwrap();
        assert_eq!(coordinator.stage(), UpdateStage::Committed);
        assert_eq!(committed.active_slot(), Slot::A);
        assert_eq!(committed.slot(Slot::B).state(), SlotState::Candidate);
        assert_eq!(committed.transaction_id(), 2);
        drop(control);
        let mut control = FileControlStore::open(&control_root).unwrap();
        assert_eq!(control.current(), committed);
        assert_eq!(
            load_transaction_record(&staging_root).unwrap().stage(),
            UpdateStage::Committed
        );

        // Simulate a crash after control commit but before journal replacement.
        persist_transaction_record(&staging_root, prepared.record).unwrap();
        let mut repaired = UpdateCoordinator::recover_with_control(
            &staging_root,
            prepared.manifest.manifest.manifest_sha256,
            &control,
        )
        .unwrap();
        assert_eq!(repaired.stage(), UpdateStage::Committed);
        assert_eq!(
            load_transaction_record(&staging_root).unwrap().stage(),
            UpdateStage::Committed
        );

        let decision = repaired.begin_trial(&mut control, &staging_root).unwrap();
        assert_eq!(decision.reason, BootReason::CandidateTrial);
        assert_eq!(decision.attempt, 1);
        let mut coordinator = UpdateCoordinator::recover_with_control(
            &staging_root,
            prepared.manifest.manifest.manifest_sha256,
            &control,
        )
        .unwrap();
        coordinator
            .report_candidate_health(&mut control, &staging_root, true)
            .unwrap();
        assert_eq!(coordinator.stage(), UpdateStage::Confirmed);
        assert_eq!(control.current().active_slot(), Slot::B);

        persist_transaction_record(&staging_root, prepared.record).unwrap();
        let fully_repaired = UpdateCoordinator::recover_with_control(
            &staging_root,
            prepared.manifest.manifest.manifest_sha256,
            &control,
        )
        .unwrap();
        assert_eq!(fully_repaired.stage(), UpdateStage::Confirmed);
        let mut terminal = control.current();
        terminal
            .record_terminal(
                jasper_lifecycle_model::boot::TransactionTerminal::Complete,
                terminal.transaction_id(),
                prepared.manifest.manifest.manifest_sha256,
            )
            .unwrap();
        control.commit_next(terminal).unwrap();
        assert_eq!(
            load_transaction_record(&staging_root).unwrap().stage(),
            UpdateStage::Confirmed
        );
        let completed = UpdateCoordinator::recover_with_control(
            &staging_root,
            prepared.manifest.manifest.manifest_sha256,
            &control,
        )
        .unwrap();
        assert_eq!(completed.stage(), UpdateStage::Complete);
        assert_eq!(
            load_transaction_record(&staging_root).unwrap().stage(),
            UpdateStage::Complete
        );
        assert_eq!(
            control.current().terminal(),
            jasper_lifecycle_model::boot::TransactionTerminal::Complete
        );
        let archive_root = temp.path().join("audit-archive");
        let archive = archive_completed_transaction(&staging_root, &archive_root).unwrap();
        assert_eq!(archive.record.stage(), UpdateStage::Complete);
        cleanup_staged_transaction(&staging_root, &archive).unwrap();
        assert!(!staging_root.exists());
        assert!(archive_root.join(MANIFEST_FILE).is_file());
        assert!(archive_root.join(TRANSACTION_COPIES[0]).is_file());

        let rollback_manifest_bytes = b"signed-rollback-manifest";
        let mut rollback_manifest = manifest(
            rollback_manifest_bytes,
            vec![artifact(ArtifactKind::Kernel, "kernel", bytes)],
        );
        rollback_manifest.manifest.release_sequence = 10;
        let rollback_grant = LocalInstallGrant {
            locally_authenticated: true,
            purpose: 1,
            manifest_sha256: rollback_manifest.manifest.manifest_sha256,
            profile: rollback_manifest.manifest.target_profile,
            expires_at: 10,
        };
        let rollback_root = temp.path().join("rollback-staging");
        let mut rollback = UpdateCoordinator::idle();
        let rollback_prepared = rollback
            .prepare(
                rollback_manifest,
                rollback_manifest_bytes,
                rollback_grant,
                9,
                &[],
                &[ArtifactSource {
                    name: "kernel",
                    path: &source_path,
                }],
                &rollback_root,
                4096,
            )
            .unwrap();
        rollback
            .commit_prepared(&rollback_prepared, &mut control, Slot::A, 3)
            .unwrap();
        rollback.begin_trial(&mut control, &rollback_root).unwrap();
        rollback
            .report_candidate_health(&mut control, &rollback_root, false)
            .unwrap();
        assert_eq!(rollback.stage(), UpdateStage::Rollback);
        assert_eq!(control.current().active_slot(), Slot::B);
        assert_eq!(
            rollback
                .finish_rollback(&mut control, &rollback_root)
                .unwrap(),
            Slot::B
        );
        assert_eq!(rollback.stage(), UpdateStage::RolledBack);
        assert_eq!(
            load_transaction_record(&rollback_root).unwrap().stage(),
            UpdateStage::RolledBack
        );
        assert_eq!(
            control.current().terminal(),
            jasper_lifecycle_model::boot::TransactionTerminal::RolledBack
        );
        assert_eq!(
            control.current().transaction_digest(),
            Some(rollback_prepared.manifest.manifest.manifest_sha256)
        );
        let rollback_archive = archive_completed_transaction(
            &rollback_root,
            &temp.path().join("rollback-audit-archive"),
        )
        .unwrap();
        cleanup_staged_transaction(&rollback_root, &rollback_archive).unwrap();
        assert!(!rollback_root.exists());
    }

    #[test]
    fn prepare_update_rejects_missing_dependencies_before_staging() {
        let temp = TestDir::new("prepare-dependency");
        let manifest_bytes = b"signed-update-manifest";
        let bytes = b"kernel-image";
        let source_path = temp.path().join("kernel.source");
        fs::write(&source_path, bytes).unwrap();
        let mut manifest = manifest(
            manifest_bytes,
            vec![artifact(ArtifactKind::Kernel, "kernel", bytes)],
        );
        manifest.dependencies = vec![String::from("jasper.missing")];
        let grant = LocalInstallGrant {
            locally_authenticated: true,
            purpose: 1,
            manifest_sha256: manifest.manifest.manifest_sha256,
            profile: manifest.manifest.target_profile,
            expires_at: 10,
        };
        let staging_root = temp.path().join("staging");
        assert!(matches!(
            prepare_update(
                manifest,
                manifest_bytes,
                grant,
                9,
                &[String::from("jasper.base")],
                &[ArtifactSource {
                    name: "kernel",
                    path: &source_path,
                }],
                &staging_root,
                0,
            ),
            Err(StagingError::MissingDependency(name)) if name == "jasper.missing"
        ));
        assert!(!staging_root.exists());
        assert!(matches!(
            check_dependency_snapshot(&[], &[String::from("same"), String::from("same")]),
            Err(StagingError::InvalidDependencySnapshot)
        ));
    }

    #[test]
    fn prepare_update_requires_a_live_local_grant() {
        let temp = TestDir::new("prepare-grant");
        let manifest_bytes = b"signed-update-manifest";
        let bytes = b"kernel-image";
        let source_path = temp.path().join("kernel.source");
        fs::write(&source_path, bytes).unwrap();
        let manifest = manifest(
            manifest_bytes,
            vec![artifact(ArtifactKind::Kernel, "kernel", bytes)],
        );
        let grant = LocalInstallGrant {
            locally_authenticated: true,
            purpose: 1,
            manifest_sha256: manifest.manifest.manifest_sha256,
            profile: manifest.manifest.target_profile,
            expires_at: 9,
        };
        let staging_root = temp.path().join("staging");
        assert!(matches!(
            prepare_update(
                manifest,
                manifest_bytes,
                grant,
                9,
                &[],
                &[ArtifactSource {
                    name: "kernel",
                    path: &source_path,
                }],
                &staging_root,
                0,
            ),
            Err(StagingError::Manifest(ManifestError::Authorization))
        ));
        assert!(!staging_root.exists());
    }

    #[test]
    fn prepared_transaction_recovers_from_one_torn_copy_and_rejects_both() {
        let temp = TestDir::new("transaction-recovery");
        let root = temp.path().join("staging");
        fs::create_dir(&root).unwrap();
        let record = persist_prepared_transaction(&root, [0x44; 32]).unwrap();
        fs::write(root.join(TRANSACTION_COPIES[0]), b"torn").unwrap();
        assert_eq!(
            load_prepared_transaction(&root, [0x44; 32]).unwrap(),
            record
        );
        fs::write(root.join(TRANSACTION_COPIES[1]), b"torn").unwrap();
        assert!(matches!(
            load_prepared_transaction(&root, [0x44; 32]),
            Err(StagingError::Transaction(TransactionError::CorruptRecord))
        ));
    }

    fn prepared_service(temp: &TestDir, tag: &str) -> (UpdateService, u64, PathBuf) {
        let manifest_bytes = b"signed-service-manifest";
        let bytes = b"service-kernel-image";
        let source_path = temp.path().join(format!("{tag}.source"));
        fs::write(&source_path, bytes).unwrap();
        let verified_manifest = manifest(
            manifest_bytes,
            vec![artifact(ArtifactKind::Kernel, "kernel", bytes)],
        );
        let grant = LocalInstallGrant {
            locally_authenticated: true,
            purpose: 1,
            manifest_sha256: verified_manifest.manifest.manifest_sha256,
            profile: verified_manifest.manifest.target_profile,
            expires_at: 10,
        };
        let staging_root = temp.path().join(format!("{tag}-staging"));
        let control_root = temp.path().join(format!("{tag}-control"));
        let initial = ControlBlock::initialize(Slot::A, 1, [1; 32], 1, 1, 1, 2).unwrap();
        let mut service = UpdateService::initialize(&control_root, initial).unwrap();
        let status = service
            .prepare(
                verified_manifest,
                manifest_bytes,
                grant,
                9,
                &[],
                &[ArtifactSource {
                    name: "kernel",
                    path: &source_path,
                }],
                &staging_root,
                4096,
            )
            .unwrap();
        (service, status.generation, staging_root)
    }

    fn transaction_copies(root: &Path) -> [Vec<u8>; 2] {
        TRANSACTION_COPIES.map(|name| fs::read(root.join(name)).unwrap())
    }

    fn restore_transaction_copies(root: &Path, copies: [Vec<u8>; 2]) {
        for (name, bytes) in TRANSACTION_COPIES.into_iter().zip(copies) {
            fs::write(root.join(name), bytes).unwrap();
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum CrashWindow {
        Prepared,
        Commit,
        BeginTrial,
        Confirm,
        Finalize,
        FailHealth,
        FinishRollback,
    }

    fn cross_control_boundary(
        service: &mut UpdateService,
        generation: u64,
        staging_root: &Path,
        window: CrashWindow,
    ) -> ([Vec<u8>; 2], UpdateStage) {
        match window {
            CrashWindow::Prepared => (transaction_copies(staging_root), UpdateStage::Prepared),
            CrashWindow::Commit => {
                let before = transaction_copies(staging_root);
                service.commit(generation, Slot::B, 2).unwrap();
                (before, UpdateStage::Committed)
            }
            CrashWindow::BeginTrial => {
                service.commit(generation, Slot::B, 2).unwrap();
                let before = transaction_copies(staging_root);
                service.begin_trial(generation).unwrap();
                (before, UpdateStage::Trial)
            }
            CrashWindow::Confirm => {
                service.commit(generation, Slot::B, 2).unwrap();
                service.begin_trial(generation).unwrap();
                let before = transaction_copies(staging_root);
                service.report_health(generation, true).unwrap();
                (before, UpdateStage::Confirmed)
            }
            CrashWindow::Finalize => {
                service.commit(generation, Slot::B, 2).unwrap();
                service.begin_trial(generation).unwrap();
                service.report_health(generation, true).unwrap();
                let before = transaction_copies(staging_root);
                service.finalize_confirmed(generation).unwrap();
                (before, UpdateStage::Complete)
            }
            CrashWindow::FailHealth => {
                service.commit(generation, Slot::B, 2).unwrap();
                service.begin_trial(generation).unwrap();
                let before = transaction_copies(staging_root);
                service.report_health(generation, false).unwrap();
                (before, UpdateStage::Rollback)
            }
            CrashWindow::FinishRollback => {
                service.commit(generation, Slot::B, 2).unwrap();
                service.begin_trial(generation).unwrap();
                service.report_health(generation, false).unwrap();
                let before = transaction_copies(staging_root);
                service.finish_rollback(generation).unwrap();
                (before, UpdateStage::RolledBack)
            }
        }
    }

    #[test]
    fn restart_recovery_matrix_repairs_each_control_ahead_of_journal_window() {
        let temp = TestDir::new("restart-matrix");
        for (index, window) in [
            CrashWindow::Prepared,
            CrashWindow::Commit,
            CrashWindow::BeginTrial,
            CrashWindow::Confirm,
            CrashWindow::Finalize,
            CrashWindow::FailHealth,
            CrashWindow::FinishRollback,
        ]
        .into_iter()
        .enumerate()
        {
            let tag = format!("restart-matrix-{index}");
            let (mut service, generation, staging_root) = prepared_service(&temp, &tag);
            let digest = service.status().manifest_sha256.unwrap();
            let (journal_before_durable_step, expected) =
                cross_control_boundary(&mut service, generation, &staging_root, window);
            drop(service);

            // The control record crossed its durable boundary while the
            // transaction journal still names the preceding stage.
            restore_transaction_copies(&staging_root, journal_before_durable_step);
            let control_root = temp.path().join(format!("{tag}-control"));
            let mut restarted = UpdateService::open(&control_root).unwrap();
            let recovered = restarted
                .recover(&staging_root, digest)
                .unwrap_or_else(|error| panic!("window={window:?}: {error}"));
            assert_eq!(recovered.stage, Some(expected), "window={window:?}");
            let recovered_generation = recovered.generation;
            if matches!(window, CrashWindow::Prepared) {
                assert_eq!(recovered_generation, generation, "window={window:?}");
            } else {
                assert!(recovered_generation > generation, "window={window:?}");
            }
            assert!(!recovered.recovery_required, "window={window:?}");
            assert_eq!(
                load_transaction_record(&staging_root).unwrap().stage(),
                expected,
                "window={window:?}"
            );

            // A client retry after losing the first response must observe the
            // same service generation and never apply the repair twice.
            let replayed = restarted.recover(&staging_root, digest).unwrap();
            assert_eq!(replayed, recovered, "window={window:?}");
            assert!(matches!(
                restarted.recover(&staging_root, [0xA5; 32]),
                Err(ServiceError::RecoveryTargetMismatch)
            ));
        }
    }

    #[test]
    fn restart_recovery_uses_newer_copy_after_each_torn_journal_replace() {
        let temp = TestDir::new("torn-journal-matrix");
        for (index, window) in [
            CrashWindow::Commit,
            CrashWindow::BeginTrial,
            CrashWindow::Confirm,
            CrashWindow::Finalize,
            CrashWindow::FailHealth,
            CrashWindow::FinishRollback,
        ]
        .into_iter()
        .enumerate()
        {
            let tag = format!("torn-journal-matrix-{index}");
            let (mut service, generation, staging_root) = prepared_service(&temp, &tag);
            let digest = service.status().manifest_sha256.unwrap();
            let (previous, expected) =
                cross_control_boundary(&mut service, generation, &staging_root, window);
            let completed = transaction_copies(&staging_root);
            drop(service);

            // Simulate power loss after the first journal replacement became
            // durable but before the second copy was written. Recovery may
            // select the newer valid copy but must not regress or split state.
            fs::write(staging_root.join(TRANSACTION_COPIES[0]), &previous[0]).unwrap();
            fs::write(staging_root.join(TRANSACTION_COPIES[1]), &completed[1]).unwrap();
            let control_root = temp.path().join(format!("{tag}-control"));
            let mut restarted = UpdateService::open(&control_root).unwrap();
            let recovered = restarted
                .recover(&staging_root, digest)
                .unwrap_or_else(|error| panic!("window={window:?}: {error}"));
            assert_eq!(recovered.stage, Some(expected), "window={window:?}");
            assert!(!recovered.recovery_required, "window={window:?}");
            let replayed = restarted.recover(&staging_root, digest).unwrap();
            assert_eq!(replayed, recovered, "window={window:?}");
        }
    }

    #[test]
    fn a_second_live_service_cannot_race_the_control_generation() {
        let temp = TestDir::new("service-lease");
        let control_root = temp.path().join("service-lease-control");
        let initial = ControlBlock::initialize(Slot::A, 1, [1; 32], 1, 1, 1, 2).unwrap();
        let service = UpdateService::initialize(&control_root, initial).unwrap();
        assert!(matches!(
            UpdateService::open(&control_root),
            Err(CoordinatorError::ControlStore(ControlStoreError::Busy))
        ));
        drop(service);
        assert_eq!(UpdateService::open(&control_root).unwrap().status().stage, None);
    }

    #[test]
    fn service_generation_guards_full_commit_trial_health_and_archive_path() {
        let temp = TestDir::new("service-success");
        let (mut service, generation, _) = prepared_service(&temp, "success");
        assert_eq!(service.status().stage, Some(UpdateStage::Prepared));
        assert!(matches!(
            service.commit(0, Slot::B, 2),
            Err(ServiceError::StaleGeneration {
                expected,
                actual: 0
            }) if expected == generation
        ));

        let committed = service.commit(generation, Slot::B, 2).unwrap();
        assert_eq!(committed.stage, Some(UpdateStage::Committed));
        let decision = service.begin_trial(generation).unwrap();
        assert_eq!(decision.reason, BootReason::CandidateTrial);
        let confirmed = service.report_health(generation, true).unwrap();
        assert_eq!(confirmed.stage, Some(UpdateStage::Confirmed));
        assert_eq!(confirmed.active_slot, Slot::B);

        let complete = service.finalize_confirmed(generation).unwrap();
        assert_eq!(complete.stage, Some(UpdateStage::Complete));
        let archive = service
            .archive_and_cleanup(generation, &temp.path().join("service-success-archive"))
            .unwrap();
        assert_eq!(archive.record.stage(), UpdateStage::Complete);
        assert_eq!(service.status().stage, None);
    }

    #[test]
    fn managed_binding_archives_without_caller_paths() {
        let temp = TestDir::new("service-bound-archive");
        let (mut service, generation, _) = prepared_service(&temp, "bound-archive");
        service.commit(generation, Slot::B, 2).unwrap();
        service.begin_trial(generation).unwrap();
        service.report_health(generation, true).unwrap();
        service.finalize_confirmed(generation).unwrap();

        let binding = service.binding().unwrap();
        assert_eq!(binding.generation, generation);
        assert!(matches!(
            service.archive_bound(TransactionBinding {
                generation: generation + 1,
                ..binding
            }),
            Err(ServiceError::RecoveryTargetMismatch)
        ));
        assert!(matches!(
            service.archive_bound(binding),
            Err(ServiceError::ArchiveRootUnavailable)
        ));

        service.archive_root = Some(temp.path().join("managed-archive"));
        let ledger_root = temp.path().join("managed-archive-ledger");
        fs::create_dir(&ledger_root).unwrap();
        service.configure_archive_ledger(&ledger_root).unwrap();
        let archive = service.archive_bound(binding).unwrap();
        assert_eq!(archive.manifest_sha256, binding.manifest_sha256);
        assert_eq!(archive.record.stage(), UpdateStage::Complete);
        let receipt = FileArchiveStore::open(&ledger_root)
            .unwrap()
            .load()
            .unwrap()
            .unwrap();
        assert_eq!(receipt.transaction_id(), binding.transaction_id);
        assert_eq!(receipt.manifest_sha256(), binding.manifest_sha256);
        assert_eq!(receipt.terminal_stage(), UpdateStage::Complete);
        assert_eq!(service.status().stage, None);
    }

    #[test]
    fn service_failed_health_is_the_only_path_to_rollback() {
        let temp = TestDir::new("service-rollback");
        let (mut service, generation, _) = prepared_service(&temp, "rollback");
        service.commit(generation, Slot::B, 2).unwrap();
        service.begin_trial(generation).unwrap();
        assert!(matches!(
            service.finalize_confirmed(generation),
            Err(ServiceError::WrongStage {
                expected: UpdateStage::Confirmed,
                actual: UpdateStage::Trial
            })
        ));
        assert_eq!(
            service.report_health(generation, false).unwrap().stage,
            Some(UpdateStage::Rollback)
        );
        assert_eq!(service.finish_rollback(generation).unwrap(), Slot::A);
        assert_eq!(service.status().stage, Some(UpdateStage::RolledBack));
        let archive = service
            .archive_and_cleanup(generation, &temp.path().join("service-rollback-archive"))
            .unwrap();
        assert_eq!(archive.record.stage(), UpdateStage::RolledBack);
    }

    #[test]
    fn service_cleanup_reopens_an_archive_published_before_cleanup_retry() {
        let temp = TestDir::new("service-archive-retry");
        let (mut service, generation, staging_root) = prepared_service(&temp, "archive-retry");
        service.commit(generation, Slot::B, 2).unwrap();
        service.begin_trial(generation).unwrap();
        service.report_health(generation, true).unwrap();
        service.finalize_confirmed(generation).unwrap();

        let archive_root = temp.path().join("archive-retry-audit");
        let published = archive_completed_transaction(&staging_root, &archive_root).unwrap();
        assert_eq!(published.record.stage(), UpdateStage::Complete);

        let reopened = service
            .archive_and_cleanup(generation, &archive_root)
            .unwrap();
        assert_eq!(reopened, published);
        assert!(!staging_root.exists());
        assert_eq!(service.status().stage, None);
    }

    #[test]
    fn service_recovery_repairs_control_commit_and_keeps_generation_boundary() {
        let temp = TestDir::new("service-recovery");
        let (mut service, generation, staging_root) = prepared_service(&temp, "recovery");
        let prepared_record = service
            .active
            .as_ref()
            .and_then(|active| active.prepared.as_ref())
            .map(|prepared| prepared.record)
            .unwrap();
        let digest = service.status().manifest_sha256.unwrap();
        let control_root = temp.path().join("recovery-control");
        service.commit(generation, Slot::B, 2).unwrap();

        // Simulate a crash after control commit but before the transaction journal update.
        persist_transaction_record(&staging_root, prepared_record).unwrap();
        service.active.as_mut().unwrap().recovery_required = true;
        assert!(matches!(
            service.recover(&staging_root, [0x55; 32]),
            Err(ServiceError::RecoveryTargetMismatch)
        ));
        drop(service);

        let mut recovered = UpdateService::open(&control_root).unwrap();
        let status = recovered.recover(&staging_root, digest).unwrap();
        assert_eq!(status.stage, Some(UpdateStage::Committed));
        assert!(status.generation > generation);
        assert!(matches!(
            recovered.report_health(generation, true),
            Err(ServiceError::StaleGeneration { .. })
        ));
    }

    #[test]
    fn active_recovery_uses_only_stable_binding_identity() {
        let temp = TestDir::new("service-bound-recovery");
        let (mut service, generation, staging_root) = prepared_service(&temp, "bound-recovery");
        let prepared_record = service
            .active
            .as_ref()
            .and_then(|active| active.prepared.as_ref())
            .map(|prepared| prepared.record)
            .unwrap();
        service.commit(generation, Slot::B, 2).unwrap();
        persist_transaction_record(&staging_root, prepared_record).unwrap();
        service.active.as_mut().unwrap().recovery_required = true;

        let binding = service.binding().unwrap();
        assert!(matches!(
            service.recover_bound(TransactionBinding {
                manifest_sha256: [0x44; 32],
                ..binding
            }),
            Err(ServiceError::RecoveryTargetMismatch)
        ));
        assert!(matches!(
            service.recover_bound(TransactionBinding {
                transaction_id: binding.transaction_id + 1,
                ..binding
            }),
            Err(ServiceError::RecoveryTargetMismatch)
        ));
        let recovered = service.recover_bound(binding).unwrap();
        assert_eq!(recovered.stage, Some(UpdateStage::Committed));
        assert!(recovered.generation > generation);
        assert!(!recovered.recovery_required);
    }

    #[test]
    fn service_online_and_offline_sources_keep_the_same_trust_and_staging_result() {
        let temp = TestDir::new("service-source-parity");
        let artifact_bytes = b"service-identical-kernel";
        let (manifest_bytes, signature, signer, _) = signed_cbor_bundle(artifact_bytes);
        let profile = [0x42; 32];
        let manifest_sha256: [u8; 32] = Sha256::digest(&manifest_bytes).into();
        let trusted = [signer];
        let revoked = [[0u8; 32]];
        let policy = TrustPolicy {
            trusted_keys: &trusted,
            revoked_keys: &revoked,
            minimum_security_epoch: 3,
        };
        let target = UpdateTarget {
            rollback_floor: 8,
            profile,
        };
        let grant = LocalInstallGrant {
            locally_authenticated: true,
            purpose: 1,
            manifest_sha256,
            profile,
            expires_at: 200,
        };

        let offline_root = temp.path().join("service-offline-bundle");
        fs::create_dir_all(offline_root.join(crate::source::SOURCE_ARTIFACT_DIR)).unwrap();
        fs::write(
            offline_root.join(crate::source::SOURCE_MANIFEST_FILE),
            &manifest_bytes,
        )
        .unwrap();
        fs::write(
            offline_root.join(crate::source::SOURCE_SIGNATURE_FILE),
            signature,
        )
        .unwrap();
        fs::write(
            offline_root
                .join(crate::source::SOURCE_ARTIFACT_DIR)
                .join("kernel"),
            artifact_bytes,
        )
        .unwrap();

        let initial = ControlBlock::initialize(Slot::A, 1, [1; 32], 1, 1, 1, 2).unwrap();
        let mut offline =
            UpdateService::initialize(temp.path().join("service-offline-control"), initial)
                .unwrap();
        let offline_status = offline
            .prepare_from_source(
                policy,
                target,
                &DirectoryBundle::new(&offline_root),
                grant,
                150,
                &[],
                &temp.path().join("service-offline-staging"),
                4096,
            )
            .unwrap();

        let memory = MemoryBundle {
            manifest: manifest_bytes.clone(),
            signature,
            artifact: artifact_bytes.to_vec(),
        };
        let mut online =
            UpdateService::initialize(temp.path().join("service-online-control"), initial).unwrap();
        let online_status = online
            .prepare_from_source(
                policy,
                target,
                &memory,
                grant,
                150,
                &[],
                &temp.path().join("service-online-staging"),
                4096,
            )
            .unwrap();

        assert_eq!(offline_status.stage, Some(UpdateStage::Prepared));
        assert_eq!(online_status.stage, Some(UpdateStage::Prepared));
        assert_eq!(offline_status.manifest_sha256, Some(manifest_sha256));
        assert_eq!(
            offline.status().manifest_sha256,
            online.status().manifest_sha256
        );
        assert_eq!(
            fs::read(
                temp.path()
                    .join("service-offline-staging")
                    .join(ARTIFACT_DIR)
                    .join("kernel")
            )
            .unwrap(),
            artifact_bytes
        );
        assert_eq!(
            fs::read(
                temp.path()
                    .join("service-online-staging")
                    .join(ARTIFACT_DIR)
                    .join("kernel")
            )
            .unwrap(),
            artifact_bytes
        );
    }
}
