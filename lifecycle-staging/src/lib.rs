//! LC-2 更新工件的已验签、持久化暂存边界。
//! Verified durable artifact-staging boundary for LC-2 updates.
//!
//! 本 crate 只把已经验签的清单和本地制品复制到新的暂存目录，逐项校验大小与
//! SHA-256，刷新文件和目录后再次读回验证。它不下载、不激活、不修改启动槽，也不
//! 替代 Update Coordinator 的交易状态机。
//! This crate copies an already verified manifest and local artifacts into a fresh staging
//! directory, verifies size and SHA-256, flushes and reads them back. It does not download,
//! activate, modify boot slots or replace the Update Coordinator state machine.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use jasper_lifecycle_model::manifest::{authorize_install, LocalInstallGrant, ManifestError};
use jasper_lifecycle_model::manifest_cbor::{
    ArtifactKind, VerifiedArtifact, VerifiedCborManifest, MAX_MANIFEST_CBOR_BYTES,
};
use jasper_lifecycle_model::transaction::{recover, TransactionError, TransactionRecord};
use jasper_lifecycle_model::update::UpdateStage;
use sha2::{Digest, Sha256};

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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use jasper_lifecycle_model::manifest::VerifiedManifest;
    use jasper_lifecycle_model::manifest_cbor::Channel;
    use sha2::{Digest, Sha256};

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
}
