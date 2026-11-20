//! Transport-neutral update bundle acquisition for LC-2.
//!
//! The transport may be an offline directory or an HTTPS endpoint, but both
//! paths return the same authenticated bytes to the one manifest verifier and
//! staging coordinator. Transport identity never replaces signature, grant,
//! dependency, capacity or digest checks.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use jasper_lifecycle_model::manifest::{
    SignatureSet, ThresholdError, ThresholdTrustPolicy, TrustPolicy, UpdateTarget,
    MAX_SIGNATURE_SET_BYTES,
};
use jasper_lifecycle_model::manifest_cbor::{
    verify_cbor_manifest, verify_cbor_manifest_threshold, CborManifestError, VerifiedCborManifest,
    MAX_MANIFEST_CBOR_BYTES,
};
use sha2::{Digest, Sha256};

use crate::ArtifactSource;

/// Manifest file name in an offline bundle or at an HTTPS bundle root.
pub const SOURCE_MANIFEST_FILE: &str = "manifest.cbor";
/// Signature file name in an offline bundle or at an HTTPS bundle root.
pub const SOURCE_SIGNATURE_FILE: &str = "manifest.sig";
/// Canonical threshold signature-set file name.
pub const SOURCE_SIGNATURE_SET_FILE: &str = "manifest.sigset";
/// Artifact directory in an offline bundle or below an HTTPS bundle root.
pub const SOURCE_ARTIFACT_DIR: &str = "artifacts";

const READ_BUFFER_BYTES: usize = 64 * 1024;
const SIGNATURE_BYTES: usize = 64;
const RESUME_CHECKPOINT_FILE: &str = ".update-source-resume";
const RESUME_CHECKPOINT_MAGIC: &[u8; 8] = b"JSURES01";
const MIRROR_HEALTH_MAGIC: &[u8; 8] = b"JSURHM01";
const MIRROR_HEALTH_VERSION: u16 = 1;
const MIRROR_HEALTH_HEADER_BYTES: usize = 16;
const MIRROR_HEALTH_ENTRY_BYTES: usize = 48;
static MIRROR_HEALTH_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// A transport-independent source for one signed update bundle.
pub trait UpdateBundleSource {
    /// Stable, path-free mirror identity for persistent health ordering.
    ///
    /// Sources without a stable identity retain caller priority and receive no
    /// persisted health state.
    fn mirror_identity(&self) -> Option<[u8; 32]> {
        None
    }

    /// Returns exactly one bounded canonical manifest candidate.
    fn read_manifest(&self) -> Result<Vec<u8>, SourceError>;
    /// Returns exactly one detached 64-byte signature candidate.
    fn read_signature(&self) -> Result<[u8; SIGNATURE_BYTES], SourceError>;
    /// Returns one canonical threshold signature set when the transport supports it.
    fn read_signature_set(&self) -> Result<SignatureSet, SourceError> {
        Err(SourceError::SignatureSetUnsupported)
    }
    /// Copies one manifest-named artifact into a fresh destination.
    fn copy_artifact(
        &self,
        name: &str,
        destination: &Path,
        max_bytes: u64,
    ) -> Result<(), SourceError>;

    /// Appends an artifact starting at an already durable byte offset.
    ///
    /// Implementations that cannot prove range semantics must reject a nonzero
    /// offset. The default preserves legacy sources for complete downloads.
    /// 从已持久化的字节偏移继续追加工件；无法证明 Range 语义的来源必须拒绝
    /// 非零偏移。默认实现仅支持完整下载，保持旧来源兼容。
    fn resume_artifact(
        &self,
        name: &str,
        destination: &Path,
        max_bytes: u64,
        offset: u64,
    ) -> Result<(), SourceError> {
        if offset != 0 {
            return Err(SourceError::ResumeUnsupported);
        }
        self.copy_artifact(name, destination, max_bytes)
    }
}

/// One durable mirror-health record. It is ordering information only and never
/// participates in manifest trust, signature, authorization or anti-rollback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MirrorHealthEntry {
    /// Stable path-free mirror identity. 稳定、无路径的镜像身份。
    pub identity: [u8; 32],
    /// Successful completed materializations. 成功完成材料化的次数。
    pub successes: u32,
    /// Failed authentication or artifact attempts. 认证或工件尝试失败次数。
    pub failures: u32,
    /// Monotonic local update sequence. 单调递增的本地更新序号。
    pub last_sequence: u64,
}

/// Caller-selected durable snapshot of long-term mirror outcomes.
#[derive(Clone, Debug)]
pub struct MirrorHealthStore {
    path: PathBuf,
}

impl MirrorHealthStore {
    /// Selects the exact non-directory snapshot path. The parent must exist.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Returns the exact snapshot path. 返回精确的快照路径。
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn load(&self) -> Result<MirrorHealthState, SourceError> {
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(MirrorHealthState::default())
            }
            Err(source) => {
                return Err(SourceError::Io {
                    operation: "inspect mirror health snapshot",
                    path: self.path.clone(),
                    source,
                })
            }
        };
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(mirror_health_error(
                &self.path,
                "snapshot is not a regular non-symlink file",
            ));
        }
        let len = usize::try_from(metadata.len())
            .map_err(|_| mirror_health_error(&self.path, "snapshot length is not addressable"))?;
        if len < MIRROR_HEALTH_HEADER_BYTES
            || !(len - MIRROR_HEALTH_HEADER_BYTES).is_multiple_of(MIRROR_HEALTH_ENTRY_BYTES)
        {
            return Err(mirror_health_error(&self.path, "snapshot length is invalid"));
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(len)
            .map_err(|_| mirror_health_error(&self.path, "snapshot allocation failed"))?;
        bytes.resize(len, 0);
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.path)
            .map_err(|source| SourceError::Io {
                operation: "open mirror health snapshot",
                path: self.path.clone(),
                source,
            })?;
        file.read_exact(&mut bytes)
            .map_err(|source| SourceError::Io {
                operation: "read mirror health snapshot",
                path: self.path.clone(),
                source,
            })?;
        if &bytes[..8] != MIRROR_HEALTH_MAGIC
            || u16::from_le_bytes([bytes[8], bytes[9]]) != MIRROR_HEALTH_VERSION
            || bytes[10..12] != [0, 0]
        {
            return Err(mirror_health_error(&self.path, "snapshot header is invalid"));
        }
        let count = u32::from_le_bytes(bytes[12..16].try_into().expect("four-byte field")) as usize;
        if count != (len - MIRROR_HEALTH_HEADER_BYTES) / MIRROR_HEALTH_ENTRY_BYTES {
            return Err(mirror_health_error(
                &self.path,
                "snapshot entry count is inconsistent",
            ));
        }
        let mut state = MirrorHealthState::default();
        let (records, remainder) =
            bytes[MIRROR_HEALTH_HEADER_BYTES..].as_chunks::<MIRROR_HEALTH_ENTRY_BYTES>();
        if !remainder.is_empty() {
            return Err(mirror_health_error(
                &self.path,
                "snapshot has a partial entry",
            ));
        }
        for record in records {
            let identity: [u8; 32] = record[..32].try_into().expect("32-byte identity");
            if identity == [0; 32] || state.entries.contains_key(&identity) {
                return Err(mirror_health_error(
                    &self.path,
                    "snapshot contains zero or duplicate identity",
                ));
            }
            let entry = MirrorHealthEntry {
                identity,
                successes: u32::from_le_bytes(record[32..36].try_into().expect("four-byte field")),
                failures: u32::from_le_bytes(record[36..40].try_into().expect("four-byte field")),
                last_sequence: u64::from_le_bytes(
                    record[40..48].try_into().expect("eight-byte field"),
                ),
            };
            if entry.last_sequence == 0 {
                return Err(mirror_health_error(
                    &self.path,
                    "snapshot contains a zero sequence",
                ));
            }
            state.next_sequence = state
                .next_sequence
                .max(entry.last_sequence.saturating_add(1));
            state.entries.insert(identity, entry);
        }
        Ok(state)
    }

    fn store(&self, state: &MirrorHealthState) -> Result<(), SourceError> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| mirror_health_error(&self.path, "snapshot has no parent"))?;
        let file_name = self
            .path
            .file_name()
            .ok_or_else(|| mirror_health_error(&self.path, "snapshot has no file name"))?
            .to_string_lossy();
        let sequence = MIRROR_HEALTH_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(
            ".{file_name}.{}.{sequence}.tmp",
            std::process::id()
        ));
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(
                MIRROR_HEALTH_HEADER_BYTES
                    .checked_add(state.entries.len().saturating_mul(MIRROR_HEALTH_ENTRY_BYTES))
                    .ok_or_else(|| mirror_health_error(&self.path, "snapshot length overflow"))?,
            )
            .map_err(|_| mirror_health_error(&self.path, "snapshot allocation failed"))?;
        bytes.extend_from_slice(MIRROR_HEALTH_MAGIC);
        bytes.extend_from_slice(&MIRROR_HEALTH_VERSION.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        let count = u32::try_from(state.entries.len())
            .map_err(|_| mirror_health_error(&self.path, "too many mirror entries"))?;
        bytes.extend_from_slice(&count.to_le_bytes());
        for entry in state.entries.values() {
            bytes.extend_from_slice(&entry.identity);
            bytes.extend_from_slice(&entry.successes.to_le_bytes());
            bytes.extend_from_slice(&entry.failures.to_le_bytes());
            bytes.extend_from_slice(&entry.last_sequence.to_le_bytes());
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)
            .map_err(|source| SourceError::Io {
                operation: "create mirror health temporary snapshot",
                path: temporary.clone(),
                source,
            })?;
        if let Err(source) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
            drop(file);
            let _ = fs::remove_file(&temporary);
            return Err(SourceError::Io {
                operation: "persist mirror health temporary snapshot",
                path: temporary,
                source,
            });
        }
        drop(file);
        if let Err(source) = fs::rename(&temporary, &self.path) {
            let _ = fs::remove_file(&temporary);
            return Err(SourceError::Io {
                operation: "publish mirror health snapshot",
                path: self.path.clone(),
                source,
            });
        }
        sync_directory(parent)
    }
}

#[derive(Default)]
struct MirrorHealthState {
    entries: BTreeMap<[u8; 32], MirrorHealthEntry>,
    next_sequence: u64,
}

impl MirrorHealthState {
    fn record(&mut self, identity: [u8; 32], success: bool) {
        let sequence = self.next_sequence.max(1);
        self.next_sequence = sequence.saturating_add(1);
        let entry = self
            .entries
            .entry(identity)
            .or_insert(MirrorHealthEntry {
                identity,
                successes: 0,
                failures: 0,
                last_sequence: sequence,
            });
        if success {
            entry.successes = entry.successes.saturating_add(1);
        } else {
            entry.failures = entry.failures.saturating_add(1);
        }
        entry.last_sequence = sequence;
    }

    fn score(&self, identity: [u8; 32]) -> (i64, u64) {
        self.entries
            .get(&identity)
            .map(|entry| {
                (
                    i64::from(entry.successes)
                        .saturating_mul(4)
                        .saturating_sub(i64::from(entry.failures).saturating_mul(3)),
                    entry.last_sequence,
                )
            })
            .unwrap_or((0, 0))
    }
}

fn mirror_health_error(path: &Path, reason: &'static str) -> SourceError {
    SourceError::MirrorHealth {
        path: path.to_path_buf(),
        reason,
    }
}

fn mirror_identity(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0]);
    hasher.update(value);
    hasher.finalize().into()
}

fn note_mirror_outcome(
    health: Option<&MirrorHealthStore>,
    state: &mut MirrorHealthState,
    identity: Option<[u8; 32]>,
    success: bool,
) -> Result<(), SourceError> {
    let (Some(store), Some(identity)) = (health, identity) else {
        return Ok(());
    };
    state.record(identity, success);
    store.store(state)
}

/// Offline bundle rooted in a local directory.
#[derive(Clone, Debug)]
pub struct DirectoryBundle {
    root: PathBuf,
}

impl DirectoryBundle {
    /// Selects one offline bundle root.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Returns the selected root.
    pub fn root(&self) -> &Path {
        &self.root
    }
}

impl UpdateBundleSource for DirectoryBundle {
    fn mirror_identity(&self) -> Option<[u8; 32]> {
        let root = fs::canonicalize(&self.root).unwrap_or_else(|_| self.root.clone());
        Some(mirror_identity(
            b"directory",
            root.as_os_str().as_bytes(),
        ))
    }

    fn read_manifest(&self) -> Result<Vec<u8>, SourceError> {
        read_bounded_regular(
            &self.root.join(SOURCE_MANIFEST_FILE),
            MAX_MANIFEST_CBOR_BYTES as u64,
            "read offline manifest",
        )
    }

    fn read_signature(&self) -> Result<[u8; SIGNATURE_BYTES], SourceError> {
        read_signature_path(
            &self.root.join(SOURCE_SIGNATURE_FILE),
            "read offline signature",
        )
    }

    fn read_signature_set(&self) -> Result<SignatureSet, SourceError> {
        read_signature_set_path(
            &self.root.join(SOURCE_SIGNATURE_SET_FILE),
            "read offline signature set",
        )
    }

    fn copy_artifact(
        &self,
        name: &str,
        destination: &Path,
        max_bytes: u64,
    ) -> Result<(), SourceError> {
        self.resume_artifact(name, destination, max_bytes, 0)
    }

    fn resume_artifact(
        &self,
        name: &str,
        destination: &Path,
        max_bytes: u64,
        offset: u64,
    ) -> Result<(), SourceError> {
        validate_artifact_name(name)?;
        let source = self.root.join(SOURCE_ARTIFACT_DIR).join(name);
        copy_regular_resume(&source, destination, max_bytes, name, offset)
    }
}

/// HTTPS bundle fetched through the system `curl` transport.
///
/// Redirects remain HTTPS by default. Callers testing a controlled local HTTP
/// origin may opt in explicitly; enabling HTTP changes transport policy but
/// does not weaken manifest signature or artifact digest verification.
#[derive(Clone, Debug)]
pub struct HttpBundle {
    base_url: String,
    curl: PathBuf,
    allow_http: bool,
    identity: Option<[u8; 32]>,
}

impl HttpBundle {
    /// Selects an HTTPS bundle root and the system `curl` executable.
    pub fn new(base_url: impl Into<String>, curl: impl Into<PathBuf>) -> Self {
        Self {
            base_url: base_url.into(),
            curl: curl.into(),
            allow_http: false,
            identity: None,
        }
    }

    /// Allows plain HTTP for an explicitly controlled local test origin.
    pub fn allow_http(mut self, allow: bool) -> Self {
        self.allow_http = allow;
        self
    }

    /// Supplies a stable, path-free identity for durable health ordering.
    ///
    /// Callers should derive this from configuration rather than embedding URL
    /// credentials or query parameters in the persisted health record.
    pub fn with_mirror_identity(mut self, identity: [u8; 32]) -> Self {
        self.identity = (identity != [0; 32]).then_some(identity);
        self
    }

    fn url(&self, relative: &str) -> Result<String, SourceError> {
        let allowed_scheme = if self.allow_http {
            self.base_url.starts_with("https://") || self.base_url.starts_with("http://")
        } else {
            self.base_url.starts_with("https://")
        };
        if !allowed_scheme
            || self
                .base_url
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
            || relative.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(SourceError::InvalidUrl);
        }
        Ok(format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            relative
        ))
    }

    fn run_curl(
        &self,
        relative: &str,
        max_bytes: u64,
        output: &mut impl Write,
    ) -> Result<u64, SourceError> {
        self.run_curl_range(relative, max_bytes, output, 0)
    }

    fn run_curl_range(
        &self,
        relative: &str,
        max_bytes: u64,
        output: &mut impl Write,
        offset: u64,
    ) -> Result<u64, SourceError> {
        let url = self.url(relative)?;
        let protocols = if self.allow_http {
            "=https,http"
        } else {
            "=https"
        };
        let mut command = Command::new(&self.curl);
        command.args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--globoff",
            "--proto",
            protocols,
            "--proto-redir",
            protocols,
            "--max-redirs",
            "3",
            "--connect-timeout",
            "15",
            "--max-time",
            "600",
            "--max-filesize",
            &max_bytes.to_string(),
            "--header",
            "Accept-Encoding: identity",
            "--output",
            "-",
        ]);
        if offset != 0 {
            command.arg("--range").arg(format!("{offset}-"));
        }
        let mut child = command
            .arg(&url)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|source| SourceError::Transport {
                operation: "start curl",
                status: None,
                source,
            })?;
        let mut stdout = child.stdout.take().ok_or_else(|| SourceError::Transport {
            operation: "capture curl output",
            status: None,
            source: io::Error::other("curl stdout was not piped"),
        })?;
        let mut total = 0u64;
        let mut buffer = [0u8; READ_BUFFER_BYTES];
        loop {
            let count = match stdout.read(&mut buffer) {
                Ok(count) => count,
                Err(source) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(SourceError::Transport {
                        operation: "read curl output",
                        status: None,
                        source,
                    });
                }
            };
            if count == 0 {
                break;
            }
            total = total
                .checked_add(count as u64)
                .ok_or(SourceError::TooLarge {
                    name: relative.into(),
                    max: max_bytes,
                })?;
            if total > max_bytes {
                let _ = child.kill();
                let _ = child.wait();
                return Err(SourceError::TooLarge {
                    name: relative.into(),
                    max: max_bytes,
                });
            }
            if let Err(source) = output.write_all(&buffer[..count]) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(SourceError::Transport {
                    operation: "write fetched bytes",
                    status: None,
                    source,
                });
            }
        }
        let status = child.wait().map_err(|source| SourceError::Transport {
            operation: "wait for curl",
            status: None,
            source,
        })?;
        if !status.success() {
            return Err(SourceError::Transport {
                operation: "fetch update bundle",
                status: status.code(),
                source: io::Error::other("curl rejected the transfer"),
            });
        }
        Ok(total)
    }
}

impl UpdateBundleSource for HttpBundle {
    fn mirror_identity(&self) -> Option<[u8; 32]> {
        self.identity
    }

    fn read_manifest(&self) -> Result<Vec<u8>, SourceError> {
        let mut bytes = Vec::new();
        self.run_curl(
            SOURCE_MANIFEST_FILE,
            MAX_MANIFEST_CBOR_BYTES as u64,
            &mut bytes,
        )?;
        if bytes.is_empty() {
            return Err(SourceError::TooLarge {
                name: SOURCE_MANIFEST_FILE.into(),
                max: MAX_MANIFEST_CBOR_BYTES as u64,
            });
        }
        Ok(bytes)
    }

    fn read_signature(&self) -> Result<[u8; SIGNATURE_BYTES], SourceError> {
        let mut bytes = Vec::new();
        self.run_curl(SOURCE_SIGNATURE_FILE, SIGNATURE_BYTES as u64, &mut bytes)?;
        signature_array(bytes)
    }

    fn read_signature_set(&self) -> Result<SignatureSet, SourceError> {
        let mut bytes = Vec::new();
        self.run_curl(
            SOURCE_SIGNATURE_SET_FILE,
            MAX_SIGNATURE_SET_BYTES as u64,
            &mut bytes,
        )?;
        SignatureSet::decode(&bytes).map_err(SourceError::SignatureSet)
    }

    fn copy_artifact(
        &self,
        name: &str,
        destination: &Path,
        max_bytes: u64,
    ) -> Result<(), SourceError> {
        self.resume_artifact(name, destination, max_bytes, 0)
    }

    fn resume_artifact(
        &self,
        name: &str,
        destination: &Path,
        max_bytes: u64,
        offset: u64,
    ) -> Result<(), SourceError> {
        validate_artifact_name(name)?;
        if offset > max_bytes {
            return Err(SourceError::Size {
                name: name.into(),
                expected: max_bytes,
                actual: offset,
            });
        }
        if offset > 0 {
            let metadata = fs::symlink_metadata(destination).map_err(|source| SourceError::Io {
                operation: "inspect partial fetched artifact",
                path: destination.to_path_buf(),
                source,
            })?;
            if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() != offset
            {
                return Err(SourceError::ResumeState {
                    name: name.into(),
                    expected: offset,
                    actual: metadata.len(),
                });
            }
        }
        let mut output = OpenOptions::new()
            .append(true)
            .create(offset == 0)
            .custom_flags(libc::O_NOFOLLOW)
            .open(destination)
            .map_err(|source| SourceError::Io {
                operation: "create fetched artifact",
                path: destination.to_path_buf(),
                source,
            })?;
        let relative = format!("{SOURCE_ARTIFACT_DIR}/{name}");
        let remaining = max_bytes - offset;
        self.run_curl_range(&relative, remaining, &mut output, offset)
            .and_then(|fetched| {
                if fetched == remaining {
                    Ok(())
                } else {
                    Err(SourceError::Size {
                        name: name.into(),
                        expected: remaining,
                        actual: fetched,
                    })
                }
            })
            .and_then(|()| {
                output.sync_all().map_err(|source| SourceError::Io {
                    operation: "flush fetched artifact",
                    path: destination.to_path_buf(),
                    source,
                })
            })
    }
}

/// Verified manifest bytes and artifact paths materialized by one source.
pub struct MaterializedUpdate {
    /// Authenticated manifest.
    pub manifest: VerifiedCborManifest,
    /// Exact canonical manifest bytes that were authenticated.
    pub manifest_bytes: Vec<u8>,
    sources: Vec<OwnedArtifactSource>,
    root: PathBuf,
}

impl MaterializedUpdate {
    /// Borrows materialized artifacts for the common staging path.
    pub fn artifact_sources(&self) -> Vec<ArtifactSource<'_>> {
        self.sources
            .iter()
            .map(|source| ArtifactSource {
                name: &source.name,
                path: &source.path,
            })
            .collect()
    }
}

impl Drop for MaterializedUpdate {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[derive(Debug)]
struct OwnedArtifactSource {
    name: String,
    path: PathBuf,
}

/// Reads, authenticates and materializes one bundle before staging.
///
/// The spool is removed when the returned value is dropped. Manifest trust is
/// established before any declared artifact is requested.
pub fn materialize_verified<S: UpdateBundleSource + ?Sized>(
    source: &S,
    policy: TrustPolicy<'_>,
    target: UpdateTarget,
    spool_root: &Path,
) -> Result<MaterializedUpdate, SourceError> {
    match fs::symlink_metadata(spool_root) {
        Ok(_) => return Err(SourceError::SpoolExists(spool_root.to_path_buf())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(SourceError::Io {
                operation: "inspect source spool",
                path: spool_root.to_path_buf(),
                source,
            })
        }
    }
    fs::create_dir(spool_root).map_err(|source| SourceError::Io {
        operation: "create source spool",
        path: spool_root.to_path_buf(),
        source,
    })?;
    let result = (|| {
        let manifest_bytes = source.read_manifest()?;
        let signature = source.read_signature()?;
        let manifest = verify_cbor_manifest(policy, target, &manifest_bytes, signature)
            .map_err(SourceError::Manifest)?;
        let artifact_root = spool_root.join(SOURCE_ARTIFACT_DIR);
        fs::create_dir(&artifact_root).map_err(|source| SourceError::Io {
            operation: "create materialized artifact directory",
            path: artifact_root.clone(),
            source,
        })?;
        let mut artifacts = Vec::with_capacity(manifest.artifacts.len());
        for artifact in &manifest.artifacts {
            let path = artifact_root.join(&artifact.name);
            source.copy_artifact(&artifact.name, &path, artifact.size)?;
            artifacts.push(OwnedArtifactSource {
                name: artifact.name.clone(),
                path,
            });
        }
        Ok(MaterializedUpdate {
            manifest,
            manifest_bytes,
            sources: artifacts,
            root: spool_root.to_path_buf(),
        })
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(spool_root);
    }
    result
}

/// Authenticate and materialize one bundle through a production threshold policy.
pub fn materialize_verified_threshold<S: UpdateBundleSource + ?Sized>(
    source: &S,
    policy: ThresholdTrustPolicy<'_>,
    target: UpdateTarget,
    spool_root: &Path,
) -> Result<MaterializedUpdate, SourceError> {
    match fs::symlink_metadata(spool_root) {
        Ok(_) => return Err(SourceError::SpoolExists(spool_root.to_path_buf())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(SourceError::Io {
                operation: "inspect source spool",
                path: spool_root.to_path_buf(),
                source,
            })
        }
    }
    fs::create_dir(spool_root).map_err(|source| SourceError::Io {
        operation: "create source spool",
        path: spool_root.to_path_buf(),
        source,
    })?;
    let result = (|| {
        let manifest_bytes = source.read_manifest()?;
        let signatures = source.read_signature_set()?;
        let manifest = verify_cbor_manifest_threshold(policy, target, &manifest_bytes, signatures)
            .map_err(SourceError::Manifest)?;
        let artifact_root = spool_root.join(SOURCE_ARTIFACT_DIR);
        fs::create_dir(&artifact_root).map_err(|source| SourceError::Io {
            operation: "create materialized artifact directory",
            path: artifact_root.clone(),
            source,
        })?;
        let mut artifacts = Vec::with_capacity(manifest.artifacts.len());
        for artifact in &manifest.artifacts {
            let path = artifact_root.join(&artifact.name);
            source.copy_artifact(&artifact.name, &path, artifact.size)?;
            artifacts.push(OwnedArtifactSource {
                name: artifact.name.clone(),
                path,
            });
        }
        Ok(MaterializedUpdate {
            manifest,
            manifest_bytes,
            sources: artifacts,
            root: spool_root.to_path_buf(),
        })
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(spool_root);
    }
    result
}

/// Authenticate mirrors in priority order and materialize one bundle into a
/// durable resume spool.
///
/// The first authenticated manifest defines the bundle identity. Additional
/// mirrors are admitted only when they authenticate byte-identical manifest
/// bytes. A failed mirror may be replaced without changing signature, grant,
/// rollback, artifact hash or eventual staging authority.
///
/// 按优先级认证多个镜像并把一个更新包材料化到持久续传 spool。首个通过认证的
/// 清单定义包身份；仅接受认证后字节完全相同的其他镜像。镜像切换不改变签名、
/// 授权、反回滚、工件摘要或最终暂存权威。
pub fn materialize_verified_resumable(
    sources: &[&dyn UpdateBundleSource],
    policy: TrustPolicy<'_>,
    target: UpdateTarget,
    spool_root: &Path,
) -> Result<MaterializedUpdate, SourceError> {
    materialize_verified_mirrors(sources, spool_root, None, |source| {
        let manifest_bytes = source.read_manifest()?;
        let signature = source.read_signature()?;
        let manifest = verify_cbor_manifest(policy, target, &manifest_bytes, signature)
            .map_err(SourceError::Manifest)?;
        Ok((manifest_bytes, manifest))
    })
}

/// Threshold-authenticated mirror variant of [`materialize_verified_resumable`].
pub fn materialize_verified_threshold_resumable(
    sources: &[&dyn UpdateBundleSource],
    policy: ThresholdTrustPolicy<'_>,
    target: UpdateTarget,
    spool_root: &Path,
) -> Result<MaterializedUpdate, SourceError> {
    materialize_verified_mirrors(sources, spool_root, None, |source| {
        let manifest_bytes = source.read_manifest()?;
        let signatures = source.read_signature_set()?;
        let manifest = verify_cbor_manifest_threshold(policy, target, &manifest_bytes, signatures)
            .map_err(SourceError::Manifest)?;
        Ok((manifest_bytes, manifest))
    })
}

/// Mirror variant that durably ranks stable mirror identities by long-term
/// outcomes. Health affects only attempt order; every admitted mirror still
/// passes the same manifest, signature, rollback and artifact-digest checks.
pub fn materialize_verified_resumable_with_health(
    sources: &[&dyn UpdateBundleSource],
    policy: TrustPolicy<'_>,
    target: UpdateTarget,
    spool_root: &Path,
    health: &MirrorHealthStore,
) -> Result<MaterializedUpdate, SourceError> {
    materialize_verified_mirrors(sources, spool_root, Some(health), |source| {
        let manifest_bytes = source.read_manifest()?;
        let signature = source.read_signature()?;
        let manifest = verify_cbor_manifest(policy, target, &manifest_bytes, signature)
            .map_err(SourceError::Manifest)?;
        Ok((manifest_bytes, manifest))
    })
}

/// Threshold-authenticated persistent-health variant of
/// [`materialize_verified_resumable_with_health`].
pub fn materialize_verified_threshold_resumable_with_health(
    sources: &[&dyn UpdateBundleSource],
    policy: ThresholdTrustPolicy<'_>,
    target: UpdateTarget,
    spool_root: &Path,
    health: &MirrorHealthStore,
) -> Result<MaterializedUpdate, SourceError> {
    materialize_verified_mirrors(sources, spool_root, Some(health), |source| {
        let manifest_bytes = source.read_manifest()?;
        let signatures = source.read_signature_set()?;
        let manifest = verify_cbor_manifest_threshold(policy, target, &manifest_bytes, signatures)
            .map_err(SourceError::Manifest)?;
        Ok((manifest_bytes, manifest))
    })
}

fn materialize_verified_mirrors<F>(
    sources: &[&dyn UpdateBundleSource],
    spool_root: &Path,
    health: Option<&MirrorHealthStore>,
    verify: F,
) -> Result<MaterializedUpdate, SourceError>
where
    F: Fn(&dyn UpdateBundleSource) -> Result<(Vec<u8>, VerifiedCborManifest), SourceError>,
{
    if sources.is_empty() {
        return Err(SourceError::NoVerifiedSource);
    }
    let mut health_state = health
        .map(MirrorHealthStore::load)
        .transpose()?
        .unwrap_or_default();
    let active_identities: BTreeSet<[u8; 32]> =
        sources.iter().filter_map(|source| source.mirror_identity()).collect();
    health_state
        .entries
        .retain(|identity, _| active_identities.contains(identity));
    let mut ordered: Vec<usize> = (0..sources.len()).collect();
    ordered.sort_by_key(|index| {
        let identity = sources[*index].mirror_identity();
        let (score, sequence) = identity
            .map(|identity| health_state.score(identity))
            .unwrap_or((0, 0));
        (std::cmp::Reverse(score), std::cmp::Reverse(sequence), *index)
    });
    let mut authenticated = Vec::new();
    let mut primary_digest = None;
    let mut primary_bytes = None;
    let mut primary_manifest = None;
    let mut last_error = None;
    for index in ordered {
        let source = sources[index];
        match verify(source) {
            Ok((bytes, manifest)) => {
                let digest = manifest.manifest.manifest_sha256;
                if primary_digest.is_none() {
                    primary_digest = Some(digest);
                    primary_bytes = Some(bytes);
                    primary_manifest = Some(manifest);
                    authenticated.push(source);
                } else if primary_digest == Some(digest) {
                    authenticated.push(source);
                } else {
                    note_mirror_outcome(
                        health,
                        &mut health_state,
                        source.mirror_identity(),
                        false,
                    )?;
                }
            }
            Err(error) => {
                note_mirror_outcome(
                    health,
                    &mut health_state,
                    source.mirror_identity(),
                    false,
                )?;
                last_error = Some(error);
            }
        }
    }
    let (Some(digest), Some(manifest_bytes), Some(manifest)) =
        (primary_digest, primary_bytes, primary_manifest)
    else {
        return Err(last_error.unwrap_or(SourceError::NoVerifiedSource));
    };
    prepare_resume_spool(spool_root, digest)?;
    let artifact_root = spool_root.join(SOURCE_ARTIFACT_DIR);
    match fs::symlink_metadata(&artifact_root) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => {
            return Err(SourceError::Io {
                operation: "inspect resume artifact directory",
                path: artifact_root,
                source: io::Error::new(io::ErrorKind::InvalidInput, "not a directory"),
            })
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(&artifact_root).map_err(|source| SourceError::Io {
                operation: "create resume artifact directory",
                path: artifact_root.clone(),
                source,
            })?;
        }
        Err(source) => {
            return Err(SourceError::Io {
                operation: "inspect resume artifact directory",
                path: artifact_root,
                source,
            })
        }
    }
    let mut artifacts = Vec::with_capacity(manifest.artifacts.len());
    for artifact in &manifest.artifacts {
        let path = artifact_root.join(&artifact.name);
        materialize_one_artifact(
            &authenticated,
            artifact.name.as_str(),
            &path,
            artifact,
            health,
            &mut health_state,
        )?;
        artifacts.push(OwnedArtifactSource {
            name: artifact.name.clone(),
            path,
        });
    }
    Ok(MaterializedUpdate {
        manifest,
        manifest_bytes,
        sources: artifacts,
        root: spool_root.to_path_buf(),
    })
}

fn prepare_resume_spool(spool_root: &Path, manifest_sha256: [u8; 32]) -> Result<(), SourceError> {
    match fs::symlink_metadata(spool_root) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => {
            return Err(SourceError::Io {
                operation: "inspect source resume spool",
                path: spool_root.to_path_buf(),
                source: io::Error::new(io::ErrorKind::InvalidInput, "not a directory"),
            })
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(spool_root).map_err(|source| SourceError::Io {
                operation: "create source resume spool",
                path: spool_root.to_path_buf(),
                source,
            })?;
        }
        Err(source) => {
            return Err(SourceError::Io {
                operation: "inspect source resume spool",
                path: spool_root.to_path_buf(),
                source,
            })
        }
    }
    let checkpoint_path = spool_root.join(RESUME_CHECKPOINT_FILE);
    let expected = resume_checkpoint_bytes(manifest_sha256);
    match fs::symlink_metadata(&checkpoint_path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            let actual = fs::read(&checkpoint_path).map_err(|source| SourceError::Io {
                operation: "read source resume checkpoint",
                path: checkpoint_path.clone(),
                source,
            })?;
            if actual != expected {
                return Err(SourceError::CheckpointMismatch);
            }
        }
        Ok(_) => {
            return Err(SourceError::Io {
                operation: "inspect source resume checkpoint",
                path: checkpoint_path,
                source: io::Error::new(io::ErrorKind::InvalidInput, "not a regular file"),
            })
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&checkpoint_path)
                .map_err(|source| SourceError::Io {
                    operation: "create source resume checkpoint",
                    path: checkpoint_path.clone(),
                    source,
                })?;
            file.write_all(&expected)
                .and_then(|_| file.sync_all())
                .map_err(|source| SourceError::Io {
                    operation: "persist source resume checkpoint",
                    path: checkpoint_path,
                    source,
                })?;
            sync_directory(spool_root)?;
        }
        Err(source) => {
            return Err(SourceError::Io {
                operation: "inspect source resume checkpoint",
                path: checkpoint_path,
                source,
            })
        }
    }
    Ok(())
}

fn resume_checkpoint_bytes(manifest_sha256: [u8; 32]) -> [u8; 40] {
    let mut bytes = [0u8; 40];
    bytes[..8].copy_from_slice(RESUME_CHECKPOINT_MAGIC);
    bytes[8..].copy_from_slice(&manifest_sha256);
    bytes
}

fn materialize_one_artifact(
    sources: &[&dyn UpdateBundleSource],
    name: &str,
    path: &Path,
    artifact: &jasper_lifecycle_model::manifest_cbor::VerifiedArtifact,
    health: Option<&MirrorHealthStore>,
    health_state: &mut MirrorHealthState,
) -> Result<(), SourceError> {
    let mut last_error = None;
    for source in sources {
        let offset = match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                if metadata.len() > artifact.size {
                    truncate_artifact(path)?;
                    0
                } else {
                    metadata.len()
                }
            }
            Ok(_) => {
                return Err(SourceError::Io {
                    operation: "inspect partial update artifact",
                    path: path.to_path_buf(),
                    source: io::Error::new(io::ErrorKind::InvalidInput, "not a regular file"),
                })
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => 0,
            Err(source) => {
                return Err(SourceError::Io {
                    operation: "inspect partial update artifact",
                    path: path.to_path_buf(),
                    source,
                })
            }
        };
        if offset == artifact.size {
            if artifact_matches(path, artifact)? {
                note_mirror_outcome(
                    health,
                    health_state,
                    source.mirror_identity(),
                    true,
                )?;
                return Ok(());
            }
            note_mirror_outcome(health, health_state, source.mirror_identity(), false)?;
            truncate_artifact(path)?;
        }
        let resume_offset = if offset == artifact.size { 0 } else { offset };
        match source.resume_artifact(name, path, artifact.size, resume_offset) {
            Ok(()) => {
                let actual = fs::metadata(path)
                    .map_err(|source| SourceError::Io {
                        operation: "inspect completed update artifact",
                        path: path.to_path_buf(),
                        source,
                    })?
                    .len();
                if actual == artifact.size && artifact_matches(path, artifact)? {
                    note_mirror_outcome(
                        health,
                        health_state,
                        source.mirror_identity(),
                        true,
                    )?;
                    return Ok(());
                }
                note_mirror_outcome(health, health_state, source.mirror_identity(), false)?;
                last_error = Some(SourceError::ArtifactDigest { name: name.into() });
                truncate_artifact(path)?;
            }
            Err(error) => {
                note_mirror_outcome(health, health_state, source.mirror_identity(), false)?;
                last_error = Some(error);
            }
        }
    }
    Err(last_error.unwrap_or(SourceError::NoVerifiedSource))
}

fn truncate_artifact(path: &Path) -> Result<(), SourceError> {
    let file = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| SourceError::Io {
            operation: "open partial update artifact",
            path: path.to_path_buf(),
            source,
        })?;
    file.set_len(0)
        .and_then(|_| file.sync_all())
        .map_err(|source| SourceError::Io {
            operation: "reset invalid update artifact",
            path: path.to_path_buf(),
            source,
        })
}

fn artifact_matches(
    path: &Path,
    artifact: &jasper_lifecycle_model::manifest_cbor::VerifiedArtifact,
) -> Result<bool, SourceError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| SourceError::Io {
            operation: "open completed update artifact",
            path: path.to_path_buf(),
            source,
        })?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; READ_BUFFER_BYTES];
    loop {
        let count = file.read(&mut buffer).map_err(|source| SourceError::Io {
            operation: "read completed update artifact",
            path: path.to_path_buf(),
            source,
        })?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or(SourceError::TooLarge {
                name: path.display().to_string(),
                max: artifact.size,
            })?;
        hasher.update(&buffer[..count]);
    }
    Ok(total == artifact.size && hasher.finalize().as_slice() == artifact.sha256.as_slice())
}

fn sync_directory(path: &Path) -> Result<(), SourceError> {
    let directory = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|source| SourceError::Io {
            operation: "open directory for resume checkpoint",
            path: path.to_path_buf(),
            source,
        })?;
    directory.sync_all().map_err(|source| SourceError::Io {
        operation: "flush resume checkpoint directory",
        path: path.to_path_buf(),
        source,
    })
}

/// Update-source failure.
#[derive(Debug)]
pub enum SourceError {
    /// Local source or spool I/O failed.
    Io {
        /// Failed operation.
        operation: &'static str,
        /// Affected path.
        path: PathBuf,
        /// Underlying error.
        source: io::Error,
    },
    /// Bundle URL or scheme is invalid.
    InvalidUrl,
    /// Manifest-named artifact is not a safe relative component.
    InvalidArtifactName,
    /// A fetched value exceeds its declared or protocol bound.
    TooLarge {
        /// Source item.
        name: String,
        /// Maximum accepted bytes.
        max: u64,
    },
    /// A fetched value is shorter than its exact requirement.
    Size {
        /// Source item.
        name: String,
        /// Required bytes.
        expected: u64,
        /// Actual bytes.
        actual: u64,
    },
    /// Detached signature length is not 64 bytes.
    InvalidSignatureLength(usize),
    /// Transport cannot provide a canonical threshold signature set.
    SignatureSetUnsupported,
    /// Threshold signature-set decoding failed.
    SignatureSet(ThresholdError),
    /// The source spool path already exists.
    SpoolExists(PathBuf),
    /// The source cannot prove safe range semantics for a resumed transfer.
    ResumeUnsupported,
    /// A partial-artifact length does not match the durable resume checkpoint.
    ResumeState {
        /// Artifact name.
        name: String,
        /// Expected durable offset.
        expected: u64,
        /// Actual file length.
        actual: u64,
    },
    /// The spool belongs to a different authenticated manifest.
    CheckpointMismatch,
    /// A completed artifact does not match its authenticated digest.
    ArtifactDigest {
        /// Artifact name.
        name: String,
    },
    /// No configured mirror produced an authenticated manifest.
    NoVerifiedSource,
    /// The requested spool has no usable parent.
    InvalidSpoolPath(PathBuf),
    /// Persistent mirror-health snapshot is malformed or unsafe.
    MirrorHealth {
        /// Snapshot path.
        path: PathBuf,
        /// Stable failure reason.
        reason: &'static str,
    },
    /// Manifest parsing, trust, signature, rollback or policy verification failed.
    Manifest(CborManifestError),
    /// Process, transport, or stream operation failed.
    Transport {
        /// Failed operation.
        operation: &'static str,
        /// Process exit status when one exists.
        status: Option<i32>,
        /// Underlying local error.
        source: io::Error,
    },
}

impl fmt::Display for SourceError {
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
            Self::InvalidUrl => write!(formatter, "invalid update bundle URL"),
            Self::InvalidArtifactName => write!(formatter, "invalid artifact name"),
            Self::TooLarge { name, max } => {
                write!(formatter, "update source {name} exceeds {max} bytes")
            }
            Self::Size {
                name,
                expected,
                actual,
            } => write!(
                formatter,
                "update source {name} size mismatch: expected {expected}, got {actual}"
            ),
            Self::InvalidSignatureLength(length) => {
                write!(formatter, "update signature is {length} bytes; expected 64")
            }
            Self::SignatureSetUnsupported => {
                write!(formatter, "update source does not support threshold signatures")
            }
            Self::SignatureSet(error) => {
                write!(formatter, "threshold signature set rejected: {error:?}")
            }
            Self::SpoolExists(path) => {
                write!(formatter, "source spool already exists: {}", path.display())
            }
            Self::ResumeUnsupported => {
                write!(formatter, "update source cannot prove safe transfer-range semantics")
            }
            Self::ResumeState {
                name,
                expected,
                actual,
            } => write!(
                formatter,
                "partial update artifact {name} has {actual} bytes; resume checkpoint requires {expected}"
            ),
            Self::CheckpointMismatch => {
                write!(formatter, "update resume checkpoint belongs to another manifest")
            }
            Self::ArtifactDigest { name } => {
                write!(formatter, "update artifact digest rejected: {name}")
            }
            Self::NoVerifiedSource => {
                write!(formatter, "no update mirror produced an authenticated manifest")
            }
            Self::InvalidSpoolPath(path) => {
                write!(formatter, "source spool has no parent: {}", path.display())
            }
            Self::MirrorHealth { path, reason } => {
                write!(formatter, "invalid mirror health snapshot {}: {reason}", path.display())
            }
            Self::Manifest(error) => write!(formatter, "update manifest rejected: {error:?}"),
            Self::Transport {
                operation,
                status,
                source,
            } => write!(
                formatter,
                "{operation} failed with status {status:?}: {source}"
            ),
        }
    }
}

impl std::error::Error for SourceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } | Self::Transport { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn validate_artifact_name(name: &str) -> Result<(), SourceError> {
    if name.is_empty()
        || name.len() > 63
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        || name == "."
        || name == ".."
    {
        return Err(SourceError::InvalidArtifactName);
    }
    Ok(())
}

fn read_bounded_regular(
    path: &Path,
    max_bytes: u64,
    operation: &'static str,
) -> Result<Vec<u8>, SourceError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| SourceError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(SourceError::Io {
            operation,
            path: path.to_path_buf(),
            source: io::Error::new(io::ErrorKind::InvalidInput, "source is not a regular file"),
        });
    }
    if metadata.len() > max_bytes {
        return Err(SourceError::TooLarge {
            name: path.display().to_string(),
            max: max_bytes,
        });
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| SourceError::Io {
            operation,
            path: path.to_path_buf(),
            source,
        })?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    let mut buffer = [0u8; READ_BUFFER_BYTES];
    loop {
        let count = file.read(&mut buffer).map_err(|source| SourceError::Io {
            operation,
            path: path.to_path_buf(),
            source,
        })?;
        if count == 0 {
            break;
        }
        if bytes.len() as u64 + count as u64 > max_bytes {
            return Err(SourceError::TooLarge {
                name: path.display().to_string(),
                max: max_bytes,
            });
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    Ok(bytes)
}

fn read_signature_path(
    path: &Path,
    operation: &'static str,
) -> Result<[u8; SIGNATURE_BYTES], SourceError> {
    signature_array(read_bounded_regular(
        path,
        SIGNATURE_BYTES as u64,
        operation,
    )?)
}

fn signature_array(bytes: Vec<u8>) -> Result<[u8; SIGNATURE_BYTES], SourceError> {
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| SourceError::InvalidSignatureLength(bytes.len()))
}

fn read_signature_set_path(path: &Path, operation: &'static str) -> Result<SignatureSet, SourceError> {
    let bytes = read_bounded_regular(path, MAX_SIGNATURE_SET_BYTES as u64, operation)?;
    SignatureSet::decode(&bytes).map_err(SourceError::SignatureSet)
}

fn copy_regular_resume(
    source_path: &Path,
    destination: &Path,
    max_bytes: u64,
    artifact_name: &str,
    offset: u64,
) -> Result<(), SourceError> {
    let metadata = fs::symlink_metadata(source_path).map_err(|source| SourceError::Io {
        operation: "inspect offline artifact",
        path: source_path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(SourceError::Io {
            operation: "inspect offline artifact",
            path: source_path.to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                "artifact is not a regular file",
            ),
        });
    }
    if metadata.len() > max_bytes {
        return Err(SourceError::TooLarge {
            name: artifact_name.into(),
            max: max_bytes,
        });
    }
    if metadata.len() != max_bytes {
        return Err(SourceError::Size {
            name: artifact_name.into(),
            expected: max_bytes,
            actual: metadata.len(),
        });
    }
    if offset > max_bytes {
        return Err(SourceError::Size {
            name: artifact_name.into(),
            expected: max_bytes,
            actual: offset,
        });
    }
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(source_path)
        .map_err(|source| SourceError::Io {
            operation: "open offline artifact",
            path: source_path.to_path_buf(),
            source,
        })?;
    input
        .seek(SeekFrom::Start(offset))
        .map_err(|source| SourceError::Io {
            operation: "seek offline artifact",
            path: source_path.to_path_buf(),
            source,
        })?;
    let destination_metadata = match fs::symlink_metadata(destination) {
        Ok(metadata) => {
            if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() != offset
            {
                return Err(SourceError::ResumeState {
                    name: artifact_name.into(),
                    expected: offset,
                    actual: metadata.len(),
                });
            }
            Some(metadata)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound && offset == 0 => None,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(SourceError::ResumeState {
                name: artifact_name.into(),
                expected: offset,
                actual: 0,
            })
        }
        Err(source) => {
            return Err(SourceError::Io {
                operation: "inspect materialized artifact",
                path: destination.to_path_buf(),
                source,
            })
        }
    };
    let mut options = OpenOptions::new();
    options.append(true).custom_flags(libc::O_NOFOLLOW);
    if destination_metadata.is_none() {
        options.create_new(true);
    }
    let mut output = options
        .open(destination)
        .map_err(|source| SourceError::Io {
            operation: "open materialized artifact",
            path: destination.to_path_buf(),
            source,
        })?;
    (|| {
        let mut buffer = [0u8; READ_BUFFER_BYTES];
        let mut total = offset;
        loop {
            let count = input.read(&mut buffer).map_err(|source| SourceError::Io {
                operation: "read offline artifact",
                path: source_path.to_path_buf(),
                source,
            })?;
            if count == 0 {
                break;
            }
            total = total
                .checked_add(count as u64)
                .ok_or(SourceError::TooLarge {
                    name: artifact_name.into(),
                    max: max_bytes,
                })?;
            if total > max_bytes {
                return Err(SourceError::TooLarge {
                    name: artifact_name.into(),
                    max: max_bytes,
                });
            }
            output
                .write_all(&buffer[..count])
                .map_err(|source| SourceError::Io {
                    operation: "write materialized artifact",
                    path: destination.to_path_buf(),
                    source,
                })?;
        }
        if total != max_bytes {
            return Err(SourceError::Size {
                name: artifact_name.into(),
                expected: max_bytes,
                actual: total,
            });
        }
        output.sync_all().map_err(|source| SourceError::Io {
            operation: "flush materialized artifact",
            path: destination.to_path_buf(),
            source,
        })
    })()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrent_health_writers_never_share_a_temporary_path() {
        let directory = std::env::temp_dir().join(format!(
            "jasper-mirror-health-{}-{}",
            std::process::id(),
            MIRROR_HEALTH_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let store = MirrorHealthStore::new(directory.join("health.bin"));
        let mut writers = Vec::new();
        for index in 0..8u8 {
            let store = store.clone();
            writers.push(std::thread::spawn(move || {
                let mut state = MirrorHealthState::default();
                state.record([index + 1; 32], true);
                store.store(&state)
            }));
        }
        for writer in writers {
            writer.join().unwrap().unwrap();
        }
        assert!(store.load().is_ok());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn http_health_identity_is_explicit_and_rejects_zero() {
        let source = HttpBundle::new("https://example.invalid", "curl");
        assert_eq!(source.mirror_identity(), None);
        assert_eq!(
            source
                .clone()
                .with_mirror_identity([7; 32])
                .mirror_identity(),
            Some([7; 32])
        );
        assert_eq!(
            source.with_mirror_identity([0; 32]).mirror_identity(),
            None
        );
    }
}
