//! Transport-neutral update bundle acquisition for LC-2.
//!
//! The transport may be an offline directory or an HTTPS endpoint, but both
//! paths return the same authenticated bytes to the one manifest verifier and
//! staging coordinator. Transport identity never replaces signature, grant,
//! dependency, capacity or digest checks.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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

/// A transport-independent source for one signed update bundle.
pub trait UpdateBundleSource {
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
}

impl HttpBundle {
    /// Selects an HTTPS bundle root and the system `curl` executable.
    pub fn new(base_url: impl Into<String>, curl: impl Into<PathBuf>) -> Self {
        Self {
            base_url: base_url.into(),
            curl: curl.into(),
            allow_http: false,
        }
    }

    /// Allows plain HTTP for an explicitly controlled local test origin.
    pub fn allow_http(mut self, allow: bool) -> Self {
        self.allow_http = allow;
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
    materialize_verified_mirrors(sources, spool_root, |source| {
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
    materialize_verified_mirrors(sources, spool_root, |source| {
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
    verify: F,
) -> Result<MaterializedUpdate, SourceError>
where
    F: Fn(&dyn UpdateBundleSource) -> Result<(Vec<u8>, VerifiedCborManifest), SourceError>,
{
    if sources.is_empty() {
        return Err(SourceError::NoVerifiedSource);
    }
    let mut authenticated = Vec::new();
    let mut primary_digest = None;
    let mut primary_bytes = None;
    let mut primary_manifest = None;
    let mut last_error = None;
    for source in sources {
        match verify(*source) {
            Ok((bytes, manifest)) => {
                let digest = manifest.manifest.manifest_sha256;
                if primary_digest.is_none() {
                    primary_digest = Some(digest);
                    primary_bytes = Some(bytes);
                    primary_manifest = Some(manifest);
                    authenticated.push(*source);
                } else if primary_digest == Some(digest) {
                    authenticated.push(*source);
                }
            }
            Err(error) => last_error = Some(error),
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
        materialize_one_artifact(&authenticated, artifact.name.as_str(), &path, artifact)?;
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
                return Ok(());
            }
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
                    return Ok(());
                }
                last_error = Some(SourceError::ArtifactDigest { name: name.into() });
                truncate_artifact(path)?;
            }
            Err(error) => last_error = Some(error),
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
