//! Transport-neutral update bundle acquisition for LC-2.
//!
//! The transport may be an offline directory or an HTTPS endpoint, but both
//! paths return the same authenticated bytes to the one manifest verifier and
//! staging coordinator. Transport identity never replaces signature, grant,
//! dependency, capacity or digest checks.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use jasper_lifecycle_model::manifest::{TrustPolicy, UpdateTarget};
use jasper_lifecycle_model::manifest_cbor::{
    verify_cbor_manifest, CborManifestError, VerifiedCborManifest, MAX_MANIFEST_CBOR_BYTES,
};

use crate::ArtifactSource;

/// Manifest file name in an offline bundle or at an HTTPS bundle root.
pub const SOURCE_MANIFEST_FILE: &str = "manifest.cbor";
/// Signature file name in an offline bundle or at an HTTPS bundle root.
pub const SOURCE_SIGNATURE_FILE: &str = "manifest.sig";
/// Artifact directory in an offline bundle or below an HTTPS bundle root.
pub const SOURCE_ARTIFACT_DIR: &str = "artifacts";

const READ_BUFFER_BYTES: usize = 64 * 1024;
const SIGNATURE_BYTES: usize = 64;

/// A transport-independent source for one signed update bundle.
pub trait UpdateBundleSource {
    /// Returns exactly one bounded canonical manifest candidate.
    fn read_manifest(&self) -> Result<Vec<u8>, SourceError>;
    /// Returns exactly one detached 64-byte signature candidate.
    fn read_signature(&self) -> Result<[u8; SIGNATURE_BYTES], SourceError>;
    /// Copies one manifest-named artifact into a fresh destination.
    fn copy_artifact(
        &self,
        name: &str,
        destination: &Path,
        max_bytes: u64,
    ) -> Result<(), SourceError>;
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

    fn copy_artifact(
        &self,
        name: &str,
        destination: &Path,
        max_bytes: u64,
    ) -> Result<(), SourceError> {
        validate_artifact_name(name)?;
        let source = self.root.join(SOURCE_ARTIFACT_DIR).join(name);
        copy_regular_bounded(&source, destination, max_bytes, name)
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
        let url = self.url(relative)?;
        let protocols = if self.allow_http {
            "=https,http"
        } else {
            "=https"
        };
        let mut child = Command::new(&self.curl)
            .args([
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
                "--output",
                "-",
                &url,
            ])
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

    fn copy_artifact(
        &self,
        name: &str,
        destination: &Path,
        max_bytes: u64,
    ) -> Result<(), SourceError> {
        validate_artifact_name(name)?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)
            .map_err(|source| SourceError::Io {
                operation: "create fetched artifact",
                path: destination.to_path_buf(),
                source,
            })?;
        let relative = format!("{SOURCE_ARTIFACT_DIR}/{name}");
        let result = self
            .run_curl(&relative, max_bytes, &mut output)
            .and_then(|total| {
                if total == max_bytes {
                    Ok(())
                } else {
                    Err(SourceError::Size {
                        name: name.into(),
                        expected: max_bytes,
                        actual: total,
                    })
                }
            })
            .and_then(|()| {
                output.sync_all().map_err(|source| SourceError::Io {
                    operation: "flush fetched artifact",
                    path: destination.to_path_buf(),
                    source,
                })
            });
        if result.is_err() {
            let _ = fs::remove_file(destination);
        }
        result
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
    /// The source spool path already exists.
    SpoolExists(PathBuf),
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
            Self::SpoolExists(path) => {
                write!(formatter, "source spool already exists: {}", path.display())
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

fn copy_regular_bounded(
    source_path: &Path,
    destination: &Path,
    max_bytes: u64,
    artifact_name: &str,
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
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(source_path)
        .map_err(|source| SourceError::Io {
            operation: "open offline artifact",
            path: source_path.to_path_buf(),
            source,
        })?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|source| SourceError::Io {
            operation: "create materialized artifact",
            path: destination.to_path_buf(),
            source,
        })?;
    let result = (|| {
        let mut buffer = [0u8; READ_BUFFER_BYTES];
        let mut total = 0u64;
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
    })();
    if result.is_err() {
        let _ = fs::remove_file(destination);
    }
    result
}
