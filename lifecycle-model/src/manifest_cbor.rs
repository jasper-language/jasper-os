//! LC-2 确定性 CBOR 清单解析与签名验证。
//! Deterministic CBOR manifest parsing and signature verification for LC-2.
//!
//! 本模块使用成熟 Serde/Ciborium 实现解析，不手写 CBOR 解码器。解析结果必须能
//! 重编码为完全相同的字节，防止接受非确定性或重复键编码。
//! This module uses mature Serde/Ciborium codecs. Parsed input must re-encode to the exact
//! original bytes, rejecting non-deterministic or duplicate-key encodings.

extern crate alloc;

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::manifest::{
    verify_manifest, ManifestEnvelope, ManifestError, TrustPolicy, UpdateTarget, VerifiedManifest,
};

/// 单个清单的最大 CBOR 字节数。Maximum CBOR bytes in one manifest.
pub const MAX_MANIFEST_CBOR_BYTES: usize = 8192;
/// 单个清单最多包含的工件数。Maximum artifacts in one manifest.
pub const MAX_ARTIFACTS: usize = 64;

/// 清单中的工件类别。
/// Artifact classes in a manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactKind {
    /// 启动链。Boot chain.
    BootChain,
    /// 内核。Kernel.
    Kernel,
    /// 基础系统映像。Base-system image.
    BaseSystem,
    /// 系统服务。System service.
    SystemService,
    /// 驱动。Driver.
    Driver,
    /// 固件。Firmware.
    Firmware,
    /// 兼容运行环境。Compatibility runtime.
    CompatRuntime,
    /// 普通应用。Application.
    Application,
}

impl ArtifactKind {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "boot-chain" => Self::BootChain,
            "kernel" => Self::Kernel,
            "base-system" => Self::BaseSystem,
            "system-service" => Self::SystemService,
            "driver" => Self::Driver,
            "firmware" => Self::Firmware,
            "compat-runtime" => Self::CompatRuntime,
            "application" => Self::Application,
            _ => return None,
        })
    }
}

/// 一个被签名清单工件的 wire 表示。
/// Wire representation of one signed artifact.
#[derive(Clone, Serialize, Deserialize)]
struct ArtifactWire {
    kind: String,
    name: String,
    size: u64,
    sha256: [u8; 32],
}

/// 确定性 CBOR 清单 wire 表示；字段顺序即规范编码顺序。
/// Deterministic CBOR wire representation; declaration order is the canonical encoding order.
#[derive(Serialize, Deserialize)]
struct ManifestWire {
    schema_version: u16,
    release_sequence: u64,
    security_epoch: u64,
    target_profile: [u8; 32],
    signer: [u8; 32],
    artifacts: Vec<ArtifactWire>,
}

/// CBOR 清单验证错误。
/// CBOR-manifest verification error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CborManifestError {
    /// CBOR 解码或结构类型错误。CBOR decoding or structural type error.
    Decode,
    /// 重编码结果与输入不一致。Re-encoding differs from the input bytes.
    NonCanonical,
    /// 清单超过有界长度。Manifest exceeds its bounded size.
    TooLarge,
    /// 工件数量、名称、类别、尺寸或摘要非法。Artifact count, name, kind, size, or digest is invalid.
    InvalidArtifact,
    /// 工件名称或摘要重复。Artifact name or digest is duplicated.
    DuplicateArtifact,
    /// 签名、信任、反回滚或 Profile 验证失败。Signature, trust, anti-rollback, or profile failure.
    Manifest(ManifestError),
}

/// 解析规范 CBOR、验证每个工件并执行完整签名/信任/反回滚检查。
/// Parses canonical CBOR, validates every artifact, and runs full signature/trust/anti-rollback checks.
pub fn verify_cbor_manifest(
    policy: TrustPolicy<'_>,
    target: UpdateTarget,
    bytes: &[u8],
    signature: [u8; 64],
) -> Result<VerifiedManifest, CborManifestError> {
    if bytes.is_empty() || bytes.len() > MAX_MANIFEST_CBOR_BYTES {
        return Err(CborManifestError::TooLarge);
    }
    let wire: ManifestWire =
        ciborium::de::from_reader(bytes).map_err(|_| CborManifestError::Decode)?;
    validate_artifacts(&wire.artifacts)?;
    let mut canonical = Vec::with_capacity(bytes.len());
    ciborium::ser::into_writer(&wire, &mut canonical).map_err(|_| CborManifestError::Decode)?;
    if canonical != bytes {
        return Err(CborManifestError::NonCanonical);
    }
    verify_manifest(
        policy,
        target,
        ManifestEnvelope {
            schema_version: wire.schema_version,
            release_sequence: wire.release_sequence,
            security_epoch: wire.security_epoch,
            target_profile: wire.target_profile,
            canonical_cbor: bytes,
            signer: wire.signer,
            signature,
        },
    )
    .map_err(CborManifestError::Manifest)
}

fn validate_artifacts(artifacts: &[ArtifactWire]) -> Result<(), CborManifestError> {
    if artifacts.is_empty() || artifacts.len() > MAX_ARTIFACTS {
        return Err(CborManifestError::InvalidArtifact);
    }
    let mut names = BTreeSet::new();
    let mut digests = BTreeSet::new();
    for artifact in artifacts {
        if ArtifactKind::parse(&artifact.kind).is_none()
            || artifact.name.is_empty()
            || artifact.name.len() > 63
            || !artifact
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            || artifact.size == 0
            || artifact.sha256 == [0; 32]
            || !names.insert(artifact.name.as_str())
            || !digests.insert(artifact.sha256)
        {
            return if names.contains(artifact.name.as_str()) || digests.contains(&artifact.sha256) {
                Err(CborManifestError::DuplicateArtifact)
            } else {
                Err(CborManifestError::InvalidArtifact)
            };
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{signing_message, LocalInstallGrant, MANIFEST_SCHEMA_VERSION};
    use ed25519_dalek::{Signer, SigningKey};

    const PROFILE: [u8; 32] = [0x42; 32];

    fn encode(key: &SigningKey, artifacts: &[ArtifactWire]) -> Vec<u8> {
        let wire = ManifestWire {
            schema_version: MANIFEST_SCHEMA_VERSION,
            release_sequence: 9,
            security_epoch: 4,
            target_profile: PROFILE,
            signer: key.verifying_key().to_bytes(),
            artifacts: artifacts.to_vec(),
        };
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&wire, &mut bytes).unwrap();
        bytes
    }

    fn fixture() -> (SigningKey, Vec<u8>, [u8; 64]) {
        let key = SigningKey::from_bytes(&[7; 32]);
        let artifacts = [ArtifactWire {
            kind: String::from("base-system"),
            name: String::from("jasper-system"),
            size: 4096,
            sha256: [0x33; 32],
        }];
        let bytes = encode(&key, &artifacts);
        let wire: ManifestWire = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        let envelope = ManifestEnvelope {
            schema_version: wire.schema_version,
            release_sequence: wire.release_sequence,
            security_epoch: wire.security_epoch,
            target_profile: wire.target_profile,
            canonical_cbor: &bytes,
            signer: wire.signer,
            signature: [0; 64],
        };
        let (message, len) = signing_message(&envelope).unwrap();
        let signature = key.sign(&message[..len]).to_bytes();
        (key, bytes, signature)
    }

    #[test]
    fn canonical_cbor_manifest_verifies_and_binds_full_bytes() {
        let (key, bytes, signature) = fixture();
        let trusted = [key.verifying_key().to_bytes()];
        let verified = verify_cbor_manifest(
            TrustPolicy {
                trusted_keys: &trusted,
                revoked_keys: &[[0; 32]],
                minimum_security_epoch: 3,
            },
            UpdateTarget {
                rollback_floor: 8,
                profile: PROFILE,
            },
            &bytes,
            signature,
        )
        .unwrap();
        assert_eq!(verified.release_sequence, 9);
        let grant = LocalInstallGrant {
            locally_authenticated: true,
            purpose: 1,
            manifest_sha256: verified.manifest_sha256,
            profile: PROFILE,
            expires_at: 10,
        };
        assert_eq!(
            crate::manifest::authorize_install(verified, grant, 9),
            Ok(verified)
        );
    }

    #[test]
    fn duplicate_artifacts_and_malformed_cbor_fail_closed() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let duplicate = [
            ArtifactWire {
                kind: String::from("kernel"),
                name: String::from("same"),
                size: 1,
                sha256: [1; 32],
            },
            ArtifactWire {
                kind: String::from("driver"),
                name: String::from("same"),
                size: 2,
                sha256: [2; 32],
            },
        ];
        assert_eq!(
            validate_artifacts(&duplicate),
            Err(CborManifestError::DuplicateArtifact)
        );
        assert_eq!(
            verify_cbor_manifest(
                TrustPolicy {
                    trusted_keys: &[],
                    revoked_keys: &[],
                    minimum_security_epoch: 0,
                },
                UpdateTarget {
                    rollback_floor: 0,
                    profile: PROFILE,
                },
                &[0xff],
                [0; 64],
            ),
            Err(CborManifestError::Decode)
        );
        let _ = key;
    }

    #[test]
    fn nonminimal_cbor_integer_encoding_is_rejected() {
        let (_, bytes, signature) = fixture();
        let at = bytes
            .windows(3)
            .position(|window| window == [0x19, 0x10, 0x00])
            .expect("fixture encodes artifact size 4096");
        let mut noncanonical = Vec::with_capacity(bytes.len() + 2);
        noncanonical.extend_from_slice(&bytes[..at]);
        noncanonical.extend_from_slice(&[0x1a, 0x00, 0x00, 0x10, 0x00]);
        noncanonical.extend_from_slice(&bytes[at + 3..]);
        assert_eq!(
            verify_cbor_manifest(
                TrustPolicy {
                    trusted_keys: &[],
                    revoked_keys: &[],
                    minimum_security_epoch: 0,
                },
                UpdateTarget {
                    rollback_floor: 0,
                    profile: PROFILE,
                },
                &noncanonical,
                signature,
            ),
            Err(CborManifestError::NonCanonical)
        );
    }
}
