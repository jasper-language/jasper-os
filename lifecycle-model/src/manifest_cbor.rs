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
/// 单个清单最多包含的直接依赖数。Maximum direct dependencies in one manifest.
pub const MAX_DEPENDENCIES: usize = 64;

/// 更新发布通道。
/// Update release channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Channel {
    /// 开发通道。Development channel.
    Dev,
    /// 预览通道。Preview channel.
    Preview,
    /// 稳定通道。Stable channel.
    Stable,
    /// 长期维护通道。Long-term-support channel.
    Lts,
}

impl Channel {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "dev" => Self::Dev,
            "preview" => Self::Preview,
            "stable" => Self::Stable,
            "lts" => Self::Lts,
            _ => return None,
        })
    }
}

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
    channel: String,
    release_sequence: u64,
    security_epoch: u64,
    created_at: u64,
    expires_at: u64,
    target_abi_min: u16,
    target_abi_max: u16,
    data_schema_min: u32,
    data_schema_max: u32,
    migration_reversible: bool,
    rollback_allowed: bool,
    target_profile: [u8; 32],
    signer: [u8; 32],
    dependencies: Vec<String>,
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
    /// 通道、ABI、Schema、迁移或依赖策略非法。Channel, ABI, schema, migration, or dependency policy is invalid.
    InvalidPolicy,
    /// 签名、信任、反回滚或 Profile 验证失败。Signature, trust, anti-rollback, or profile failure.
    Manifest(ManifestError),
}

/// 已通过规范编码和完整性字段检查的工件。
/// Artifact that passed canonical-encoding and integrity-field validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedArtifact {
    /// 工件类别。Artifact kind.
    pub kind: ArtifactKind,
    /// 稳定且唯一的工件名。Stable and unique artifact name.
    pub name: String,
    /// 工件字节数。Artifact size in bytes.
    pub size: u64,
    /// 工件完整内容 SHA-256。SHA-256 of the complete artifact.
    pub sha256: [u8; 32],
}

/// 通过 CBOR、工件和发布策略验证的清单。
/// Manifest that passed CBOR, artifact, and release-policy verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedCborManifest {
    /// 基础清单验证结果。Base manifest verification result.
    pub manifest: VerifiedManifest,
    /// 发布通道。Release channel.
    pub channel: Channel,
    /// 目标原生 ABI 范围。Target native-ABI range.
    pub target_abi: (u16, u16),
    /// 数据 Schema 范围。Data-schema range.
    pub data_schema: (u32, u32),
    /// 清单创建时间。Manifest creation time.
    pub created_at: u64,
    /// 清单过期时间；零表示不按墙钟过期。Manifest expiry; zero means no wall-clock expiry.
    pub expires_at: u64,
    /// 迁移是否可逆。Whether migration is reversible.
    pub migration_reversible: bool,
    /// 是否允许自动回滚。Whether automatic rollback is allowed.
    pub rollback_allowed: bool,
    /// 直接依赖名称。Direct dependency names.
    pub dependencies: Vec<String>,
    /// 经验证的工件描述，顺序与规范清单一致。
    /// Verified artifact descriptors in canonical manifest order.
    pub artifacts: Vec<VerifiedArtifact>,
    /// 所有工件大小之和。Sum of all artifact sizes.
    pub artifact_bytes: u64,
}

/// 解析规范 CBOR、验证每个工件并执行完整签名/信任/反回滚检查。
/// Parses canonical CBOR, validates every artifact, and runs full signature/trust/anti-rollback checks.
pub fn verify_cbor_manifest(
    policy: TrustPolicy<'_>,
    target: UpdateTarget,
    bytes: &[u8],
    signature: [u8; 64],
) -> Result<VerifiedCborManifest, CborManifestError> {
    if bytes.is_empty() || bytes.len() > MAX_MANIFEST_CBOR_BYTES {
        return Err(CborManifestError::TooLarge);
    }
    let wire: ManifestWire =
        ciborium::de::from_reader(bytes).map_err(|_| CborManifestError::Decode)?;
    let channel = Channel::parse(&wire.channel).ok_or(CborManifestError::InvalidPolicy)?;
    if wire.target_abi_min == 0
        || wire.target_abi_min > wire.target_abi_max
        || wire.data_schema_min > wire.data_schema_max
        || (wire.expires_at != 0 && wire.expires_at < wire.created_at)
        || (!wire.migration_reversible && wire.rollback_allowed)
    {
        return Err(CborManifestError::InvalidPolicy);
    }
    validate_dependencies(&wire.dependencies)?;
    let (artifacts, artifact_bytes) = validate_artifacts(&wire.artifacts)?;
    let mut canonical = Vec::with_capacity(bytes.len());
    ciborium::ser::into_writer(&wire, &mut canonical).map_err(|_| CborManifestError::Decode)?;
    if canonical != bytes {
        return Err(CborManifestError::NonCanonical);
    }
    let manifest = verify_manifest(
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
    .map_err(CborManifestError::Manifest)?;
    Ok(VerifiedCborManifest {
        manifest,
        channel,
        target_abi: (wire.target_abi_min, wire.target_abi_max),
        data_schema: (wire.data_schema_min, wire.data_schema_max),
        created_at: wire.created_at,
        expires_at: wire.expires_at,
        migration_reversible: wire.migration_reversible,
        rollback_allowed: wire.rollback_allowed,
        dependencies: wire.dependencies,
        artifacts,
        artifact_bytes,
    })
}

fn validate_dependencies(dependencies: &[String]) -> Result<(), CborManifestError> {
    if dependencies.len() > MAX_DEPENDENCIES {
        return Err(CborManifestError::InvalidPolicy);
    }
    let mut unique = BTreeSet::new();
    for dependency in dependencies {
        if dependency.is_empty()
            || dependency.len() > 63
            || !dependency
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            || !unique.insert(dependency.as_str())
        {
            return Err(CborManifestError::InvalidPolicy);
        }
    }
    Ok(())
}

fn validate_artifacts(
    artifacts: &[ArtifactWire],
) -> Result<(Vec<VerifiedArtifact>, u64), CborManifestError> {
    if artifacts.is_empty() || artifacts.len() > MAX_ARTIFACTS {
        return Err(CborManifestError::InvalidArtifact);
    }
    let mut names = BTreeSet::new();
    let mut digests = BTreeSet::new();
    let mut verified = Vec::with_capacity(artifacts.len());
    let mut total_bytes = 0u64;
    for artifact in artifacts {
        let kind = ArtifactKind::parse(&artifact.kind).ok_or(CborManifestError::InvalidArtifact)?;
        if artifact.name.is_empty()
            || artifact.name.len() > 63
            || !artifact
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            || artifact.size == 0
            || artifact.sha256 == [0; 32]
        {
            return Err(CborManifestError::InvalidArtifact);
        }
        if !names.insert(artifact.name.as_str()) || !digests.insert(artifact.sha256) {
            return Err(CborManifestError::DuplicateArtifact);
        }
        total_bytes = total_bytes
            .checked_add(artifact.size)
            .ok_or(CborManifestError::InvalidArtifact)?;
        verified.push(VerifiedArtifact {
            kind,
            name: artifact.name.clone(),
            size: artifact.size,
            sha256: artifact.sha256,
        });
    }
    Ok((verified, total_bytes))
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
            channel: String::from("stable"),
            release_sequence: 9,
            security_epoch: 4,
            created_at: 100,
            expires_at: 200,
            target_abi_min: 3,
            target_abi_max: 3,
            data_schema_min: 1,
            data_schema_max: 2,
            migration_reversible: true,
            rollback_allowed: true,
            target_profile: PROFILE,
            signer: key.verifying_key().to_bytes(),
            dependencies: alloc::vec![String::from("jasper.base")],
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
        assert_eq!(verified.manifest.release_sequence, 9);
        assert_eq!(verified.channel, Channel::Stable);
        assert_eq!(verified.target_abi, (3, 3));
        assert_eq!(verified.data_schema, (1, 2));
        assert_eq!(verified.created_at, 100);
        assert_eq!(verified.expires_at, 200);
        assert_eq!(verified.dependencies, [String::from("jasper.base")]);
        assert_eq!(verified.artifact_bytes, 4096);
        assert_eq!(verified.artifacts.len(), 1);
        assert_eq!(verified.artifacts[0].kind, ArtifactKind::BaseSystem);
        let grant = LocalInstallGrant {
            locally_authenticated: true,
            purpose: 1,
            manifest_sha256: verified.manifest.manifest_sha256,
            profile: PROFILE,
            expires_at: 10,
        };
        assert_eq!(
            crate::manifest::authorize_install(verified.manifest, grant, 9),
            Ok(verified.manifest)
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

    #[test]
    fn contradictory_migration_and_rollback_policy_is_rejected() {
        let (_, bytes, signature) = fixture();
        let mut wire: ManifestWire = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        wire.migration_reversible = false;
        wire.rollback_allowed = true;
        let mut invalid = Vec::new();
        ciborium::ser::into_writer(&wire, &mut invalid).unwrap();
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
                &invalid,
                signature,
            ),
            Err(CborManifestError::InvalidPolicy)
        );
        assert_eq!(
            validate_dependencies(&[String::from("one"), String::from("one")]),
            Err(CborManifestError::InvalidPolicy)
        );
    }

    #[test]
    fn every_declared_manifest_policy_range_fails_closed() {
        let (_, bytes, signature) = fixture();
        let reject = |mutate: &dyn Fn(&mut ManifestWire)| {
            let mut wire: ManifestWire = ciborium::de::from_reader(bytes.as_slice()).unwrap();
            mutate(&mut wire);
            let mut invalid = Vec::new();
            ciborium::ser::into_writer(&wire, &mut invalid).unwrap();
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
                    &invalid,
                    signature,
                ),
                Err(CborManifestError::InvalidPolicy)
            );
        };

        reject(&|wire| wire.channel = String::from("nightly"));
        reject(&|wire| wire.target_abi_min = 0);
        reject(&|wire| {
            wire.target_abi_min = 4;
            wire.target_abi_max = 3;
        });
        reject(&|wire| {
            wire.data_schema_min = 3;
            wire.data_schema_max = 2;
        });
        reject(&|wire| {
            wire.created_at = 201;
            wire.expires_at = 200;
        });
        reject(&|wire| wire.dependencies = alloc::vec![String::from("bad/name")]);
        reject(&|wire| {
            wire.dependencies = (0..=MAX_DEPENDENCIES)
                .map(|index| {
                    let mut name = String::from("dep");
                    name.push((b'0' + (index % 10) as u8) as char);
                    name
                })
                .collect();
        });
    }

    #[test]
    fn artifact_size_sum_overflow_fails_closed() {
        let artifacts = [
            ArtifactWire {
                kind: String::from("kernel"),
                name: String::from("one"),
                size: u64::MAX,
                sha256: [1; 32],
            },
            ArtifactWire {
                kind: String::from("driver"),
                name: String::from("two"),
                size: 1,
                sha256: [2; 32],
            },
        ];
        assert_eq!(
            validate_artifacts(&artifacts),
            Err(CborManifestError::InvalidArtifact)
        );
    }
}
