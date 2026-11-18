//! LC-2 更新清单的域分隔签名与本地授权模型。
//! Domain-separated update-manifest signature and local-authorization model for LC-2.
//!
//! 本模块不解析 CBOR、不下载内容、不写槽位，也不注册接口。调用者必须提供确定性
//! CBOR 字节、其已解析声明和签名；本模块验证声明、签名、撤销、反回滚和本地授权。
//! This module does not decode CBOR, fetch content, write slots, or register an interface.
//! The caller supplies deterministic CBOR bytes, parsed claims, and a signature for verification.

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

/// 更新清单签名域。Update-manifest signature domain.
pub const SIGNATURE_DOMAIN: &[u8] = b"JASPER-UPDATE-V1\0";
/// 支持的清单 Schema。Supported manifest schema.
pub const MANIFEST_SCHEMA_VERSION: u16 = 1;
/// 单个确定性 CBOR 清单的最大长度。Maximum length of one deterministic CBOR manifest.
pub const MAX_CANONICAL_MANIFEST_BYTES: usize = 8192;
/// Maximum signatures admitted in one threshold set.
pub const MAX_THRESHOLD_SIGNATURES: usize = 3; // JASPER-HARDCODE-REVIEW: issue=21 source=release-threshold-policy-v1 reason=policy-bound
/// Domain separator for a canonical threshold signature set.
pub const SIGNATURE_SET_DOMAIN: &[u8] = b"JASPER-UPDATE-SIGSET-V1\0";
/// Encoded bytes per threshold signature entry.
pub const THRESHOLD_SIGNATURE_BYTES: usize = 32 + 64;
/// Maximum encoded threshold signature set.
pub const MAX_SIGNATURE_SET_BYTES: usize = SIGNATURE_SET_DOMAIN.len() // JASPER-HARDCODE-REVIEW: issue=21 source=release-threshold-policy-v1 reason=wire-bound
    + 1
    + MAX_THRESHOLD_SIGNATURES * THRESHOLD_SIGNATURE_BYTES;

/// 已由确定性 CBOR 解码器得到的清单声明和原始签名。
/// Manifest claims produced by a canonical-CBOR decoder, together with the detached signature.
#[derive(Clone, Copy, Debug)]
pub struct ManifestEnvelope<'a> {
    /// 清单 Schema 版本。Manifest schema version.
    pub schema_version: u16,
    /// 单调发布序列。Monotonic release sequence.
    pub release_sequence: u64,
    /// 防回滚安全纪元。Anti-rollback security epoch.
    pub security_epoch: u64,
    /// 目标 Profile 摘要。Target-profile digest.
    pub target_profile: [u8; 32],
    /// 完整确定性 CBOR 字节。Complete deterministic CBOR bytes.
    pub canonical_cbor: &'a [u8],
    /// 用于选择信任策略的发布者公钥。Publisher key used to select the trust policy.
    pub signer: [u8; 32],
    /// Ed25519 分离签名。Detached Ed25519 signature.
    pub signature: [u8; 64],
}

/// 当前信任快照。
/// Current trust snapshot.
#[derive(Clone, Copy, Debug)]
pub struct TrustPolicy<'a> {
    /// 当前受信发布公钥。Currently trusted publisher keys.
    pub trusted_keys: &'a [[u8; 32]],
    /// 已撤销发布公钥。Revoked publisher keys.
    pub revoked_keys: &'a [[u8; 32]],
    /// 持久最小安全纪元。Persistent minimum security epoch.
    pub minimum_security_epoch: u64,
}

/// Threshold trust snapshot for production update admission.
#[derive(Clone, Copy, Debug)]
pub struct ThresholdTrustPolicy<'a> {
    /// Current trusted publisher keys.
    pub trusted_keys: &'a [[u8; 32]],
    /// Revoked publisher keys; revocation takes precedence over trust.
    pub revoked_keys: &'a [[u8; 32]],
    /// Persistent minimum security epoch.
    pub minimum_security_epoch: u64,
    /// Minimum number of distinct valid signatures.
    pub threshold: u8,
}

/// One detached signer and signature in a canonical threshold set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThresholdSignature {
    /// Ed25519 public key identifying this signer.
    pub signer: [u8; 32],
    /// Detached Ed25519 signature over the canonical signature-set message.
    pub signature: [u8; 64],
}

/// Bounded canonical signature set carried beside the unchanged CBOR manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignatureSet {
    entries: [Option<ThresholdSignature>; MAX_THRESHOLD_SIGNATURES],
    len: u8,
}

/// Signature-set encoding or threshold-verification failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThresholdError {
    /// The signature set has an invalid length or domain prefix.
    SignatureSetFormat,
    /// Entries are unsorted, zero, or otherwise non-canonical.
    SignatureSetNonCanonical,
    /// The same signer appears more than once.
    DuplicateSigner,
    /// More signatures were supplied than the bounded set admits.
    TooManySignatures,
    /// The required threshold is zero or exceeds the admitted signature count.
    InvalidThreshold,
    /// Fewer independent valid signatures were supplied than required.
    InsufficientSignatures,
    /// The underlying manifest signature validation failed.
    Manifest(ManifestError),
}

impl SignatureSet {
    /// Construct an empty, non-publishable signature set.
    pub const fn empty() -> Self {
        Self {
            entries: [None; MAX_THRESHOLD_SIGNATURES],
            len: 0,
        }
    }

    /// Build a canonical set sorted by signer public key.
    pub fn new(entries: &[ThresholdSignature]) -> Result<Self, ThresholdError> {
        if entries.is_empty() || entries.len() > MAX_THRESHOLD_SIGNATURES {
            return Err(ThresholdError::TooManySignatures);
        }
        let mut set = Self::empty();
        for entry in entries {
            if entry.signer.iter().all(|byte| *byte == 0) {
                return Err(ThresholdError::SignatureSetFormat);
            }
            set.entries[set.len as usize] = Some(*entry);
            set.len += 1;
        }
        set.sort_and_check()
    }

    /// Number of signature entries currently retained.
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Whether the set contains no entries.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Iterate over retained signatures in canonical signer order.
    pub fn entries(&self) -> impl Iterator<Item = ThresholdSignature> + '_ {
        self.entries[..self.len as usize]
            .iter()
            .filter_map(|entry| *entry)
    }

    /// Encode the canonical fixed-layout signature set.
    pub fn encode(&self) -> Result<([u8; MAX_SIGNATURE_SET_BYTES], usize), ThresholdError> {
        if self.len < 2 {
            return Err(ThresholdError::InsufficientSignatures);
        }
        let mut out = [0u8; MAX_SIGNATURE_SET_BYTES];
        let mut at = SIGNATURE_SET_DOMAIN.len();
        out[..at].copy_from_slice(SIGNATURE_SET_DOMAIN);
        out[at] = self.len;
        at += 1;
        for entry in self.entries() {
            out[at..at + 32].copy_from_slice(&entry.signer);
            out[at + 32..at + 96].copy_from_slice(&entry.signature);
            at += THRESHOLD_SIGNATURE_BYTES;
        }
        Ok((out, at))
    }

    /// Decode and reject duplicates, non-canonical order and trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, ThresholdError> {
        if bytes.len() <= SIGNATURE_SET_DOMAIN.len() || !bytes.starts_with(SIGNATURE_SET_DOMAIN) {
            return Err(ThresholdError::SignatureSetFormat);
        }
        let count = bytes[SIGNATURE_SET_DOMAIN.len()] as usize;
        if !(2..=MAX_THRESHOLD_SIGNATURES).contains(&count) {
            return Err(ThresholdError::SignatureSetFormat);
        }
        let expected = SIGNATURE_SET_DOMAIN.len() + 1 + count * THRESHOLD_SIGNATURE_BYTES;
        if bytes.len() != expected {
            return Err(ThresholdError::SignatureSetFormat);
        }
        let mut set = Self::empty();
        let mut at = SIGNATURE_SET_DOMAIN.len() + 1;
        for slot in 0..count {
            let mut signer = [0u8; 32];
            let mut signature = [0u8; 64];
            signer.copy_from_slice(&bytes[at..at + 32]);
            signature.copy_from_slice(&bytes[at + 32..at + 96]);
            if signer.iter().all(|byte| *byte == 0) {
                return Err(ThresholdError::SignatureSetFormat);
            }
            if slot != 0 {
                let previous = set.entries[slot - 1].expect("previous threshold entry");
                if previous.signer >= signer {
                    return Err(if previous.signer == signer {
                        ThresholdError::DuplicateSigner
                    } else {
                        ThresholdError::SignatureSetNonCanonical
                    });
                }
            }
            set.entries[slot] = Some(ThresholdSignature { signer, signature });
            at += THRESHOLD_SIGNATURE_BYTES;
        }
        set.len = count as u8;
        Ok(set)
    }

    fn sort_and_check(mut self) -> Result<Self, ThresholdError> {
        for index in 1..self.len as usize {
            let mut cursor = index;
            while cursor > 0 {
                let left = self.entries[cursor - 1].expect("threshold left entry");
                let right = self.entries[cursor].expect("threshold right entry");
                if left.signer < right.signer {
                    break;
                }
                if left.signer == right.signer {
                    return Err(ThresholdError::DuplicateSigner);
                }
                self.entries[cursor - 1] = Some(right);
                self.entries[cursor] = Some(left);
                cursor -= 1;
            }
        }
        Ok(self)
    }
}

/// 调用方要求的目标状态。
/// Target state required by the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpdateTarget {
    /// 当前反回滚发布下限。Current release anti-rollback floor.
    pub rollback_floor: u64,
    /// 当前设备 Profile 摘要。Current device-profile digest.
    pub profile: [u8; 32],
}

/// 清单验证失败原因。
/// Manifest-verification failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManifestError {
    /// Schema 不支持。Unsupported schema.
    UnsupportedSchema,
    /// 清单为空或超过栈上有界上限。Manifest is empty or exceeds the bounded stack size.
    ManifestTooLarge,
    /// 发布序列低于或等于回滚下限。Release sequence is at or below the rollback floor.
    Downgrade,
    /// 安全纪元低于持久下限。Security epoch is below the persistent floor.
    SecurityEpoch,
    /// Profile 不匹配。Profile mismatch.
    WrongProfile,
    /// 发布者不在当前信任快照。Publisher is absent from the current trust snapshot.
    UnknownSigner,
    /// 发布者已经撤销。Publisher has been revoked.
    RevokedSigner,
    /// 公钥或签名编码失败。Public key or signature encoding failed.
    Encoding,
    /// Ed25519 严格验证失败。Ed25519 strict verification failed.
    Signature,
    /// 本地安装授权无效。Local installation authorization is invalid.
    Authorization,
}

/// 已验证清单；摘要用于后续工件绑定，声明不能由其他服务重新解释。
/// Verified manifest; digests bind later artifacts and claims cannot be reinterpreted by another service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedManifest {
    /// 发布序列。Release sequence.
    pub release_sequence: u64,
    /// 安全纪元。Security epoch.
    pub security_epoch: u64,
    /// 目标 Profile 摘要。Target-profile digest.
    pub target_profile: [u8; 32],
    /// 发布者公钥。Publisher key.
    pub signer: [u8; 32],
    /// 完整清单 SHA-256。SHA-256 of the complete manifest.
    pub manifest_sha256: [u8; 32],
}

/// 本地安装授权；来源账号或网络 Provider 不能替代。
/// Local installation authorization; a source account or network provider cannot replace it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalInstallGrant {
    /// 是否由本地用户/组织完成认证。Whether a local user or organization authenticated it.
    pub locally_authenticated: bool,
    /// 授权用途代码，必须非零。Non-zero authorization purpose code.
    pub purpose: u32,
    /// 获得授权的完整清单摘要。Digest of the exact authorized manifest.
    pub manifest_sha256: [u8; 32],
    /// Profile 范围。Profile scope.
    pub profile: [u8; 32],
    /// 单调时钟有效期。Monotonic validity end.
    pub expires_at: u64,
}

/// 验证更新清单的全部安全前置条件。
/// Verifies every security precondition for an update manifest.
pub fn verify_manifest(
    policy: TrustPolicy<'_>,
    target: UpdateTarget,
    envelope: ManifestEnvelope<'_>,
) -> Result<VerifiedManifest, ManifestError> {
    if envelope.schema_version != MANIFEST_SCHEMA_VERSION {
        return Err(ManifestError::UnsupportedSchema);
    }
    let (message, message_len) = signing_message(&envelope)?;
    if envelope.release_sequence <= target.rollback_floor {
        return Err(ManifestError::Downgrade);
    }
    if envelope.security_epoch < policy.minimum_security_epoch {
        return Err(ManifestError::SecurityEpoch);
    }
    if envelope.target_profile != target.profile {
        return Err(ManifestError::WrongProfile);
    }
    if !policy.trusted_keys.contains(&envelope.signer) {
        return Err(ManifestError::UnknownSigner);
    }
    if policy.revoked_keys.contains(&envelope.signer) {
        return Err(ManifestError::RevokedSigner);
    }
    let key = VerifyingKey::from_bytes(&envelope.signer).map_err(|_| ManifestError::Encoding)?;
    let signature = Signature::from_bytes(&envelope.signature);
    key.verify_strict(&message[..message_len], &signature)
        .map_err(|_| ManifestError::Signature)?;
    Ok(VerifiedManifest {
        release_sequence: envelope.release_sequence,
        security_epoch: envelope.security_epoch,
        target_profile: envelope.target_profile,
        signer: envelope.signer,
        manifest_sha256: Sha256::digest(envelope.canonical_cbor).into(),
    })
}

/// Verify an unchanged CBOR manifest against a production threshold policy.
///
/// Every supplied signature is authenticated. A revoked or unknown signer
/// invalidates the whole set even if the numeric threshold could otherwise be
/// met; revocation always takes precedence.
pub fn verify_manifest_threshold(
    policy: ThresholdTrustPolicy<'_>,
    target: UpdateTarget,
    envelope: ManifestEnvelope<'_>,
    signatures: SignatureSet,
) -> Result<VerifiedManifest, ThresholdError> {
    let trusted = policy.trusted_keys.len();
    if policy.threshold < 2
        || usize::from(policy.threshold) > trusted
        || trusted > MAX_THRESHOLD_SIGNATURES
    {
        return Err(ThresholdError::InvalidThreshold);
    }
    if signatures.is_empty() || signatures.len() < usize::from(policy.threshold) {
        return Err(ThresholdError::InsufficientSignatures);
    }
    let mut embedded = None;
    for entry in signatures.entries() {
        if entry.signer == envelope.signer {
            embedded = Some(entry.signature);
        }
        if policy.revoked_keys.contains(&entry.signer) {
            return Err(ThresholdError::Manifest(ManifestError::RevokedSigner));
        }
        if !policy.trusted_keys.contains(&entry.signer) {
            return Err(ThresholdError::Manifest(ManifestError::UnknownSigner));
        }
    }
    if embedded != Some(envelope.signature) {
        return Err(ThresholdError::Manifest(ManifestError::Signature));
    }
    let verified = verify_manifest(
        TrustPolicy {
            trusted_keys: policy.trusted_keys,
            revoked_keys: policy.revoked_keys,
            minimum_security_epoch: policy.minimum_security_epoch,
        },
        target,
        envelope,
    )
    .map_err(ThresholdError::Manifest)?;
    let (message, message_len) = signing_message(&envelope).map_err(ThresholdError::Manifest)?;
    for entry in signatures.entries() {
        let key = VerifyingKey::from_bytes(&entry.signer)
            .map_err(|_| ThresholdError::Manifest(ManifestError::Encoding))?;
        let signature = Signature::from_bytes(&entry.signature);
        key.verify_strict(&message[..message_len], &signature)
            .map_err(|_| ThresholdError::Manifest(ManifestError::Signature))?;
    }
    Ok(verified)
}

/// 验证本地安装授权；不产生下载、提交或网络副作用。
/// Verifies local installation authorization without download, commit, or network effects.
pub fn authorize_install(
    manifest: VerifiedManifest,
    grant: LocalInstallGrant,
    now: u64,
) -> Result<VerifiedManifest, ManifestError> {
    if !grant.locally_authenticated
        || grant.purpose == 0
        || grant.manifest_sha256 != manifest.manifest_sha256
        || grant.profile != manifest.target_profile
        || now >= grant.expires_at
    {
        return Err(ManifestError::Authorization);
    }
    Ok(manifest)
}

pub(crate) fn signing_message(
    envelope: &ManifestEnvelope<'_>,
) -> Result<([u8; MAX_CANONICAL_MANIFEST_BYTES], usize), ManifestError> {
    if envelope.canonical_cbor.is_empty() {
        return Err(ManifestError::ManifestTooLarge);
    }
    let payload_len = envelope.canonical_cbor.len();
    let fixed_len = SIGNATURE_DOMAIN.len() + 2 + 8 + 8 + 32 + 8;
    let total = fixed_len
        .checked_add(payload_len)
        .ok_or(ManifestError::ManifestTooLarge)?;
    if total > MAX_CANONICAL_MANIFEST_BYTES {
        return Err(ManifestError::ManifestTooLarge);
    }
    let mut message = [0u8; MAX_CANONICAL_MANIFEST_BYTES];
    let mut at = SIGNATURE_DOMAIN.len();
    message[..at].copy_from_slice(SIGNATURE_DOMAIN);
    message[at..at + 2].copy_from_slice(&envelope.schema_version.to_le_bytes());
    at += 2;
    message[at..at + 8].copy_from_slice(&envelope.release_sequence.to_le_bytes());
    at += 8;
    message[at..at + 8].copy_from_slice(&envelope.security_epoch.to_le_bytes());
    at += 8;
    message[at..at + 32].copy_from_slice(&envelope.target_profile);
    at += 32;
    message[at..at + 8].copy_from_slice(&(payload_len as u64).to_le_bytes());
    at += 8;
    message[at..at + payload_len].copy_from_slice(envelope.canonical_cbor);
    Ok((message, total))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const PROFILE: [u8; 32] = [0x42; 32];

    struct Fixture {
        key: SigningKey,
        bytes: [u8; 64],
    }

    impl Fixture {
        fn new() -> Self {
            let key = SigningKey::from_bytes(&[7; 32]);
            let mut bytes = [0u8; 64];
            bytes[..16].copy_from_slice(b"canonical-cbor!!");
            Self { key, bytes }
        }

        fn envelope(&self) -> ManifestEnvelope<'_> {
            let mut envelope = ManifestEnvelope {
                schema_version: MANIFEST_SCHEMA_VERSION,
                release_sequence: 9,
                security_epoch: 4,
                target_profile: PROFILE,
                canonical_cbor: &self.bytes,
                signer: self.key.verifying_key().to_bytes(),
                signature: [0; 64],
            };
            let (message, len) = signing_message(&envelope).unwrap();
            envelope.signature = self.key.sign(&message[..len]).to_bytes();
            envelope
        }

        fn policy(&self) -> ([[u8; 32]; 1], [[u8; 32]; 1]) {
            ([self.key.verifying_key().to_bytes()], [[0; 32]])
        }
    }

    fn target() -> UpdateTarget {
        UpdateTarget {
            rollback_floor: 8,
            profile: PROFILE,
        }
    }

    #[test]
    fn valid_domain_separated_manifest_verifies_and_binds_digest() {
        let fixture = Fixture::new();
        let (trusted, revoked) = fixture.policy();
        let verified = verify_manifest(
            TrustPolicy {
                trusted_keys: &trusted,
                revoked_keys: &revoked,
                minimum_security_epoch: 3,
            },
            target(),
            fixture.envelope(),
        )
        .unwrap();
        assert_eq!(verified.release_sequence, 9);
        assert_eq!(verified.security_epoch, 4);
        assert_eq!(verified.target_profile, PROFILE);
        let expected: [u8; 32] = Sha256::digest(fixture.bytes).into();
        assert_eq!(verified.manifest_sha256, expected);
    }

    #[test]
    fn tampered_payload_fails_strict_signature_verification() {
        let fixture = Fixture::new();
        let (trusted, revoked) = fixture.policy();
        let mut envelope = fixture.envelope();
        let mut tampered = fixture.bytes;
        tampered[0] ^= 1;
        envelope.canonical_cbor = &tampered;
        assert_eq!(
            verify_manifest(
                TrustPolicy {
                    trusted_keys: &trusted,
                    revoked_keys: &revoked,
                    minimum_security_epoch: 3
                },
                target(),
                envelope
            ),
            Err(ManifestError::Signature)
        );
    }

    #[test]
    fn wrong_domain_signature_is_not_reused() {
        let fixture = Fixture::new();
        let (trusted, revoked) = fixture.policy();
        let mut envelope = fixture.envelope();
        let wrong = fixture.key.sign(b"different-domain");
        envelope.signature = wrong.to_bytes();
        assert_eq!(
            verify_manifest(
                TrustPolicy {
                    trusted_keys: &trusted,
                    revoked_keys: &revoked,
                    minimum_security_epoch: 3
                },
                target(),
                envelope
            ),
            Err(ManifestError::Signature)
        );
    }

    #[test]
    fn revocation_downgrade_epoch_schema_and_profile_fail_closed() {
        let fixture = Fixture::new();
        let (trusted, _) = fixture.policy();
        let revoked = [fixture.key.verifying_key().to_bytes()];
        let policy = TrustPolicy {
            trusted_keys: &trusted,
            revoked_keys: &revoked,
            minimum_security_epoch: 3,
        };
        assert_eq!(
            verify_manifest(policy, target(), fixture.envelope()),
            Err(ManifestError::RevokedSigner)
        );

        let clean_policy = TrustPolicy {
            trusted_keys: &trusted,
            revoked_keys: &[[0; 32]],
            minimum_security_epoch: 3,
        };
        let mut envelope = fixture.envelope();
        envelope.release_sequence = 8;
        assert_eq!(
            verify_manifest(clean_policy, target(), envelope),
            Err(ManifestError::Downgrade)
        );
        envelope = fixture.envelope();
        envelope.security_epoch = 2;
        assert_eq!(
            verify_manifest(clean_policy, target(), envelope),
            Err(ManifestError::SecurityEpoch)
        );
        envelope = fixture.envelope();
        envelope.schema_version = 2;
        assert_eq!(
            verify_manifest(clean_policy, target(), envelope),
            Err(ManifestError::UnsupportedSchema)
        );
        envelope = fixture.envelope();
        envelope.target_profile = [0x43; 32];
        assert_eq!(
            verify_manifest(clean_policy, target(), envelope),
            Err(ManifestError::WrongProfile)
        );
        let unknown = [[9; 32]];
        assert_eq!(
            verify_manifest(
                TrustPolicy {
                    trusted_keys: &unknown,
                    revoked_keys: &[[0; 32]],
                    minimum_security_epoch: 3
                },
                target(),
                fixture.envelope()
            ),
            Err(ManifestError::UnknownSigner)
        );
    }

    #[test]
    fn local_authorization_requires_live_authenticated_profile_scoped_grant() {
        let fixture = Fixture::new();
        let (trusted, revoked) = fixture.policy();
        let verified = verify_manifest(
            TrustPolicy {
                trusted_keys: &trusted,
                revoked_keys: &revoked,
                minimum_security_epoch: 3,
            },
            target(),
            fixture.envelope(),
        )
        .unwrap();
        let grant = LocalInstallGrant {
            locally_authenticated: true,
            purpose: 1,
            manifest_sha256: verified.manifest_sha256,
            profile: PROFILE,
            expires_at: 10,
        };
        assert_eq!(authorize_install(verified, grant, 9), Ok(verified));
        assert_eq!(
            authorize_install(
                verified,
                LocalInstallGrant {
                    manifest_sha256: [0x55; 32],
                    ..grant
                },
                9
            ),
            Err(ManifestError::Authorization)
        );
        assert_eq!(
            authorize_install(
                verified,
                LocalInstallGrant {
                    locally_authenticated: false,
                    ..grant
                },
                9
            ),
            Err(ManifestError::Authorization)
        );
        assert_eq!(
            authorize_install(
                verified,
                LocalInstallGrant {
                    expires_at: 9,
                    ..grant
                },
                9
            ),
            Err(ManifestError::Authorization)
        );
        assert_eq!(
            authorize_install(
                verified,
                LocalInstallGrant {
                    profile: [0x44; 32],
                    ..grant
                },
                9
            ),
            Err(ManifestError::Authorization)
        );
    }

    #[test]
    fn oversized_or_empty_manifest_is_rejected() {
        let fixture = Fixture::new();
        let (trusted, revoked) = fixture.policy();
        let policy = TrustPolicy {
            trusted_keys: &trusted,
            revoked_keys: &revoked,
            minimum_security_epoch: 3,
        };
        let mut envelope = fixture.envelope();
        envelope.canonical_cbor = &[];
        assert_eq!(
            verify_manifest(policy, target(), envelope),
            Err(ManifestError::ManifestTooLarge)
        );
        let oversized = [0u8; MAX_CANONICAL_MANIFEST_BYTES];
        envelope.canonical_cbor = &oversized;
        assert_eq!(
            verify_manifest(policy, target(), envelope),
            Err(ManifestError::ManifestTooLarge)
        );
    }

    #[test]
    fn threshold_access_requires_two_distinct_valid_signers() {
        let primary = Fixture::new();
        let second = SigningKey::from_bytes(&[8; 32]);
        let third = SigningKey::from_bytes(&[9; 32]);
        let envelope = primary.envelope();
        let (message, message_len) = signing_message(&envelope).unwrap();
        let second_signature = second.sign(&message[..message_len]).to_bytes();
        let trusted = [
            primary.key.verifying_key().to_bytes(),
            second.verifying_key().to_bytes(),
            third.verifying_key().to_bytes(),
        ];
        let revoked = [[0u8; 32]];
        let policy = ThresholdTrustPolicy {
            trusted_keys: &trusted,
            revoked_keys: &revoked,
            minimum_security_epoch: 3,
            threshold: 2,
        };
        let set = SignatureSet::new(&[
            ThresholdSignature {
                signer: second.verifying_key().to_bytes(),
                signature: second_signature,
            },
            ThresholdSignature {
                signer: primary.key.verifying_key().to_bytes(),
                signature: envelope.signature,
            },
        ])
        .unwrap();
        assert_eq!(
            verify_manifest_threshold(policy, target(), envelope, set),
            Ok(VerifiedManifest {
                release_sequence: 9,
                security_epoch: 4,
                target_profile: PROFILE,
                signer: primary.key.verifying_key().to_bytes(),
                manifest_sha256: Sha256::digest(primary.bytes).into(),
            })
        );

        let insufficient = SignatureSet::new(&[ThresholdSignature {
            signer: primary.key.verifying_key().to_bytes(),
            signature: envelope.signature,
        }])
        .unwrap();
        assert_eq!(
            verify_manifest_threshold(policy, target(), envelope, insufficient),
            Err(ThresholdError::InsufficientSignatures)
        );

        let invalid_policy = ThresholdTrustPolicy {
            threshold: 1,
            ..policy
        };
        assert_eq!(
            verify_manifest_threshold(invalid_policy, target(), envelope, set),
            Err(ThresholdError::InvalidThreshold)
        );
    }

    #[test]
    fn threshold_rejects_revocation_unknown_bad_and_duplicate_signers() {
        let primary = Fixture::new();
        let second = SigningKey::from_bytes(&[8; 32]);
        let third = SigningKey::from_bytes(&[9; 32]);
        let envelope = primary.envelope();
        let (message, message_len) = signing_message(&envelope).unwrap();
        let trusted = [
            primary.key.verifying_key().to_bytes(),
            second.verifying_key().to_bytes(),
            third.verifying_key().to_bytes(),
        ];
        let second_signature = second.sign(&message[..message_len]).to_bytes();
        let set = SignatureSet::new(&[
            ThresholdSignature {
                signer: primary.key.verifying_key().to_bytes(),
                signature: envelope.signature,
            },
            ThresholdSignature {
                signer: second.verifying_key().to_bytes(),
                signature: second_signature,
            },
        ])
        .unwrap();
        let revoked = [second.verifying_key().to_bytes()];
        let policy = ThresholdTrustPolicy {
            trusted_keys: &trusted,
            revoked_keys: &revoked,
            minimum_security_epoch: 3,
            threshold: 2,
        };
        assert_eq!(
            verify_manifest_threshold(policy, target(), envelope, set),
            Err(ThresholdError::Manifest(ManifestError::RevokedSigner))
        );

        let unknown_key = SigningKey::from_bytes(&[0x33; 32]);
        let unknown = SignatureSet::new(&[
            ThresholdSignature {
                signer: primary.key.verifying_key().to_bytes(),
                signature: envelope.signature,
            },
            ThresholdSignature {
                signer: unknown_key.verifying_key().to_bytes(),
                signature: unknown_key.sign(&message[..message_len]).to_bytes(),
            },
        ])
        .unwrap();
        let clean = ThresholdTrustPolicy {
            revoked_keys: &[[0u8; 32]],
            ..policy
        };
        assert_eq!(
            verify_manifest_threshold(clean, target(), envelope, unknown),
            Err(ThresholdError::Manifest(ManifestError::UnknownSigner))
        );

        let bad = SignatureSet::new(&[
            ThresholdSignature {
                signer: primary.key.verifying_key().to_bytes(),
                signature: envelope.signature,
            },
            ThresholdSignature {
                signer: second.verifying_key().to_bytes(),
                signature: [0x55; 64],
            },
        ])
        .unwrap();
        assert_eq!(
            verify_manifest_threshold(clean, target(), envelope, bad),
            Err(ThresholdError::Manifest(ManifestError::Signature))
        );
        assert_eq!(
            SignatureSet::new(&[
                ThresholdSignature {
                    signer: primary.key.verifying_key().to_bytes(),
                    signature: envelope.signature,
                },
                ThresholdSignature {
                    signer: primary.key.verifying_key().to_bytes(),
                    signature: envelope.signature,
                },
            ]),
            Err(ThresholdError::DuplicateSigner)
        );
    }

    #[test]
    fn signature_set_wire_is_bounded_canonical_and_round_trips() {
        let primary = Fixture::new();
        let second = SigningKey::from_bytes(&[8; 32]);
        let envelope = primary.envelope();
        let (message, message_len) = signing_message(&envelope).unwrap();
        let set = SignatureSet::new(&[
            ThresholdSignature {
                signer: second.verifying_key().to_bytes(),
                signature: second.sign(&message[..message_len]).to_bytes(),
            },
            ThresholdSignature {
                signer: primary.key.verifying_key().to_bytes(),
                signature: envelope.signature,
            },
        ])
        .unwrap();
        let (wire, length) = set.encode().unwrap();
        assert_eq!(SignatureSet::decode(&wire[..length]), Ok(set));
        let mut noncanonical = wire;
        let first = SIGNATURE_SET_DOMAIN.len() + 1;
        let second = first + THRESHOLD_SIGNATURE_BYTES;
        let mut temporary = [0u8; THRESHOLD_SIGNATURE_BYTES];
        temporary.copy_from_slice(&noncanonical[first..second]);
        noncanonical.copy_within(second..second + THRESHOLD_SIGNATURE_BYTES, first);
        noncanonical[second..second + THRESHOLD_SIGNATURE_BYTES].copy_from_slice(&temporary);
        assert_eq!(
            SignatureSet::decode(&noncanonical[..length]),
            Err(ThresholdError::SignatureSetNonCanonical)
        );
        assert_eq!(
            SignatureSet::decode(&wire[..length - 1]),
            Err(ThresholdError::SignatureSetFormat)
        );
        assert_eq!(
            SignatureSet::new(&[
                ThresholdSignature {
                    signer: [0; 32],
                    signature: envelope.signature,
                },
                ThresholdSignature {
                    signer: primary.key.verifying_key().to_bytes(),
                    signature: envelope.signature,
                },
            ]),
            Err(ThresholdError::SignatureSetFormat)
        );
    }
}
