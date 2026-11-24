//! Jasper Trust Framework software-attestation vertical slice.
//!
//! This crate is a user-space system service model. It binds a measured `.jaso`
//! package to SEC process/object generations and a relying-party challenge. It
//! deliberately reports only software-observation evidence with explicit gaps;
//! it never claims protected boot measurement or hardware backing.
//!
//! 本 crate 是用户态系统服务模型：把真实的 `.jaso` 内容测量绑定到 SEC
//! Process/Object 世代和依赖方 Challenge，只输出 software-observation 证据及
//! 明确缺口，不声称受保护启动测量或硬件背书。

use std::collections::BTreeSet;
use std::fmt;

use ciborium::value::Value;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use jaso::Jaso;
use kernel_core::security::{IdentityClass, SecurityContext};
use sha2::{Digest, Sha256};

pub const PROTOCOL_VERSION: u64 = 1;
pub const EVIDENCE_DOMAIN: &[u8] = b"JASPER-TRUST-EVIDENCE-V1\0";
pub const RESULT_DOMAIN: &[u8] = b"JASPER-TRUST-RESULT-V1\0";
pub const POLICY_DOMAIN: &[u8] = b"JASPER-TRUST-POLICY-V1\0";
pub const CHALLENGE_ID_BYTES: usize = 16;
pub const NONCE_BYTES: usize = 32;
pub const DIGEST_BYTES: usize = 32;
pub const MAX_WIRE_BYTES: usize = 16 * 1024; // JASPER-HARDCODE-REVIEW: issue=46 source=trust-v1-wire-envelope reason=bounded-protocol-message
pub const MAX_AUDIENCE_BYTES: usize = 128; // JASPER-HARDCODE-REVIEW: issue=46 source=trust-v1-wire-envelope reason=bounded-audience
pub const MAX_TEXT_BYTES: usize = 128; // JASPER-HARDCODE-REVIEW: issue=46 source=trust-v1-wire-envelope reason=bounded-protocol-text
pub const MAX_ITEMS: usize = 16; // JASPER-HARDCODE-REVIEW: issue=46 source=trust-v1-wire-envelope reason=bounded-protocol-collection
pub const MAX_CHALLENGE_LIFETIME: u64 = 300; // JASPER-HARDCODE-REVIEW: issue=46 source=trust-v1-freshness reason=maximum-challenge-window

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustError {
    InvalidSubject,
    MeasurementUnavailable,
    MeasurementMismatch,
    UnsignedPackage,
    MalformedChallenge,
    MalformedEvidence,
    MalformedResult,
    MalformedPolicy,
    InvalidSignature,
    ChallengeMissing,
    ChallengeExpired,
    ChallengeMismatch,
    Replay,
    ForgedScope,
    PolicyStale,
    ProviderRevoked,
    ProviderUnavailable,
    BrokerUnavailable,
    Capacity,
    ClockUntrusted,
    Unsupported,
}

impl TrustError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidSubject => "trust.error.invalid-subject",
            Self::MeasurementUnavailable => "trust.error.measurement-unavailable",
            Self::MeasurementMismatch => "trust.error.measurement-mismatch",
            Self::UnsignedPackage => "trust.error.unsigned-package",
            Self::MalformedChallenge => "trust.error.malformed-challenge",
            Self::MalformedEvidence => "trust.error.malformed-evidence",
            Self::MalformedResult => "trust.error.malformed-result",
            Self::MalformedPolicy => "trust.error.malformed-policy",
            Self::InvalidSignature => "trust.error.invalid-signature",
            Self::ChallengeMissing => "trust.error.challenge-missing",
            Self::ChallengeExpired => "trust.error.challenge-expired",
            Self::ChallengeMismatch => "trust.error.challenge-mismatch",
            Self::Replay => "trust.error.replay",
            Self::ForgedScope => "trust.error.unauthorized-scope",
            Self::PolicyStale => "trust.error.policy-stale",
            Self::ProviderRevoked => "trust.error.revoked",
            Self::ProviderUnavailable => "trust.error.provider-unavailable",
            Self::BrokerUnavailable => "trust.error.broker-unavailable",
            Self::Capacity => "trust.error.capacity",
            Self::ClockUntrusted => "trust.error.clock-untrusted",
            Self::Unsupported => "trust.error.unsupported",
        }
    }
}

impl fmt::Display for TrustError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(self.name())
    }
}

impl std::error::Error for TrustError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubjectKind {
    Application,
    Process,
    Service,
    Module,
    Device,
    ExecutionEnvironment,
}

impl SubjectKind {
    fn wire(self) -> &'static str {
        match self {
            Self::Application => "application",
            Self::Process => "process",
            Self::Service => "service",
            Self::Module => "module",
            Self::Device => "device",
            Self::ExecutionEnvironment => "execution-environment",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "application" => Some(Self::Application),
            "process" => Some(Self::Process),
            "service" => Some(Self::Service),
            "module" => Some(Self::Module),
            "device" => Some(Self::Device),
            "execution-environment" => Some(Self::ExecutionEnvironment),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EvidenceLevel {
    SoftwareObservation,
    SignedStaticPackage,
    ProtectedSystemMeasurement,
    HardwareBacked,
}

impl EvidenceLevel {
    fn wire(self) -> &'static str {
        match self {
            Self::SoftwareObservation => "software-observation",
            Self::SignedStaticPackage => "signed-static-package",
            Self::ProtectedSystemMeasurement => "protected-system-measurement",
            Self::HardwareBacked => "hardware-backed",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "software-observation" => Some(Self::SoftwareObservation),
            "signed-static-package" => Some(Self::SignedStaticPackage),
            "protected-system-measurement" => Some(Self::ProtectedSystemMeasurement),
            "hardware-backed" => Some(Self::HardwareBacked),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CoverageGapCode {
    NotObserved,
    ProcessMemoryNotMeasured,
    RuntimeDependenciesNotMeasured,
    BootChainNotMeasured,
    HardwareBackingUnavailable,
    ProviderUnavailable,
    Unknown,
}

impl CoverageGapCode {
    pub fn wire(self) -> &'static str {
        match self {
            Self::NotObserved => "not-observed",
            Self::ProcessMemoryNotMeasured => "process-memory-not-measured",
            Self::RuntimeDependenciesNotMeasured => "runtime-dependencies-not-measured",
            Self::BootChainNotMeasured => "boot-chain-not-measured",
            Self::HardwareBackingUnavailable => "hardware-backing-unavailable",
            Self::ProviderUnavailable => "provider-unavailable",
            Self::Unknown => "unknown",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "not-observed" => Some(Self::NotObserved),
            "process-memory-not-measured" => Some(Self::ProcessMemoryNotMeasured),
            "runtime-dependencies-not-measured" => Some(Self::RuntimeDependenciesNotMeasured),
            "boot-chain-not-measured" => Some(Self::BootChainNotMeasured),
            "hardware-backing-unavailable" => Some(Self::HardwareBackingUnavailable),
            "provider-unavailable" => Some(Self::ProviderUnavailable),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MeasurementKind {
    Package,
    ProcessImage,
    Module,
    Configuration,
}

impl MeasurementKind {
    fn wire(self) -> &'static str {
        match self {
            Self::Package => "package",
            Self::ProcessImage => "process-image",
            Self::Module => "module",
            Self::Configuration => "configuration",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "package" => Some(Self::Package),
            "process-image" => Some(Self::ProcessImage),
            "module" => Some(Self::Module),
            "configuration" => Some(Self::Configuration),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Measurement {
    pub kind: MeasurementKind,
    pub digest: [u8; DIGEST_BYTES],
    pub covered: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoverageGap {
    pub code: CoverageGapCode,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubjectSnapshot {
    pub kind: SubjectKind,
    pub object_id: u64,
    pub subject_generation: u32,
    pub boot_id: [u64; 2],
    pub application_id: u64,
    pub application_generation: u32,
    pub measurement: [u8; DIGEST_BYTES],
}

impl SubjectSnapshot {
    pub fn from_context(context: SecurityContext) -> Result<Self, TrustError> {
        context
            .require_active()
            .map_err(|_| TrustError::InvalidSubject)?;
        let subject = context
            .subject_identity()
            .ok_or(TrustError::InvalidSubject)?;
        let application = subject
            .application
            .filter(|application| application.is_measured())
            .ok_or(TrustError::MeasurementUnavailable)?;
        Ok(Self {
            kind: match context.object.class {
                IdentityClass::Process => SubjectKind::Process,
                IdentityClass::Service => SubjectKind::Service,
                IdentityClass::Module => SubjectKind::Module,
                IdentityClass::Device => SubjectKind::Device,
                _ => return Err(TrustError::InvalidSubject),
            },
            object_id: subject.object.object_id,
            subject_generation: subject.object.generation,
            boot_id: subject.object.boot_id.words,
            application_id: application.stable_id,
            application_generation: application.generation,
            measurement: application.measurement,
        })
    }

    pub fn identity_matches(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.object_id == other.object_id
            && self.subject_generation == other.subject_generation
            && self.boot_id == other.boot_id
            && self.application_id == other.application_id
            && self.application_generation == other.application_generation
            && self.measurement == other.measurement
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderIdentity {
    pub id: u64,
    pub generation: u32,
    pub level: EvidenceLevel,
    pub revocation_epoch: u64,
    pub not_before: u64,
    pub not_after: u64,
    pub signer: [u8; 32],
}

impl ProviderIdentity {
    fn validate(&self) -> Result<(), TrustError> {
        if self.id == 0
            || self.generation == 0
            || self.signer.iter().all(|byte| *byte == 0)
            || self.not_before > self.not_after
        {
            Err(TrustError::ProviderUnavailable)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    pub id: [u8; CHALLENGE_ID_BYTES],
    pub nonce: [u8; NONCE_BYTES],
    pub audience: String,
    pub expected: SubjectSnapshot,
    pub accepted_levels: Vec<EvidenceLevel>,
    pub requested_fields: Vec<String>,
    pub accepted_gaps: Vec<CoverageGapCode>,
    pub policy_epoch: u64,
    pub issued_at: u64,
    pub expires_at: u64,
}

pub struct ChallengeRequest<'a> {
    pub nonce: [u8; NONCE_BYTES],
    pub audience: &'a str,
    pub expected: SubjectSnapshot,
    pub accepted_levels: Vec<EvidenceLevel>,
    pub requested_fields: Vec<String>,
    pub accepted_gaps: Vec<CoverageGapCode>,
    pub policy_epoch: u64,
    pub now: u64,
    pub lifetime: u64,
}

impl Challenge {
    pub fn encode(&self) -> Result<Vec<u8>, TrustError> {
        wire::encode(&self.to_value(), MAX_WIRE_BYTES)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TrustError> {
        wire::decode_challenge(bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    subject: SubjectSnapshot,
    object_generation: u32,
    measurements: Vec<Measurement>,
    gaps: Vec<CoverageGap>,
    policy_epoch: u64,
    observed_at: u64,
}

#[derive(Default)]
pub struct Collector;

impl Collector {
    /// Collect one measured package observation for the exact challenge subject.
    ///
    /// The caller's service gate must pass only the current caller's
    /// `SecurityContext`; this function then enforces self-subject binding and
    /// package measurement equality before publishing any fact.
    pub fn collect(
        &self,
        challenge: &Challenge,
        context: SecurityContext,
        package_bytes: &[u8],
        now: u64,
    ) -> Result<Observation, TrustError> {
        validate_challenge_time(challenge, now)?;
        if !challenge
            .accepted_levels
            .contains(&EvidenceLevel::SoftwareObservation)
        {
            return Err(TrustError::Unsupported);
        }
        let subject = SubjectSnapshot::from_context(context)?;
        if !subject.identity_matches(&challenge.expected) {
            return Err(TrustError::ForgedScope);
        }
        let image = Jaso::parse(package_bytes).map_err(|_| TrustError::UnsignedPackage)?;
        if image.signature().is_none() {
            return Err(TrustError::UnsignedPackage);
        }
        let digest = jaso::digest_of(package_bytes);
        if digest != subject.measurement {
            return Err(TrustError::MeasurementMismatch);
        }
        Ok(Observation {
            object_generation: subject.subject_generation,
            subject,
            measurements: vec![Measurement {
                kind: MeasurementKind::Package,
                digest,
                covered: vec![
                    "jaso.container".to_owned(),
                    "application-identity.measurement".to_owned(),
                ],
            }],
            gaps: vec![
                CoverageGap {
                    code: CoverageGapCode::ProcessMemoryNotMeasured,
                    detail: "runtime process memory is not measured".to_owned(),
                },
                CoverageGap {
                    code: CoverageGapCode::RuntimeDependenciesNotMeasured,
                    detail: "runtime dependency closure is not measured".to_owned(),
                },
                CoverageGap {
                    code: CoverageGapCode::BootChainNotMeasured,
                    detail: "boot chain is outside software-observation scope".to_owned(),
                },
                CoverageGap {
                    code: CoverageGapCode::HardwareBackingUnavailable,
                    detail: "no TPM or TEE evidence provider is configured".to_owned(),
                },
            ],
            policy_epoch: challenge.policy_epoch,
            observed_at: now,
        })
    }
}

pub struct Broker {
    key: SigningKey,
    provider: ProviderIdentity,
}

impl Broker {
    pub fn new(seed: [u8; 32], mut provider: ProviderIdentity) -> Result<Self, TrustError> {
        let key = SigningKey::from_bytes(&seed);
        provider.signer = key.verifying_key().to_bytes();
        provider.validate()?;
        Ok(Self { key, provider })
    }

    pub fn provider(&self) -> ProviderIdentity {
        self.provider.clone()
    }

    pub fn attest(
        &self,
        challenge: &Challenge,
        observation: Observation,
        now: u64,
    ) -> Result<EvidenceMessage, TrustError> {
        validate_challenge_time(challenge, now)?;
        if !observation.subject.identity_matches(&challenge.expected) {
            return Err(TrustError::ForgedScope);
        }
        if observation.object_generation != observation.subject.subject_generation {
            return Err(TrustError::ForgedScope);
        }
        if observation.policy_epoch != challenge.policy_epoch
            || self.provider.level != EvidenceLevel::SoftwareObservation
            || now < self.provider.not_before
            || now >= self.provider.not_after
            || !challenge.accepted_levels.contains(&self.provider.level)
        {
            return Err(TrustError::PolicyStale);
        }
        let id = message_id(
            b"JASPER-TRUST-EVIDENCE-ID-V1\0",
            &[
                &challenge.id,
                &challenge.nonce,
                &observation.subject.measurement,
                &now.to_le_bytes(),
            ],
        );
        let claims = EvidenceClaims {
            id,
            challenge_id: challenge.id,
            nonce: challenge.nonce,
            subject: observation.subject,
            provider: self.provider.clone(),
            object_generation: observation.object_generation,
            measurements: observation.measurements,
            gaps: observation.gaps,
            issued_at: now,
            expires_at: challenge.expires_at,
            policy_epoch: observation.policy_epoch,
            disclosure_fields: challenge.requested_fields.clone(),
            trust_chain: vec![self.key.verifying_key().to_bytes().to_vec()],
            revocation_references: Vec::new(),
            signature: None,
        };
        let signature = self.sign(&wire::evidence_signing_message(&claims)?);
        let bytes = claims.encode(Some(signature))?;
        Ok(EvidenceMessage { id, bytes })
    }

    fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.key.sign(message).to_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceMessage {
    pub id: [u8; CHALLENGE_ID_BYTES],
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResultStatus {
    Verified,
    VerifiedWithGaps,
    Rejected,
    Unavailable,
    Unsupported,
}

impl ResultStatus {
    fn wire(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::VerifiedWithGaps => "verified-with-gaps",
            Self::Rejected => "rejected",
            Self::Unavailable => "unavailable",
            Self::Unsupported => "unsupported",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "verified" => Some(Self::Verified),
            "verified-with-gaps" => Some(Self::VerifiedWithGaps),
            "rejected" => Some(Self::Rejected),
            "unavailable" => Some(Self::Unavailable),
            "unsupported" => Some(Self::Unsupported),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationResult {
    pub id: [u8; CHALLENGE_ID_BYTES],
    pub status: ResultStatus,
    pub verifier_signer: [u8; 32],
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct VerifierPolicy {
    pub trusted_provider_key: [u8; 32],
    pub revoked_provider_keys: Vec<[u8; 32]>,
    pub minimum_policy_epoch: u64,
    pub minimum_revocation_epoch: u64,
}

pub struct Verifier<const N: usize> {
    policy: VerifierPolicy,
    challenges: ChallengeLedger<N>,
    result_key: SigningKey,
    next_result: u64,
    next_challenge: u64,
}

impl<const N: usize> Verifier<N> {
    pub fn new(policy: VerifierPolicy, result_seed: [u8; 32]) -> Result<Self, TrustError> {
        if N == 0 || policy.trusted_provider_key.iter().all(|byte| *byte == 0) {
            return Err(TrustError::Capacity);
        }
        Ok(Self {
            policy,
            challenges: ChallengeLedger::new(),
            result_key: SigningKey::from_bytes(&result_seed),
            next_result: 1,
            next_challenge: 1,
        })
    }

    pub fn result_signer(&self) -> [u8; 32] {
        self.result_key.verifying_key().to_bytes()
    }

    pub fn live_challenges(&self) -> usize {
        self.challenges.len()
    }

    pub fn clear_challenges(&mut self) {
        self.challenges.clear();
    }

    pub fn issue_challenge(
        &mut self,
        request: ChallengeRequest<'_>,
    ) -> Result<Challenge, TrustError> {
        self.challenges.prune_expired(request.now);
        if request.audience.is_empty()
            || request.audience.len() > MAX_AUDIENCE_BYTES
            || request.nonce.iter().all(|byte| *byte == 0)
            || request.requested_fields.len() > MAX_ITEMS
            || request.accepted_gaps.len() > MAX_ITEMS
            || request.accepted_levels.is_empty()
            || request.accepted_levels.len() > MAX_ITEMS
            || request.lifetime == 0
            || request.lifetime > MAX_CHALLENGE_LIFETIME
            || request.policy_epoch < self.policy.minimum_policy_epoch
        {
            return Err(TrustError::MalformedChallenge);
        }
        let expires_at = request
            .now
            .checked_add(request.lifetime)
            .ok_or(TrustError::MalformedChallenge)?;
        let id = message_id(
            b"JASPER-TRUST-CHALLENGE-ID-V1\0",
            &[
                &request.nonce,
                request.audience.as_bytes(),
                &request.expected.object_id.to_le_bytes(),
                &request.expected.subject_generation.to_le_bytes(),
                &request.now.to_le_bytes(),
                &self.next_challenge.to_le_bytes(),
            ],
        );
        self.next_challenge = self
            .next_challenge
            .checked_add(1)
            .ok_or(TrustError::Capacity)?;
        let challenge = Challenge {
            id,
            nonce: request.nonce,
            audience: request.audience.to_owned(),
            expected: request.expected,
            accepted_levels: request.accepted_levels,
            requested_fields: request.requested_fields,
            accepted_gaps: request.accepted_gaps,
            policy_epoch: request.policy_epoch,
            issued_at: request.now,
            expires_at,
        };
        self.challenges.insert(challenge.clone())?;
        Ok(challenge)
    }

    pub fn verify(&mut self, evidence: &[u8], now: u64) -> Result<VerificationResult, TrustError> {
        let claims = wire::decode_evidence(evidence)?;
        if self
            .policy
            .revoked_provider_keys
            .contains(&claims.provider.signer)
            || claims.provider.signer != self.policy.trusted_provider_key
            || claims.provider.revocation_epoch < self.policy.minimum_revocation_epoch
        {
            return Err(TrustError::ProviderRevoked);
        }
        claims.provider.validate()?;
        if now < claims.provider.not_before || now >= claims.provider.not_after {
            return Err(TrustError::ProviderUnavailable);
        }
        if claims.provider.level != EvidenceLevel::SoftwareObservation {
            return Err(TrustError::Unsupported);
        }
        let chain_key = claims
            .trust_chain
            .first()
            .filter(|key| key.len() == 32)
            .ok_or(TrustError::InvalidSignature)?;
        if chain_key.as_slice() != claims.provider.signer {
            return Err(TrustError::InvalidSignature);
        }
        let key = VerifyingKey::from_bytes(&claims.provider.signer)
            .map_err(|_| TrustError::InvalidSignature)?;
        let signature =
            Signature::from_bytes(&claims.signature.ok_or(TrustError::InvalidSignature)?);
        key.verify_strict(&wire::evidence_signing_message(&claims)?, &signature)
            .map_err(|_| TrustError::InvalidSignature)?;

        let challenge = self
            .challenges
            .get(claims.challenge_id)
            .ok_or(TrustError::Replay)?
            .clone();
        validate_challenge_time(&challenge, now)?;
        if challenge.nonce != claims.nonce
            || !challenge.expected.identity_matches(&claims.subject)
            || claims.object_generation != claims.subject.subject_generation
            || challenge.policy_epoch != claims.policy_epoch
            || challenge.policy_epoch < self.policy.minimum_policy_epoch
            || claims.policy_epoch < self.policy.minimum_policy_epoch
        {
            return Err(TrustError::ChallengeMismatch);
        }
        if claims.issued_at > now
            || claims.expires_at <= now
            || claims.expires_at > challenge.expires_at
        {
            return Err(TrustError::ChallengeExpired);
        }
        let requested: BTreeSet<_> = challenge
            .requested_fields
            .iter()
            .map(String::as_str)
            .collect();
        let disclosed: BTreeSet<_> = claims
            .disclosure_fields
            .iter()
            .map(String::as_str)
            .collect();
        if !requested.is_subset(&disclosed) {
            return Err(TrustError::ForgedScope);
        }
        let accepted_gaps: BTreeSet<_> = challenge.accepted_gaps.iter().copied().collect();
        if claims
            .gaps
            .iter()
            .any(|gap| !accepted_gaps.contains(&gap.code))
        {
            return Err(TrustError::Unsupported);
        }
        if !challenge.accepted_levels.contains(&claims.provider.level) {
            return Err(TrustError::Unsupported);
        }

        self.challenges.consume(claims.challenge_id)?;
        let status = if claims.gaps.is_empty() {
            ResultStatus::Verified
        } else {
            ResultStatus::VerifiedWithGaps
        };
        let result_id = message_id(
            b"JASPER-TRUST-RESULT-ID-V1\0",
            &[&claims.id, &self.next_result.to_le_bytes()],
        );
        self.next_result = self
            .next_result
            .checked_add(1)
            .ok_or(TrustError::Capacity)?;
        let result = ResultClaims {
            id: result_id,
            challenge_id: claims.challenge_id,
            evidence_id: claims.id,
            nonce: claims.nonce,
            status,
            level: claims.provider.level,
            verified: vec![
                "jaso.container.digest".to_owned(),
                "application.identity".to_owned(),
                "process.object.generation".to_owned(),
                "challenge.nonce".to_owned(),
            ],
            gaps: claims.gaps,
            subject_generation: claims.subject.subject_generation,
            object_generation: claims.object_generation,
            provider_generation: claims.provider.generation,
            policy_epoch: claims.policy_epoch,
            issued_at: now,
            expires_at: claims.expires_at,
            verifier_signer: self.result_key.verifying_key().to_bytes(),
            signature: None,
        };
        let signature = self
            .result_key
            .sign(&wire::result_signing_message(&result)?);
        let bytes = result.encode(signature.to_bytes())?;
        Ok(VerificationResult {
            id: result_id,
            status,
            verifier_signer: self.result_signer(),
            bytes,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny,
    Degrade,
    Unavailable,
}

impl PolicyDecision {
    fn wire(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Degrade => "degrade",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyResult {
    pub decision: PolicyDecision,
    pub reasons: Vec<String>,
    pub signed_bytes: Vec<u8>,
}

pub struct PolicyEvaluator {
    verifier_key: [u8; 32],
    profile: String,
    accepted_gaps: Vec<CoverageGapCode>,
    policy_epoch: u64,
    key: SigningKey,
}

impl PolicyEvaluator {
    pub fn new(
        verifier_key: [u8; 32],
        profile: &str,
        accepted_gaps: Vec<CoverageGapCode>,
        policy_epoch: u64,
        seed: [u8; 32],
    ) -> Result<Self, TrustError> {
        if verifier_key.iter().all(|byte| *byte == 0)
            || profile.is_empty()
            || profile.len() > MAX_TEXT_BYTES
            || accepted_gaps.len() > MAX_ITEMS
        {
            return Err(TrustError::MalformedPolicy);
        }
        Ok(Self {
            verifier_key,
            profile: profile.to_owned(),
            accepted_gaps,
            policy_epoch,
            key: SigningKey::from_bytes(&seed),
        })
    }

    pub fn evaluate(
        &self,
        result: &VerificationResult,
        now: u64,
    ) -> Result<PolicyResult, TrustError> {
        let wire = wire::decode_result(&result.bytes)?;
        if wire.verifier_signer != self.verifier_key
            || wire.policy_epoch < self.policy_epoch
            || wire.issued_at > now
            || wire.expires_at <= now
        {
            return Err(TrustError::PolicyStale);
        }
        let key = VerifyingKey::from_bytes(&self.verifier_key)
            .map_err(|_| TrustError::InvalidSignature)?;
        let signature = Signature::from_bytes(&wire.signature.ok_or(TrustError::InvalidSignature)?);
        key.verify_strict(&wire::result_signing_message(&wire)?, &signature)
            .map_err(|_| TrustError::InvalidSignature)?;

        let decision = match wire.status {
            ResultStatus::Verified => PolicyDecision::Allow,
            ResultStatus::VerifiedWithGaps
                if wire
                    .gaps
                    .iter()
                    .all(|gap| self.accepted_gaps.contains(&gap.code)) =>
            {
                PolicyDecision::Degrade
            }
            ResultStatus::Rejected => PolicyDecision::Deny,
            ResultStatus::Unavailable | ResultStatus::Unsupported => PolicyDecision::Unavailable,
            ResultStatus::VerifiedWithGaps => PolicyDecision::Deny,
        };
        let mut reasons = vec![
            "software-observation-only".to_owned(),
            "challenge-bound".to_owned(),
        ];
        reasons.extend(wire.gaps.iter().map(|gap| gap.code.wire().to_owned()));
        let policy_id = message_id(
            b"JASPER-TRUST-POLICY-ID-V1\0",
            &[&wire.id, self.profile.as_bytes(), &now.to_le_bytes()],
        );
        let claims = PolicyClaims {
            id: policy_id,
            result_id: wire.id,
            profile: self.profile.clone(),
            policy_epoch: self.policy_epoch,
            decision,
            reasons: reasons.clone(),
            gaps: wire.gaps,
            issued_at: now,
            expires_at: wire.expires_at,
        };
        let signature = self.key.sign(&wire::policy_signing_message(&claims)?);
        let signed_bytes = claims.encode(signature.to_bytes())?;
        Ok(PolicyResult {
            decision,
            reasons,
            signed_bytes,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustOutcome {
    pub evidence: EvidenceMessage,
    pub verification: VerificationResult,
    pub policy: PolicyResult,
}

pub struct TrustDaemon<const N: usize> {
    collector: Collector,
    broker: Option<Broker>,
    verifier: Verifier<N>,
    policy: PolicyEvaluator,
}

impl<const N: usize> TrustDaemon<N> {
    pub fn new(
        broker: Broker,
        verifier_policy: VerifierPolicy,
        verifier_seed: [u8; 32],
        policy: PolicyEvaluator,
    ) -> Result<Self, TrustError> {
        Ok(Self {
            collector: Collector,
            broker: Some(broker),
            verifier: Verifier::new(verifier_policy, verifier_seed)?,
            policy,
        })
    }

    pub fn stop_broker(&mut self) {
        self.broker = None;
        self.verifier.clear_challenges();
    }

    pub fn broker_online(&self) -> bool {
        self.broker.is_some()
    }

    pub fn live_challenges(&self) -> usize {
        self.verifier.live_challenges()
    }

    pub fn attest(
        &mut self,
        nonce: [u8; NONCE_BYTES],
        audience: &str,
        context: SecurityContext,
        package_bytes: &[u8],
        now: u64,
        lifetime: u64,
    ) -> Result<TrustOutcome, TrustError> {
        if self.broker.is_none() {
            return Err(TrustError::BrokerUnavailable);
        }
        let expected = SubjectSnapshot::from_context(context)?;
        let challenge = self.verifier.issue_challenge(ChallengeRequest {
            nonce,
            audience,
            expected,
            accepted_levels: vec![EvidenceLevel::SoftwareObservation],
            requested_fields: vec!["jaso.digest".to_owned(), "subject.generation".to_owned()],
            accepted_gaps: vec![
                CoverageGapCode::ProcessMemoryNotMeasured,
                CoverageGapCode::RuntimeDependenciesNotMeasured,
                CoverageGapCode::BootChainNotMeasured,
                CoverageGapCode::HardwareBackingUnavailable,
            ],
            policy_epoch: self.policy.policy_epoch,
            now,
            lifetime,
        })?;
        let evidence = match self
            .collector
            .collect(&challenge, context, package_bytes, now)
            .and_then(|observation| {
                self.broker
                    .as_ref()
                    .ok_or(TrustError::BrokerUnavailable)?
                    .attest(&challenge, observation, now)
            }) {
            Ok(evidence) => evidence,
            Err(error) => {
                self.verifier.challenges.discard(challenge.id);
                return Err(error);
            }
        };
        let verification = match self.verifier.verify(&evidence.bytes, now) {
            Ok(verification) => verification,
            Err(error) => {
                self.verifier.challenges.discard(challenge.id);
                return Err(error);
            }
        };
        let policy = self.policy.evaluate(&verification, now)?;
        Ok(TrustOutcome {
            evidence,
            verification,
            policy,
        })
    }
}

struct ChallengeLedger<const N: usize> {
    entries: Vec<Option<Challenge>>,
    used: [Option<[u8; CHALLENGE_ID_BYTES]>; N],
    used_head: usize,
}

impl<const N: usize> ChallengeLedger<N> {
    fn new() -> Self {
        Self {
            entries: vec![None; N],
            used: [None; N],
            used_head: 0,
        }
    }

    fn len(&self) -> usize {
        self.entries.iter().filter(|entry| entry.is_some()).count()
    }

    fn insert(&mut self, challenge: Challenge) -> Result<(), TrustError> {
        if self.used.iter().flatten().any(|used| *used == challenge.id)
            || self
                .entries
                .iter()
                .flatten()
                .any(|existing| existing.id == challenge.id)
        {
            return Err(TrustError::Replay);
        }
        let slot = self
            .entries
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or(TrustError::Capacity)?;
        *slot = Some(challenge);
        Ok(())
    }

    fn get(&self, id: [u8; CHALLENGE_ID_BYTES]) -> Option<&Challenge> {
        self.entries
            .iter()
            .flatten()
            .find(|challenge| challenge.id == id)
    }

    fn consume(&mut self, id: [u8; CHALLENGE_ID_BYTES]) -> Result<(), TrustError> {
        let slot = self
            .entries
            .iter_mut()
            .find(|entry| entry.as_ref().is_some_and(|challenge| challenge.id == id))
            .ok_or(TrustError::ChallengeMissing)?;
        *slot = None;
        self.used[self.used_head] = Some(id);
        self.used_head = (self.used_head + 1) % N;
        Ok(())
    }

    fn discard(&mut self, id: [u8; CHALLENGE_ID_BYTES]) {
        if let Some(slot) = self
            .entries
            .iter_mut()
            .find(|entry| entry.as_ref().is_some_and(|challenge| challenge.id == id))
        {
            *slot = None;
        }
    }

    fn clear(&mut self) {
        self.entries.iter_mut().for_each(|entry| *entry = None);
    }

    fn prune_expired(&mut self, now: u64) {
        for entry in &mut self.entries {
            if entry
                .as_ref()
                .is_some_and(|challenge| challenge.expires_at <= now)
            {
                *entry = None;
            }
        }
    }
}

fn validate_challenge_time(challenge: &Challenge, now: u64) -> Result<(), TrustError> {
    if challenge.issued_at > now {
        Err(TrustError::ChallengeMismatch)
    } else if challenge.expires_at <= now {
        Err(TrustError::ChallengeExpired)
    } else {
        Ok(())
    }
}

fn message_id(domain: &[u8], parts: &[&[u8]]) -> [u8; CHALLENGE_ID_BYTES] {
    let mut hash = Sha256::new();
    hash.update(domain);
    for part in parts {
        hash.update((part.len() as u64).to_le_bytes());
        hash.update(part);
    }
    let digest = hash.finalize();
    let mut id = [0u8; CHALLENGE_ID_BYTES];
    id.copy_from_slice(&digest[..CHALLENGE_ID_BYTES]);
    if id.iter().all(|byte| *byte == 0) {
        id[CHALLENGE_ID_BYTES - 1] = 1;
    }
    id
}

#[derive(Clone)]
struct EvidenceClaims {
    id: [u8; CHALLENGE_ID_BYTES],
    challenge_id: [u8; CHALLENGE_ID_BYTES],
    nonce: [u8; NONCE_BYTES],
    subject: SubjectSnapshot,
    provider: ProviderIdentity,
    object_generation: u32,
    measurements: Vec<Measurement>,
    gaps: Vec<CoverageGap>,
    issued_at: u64,
    expires_at: u64,
    policy_epoch: u64,
    disclosure_fields: Vec<String>,
    trust_chain: Vec<Vec<u8>>,
    revocation_references: Vec<Vec<u8>>,
    signature: Option<[u8; 64]>,
}

impl EvidenceClaims {
    fn to_value(&self, include_signature: bool) -> Value {
        let mut pairs = vec![
            (Value::from(1u64), Value::from("trust.evidence/v1")),
            (Value::from(2u64), Value::from(PROTOCOL_VERSION)),
            (Value::from(3u64), Value::from(self.id.to_vec())),
            (Value::from(4u64), Value::from(self.challenge_id.to_vec())),
            (Value::from(5u64), Value::from(self.nonce.to_vec())),
            (Value::from(6u64), wire::subject_value(&self.subject)),
            (Value::from(7u64), wire::provider_value(&self.provider)),
            (
                Value::from(8u64),
                Value::from(u64::from(self.object_generation)),
            ),
            (
                Value::from(9u64),
                Value::Array(
                    self.measurements
                        .iter()
                        .map(wire::measurement_value)
                        .collect(),
                ),
            ),
            (
                Value::from(10u64),
                Value::Array(self.gaps.iter().map(wire::gap_value).collect()),
            ),
            (Value::from(11u64), Value::from(self.issued_at)),
            (Value::from(12u64), Value::from(self.expires_at)),
            (Value::from(13u64), Value::from(self.policy_epoch)),
            (
                Value::from(14u64),
                Value::Array(
                    self.disclosure_fields
                        .iter()
                        .map(|field| Value::from(field.as_str()))
                        .collect(),
                ),
            ),
        ];
        if include_signature {
            pairs.push((
                Value::from(15u64),
                Value::from(self.signature.unwrap_or([0u8; 64]).to_vec()),
            ));
        }
        pairs.push((
            Value::from(16u64),
            Value::Array(
                self.trust_chain
                    .iter()
                    .map(|key| Value::from(key.clone()))
                    .collect(),
            ),
        ));
        pairs.push((
            Value::from(17u64),
            Value::Array(
                self.revocation_references
                    .iter()
                    .map(|reference| Value::from(reference.clone()))
                    .collect(),
            ),
        ));
        Value::Map(pairs)
    }

    fn encode(&self, signature: Option<[u8; 64]>) -> Result<Vec<u8>, TrustError> {
        let mut copy = self.clone();
        copy.signature = signature;
        wire::encode(&copy.to_value(true), MAX_WIRE_BYTES)
    }
}

#[derive(Clone)]
struct ResultClaims {
    id: [u8; CHALLENGE_ID_BYTES],
    challenge_id: [u8; CHALLENGE_ID_BYTES],
    evidence_id: [u8; CHALLENGE_ID_BYTES],
    nonce: [u8; NONCE_BYTES],
    status: ResultStatus,
    level: EvidenceLevel,
    verified: Vec<String>,
    gaps: Vec<CoverageGap>,
    subject_generation: u32,
    object_generation: u32,
    provider_generation: u32,
    policy_epoch: u64,
    issued_at: u64,
    expires_at: u64,
    verifier_signer: [u8; 32],
    signature: Option<[u8; 64]>,
}

impl ResultClaims {
    fn to_value(&self, include_signature: bool) -> Value {
        let mut pairs = vec![
            (Value::from(1u64), Value::from("trust.result/v1")),
            (Value::from(2u64), Value::from(PROTOCOL_VERSION)),
            (Value::from(3u64), Value::from(self.id.to_vec())),
            (Value::from(4u64), Value::from(self.challenge_id.to_vec())),
            (Value::from(5u64), Value::from(self.evidence_id.to_vec())),
            (Value::from(6u64), Value::from(self.nonce.to_vec())),
            (Value::from(7u64), Value::from(self.status.wire())),
            (Value::from(8u64), Value::from(self.level.wire())),
            (
                Value::from(9u64),
                Value::Array(
                    self.verified
                        .iter()
                        .map(|item| Value::from(item.as_str()))
                        .collect(),
                ),
            ),
            (
                Value::from(10u64),
                Value::Array(self.gaps.iter().map(wire::gap_value).collect()),
            ),
            (
                Value::from(11u64),
                Value::from(u64::from(self.subject_generation)),
            ),
            (
                Value::from(12u64),
                Value::from(u64::from(self.object_generation)),
            ),
            (
                Value::from(13u64),
                Value::from(u64::from(self.provider_generation)),
            ),
            (Value::from(14u64), Value::from(self.policy_epoch)),
            (Value::from(15u64), Value::from(self.issued_at)),
            (Value::from(16u64), Value::from(self.expires_at)),
        ];
        if include_signature {
            pairs.push((
                Value::from(17u64),
                Value::from(self.signature.unwrap_or([0u8; 64]).to_vec()),
            ));
        }
        pairs.push((
            Value::from(19u64),
            Value::Map(vec![(
                Value::from("verifier-signer"),
                Value::from(self.verifier_signer.to_vec()),
            )]),
        ));
        Value::Map(pairs)
    }

    fn encode(&self, signature: [u8; 64]) -> Result<Vec<u8>, TrustError> {
        let mut copy = self.clone();
        copy.signature = Some(signature);
        wire::encode(&copy.to_value(true), MAX_WIRE_BYTES)
    }
}

#[derive(Clone)]
struct PolicyClaims {
    id: [u8; CHALLENGE_ID_BYTES],
    result_id: [u8; CHALLENGE_ID_BYTES],
    profile: String,
    policy_epoch: u64,
    decision: PolicyDecision,
    reasons: Vec<String>,
    gaps: Vec<CoverageGap>,
    issued_at: u64,
    expires_at: u64,
}

impl PolicyClaims {
    fn to_value(&self, signature: Option<[u8; 64]>) -> Value {
        let mut pairs = vec![
            (Value::from(1u64), Value::from("trust.policy/v1")),
            (Value::from(2u64), Value::from(PROTOCOL_VERSION)),
            (Value::from(3u64), Value::from(self.id.to_vec())),
            (Value::from(4u64), Value::from(self.result_id.to_vec())),
            (Value::from(5u64), Value::from(self.profile.as_str())),
            (Value::from(6u64), Value::from(self.policy_epoch)),
            (Value::from(7u64), Value::from(self.decision.wire())),
            (
                Value::from(8u64),
                Value::Array(
                    self.reasons
                        .iter()
                        .map(|reason| Value::from(reason.as_str()))
                        .collect(),
                ),
            ),
            (
                Value::from(9u64),
                Value::Array(self.gaps.iter().map(wire::gap_value).collect()),
            ),
            (Value::from(10u64), Value::from(self.issued_at)),
            (Value::from(11u64), Value::from(self.expires_at)),
        ];
        if let Some(signature) = signature {
            pairs.push((Value::from(12u64), Value::from(signature.to_vec())));
        }
        Value::Map(pairs)
    }

    fn encode(&self, signature: [u8; 64]) -> Result<Vec<u8>, TrustError> {
        wire::encode(&self.to_value(Some(signature)), MAX_WIRE_BYTES)
    }
}

mod wire {
    use super::*;

    pub(super) fn encode(value: &Value, limit: usize) -> Result<Vec<u8>, TrustError> {
        let mut output = Vec::new();
        ciborium::ser::into_writer(value, &mut output)
            .map_err(|_| TrustError::MalformedEvidence)?;
        if output.is_empty() || output.len() > limit {
            return Err(TrustError::Capacity);
        }
        Ok(output)
    }

    fn decode(bytes: &[u8], limit: usize, error: TrustError) -> Result<Value, TrustError> {
        if bytes.is_empty() || bytes.len() > limit {
            return Err(if bytes.len() > limit {
                TrustError::Capacity
            } else {
                error
            });
        }
        let value: Value = ciborium::de::from_reader(bytes).map_err(|_| error)?;
        let canonical = encode(&value, limit).map_err(|_| error)?;
        if canonical != bytes {
            return Err(error);
        }
        Ok(value)
    }

    fn integer_entries(value: &Value, error: TrustError) -> Result<Vec<(u64, &Value)>, TrustError> {
        let Value::Map(pairs) = value else {
            return Err(error);
        };
        let mut entries = Vec::with_capacity(pairs.len());
        let mut previous = None;
        for (key, value) in pairs {
            let Value::Integer(integer) = key else {
                return Err(error);
            };
            let key = u64::try_from(*integer).map_err(|_| error)?;
            if previous.is_some_and(|previous| previous >= key) {
                return Err(error);
            }
            previous = Some(key);
            entries.push((key, value));
        }
        Ok(entries)
    }

    fn get<'a>(entries: &'a [(u64, &'a Value)], key: u64) -> Option<&'a Value> {
        entries
            .iter()
            .find_map(|(candidate, value)| (*candidate == key).then_some(*value))
    }

    fn uint(value: &Value, error: TrustError) -> Result<u64, TrustError> {
        let Value::Integer(integer) = value else {
            return Err(error);
        };
        u64::try_from(*integer).map_err(|_| error)
    }

    fn u32_value(value: &Value, error: TrustError) -> Result<u32, TrustError> {
        u32::try_from(uint(value, error)?).map_err(|_| error)
    }

    fn text(value: &Value, error: TrustError) -> Result<String, TrustError> {
        let Value::Text(text) = value else {
            return Err(error);
        };
        if text.len() > MAX_TEXT_BYTES {
            return Err(TrustError::Capacity);
        }
        Ok(text.clone())
    }

    fn bytes_value(
        value: &Value,
        width: Option<usize>,
        error: TrustError,
    ) -> Result<Vec<u8>, TrustError> {
        let Value::Bytes(bytes) = value else {
            return Err(error);
        };
        if width.is_some_and(|width| bytes.len() != width) || bytes.len() > MAX_WIRE_BYTES {
            return Err(error);
        }
        Ok(bytes.clone())
    }

    fn array(value: &Value, error: TrustError) -> Result<&[Value], TrustError> {
        let Value::Array(array) = value else {
            return Err(error);
        };
        if array.len() > MAX_ITEMS {
            return Err(TrustError::Capacity);
        }
        Ok(array)
    }

    pub(super) fn subject_value(subject: &SubjectSnapshot) -> Value {
        Value::Map(vec![
            (Value::from(1u64), Value::from(subject.kind.wire())),
            (Value::from(2u64), Value::from(subject.object_id)),
            (
                Value::from(3u64),
                Value::from(u64::from(subject.subject_generation)),
            ),
            (Value::from(4u64), Value::from(subject.boot_id[0])),
            (
                Value::from(5u64),
                Value::from(subject.application_id.to_be_bytes().to_vec()),
            ),
            (Value::from(6u64), Value::from(subject.measurement.to_vec())),
            (
                Value::from(7u64),
                Value::Map(vec![
                    (Value::from("boot-high"), Value::from(subject.boot_id[1])),
                    (
                        Value::from("application-generation"),
                        Value::from(u64::from(subject.application_generation)),
                    ),
                ]),
            ),
        ])
    }

    fn subject_parse(value: &Value) -> Result<SubjectSnapshot, TrustError> {
        let error = TrustError::MalformedEvidence;
        let entries = integer_entries(value, error)?;
        let kind = text(get(&entries, 1).ok_or(error)?, error)?;
        let object_id = uint(get(&entries, 2).ok_or(error)?, error)?;
        let subject_generation = u32_value(get(&entries, 3).ok_or(error)?, error)?;
        let boot_low = uint(get(&entries, 4).ok_or(error)?, error)?;
        let application_id_bytes = bytes_value(get(&entries, 5).ok_or(error)?, Some(8), error)?;
        let measurement_bytes = bytes_value(get(&entries, 6).ok_or(error)?, Some(32), error)?;
        let extension = get(&entries, 7).ok_or(error)?;
        let Value::Map(extension) = extension else {
            return Err(error);
        };
        let mut boot_high = None;
        let mut app_generation = None;
        for (key, value) in extension {
            match key {
                Value::Text(key) if key == "boot-high" => boot_high = Some(uint(value, error)?),
                Value::Text(key) if key == "application-generation" => {
                    app_generation = Some(u32_value(value, error)?)
                }
                _ => return Err(error),
            }
        }
        let mut application_id = [0u8; 8];
        application_id.copy_from_slice(&application_id_bytes);
        let mut measurement = [0u8; DIGEST_BYTES];
        measurement.copy_from_slice(&measurement_bytes);
        Ok(SubjectSnapshot {
            kind: SubjectKind::parse(&kind).ok_or(error)?,
            object_id,
            subject_generation,
            boot_id: [boot_low, boot_high.ok_or(error)?],
            application_id: u64::from_be_bytes(application_id),
            application_generation: app_generation.ok_or(error)?,
            measurement,
        })
    }

    pub(super) fn provider_value(provider: &ProviderIdentity) -> Value {
        Value::Map(vec![
            (Value::from(1u64), Value::from(provider.id)),
            (
                Value::from(2u64),
                Value::from(u64::from(provider.generation)),
            ),
            (Value::from(3u64), Value::from(provider.level.wire())),
            (
                Value::from(4u64),
                Value::Array(vec![Value::from("trust/1")]),
            ),
            (
                Value::from(5u64),
                Value::Array(vec![Value::from("ed25519")]),
            ),
            (
                Value::from(6u64),
                Value::Array(vec![Value::from("jasper-os")]),
            ),
            (Value::from(7u64), Value::from(provider.revocation_epoch)),
            (Value::from(8u64), Value::from(provider.not_before)),
            (Value::from(9u64), Value::from(provider.not_after)),
        ])
    }

    fn provider_parse(value: &Value) -> Result<ProviderIdentity, TrustError> {
        let error = TrustError::MalformedEvidence;
        let entries = integer_entries(value, error)?;
        Ok(ProviderIdentity {
            id: uint(get(&entries, 1).ok_or(error)?, error)?,
            generation: u32_value(get(&entries, 2).ok_or(error)?, error)?,
            level: EvidenceLevel::parse(&text(get(&entries, 3).ok_or(error)?, error)?)
                .ok_or(error)?,
            revocation_epoch: uint(get(&entries, 7).ok_or(error)?, error)?,
            not_before: uint(get(&entries, 8).ok_or(error)?, error)?,
            not_after: uint(get(&entries, 9).ok_or(error)?, error)?,
            signer: [0; 32],
        })
    }

    pub(super) fn measurement_value(measurement: &Measurement) -> Value {
        Value::Map(vec![
            (Value::from(1u64), Value::from(measurement.kind.wire())),
            (Value::from(2u64), Value::from(measurement.digest.to_vec())),
            (
                Value::from(3u64),
                Value::Array(
                    measurement
                        .covered
                        .iter()
                        .map(|item| Value::from(item.as_str()))
                        .collect(),
                ),
            ),
            (Value::from(4u64), Value::Array(Vec::new())),
        ])
    }

    fn measurement_parse(value: &Value) -> Result<Measurement, TrustError> {
        let error = TrustError::MalformedEvidence;
        let entries = integer_entries(value, error)?;
        let digest_bytes = bytes_value(get(&entries, 2).ok_or(error)?, Some(32), error)?;
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&digest_bytes);
        Ok(Measurement {
            kind: MeasurementKind::parse(&text(get(&entries, 1).ok_or(error)?, error)?)
                .ok_or(error)?,
            digest,
            covered: array(get(&entries, 3).ok_or(error)?, error)?
                .iter()
                .map(|item| text(item, error))
                .collect::<Result<Vec<_>, _>>()?,
        })
    }

    pub(super) fn gap_value(gap: &CoverageGap) -> Value {
        Value::Map(vec![
            (Value::from(1u64), Value::from(gap.code.wire())),
            (Value::from(2u64), Value::from(gap.detail.as_str())),
        ])
    }

    fn gap_parse(value: &Value, error: TrustError) -> Result<CoverageGap, TrustError> {
        let entries = integer_entries(value, error)?;
        Ok(CoverageGap {
            code: CoverageGapCode::parse(&text(get(&entries, 1).ok_or(error)?, error)?)
                .ok_or(error)?,
            detail: text(get(&entries, 2).ok_or(error)?, error)?,
        })
    }

    pub(super) fn evidence_signing_message(claims: &EvidenceClaims) -> Result<Vec<u8>, TrustError> {
        let mut message = EVIDENCE_DOMAIN.to_vec();
        message.extend_from_slice(&encode(&claims.to_value(false), MAX_WIRE_BYTES)?);
        Ok(message)
    }

    pub(super) fn decode_evidence(bytes: &[u8]) -> Result<EvidenceClaims, TrustError> {
        let error = TrustError::MalformedEvidence;
        let value = decode(bytes, MAX_WIRE_BYTES, error)?;
        let entries = integer_entries(&value, error)?;
        if text(get(&entries, 1).ok_or(error)?, error)? != "trust.evidence/v1"
            || uint(get(&entries, 2).ok_or(error)?, error)? != PROTOCOL_VERSION
        {
            return Err(TrustError::Unsupported);
        }
        let id = fixed_id(get(&entries, 3).ok_or(error)?, error)?;
        let challenge_id = fixed_id(get(&entries, 4).ok_or(error)?, error)?;
        let nonce = fixed_nonce(get(&entries, 5).ok_or(error)?, error)?;
        let subject = subject_parse(get(&entries, 6).ok_or(error)?)?;
        let mut provider = provider_parse(get(&entries, 7).ok_or(error)?)?;
        let trust_chain = array(get(&entries, 16).ok_or(error)?, error)?
            .iter()
            .map(|item| bytes_value(item, Some(32), error))
            .collect::<Result<Vec<_>, _>>()?;
        if trust_chain.len() != 1 {
            return Err(error);
        }
        provider.signer.copy_from_slice(&trust_chain[0]);
        let revocation_references = array(get(&entries, 17).ok_or(error)?, error)?
            .iter()
            .map(|item| bytes_value(item, None, error))
            .collect::<Result<Vec<_>, _>>()?;
        let signature = fixed_signature(get(&entries, 15).ok_or(error)?, error)?;
        Ok(EvidenceClaims {
            id,
            challenge_id,
            nonce,
            subject: subject.clone(),
            provider,
            object_generation: u32_value(get(&entries, 8).ok_or(error)?, error)?,
            measurements: array(get(&entries, 9).ok_or(error)?, error)?
                .iter()
                .map(measurement_parse)
                .collect::<Result<Vec<_>, _>>()?,
            gaps: array(get(&entries, 10).ok_or(error)?, error)?
                .iter()
                .map(|item| gap_parse(item, error))
                .collect::<Result<Vec<_>, _>>()?,
            issued_at: uint(get(&entries, 11).ok_or(error)?, error)?,
            expires_at: uint(get(&entries, 12).ok_or(error)?, error)?,
            policy_epoch: uint(get(&entries, 13).ok_or(error)?, error)?,
            disclosure_fields: array(get(&entries, 14).ok_or(error)?, error)?
                .iter()
                .map(|item| text(item, error))
                .collect::<Result<Vec<_>, _>>()?,
            trust_chain,
            revocation_references,
            signature: Some(signature),
        })
    }

    pub(super) fn result_signing_message(claims: &ResultClaims) -> Result<Vec<u8>, TrustError> {
        let mut message = RESULT_DOMAIN.to_vec();
        message.extend_from_slice(&encode(&claims.to_value(false), MAX_WIRE_BYTES)?);
        Ok(message)
    }

    pub(super) fn decode_result(bytes: &[u8]) -> Result<ResultClaims, TrustError> {
        let error = TrustError::MalformedResult;
        let value = decode(bytes, MAX_WIRE_BYTES, error)?;
        let entries = integer_entries(&value, error)?;
        if text(get(&entries, 1).ok_or(error)?, error)? != "trust.result/v1"
            || uint(get(&entries, 2).ok_or(error)?, error)? != PROTOCOL_VERSION
        {
            return Err(TrustError::Unsupported);
        }
        let extension = get(&entries, 19).ok_or(error)?;
        let Value::Map(extension) = extension else {
            return Err(error);
        };
        let mut verifier_signer = None;
        for (key, value) in extension {
            match key {
                Value::Text(key) if key == "verifier-signer" => {
                    let bytes = bytes_value(value, Some(32), error)?;
                    let mut signer = [0u8; 32];
                    signer.copy_from_slice(&bytes);
                    verifier_signer = Some(signer);
                }
                _ => return Err(error),
            }
        }
        Ok(ResultClaims {
            id: fixed_id(get(&entries, 3).ok_or(error)?, error)?,
            challenge_id: fixed_id(get(&entries, 4).ok_or(error)?, error)?,
            evidence_id: fixed_id(get(&entries, 5).ok_or(error)?, error)?,
            nonce: fixed_nonce(get(&entries, 6).ok_or(error)?, error)?,
            status: ResultStatus::parse(&text(get(&entries, 7).ok_or(error)?, error)?)
                .ok_or(error)?,
            level: EvidenceLevel::parse(&text(get(&entries, 8).ok_or(error)?, error)?)
                .ok_or(error)?,
            verified: array(get(&entries, 9).ok_or(error)?, error)?
                .iter()
                .map(|item| text(item, error))
                .collect::<Result<Vec<_>, _>>()?,
            gaps: array(get(&entries, 10).ok_or(error)?, error)?
                .iter()
                .map(|item| gap_parse(item, error))
                .collect::<Result<Vec<_>, _>>()?,
            subject_generation: u32_value(get(&entries, 11).ok_or(error)?, error)?,
            object_generation: u32_value(get(&entries, 12).ok_or(error)?, error)?,
            provider_generation: u32_value(get(&entries, 13).ok_or(error)?, error)?,
            policy_epoch: uint(get(&entries, 14).ok_or(error)?, error)?,
            issued_at: uint(get(&entries, 15).ok_or(error)?, error)?,
            expires_at: uint(get(&entries, 16).ok_or(error)?, error)?,
            verifier_signer: verifier_signer.ok_or(error)?,
            signature: Some(fixed_signature(get(&entries, 17).ok_or(error)?, error)?),
        })
    }

    pub(super) fn policy_signing_message(claims: &PolicyClaims) -> Result<Vec<u8>, TrustError> {
        let mut message = POLICY_DOMAIN.to_vec();
        message.extend_from_slice(&encode(&claims.to_value(None), MAX_WIRE_BYTES)?);
        Ok(message)
    }

    pub(super) fn decode_challenge(bytes: &[u8]) -> Result<Challenge, TrustError> {
        let error = TrustError::MalformedChallenge;
        let value = decode(bytes, MAX_WIRE_BYTES, error)?;
        let entries = integer_entries(&value, error)?;
        if text(get(&entries, 1).ok_or(error)?, error)? != "trust.challenge/v1"
            || uint(get(&entries, 2).ok_or(error)?, error)? != PROTOCOL_VERSION
        {
            return Err(TrustError::Unsupported);
        }
        let extension = get(&entries, 12).ok_or(error)?;
        let Value::Map(extension) = extension else {
            return Err(error);
        };
        let mut expected = None;
        let mut accepted_gaps = None;
        for (key, value) in extension {
            match key {
                Value::Text(key) if key == "expected-subject" => {
                    expected = Some(subject_parse(value)?)
                }
                Value::Text(key) if key == "accepted-gaps" => {
                    accepted_gaps = Some(
                        array(value, error)?
                            .iter()
                            .map(|item| CoverageGapCode::parse(&text(item, error)?).ok_or(error))
                            .collect::<Result<Vec<_>, _>>()?,
                    )
                }
                _ => return Err(error),
            }
        }
        Ok(Challenge {
            id: fixed_id(get(&entries, 3).ok_or(error)?, error)?,
            nonce: fixed_nonce(get(&entries, 4).ok_or(error)?, error)?,
            audience: text(get(&entries, 5).ok_or(error)?, error)?,
            expected: expected.ok_or(error)?,
            accepted_levels: array(get(&entries, 7).ok_or(error)?, error)?
                .iter()
                .map(|item| EvidenceLevel::parse(&text(item, error)?).ok_or(error))
                .collect::<Result<Vec<_>, _>>()?,
            requested_fields: array(get(&entries, 8).ok_or(error)?, error)?
                .iter()
                .map(|item| text(item, error))
                .collect::<Result<Vec<_>, _>>()?,
            accepted_gaps: accepted_gaps.ok_or(error)?,
            policy_epoch: uint(get(&entries, 9).ok_or(error)?, error)?,
            issued_at: uint(get(&entries, 10).ok_or(error)?, error)?,
            expires_at: uint(get(&entries, 11).ok_or(error)?, error)?,
        })
    }

    fn fixed_id(value: &Value, error: TrustError) -> Result<[u8; CHALLENGE_ID_BYTES], TrustError> {
        let bytes = bytes_value(value, Some(CHALLENGE_ID_BYTES), error)?;
        let mut output = [0u8; CHALLENGE_ID_BYTES];
        output.copy_from_slice(&bytes);
        Ok(output)
    }

    fn fixed_nonce(value: &Value, error: TrustError) -> Result<[u8; NONCE_BYTES], TrustError> {
        let bytes = bytes_value(value, Some(NONCE_BYTES), error)?;
        let mut output = [0u8; NONCE_BYTES];
        output.copy_from_slice(&bytes);
        Ok(output)
    }

    fn fixed_signature(value: &Value, error: TrustError) -> Result<[u8; 64], TrustError> {
        let bytes = bytes_value(value, Some(64), error)?;
        let mut output = [0u8; 64];
        output.copy_from_slice(&bytes);
        Ok(output)
    }
}

impl Challenge {
    fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::from(1u64), Value::from("trust.challenge/v1")),
            (Value::from(2u64), Value::from(PROTOCOL_VERSION)),
            (Value::from(3u64), Value::from(self.id.to_vec())),
            (Value::from(4u64), Value::from(self.nonce.to_vec())),
            (Value::from(5u64), Value::from(self.audience.as_str())),
            (Value::from(6u64), Value::from(self.expected.kind.wire())),
            (
                Value::from(7u64),
                Value::Array(
                    self.accepted_levels
                        .iter()
                        .map(|level| Value::from(level.wire()))
                        .collect(),
                ),
            ),
            (
                Value::from(8u64),
                Value::Array(
                    self.requested_fields
                        .iter()
                        .map(|field| Value::from(field.as_str()))
                        .collect(),
                ),
            ),
            (Value::from(9u64), Value::from(self.policy_epoch)),
            (Value::from(10u64), Value::from(self.issued_at)),
            (Value::from(11u64), Value::from(self.expires_at)),
            (
                Value::from(12u64),
                Value::Map(vec![
                    (
                        Value::from("expected-subject"),
                        wire::subject_value(&self.expected),
                    ),
                    (
                        Value::from("accepted-gaps"),
                        Value::Array(
                            self.accepted_gaps
                                .iter()
                                .map(|gap| Value::from(gap.wire()))
                                .collect(),
                        ),
                    ),
                ]),
            ),
        ])
    }
}

#[cfg(test)]
mod tests;
