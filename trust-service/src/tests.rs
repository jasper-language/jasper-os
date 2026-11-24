use super::*;
use jaso::build::{Builder, SegmentIn, Signer};
use jaso::{Arch, Stage, FLAG_R, FLAG_X, PAGE};
use kernel_core::objtable::ObjId;
use kernel_core::security::{
    ApplicationIdentity, BootId, IdentityClass, MetadataState, SecurityContext,
};

const MANIFEST: &[u8] = b"core.name = demo.trust\ncore.version = 1.0.0\ncore.abi = c.v1\ncore.stage = runtime\ncore.publisher = trust.demo\ncore.exports = f_one\n";
const GAPS: [CoverageGapCode; 4] = [
    CoverageGapCode::ProcessMemoryNotMeasured,
    CoverageGapCode::RuntimeDependenciesNotMeasured,
    CoverageGapCode::BootChainNotMeasured,
    CoverageGapCode::HardwareBackingUnavailable,
];

fn package() -> Vec<u8> {
    let mut builder = Builder::native(Arch::X86_64, Stage::Runtime, MANIFEST);
    builder.segments = vec![
        SegmentIn {
            vaddr: 0,
            mem_size: 64,
            flags: FLAG_R,
            data: vec![5; 64],
        },
        SegmentIn {
            vaddr: PAGE,
            mem_size: 32,
            flags: FLAG_R | FLAG_X,
            data: vec![0xC3; 32],
        },
    ];
    builder.exports = vec![(b"f_one".to_vec(), PAGE)];
    builder.relocs = vec![(0, 0x10)];
    let signer = Signer::from_seed(&[0xA1; 32]);
    builder.finish_signed(&signer).expect("signed JASO")
}

fn context(generation: u32, digest: [u8; 32]) -> SecurityContext {
    let raw = (u64::from(generation) << 32) | 0x27;
    let id = ObjId::from_raw(raw).expect("process object id");
    SecurityContext::new(
        BootId::from_words([0x1010, 0x2020]),
        IdentityClass::Process,
        id,
        Some(ApplicationIdentity::measured(0x5157, 3, digest)),
        MetadataState::Active,
    )
}

fn unmeasured_context() -> SecurityContext {
    let id = ObjId::from_raw((1u64 << 32) | 0x27).expect("process object id");
    SecurityContext::new(
        BootId::from_words([0x1010, 0x2020]),
        IdentityClass::Process,
        id,
        None,
        MetadataState::Active,
    )
}

fn broker() -> Broker {
    Broker::new(
        [0xB1; 32],
        ProviderIdentity {
            id: 7,
            generation: 4,
            level: EvidenceLevel::SoftwareObservation,
            revocation_epoch: 9,
            not_before: 1,
            not_after: 10_000,
            signer: [0; 32],
        },
    )
    .expect("broker")
}

fn verifier_policy(provider_key: [u8; 32], revoked: bool) -> VerifierPolicy {
    VerifierPolicy {
        trusted_provider_key: provider_key,
        revoked_provider_keys: revoked.then_some(provider_key).into_iter().collect(),
        minimum_policy_epoch: 7,
        minimum_revocation_epoch: 9,
    }
}

fn policy(verifier_seed: [u8; 32], epoch: u64) -> PolicyEvaluator {
    let verifier_key = SigningKey::from_bytes(&verifier_seed)
        .verifying_key()
        .to_bytes();
    PolicyEvaluator::new(
        verifier_key,
        "relying-party.software-integrity/1",
        GAPS.to_vec(),
        epoch,
        [0xF1; 32],
    )
    .expect("policy")
}

fn daemon<const N: usize>(revoked: bool, policy_epoch: u64) -> TrustDaemon<N> {
    let broker = broker();
    let provider_key = broker.provider().signer;
    let verifier_seed = [0xE2; 32];
    TrustDaemon::new(
        broker,
        verifier_policy(provider_key, revoked),
        verifier_seed,
        policy(verifier_seed, policy_epoch),
    )
    .expect("trust daemon")
}

fn issue<const N: usize>(
    daemon: &mut TrustDaemon<N>,
    nonce: [u8; NONCE_BYTES],
    expected: SubjectSnapshot,
    lifetime: u64,
    now: u64,
) -> Challenge {
    daemon
        .verifier
        .issue_challenge(ChallengeRequest {
            nonce,
            audience: "relying-party.example",
            expected,
            accepted_levels: vec![EvidenceLevel::SoftwareObservation],
            requested_fields: vec!["jaso.digest".to_owned()],
            accepted_gaps: GAPS.to_vec(),
            policy_epoch: 7,
            now,
            lifetime,
        })
        .unwrap()
}

#[test]
fn real_measured_jaso_is_bound_to_sec_generation_and_nonce() {
    let package = package();
    let digest = jaso::digest_of(&package);
    let context = context(1, digest);
    let subject = SubjectSnapshot::from_context(context).expect("subject");
    let mut daemon = daemon::<2>(false, 7);
    let outcome = daemon
        .attest(
            [7; NONCE_BYTES],
            "relying-party.example",
            context,
            &package,
            100,
            30,
        )
        .expect("software evidence");

    assert_eq!(outcome.verification.status, ResultStatus::VerifiedWithGaps);
    assert_eq!(outcome.policy.decision, PolicyDecision::Degrade);
    assert_eq!(outcome.verification.id.len(), CHALLENGE_ID_BYTES);
    assert_eq!(daemon.live_challenges(), 0);
    assert!(outcome
        .policy
        .reasons
        .contains(&"hardware-backing-unavailable".to_owned()));

    let claims = wire::decode_evidence(&outcome.evidence.bytes).expect("evidence wire");
    assert!(claims.subject.identity_matches(&subject));
    assert_eq!(claims.subject.measurement, digest);
    assert_eq!(claims.nonce, [7; NONCE_BYTES]);
    assert_eq!(claims.measurements[0].kind, MeasurementKind::Package);
    assert!(claims
        .gaps
        .iter()
        .any(|gap| { gap.code == CoverageGapCode::HardwareBackingUnavailable }));
}

#[test]
fn challenge_wire_roundtrip_preserves_generation_and_gaps() {
    let package = package();
    let context = context(2, jaso::digest_of(&package));
    let expected = SubjectSnapshot::from_context(context).unwrap();
    let mut verifier = daemon::<1>(false, 7);
    let challenge = issue(&mut verifier, [9; NONCE_BYTES], expected.clone(), 20, 100);
    let wire = challenge.encode().unwrap();
    let decoded = Challenge::decode(&wire).unwrap();
    assert_eq!(decoded.expected, expected);
    assert_eq!(decoded.accepted_gaps, GAPS);
}

#[test]
fn missing_measurement_and_tampered_package_fail_closed() {
    let package = package();
    let missing_context = unmeasured_context();
    let mut daemon = daemon::<1>(false, 7);
    assert_eq!(
        daemon.attest(
            [1; NONCE_BYTES],
            "relying-party.example",
            missing_context,
            &package,
            100,
            30,
        ),
        Err(TrustError::MeasurementUnavailable)
    );

    let mut tampered = package.clone();
    tampered[100] ^= 1;
    let measured_context = context(1, jaso::digest_of(&package));
    assert_eq!(
        daemon.attest(
            [2; NONCE_BYTES],
            "relying-party.example",
            measured_context,
            &tampered,
            100,
            30,
        ),
        Err(TrustError::UnsignedPackage)
    );
}

#[test]
fn forged_subject_and_cross_generation_are_rejected() {
    let package = package();
    let digest = jaso::digest_of(&package);
    let expected_context = context(1, digest);
    let expected = SubjectSnapshot::from_context(expected_context).unwrap();
    let mut daemon = daemon::<2>(false, 7);
    let challenge = issue(&mut daemon, [3; NONCE_BYTES], expected, 30, 100);
    assert_eq!(
        daemon
            .collector
            .collect(&challenge, context(2, digest), &package, 100),
        Err(TrustError::ForgedScope)
    );
    assert_eq!(
        daemon
            .collector
            .collect(&challenge, context(1, [0xA5; 32]), &package, 100),
        Err(TrustError::ForgedScope)
    );
}

#[test]
fn stale_challenge_and_replay_fail_closed() {
    let package = package();
    let digest = jaso::digest_of(&package);
    let context = context(1, digest);
    let expected = SubjectSnapshot::from_context(context).unwrap();
    let mut daemon = daemon::<1>(false, 7);
    let challenge = issue(&mut daemon, [4; NONCE_BYTES], expected, 5, 100);
    let observation = daemon
        .collector
        .collect(&challenge, context, &package, 101)
        .unwrap();
    let evidence = daemon
        .broker
        .as_ref()
        .unwrap()
        .attest(&challenge, observation, 101)
        .unwrap();
    assert_eq!(
        daemon.verifier.verify(&evidence.bytes, 106),
        Err(TrustError::ChallengeExpired)
    );

    let challenge = issue(
        &mut daemon,
        [5; NONCE_BYTES],
        SubjectSnapshot::from_context(context).unwrap(),
        30,
        110,
    );
    let observation = daemon
        .collector
        .collect(&challenge, context, &package, 111)
        .unwrap();
    let evidence = daemon
        .broker
        .as_ref()
        .unwrap()
        .attest(&challenge, observation, 111)
        .unwrap();
    daemon.verifier.verify(&evidence.bytes, 111).unwrap();
    assert_eq!(
        daemon.verifier.verify(&evidence.bytes, 111),
        Err(TrustError::Replay)
    );
}

#[test]
fn revoked_provider_and_stale_policy_are_rejected() {
    let package = package();
    let digest = jaso::digest_of(&package);
    let context = context(1, digest);
    let mut revoked = daemon::<1>(true, 7);
    let expected = SubjectSnapshot::from_context(context).unwrap();
    let challenge = issue(&mut revoked, [6; NONCE_BYTES], expected, 30, 100);
    let observation = revoked
        .collector
        .collect(&challenge, context, &package, 100)
        .unwrap();
    let evidence = revoked
        .broker
        .as_ref()
        .unwrap()
        .attest(&challenge, observation, 100)
        .unwrap();
    assert_eq!(
        revoked.verifier.verify(&evidence.bytes, 100),
        Err(TrustError::ProviderRevoked)
    );

    let mut current = daemon::<1>(false, 7);
    let outcome = current
        .attest(
            [8; NONCE_BYTES],
            "relying-party.example",
            context,
            &package,
            100,
            30,
        )
        .unwrap();
    let strict = policy([0xE2; 32], 8);
    assert_eq!(
        strict.evaluate(&outcome.verification, 100),
        Err(TrustError::PolicyStale)
    );
}

#[test]
fn broker_death_releases_challenges_and_returns_unavailable() {
    let package = package();
    let digest = jaso::digest_of(&package);
    let context = context(1, digest);
    let mut daemon = daemon::<2>(false, 7);
    let expected = SubjectSnapshot::from_context(context).unwrap();
    issue(&mut daemon, [10; NONCE_BYTES], expected, 30, 100);
    assert_eq!(daemon.live_challenges(), 1);
    daemon.stop_broker();
    assert_eq!(daemon.live_challenges(), 0);
    assert_eq!(
        daemon.attest(
            [11; NONCE_BYTES],
            "relying-party.example",
            context,
            &package,
            100,
            30,
        ),
        Err(TrustError::BrokerUnavailable)
    );
    assert_eq!(daemon.live_challenges(), 0);
}

#[test]
fn challenge_capacity_recovers_after_success() {
    let package = package();
    let digest = jaso::digest_of(&package);
    let context = context(1, digest);
    let expected = SubjectSnapshot::from_context(context).unwrap();
    let mut daemon = daemon::<1>(false, 7);
    issue(&mut daemon, [12; NONCE_BYTES], expected.clone(), 30, 100);
    assert_eq!(
        daemon.verifier.issue_challenge(ChallengeRequest {
            nonce: [13; NONCE_BYTES],
            audience: "relying-party.example",
            expected,
            accepted_levels: vec![EvidenceLevel::SoftwareObservation],
            requested_fields: vec!["jaso.digest".to_owned()],
            accepted_gaps: GAPS.to_vec(),
            policy_epoch: 7,
            now: 100,
            lifetime: 30,
        },),
        Err(TrustError::Capacity)
    );
    daemon.verifier.clear_challenges();
    daemon
        .attest(
            [14; NONCE_BYTES],
            "relying-party.example",
            context,
            &package,
            100,
            30,
        )
        .expect("capacity recovered");
    assert_eq!(daemon.live_challenges(), 0);
}

#[test]
fn malformed_evidence_and_tampered_result_never_succeed() {
    let package = package();
    let digest = jaso::digest_of(&package);
    let context = context(1, digest);
    let mut daemon = daemon::<1>(false, 7);
    let outcome = daemon
        .attest(
            [15; NONCE_BYTES],
            "relying-party.example",
            context,
            &package,
            100,
            30,
        )
        .unwrap();
    assert!(matches!(
        wire::decode_evidence(&outcome.evidence.bytes[..outcome.evidence.bytes.len() - 1]),
        Err(TrustError::MalformedEvidence)
    ));

    let mut tampered = outcome.verification.bytes.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let result = VerificationResult {
        id: outcome.verification.id,
        status: outcome.verification.status,
        verifier_signer: outcome.verification.verifier_signer,
        bytes: tampered,
    };
    assert!(daemon.policy.evaluate(&result, 100).is_err());
}

#[test]
fn signed_payload_mutation_with_reused_signature_is_rejected() {
    let package = package();
    let digest = jaso::digest_of(&package);
    let context = context(1, digest);
    let expected = SubjectSnapshot::from_context(context).unwrap();
    let mut daemon = daemon::<2>(false, 7);
    let challenge = issue(&mut daemon, [16; NONCE_BYTES], expected, 30, 100);
    let observation = daemon
        .collector
        .collect(&challenge, context, &package, 100)
        .unwrap();
    let evidence = daemon
        .broker
        .as_ref()
        .unwrap()
        .attest(&challenge, observation, 100)
        .unwrap();

    let mut forged = wire::decode_evidence(&evidence.bytes).unwrap();
    let signature = forged.signature.unwrap();
    forged.measurements[0].digest[0] ^= 1;
    let forged_wire = forged.encode(Some(signature)).unwrap();
    assert_eq!(
        daemon.verifier.verify(&forged_wire, 100),
        Err(TrustError::InvalidSignature)
    );
    let verified = daemon.verifier.verify(&evidence.bytes, 100).unwrap();

    let mut forged_result = wire::decode_result(&verified.bytes).unwrap();
    let signature = forged_result.signature.unwrap();
    forged_result.status = ResultStatus::Verified;
    let forged_result_wire = forged_result.encode(signature).unwrap();
    let result = VerificationResult {
        id: verified.id,
        status: ResultStatus::Verified,
        verifier_signer: verified.verifier_signer,
        bytes: forged_result_wire,
    };
    assert_eq!(
        daemon.policy.evaluate(&result, 100),
        Err(TrustError::InvalidSignature)
    );
}
