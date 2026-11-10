//! SEC-3 mandatory access control: multi-dimensional labels, signed policy
//! packages and a bounded fail-closed decision journal.
//!
//! A policy decision succeeds only when all of the following hold:
//! * a verified policy contains a rule for the source domain, target domain,
//!   effect and object class;
//! * all rules that match those dimensions accept the label ordering and
//!   class mask;
//! * an audit record can be reserved before the effect is permitted.
//!
//! There is no implicit allow rule. Unknown labels, domains, classes, effects,
//! malformed packages and exhausted audit storage all fail closed.

use crate::meta::Effects;
use crate::security::{IdentityClass, ObjectIdentity, SecurityDomain};

pub const MAC_LABEL_VERSION: u16 = 1;
pub const MAX_POLICY_RULES: usize = 32;
pub const MAX_AUDIT_EVENTS: usize = 256;
pub const POLICY_AUTHORITY_JASPER: u64 = 0x4a53_524d_4143_0001;
pub const OBJECT_CLASS_ALL: u16 = (1u16 << 10) - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Secrecy {
    Public = 0,
    Internal = 1,
    Sensitive = 2,
    Secret = 3,
}

impl Secrecy {
    pub const fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Public),
            1 => Some(Self::Internal),
            2 => Some(Self::Sensitive),
            3 => Some(Self::Secret),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Integrity {
    Untrusted = 0,
    Managed = 1,
    Trusted = 2,
    System = 3,
}

impl Integrity {
    pub const fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Untrusted),
            1 => Some(Self::Managed),
            2 => Some(Self::Trusted),
            3 => Some(Self::System),
            _ => None,
        }
    }
}

/// A label attached to an object or execution subject. For a subject,
/// `object_classes` is an allowance set. For an object it is membership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MacLabel {
    pub version: u16,
    pub domain: SecurityDomain,
    pub secrecy: u8,
    pub integrity: u8,
    pub object_classes: u16,
    pub reserved: u8,
}

impl MacLabel {
    pub const fn new(
        domain: SecurityDomain,
        secrecy: Secrecy,
        integrity: Integrity,
        object_classes: u16,
    ) -> Self {
        Self {
            version: MAC_LABEL_VERSION,
            domain,
            secrecy: secrecy as u8,
            integrity: integrity as u8,
            object_classes,
            reserved: 0,
        }
    }

    pub const fn system(class: IdentityClass) -> Self {
        match class {
            IdentityClass::Bootstrap => Self::new(
                SecurityDomain::SYSTEM,
                Secrecy::Secret,
                Integrity::System,
                OBJECT_CLASS_ALL,
            ),
            _ => Self::new(
                SecurityDomain::SYSTEM,
                Secrecy::Internal,
                Integrity::Trusted,
                class_bit(class),
            ),
        }
    }

    /// Default process labels can name every object class. Default object
    /// labels contain only their own class bit.
    pub const fn for_class(class: IdentityClass) -> Self {
        match class {
            IdentityClass::Bootstrap => Self::system(class),
            IdentityClass::KernelObject | IdentityClass::Module => Self::new(
                SecurityDomain::SYSTEM,
                Secrecy::Internal,
                Integrity::Trusted,
                class_bit(class),
            ),
            IdentityClass::Process | IdentityClass::Task | IdentityClass::Service => Self::new(
                SecurityDomain::USER,
                Secrecy::Internal,
                Integrity::Managed,
                OBJECT_CLASS_ALL,
            ),
            IdentityClass::Memory => Self::new(
                SecurityDomain::USER,
                Secrecy::Internal,
                Integrity::Managed,
                class_bit(IdentityClass::Memory),
            ),
            IdentityClass::Device | IdentityClass::Vcpu => Self::new(
                SecurityDomain::USER,
                Secrecy::Internal,
                Integrity::Untrusted,
                class_bit(class),
            ),
            IdentityClass::File => Self::new(
                SecurityDomain::USER,
                Secrecy::Internal,
                Integrity::Managed,
                class_bit(class),
            ),
        }
    }

    pub const fn with_domain(mut self, domain: SecurityDomain) -> Self {
        self.domain = domain;
        self
    }

    /// Project a subject label onto a concrete object class while preserving
    /// domain, secrecy and integrity. Process-owned objects use this narrower
    /// form instead of inheriting the subject's whole class clearance.
    pub const fn as_object(mut self, class: IdentityClass) -> Self {
        self.object_classes = class_bit(class);
        self
    }

    pub const fn is_supported(self) -> bool {
        self.version == MAC_LABEL_VERSION
            && self.reserved == 0
            && self.secrecy <= Secrecy::Secret as u8
            && self.integrity <= Integrity::System as u8
            && self.object_classes != 0
            && self.object_classes & !OBJECT_CLASS_ALL == 0
    }

    pub const fn secrecy(self) -> Option<Secrecy> {
        if self.is_supported() {
            Secrecy::from_raw(self.secrecy)
        } else {
            None
        }
    }

    pub const fn integrity(self) -> Option<Integrity> {
        if self.is_supported() {
            Integrity::from_raw(self.integrity)
        } else {
            None
        }
    }
}

/// A subject additionally records the object classes it may name. Keeping it
/// as a separate type prevents an object label from being used accidentally as
/// a subject clearance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubjectLabel {
    pub label: MacLabel,
    pub allowed_classes: u16,
}

impl SubjectLabel {
    pub const fn from_label(label: MacLabel) -> Self {
        Self {
            label,
            allowed_classes: label.object_classes,
        }
    }

    pub const fn with_allowed_classes(mut self, classes: u16) -> Self {
        self.allowed_classes = classes;
        self
    }

    pub const fn is_supported(self) -> bool {
        self.label.is_supported()
            && self.allowed_classes != 0
            && self.allowed_classes & !OBJECT_CLASS_ALL == 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MacEffect {
    Observe,
    Read,
    Write,
    Control,
    Share,
}

impl MacEffect {
    pub const fn from_effects(effect: Effects) -> Self {
        match effect {
            Effects::None | Effects::Read => Self::Read,
            Effects::Write => Self::Write,
            Effects::Irreversible => Self::Control,
        }
    }

    const fn bit(self) -> u8 {
        1 << (self as u8)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MacRule {
    pub source: SecurityDomain,
    pub target: SecurityDomain,
    pub effects: u8,
    pub object_classes: u16,
}

impl MacRule {
    pub const fn new(
        source: SecurityDomain,
        target: SecurityDomain,
        effects: &[MacEffect],
        object_classes: &[IdentityClass],
    ) -> Self {
        let mut effect_bits = 0u8;
        let mut index = 0usize;
        while index < effects.len() {
            effect_bits |= effects[index].bit();
            index += 1;
        }
        let mut class_bits = 0u16;
        let mut index = 0usize;
        while index < object_classes.len() {
            class_bits |= class_bit(object_classes[index]);
            index += 1;
        }
        Self {
            source,
            target,
            effects: effect_bits,
            object_classes: class_bits,
        }
    }

    const fn permits(
        self,
        source: SecurityDomain,
        target: SecurityDomain,
        effect: MacEffect,
        object_classes: u16,
    ) -> bool {
        self.source.0 == source.0
            && self.target.0 == target.0
            && self.effects & effect.bit() != 0
            && self.object_classes & object_classes != 0
    }

    const fn is_valid(self) -> bool {
        self.effects != 0
            && self.object_classes != 0
            && self.object_classes & !OBJECT_CLASS_ALL == 0
    }
}

pub const fn class_bit(class: IdentityClass) -> u16 {
    1u16 << (class as u32 - 1)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicySource {
    pub authority_id: u64,
    pub version: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyDigest(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicySignature(pub [u8; 64]);

pub trait PolicySignatureVerifier {
    fn verify(
        &self,
        source: PolicySource,
        digest: PolicyDigest,
        signature: PolicySignature,
    ) -> bool;
}

/// Fixed-capacity package. The digest covers the source, rule count and every
/// canonical rule field; signatures are checked by the supplied verifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MacPolicyPackage {
    pub source: PolicySource,
    pub digest: PolicyDigest,
    pub signature: PolicySignature,
    len: u8,
    rules: [MacRule; MAX_POLICY_RULES],
}

impl MacPolicyPackage {
    const EMPTY_RULE: MacRule = MacRule {
        source: SecurityDomain::SYSTEM,
        target: SecurityDomain::SYSTEM,
        effects: 0,
        object_classes: 0,
    };

    pub const fn empty(source: PolicySource) -> Self {
        Self {
            source,
            digest: PolicyDigest([0; 32]),
            signature: PolicySignature([0; 64]),
            len: 0,
            rules: [Self::EMPTY_RULE; MAX_POLICY_RULES],
        }
    }

    pub fn push(&mut self, rule: MacRule) -> Result<(), MacDenial> {
        if !rule.is_valid() || self.len as usize >= MAX_POLICY_RULES {
            return Err(MacDenial::InvalidPolicy);
        }
        self.rules[self.len as usize] = rule;
        self.len += 1;
        Ok(())
    }

    pub const fn len(self) -> usize {
        self.len as usize
    }

    pub fn rule(self, index: usize) -> Option<MacRule> {
        if index < self.len() {
            Some(self.rules[index])
        } else {
            None
        }
    }

    /// Deterministic content digest. This is an integrity input to a real
    /// signature verifier, not a claim that a non-cryptographic hash is a
    /// signature by itself.
    pub fn content_digest(self) -> PolicyDigest {
        let mut out = [0u8; 32];
        let mut hash = 0xcbf2_9ce4_8422_2325u64;
        hash = mix(hash, self.source.authority_id);
        hash = mix(hash, self.source.version as u64);
        hash = mix(hash, self.len as u64);
        let mut index = 0usize;
        while index < self.len() {
            let rule = self.rules[index];
            hash = mix(hash, rule.source.0 as u64);
            hash = mix(hash, rule.target.0 as u64);
            hash = mix(hash, rule.effects as u64);
            hash = mix(hash, rule.object_classes as u64);
            index += 1;
        }
        let mut word = 0usize;
        while word < out.len() / 8 {
            hash = mix(hash, word as u64);
            out[word * 8..word * 8 + 8].copy_from_slice(&hash.to_le_bytes());
            word += 1;
        }
        PolicyDigest(out)
    }

    pub fn seal_digest(&mut self) {
        self.digest = self.content_digest();
    }

    fn canonical_valid(self) -> bool {
        if self.len as usize > MAX_POLICY_RULES {
            return false;
        }
        let mut index = 0usize;
        while index < self.len() {
            if !self.rules[index].is_valid() {
                return false;
            }
            index += 1;
        }
        index = self.len() as usize;
        while index < MAX_POLICY_RULES {
            if self.rules[index] != Self::EMPTY_RULE {
                return false;
            }
            index += 1;
        }
        self.digest == self.content_digest()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MacPolicy {
    pub source: PolicySource,
    pub epoch: u64,
    len: u8,
    rules: [MacRule; MAX_POLICY_RULES],
}

impl MacPolicy {
    pub const fn deny_all(source: PolicySource, epoch: u64) -> Self {
        Self {
            source,
            epoch,
            len: 0,
            rules: [MacPolicyPackage::EMPTY_RULE; MAX_POLICY_RULES],
        }
    }

    pub fn compile_verified(
        package: MacPolicyPackage,
        source: PolicySource,
        verifier: &impl PolicySignatureVerifier,
    ) -> Result<Self, MacDenial> {
        if package.source != source || !package.canonical_valid() {
            return Err(MacDenial::InvalidPolicy);
        }
        if !verifier.verify(package.source, package.digest, package.signature) {
            return Err(MacDenial::InvalidSignature);
        }
        Ok(Self {
            source,
            epoch: 0,
            len: package.len,
            rules: package.rules,
        })
    }

    pub const fn len(self) -> usize {
        self.len as usize
    }

    pub fn rule(self, index: usize) -> Option<MacRule> {
        if index < self.len() {
            Some(self.rules[index])
        } else {
            None
        }
    }

    pub fn evaluate(
        self,
        subject: SubjectLabel,
        object: MacLabel,
        effect: MacEffect,
    ) -> Result<(), MacDenial> {
        if !subject.is_supported() {
            return Err(MacDenial::InvalidSubjectLabel);
        }
        if !object.is_supported() {
            return Err(MacDenial::InvalidObjectLabel);
        }
        if subject.allowed_classes & object.object_classes != object.object_classes {
            return Err(MacDenial::ClassDenied);
        }
        let subject_secrecy = subject.label.secrecy().ok_or(MacDenial::InvalidSubjectLabel)?;
        let subject_integrity = subject.label.integrity().ok_or(MacDenial::InvalidSubjectLabel)?;
        let object_secrecy = object.secrecy().ok_or(MacDenial::InvalidObjectLabel)?;
        let object_integrity = object.integrity().ok_or(MacDenial::InvalidObjectLabel)?;
        let mut matched = false;
        let mut index = 0usize;
        while index < self.len() {
            let rule = self.rules[index];
            index += 1;
            if !rule.permits(
                subject.label.domain,
                object.domain,
                effect,
                object.object_classes,
            ) {
                continue;
            }
            matched = true;
            match effect {
                MacEffect::Observe | MacEffect::Read => {
                    if subject_secrecy < object_secrecy {
                        return Err(MacDenial::SecrecyDenied);
                    }
                    if subject_integrity < object_integrity {
                        return Err(MacDenial::IntegrityDenied);
                    }
                }
                MacEffect::Write => {
                    if subject_secrecy > object_secrecy {
                        return Err(MacDenial::SecrecyDenied);
                    }
                    if subject_integrity < object_integrity {
                        return Err(MacDenial::IntegrityDenied);
                    }
                }
                MacEffect::Control | MacEffect::Share => {
                    if subject_integrity < object_integrity {
                        return Err(MacDenial::IntegrityDenied);
                    }
                }
            }
        }
        if matched {
            Ok(())
        } else {
            Err(MacDenial::NoRule)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicySlot {
    current: MacPolicy,
}

impl PolicySlot {
    pub const fn deny_all(source: PolicySource) -> Self {
        Self {
            current: MacPolicy::deny_all(source, 1),
        }
    }

    pub fn epoch(&self) -> u64 {
        self.current.epoch
    }

    pub fn current(&self) -> MacPolicy {
        self.current
    }

    /// Atomically install a compiled package. A ruleset can advance only by a
    /// strictly newer source version; the initial deny-all slot accepts the
    /// first package with the same source version. Failure changes nothing.
    pub fn replace_policy(&mut self, candidate: MacPolicy) -> Result<MacPolicy, MacDenial> {
        if candidate.len() == 0 {
            return Err(MacDenial::InvalidPolicy);
        }
        if candidate.source.authority_id != self.current.source.authority_id {
            return Err(MacDenial::PolicyAuthority);
        }
        if self.current.len() != 0 && candidate.source.version <= self.current.source.version {
            return Err(MacDenial::StalePolicy);
        }
        let next_epoch = self
            .current
            .epoch
            .checked_add(1)
            .ok_or(MacDenial::EpochExhausted)?;
        let installed = MacPolicy {
            epoch: next_epoch,
            ..candidate
        };
        self.current = installed;
        Ok(installed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MacDenial {
    NoPolicy,
    NoRule,
    InvalidSubjectLabel,
    InvalidObjectLabel,
    InvalidPolicy,
    InvalidSignature,
    PolicyAuthority,
    StalePolicy,
    EpochExhausted,
    SecrecyDenied,
    IntegrityDenied,
    ClassDenied,
    AuditFull,
}

impl MacDenial {
    pub const fn name(self) -> &'static str {
        match self {
            Self::NoPolicy => "system.mac.error.no_policy",
            Self::NoRule => "system.mac.error.default_deny",
            Self::InvalidSubjectLabel => "system.mac.error.subject_label",
            Self::InvalidObjectLabel => "system.mac.error.object_label",
            Self::InvalidPolicy => "system.mac.error.invalid_policy",
            Self::InvalidSignature => "system.mac.error.invalid_signature",
            Self::PolicyAuthority => "system.mac.error.policy_authority",
            Self::StalePolicy => "system.mac.error.stale_policy",
            Self::EpochExhausted => "system.mac.error.epoch_exhausted",
            Self::SecrecyDenied => "system.mac.error.secrecy",
            Self::IntegrityDenied => "system.mac.error.integrity",
            Self::ClassDenied => "system.mac.error.class",
            Self::AuditFull => "system.mac.error.audit_full",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MacDecision {
    pub sequence: u64,
    pub epoch: u64,
    pub subject: ObjectIdentity,
    pub object: ObjectIdentity,
    pub subject_domain: SecurityDomain,
    pub object_domain: SecurityDomain,
    pub effect: MacEffect,
    pub allowed: bool,
    pub denial: Option<MacDenial>,
    pub digest: u64,
}

#[derive(Clone, Copy)]
struct DecisionSlot {
    decision: Option<MacDecision>,
}

impl DecisionSlot {
    const EMPTY: Self = Self { decision: None };
}

pub struct MacEngine {
    policy: PolicySlot,
    decisions: [DecisionSlot; MAX_AUDIT_EVENTS],
    head: usize,
    len: usize,
    next_sequence: u64,
    overflow_attempts: u64,
    digest: u64,
}

impl MacEngine {
    pub const fn new(policy: PolicySlot) -> Self {
        Self {
            policy,
            decisions: [DecisionSlot::EMPTY; MAX_AUDIT_EVENTS],
            head: 0,
            len: 0,
            next_sequence: 1,
            overflow_attempts: 0,
            digest: 0xcbf2_9ce4_8422_2325,
        }
    }

    pub fn epoch(&self) -> u64 {
        self.policy.epoch()
    }

    pub fn policy(&self) -> MacPolicy {
        self.policy.current()
    }

    pub fn replace_policy(&mut self, candidate: MacPolicy) -> Result<MacPolicy, MacDenial> {
        self.policy.replace_policy(candidate)
    }

    /// Reserve and commit the audit decision before returning authorization.
    /// If the bounded decision queue is full, the operation is denied.
    pub fn authorize(
        &mut self,
        subject_identity: ObjectIdentity,
        subject: SubjectLabel,
        object_identity: ObjectIdentity,
        object: MacLabel,
        effect: MacEffect,
    ) -> Result<MacDecision, MacDenial> {
        if self.len == MAX_AUDIT_EVENTS {
            self.overflow_attempts = self.overflow_attempts.saturating_add(1);
            return Err(MacDenial::AuditFull);
        }
        let decision = self.policy.current().evaluate(subject, object, effect);
        let mut record = MacDecision {
            sequence: self.next_sequence,
            epoch: self.policy.epoch(),
            subject: subject_identity,
            object: object_identity,
            subject_domain: subject.label.domain,
            object_domain: object.domain,
            effect,
            allowed: decision.is_ok(),
            denial: decision.err(),
            digest: 0,
        };
        self.digest = decision_digest(self.digest, record);
        record.digest = self.digest;
        let tail = (self.head + self.len) % MAX_AUDIT_EVENTS;
        self.decisions[tail].decision = Some(record);
        self.len += 1;
        self.next_sequence = match self.next_sequence.checked_add(1) {
            Some(next) => next,
            None => {
                self.overflow_attempts = self.overflow_attempts.saturating_add(1);
                return Err(MacDenial::AuditFull);
            }
        };
        match record.denial {
            None => Ok(record),
            Some(reason) => Err(reason),
        }
    }

    pub fn drain_audit(&mut self) -> Option<MacDecision> {
        if self.len == 0 {
            return None;
        }
        let decision = self.decisions[self.head].decision.take();
        self.head = (self.head + 1) % MAX_AUDIT_EVENTS;
        self.len -= 1;
        decision
    }

    pub fn audit_pending(&self) -> usize {
        self.len
    }

    pub fn audit_overflow_attempts(&self) -> u64 {
        self.overflow_attempts
    }

    pub fn audit_digest(&self) -> u64 {
        self.digest
    }
}

const fn mix(mut digest: u64, word: u64) -> u64 {
    digest ^= word;
    digest.wrapping_mul(0x100_0000_01b3)
}

fn decision_digest(mut digest: u64, decision: MacDecision) -> u64 {
    digest = mix(digest, decision.sequence);
    digest = mix(digest, decision.epoch);
    digest = mix(digest, decision.subject.boot_id.words[0]);
    digest = mix(digest, decision.subject.boot_id.words[1]);
    digest = mix(digest, decision.subject.object_id);
    digest = mix(digest, decision.subject.generation as u64);
    digest = mix(digest, decision.object.boot_id.words[0]);
    digest = mix(digest, decision.object.boot_id.words[1]);
    digest = mix(digest, decision.object.object_id);
    digest = mix(digest, decision.object.generation as u64);
    digest = mix(digest, decision.subject_domain.0 as u64);
    digest = mix(digest, decision.object_domain.0 as u64);
    digest = mix(digest, decision.effect as u64);
    digest = mix(digest, decision.allowed as u64);
    if let Some(denial) = decision.denial {
        digest = mix(digest, 0x100 + denial as u64);
    }
    digest
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::BootId;

    const SOURCE: PolicySource = PolicySource {
        authority_id: POLICY_AUTHORITY_JASPER,
        version: 1,
    };

    struct TestVerifier;
    impl PolicySignatureVerifier for TestVerifier {
        fn verify(
            &self,
            source: PolicySource,
            digest: PolicyDigest,
            signature: PolicySignature,
        ) -> bool {
            source.authority_id != 0
                && digest.0 != [0; 32]
                && signature.0 == [0x33; 64]
        }
    }

    fn package(version: u32) -> MacPolicyPackage {
        let source = PolicySource {
            authority_id: POLICY_AUTHORITY_JASPER,
            version,
        };
        let mut package = MacPolicyPackage::empty(source);
        package
            .push(MacRule::new(
                SecurityDomain::USER,
                SecurityDomain::USER,
                &[
                    MacEffect::Observe,
                    MacEffect::Read,
                    MacEffect::Write,
                    MacEffect::Control,
                    MacEffect::Share,
                ],
                &[
                    IdentityClass::KernelObject,
                    IdentityClass::Process,
                    IdentityClass::Task,
                    IdentityClass::Memory,
                    IdentityClass::Device,
                    IdentityClass::Vcpu,
                    IdentityClass::Service,
                    IdentityClass::Module,
                    IdentityClass::Bootstrap,
                ],
            ))
            .unwrap();
        package.seal_digest();
        package.signature = PolicySignature([0x33; 64]);
        package
    }

    fn engine() -> MacEngine {
        let mut engine = MacEngine::new(PolicySlot::deny_all(SOURCE));
        let policy = MacPolicy::compile_verified(package(1), SOURCE, &TestVerifier).unwrap();
        engine.replace_policy(policy).unwrap();
        engine
    }

    fn subject() -> SubjectLabel {
        SubjectLabel::from_label(MacLabel::for_class(IdentityClass::Process))
    }

    fn object() -> MacLabel {
        MacLabel::for_class(IdentityClass::Memory)
    }

    fn subject_id() -> ObjectIdentity {
        ObjectIdentity {
            boot_id: BootId::from_words([7, 11]),
            class: IdentityClass::Process,
            object_id: 17,
            generation: 0,
        }
    }

    fn object_id() -> ObjectIdentity {
        ObjectIdentity {
            boot_id: BootId::from_words([7, 11]),
            class: IdentityClass::Memory,
            object_id: 23,
            generation: 1,
        }
    }

    #[test]
    fn deny_all_is_the_initial_state() {
        let mut empty = MacEngine::new(PolicySlot::deny_all(SOURCE));
        assert_eq!(
            empty.authorize(subject_id(), subject(), object_id(), object(), MacEffect::Read),
            Err(MacDenial::NoRule)
        );
        assert_eq!(empty.audit_pending(), 1);
    }

    #[test]
    fn policy_allows_same_domain_read_and_write() {
        let mut engine = engine();
        assert!(engine
            .authorize(subject_id(), subject(), object_id(), object(), MacEffect::Read)
            .is_ok());
        assert!(engine
            .authorize(subject_id(), subject(), object_id(), object(), MacEffect::Write)
            .is_ok());
    }

    #[test]
    fn same_domain_rule_does_not_imply_cross_domain_authority() {
        let mut engine = engine();
        let mut system = object();
        system.domain = SecurityDomain::SYSTEM;
        assert_eq!(
            engine.authorize(subject_id(), subject(), object_id(), system, MacEffect::Read),
            Err(MacDenial::NoRule)
        );
    }

    #[test]
    fn secrecy_blocks_read_up_and_write_down() {
        let mut engine = engine();
        let secret = MacLabel::new(
            SecurityDomain::USER,
            Secrecy::Secret,
            Integrity::Managed,
            class_bit(IdentityClass::Memory),
        );
        assert_eq!(
            engine.authorize(subject_id(), subject(), object_id(), secret, MacEffect::Read),
            Err(MacDenial::SecrecyDenied)
        );
        let mut internal_subject = subject();
        internal_subject.label.secrecy = Secrecy::Internal as u8;
        let mut public_object = object();
        public_object.secrecy = Secrecy::Public as u8;
        assert_eq!(
            engine.authorize(
                subject_id(),
                internal_subject,
                object_id(),
                public_object,
                MacEffect::Write,
            ),
            Err(MacDenial::SecrecyDenied)
        );
    }

    #[test]
    fn integrity_blocks_untrusted_control_of_trusted_object() {
        let mut engine = engine();
        let mut untrusted = subject();
        untrusted.label.integrity = Integrity::Untrusted as u8;
        let trusted = MacLabel::new(
            SecurityDomain::USER,
            Secrecy::Internal,
            Integrity::Trusted,
            class_bit(IdentityClass::Memory),
        );
        assert_eq!(
            engine.authorize(
                subject_id(),
                untrusted,
                object_id(),
                trusted,
                MacEffect::Control,
            ),
            Err(MacDenial::IntegrityDenied)
        );
    }

    #[test]
    fn class_clearance_is_required() {
        let mut engine = engine();
        let mut subject = subject();
        subject.allowed_classes = class_bit(IdentityClass::Process);
        assert_eq!(
            engine.authorize(subject_id(), subject, object_id(), object(), MacEffect::Read),
            Err(MacDenial::ClassDenied)
        );
    }

    #[test]
    fn malformed_labels_and_policy_fail_closed() {
        let mut engine = engine();
        let mut bad_subject = subject();
        bad_subject.label.version = 2;
        assert_eq!(
            engine.authorize(
                subject_id(),
                bad_subject,
                object_id(),
                object(),
                MacEffect::Read,
            ),
            Err(MacDenial::InvalidSubjectLabel)
        );
        let mut bad_object = object();
        bad_object.object_classes = 0;
        assert_eq!(
            engine.authorize(
                subject_id(),
                subject(),
                object_id(),
                bad_object,
                MacEffect::Read,
            ),
            Err(MacDenial::InvalidObjectLabel)
        );
    }

    #[test]
    fn policy_digest_and_signature_are_checked_before_use() {
        let mut bad_digest = package(1);
        bad_digest.digest.0[0] ^= 1;
        assert_eq!(
            MacPolicy::compile_verified(bad_digest, SOURCE, &TestVerifier),
            Err(MacDenial::InvalidPolicy)
        );
        let mut bad_signature = package(1);
        bad_signature.signature = PolicySignature([0; 64]);
        assert_eq!(
            MacPolicy::compile_verified(bad_signature, SOURCE, &TestVerifier),
            Err(MacDenial::InvalidSignature)
        );
    }

    #[test]
    fn reload_is_atomic_and_rejects_stale_or_wrong_authority() {
        let mut engine = engine();
        let old_epoch = engine.epoch();
        let stale = MacPolicy::compile_verified(package(1), SOURCE, &TestVerifier).unwrap();
        assert_eq!(engine.replace_policy(stale), Err(MacDenial::StalePolicy));
        assert_eq!(engine.epoch(), old_epoch);

        let other_source = PolicySource {
            authority_id: POLICY_AUTHORITY_JASPER + 1,
            version: 2,
        };
        let mut other_package = package(2);
        other_package.source = other_source;
        other_package.seal_digest();
        assert_eq!(other_package.source, other_source);
        assert_eq!(other_package.digest, other_package.content_digest());
        assert!(other_package.canonical_valid());
        let other =
            MacPolicy::compile_verified(other_package, other_source, &TestVerifier).unwrap();
        assert_eq!(
            engine.replace_policy(other),
            Err(MacDenial::PolicyAuthority)
        );
        assert_eq!(engine.epoch(), old_epoch);

        let next_source = PolicySource {
            authority_id: POLICY_AUTHORITY_JASPER,
            version: 2,
        };
        let mut next_package = package(2);
        next_package.source = next_source;
        next_package.seal_digest();
        let next =
            MacPolicy::compile_verified(next_package, next_source, &TestVerifier).unwrap();
        let installed = engine.replace_policy(next).unwrap();
        assert_eq!(installed.epoch, old_epoch + 1);
        assert_eq!(engine.epoch(), old_epoch + 1);
    }

    #[test]
    fn allow_and_deny_are_both_audited_in_sequence() {
        let mut engine = engine();
        engine
            .authorize(subject_id(), subject(), object_id(), object(), MacEffect::Read)
            .unwrap();
        let mut system = object();
        system.domain = SecurityDomain::SYSTEM;
        assert_eq!(
            engine
            .authorize(
                subject_id(),
                subject(),
                object_id(),
                system,
                MacEffect::Control,
            ),
            Err(MacDenial::NoRule)
        );
        let first = engine.drain_audit().unwrap();
        let second = engine.drain_audit().unwrap();
        assert_eq!(first.sequence, 1);
        assert_eq!(second.sequence, 2);
        assert!(first.allowed);
        assert!(!second.allowed);
        assert_eq!(second.denial, Some(MacDenial::NoRule));
        assert!(first.digest != second.digest);
    }

    #[test]
    fn full_audit_queue_fails_closed_without_overwriting() {
        let mut engine = MacEngine::new(PolicySlot::deny_all(SOURCE));
        for _ in 0..MAX_AUDIT_EVENTS {
            assert_eq!(
                engine.authorize(
                    subject_id(),
                    subject(),
                    object_id(),
                    object(),
                    MacEffect::Read,
                ),
                Err(MacDenial::NoRule)
            );
        }
        assert_eq!(
            engine.authorize(
                subject_id(),
                subject(),
                object_id(),
                object(),
                MacEffect::Read,
            ),
            Err(MacDenial::AuditFull)
        );
        assert_eq!(engine.audit_pending(), MAX_AUDIT_EVENTS);
        assert_eq!(engine.audit_overflow_attempts(), 1);
        assert!(engine.drain_audit().is_some());
        assert!(engine
            .authorize(
                subject_id(),
                subject(),
                object_id(),
                object(),
                MacEffect::Read,
            )
            .is_err());
    }

    #[test]
    fn effects_metadata_maps_to_mac_effects() {
        assert_eq!(MacEffect::from_effects(Effects::None), MacEffect::Read);
        assert_eq!(MacEffect::from_effects(Effects::Read), MacEffect::Read);
        assert_eq!(MacEffect::from_effects(Effects::Write), MacEffect::Write);
        assert_eq!(
            MacEffect::from_effects(Effects::Irreversible),
            MacEffect::Control
        );
    }
}
