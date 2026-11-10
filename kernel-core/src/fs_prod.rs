//! Security-gated production file service.
//!
//! The ext4/VFS backend owns bytes and namespace state. This layer owns file
//! object security metadata and must authorize an effect before the backend is
//! called. No path string is an authorization token.

use crate::fs::PersistentIdentity;
use crate::ifc::{FlowError, FlowLabel, FlowPolicy, PURPOSE_SYSTEM};
use crate::mac::{MacDenial, MacEffect, MacLabel, MacPolicy, SubjectLabel};
use crate::security::IdentityClass;

pub const MAX_FILES: usize = 64;
pub const MAX_AUDIT: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileAccess {
    Read,
    Write,
    Control,
}

impl FileAccess {
    const fn mac_effect(self) -> MacEffect {
        match self {
            Self::Read => MacEffect::Read,
            Self::Write => MacEffect::Write,
            Self::Control => MacEffect::Control,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileSecurityError {
    InvalidIdentity,
    DuplicateFile,
    Capacity,
    Revoked,
    StaleGeneration,
    Mac(MacDenial),
    Flow(FlowError),
    Quota,
    AuditFull,
}

impl FileSecurityError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidIdentity => "system.fs.security.invalid_identity",
            Self::DuplicateFile => "system.fs.security.duplicate_file",
            Self::Capacity => "system.fs.security.capacity",
            Self::Revoked => "system.fs.security.revoked",
            Self::StaleGeneration => "system.fs.security.stale_generation",
            Self::Mac(error) => error.name(),
            Self::Flow(error) => flow_name(error),
            Self::Quota => "system.fs.security.quota",
            Self::AuditFull => "system.fs.security.audit_full",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileSecurityLabel {
    pub mac: MacLabel,
    pub flow: FlowLabel,
    pub flow_policy: FlowPolicy,
    pub generation: u32,
    pub revoked: bool,
}

impl FileSecurityLabel {
    pub fn standard(secrecy: crate::mac::Secrecy) -> Self {
        Self {
            mac: MacLabel::new(
                crate::security::SecurityDomain::USER,
                secrecy,
                crate::mac::Integrity::Managed,
                crate::mac::class_bit(IdentityClass::KernelObject),
            ),
            flow: FlowLabel::for_secrecy(secrecy),
            flow_policy: FlowPolicy::for_clearance(secrecy),
            generation: 1,
            revoked: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileQuota {
    pub operations: u64,
    pub bytes: u64,
    pub open_handles: u32,
    pub max_operations: u64,
    pub max_bytes: u64,
    pub max_open_handles: u32,
}

impl FileQuota {
    pub const fn new(max_operations: u64, max_bytes: u64, max_handles: u32) -> Self {
        Self {
            operations: 0,
            bytes: 0,
            open_handles: 0,
            max_operations,
            max_bytes,
            max_open_handles: max_handles,
        }
    }

    fn reserve(&mut self, access: FileAccess, bytes: u64) -> Result<(), FileSecurityError> {
        let operations = self
            .operations
            .checked_add(1)
            .ok_or(FileSecurityError::Quota)?;
        let total_bytes = if access == FileAccess::Write {
            self.bytes.checked_add(bytes).ok_or(FileSecurityError::Quota)?
        } else {
            self.bytes
        };
        if operations > self.max_operations || total_bytes > self.max_bytes {
            return Err(FileSecurityError::Quota);
        }
        self.operations = operations;
        self.bytes = total_bytes;
        Ok(())
    }

    pub fn open(&mut self) -> Result<(), FileSecurityError> {
        let next = self
            .open_handles
            .checked_add(1)
            .ok_or(FileSecurityError::Quota)?;
        if next > self.max_open_handles {
            return Err(FileSecurityError::Quota);
        }
        self.open_handles = next;
        Ok(())
    }

    pub fn close(&mut self) -> Result<(), FileSecurityError> {
        self.open_handles = self
            .open_handles
            .checked_sub(1)
            .ok_or(FileSecurityError::Quota)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileAudit {
    pub sequence: u64,
    pub identity: PersistentIdentity,
    pub access: FileAccess,
    pub allowed: bool,
    pub denial: Option<FileSecurityError>,
    pub mac_epoch: u64,
    pub flow_digest: u64,
}

#[derive(Clone, Copy)]
struct FileRecord {
    identity: PersistentIdentity,
    label: FileSecurityLabel,
}

pub struct ProductionFileGate<const N: usize = MAX_FILES, const A: usize = MAX_AUDIT> {
    policy: MacPolicy,
    files: [Option<FileRecord>; N],
    audit: [Option<FileAudit>; A],
    audit_next: usize,
    audit_len: usize,
    sequence: u64,
    quota: FileQuota,
}

impl<const N: usize, const A: usize> ProductionFileGate<N, A> {
    pub fn new(policy: MacPolicy, quota: FileQuota) -> Self {
        Self {
            policy,
            files: [None; N],
            audit: [None; A],
            audit_next: 0,
            audit_len: 0,
            sequence: 0,
            quota,
        }
    }

    pub fn register(
        &mut self,
        identity: PersistentIdentity,
        label: FileSecurityLabel,
    ) -> Result<(), FileSecurityError> {
        if !identity.is_valid() || label.generation == 0 {
            return Err(FileSecurityError::InvalidIdentity);
        }
        if self
            .files
            .iter()
            .flatten()
            .any(|record| record.identity == identity)
        {
            return Err(FileSecurityError::DuplicateFile);
        }
        let slot = self
            .files
            .iter()
            .position(Option::is_none)
            .ok_or(FileSecurityError::Capacity)?;
        self.files[slot] = Some(FileRecord { identity, label });
        Ok(())
    }

    pub fn revoke(
        &mut self,
        identity: PersistentIdentity,
        generation: u32,
    ) -> Result<(), FileSecurityError> {
        let record = self
            .files
            .iter_mut()
            .flatten()
            .find(|record| record.identity == identity)
            .ok_or(FileSecurityError::InvalidIdentity)?;
        if record.label.generation != generation {
            return Err(FileSecurityError::StaleGeneration);
        }
        record.label.revoked = true;
        Ok(())
    }

    pub fn label(&self, identity: PersistentIdentity) -> Option<FileSecurityLabel> {
        self.files
            .iter()
            .flatten()
            .find(|record| record.identity == identity)
            .map(|record| record.label)
    }

    pub fn authorize(
        &mut self,
        subject: SubjectLabel,
        subject_flow: FlowLabel,
        identity: PersistentIdentity,
        access: FileAccess,
        bytes: u64,
        now: u64,
    ) -> Result<FlowLabel, FileSecurityError> {
        if A == 0 || self.audit_len == A {
            return Err(FileSecurityError::AuditFull);
        }
        let slot = self.file_slot(identity)?;
        let before = self.files[slot].expect("file slot exists").label;
        let result = (|| {
            if before.revoked {
                return Err(FileSecurityError::Revoked);
            }
            self.policy
                .evaluate(subject, before.mac, access.mac_effect())
                .map_err(FileSecurityError::Mac)?;
            let next_flow = if access == FileAccess::Write {
                before
                    .flow
                    .join(subject_flow)
                    .map_err(FileSecurityError::Flow)?
            } else {
                before.flow
            };
            before
                .flow_policy
                .evaluate(next_flow, PURPOSE_SYSTEM, now)
                .map_err(FileSecurityError::Flow)?;
            self.quota.reserve(access, bytes)?;
            Ok(next_flow)
        })();
        self.record(identity, access, result.as_ref().err().copied(), before.flow);
        let next_flow = result?;
        if access == FileAccess::Write {
            self.files[slot].as_mut().expect("file slot exists").label.flow = next_flow;
        }
        Ok(next_flow)
    }

    pub fn audit_events(&self) -> impl Iterator<Item = FileAudit> + '_ {
        (0..self.audit_len).filter_map(move |index| self.audit[index])
    }

    pub const fn quota(&self) -> FileQuota {
        self.quota
    }

    pub fn close_handle(&mut self) -> Result<(), FileSecurityError> {
        self.quota.close()
    }

    fn file_slot(&self, identity: PersistentIdentity) -> Result<usize, FileSecurityError> {
        if !identity.is_valid() {
            return Err(FileSecurityError::InvalidIdentity);
        }
        self.files
            .iter()
            .position(|record| record.is_some_and(|record| record.identity == identity))
            .ok_or(FileSecurityError::InvalidIdentity)
    }

    fn record(
        &mut self,
        identity: PersistentIdentity,
        access: FileAccess,
        denial: Option<FileSecurityError>,
        flow: FlowLabel,
    ) {
        let sequence = self.sequence.saturating_add(1);
        if self.audit_len == A {
            return;
        }
        let record = FileAudit {
            sequence,
            identity,
            access,
            allowed: denial.is_none(),
            denial,
            mac_epoch: self.policy.epoch,
            flow_digest: flow.digest(),
        };
        self.audit[self.audit_next] = Some(record);
        self.audit_next = (self.audit_next + 1) % A;
        self.audit_len += 1;
        self.sequence = sequence;
    }
}

const fn flow_name(error: FlowError) -> &'static str {
    match error {
        FlowError::InvalidIdentity => "system.ifc.error.invalid_identity",
        FlowError::InvalidLabel => "system.ifc.error.invalid_label",
        FlowError::InvalidPolicy => "system.ifc.error.invalid_policy",
        FlowError::InvalidGrant => "system.ifc.error.invalid_grant",
        FlowError::Capacity => "system.ifc.error.capacity",
        FlowError::AlreadyRegistered => "system.ifc.error.already_registered",
        FlowError::NotFound => "system.ifc.error.not_found",
        FlowError::PurposeConflict => "system.ifc.error.purpose_conflict",
        FlowError::PurposeDenied => "system.ifc.error.purpose_denied",
        FlowError::DataTaint => "system.ifc.error.data_taint",
        FlowError::ControlTaint => "system.ifc.error.control_taint",
        FlowError::Endorsement => "system.ifc.error.endorsement",
        FlowError::Expired => "system.ifc.error.expired",
        FlowError::Generation => "system.ifc.error.generation",
        FlowError::AuditFull => "system.ifc.error.audit_full",
        FlowError::Denied => "system.ifc.error.denied",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mac::{
        Integrity, MacPolicyPackage, MacRule, PolicyDigest, PolicySignature,
        PolicySignatureVerifier, PolicySource, Secrecy,
    };
    use crate::security::SecurityDomain;

    const SOURCE: PolicySource = PolicySource { authority_id: 1, version: 1 };
    struct Allow;
    impl PolicySignatureVerifier for Allow {
        fn verify(
            &self,
            _: PolicySource,
            _: PolicyDigest,
            _: PolicySignature,
        ) -> bool {
            true
        }
    }

    fn policy() -> MacPolicy {
        let mut package = MacPolicyPackage::empty(SOURCE);
        package
            .push(MacRule::new(
                SecurityDomain::USER,
                SecurityDomain::USER,
                &[MacEffect::Read, MacEffect::Write, MacEffect::Control],
                &[IdentityClass::KernelObject],
            ))
            .unwrap();
        package.seal_digest();
        MacPolicy::compile_verified(package, SOURCE, &Allow).unwrap()
    }

    fn subject(secrecy: Secrecy, integrity: Integrity) -> SubjectLabel {
        SubjectLabel::from_label(MacLabel::new(
            SecurityDomain::USER,
            secrecy,
            integrity,
            crate::mac::class_bit(IdentityClass::KernelObject),
        ))
    }

    fn identity() -> PersistentIdentity {
        PersistentIdentity::new(1, 2, 0)
    }

    #[test]
    fn default_deny_mac_flow_and_revocation_fail_closed() {
        let mut gate = ProductionFileGate::<8, 32>::new(
            policy(),
            FileQuota::new(100, 4096, 4),
        );
        gate.register(identity(), FileSecurityLabel::standard(Secrecy::Sensitive))
            .unwrap();
        assert_eq!(
            gate.authorize(
                subject(Secrecy::Public, Integrity::Managed),
                FlowLabel::public(),
                identity(),
                FileAccess::Read,
                0,
                1,
            ),
            Err(FileSecurityError::Mac(MacDenial::SecrecyDenied))
        );
        let high = subject(Secrecy::Secret, Integrity::Trusted);
        assert!(gate.authorize(
            high,
            FlowLabel::for_secrecy(Secrecy::Secret),
            identity(),
            FileAccess::Read,
            0,
            1,
        ).is_ok());
        gate.revoke(identity(), 1).unwrap();
        assert_eq!(
            gate.authorize(
                high,
                FlowLabel::for_secrecy(Secrecy::Secret),
                identity(),
                FileAccess::Read,
                0,
                1,
            ),
            Err(FileSecurityError::Revoked)
        );
        assert_eq!(gate.audit_events().count(), 3);
    }

    #[test]
    fn write_joins_taint_and_quota_is_atomic() {
        let mut gate = ProductionFileGate::<8, 16>::new(
            policy(),
            FileQuota::new(2, 8, 1),
        );
        gate.register(identity(), FileSecurityLabel::standard(Secrecy::Secret))
            .unwrap();
        let label = gate
            .authorize(
                subject(Secrecy::Secret, Integrity::Trusted),
                FlowLabel::public(),
                identity(),
                FileAccess::Write,
                8,
                1,
            )
            .unwrap();
        assert!(label.data.contains(crate::ifc::TaintSet::INTERNAL));
        assert_eq!(
            gate.authorize(
                subject(Secrecy::Secret, Integrity::Trusted),
                FlowLabel::public(),
                identity(),
                FileAccess::Write,
                1,
                2,
            ),
            Err(FileSecurityError::Quota)
        );
        assert_eq!(gate.quota().operations, 1);
        assert_eq!(gate.quota().bytes, 8);
    }

    #[test]
    fn audit_exhaustion_prevents_effects() {
        let mut gate = ProductionFileGate::<4, 1>::new(
            policy(),
            FileQuota::new(10, 10, 2),
        );
        gate.register(identity(), FileSecurityLabel::standard(Secrecy::Public))
            .unwrap();
        let subject = subject(Secrecy::Public, Integrity::Managed);
        assert!(gate.authorize(
            subject,
            FlowLabel::public(),
            identity(),
            FileAccess::Read,
            0,
            1,
        ).is_ok());
        assert_eq!(
            gate.authorize(
                subject,
                FlowLabel::public(),
                identity(),
                FileAccess::Read,
                0,
                1,
            ),
            Err(FileSecurityError::AuditFull)
        );
        assert_eq!(gate.audit_events().count(), 1);
    }
}
