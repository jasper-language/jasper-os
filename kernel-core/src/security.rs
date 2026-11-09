//! SEC-1 identity and metadata substrate.
//!
//! These records are internal kernel metadata and are not part of the public
//! `system.*` ABI. Identity is attached to object-table entries, so copying or
//! transferring a handle cannot create a second authorization root.

use crate::objtable::ObjId;

pub const SECURITY_CONTEXT_FORMAT_VERSION: u16 = 1;

/// Opaque boot identity. It is stable for one kernel boot and is never a
/// secret or a replacement for cryptographic randomness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BootId {
    pub words: [u64; 2],
}

impl BootId {
    pub const ZERO: Self = Self { words: [0, 0] };

    pub const fn from_words(words: [u64; 2]) -> Self {
        Self { words }
    }

    pub const fn is_valid(self) -> bool {
        self.words[0] != 0 || self.words[1] != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum IdentityClass {
    KernelObject = 1,
    Process = 2,
    Task = 3,
    Memory = 4,
    Device = 5,
    Vcpu = 6,
    Service = 7,
    Module = 8,
    Bootstrap = 9,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MeasurementState {
    Unavailable = 0,
    Present = 1,
}

/// Stable installation identity plus a separately tracked content measurement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApplicationIdentity {
    pub stable_id: u64,
    pub generation: u32,
    pub measurement_state: MeasurementState,
    pub measurement: [u8; 32],
}

impl ApplicationIdentity {
    /// Migration form for the existing kernel-stamped 32-bit application id.
    pub const fn migrated(stable_id: u64) -> Self {
        Self {
            stable_id,
            generation: 1,
            measurement_state: MeasurementState::Unavailable,
            measurement: [0; 32],
        }
    }

    pub const fn measured(stable_id: u64, generation: u32, measurement: [u8; 32]) -> Self {
        Self {
            stable_id,
            generation,
            measurement_state: MeasurementState::Present,
            measurement,
        }
    }

    pub const fn is_measured(self) -> bool {
        matches!(self.measurement_state, MeasurementState::Present)
    }

    pub const fn is_valid(self) -> bool {
        self.stable_id != 0 && self.generation != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectIdentity {
    pub boot_id: BootId,
    pub class: IdentityClass,
    pub object_id: u64,
    pub generation: u32,
}

impl ObjectIdentity {
    pub fn matches(self, id: ObjId) -> bool {
        self.object_id == id.raw() && self.generation == id.generation()
    }
}

/// Execution principal derived from a process, task or service object. The
/// application identity, when present, remains a separate install/measurement
/// fact and is never replaced by a PID or service name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubjectIdentity {
    pub object: ObjectIdentity,
    pub application: Option<ApplicationIdentity>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MetadataState {
    Active = 1,
    LegacyBootstrap = 2,
}

/// Versioned policy-context carrier. SEC-1 defines the fixed, bounded record;
/// policy installation and evaluation remain SEC-2/SEC-3 work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct PolicyContext {
    pub format_version: u16,
    pub reserved: u16,
    pub policy_epoch: u64,
    pub revocation_generation: u32,
    pub reserved2: u32,
}

impl PolicyContext {
    pub const V1_UNCONFIGURED: Self = Self {
        format_version: 1,
        reserved: 0,
        policy_epoch: 0,
        revocation_generation: 0,
        reserved2: 0,
    };

    pub const fn is_supported(self) -> bool {
        self.format_version == 1 && self.reserved == 0 && self.reserved2 == 0
    }
}

/// Versioned audit-context carrier. It reserves no audit capacity and does not
/// claim that the debug trace is a reliable audit log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct AuditContext {
    pub format_version: u16,
    pub reserved: u16,
    pub audit_epoch: u64,
    pub event_generation: u32,
    pub reserved2: u32,
}

impl AuditContext {
    pub const V1_UNCONFIGURED: Self = Self {
        format_version: 1,
        reserved: 0,
        audit_epoch: 0,
        event_generation: 0,
        reserved2: 0,
    };

    pub const fn is_supported(self) -> bool {
        self.format_version == 1 && self.reserved == 0 && self.reserved2 == 0
    }
}

/// Internal security context attached to one object-table entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecurityContext {
    pub format_version: u16,
    pub reserved: u16,
    pub object: ObjectIdentity,
    pub application: Option<ApplicationIdentity>,
    pub state: MetadataState,
}

impl SecurityContext {
    pub const fn new(
        boot_id: BootId,
        class: IdentityClass,
        id: ObjId,
        application: Option<ApplicationIdentity>,
        state: MetadataState,
    ) -> Self {
        Self {
            format_version: SECURITY_CONTEXT_FORMAT_VERSION,
            reserved: 0,
            object: ObjectIdentity {
                boot_id,
                class,
                object_id: id.raw(),
                generation: id.generation(),
            },
            application,
            state,
        }
    }

    pub const fn legacy() -> Self {
        Self {
            format_version: 0,
            reserved: 0,
            object: ObjectIdentity {
                boot_id: BootId::ZERO,
                class: IdentityClass::Bootstrap,
                object_id: 0,
                generation: 0,
            },
            application: None,
            state: MetadataState::LegacyBootstrap,
        }
    }

    /// Bind an application identity once. Repeating the same binding is
    /// idempotent; replacing it is refused without changing the object.
    pub fn bind_application(
        &mut self,
        application: ApplicationIdentity,
    ) -> Result<(), SecurityError> {
        self.require_active()?;
        if !application.is_valid() {
            return Err(SecurityError::InvalidApplication);
        }
        match self.application {
            None => {
                self.application = Some(application);
                Ok(())
            }
            Some(current) if current == application => Ok(()),
            Some(_) => Err(SecurityError::AlreadyBound),
        }
    }

    /// SEC-1 does not yet enforce MAC or capabilities. It requires active
    /// identity metadata before sensitive effects can later opt into SEC-2/3.
    pub fn require_active(self) -> Result<Self, SecurityError> {
        if self.state != MetadataState::Active
            || self.format_version != SECURITY_CONTEXT_FORMAT_VERSION
            || self.reserved != 0
            || self.object.object_id == 0
            || self.object.class == IdentityClass::Bootstrap
            || !self.object.boot_id.is_valid()
        {
            return Err(SecurityError::MissingMetadata);
        }
        Ok(self)
    }

    pub fn subject_identity(self) -> Option<SubjectIdentity> {
        matches!(
            self.object.class,
            IdentityClass::Process | IdentityClass::Task | IdentityClass::Service
        )
        .then_some(SubjectIdentity {
            object: self.object,
            application: self.application,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityError {
    MissingMetadata,
    AlreadyBound,
    InvalidApplication,
}

impl SecurityError {
    pub const fn name(self) -> &'static str {
        match self {
            SecurityError::MissingMetadata => "system.security.error.metadata_missing",
            SecurityError::AlreadyBound => "system.security.error.identity_already_bound",
            SecurityError::InvalidApplication => "system.security.error.invalid_application",
        }
    }
}

/// Seed used by object-table insertion to construct a complete identity after
/// the slot and generation are known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecuritySeed {
    pub boot_id: BootId,
    pub class: IdentityClass,
    pub application: Option<ApplicationIdentity>,
    pub state: MetadataState,
}

impl SecuritySeed {
    pub const fn active(boot_id: BootId, class: IdentityClass) -> Self {
        Self {
            boot_id,
            class,
            application: None,
            state: MetadataState::Active,
        }
    }

    pub const fn with_application(mut self, application: Option<ApplicationIdentity>) -> Self {
        self.application = application;
        self
    }

    pub const fn legacy() -> Self {
        Self {
            boot_id: BootId::ZERO,
            class: IdentityClass::Bootstrap,
            application: None,
            state: MetadataState::LegacyBootstrap,
        }
    }
}

/// Typed module identity used by the static assembly/service layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModuleIdentity {
    pub boot_id: BootId,
    pub name_hash: u64,
    pub version_hash: u64,
    pub generation: u32,
}

impl ModuleIdentity {
    pub fn from_name_version(boot_id: BootId, name: &str, version: &str, generation: u32) -> Self {
        Self {
            boot_id,
            name_hash: fnv1a(name.as_bytes()),
            version_hash: fnv1a(version.as_bytes()),
            generation,
        }
    }
}

const fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u64;
        hash = hash.wrapping_mul(0x100_0000_01b3);
        i += 1;
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boot() -> BootId {
        BootId::from_words([0x1234, 0x5678])
    }

    #[test]
    fn object_identity_tracks_raw_id_and_generation() {
        let id = ObjId::from_raw((9u64 << 32) | 7).unwrap();
        let context = SecurityContext::new(
            boot(),
            IdentityClass::Process,
            id,
            None,
            MetadataState::Active,
        );
        assert!(context.object.matches(id));
        assert_eq!(context.object.object_id, id.raw());
        assert_eq!(context.object.generation, id.generation());
        let subject = context.subject_identity().unwrap();
        assert_eq!(subject.object, context.object);
        assert!(subject.application.is_none());
        assert_eq!(context.require_active(), Ok(context));
    }

    #[test]
    fn generation_zero_is_a_valid_first_object_generation() {
        let id = ObjId::from_raw(7).unwrap();
        assert_eq!(id.generation(), 0);
        let context = SecurityContext::new(
            boot(),
            IdentityClass::Process,
            id,
            None,
            MetadataState::Active,
        );
        assert!(context.object.matches(id));
        assert_eq!(context.require_active(), Ok(context));
    }

    #[test]
    fn application_binding_is_one_way_and_measurement_is_distinct() {
        let id = ObjId::from_raw((1u64 << 32) | 1).unwrap();
        let mut context = SecurityContext::new(
            boot(),
            IdentityClass::Process,
            id,
            None,
            MetadataState::Active,
        );
        let legacy = ApplicationIdentity::migrated(0x5157);
        assert_eq!(context.bind_application(legacy), Ok(()));
        assert!(!context.application.unwrap().is_measured());
        assert_eq!(context.bind_application(legacy), Ok(()));
        assert_eq!(
            context.bind_application(ApplicationIdentity::migrated(0x9999)),
            Err(SecurityError::AlreadyBound)
        );
        let measured = ApplicationIdentity::measured(0x5157, 2, [0xA5; 32]);
        assert!(measured.is_measured());
        assert_ne!(measured, legacy);
        let mut fresh = SecurityContext::new(
            boot(),
            IdentityClass::Process,
            id,
            None,
            MetadataState::Active,
        );
        assert_eq!(
            fresh.bind_application(ApplicationIdentity::migrated(0)),
            Err(SecurityError::InvalidApplication)
        );
        assert_eq!(
            fresh.bind_application(ApplicationIdentity::measured(7, 0, [0; 32])),
            Err(SecurityError::InvalidApplication)
        );
        assert!(fresh.application.is_none());
    }

    #[test]
    fn legacy_and_malformed_metadata_fail_closed() {
        let legacy = SecurityContext::legacy();
        assert_eq!(legacy.require_active(), Err(SecurityError::MissingMetadata));
        let mut bad = legacy;
        bad.object.boot_id = boot();
        bad.state = MetadataState::Active;
        assert_eq!(bad.require_active(), Err(SecurityError::MissingMetadata));
        bad.format_version = SECURITY_CONTEXT_FORMAT_VERSION;
        bad.object.object_id = 1;
        bad.object.generation = 1;
        bad.object.class = IdentityClass::Process;
        assert!(bad.require_active().is_ok());
        bad.format_version += 1;
        assert_eq!(bad.require_active(), Err(SecurityError::MissingMetadata));
        bad.format_version = SECURITY_CONTEXT_FORMAT_VERSION;
        bad.reserved = 1;
        assert_eq!(bad.require_active(), Err(SecurityError::MissingMetadata));
        let mut legacy_bind = legacy;
        assert_eq!(
            legacy_bind.bind_application(ApplicationIdentity::migrated(7)),
            Err(SecurityError::MissingMetadata)
        );
        assert!(legacy_bind.application.is_none());
    }

    #[test]
    fn module_identity_separates_name_and_version() {
        let a = ModuleIdentity::from_name_version(boot(), "core", "1.0.0", 1);
        let b = ModuleIdentity::from_name_version(boot(), "core", "1.0.1", 1);
        let c = ModuleIdentity::from_name_version(boot(), "memory", "1.0.0", 1);
        assert_eq!(a.name_hash, b.name_hash);
        assert_ne!(a.version_hash, b.version_hash);
        assert_ne!(a.name_hash, c.name_hash);
    }

    #[test]
    fn policy_and_audit_carriers_reject_unknown_layouts() {
        let policy = PolicyContext::V1_UNCONFIGURED;
        assert!(policy.is_supported());
        let mut unknown = policy;
        unknown.format_version = 2;
        assert!(!unknown.is_supported());

        let audit = AuditContext::V1_UNCONFIGURED;
        assert!(audit.is_supported());
        let mut corrupt = audit;
        corrupt.reserved = 1;
        assert!(!corrupt.is_supported());
    }
}
