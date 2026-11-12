//! Bounded native package installation and authorization contract.
//!
//! This module deliberately keeps package bytes, installation registration,
//! discovery, launch authority, runtime principals, data ownership and update
//! authority separate. Logical paths and AppIDs are descriptive facts, never
//! authorization credentials.
//!
//! 原生包安装与授权契约。本模块显式分离包字节、安装登记、发现、启动授权、
//! 运行主体、数据所有权和更新权；逻辑路径与 AppID 只表达事实，不能作为权限
//! 凭证。所有表固定容量，失败路径不产生部分写入。

use crate::security_domain::DomainKey;

pub const CONTENT_BYTES: usize = 32;

/// Stable package identifier assigned by this registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackageKey {
    slot: u16,
    generation: u32,
}

impl PackageKey {
    pub const fn slot(self) -> u16 {
        self.slot
    }

    pub const fn generation(self) -> u32 {
        self.generation
    }

    pub const fn to_raw(self) -> u64 {
        ((self.generation as u64) << 16) | self.slot as u64
    }

    pub const fn from_raw(raw: u64) -> Option<Self> {
        if raw == 0 || raw >> 48 != 0 || (raw >> 16) as u32 == 0 {
            return None;
        }
        Some(Self {
            slot: raw as u16,
            generation: (raw >> 16) as u32,
        })
    }
}

/// Stable installation registration identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstallationKey {
    slot: u16,
    generation: u32,
}

impl InstallationKey {
    pub const fn to_raw(self) -> u64 {
        ((self.generation as u64) << 16) | self.slot as u64
    }

    pub const fn from_raw(raw: u64) -> Option<Self> {
        if raw == 0 || raw >> 48 != 0 || (raw >> 16) as u32 == 0 {
            return None;
        }
        Some(Self {
            slot: raw as u16,
            generation: (raw >> 16) as u32,
        })
    }
}

/// Stable grant identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantKey {
    slot: u16,
    generation: u32,
}

impl GrantKey {
    pub const fn to_raw(self) -> u64 {
        ((self.generation as u64) << 16) | self.slot as u64
    }

    pub const fn from_raw(raw: u64) -> Option<Self> {
        if raw == 0 || raw >> 48 != 0 || (raw >> 16) as u32 == 0 {
            return None;
        }
        Some(Self {
            slot: raw as u16,
            generation: (raw >> 16) as u32,
        })
    }
}

/// Stable runtime identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeKey {
    slot: u16,
    generation: u32,
}

impl RuntimeKey {
    pub const fn to_raw(self) -> u64 {
        ((self.generation as u64) << 16) | self.slot as u64
    }

    pub const fn from_raw(raw: u64) -> Option<Self> {
        if raw == 0 || raw >> 48 != 0 || (raw >> 16) as u32 == 0 {
            return None;
        }
        Some(Self {
            slot: raw as u16,
            generation: (raw >> 16) as u32,
        })
    }
}

/// Stable owned-data identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataKey {
    slot: u16,
    generation: u32,
}

impl DataKey {
    pub const fn to_raw(self) -> u64 {
        ((self.generation as u64) << 16) | self.slot as u64
    }

    pub const fn from_raw(raw: u64) -> Option<Self> {
        if raw == 0 || raw >> 48 != 0 || (raw >> 16) as u32 == 0 {
            return None;
        }
        Some(Self {
            slot: raw as u16,
            generation: (raw >> 16) as u32,
        })
    }
}

/// Installation or data ownership scope. The numeric identity is opaque.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerScope {
    System,
    Device(u64),
    User(u64),
    Group(u64),
    Tenant(u64),
    Workload(u64),
}

impl OwnerScope {
    pub const fn is_valid(self) -> bool {
        match self {
            Self::System => true,
            Self::Device(id)
            | Self::User(id)
            | Self::Group(id)
            | Self::Tenant(id)
            | Self::Workload(id) => id != 0,
        }
    }
}

/// Subject presented to package discovery, launch or update checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Subject {
    System,
    Device(u64),
    User(u64),
    Group(u64),
    Tenant(u64),
    Workload(u64),
    Service(u64),
}

impl Subject {
    pub const fn is_valid(self) -> bool {
        match self {
            Self::System => true,
            Self::Device(id)
            | Self::User(id)
            | Self::Group(id)
            | Self::Tenant(id)
            | Self::Workload(id)
            | Self::Service(id) => id != 0,
        }
    }
}

/// Borrowed subject set. Group and tenant membership is an input fact, not a
/// path-derived permission.
#[derive(Clone, Copy, Debug)]
pub struct Actor<'a> {
    pub subjects: &'a [Subject],
}

impl<'a> Actor<'a> {
    pub const fn new(subjects: &'a [Subject]) -> Self {
        Self { subjects }
    }

    fn contains(self, subject: Subject) -> bool {
        self.subjects.contains(&subject)
    }

    fn matches_scope(self, scope: OwnerScope) -> bool {
        match scope {
            OwnerScope::System => self.contains(Subject::System),
            OwnerScope::Device(id) => self.contains(Subject::Device(id)),
            OwnerScope::User(id) => self.contains(Subject::User(id)),
            OwnerScope::Group(id) => self.contains(Subject::Group(id)),
            OwnerScope::Tenant(id) => self.contains(Subject::Tenant(id)),
            OwnerScope::Workload(id) => self.contains(Subject::Workload(id)),
        }
    }
}

/// Installation source is supply-chain metadata, not trust or launch authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackageSource {
    SystemBuiltin,
    Store,
    UserImport,
    Enterprise,
    Developer,
}

/// Immutable package bytes identity. Equality is identity, not proof of signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackageSpec {
    pub app_id: u64,
    pub publisher: u64,
    pub content: [u8; CONTENT_BYTES],
    pub version: u32,
}

impl PackageSpec {
    fn valid(self) -> bool {
        self.app_id != 0
            && self.publisher != 0
            && self.version != 0
            && self.content.iter().any(|byte| *byte != 0)
    }
}

/// Update authority is a distinct subject and never implies discovery or launch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpdateAuthority {
    pub subject: Subject,
}

/// Installation registration and its non-authoritative descriptive source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstallSpec {
    pub package: PackageKey,
    pub scope: OwnerScope,
    pub source: PackageSource,
    pub update_authority: UpdateAuthority,
}

/// Permission bits carried by a grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantRights(pub u32);

impl GrantRights {
    pub const DISCOVER: Self = Self(1 << 0);
    pub const START: Self = Self(1 << 1);
    pub const SERVICE_CALL: Self = Self(1 << 2);
    pub const ALL: Self = Self(Self::DISCOVER.0 | Self::START.0 | Self::SERVICE_CALL.0);

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    fn valid(self) -> bool {
        self.0 != 0 && self.0 & !Self::ALL.0 == 0
    }
}

/// A grant may be subject-, group- or tenant-scoped and may expire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantSpec {
    pub installation: InstallationKey,
    pub subject: Subject,
    pub rights: GrantRights,
    pub expires_at: Option<u64>,
}

/// Runtime kind is independent of installation owner and data owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrincipalKind {
    User,
    Service,
    Workload,
    Sandbox,
}

/// Requested runtime principal. The actor must also prove the same subject;
/// `generation` is carried into the frozen runtime fact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrincipalSpec {
    pub kind: PrincipalKind,
    pub subject: Subject,
    pub generation: u32,
    pub domain: DomainKey,
}

impl PrincipalSpec {
    fn valid(self) -> bool {
        self.subject.is_valid()
            && self.generation != 0
            && self.domain.is_valid()
            && matches!(
                (self.kind, self.subject),
                (PrincipalKind::User, Subject::User(_))
                    | (PrincipalKind::Service, Subject::Service(_))
                    | (
                        PrincipalKind::Workload | PrincipalKind::Sandbox,
                        Subject::Workload(_)
                    )
            )
    }
}

/// Frozen principal and grant snapshot. Later revocation affects new starts only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimePrincipal {
    pub kind: PrincipalKind,
    pub subject: Subject,
    pub generation: u32,
    pub domain: DomainKey,
    pub rights: GrantRights,
}

/// Data ownership is independent of code installation and logical paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataOwnerKind {
    PrivateUser,
    SharedService,
    Tenant,
    Cache,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallError {
    InvalidPackage,
    InvalidScope,
    InvalidGrant,
    InvalidPrincipal,
    InvalidAuthority,
    StaleKey,
    Capacity,
    IdExhausted,
    Duplicate,
    Disabled,
    NotVisible,
    NotAuthorized,
    InUse,
}

impl InstallError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidPackage => "system.install.error.package",
            Self::InvalidScope => "system.install.error.scope",
            Self::InvalidGrant => "system.install.error.grant",
            Self::InvalidPrincipal => "system.install.error.principal",
            Self::InvalidAuthority => "system.install.error.authority",
            Self::StaleKey => "system.install.error.stale",
            Self::Capacity => "system.install.error.capacity",
            Self::IdExhausted => "system.install.error.ids_exhausted",
            Self::Duplicate => "system.install.error.duplicate",
            Self::Disabled => "system.install.error.disabled",
            Self::NotVisible => "system.install.error.not_visible",
            Self::NotAuthorized => "system.install.error.not_authorized",
            Self::InUse => "system.install.error.in_use",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackageSnapshot {
    pub key: PackageKey,
    pub spec: PackageSpec,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstallationSnapshot {
    pub key: InstallationKey,
    pub package: PackageKey,
    pub scope: OwnerScope,
    pub source: PackageSource,
    pub update_authority: UpdateAuthority,
    pub enabled: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantSnapshot {
    pub key: GrantKey,
    pub installation: InstallationKey,
    pub subject: Subject,
    pub rights: GrantRights,
    pub expires_at: Option<u64>,
    pub active: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeSnapshot {
    pub key: RuntimeKey,
    pub installation: InstallationKey,
    pub principal: RuntimePrincipal,
    pub started_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataSnapshot {
    pub key: DataKey,
    pub package: PackageKey,
    pub owner: Subject,
    pub kind: DataOwnerKind,
}

#[derive(Clone, Copy)]
struct PackageRecord {
    key: PackageKey,
    spec: PackageSpec,
}

#[derive(Clone, Copy)]
struct InstallationRecord {
    key: InstallationKey,
    package: PackageKey,
    scope: OwnerScope,
    source: PackageSource,
    update_authority: UpdateAuthority,
    enabled: bool,
}

#[derive(Clone, Copy)]
struct GrantRecord {
    key: GrantKey,
    installation: InstallationKey,
    subject: Subject,
    rights: GrantRights,
    expires_at: Option<u64>,
    active: bool,
}

#[derive(Clone, Copy)]
struct RuntimeRecord {
    key: RuntimeKey,
    installation: InstallationKey,
    principal: RuntimePrincipal,
    started_at: u64,
}

#[derive(Clone, Copy)]
struct DataRecord {
    key: DataKey,
    package: PackageKey,
    owner: Subject,
    kind: DataOwnerKind,
}

/// Fixed-capacity registry. Every key is generation-safe and every rejection
/// leaves package, installation, grant, runtime and data tables unchanged.
pub struct InstallModel<
    const P: usize,
    const I: usize,
    const G: usize,
    const R: usize,
    const D: usize,
> {
    packages: [Option<PackageRecord>; P],
    package_generations: [u32; P],
    installations: [Option<InstallationRecord>; I],
    installation_generations: [u32; I],
    grants: [Option<GrantRecord>; G],
    grant_generations: [u32; G],
    runtimes: [Option<RuntimeRecord>; R],
    runtime_generations: [u32; R],
    data: [Option<DataRecord>; D],
    data_generations: [u32; D],
}

impl<const P: usize, const I: usize, const G: usize, const R: usize, const D: usize>
    InstallModel<P, I, G, R, D>
{
    pub const fn new() -> Self {
        Self {
            packages: [None; P],
            package_generations: [0; P],
            installations: [None; I],
            installation_generations: [0; I],
            grants: [None; G],
            grant_generations: [0; G],
            runtimes: [None; R],
            runtime_generations: [0; R],
            data: [None; D],
            data_generations: [0; D],
        }
    }

    pub fn add_package(&mut self, spec: PackageSpec) -> Result<PackageKey, InstallError> {
        if !spec.valid() {
            return Err(InstallError::InvalidPackage);
        }
        let (slot, generation) = vacant(&self.packages, &mut self.package_generations)?;
        let key = PackageKey { slot, generation };
        self.packages[slot as usize] = Some(PackageRecord { key, spec });
        Ok(key)
    }

    pub fn package(&self, key: PackageKey) -> Result<PackageSnapshot, InstallError> {
        self.package_record(key).map(|record| PackageSnapshot {
            key,
            spec: record.spec,
        })
    }

    pub fn install(&mut self, spec: InstallSpec) -> Result<InstallationKey, InstallError> {
        if !spec.scope.is_valid() {
            return Err(InstallError::InvalidScope);
        }
        if !spec.update_authority.subject.is_valid() {
            return Err(InstallError::InvalidAuthority);
        }
        self.package_record(spec.package)?;
        if self.installations.iter().flatten().any(|installation| {
            installation.package == spec.package && installation.scope == spec.scope
        }) {
            return Err(InstallError::Duplicate);
        }
        let (slot, generation) = vacant(&self.installations, &mut self.installation_generations)?;
        let key = InstallationKey { slot, generation };
        self.installations[slot as usize] = Some(InstallationRecord {
            key,
            package: spec.package,
            scope: spec.scope,
            source: spec.source,
            update_authority: spec.update_authority,
            enabled: true,
        });
        Ok(key)
    }

    pub fn installation(&self, key: InstallationKey) -> Result<InstallationSnapshot, InstallError> {
        self.installation_record(key)
            .map(|record| InstallationSnapshot {
                key,
                package: record.package,
                scope: record.scope,
                source: record.source,
                update_authority: record.update_authority,
                enabled: record.enabled,
            })
    }

    pub fn add_grant(&mut self, spec: GrantSpec) -> Result<GrantKey, InstallError> {
        self.installation_record(spec.installation)?;
        if !spec.subject.is_valid() || !spec.rights.valid() {
            return Err(InstallError::InvalidGrant);
        }
        let (slot, generation) = vacant(&self.grants, &mut self.grant_generations)?;
        let key = GrantKey { slot, generation };
        self.grants[slot as usize] = Some(GrantRecord {
            key,
            installation: spec.installation,
            subject: spec.subject,
            rights: spec.rights,
            expires_at: spec.expires_at,
            active: true,
        });
        Ok(key)
    }

    pub fn grant(&self, key: GrantKey) -> Result<GrantSnapshot, InstallError> {
        self.grant_record(key).map(|record| GrantSnapshot {
            key,
            installation: record.installation,
            subject: record.subject,
            rights: record.rights,
            expires_at: record.expires_at,
            active: record.active,
        })
    }

    pub fn revoke_grant(&mut self, key: GrantKey) -> Result<(), InstallError> {
        let slot = self.grant_slot(key)?;
        let record = self.grants[slot].as_mut().ok_or(InstallError::StaleKey)?;
        if !record.active {
            return Err(InstallError::StaleKey);
        }
        record.active = false;
        Ok(())
    }

    /// Discovery requires both owner-scope visibility and a live DISCOVER grant.
    pub fn can_discover(&self, actor: Actor<'_>, installation: InstallationKey, now: u64) -> bool {
        self.effective_rights(actor, installation, now)
            .is_some_and(|rights| rights.contains(GrantRights::DISCOVER))
    }

    /// Launch authority is separate from discovery and update authority.
    pub fn can_start(&self, actor: Actor<'_>, installation: InstallationKey, now: u64) -> bool {
        self.effective_rights(actor, installation, now)
            .is_some_and(|rights| rights.contains(GrantRights::START))
    }

    /// Update authority never grants discovery or launch.
    pub fn can_update(&self, actor: Actor<'_>, installation: InstallationKey) -> bool {
        self.installation_record(installation)
            .is_ok_and(|record| actor.contains(record.update_authority.subject))
    }

    pub fn set_update_authority(
        &mut self,
        actor: Actor<'_>,
        installation: InstallationKey,
        authority: UpdateAuthority,
    ) -> Result<(), InstallError> {
        if !authority.subject.is_valid() {
            return Err(InstallError::InvalidAuthority);
        }
        if !self.can_update(actor, installation) {
            return Err(InstallError::NotAuthorized);
        }
        let slot = self.installation_slot(installation)?;
        self.installations[slot]
            .as_mut()
            .ok_or(InstallError::StaleKey)?
            .update_authority = authority;
        Ok(())
    }

    /// Start snapshots the principal and effective rights. Revocation after this
    /// point affects only new starts, not the running instance's authority.
    pub fn start(
        &mut self,
        actor: Actor<'_>,
        installation: InstallationKey,
        principal: PrincipalSpec,
        now: u64,
    ) -> Result<RuntimeKey, InstallError> {
        if !principal.valid() {
            return Err(InstallError::InvalidPrincipal);
        }
        if !actor.contains(principal.subject) {
            return Err(InstallError::NotAuthorized);
        }
        if !self.installation_record(installation)?.enabled {
            return Err(InstallError::Disabled);
        }
        let rights = self
            .effective_rights(actor, installation, now)
            .ok_or(InstallError::NotVisible)?;
        if !rights.contains(GrantRights::START) {
            return Err(InstallError::NotAuthorized);
        }
        let (slot, generation) = vacant(&self.runtimes, &mut self.runtime_generations)?;
        let key = RuntimeKey { slot, generation };
        self.runtimes[slot as usize] = Some(RuntimeRecord {
            key,
            installation,
            principal: RuntimePrincipal {
                kind: principal.kind,
                subject: principal.subject,
                generation: principal.generation,
                domain: principal.domain,
                rights,
            },
            started_at: now,
        });
        Ok(key)
    }

    pub fn runtime(&self, key: RuntimeKey) -> Result<RuntimeSnapshot, InstallError> {
        let slot = self.runtime_slot(key)?;
        let record = self.runtimes[slot].ok_or(InstallError::StaleKey)?;
        Ok(RuntimeSnapshot {
            key,
            installation: record.installation,
            principal: record.principal,
            started_at: record.started_at,
        })
    }

    pub fn stop_runtime(&mut self, key: RuntimeKey) -> Result<(), InstallError> {
        let slot = self.runtime_slot(key)?;
        if self.runtimes[slot].take().is_none() {
            return Err(InstallError::StaleKey);
        }
        Ok(())
    }

    /// Creates explicitly owned data. This identity survives code uninstall.
    pub fn create_data(
        &mut self,
        installation: InstallationKey,
        owner: Subject,
        kind: DataOwnerKind,
    ) -> Result<DataKey, InstallError> {
        if !owner.is_valid() {
            return Err(InstallError::InvalidScope);
        }
        let package = self.installation_record(installation)?.package;
        if self
            .data
            .iter()
            .flatten()
            .any(|data| data.package == package && data.owner == owner && data.kind == kind)
        {
            return Err(InstallError::Duplicate);
        }
        let (slot, generation) = vacant(&self.data, &mut self.data_generations)?;
        let key = DataKey { slot, generation };
        self.data[slot as usize] = Some(DataRecord {
            key,
            package,
            owner,
            kind,
        });
        Ok(key)
    }

    pub fn data(&self, key: DataKey) -> Result<DataSnapshot, InstallError> {
        let slot = self.data_slot(key)?;
        let record = self.data[slot].ok_or(InstallError::StaleKey)?;
        Ok(DataSnapshot {
            key,
            package: record.package,
            owner: record.owner,
            kind: record.kind,
        })
    }

    pub fn destroy_data(&mut self, key: DataKey) -> Result<(), InstallError> {
        let slot = self.data_slot(key)?;
        if self.data[slot].take().is_none() {
            return Err(InstallError::StaleKey);
        }
        Ok(())
    }

    /// Removes only this installation registration and its grants. Shared
    /// package bytes and independently owned data remain intact.
    pub fn uninstall(
        &mut self,
        actor: Actor<'_>,
        key: InstallationKey,
    ) -> Result<(), InstallError> {
        let slot = self.installation_slot(key)?;
        let record = self.installations[slot].ok_or(InstallError::StaleKey)?;
        let owner_allowed = actor.matches_scope(record.scope);
        let authority_allowed = actor.contains(record.update_authority.subject);
        if !owner_allowed && !authority_allowed {
            return Err(InstallError::NotAuthorized);
        }
        if self
            .runtimes
            .iter()
            .flatten()
            .any(|runtime| runtime.installation == key)
        {
            return Err(InstallError::InUse);
        }
        for grant in &mut self.grants {
            if grant.is_some_and(|grant| grant.installation == key) {
                *grant = None;
            }
        }
        self.installations[slot] = None;
        Ok(())
    }

    /// Enables/disables new discovery and starts without rewriting runtime facts.
    pub fn set_enabled(
        &mut self,
        actor: Actor<'_>,
        installation: InstallationKey,
        enabled: bool,
    ) -> Result<(), InstallError> {
        if !self.can_update(actor, installation) {
            return Err(InstallError::NotAuthorized);
        }
        let slot = self.installation_slot(installation)?;
        self.installations[slot]
            .as_mut()
            .ok_or(InstallError::StaleKey)?
            .enabled = enabled;
        Ok(())
    }

    /// Package deletion is blocked while any installation or owned data remains.
    pub fn destroy_package(&mut self, key: PackageKey) -> Result<(), InstallError> {
        let slot = self.package_slot(key)?;
        if self
            .installations
            .iter()
            .flatten()
            .any(|installation| installation.package == key)
            || self.data.iter().flatten().any(|data| data.package == key)
        {
            return Err(InstallError::InUse);
        }
        self.packages[slot] = None;
        Ok(())
    }

    pub fn installation_count_for(&self, package: PackageKey) -> usize {
        self.installations
            .iter()
            .flatten()
            .filter(|installation| installation.package == package)
            .count()
    }

    fn effective_rights(
        &self,
        actor: Actor<'_>,
        installation: InstallationKey,
        now: u64,
    ) -> Option<GrantRights> {
        let record = self.installation_record(installation).ok()?;
        if !record.enabled || !actor.matches_scope(record.scope) {
            return None;
        }
        let mut rights = GrantRights(0);
        for grant in self.grants.iter().flatten().filter(|grant| {
            grant.installation == installation
                && grant.active
                && actor.contains(grant.subject)
                && grant.expires_at.is_none_or(|deadline| now < deadline)
        }) {
            rights = rights.union(grant.rights);
        }
        (rights.0 != 0).then_some(rights)
    }

    fn package_record(&self, key: PackageKey) -> Result<PackageRecord, InstallError> {
        self.packages
            .get(key.slot as usize)
            .and_then(|record| *record)
            .filter(|record| record.key == key)
            .ok_or(InstallError::StaleKey)
    }

    fn installation_record(
        &self,
        key: InstallationKey,
    ) -> Result<InstallationRecord, InstallError> {
        self.installations
            .get(key.slot as usize)
            .and_then(|record| *record)
            .filter(|record| record.key == key)
            .ok_or(InstallError::StaleKey)
    }

    fn grant_record(&self, key: GrantKey) -> Result<GrantRecord, InstallError> {
        self.grants
            .get(key.slot as usize)
            .and_then(|record| *record)
            .filter(|record| record.key == key)
            .ok_or(InstallError::StaleKey)
    }

    fn package_slot(&self, key: PackageKey) -> Result<usize, InstallError> {
        self.package_record(key).map(|_| key.slot as usize)
    }

    fn installation_slot(&self, key: InstallationKey) -> Result<usize, InstallError> {
        self.installation_record(key).map(|_| key.slot as usize)
    }

    fn grant_slot(&self, key: GrantKey) -> Result<usize, InstallError> {
        self.grant_record(key).map(|_| key.slot as usize)
    }

    fn runtime_slot(&self, key: RuntimeKey) -> Result<usize, InstallError> {
        self.runtimes
            .get(key.slot as usize)
            .and_then(|record| *record)
            .filter(|record| record.key == key)
            .map(|_| key.slot as usize)
            .ok_or(InstallError::StaleKey)
    }

    fn data_slot(&self, key: DataKey) -> Result<usize, InstallError> {
        self.data
            .get(key.slot as usize)
            .and_then(|record| *record)
            .filter(|record| record.key == key)
            .map(|_| key.slot as usize)
            .ok_or(InstallError::StaleKey)
    }
}

impl<const P: usize, const I: usize, const G: usize, const R: usize, const D: usize> Default
    for InstallModel<P, I, G, R, D>
{
    fn default() -> Self {
        Self::new()
    }
}

fn vacant<T>(slots: &[Option<T>], generations: &mut [u32]) -> Result<(u16, u32), InstallError> {
    let slot = slots
        .iter()
        .position(Option::is_none)
        .ok_or(InstallError::Capacity)?;
    if slot > u16::MAX as usize {
        return Err(InstallError::Capacity);
    }
    let generation = generations[slot]
        .checked_add(1)
        .ok_or(InstallError::IdExhausted)?;
    generations[slot] = generation;
    Ok((slot as u16, generation))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(seed: u8) -> [u8; CONTENT_BYTES] {
        [seed; CONTENT_BYTES]
    }

    fn package_spec(seed: u8) -> PackageSpec {
        PackageSpec {
            app_id: 0x1000 + u64::from(seed),
            publisher: 7,
            content: digest(seed),
            version: 1,
        }
    }

    fn scope_user(id: u64) -> OwnerScope {
        OwnerScope::User(id)
    }

    fn authority_group(id: u64) -> UpdateAuthority {
        UpdateAuthority {
            subject: Subject::Group(id),
        }
    }

    fn principal(user: u64) -> PrincipalSpec {
        PrincipalSpec {
            kind: PrincipalKind::User,
            subject: Subject::User(user),
            generation: 1,
            domain: DomainKey {
                id: 1,
                generation: 1,
            },
        }
    }

    fn install_for<
        const P: usize,
        const I: usize,
        const G: usize,
        const R: usize,
        const D: usize,
    >(
        model: &mut InstallModel<P, I, G, R, D>,
        package: PackageKey,
        user: u64,
        authority: UpdateAuthority,
    ) -> InstallationKey {
        model
            .install(InstallSpec {
                package,
                scope: scope_user(user),
                source: PackageSource::Store,
                update_authority: authority,
            })
            .unwrap()
    }

    fn allow_user<
        const P: usize,
        const I: usize,
        const G: usize,
        const R: usize,
        const D: usize,
    >(
        model: &mut InstallModel<P, I, G, R, D>,
        installation: InstallationKey,
        user: u64,
    ) -> GrantKey {
        model
            .add_grant(GrantSpec {
                installation,
                subject: Subject::User(user),
                rights: GrantRights::ALL,
                expires_at: None,
            })
            .unwrap()
    }

    #[test]
    fn install_identity_and_duplicate_are_failure_atomic() {
        let mut model = InstallModel::<1, 2, 1, 1, 1>::new();
        let package = model.add_package(package_spec(1)).unwrap();
        let installation = model
            .install(InstallSpec {
                package,
                scope: scope_user(1),
                source: PackageSource::UserImport,
                update_authority: UpdateAuthority {
                    subject: Subject::User(1),
                },
            })
            .unwrap();
        assert_eq!(
            model.install(InstallSpec {
                package,
                scope: scope_user(1),
                source: PackageSource::Store,
                update_authority: UpdateAuthority {
                    subject: Subject::User(1),
                },
            }),
            Err(InstallError::Duplicate)
        );
        assert_eq!(model.installation_count_for(package), 1);
        let actor = [Subject::User(1)];
        model.uninstall(Actor::new(&actor), installation).unwrap();
        let replacement = model
            .install(InstallSpec {
                package,
                scope: scope_user(1),
                source: PackageSource::Store,
                update_authority: UpdateAuthority {
                    subject: Subject::User(1),
                },
            })
            .unwrap();
        assert_ne!(installation, replacement);
        assert_eq!(
            model.installation(installation),
            Err(InstallError::StaleKey)
        );
    }

    #[test]
    fn user_installations_are_isolated_and_package_is_shared() {
        let mut model = InstallModel::<2, 3, 3, 2, 2>::new();
        let package = model.add_package(package_spec(2)).unwrap();
        let installation_a = install_for(&mut model, package, 10, authority_group(50));
        let installation_b = install_for(&mut model, package, 20, authority_group(50));
        allow_user(&mut model, installation_a, 10);
        allow_user(&mut model, installation_b, 20);
        let actor_a = [Subject::User(10)];
        let actor_b = [Subject::User(20)];
        assert!(model.can_discover(Actor::new(&actor_a), installation_a, 0));
        assert!(!model.can_discover(Actor::new(&actor_a), installation_b, 0));
        assert!(model.can_discover(Actor::new(&actor_b), installation_b, 0));
        assert_eq!(model.installation_count_for(package), 2);
        model
            .uninstall(Actor::new(&actor_a), installation_a)
            .unwrap();
        assert_eq!(model.installation_count_for(package), 1);
        assert!(model.can_discover(Actor::new(&actor_b), installation_b, 0));
        assert_eq!(model.destroy_package(package), Err(InstallError::InUse));
    }

    #[test]
    fn group_revocation_blocks_new_start_but_not_existing_runtime() {
        let mut model = InstallModel::<2, 2, 2, 2, 2>::new();
        let package = model.add_package(package_spec(3)).unwrap();
        let installation = install_for(&mut model, package, 10, authority_group(60));
        let grant = model
            .add_grant(GrantSpec {
                installation,
                subject: Subject::Group(60),
                rights: GrantRights::ALL,
                expires_at: None,
            })
            .unwrap();
        let actor = [Subject::User(10), Subject::Group(60)];
        let runtime = model
            .start(Actor::new(&actor), installation, principal(10), 1)
            .unwrap();
        assert!(model
            .runtime(runtime)
            .unwrap()
            .principal
            .rights
            .contains(GrantRights::START));
        model.revoke_grant(grant).unwrap();
        assert!(!model.can_start(Actor::new(&actor), installation, 2));
        assert_eq!(
            model.start(Actor::new(&actor), installation, principal(10), 2),
            Err(InstallError::NotVisible)
        );
        assert_eq!(
            model.runtime(runtime).unwrap().principal.subject,
            Subject::User(10)
        );
    }

    #[test]
    fn expiry_and_disable_only_affect_new_launches() {
        let mut model = InstallModel::<2, 2, 2, 2, 2>::new();
        let package = model.add_package(package_spec(4)).unwrap();
        let authority = subject_authority(Subject::Group(70));
        let installation = install_for(&mut model, package, 10, authority);
        model
            .add_grant(GrantSpec {
                installation,
                subject: Subject::User(10),
                rights: GrantRights::ALL,
                expires_at: Some(100),
            })
            .unwrap();
        let user = [Subject::User(10)];
        let administrator = [Subject::Group(70)];
        let runtime = model
            .start(Actor::new(&user), installation, principal(10), 99)
            .unwrap();
        assert!(!model.can_start(Actor::new(&user), installation, 100));
        assert_eq!(model.runtime(runtime).unwrap().principal.generation, 1);
        model
            .set_enabled(Actor::new(&administrator), installation, false)
            .unwrap();
        assert_eq!(
            model.start(Actor::new(&user), installation, principal(10), 101),
            Err(InstallError::Disabled)
        );
        assert!(model.runtime(runtime).is_ok());
    }

    #[test]
    fn data_ownership_survives_code_uninstall() {
        let mut model = InstallModel::<2, 3, 3, 2, 4>::new();
        let package = model.add_package(package_spec(5)).unwrap();
        let installation_a = install_for(&mut model, package, 10, authority_group(80));
        let installation_b = install_for(&mut model, package, 20, authority_group(80));
        let data_a = model
            .create_data(
                installation_a,
                Subject::User(10),
                DataOwnerKind::PrivateUser,
            )
            .unwrap();
        let data_b = model
            .create_data(
                installation_b,
                Subject::User(20),
                DataOwnerKind::PrivateUser,
            )
            .unwrap();
        assert_ne!(data_a, data_b);
        let actor_a = [Subject::User(10)];
        model
            .uninstall(Actor::new(&actor_a), installation_a)
            .unwrap();
        assert_eq!(model.data(data_a).unwrap().owner, Subject::User(10));
        assert_eq!(model.data(data_b).unwrap().owner, Subject::User(20));
        assert_eq!(model.destroy_package(package), Err(InstallError::InUse));
        model.destroy_data(data_a).unwrap();
        model.destroy_data(data_b).unwrap();
        let actor_b = [Subject::User(20)];
        model
            .uninstall(Actor::new(&actor_b), installation_b)
            .unwrap();
        model.destroy_package(package).unwrap();
    }

    #[test]
    fn update_visibility_and_launch_authority_are_independent() {
        let mut model = InstallModel::<2, 2, 2, 2, 2>::new();
        let package = model.add_package(package_spec(6)).unwrap();
        let installation = install_for(&mut model, package, 10, authority_group(90));
        allow_user(&mut model, installation, 10);
        let owner = [Subject::User(10)];
        let administrator = [Subject::Group(90)];
        assert!(model.can_start(Actor::new(&owner), installation, 0));
        assert!(!model.can_update(Actor::new(&owner), installation));
        assert!(model.can_update(Actor::new(&administrator), installation));
        assert!(!model.can_discover(Actor::new(&administrator), installation, 0));
        assert!(!model.can_start(Actor::new(&administrator), installation, 0));
    }

    #[test]
    fn system_scope_requires_a_system_actor() {
        let mut model = InstallModel::<1, 1, 1, 1, 1>::new();
        let package = model.add_package(package_spec(9)).unwrap();
        let installation = model
            .install(InstallSpec {
                package,
                scope: OwnerScope::System,
                source: PackageSource::SystemBuiltin,
                update_authority: authority_group(110),
            })
            .unwrap();
        let user = [Subject::User(1)];
        let administrator = [Subject::Group(110)];
        assert_eq!(
            model.uninstall(Actor::new(&user), installation),
            Err(InstallError::NotAuthorized)
        );
        model
            .uninstall(Actor::new(&administrator), installation)
            .unwrap();
    }

    #[test]
    fn capacity_rejects_without_partial_creation_and_runtime_generation_advances() {
        let mut model = InstallModel::<1, 1, 1, 1, 1>::new();
        let package = model.add_package(package_spec(7)).unwrap();
        assert_eq!(
            model.add_package(package_spec(8)),
            Err(InstallError::Capacity)
        );
        let installation = install_for(&mut model, package, 10, authority_group(100));
        allow_user(&mut model, installation, 10);
        let actor = [Subject::User(10)];
        let first = model
            .start(Actor::new(&actor), installation, principal(10), 0)
            .unwrap();
        assert_eq!(
            model.start(Actor::new(&actor), installation, principal(10), 0),
            Err(InstallError::Capacity)
        );
        model.stop_runtime(first).unwrap();
        let second = model
            .start(Actor::new(&actor), installation, principal(10), 0)
            .unwrap();
        assert_ne!(first, second);
        assert_eq!(model.runtime(first), Err(InstallError::StaleKey));
    }

    fn subject_authority(subject: Subject) -> UpdateAuthority {
        UpdateAuthority { subject }
    }
}
