//! Bounded native module installation and activation lifecycle.
//!
//! This layer joins module metadata and dependency ordering to an installation
//! identity. It deliberately does not execute modules: `assembly` remains the
//! runtime activation mechanism, while authorization is delegated to an
//! explicit authority interface backed by the existing SEC/PEP/Handle policy.
//!
//! 有界原生模块安装与激活生命周期。本层只维护模块元数据、依赖和安装身份，
//! 不复制模块执行路径；授权通过显式 authority 接口交给既有 SEC/PEP/Handle
//! 体系。模块名、AppID 或逻辑路径都不是授权凭证。

use crate::native_install::{Actor, OwnerScope, Subject};

pub const MAX_MODULE_NAME_BYTES: usize = 48;
pub const MAX_MODULE_DEPENDENCIES: usize = 16;

/// Opaque display/identity name. It is not a path and grants no authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModuleName {
    bytes: [u8; MAX_MODULE_NAME_BYTES],
    len: u8,
}

impl ModuleName {
    pub fn new(value: &str) -> Option<Self> {
        let raw = value.as_bytes();
        if raw.is_empty()
            || raw.len() > MAX_MODULE_NAME_BYTES
            || !matches!(raw[0], b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_')
            || !raw.iter().all(|byte| {
                matches!(
                    byte,
                    b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'-' | b'.'
                )
            })
        {
            return None;
        }
        let mut bytes = [0u8; MAX_MODULE_NAME_BYTES];
        bytes[..raw.len()].copy_from_slice(raw);
        Some(Self {
            bytes,
            len: raw.len() as u8,
        })
    }

    pub fn as_str(&self) -> &str {
        // Construction accepts only ASCII bytes.
        core::str::from_utf8(&self.bytes[..self.len as usize]).unwrap()
    }
}

/// Numeric module version used for deterministic dependency checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ModuleVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl ModuleVersion {
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    const fn is_valid(self) -> bool {
        self.major != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModuleDependency {
    pub name: ModuleName,
    pub minimum: ModuleVersion,
}

#[derive(Clone, Copy, Debug)]
pub struct ModuleSpec<'a> {
    pub name: ModuleName,
    pub version: ModuleVersion,
    pub owner: OwnerScope,
    pub dependencies: &'a [ModuleDependency],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModuleKey {
    slot: u16,
    generation: u32,
}

impl ModuleKey {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModuleState {
    Installed,
    Started,
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModuleStatus {
    pub key: ModuleKey,
    pub name: ModuleName,
    pub version: ModuleVersion,
    pub owner: OwnerScope,
    pub state: ModuleState,
    pub dependencies: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModuleOperation {
    Query,
    Install,
    Start,
    Stop,
    Uninstall,
}

/// Existing policy must answer this question; the lifecycle model never
/// derives authorization from a module name, installation path or AppID.
pub trait ModuleAuthority {
    fn authorize(&self, actor: Actor<'_>, operation: ModuleOperation, owner: OwnerScope) -> bool;
}

/// Basic scope adapter for models and tests. Production must provide a PEP or
/// Handle/Rights-backed implementation rather than relying on this adapter.
#[derive(Clone, Copy, Debug, Default)]
pub struct ScopeModuleAuthority;

impl ModuleAuthority for ScopeModuleAuthority {
    fn authorize(&self, actor: Actor<'_>, _operation: ModuleOperation, owner: OwnerScope) -> bool {
        match owner {
            OwnerScope::System => actor.subjects.contains(&Subject::System),
            OwnerScope::Device(id) => actor.subjects.contains(&Subject::Device(id)),
            OwnerScope::User(id) => actor.subjects.contains(&Subject::User(id)),
            OwnerScope::Group(id) => actor.subjects.contains(&Subject::Group(id)),
            OwnerScope::Tenant(id) => actor.subjects.contains(&Subject::Tenant(id)),
            OwnerScope::Workload(id) => actor.subjects.contains(&Subject::Workload(id)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModuleError {
    InvalidName,
    InvalidVersion,
    InvalidDependency,
    InvalidScope,
    NotAuthorized,
    Duplicate,
    NotInstalled,
    StaleKey,
    Capacity,
    IdExhausted,
    DependencyMissing,
    DependencyVersion,
    DependencyNotStarted,
    ActiveDependent,
    DependentInstalled,
    InvalidState,
}

impl ModuleError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidName => "system.module.lifecycle.error.name",
            Self::InvalidVersion => "system.module.lifecycle.error.version",
            Self::InvalidDependency => "system.module.lifecycle.error.dependency",
            Self::InvalidScope => "system.module.lifecycle.error.scope",
            Self::NotAuthorized => "system.module.lifecycle.error.not_authorized",
            Self::Duplicate => "system.module.lifecycle.error.duplicate",
            Self::NotInstalled => "system.module.lifecycle.error.not_installed",
            Self::StaleKey => "system.module.lifecycle.error.stale",
            Self::Capacity => "system.module.lifecycle.error.capacity",
            Self::IdExhausted => "system.module.lifecycle.error.ids_exhausted",
            Self::DependencyMissing => "system.module.lifecycle.error.dependency_missing",
            Self::DependencyVersion => "system.module.lifecycle.error.dependency_version",
            Self::DependencyNotStarted => "system.module.lifecycle.error.dependency_state",
            Self::ActiveDependent => "system.module.lifecycle.error.active_dependent",
            Self::DependentInstalled => "system.module.lifecycle.error.dependent_installed",
            Self::InvalidState => "system.module.lifecycle.error.state",
        }
    }
}

#[derive(Clone, Copy)]
struct ModuleRecord {
    key: ModuleKey,
    name: ModuleName,
    version: ModuleVersion,
    owner: OwnerScope,
    state: ModuleState,
    dependencies: [Option<ModuleDependency>; MAX_MODULE_DEPENDENCIES],
    dependency_count: u8,
}

impl ModuleRecord {
    fn dependencies(&self) -> &[Option<ModuleDependency>] {
        &self.dependencies[..self.dependency_count as usize]
    }
}

/// Fixed-capacity native module registry. Every fallible operation computes a
/// complete next state first, so rejection never leaves a partial transition.
#[derive(Clone, Copy)]
pub struct NativeModuleRegistry<const N: usize> {
    slots: [Option<ModuleRecord>; N],
    generations: [u32; N],
}

impl<const N: usize> NativeModuleRegistry<N> {
    pub const fn new() -> Self {
        Self {
            slots: [None; N],
            generations: [0; N],
        }
    }

    pub fn install<A: ModuleAuthority>(
        &mut self,
        actor: Actor<'_>,
        authority: &A,
        spec: ModuleSpec<'_>,
    ) -> Result<ModuleKey, ModuleError> {
        validate_spec(spec)?;
        if !authority.authorize(actor, ModuleOperation::Install, spec.owner) {
            return Err(ModuleError::NotAuthorized);
        }
        if self
            .slots
            .iter()
            .flatten()
            .any(|record| record.name == spec.name)
        {
            return Err(ModuleError::Duplicate);
        }
        let slot = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(ModuleError::Capacity)?;
        if slot > u16::MAX as usize {
            return Err(ModuleError::Capacity);
        }
        let generation = self.generations[slot]
            .checked_add(1)
            .ok_or(ModuleError::IdExhausted)?;
        let key = ModuleKey {
            slot: slot as u16,
            generation,
        };
        let mut dependencies = [None; MAX_MODULE_DEPENDENCIES];
        for (target, dependency) in dependencies
            .iter_mut()
            .zip(spec.dependencies.iter().copied())
        {
            *target = Some(dependency);
        }
        let mut next = self.clone();
        next.generations[slot] = generation;
        next.slots[slot] = Some(ModuleRecord {
            key,
            name: spec.name,
            version: spec.version,
            owner: spec.owner,
            state: ModuleState::Installed,
            dependencies,
            dependency_count: spec.dependencies.len() as u8,
        });
        *self = next;
        Ok(key)
    }

    pub fn start<A: ModuleAuthority>(
        &mut self,
        actor: Actor<'_>,
        authority: &A,
        key: ModuleKey,
    ) -> Result<(), ModuleError> {
        let slot = self.slot(key)?;
        let record = self.slots[slot].ok_or(ModuleError::StaleKey)?;
        if !authority.authorize(actor, ModuleOperation::Start, record.owner) {
            return Err(ModuleError::NotAuthorized);
        }
        if record.state == ModuleState::Started {
            return Err(ModuleError::InvalidState);
        }
        for dependency in record.dependencies().iter().flatten() {
            let installed = self
                .slots
                .iter()
                .flatten()
                .find(|candidate| candidate.name == dependency.name)
                .ok_or(ModuleError::DependencyMissing)?;
            if installed.version < dependency.minimum {
                return Err(ModuleError::DependencyVersion);
            }
            if installed.state != ModuleState::Started {
                return Err(ModuleError::DependencyNotStarted);
            }
        }
        let mut next = self.clone();
        next.slots[slot]
            .as_mut()
            .ok_or(ModuleError::StaleKey)?
            .state = ModuleState::Started;
        *self = next;
        Ok(())
    }

    pub fn stop<A: ModuleAuthority>(
        &mut self,
        actor: Actor<'_>,
        authority: &A,
        key: ModuleKey,
    ) -> Result<(), ModuleError> {
        let slot = self.slot(key)?;
        let record = self.slots[slot].ok_or(ModuleError::StaleKey)?;
        if !authority.authorize(actor, ModuleOperation::Stop, record.owner) {
            return Err(ModuleError::NotAuthorized);
        }
        if record.state != ModuleState::Started {
            return Err(ModuleError::InvalidState);
        }
        if self.has_active_dependent(record.name) {
            return Err(ModuleError::ActiveDependent);
        }
        let mut next = self.clone();
        next.slots[slot]
            .as_mut()
            .ok_or(ModuleError::StaleKey)?
            .state = ModuleState::Stopped;
        *self = next;
        Ok(())
    }

    pub fn uninstall<A: ModuleAuthority>(
        &mut self,
        actor: Actor<'_>,
        authority: &A,
        key: ModuleKey,
    ) -> Result<(), ModuleError> {
        let slot = self.slot(key)?;
        let record = self.slots[slot].ok_or(ModuleError::StaleKey)?;
        if !authority.authorize(actor, ModuleOperation::Uninstall, record.owner) {
            return Err(ModuleError::NotAuthorized);
        }
        if record.state == ModuleState::Started {
            return Err(ModuleError::InvalidState);
        }
        if self.has_dependent(record.name) {
            return Err(ModuleError::DependentInstalled);
        }
        let mut next = self.clone();
        next.slots[slot] = None;
        *self = next;
        Ok(())
    }

    pub fn status<A: ModuleAuthority>(
        &self,
        actor: Actor<'_>,
        authority: &A,
        key: ModuleKey,
    ) -> Result<ModuleStatus, ModuleError> {
        let slot = self.slot(key)?;
        let record = self.slots[slot].ok_or(ModuleError::StaleKey)?;
        if !authority.authorize(actor, ModuleOperation::Query, record.owner) {
            return Err(ModuleError::NotAuthorized);
        }
        Ok(ModuleStatus {
            key: record.key,
            name: record.name,
            version: record.version,
            owner: record.owner,
            state: record.state,
            dependencies: u16::from(record.dependency_count),
        })
    }

    pub fn len(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn started_count(&self) -> usize {
        self.slots
            .iter()
            .flatten()
            .filter(|record| record.state == ModuleState::Started)
            .count()
    }

    fn slot(&self, key: ModuleKey) -> Result<usize, ModuleError> {
        let slot = key.slot as usize;
        let record = self.slots.get(slot).and_then(|record| *record);
        match record {
            Some(record) if record.key == key => Ok(slot),
            Some(record) if record.key.generation > key.generation => Err(ModuleError::StaleKey),
            _ => Err(ModuleError::NotInstalled),
        }
    }

    fn has_active_dependent(&self, name: ModuleName) -> bool {
        self.slots.iter().flatten().any(|record| {
            record.state == ModuleState::Started
                && record
                    .dependencies()
                    .iter()
                    .flatten()
                    .any(|dependency| dependency.name == name)
        })
    }

    fn has_dependent(&self, name: ModuleName) -> bool {
        self.slots.iter().flatten().any(|record| {
            record
                .dependencies()
                .iter()
                .flatten()
                .any(|dependency| dependency.name == name)
        })
    }
}

impl<const N: usize> Default for NativeModuleRegistry<N> {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_spec(spec: ModuleSpec<'_>) -> Result<(), ModuleError> {
    if !spec.version.is_valid() {
        return Err(ModuleError::InvalidVersion);
    }
    if !spec.owner.is_valid() {
        return Err(ModuleError::InvalidScope);
    }
    if spec.dependencies.len() > MAX_MODULE_DEPENDENCIES {
        return Err(ModuleError::InvalidDependency);
    }
    for (index, dependency) in spec.dependencies.iter().copied().enumerate() {
        if !dependency.minimum.is_valid() || dependency.name == spec.name {
            return Err(ModuleError::InvalidDependency);
        }
        if spec.dependencies[..index]
            .iter()
            .any(|existing| existing.name == dependency.name)
        {
            return Err(ModuleError::InvalidDependency);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER: Actor<'static> = Actor::new(&[Subject::User(7)]);
    const OTHER_USER: Actor<'static> = Actor::new(&[Subject::User(8)]);
    const USER_SCOPE: OwnerScope = OwnerScope::User(7);
    const AUTHORITY: ScopeModuleAuthority = ScopeModuleAuthority;

    fn name(value: &str) -> ModuleName {
        ModuleName::new(value).unwrap()
    }

    fn version(major: u32, minor: u32, patch: u32) -> ModuleVersion {
        ModuleVersion::new(major, minor, patch)
    }

    fn spec<'a>(
        module_name: &str,
        module_version: ModuleVersion,
        dependencies: &'a [ModuleDependency],
    ) -> ModuleSpec<'a> {
        ModuleSpec {
            name: name(module_name),
            version: module_version,
            owner: USER_SCOPE,
            dependencies,
        }
    }

    #[test]
    fn install_start_stop_uninstall_follow_dependency_order() {
        let mut registry = NativeModuleRegistry::<4>::new();
        let base = registry
            .install(USER, &AUTHORITY, spec("jasper.base", version(1, 2, 0), &[]))
            .unwrap();
        let dependencies = [ModuleDependency {
            name: name("jasper.base"),
            minimum: version(1, 1, 0),
        }];
        let app = registry
            .install(
                USER,
                &AUTHORITY,
                spec("jasper.app", version(2, 0, 0), &dependencies),
            )
            .unwrap();

        assert_eq!(
            registry.start(USER, &AUTHORITY, app),
            Err(ModuleError::DependencyNotStarted)
        );
        registry.start(USER, &AUTHORITY, base).unwrap();
        registry.start(USER, &AUTHORITY, app).unwrap();
        assert_eq!(registry.started_count(), 2);
        assert_eq!(
            registry.stop(USER, &AUTHORITY, base),
            Err(ModuleError::ActiveDependent)
        );
        registry.stop(USER, &AUTHORITY, app).unwrap();
        registry.stop(USER, &AUTHORITY, base).unwrap();
        assert_eq!(
            registry.uninstall(USER, &AUTHORITY, base),
            Err(ModuleError::DependentInstalled)
        );
        registry.uninstall(USER, &AUTHORITY, app).unwrap();
        registry.uninstall(USER, &AUTHORITY, base).unwrap();
        assert!(registry.is_empty());
        assert_eq!(
            registry.status(USER, &AUTHORITY, base),
            Err(ModuleError::NotInstalled)
        );
    }

    #[test]
    fn rejected_install_and_cross_scope_queries_are_failure_atomic() {
        let mut registry = NativeModuleRegistry::<2>::new();
        let key = registry
            .install(USER, &AUTHORITY, spec("jasper.base", version(1, 0, 0), &[]))
            .unwrap();
        assert_eq!(
            registry.install(USER, &AUTHORITY, spec("jasper.base", version(2, 0, 0), &[])),
            Err(ModuleError::Duplicate)
        );
        assert_eq!(
            registry.install(
                OTHER_USER,
                &AUTHORITY,
                spec("jasper.other", version(1, 0, 0), &[])
            ),
            Err(ModuleError::NotAuthorized)
        );
        assert_eq!(registry.len(), 1);
        assert_eq!(
            registry.status(OTHER_USER, &AUTHORITY, key),
            Err(ModuleError::NotAuthorized)
        );
        assert_eq!(
            registry.status(USER, &AUTHORITY, key).unwrap().state,
            ModuleState::Installed
        );
    }

    #[test]
    fn versions_capacity_and_invalid_dependencies_fail_without_mutation() {
        let mut registry = NativeModuleRegistry::<1>::new();
        let old = registry
            .install(USER, &AUTHORITY, spec("jasper.base", version(1, 0, 0), &[]))
            .unwrap();
        registry.start(USER, &AUTHORITY, old).unwrap();
        let dependencies = [ModuleDependency {
            name: name("jasper.base"),
            minimum: version(2, 0, 0),
        }];
        assert_eq!(
            registry.install(
                USER,
                &AUTHORITY,
                spec("jasper.app", version(1, 0, 0), &dependencies)
            ),
            Err(ModuleError::Capacity)
        );
        assert_eq!(registry.len(), 1);

        let mut registry = NativeModuleRegistry::<2>::new();
        let duplicate = [dependencies[0], dependencies[0]];
        assert_eq!(
            registry.install(
                USER,
                &AUTHORITY,
                spec("jasper.app", version(1, 0, 0), &duplicate)
            ),
            Err(ModuleError::InvalidDependency)
        );
        assert!(registry.is_empty());
    }

    #[test]
    fn uninstall_reuse_never_revives_an_old_generation() {
        let mut registry = NativeModuleRegistry::<1>::new();
        let old = registry
            .install(USER, &AUTHORITY, spec("jasper.base", version(1, 0, 0), &[]))
            .unwrap();
        registry.uninstall(USER, &AUTHORITY, old).unwrap();
        let new = registry
            .install(USER, &AUTHORITY, spec("jasper.base", version(1, 0, 1), &[]))
            .unwrap();
        assert_ne!(old, new);
        assert_eq!(
            registry.status(USER, &AUTHORITY, old),
            Err(ModuleError::StaleKey)
        );
        assert_eq!(
            registry.status(USER, &AUTHORITY, new).unwrap().version,
            version(1, 0, 1)
        );
    }

    #[test]
    fn stopped_dependent_does_not_block_base_stop_but_still_blocks_uninstall() {
        let mut registry = NativeModuleRegistry::<2>::new();
        let base = registry
            .install(USER, &AUTHORITY, spec("jasper.base", version(1, 0, 0), &[]))
            .unwrap();
        let dependencies = [ModuleDependency {
            name: name("jasper.base"),
            minimum: version(1, 0, 0),
        }];
        let app = registry
            .install(
                USER,
                &AUTHORITY,
                spec("jasper.app", version(1, 0, 0), &dependencies),
            )
            .unwrap();
        registry.start(USER, &AUTHORITY, base).unwrap();
        registry.start(USER, &AUTHORITY, app).unwrap();
        registry.stop(USER, &AUTHORITY, app).unwrap();
        registry.stop(USER, &AUTHORITY, base).unwrap();
        assert_eq!(registry.started_count(), 0);
        assert_eq!(
            registry.uninstall(USER, &AUTHORITY, base),
            Err(ModuleError::DependentInstalled)
        );
    }
}
