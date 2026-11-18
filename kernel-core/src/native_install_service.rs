//! Authorized kernel-facing facade over the persistent native install store.
//!
//! The facade adds current security-context, domain, subject and ownership
//! checks before calling the persistent package/install model. It does not
//! expose a user ABI or reserve `system.*` identifiers: a later ABI/USI review
//! must define the public handle and operation surface.

use crate::fs::journal::SectorIo;
use crate::native_install::{
    Actor, DataKey, DataOwnerKind, DataSnapshot, GrantKey, GrantRights, GrantSpec, InstallError,
    InstallSpec, InstallationKey, InstallationSnapshot, OwnerScope, PackageKey, PackageSnapshot,
    PackageSpec, PrincipalSpec, RuntimeKey, RuntimeSnapshot, Subject, UpdateAuthority,
};
use crate::persistent_install::{PersistentInstallError, PersistentInstallStore};
use crate::security::{SecurityContext, SecurityError};
use crate::security_domain::DomainKey;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallServiceError {
    InvalidCaller,
    Unauthorized,
    Capacity,
    Security(SecurityError),
    Store(PersistentInstallError),
}

impl InstallServiceError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidCaller => "system.install.service.error.caller",
            Self::Unauthorized => "system.install.service.error.rights_denied",
            Self::Capacity => "system.install.service.error.capacity",
            Self::Security(error) => error.name(),
            Self::Store(error) => error.name(),
        }
    }
}

impl From<PersistentInstallError> for InstallServiceError {
    fn from(error: PersistentInstallError) -> Self {
        Self::Store(error)
    }
}

impl From<InstallError> for InstallServiceError {
    fn from(error: InstallError) -> Self {
        Self::Store(PersistentInstallError::Install(error))
    }
}

/// Trusted caller projection supplied by the kernel SEC/PEP adapter.
#[derive(Clone, Copy, Debug)]
pub struct InstallServiceCaller {
    context: SecurityContext,
    domain: Option<DomainKey>,
    subject: Subject,
}

impl InstallServiceCaller {
    /// Construct a caller only after the kernel has resolved the process's
    /// active SEC metadata and current workload domain.
    pub fn new(
        context: SecurityContext,
        domain: Option<DomainKey>,
        subject: Subject,
    ) -> Result<Self, InstallServiceError> {
        context
            .require_active()
            .map_err(InstallServiceError::Security)?;
        if !subject.is_valid()
            || (subject != Subject::System && domain.is_none_or(|domain| !domain.is_valid()))
        {
            return Err(InstallServiceError::InvalidCaller);
        }
        Ok(Self {
            context,
            domain,
            subject,
        })
    }

    pub const fn context(self) -> SecurityContext {
        self.context
    }

    pub const fn domain(self) -> Option<DomainKey> {
        self.domain
    }

    pub const fn subject(self) -> Subject {
        self.subject
    }

    fn is_system(self) -> bool {
        self.subject == Subject::System
    }

    fn owns(self, scope: OwnerScope) -> bool {
        scope_matches_subject(scope, self.subject)
    }
}

/// Authorized operations over one bounded persistent install store.
pub struct NativeInstallService<D: SectorIo> {
    store: PersistentInstallStore<D>,
}

/// One update-visible installation and its immutable package identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VisibleUpdate {
    /// Installation registration visible to the update principal.
    pub installation: InstallationKey,
    /// Immutable package identity.
    pub package: PackageSnapshot,
    /// Installation ownership scope.
    pub scope: OwnerScope,
    /// Descriptive installation source.
    pub source: crate::native_install::PackageSource,
    /// Whether the installation is currently enabled.
    pub enabled: bool,
}

impl<D: SectorIo> NativeInstallService<D> {
    pub const fn new(store: PersistentInstallStore<D>) -> Self {
        Self { store }
    }

    pub fn into_store(self) -> PersistentInstallStore<D> {
        self.store
    }

    pub fn store(&self) -> &PersistentInstallStore<D> {
        &self.store
    }

    /// Package bytes enter the shared content store only through a system
    /// authority. Registration remains a separate operation below.
    pub fn install_package(
        &mut self,
        caller: InstallServiceCaller,
        spec: PackageSpec,
        bytes: &[u8],
    ) -> Result<PackageKey, InstallServiceError> {
        if !caller.is_system() {
            return Err(InstallServiceError::Unauthorized);
        }
        self.store.install_package(spec, bytes).map_err(Into::into)
    }

    /// Register one package for the caller's own scope. A system caller may
    /// register another scope, but update authority is always explicit.
    pub fn register(
        &mut self,
        caller: InstallServiceCaller,
        package: PackageKey,
        scope: OwnerScope,
        source: crate::native_install::PackageSource,
        update_authority: Subject,
    ) -> Result<InstallationKey, InstallServiceError> {
        if !scope.is_valid()
            || !update_authority.is_valid()
            || (!caller.is_system() && (!caller.owns(scope) || update_authority != caller.subject))
        {
            return Err(InstallServiceError::Unauthorized);
        }
        self.store
            .install(InstallSpec {
                package,
                scope,
                source,
                update_authority: UpdateAuthority {
                    subject: update_authority,
                },
            })
            .map_err(Into::into)
    }

    /// Switch one installation to a newer package while preserving active
    /// runtime package identities and the application data scope.
    pub fn upgrade_application(
        &mut self,
        caller: InstallServiceCaller,
        installation: InstallationKey,
        package: PackageKey,
    ) -> Result<(), InstallServiceError> {
        self.require_update_authority(caller, installation)?;
        let subjects = [caller.subject];
        self.store
            .upgrade(Actor::new(&subjects), installation, package)
            .map_err(Into::into)
    }

    /// A non-system caller may grant only from an installation it updates.
    pub fn add_grant(
        &mut self,
        caller: InstallServiceCaller,
        installation: InstallationKey,
        subject: Subject,
        rights: GrantRights,
        expires_at: Option<u64>,
    ) -> Result<GrantKey, InstallServiceError> {
        self.require_update_authority(caller, installation)?;
        self.store
            .add_grant(GrantSpec {
                installation,
                subject,
                rights,
                expires_at,
            })
            .map_err(Into::into)
    }

    pub fn revoke_grant(
        &mut self,
        caller: InstallServiceCaller,
        key: GrantKey,
    ) -> Result<(), InstallServiceError> {
        let state = self.store.state();
        let installation = state
            .grants
            .iter()
            .flatten()
            .find(|grant| grant.key == key)
            .ok_or(InstallServiceError::Store(PersistentInstallError::NotFound))?
            .installation;
        self.require_update_authority(caller, installation)?;
        self.store.revoke_grant(key).map_err(Into::into)
    }

    /// Start with an actor derived solely from the authenticated service
    /// caller; the caller cannot supply a different subject or domain.
    pub fn start(
        &mut self,
        caller: InstallServiceCaller,
        installation: InstallationKey,
        kind: crate::native_install::PrincipalKind,
        generation: u32,
        now: u64,
    ) -> Result<RuntimeKey, InstallServiceError> {
        let domain = caller.domain.ok_or(InstallServiceError::InvalidCaller)?;
        let subjects = [caller.subject];
        self.store
            .start(
                Actor::new(&subjects),
                installation,
                PrincipalSpec {
                    kind,
                    subject: caller.subject,
                    generation,
                    domain,
                },
                now,
            )
            .map_err(Into::into)
    }

    pub fn stop_runtime(
        &mut self,
        caller: InstallServiceCaller,
        key: RuntimeKey,
    ) -> Result<(), InstallServiceError> {
        let runtime = self.runtime_snapshot(key)?;
        if !caller.is_system() && runtime.principal.subject != caller.subject {
            return Err(InstallServiceError::Unauthorized);
        }
        self.store.stop_runtime(key).map_err(Into::into)
    }

    pub fn create_data(
        &mut self,
        caller: InstallServiceCaller,
        installation: InstallationKey,
        owner: Subject,
        kind: DataOwnerKind,
    ) -> Result<DataKey, InstallServiceError> {
        if !caller.is_system() && owner != caller.subject {
            return Err(InstallServiceError::Unauthorized);
        }
        self.store
            .create_data(installation, owner, kind)
            .map_err(Into::into)
    }

    pub fn destroy_data(
        &mut self,
        caller: InstallServiceCaller,
        key: DataKey,
    ) -> Result<(), InstallServiceError> {
        let data = self.data_snapshot(key)?;
        if !caller.is_system() && data.owner != caller.subject {
            return Err(InstallServiceError::Unauthorized);
        }
        self.store.destroy_data(key).map_err(Into::into)
    }

    pub fn uninstall(
        &mut self,
        caller: InstallServiceCaller,
        installation: InstallationKey,
    ) -> Result<(), InstallServiceError> {
        self.require_update_authority(caller, installation)?;
        let subjects = [caller.subject];
        self.store
            .uninstall(Actor::new(&subjects), installation)
            .map_err(Into::into)
    }

    pub fn set_enabled(
        &mut self,
        caller: InstallServiceCaller,
        installation: InstallationKey,
        enabled: bool,
    ) -> Result<(), InstallServiceError> {
        self.require_update_authority(caller, installation)?;
        let subjects = [caller.subject];
        self.store
            .set_enabled(Actor::new(&subjects), installation, enabled)
            .map_err(Into::into)
    }

    pub fn query(
        &self,
        caller: InstallServiceCaller,
        installation: InstallationKey,
        now: u64,
    ) -> Result<InstallationSnapshot, InstallServiceError> {
        let subjects = [caller.subject];
        if !self
            .store
            .can_discover(Actor::new(&subjects), installation, now)
        {
            return Err(InstallServiceError::Unauthorized);
        }
        self.store.installation(installation).map_err(Into::into)
    }

    /// Fill the update set visible to the authenticated caller.
    ///
    /// Update visibility is derived from the installation's explicit update
    /// authority, not from DISCOVER rights or a caller-selected tenant. The
    /// system subject receives no implicit cross-tenant visibility. Capacity
    /// is checked before writing, so an undersized output has no partial effect.
    pub fn visible_updates(
        &self,
        caller: InstallServiceCaller,
        output: &mut [Option<VisibleUpdate>],
    ) -> Result<usize, InstallServiceError> {
        let subjects = [caller.subject];
        let actor = Actor::new(&subjects);
        let state = self.store.state();
        let required = state
            .installations
            .iter()
            .flatten()
            .filter(|installation| self.store.can_update(actor, installation.key))
            .count();
        if output.len() < required {
            return Err(InstallServiceError::Capacity);
        }

        let mut written = 0;
        for installation in state.installations.iter().flatten().copied() {
            if !self.store.can_update(actor, installation.key) {
                continue;
            }
            let package = self.store.package(installation.package)?;
            output[written] = Some(VisibleUpdate {
                installation: installation.key,
                package,
                scope: installation.scope,
                source: installation.source,
                enabled: installation.enabled,
            });
            written += 1;
        }
        Ok(written)
    }

    fn require_update_authority(
        &self,
        caller: InstallServiceCaller,
        installation: InstallationKey,
    ) -> Result<(), InstallServiceError> {
        let record = self.store.installation(installation)?;
        if !caller.is_system() && record.update_authority.subject != caller.subject {
            return Err(InstallServiceError::Unauthorized);
        }
        Ok(())
    }

    fn runtime_snapshot(&self, key: RuntimeKey) -> Result<RuntimeSnapshot, InstallServiceError> {
        self.store
            .state()
            .runtimes
            .iter()
            .flatten()
            .copied()
            .find(|runtime| runtime.key == key)
            .ok_or(InstallServiceError::Store(PersistentInstallError::NotFound))
    }

    fn data_snapshot(&self, key: DataKey) -> Result<DataSnapshot, InstallServiceError> {
        self.store
            .state()
            .data
            .iter()
            .flatten()
            .copied()
            .find(|data| data.key == key)
            .ok_or(InstallServiceError::Store(PersistentInstallError::NotFound))
    }
}

fn scope_matches_subject(scope: OwnerScope, subject: Subject) -> bool {
    matches!(
        (scope, subject),
        (OwnerScope::System, Subject::System)
            | (OwnerScope::Device(_), Subject::Device(_))
            | (OwnerScope::User(_), Subject::User(_))
            | (OwnerScope::Group(_), Subject::Group(_))
            | (OwnerScope::Tenant(_), Subject::Tenant(_))
            | (OwnerScope::Workload(_), Subject::Workload(_))
    ) && scope_id(scope) == subject_id(subject)
}

const fn scope_id(scope: OwnerScope) -> Option<u64> {
    match scope {
        OwnerScope::System => None,
        OwnerScope::Device(id)
        | OwnerScope::User(id)
        | OwnerScope::Group(id)
        | OwnerScope::Tenant(id)
        | OwnerScope::Workload(id) => Some(id),
    }
}

const fn subject_id(subject: Subject) -> Option<u64> {
    match subject {
        Subject::System => None,
        Subject::Device(id)
        | Subject::User(id)
        | Subject::Group(id)
        | Subject::Tenant(id)
        | Subject::Workload(id)
        | Subject::Service(id) => Some(id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::journal::{JournalError, STORAGE_UNIT_BYTES};
    use crate::native_install::{PackageSource, PrincipalKind, CONTENT_BYTES};
    use crate::security::{BootId, IdentityClass, MetadataState};

    struct MemoryDisk {
        bytes: Vec<u8>,
    }

    impl MemoryDisk {
        fn new(units: usize) -> Self {
            Self {
                bytes: vec![0u8; units * STORAGE_UNIT_BYTES],
            }
        }
    }

    impl SectorIo for MemoryDisk {
        fn capacity_sectors(&self) -> u64 {
            (self.bytes.len() / 512) as u64
        }

        fn read_unit(
            &mut self,
            sector: u64,
            out: &mut [u8; STORAGE_UNIT_BYTES],
        ) -> Result<(), JournalError> {
            let start = usize::try_from(sector)
                .ok()
                .and_then(|sector| sector.checked_mul(512))
                .ok_or(JournalError::Storage)?;
            let source = self
                .bytes
                .get(start..start + STORAGE_UNIT_BYTES)
                .ok_or(JournalError::Storage)?;
            out.copy_from_slice(source);
            Ok(())
        }

        fn write_unit(
            &mut self,
            sector: u64,
            bytes: &[u8; STORAGE_UNIT_BYTES],
        ) -> Result<(), JournalError> {
            let start = usize::try_from(sector)
                .ok()
                .and_then(|sector| sector.checked_mul(512))
                .ok_or(JournalError::Storage)?;
            let target = self
                .bytes
                .get_mut(start..start + STORAGE_UNIT_BYTES)
                .ok_or(JournalError::Storage)?;
            target.copy_from_slice(bytes);
            Ok(())
        }

        fn flush(&mut self) -> Result<(), JournalError> {
            Ok(())
        }
    }

    fn context(id: u64) -> SecurityContext {
        SecurityContext::new(
            BootId::from_words([1, 2]),
            IdentityClass::Process,
            crate::objtable::ObjId::from_raw((1u64 << 32) | id).unwrap(),
            None,
            MetadataState::Active,
        )
    }

    fn system() -> InstallServiceCaller {
        InstallServiceCaller::new(context(1), None, Subject::System).unwrap()
    }

    fn workload(id: u64) -> InstallServiceCaller {
        InstallServiceCaller::new(
            context(id),
            Some(DomainKey {
                id: id as u32,
                generation: 1,
            }),
            Subject::Workload(id),
        )
        .unwrap()
    }

    fn tenant(id: u64) -> InstallServiceCaller {
        InstallServiceCaller::new(
            context(id),
            Some(DomainKey {
                id: id as u32,
                generation: 1,
            }),
            Subject::Tenant(id),
        )
        .unwrap()
    }

    #[test]
    fn service_separates_package_store_registration_grants_and_data() {
        let store = PersistentInstallStore::format(MemoryDisk::new(64)).unwrap();
        let mut service = NativeInstallService::new(store);
        let system = system();
        let owner = workload(7);
        let outsider = workload(8);
        let spec = PackageSpec {
            app_id: 0x5157,
            publisher: 9,
            content: [0x41; 32],
            version: 1,
        };

        assert_eq!(
            service.install_package(owner, spec, b"package"),
            Err(InstallServiceError::Unauthorized)
        );
        let package = service.install_package(system, spec, b"package").unwrap();
        assert_eq!(
            service.register(
                owner,
                package,
                OwnerScope::User(7),
                PackageSource::Store,
                Subject::User(7),
            ),
            Err(InstallServiceError::Unauthorized)
        );
        let installation = service
            .register(
                owner,
                package,
                OwnerScope::Workload(7),
                PackageSource::Store,
                Subject::Workload(7),
            )
            .unwrap();
        assert!(matches!(
            service.add_grant(
                outsider,
                installation,
                Subject::Workload(8),
                GrantRights::DISCOVER,
                None,
            ),
            Err(InstallServiceError::Unauthorized)
        ));
        let grant = service
            .add_grant(
                owner,
                installation,
                Subject::Workload(7),
                GrantRights::DISCOVER.union(GrantRights::START),
                None,
            )
            .unwrap();
        assert_eq!(
            service.query(outsider, installation, 10),
            Err(InstallServiceError::Unauthorized)
        );
        assert_eq!(
            service.query(owner, installation, 10).unwrap().package,
            package
        );
        let runtime = service
            .start(owner, installation, PrincipalKind::Workload, 1, 10)
            .unwrap();
        let data = service
            .create_data(
                owner,
                installation,
                Subject::Workload(7),
                DataOwnerKind::Cache,
            )
            .unwrap();
        assert_eq!(
            service.create_data(
                owner,
                installation,
                Subject::Workload(8),
                DataOwnerKind::Cache,
            ),
            Err(InstallServiceError::Unauthorized)
        );
        assert_eq!(
            service.destroy_data(outsider, data),
            Err(InstallServiceError::Unauthorized)
        );
        service.revoke_grant(owner, grant).unwrap();
        service.stop_runtime(owner, runtime).unwrap();
        service.uninstall(owner, installation).unwrap();
        service.destroy_data(owner, data).unwrap();
        assert_eq!(service.store().installation_count_for(package), 0);
    }

    #[test]
    fn service_updates_own_application_without_retargeting_active_runtime() {
        let store = PersistentInstallStore::format(MemoryDisk::new(64)).unwrap();
        let mut service = NativeInstallService::new(store);
        let system = system();
        let owner = workload(7);
        let outsider = workload(8);
        let old_package = service
            .install_package(
                system,
                PackageSpec {
                    app_id: 0x5158,
                    publisher: 9,
                    content: [0x51; 32],
                    version: 1,
                },
                b"app-v1",
            )
            .unwrap();
        let new_package = service
            .install_package(
                system,
                PackageSpec {
                    app_id: 0x5158,
                    publisher: 9,
                    content: [0x52; 32],
                    version: 2,
                },
                b"app-v2",
            )
            .unwrap();
        let installation = service
            .register(
                owner,
                old_package,
                OwnerScope::Workload(7),
                PackageSource::UserImport,
                Subject::Workload(7),
            )
            .unwrap();
        service
            .add_grant(
                owner,
                installation,
                Subject::Workload(7),
                GrantRights::DISCOVER.union(GrantRights::START),
                None,
            )
            .unwrap();
        let runtime = service
            .start(owner, installation, PrincipalKind::Workload, 1, 10)
            .unwrap();
        let data = service
            .create_data(
                owner,
                installation,
                Subject::Workload(7),
                DataOwnerKind::PrivateUser,
            )
            .unwrap();

        assert_eq!(
            service.upgrade_application(outsider, installation, new_package),
            Err(InstallServiceError::Unauthorized)
        );
        service
            .upgrade_application(owner, installation, new_package)
            .unwrap();
        assert_eq!(
            service.store().runtime(runtime).unwrap().package,
            old_package
        );
        assert_eq!(service.store().data(data).unwrap().package, new_package);
        assert_eq!(
            service
                .query(owner, installation, 11)
                .unwrap()
                .package,
            new_package
        );
    }

    #[test]
    fn caller_requires_active_security_metadata_and_a_domain() {
        let inactive = SecurityContext::new(
            BootId::from_words([1, 2]),
            IdentityClass::Process,
            crate::objtable::ObjId::from_raw((1u64 << 32) | 3).unwrap(),
            None,
            MetadataState::LegacyBootstrap,
        );
        assert!(matches!(
            InstallServiceCaller::new(inactive, None, Subject::Workload(3)),
            Err(InstallServiceError::Security(_))
        ));
        assert!(matches!(
            InstallServiceCaller::new(context(4), None, Subject::Workload(4)),
            Err(InstallServiceError::InvalidCaller)
        ));
    }

    #[test]
    fn tenant_update_visibility_is_explicit_bounded_and_never_inherited() {
        let store = PersistentInstallStore::format(MemoryDisk::new(64)).unwrap();
        let mut service = NativeInstallService::new(store);
        let system = system();
        let tenant_a = tenant(7);
        let tenant_b = tenant(8);
        let package_a = service
            .install_package(
                system,
                PackageSpec {
                    app_id: 0x7001,
                    publisher: 7,
                    content: [0x71; CONTENT_BYTES],
                    version: 1,
                },
                b"tenant-a",
            )
            .unwrap();
        let package_b = service
            .install_package(
                system,
                PackageSpec {
                    app_id: 0x8001,
                    publisher: 8,
                    content: [0x81; CONTENT_BYTES],
                    version: 1,
                },
                b"tenant-b",
            )
            .unwrap();
        let installation_a = service
            .register(
                tenant_a,
                package_a,
                OwnerScope::Tenant(7),
                PackageSource::Enterprise,
                Subject::Tenant(7),
            )
            .unwrap();
        let installation_b = service
            .register(
                tenant_b,
                package_b,
                OwnerScope::Tenant(8),
                PackageSource::Enterprise,
                Subject::Tenant(8),
            )
            .unwrap();

        let mut visible = [None; 2];
        assert_eq!(service.visible_updates(tenant_a, &mut visible), Ok(1));
        let record = visible[0].unwrap();
        assert_eq!(record.installation, installation_a);
        assert_eq!(record.package.spec.app_id, 0x7001);
        assert_eq!(record.scope, OwnerScope::Tenant(7));
        assert!(visible[1].is_none());

        assert_eq!(service.visible_updates(tenant_b, &mut visible), Ok(1));
        assert_eq!(visible[0].unwrap().installation, installation_b);

        let mut none = [None; 1];
        assert_eq!(service.visible_updates(system, &mut none), Ok(0));
        assert!(none[0].is_none());

        let mut too_small = [None; 1];
        assert_eq!(
            service
                .register(
                    tenant_a,
                    package_b,
                    OwnerScope::Tenant(7),
                    PackageSource::Developer,
                    Subject::Tenant(7),
                )
                .map(|_| service.visible_updates(tenant_a, &mut too_small)),
            Ok(Err(InstallServiceError::Capacity))
        );
        assert!(too_small[0].is_none());
    }
}
