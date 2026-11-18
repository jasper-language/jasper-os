//! Kernel backend for the versioned native installation ABI.
//!
//! The backend uses the same validated P0 virtio-blk device as lifecycle
//! services, but addresses only the explicitly reserved installation region.

use alloc::sync::Arc;
use kernel_core::authz;
use kernel_core::block::{self, Request, Terminal};
use kernel_core::fs::journal::{JournalError, SectorIo, STORAGE_UNIT_BYTES};
use kernel_core::native_install::{
    authorize_publisher_rotation, publisher_rotation_scope, GrantKey, InstallationKey,
    InstallationSnapshot, PackageKey, PackageSpec, PublisherRotationAuditSink,
    PublisherRotationRequest, Subject,
};
use kernel_core::native_install_abi::{GrantArgs, RegisterArgs, MAX_VISIBLE_UPDATES};
use kernel_core::native_install_service::{
    InstallServiceCaller, InstallServiceError, NativeInstallService, VisibleUpdate,
};
use kernel_core::persistent_install::{PersistentInstallError, PersistentInstallStore};
use kernel_core::security::SecurityDomain;

use crate::blk::BlockDevice;
use crate::sync::IrqSpinLock;
use crate::{proc, security};

#[derive(Clone)]
struct ReservedVirtioSectorIo {
    device: Arc<IrqSpinLock<BlockDevice>>,
    base_sector: u64,
    sectors: u64,
}

impl ReservedVirtioSectorIo {
    fn absolute(&self, sector: u64) -> Result<u64, JournalError> {
        sector
            .checked_add(block::SECTORS_PER_IO_UNIT)
            .filter(|end| *end <= self.sectors)
            .ok_or(JournalError::Storage)?;
        self.base_sector
            .checked_add(sector)
            .ok_or(JournalError::Storage)
    }
}

impl SectorIo for ReservedVirtioSectorIo {
    fn capacity_sectors(&self) -> u64 {
        self.sectors
    }

    fn read_unit(
        &mut self,
        sector: u64,
        out: &mut [u8; STORAGE_UNIT_BYTES],
    ) -> Result<(), JournalError> {
        let sector = self.absolute(sector)?;
        let mut device = self.device.lock();
        match device.execute(Request::read(sector, 1), false) {
            Ok(Terminal::Completed) => {}
            Ok(_) => return Err(JournalError::Storage),
            Err(error) => {
                crate::kprintln!(
                    "[JSR-NATIVE-INSTALL-IO] op=read sector={} error={}",
                    sector,
                    error.name()
                );
                return Err(JournalError::Storage);
            }
        }
        device.copy_prefix(out).map_err(|_| JournalError::Storage)
    }

    fn write_unit(
        &mut self,
        sector: u64,
        bytes: &[u8; STORAGE_UNIT_BYTES],
    ) -> Result<(), JournalError> {
        let sector = self.absolute(sector)?;
        let mut device = self.device.lock();
        if let Err(error) = device.fill_pattern(0, bytes) {
            crate::kprintln!(
                "[JSR-NATIVE-INSTALL-IO] op=fill sector={} error={}",
                sector,
                error.name()
            );
            return Err(JournalError::Storage);
        }
        match device.execute(Request::write(sector, 1, false), false) {
            Ok(Terminal::Completed) => Ok(()),
            Ok(_) => Err(JournalError::Storage),
            Err(error) => {
                crate::kprintln!(
                    "[JSR-NATIVE-INSTALL-IO] op=write sector={} error={}",
                    sector,
                    error.name()
                );
                Err(JournalError::Storage)
            }
        }
    }

    fn flush(&mut self) -> Result<(), JournalError> {
        match self.device.lock().execute(Request::flush(), false) {
            Ok(Terminal::Completed) => Ok(()),
            Ok(_) => Err(JournalError::Storage),
            Err(error) => {
                crate::kprintln!("[JSR-NATIVE-INSTALL-IO] op=flush error={}", error.name());
                Err(JournalError::Storage)
            }
        }
    }
}

static BACKEND: IrqSpinLock<Option<NativeInstallService<ReservedVirtioSectorIo>>> =
    IrqSpinLock::ranked(crate::lockorder::NATIVE_INSTALL, None);
static INIT_LOCK: spin::Mutex<()> = spin::Mutex::new(());

fn ensure_initialized() -> Result<(), InstallServiceError> {
    let _initialization = INIT_LOCK.lock();
    if BACKEND.lock().is_some() {
        return Ok(());
    }
    let device = crate::lifecycle_health::persistent_p0_device().map_err(|error| {
        crate::kprintln!("[JSR-NATIVE-INSTALL-IO] op=mount-p0 error={}", error.name());
        InstallServiceError::Store(PersistentInstallError::Io)
    })?;
    let (store, initialized) = PersistentInstallStore::mount_with_status(ReservedVirtioSectorIo {
        device,
        base_sector: jasper_lifecycle_boot::P0_INSTALL_STORE_LBA,
        sectors: jasper_lifecycle_boot::P0_INSTALL_STORE_SECTORS,
    })
    .map_err(InstallServiceError::Store)?;
    crate::kprintln!(
        "[JSR-NATIVE-INSTALL-STORE] mounted=true initialized={} base={} sectors={}",
        initialized,
        jasper_lifecycle_boot::P0_INSTALL_STORE_LBA,
        jasper_lifecycle_boot::P0_INSTALL_STORE_SECTORS
    );
    let mut backend = BACKEND.lock();
    if backend.is_none() {
        *backend = Some(NativeInstallService::new(store));
    }
    Ok(())
}

/// Initialize the persistent installation service before user-process baselines.
pub fn warmup() -> Result<(), InstallServiceError> {
    ensure_initialized()
}

fn current_caller() -> Result<InstallServiceCaller, InstallServiceError> {
    let pid = proc::current_process().ok_or(InstallServiceError::InvalidCaller)?;
    let context = security::require_active(pid).map_err(InstallServiceError::Security)?;
    let domain = proc::workload_domain(pid);
    let subject = if context.mac.domain == SecurityDomain::SYSTEM {
        Subject::System
    } else {
        let domain = domain.ok_or(InstallServiceError::InvalidCaller)?;
        Subject::Workload(u64::from(domain.id))
    };
    InstallServiceCaller::new(context, domain, subject)
}

struct KernelRotationAudit;

impl PublisherRotationAuditSink for KernelRotationAudit {
    fn commit(&mut self, _: &PublisherRotationRequest, decision: authz::Decision) -> bool {
        let (
            version,
            issuer,
            subject,
            executor_generation,
            tenant,
            domain,
            operation,
            scope,
            effect,
            policy,
            revocation,
            allowed,
            reason,
        ) = authz::diagnostic_fields(decision);
        crate::kprintln!(
            "[JSR-AUTHZ] version={} issuer={} subject={} executor_generation={} tenant={} domain={} operation={} scope={} effect={} policy={} revocation={:?} decision={} reason={}",
            version,
            issuer,
            subject,
            executor_generation,
            tenant,
            domain,
            operation,
            scope,
            effect,
            policy,
            revocation,
            allowed,
            reason
        );
        true
    }
}

pub fn package_put(spec: PackageSpec, bytes: &[u8]) -> Result<PackageKey, InstallServiceError> {
    let caller = current_caller()?;
    ensure_initialized()?;
    let mut backend = BACKEND.lock();
    backend
        .as_mut()
        .ok_or(InstallServiceError::InvalidCaller)?
        .install_package(caller, spec, bytes)
}

/// Project an authenticated process into the shared PEP decision, commit that
/// decision to the kernel audit stream and only then mutate publisher identity.
///
/// This remains an internal service entry until a dedicated versioned ABI is
/// frozen. Callers cannot provide subject, tenant, domain or authorization
/// facts.
pub fn rotate_publisher_key(request: PublisherRotationRequest) -> Result<(), InstallServiceError> {
    let caller = current_caller()?;
    let pid = proc::current_process().ok_or(InstallServiceError::InvalidCaller)?;
    ensure_initialized()?;
    let scope = {
        let backend = BACKEND.lock();
        let installation = backend
            .as_ref()
            .ok_or(InstallServiceError::InvalidCaller)?
            .store()
            .installation(request.installation)?;
        publisher_rotation_scope(installation.scope)
    };
    let syscalls = crate::kobj::with(|table| crate::proc::syscalls_in(table, pid))
        .map_err(|_| InstallServiceError::InvalidCaller)?;
    let tenant = caller.domain().map_or(1, |domain| u64::from(domain.id));
    let policy_epoch = crate::security::policy_epoch();
    let authorization = authorize_publisher_rotation(
        authz::CallerFacts {
            context: caller.context(),
            tenant,
            scope,
            syscalls,
            policy_epoch,
            revocation_generation: None,
            now: crate::sched::now_ns(),
            clock_trusted: false,
        },
        request,
        crate::syscall::table::SYSTEM_INSTALL_PACKAGE_WRITE,
        &mut KernelRotationAudit,
    )
    .map_err(|_| InstallServiceError::Unauthorized)?;
    let mut backend = BACKEND.lock();
    backend
        .as_mut()
        .ok_or(InstallServiceError::InvalidCaller)?
        .rotate_publisher_key(
            caller,
            authorization,
            &security::Ed25519PublisherRotationVerifier,
        )
}

pub fn register(args: RegisterArgs) -> Result<InstallationKey, InstallServiceError> {
    let caller = current_caller()?;
    ensure_initialized()?;
    let mut backend = BACKEND.lock();
    backend
        .as_mut()
        .ok_or(InstallServiceError::InvalidCaller)?
        .register(
            caller,
            args.package,
            args.scope,
            args.source,
            args.update_authority,
        )
}

pub fn grant(args: GrantArgs) -> Result<GrantKey, InstallServiceError> {
    let caller = current_caller()?;
    ensure_initialized()?;
    let mut backend = BACKEND.lock();
    backend
        .as_mut()
        .ok_or(InstallServiceError::InvalidCaller)?
        .add_grant(
            caller,
            args.installation,
            args.subject,
            args.rights,
            args.expires_at,
        )
}

pub fn query(
    installation: InstallationKey,
    now: u64,
) -> Result<InstallationSnapshot, InstallServiceError> {
    let caller = current_caller()?;
    ensure_initialized()?;
    let backend = BACKEND.lock();
    backend
        .as_ref()
        .ok_or(InstallServiceError::InvalidCaller)?
        .query(caller, installation, now)
}

pub fn visible_updates(
) -> Result<([Option<VisibleUpdate>; MAX_VISIBLE_UPDATES], usize), InstallServiceError> {
    let caller = current_caller()?;
    ensure_initialized()?;
    let backend = BACKEND.lock();
    let mut output = [None; MAX_VISIBLE_UPDATES];
    let written = backend
        .as_ref()
        .ok_or(InstallServiceError::InvalidCaller)?
        .visible_updates(caller, &mut output)?;
    Ok((output, written))
}
