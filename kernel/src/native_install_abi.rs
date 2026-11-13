//! Kernel backend for the versioned native installation ABI.
//!
//! This verification backend is a fixed RAM `SectorIo`; it proves ABI,
//! authorization and transactional store semantics without claiming reboot
//! persistence. The separately verified virtio-blk service remains the
//! persistence authority and must be mounted before this ABI is production
//! complete.

use kernel_core::fs::journal::{JournalError, SectorIo, STORAGE_UNIT_BYTES};
use kernel_core::native_install::{
    GrantKey, InstallationKey, InstallationSnapshot, PackageKey, PackageSpec, Subject,
};
use kernel_core::native_install_abi::{GrantArgs, RegisterArgs};
use kernel_core::native_install_service::{
    InstallServiceCaller, InstallServiceError, NativeInstallService,
};
use kernel_core::persistent_install::PersistentInstallStore;
use kernel_core::security::SecurityDomain;

use core::cell::UnsafeCell;

use crate::sync::IrqSpinLock;
use crate::{proc, security};

const RAM_UNITS: usize = 64;
const RAM_BYTES: usize = RAM_UNITS * STORAGE_UNIT_BYTES;

struct SharedRamStorage(UnsafeCell<[u8; RAM_BYTES]>);

unsafe impl Sync for SharedRamStorage {}

static RAM_STORAGE: SharedRamStorage = SharedRamStorage(UnsafeCell::new([0; RAM_BYTES]));

/// Zero-sized SectorIo handle over the locked verification RAM.
///
/// The enclosing `BACKEND` lock is held for every SectorIo call, so this is the
/// sole temporary mutable access to `RAM_STORAGE`. Keeping the 256 KiB backing
/// array out of the value avoids constructing a large object on the kernel stack.
#[derive(Clone, Copy)]
struct RamDisk;

impl RamDisk {
    fn offset(sector: u64) -> Result<usize, JournalError> {
        usize::try_from(sector)
            .ok()
            .and_then(|sector| sector.checked_mul(512))
            .filter(|offset| offset.saturating_add(STORAGE_UNIT_BYTES) <= RAM_BYTES)
            .ok_or(JournalError::Storage)
    }
}

impl SectorIo for RamDisk {
    fn capacity_sectors(&self) -> u64 {
        (RAM_BYTES / 512) as u64
    }

    fn read_unit(
        &mut self,
        sector: u64,
        out: &mut [u8; STORAGE_UNIT_BYTES],
    ) -> Result<(), JournalError> {
        let offset = Self::offset(sector)?;
            let bytes = unsafe { &mut *RAM_STORAGE.0.get() };
            out.copy_from_slice(&bytes[offset..offset + STORAGE_UNIT_BYTES]);
        Ok(())
    }

    fn write_unit(
        &mut self,
        sector: u64,
        bytes: &[u8; STORAGE_UNIT_BYTES],
    ) -> Result<(), JournalError> {
        let offset = Self::offset(sector)?;
        let storage = unsafe { &mut *RAM_STORAGE.0.get() };
        storage[offset..offset + STORAGE_UNIT_BYTES].copy_from_slice(bytes);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), JournalError> {
        Ok(())
    }
}

static BACKEND: IrqSpinLock<Option<NativeInstallService<RamDisk>>> =
    IrqSpinLock::ranked(crate::lockorder::NATIVE_INSTALL, None);

fn ensure_backend(
    backend: &mut Option<NativeInstallService<RamDisk>>,
) -> Result<(), InstallServiceError> {
    if backend.is_none() {
        let store =
            PersistentInstallStore::format(RamDisk).map_err(InstallServiceError::Store)?;
        *backend = Some(NativeInstallService::new(store));
    }
    Ok(())
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

pub fn package_put(spec: PackageSpec, bytes: &[u8]) -> Result<PackageKey, InstallServiceError> {
    let caller = current_caller()?;
    let mut backend = BACKEND.lock();
    ensure_backend(&mut backend)?;
    backend
        .as_mut()
        .ok_or(InstallServiceError::InvalidCaller)?
        .install_package(caller, spec, bytes)
}

pub fn register(args: RegisterArgs) -> Result<InstallationKey, InstallServiceError> {
    let caller = current_caller()?;
    let mut backend = BACKEND.lock();
    ensure_backend(&mut backend)?;
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
    let mut backend = BACKEND.lock();
    ensure_backend(&mut backend)?;
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
    let mut backend = BACKEND.lock();
    ensure_backend(&mut backend)?;
    backend
        .as_ref()
        .ok_or(InstallServiceError::InvalidCaller)?
        .query(caller, installation, now)
}
