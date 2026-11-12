//! Real virtio-blk persistence drill for installation state and package bytes.
//!
//! The first boot formats a dedicated data device, creates package and
//! installation state, and flushes every commit. The next boot opens the same
//! device and verifies package bytes, grants, runtime principal, owned data,
//! and shared-install accounting without formatting it again.

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::block::{self, Request, Terminal};
use kernel_core::fs::journal::{JournalError, SectorIo, STORAGE_UNIT_BYTES};
use kernel_core::native_install::{
    Actor, DataOwnerKind, GrantRights, GrantSpec, InstallSpec, OwnerScope, PackageSource,
    PackageSpec, PrincipalKind, PrincipalSpec, Subject, UpdateAuthority,
};
use kernel_core::persistent_install::{PersistentInstallError, PersistentInstallStore};
use kernel_core::security_domain::DomainKey;

use crate::blk::BlockDevice;
use crate::{baseline, kprintln, mmio, pci, virtio};

const DATA_PAGES: u64 = 1;
const DATA_BASE_SECTOR: u64 = 4096;
const PACKAGE_CONTENT: [u8; 32] = [0x5a; 32];
const PACKAGE_BYTES: &[u8] = b"native-install-persistence";
const PACKAGE: PackageSpec = PackageSpec {
    app_id: 0x4e41_5449_5645,
    publisher: 7,
    content: PACKAGE_CONTENT,
    version: 1,
};

static FAILED: AtomicU32 = AtomicU32::new(0);

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

fn check(condition: bool, what: &'static str) {
    if !condition {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-NATIVE-INSTALL-FAIL] {}", what);
    }
}

fn install_spec(package: kernel_core::native_install::PackageKey, user: u64) -> InstallSpec {
    InstallSpec {
        package,
        scope: OwnerScope::User(user),
        source: PackageSource::Store,
        update_authority: UpdateAuthority {
            subject: Subject::User(user),
        },
    }
}

struct VirtioSectorIo<'a> {
    device: &'a mut BlockDevice,
    base_sector: u64,
}

impl VirtioSectorIo<'_> {
    fn sector(&self, sector: u64) -> Result<u64, JournalError> {
        let absolute = self
            .base_sector
            .checked_add(sector)
            .ok_or(JournalError::Storage)?;
        let end = absolute
            .checked_add(block::SECTORS_PER_IO_UNIT)
            .ok_or(JournalError::Storage)?;
        if end > self.device.geometry().capacity_sectors {
            return Err(JournalError::Storage);
        }
        Ok(absolute)
    }
}

impl SectorIo for VirtioSectorIo<'_> {
    fn capacity_sectors(&self) -> u64 {
        self.device
            .geometry()
            .capacity_sectors
            .saturating_sub(self.base_sector)
    }

    fn read_unit(
        &mut self,
        sector: u64,
        out: &mut [u8; STORAGE_UNIT_BYTES],
    ) -> Result<(), JournalError> {
        let sector = self.sector(sector)?;
        if !matches!(
            self.device.execute(Request::read(sector, 1), false),
            Ok(Terminal::Completed)
        ) {
            return Err(JournalError::Storage);
        }
        self.device
            .copy_prefix(out)
            .map_err(|_| JournalError::Storage)
    }

    fn write_unit(
        &mut self,
        sector: u64,
        bytes: &[u8; STORAGE_UNIT_BYTES],
    ) -> Result<(), JournalError> {
        let sector = self.sector(sector)?;
        self.device
            .fill_pattern(0, bytes)
            .map_err(|_| JournalError::Storage)?;
        if !matches!(
            self.device.execute(Request::write(sector, 1, false), false),
            Ok(Terminal::Completed)
        ) {
            return Err(JournalError::Storage);
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), JournalError> {
        if matches!(
            self.device.execute(Request::flush(), false),
            Ok(Terminal::Completed)
        ) {
            Ok(())
        } else {
            Err(JournalError::Storage)
        }
    }
}

#[inline(never)]
fn exercise(device: &mut BlockDevice) -> Result<(&'static str, usize), PersistentInstallError> {
    kprintln!("[JSR-NATIVE-INSTALL] step=open-begin");
    let opened = PersistentInstallStore::open(VirtioSectorIo {
        device,
        base_sector: DATA_BASE_SECTOR,
    });
    let (phase, mut store) = match opened {
        Ok(store) => ("reopen", store),
        Err(PersistentInstallError::InvalidFormat) => (
            "format",
            PersistentInstallStore::format(VirtioSectorIo {
                device,
                base_sector: DATA_BASE_SECTOR,
            })?,
        ),
        Err(error) => return Err(error),
    };
    kprintln!("[JSR-NATIVE-INSTALL] step=open phase={}", phase);

    if phase == "format" {
        kprintln!("[JSR-NATIVE-INSTALL] step=write-begin");
        let package = store.install_package(PACKAGE, PACKAGE_BYTES)?;
        let first = store.install(install_spec(package, 7))?;
        store.install(install_spec(package, 8))?;
        store.add_grant(GrantSpec {
            installation: first,
            subject: Subject::User(7),
            rights: GrantRights::DISCOVER.union(GrantRights::START),
            expires_at: None,
        })?;
        let actor = Actor::new(&[Subject::User(7)]);
        store.start(
            actor,
            first,
            PrincipalSpec {
                kind: PrincipalKind::User,
                subject: Subject::User(7),
                generation: 1,
                domain: DomainKey {
                    id: 7,
                    generation: 1,
                },
            },
            11,
        )?;
        store.create_data(first, Subject::User(7), DataOwnerKind::PrivateUser)?;
        kprintln!(
            "[JSR-NATIVE-INSTALL] stage=format packages=1 installations=2 grants=1 runtimes=1 data=1 failed=0"
        );
        return Ok((phase, PACKAGE_BYTES.len()));
    }

    let package = store
        .find_package(PACKAGE)
        .ok_or(PersistentInstallError::NotFound)?;
    let mut bytes = [0u8; 64];
    let bytes_len = store.read_package_bytes(PACKAGE_CONTENT, &mut bytes)?;
    if &bytes[..bytes_len] != PACKAGE_BYTES || store.installation_count_for(package) != 2 {
        return Err(PersistentInstallError::Corrupt);
    }
    let state = store.state();
    if state.packages.iter().flatten().count() != 1
        || state.installations.iter().flatten().count() != 2
        || state.grants.iter().flatten().count() != 1
        || state.runtimes.iter().flatten().count() != 1
        || state.data.iter().flatten().count() != 1
    {
        return Err(PersistentInstallError::Corrupt);
    }
    let first = state
        .installations
        .iter()
        .flatten()
        .find(|installation| installation.scope == OwnerScope::User(7))
        .ok_or(PersistentInstallError::Corrupt)?;
    let actor = Actor::new(&[Subject::User(7)]);
    if !store.can_discover(actor, first.key, 12) || !store.can_start(actor, first.key, 12) {
        return Err(PersistentInstallError::Install(
            kernel_core::native_install::InstallError::NotAuthorized,
        ));
    }
    kprintln!(
        "[JSR-NATIVE-INSTALL] stage=reopen packages=1 installations=2 grants=1 runtimes=1 data=1 bytes={} failed=0",
        bytes_len
    );
    Ok((phase, bytes_len))
}

#[inline(never)]
pub fn run() {
    kprintln!("[JSR-NATIVE-INSTALL] step=start");
    if let Err(error) = mmio::prepare_window() {
        check(false, error.name());
        return;
    }
    let before = baseline::baseline();
    let Some(device) = pci::table().devices().find(|device| {
        device.header.vendor == virtio::VIRTIO_VENDOR && virtio::is_blk_device(device.header.device)
    }) else {
        check(false, "no virtio-blk data device");
        return;
    };
    kprintln!("[JSR-NATIVE-INSTALL] step=device-found");
    let result = {
        kprintln!("[JSR-NATIVE-INSTALL] step=block-setup");
        let mut blockdev = match BlockDevice::new(device, DATA_PAGES) {
            Ok(device) => device,
            Err(error) => {
                kprintln!("[JSR-NATIVE-INSTALL-FAIL] block={}", error.name());
                check(false, "block device setup");
                return;
            }
        };
        kprintln!(
            "[JSR-NATIVE-INSTALL] step=block-ready capacity={}",
            blockdev.geometry().capacity_sectors
        );
        exercise(&mut blockdev)
    };
    match result {
        Ok((phase, bytes)) => kprintln!(
            "[JSR-NATIVE-INSTALL] phase={} bytes={} failed={}",
            phase,
            bytes,
            failed()
        ),
        Err(error) => {
            kprintln!("[JSR-NATIVE-INSTALL-FAIL] error={}", error.name());
            check(false, "persistent install exercise");
        }
    }
    let after = baseline::baseline();
    check(after == before, "resources did not return to baseline");
    kprintln!(
        "[JSR-NATIVE-INSTALL] summary failed={} resources={}",
        failed(),
        after == before
    );
}
