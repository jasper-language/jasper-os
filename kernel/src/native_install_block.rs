//! Real virtio-blk persistence drill for installation state and package bytes.
//!
//! The first boot formats a dedicated data device, creates package and
//! installation state, and flushes every commit. The next boot opens the same
//! device and verifies package bytes, grants, runtime principal, owned data,
//! and shared-install accounting without formatting it again.

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::block::{self, Request, Terminal};
use kernel_core::fs::journal::{
    JournalError, SectorIo, SECTORS_PER_STORAGE_UNIT, STORAGE_UNIT_BYTES,
};
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CutPoint {
    BlobBodyTorn,
    BlobBodyUnflushed,
    BlobHeaderTorn,
    BlobHeaderUnflushed,
    MetadataBodyTorn,
    MetadataBodyUnflushed,
    MarkerTorn,
    MarkerUnflushed,
    MarkerFlushedThenFailed,
}

impl CutPoint {
    const ALL: [Self; 9] = [
        Self::BlobBodyTorn,
        Self::BlobBodyUnflushed,
        Self::BlobHeaderTorn,
        Self::BlobHeaderUnflushed,
        Self::MetadataBodyTorn,
        Self::MetadataBodyUnflushed,
        Self::MarkerTorn,
        Self::MarkerUnflushed,
        Self::MarkerFlushedThenFailed,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::BlobBodyTorn => "blob-body-torn",
            Self::BlobBodyUnflushed => "blob-body-unflushed",
            Self::BlobHeaderTorn => "blob-header-torn",
            Self::BlobHeaderUnflushed => "blob-header-unflushed",
            Self::MetadataBodyTorn => "metadata-body-torn",
            Self::MetadataBodyUnflushed => "metadata-body-unflushed",
            Self::MarkerTorn => "marker-torn",
            Self::MarkerUnflushed => "marker-unflushed",
            Self::MarkerFlushedThenFailed => "marker-flushed-then-failed",
        }
    }

    fn matches_unit(self, sector: u64) -> bool {
        let relative = sector / SECTORS_PER_STORAGE_UNIT;
        let blob = relative >= 11;
        let blob_body = blob && relative % 2 == 1;
        let blob_header = blob && relative % 2 == 0;
        let slot_body = (1..=9).contains(&relative) && relative % 5 != 0;
        let marker = matches!(relative, 5 | 10);
        match self {
            Self::BlobBodyTorn | Self::BlobBodyUnflushed => blob_body,
            Self::BlobHeaderTorn | Self::BlobHeaderUnflushed => blob_header,
            Self::MetadataBodyTorn | Self::MetadataBodyUnflushed => slot_body,
            Self::MarkerTorn | Self::MarkerUnflushed | Self::MarkerFlushedThenFailed => marker,
        }
    }

    const fn flush_target(self) -> Option<u32> {
        match self {
            Self::BlobBodyUnflushed => Some(1),
            Self::BlobHeaderUnflushed => Some(2),
            Self::MetadataBodyUnflushed => Some(3),
            Self::MarkerUnflushed | Self::MarkerFlushedThenFailed => Some(4),
            _ => None,
        }
    }

    const fn after_flush(self) -> bool {
        matches!(self, Self::MarkerFlushedThenFailed)
    }

    const fn expects_new_state(self) -> bool {
        matches!(self, Self::MarkerFlushedThenFailed)
    }
}

struct CutSectorIo<'a> {
    inner: VirtioSectorIo<'a>,
    cut: CutPoint,
    writes: u32,
    flushes: u32,
}

impl SectorIo for CutSectorIo<'_> {
    fn capacity_sectors(&self) -> u64 {
        self.inner.capacity_sectors()
    }

    fn read_unit(
        &mut self,
        sector: u64,
        out: &mut [u8; STORAGE_UNIT_BYTES],
    ) -> Result<(), JournalError> {
        self.inner.read_unit(sector, out)
    }

    fn write_unit(
        &mut self,
        sector: u64,
        bytes: &[u8; STORAGE_UNIT_BYTES],
    ) -> Result<(), JournalError> {
        self.writes = self.writes.saturating_add(1);
        let target = self.cut.matches_unit(sector);
        if self.cut == CutPoint::MarkerUnflushed && target {
            // Simulate a marker present only in volatile cache when power is
            // lost before its required flush.
            return Ok(());
        }
        if target
            && matches!(
                self.cut,
                CutPoint::BlobBodyTorn
                    | CutPoint::BlobHeaderTorn
                    | CutPoint::MetadataBodyTorn
                    | CutPoint::MarkerTorn
            )
        {
            let mut mixed = [0u8; STORAGE_UNIT_BYTES];
            self.inner.read_unit(sector, &mut mixed)?;
            let boundary = if self.cut == CutPoint::MarkerTorn {
                14
            } else {
                STORAGE_UNIT_BYTES / 2
            };
            mixed[..boundary].copy_from_slice(&bytes[..boundary]);
            self.inner.write_unit(sector, &mixed)?;
            return Err(JournalError::Storage);
        }
        self.inner.write_unit(sector, bytes)
    }

    fn flush(&mut self) -> Result<(), JournalError> {
        self.flushes = self.flushes.saturating_add(1);
        if self.cut.flush_target() == Some(self.flushes) {
            if self.cut.after_flush() {
                self.inner.flush()?;
            }
            return Err(JournalError::Storage);
        }
        self.inner.flush()
    }
}

fn fault_package(index: u8) -> PackageSpec {
    PackageSpec {
        app_id: 0x4e41_5449_0000 + u64::from(index),
        publisher: 9,
        content: [0xa0u8.wrapping_add(index); 32],
        version: 1,
    }
}

fn verify_baseline(
    store: &mut PersistentInstallStore<VirtioSectorIo<'_>>,
    extra_package: bool,
) -> bool {
    let Some(package) = store.find_package(PACKAGE) else {
        return false;
    };
    let mut bytes = [0u8; 64];
    let Ok(length) = store.read_package_bytes(PACKAGE_CONTENT, &mut bytes) else {
        return false;
    };
    let state = store.state();
    let packages = state.packages.iter().flatten().count();
    length == PACKAGE_BYTES.len()
        && &bytes[..length] == PACKAGE_BYTES
        && packages == if extra_package { 2 } else { 1 }
        && store.installation_count_for(package) == 2
        && state.installations.iter().flatten().count() == 2
        && state.grants.iter().flatten().count() == 1
        && state.runtimes.iter().flatten().count() == 1
        && state.data.iter().flatten().count() == 1
}

fn run_fault_matrix(
    mut io: VirtioSectorIo<'_>,
) -> Result<(VirtioSectorIo<'_>, u8), PersistentInstallError> {
    let mut passed = 0u8;
    for (index, cut) in CutPoint::ALL.into_iter().enumerate() {
        kprintln!("[JSR-NATIVE-INSTALL] fault-begin={}", cut.name());
        let spec = fault_package(index as u8);
        let mut store = PersistentInstallStore::open(CutSectorIo {
            inner: VirtioSectorIo {
                device: &mut *io.device,
                base_sector: DATA_BASE_SECTOR,
            },
            cut,
            writes: 0,
            flushes: 0,
        })?;
        let injected = store.install_package(spec, b"fault-injected-package");
        kprintln!("[JSR-NATIVE-INSTALL] fault-injected={}", cut.name());
        let cut_io = store.into_device();
        let mut reopened = PersistentInstallStore::open(cut_io.inner)?;
        let package = reopened.find_package(spec);
        let state_ok = if cut.expects_new_state() {
            let Some(_package) = package else {
                check(false, cut.name());
                io = reopened.into_device();
                continue;
            };
            let mut bytes = [0u8; 64];
            let length = reopened.read_package_bytes(spec.content, &mut bytes)?;
            length == b"fault-injected-package".len()
                && &bytes[..length] == b"fault-injected-package"
        } else {
            package.is_none()
        };
        let baseline = verify_baseline(&mut reopened, cut.expects_new_state());
        if let Some(package) = package {
            reopened.destroy_package(package)?;
        }
        if injected.is_err() && state_ok && baseline {
            passed = passed.saturating_add(1);
            kprintln!(
                "[JSR-NATIVE-INSTALL] fault={} result={} baseline=true",
                cut.name(),
                if cut.expects_new_state() {
                    "new-complete"
                } else {
                    "old-preserved"
                }
            );
        } else {
            kprintln!(
                "[JSR-NATIVE-INSTALL] fault-detail={} injected_err={} state_ok={} baseline={}",
                cut.name(),
                injected.is_err(),
                state_ok,
                baseline
            );
            check(false, cut.name());
        }
        io = reopened.into_device();
    }
    Ok((io, passed))
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
    kprintln!("[JSR-NATIVE-INSTALL] reopen-step=package");
    let mut bytes = [0u8; 64];
    let bytes_len = store.read_package_bytes(PACKAGE_CONTENT, &mut bytes)?;
    kprintln!("[JSR-NATIVE-INSTALL] reopen-step=bytes");
    if &bytes[..bytes_len] != PACKAGE_BYTES || store.installation_count_for(package) != 2 {
        return Err(PersistentInstallError::Corrupt);
    }
    kprintln!("[JSR-NATIVE-INSTALL] reopen-step=counts");
    let state = store.state();
    if state.packages.iter().flatten().count() != 1
        || state.installations.iter().flatten().count() != 2
        || state.grants.iter().flatten().count() != 1
        || state.runtimes.iter().flatten().count() != 1
        || state.data.iter().flatten().count() != 1
    {
        return Err(PersistentInstallError::Corrupt);
    }
    kprintln!("[JSR-NATIVE-INSTALL] reopen-step=state");
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
    kprintln!("[JSR-NATIVE-INSTALL] reopen-step=authority");
    let (io, faults) = {
        let io = store.into_device();
        #[cfg(feature = "native-install-fault-verify")]
        {
            kprintln!("[JSR-NATIVE-INSTALL] reopen-step=fault-begin");
            run_fault_matrix(io)?
        }
        #[cfg(not(feature = "native-install-fault-verify"))]
        {
            (io, 0)
        }
    };
    let _ = io;
    kprintln!(
        "[JSR-NATIVE-INSTALL] stage=reopen packages=1 installations=2 grants=1 runtimes=1 data=1 bytes={} faults={} failed=0",
        bytes_len,
        faults
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
