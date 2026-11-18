//! Persistent Driver Host authority receipts on the validated P0 disk.
//!
//! This drill uses the same virtio-blk device and P0 GPT validation as lifecycle
//! services, but a separate bounded region. Reopening the journal restores
//! receipt history only; it never revives a live host, pass, request or
//! capability.

use alloc::sync::Arc;

use kernel_core::block::{self, Request, Terminal};
use kernel_core::driver_host::{
    DeviceIdentity, DriverHostBroker, DriverHostJournal, DriverHostJournalError,
    DriverHostPersistentEvent, DriverHostPersistentEventKind, Needs, Policy, QuiesceProof,
};
use kernel_core::driver_lifecycle::{
    admit_and_activate, crash_and_quarantine, recover_and_reactivate, reset_and_unload,
    AdmissionRequest, Controller, DriverAuthorization, LifecyclePolicy, OperatingMode, Package,
    State, TechnicalAdmission,
};
use kernel_core::fs::journal::{JournalError, SectorIo, STORAGE_UNIT_BYTES};
use kernel_core::native_install::{OwnerScope, Subject};

use crate::blk::BlockDevice;
use crate::sync::IrqSpinLock;
use crate::{mmio, pci, virtio};

const LIFECYCLE_SIGNER: [u8; 32] = [7; 32];
const LIFECYCLE_PACKAGE: [u8; 32] = [0x41; 32];
const LIFECYCLE_RECOVERY: [u8; 32] = [0x52; 32];

#[derive(Clone)]
struct P0JournalIo {
    device: Arc<IrqSpinLock<BlockDevice>>,
    base_sector: u64,
    sectors: u64,
}

impl P0JournalIo {
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

impl SectorIo for P0JournalIo {
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
        if !matches!(
            device.execute(Request::read(sector, 1), false),
            Ok(Terminal::Completed)
        ) {
            return Err(JournalError::Storage);
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
        device
            .fill_pattern(0, bytes)
            .map_err(|_| JournalError::Storage)?;
        if matches!(
            device.execute(Request::write(sector, 1, false), false),
            Ok(Terminal::Completed)
        ) {
            Ok(())
        } else {
            Err(JournalError::Storage)
        }
    }

    fn flush(&mut self) -> Result<(), JournalError> {
        if matches!(
            self.device.lock().execute(Request::flush(), false),
            Ok(Terminal::Completed)
        ) {
            Ok(())
        } else {
            Err(JournalError::Storage)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    pub initialized: bool,
    pub sequence: u64,
    pub device_identity: u32,
    pub device_generation: u32,
}

/// Reset a real virtio-rng transport and derive the same DMA/IRQ silence facts
/// consumed by the Driver Host and lifecycle controller.
fn rng_quiescence() -> Result<(DeviceIdentity, QuiesceProof), &'static str> {
    mmio::prepare_window().map_err(|_| "system.driver-host.journal.error.mmio")?;
    let device = pci::table()
        .devices()
        .find(|device| {
            device.header.vendor == virtio::VIRTIO_VENDOR
                && virtio::is_rng_device(device.header.device)
        })
        .ok_or("system.driver-host.journal.error.rng")?;
    let identity = DeviceIdentity {
        identity: kernel_core::device::pack_bdf(device.bdf),
        generation: 1,
    };
    let transport = virtio::VirtioPci::new(device)
        .map_err(|_| "system.driver-host.journal.error.rng_transport")?;
    pci::set_bus_master(device.bdf, true)
        .map_err(|_| "system.driver-host.journal.error.rng_bus_master")?;
    let reset = transport.reset().is_ok();
    let bus_master_off = pci::set_bus_master(device.bdf, false).is_ok()
        && pci::bus_master_enabled(device.bdf).is_ok_and(|enabled| !enabled);
    drop(transport);
    if !reset || !bus_master_off {
        return Err("system.driver-host.journal.error.rng_quiesce");
    }
    Ok((
        identity,
        QuiesceProof {
            dma_quiesced: bus_master_off,
            irq_quiesced: true,
        },
    ))
}

fn lifecycle_policy() -> LifecyclePolicy {
    LifecyclePolicy {
        trusted_signer: LIFECYCLE_SIGNER,
        revoked_signers: [[0; 32]; 4],
        release_floor: 0,
        security_epoch: 1,
        hotplug: true,
    }
}

fn admission(
    identity: DeviceIdentity,
    proof: QuiesceProof,
) -> AdmissionRequest {
    AdmissionRequest {
        authorization: DriverAuthorization {
            decision_maker: Subject::Device(u64::from(identity.identity)),
            executor: Subject::Service(7),
            scope: OwnerScope::Device(u64::from(identity.identity)),
            device_identity: identity.identity,
            device_generation: identity.generation,
            policy_epoch: 1,
            revocation_generation: 1,
            expires_at: None,
        },
        executor: Subject::Service(7),
        now: 1,
        current_policy_epoch: 1,
        current_revocation_generation: 1,
        device_identity: identity.identity,
        device_generation: identity.generation,
        technical: TechnicalAdmission {
            device_matches: true,
            abi_compatible: true,
            resource_scope_valid: true,
            isolation_required: false,
            isolation_verified: false,
            revocable: true,
            quiescence_verified: proof.dma_quiesced && proof.irq_quiesced,
            recovery_verified: true,
        },
        mode: OperatingMode::Production,
    }
}

fn journal_error(error: DriverHostJournalError) -> &'static str {
    error.name()
}

fn event_name(kind: DriverHostPersistentEventKind) -> &'static str {
    match kind {
        DriverHostPersistentEventKind::Registered => "registered",
        DriverHostPersistentEventKind::Admitted => "admitted",
        DriverHostPersistentEventKind::Reset => "reset",
        DriverHostPersistentEventKind::Crashed => "crashed",
        DriverHostPersistentEventKind::Recovered => "recovered",
    }
}

/// Mount the P0 journal. An empty region may be formatted; foreign or corrupt
/// non-empty storage is rejected without overwriting it.
pub fn run() -> Result<Report, &'static str> {
    crate::kprintln!("[JSR-DRIVER-HOST-JOURNAL] step=begin");
    crate::kprintln!("[JSR-DRIVER-HOST-JOURNAL] step=control");
    crate::lifecycle_health::init_control_backend()
        .map_err(|_| "system.driver-host.journal.error.p0")?;
    crate::kprintln!("[JSR-DRIVER-HOST-JOURNAL] step=control-ready");
    let device = crate::lifecycle_health::persistent_p0_device()
        .map_err(|_| "system.driver-host.journal.error.p0")?;
    crate::kprintln!("[JSR-DRIVER-HOST-JOURNAL] step=device");
    crate::kprintln!("[JSR-DRIVER-HOST-JOURNAL] step=mount");
    let io = P0JournalIo {
        device,
        base_sector: jasper_lifecycle_boot::P0_DRIVER_HOST_JOURNAL_LBA,
        sectors: jasper_lifecycle_boot::P0_DRIVER_HOST_JOURNAL_SECTORS,
    };
    let (mut journal, initialized) =
        DriverHostJournal::<_, 4>::mount_with_status(io).map_err(journal_error)?;
    crate::kprintln!(
        "[JSR-DRIVER-HOST-JOURNAL] step=mounted initialized={}",
        initialized
    );

    if initialized {
        crate::kprintln!("[JSR-DRIVER-HOST-JOURNAL] step=record");
        let (identity, proof) = rng_quiescence()?;
        let mut broker = DriverHostBroker::<1, 1, 1, 1>::new();
        broker
            .discover(identity)
            .map_err(|_| "system.driver-host.journal.error.discovery")?;
        let host = broker
            .register_host()
            .map_err(|_| "system.driver-host.journal.error.host")?;
        journal
            .record_registration(host)
            .map_err(journal_error)?;
        let allowed = Needs::DEVICE;
        let policy = Policy::new(allowed, 0, 0, 0);
        let mut lifecycle = Controller::new(
            lifecycle_policy(),
            Some(Package::verified(LIFECYCLE_RECOVERY, LIFECYCLE_SIGNER, 1, 1)),
        );
        let lease = admit_and_activate(
            &mut lifecycle,
            &mut broker,
            admission(identity, proof),
            Package::verified(LIFECYCLE_PACKAGE, LIFECYCLE_SIGNER, 2, 1),
            host,
            identity,
            allowed,
            policy,
        )
        .map_err(|_| "system.driver-host.journal.error.lifecycle_admission")?;
        if lifecycle.state() != State::Active || !lifecycle.owns_device(identity.generation) {
            return Err("system.driver-host.journal.error.lifecycle_binding");
        }
        journal
            .record_admission(host, lease.pass, identity)
            .map_err(journal_error)?;
        crate::kprintln!(
            "[JSR-DRIVER-HOST-LIFECYCLE] event=admitted host_generation={} pass_generation={} device=0x{:08x} device_generation={} package_generation={} dma_quiesced={} irq_quiesced={}",
            host.generation(),
            lease.pass.generation(),
            identity.identity,
            identity.generation,
            lease.package.generation,
            proof.dma_quiesced,
            proof.irq_quiesced
        );
        let crash = crash_and_quarantine(
            &mut lifecycle,
            &mut broker,
            host,
            identity.generation,
            proof,
        )
        .map_err(|_| "system.driver-host.journal.error.crash")?;
        journal
            .record_crash(host, proof, crash)
            .map_err(journal_error)?;
        crate::kprintln!(
            "[JSR-DRIVER-HOST-LIFECYCLE] event=crashed cancelled={} revoked_passes={} quarantined={} dma_quiesced={} irq_quiesced={}",
            crash.cancelled,
            crash.revoked_passes,
            crash.quarantined_devices,
            proof.dma_quiesced,
            proof.irq_quiesced
        );
        let recovered = recover_and_reactivate(&mut lifecycle, &mut broker, host, proof)
            .map_err(|_| "system.driver-host.journal.error.recovery")?;
        journal
            .record_recovery(host, proof, recovered)
            .map_err(journal_error)?;
        crate::kprintln!(
            "[JSR-DRIVER-HOST-LIFECYCLE] event=recovered host_generation={} dma_quiesced={} irq_quiesced={}",
            recovered.generation(),
            proof.dma_quiesced,
            proof.irq_quiesced
        );
        let (reset, _) = reset_and_unload(&mut lifecycle, &mut broker, recovered, proof)
            .map_err(|_| "system.driver-host.journal.error.reset")?;
        journal
            .record_reset(recovered, proof, reset)
            .map_err(journal_error)?;
        crate::kprintln!(
            "[JSR-DRIVER-HOST-LIFECYCLE] event=reset host_generation={} cancelled={} revoked_passes={} dma_quiesced={} irq_quiesced={}",
            reset.token.generation(),
            reset.cancelled,
            reset.revoked_passes,
            proof.dma_quiesced,
            proof.irq_quiesced
        );
    }

    let sequence = journal.sequence();
    if sequence != 5
        || journal
            .event(0)
            .is_none_or(|event| event.kind() != DriverHostPersistentEventKind::Registered)
        || journal.event(1).is_none_or(|event| {
            event.kind() != DriverHostPersistentEventKind::Admitted
                || event.device_identity() == 0
                || event.device_generation() == 0
        })
        || journal.event(2).is_none_or(|event| {
            event.kind() != DriverHostPersistentEventKind::Crashed
                || !event.dma_quiesced()
                || !event.irq_quiesced()
        })
        || journal
            .event(3)
            .is_none_or(|event| event.kind() != DriverHostPersistentEventKind::Recovered)
        || journal.event(4).is_none_or(|event| {
            event.kind() != DriverHostPersistentEventKind::Reset
                || !event.dma_quiesced()
                || !event.irq_quiesced()
        })
    {
        return Err("system.driver-host.journal.error.history");
    }
    if journal.event(3).is_some_and(|event| {
        event.host_generation_before().saturating_add(1) != event.host_generation_after()
    }) {
        return Err("system.driver-host.journal.error.recovery_generation");
    }
    let admitted_identity = journal
        .event(1)
        .map_or(0, DriverHostPersistentEvent::device_identity);
    let admitted_generation = journal
        .event(1)
        .map_or(0, DriverHostPersistentEvent::device_generation);
    crate::kprintln!(
        "[JSR-DRIVER-HOST-JOURNAL] mounted=true initialized={} sequence={} last={} device=0x{:08x} generation={} live_restored=false",
        initialized,
        sequence,
        journal
            .last()
            .map(|event| event_name(event.kind()))
            .unwrap_or("none"),
        admitted_identity,
        admitted_generation
    );
    Ok(Report {
        initialized,
        sequence,
        device_identity: admitted_identity,
        device_generation: admitted_generation,
    })
}
