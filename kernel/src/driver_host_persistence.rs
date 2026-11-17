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
    DriverHostPersistentEventKind, Needs, Policy,
};
use kernel_core::fs::journal::{JournalError, SectorIo, STORAGE_UNIT_BYTES};

use crate::blk::BlockDevice;
use crate::sync::IrqSpinLock;

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
    let identity = {
        let device = device.lock();
        DeviceIdentity {
            identity: kernel_core::device::pack_bdf(device.bdf()),
            generation: 1,
        }
    };
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
        let allowed = Needs::DEVICE
            .union(Needs::MMIO)
            .union(Needs::MMIO_WRITE)
            .union(Needs::DMA)
            .union(Needs::DMA_WRITE)
            .union(Needs::IRQ);
        let pass = broker
            .admit(host, identity, allowed, Policy::new(allowed, 1, 1, 1))
            .map_err(|_| "system.driver-host.journal.error.admission")?;
        journal
            .record_admission(host, pass, identity)
            .map_err(journal_error)?;
    }

    let sequence = journal.sequence();
    if sequence != 2
        || journal
            .event(0)
            .is_none_or(|event| event.kind() != DriverHostPersistentEventKind::Registered)
        || journal.event(1).is_none_or(|event| {
            event.kind() != DriverHostPersistentEventKind::Admitted
                || event.device_identity() != identity.identity
                || event.device_generation() != identity.generation
        })
    {
        return Err("system.driver-host.journal.error.history");
    }
    crate::kprintln!(
        "[JSR-DRIVER-HOST-JOURNAL] mounted=true initialized={} sequence={} last={} device=0x{:08x} generation={} live_restored=false",
        initialized,
        sequence,
        journal
            .last()
            .map(|event| event_name(event.kind()))
            .unwrap_or("none"),
        identity.identity,
        identity.generation
    );
    Ok(Report {
        initialized,
        sequence,
        device_identity: identity.identity,
        device_generation: identity.generation,
    })
}
