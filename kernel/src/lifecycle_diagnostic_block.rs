//! Real virtio-blk persistence and bounded queries for LC-1 diagnostics.
//!
//! The first boot formats the diagnostic copies and records three events. The
//! next boot reopens the same device, verifies durable statistics, enforces the
//! privacy ceiling and appends one more event. Device access reuses the
//! existing BlockDevice Handle/Rights and DMA path.

use core::sync::atomic::{AtomicU32, Ordering};

use jasper_lifecycle_model::diagnostics::{
    ClockQuality, DiagnosticCollector, DiagnosticIo, DiagnosticIoError, DiagnosticPage,
    DiagnosticQuery, DiagnosticStoreError, EventInput, EventKind, PayloadKind, PrivacyClass,
    RecoveryAction, Severity, DIAGNOSTIC_COPY_STRIDE,
};
use kernel_core::block::{self, Request, Terminal};

use crate::blk::BlockDevice;
use crate::{baseline, kprintln, mmio, pci, virtio};

const DATA_PAGES: u64 = 1;
const DATA_BASE_SECTOR: u64 = 8192;
const DIAGNOSTIC_CAPACITY: usize = DIAGNOSTIC_COPY_STRIDE * 2;

static FAILED: AtomicU32 = AtomicU32::new(0);

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

fn check(condition: bool, what: &'static str) {
    if !condition {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-LIFE-DIAG-FAIL] {}", what);
    }
}

struct VirtioDiagnosticIo<'a> {
    device: &'a mut BlockDevice,
}

impl VirtioDiagnosticIo<'_> {
    fn sector(&self, block_index: usize) -> Result<u64, DiagnosticIoError> {
        let sectors = u64::try_from(block_index)
            .ok()
            .and_then(|index| index.checked_mul(block::SECTORS_PER_IO_UNIT))
            .ok_or(DiagnosticIoError::Read)?;
        let start = DATA_BASE_SECTOR
            .checked_add(sectors)
            .ok_or(DiagnosticIoError::Read)?;
        let end = start
            .checked_add(block::SECTORS_PER_IO_UNIT)
            .ok_or(DiagnosticIoError::Read)?;
        if end > self.device.geometry().capacity_sectors {
            return Err(DiagnosticIoError::Read);
        }
        Ok(start)
    }

    fn read_block(
        &mut self,
        block_index: usize,
    ) -> Result<[u8; block::IO_ALIGNMENT as usize], DiagnosticIoError> {
        let sector = self.sector(block_index)?;
        if !matches!(
            self.device.execute(Request::read(sector, 1), false),
            Ok(Terminal::Completed)
        ) {
            return Err(DiagnosticIoError::Read);
        }
        let mut bytes = [0u8; block::IO_ALIGNMENT as usize];
        self.device
            .copy_prefix(&mut bytes)
            .map_err(|_| DiagnosticIoError::Read)?;
        Ok(bytes)
    }

    fn write_block(
        &mut self,
        block_index: usize,
        bytes: &[u8; block::IO_ALIGNMENT as usize],
    ) -> Result<(), DiagnosticIoError> {
        let sector = self.sector(block_index)?;
        self.device
            .fill_pattern(0, bytes)
            .map_err(|_| DiagnosticIoError::Write)?;
        if !matches!(
            self.device.execute(Request::write(sector, 1, false), false),
            Ok(Terminal::Completed)
        ) {
            return Err(DiagnosticIoError::Write);
        }
        Ok(())
    }
}

impl DiagnosticIo for VirtioDiagnosticIo<'_> {
    fn capacity(&self) -> usize {
        DIAGNOSTIC_CAPACITY
    }

    fn read(&mut self, offset: usize, out: &mut [u8]) -> Result<(), DiagnosticIoError> {
        let end = offset
            .checked_add(out.len())
            .filter(|end| *end <= DIAGNOSTIC_CAPACITY)
            .ok_or(DiagnosticIoError::Read)?;
        let mut source = offset;
        let mut destination = 0;
        while source < end {
            let block_index = source / block::IO_ALIGNMENT as usize;
            let inner = source % block::IO_ALIGNMENT as usize;
            let take = (end - source).min(block::IO_ALIGNMENT as usize - inner);
            let block = self.read_block(block_index)?;
            out[destination..destination + take].copy_from_slice(&block[inner..inner + take]);
            source += take;
            destination += take;
        }
        Ok(())
    }

    fn write(&mut self, offset: usize, input: &[u8]) -> Result<(), DiagnosticIoError> {
        let end = offset
            .checked_add(input.len())
            .filter(|end| *end <= DIAGNOSTIC_CAPACITY)
            .ok_or(DiagnosticIoError::Write)?;
        let mut destination = offset;
        let mut source = 0;
        while destination < end {
            let block_index = destination / block::IO_ALIGNMENT as usize;
            let inner = destination % block::IO_ALIGNMENT as usize;
            let take = (end - destination).min(block::IO_ALIGNMENT as usize - inner);
            let mut block = if inner == 0 && take == block::IO_ALIGNMENT as usize {
                [0u8; block::IO_ALIGNMENT as usize]
            } else {
                self.read_block(block_index)?
            };
            block[inner..inner + take].copy_from_slice(&input[source..source + take]);
            self.write_block(block_index, &block)?;
            destination += take;
            source += take;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), DiagnosticIoError> {
        if matches!(
            self.device.execute(Request::flush(), false),
            Ok(Terminal::Completed)
        ) {
            Ok(())
        } else {
            Err(DiagnosticIoError::Flush)
        }
    }
}

fn event(
    kind: EventKind,
    severity: Severity,
    privacy: PrivacyClass,
    component: &'static str,
    observed_at: u64,
    transaction_id: u64,
) -> EventInput<'static> {
    EventInput {
        kind,
        severity,
        privacy,
        clock_quality: ClockQuality::Untrusted,
        observed_at,
        causes: &[],
        component,
        component_version: 1,
        transaction_id,
        boot_id: 1,
        platform_profile: [0x4c; 32],
        resource_pressure: [10, 20, 30, 0],
        recovery: RecoveryAction::None,
        payload_kind: PayloadKind::None,
        payload_reference: &[],
        payload_digest: [0; 32],
        redacted: true,
    }
}

fn exercise(device: &mut BlockDevice) -> Result<(&'static str, u64), DiagnosticStoreError> {
    match DiagnosticCollector::open(VirtioDiagnosticIo { device }) {
        Ok(mut collector) => {
            let status = collector.status();
            check(status.stats.len == 3, "reopen event count");
            check(status.stats.accepted == 3, "reopen accepted count");
            check(status.sequence == 4, "reopen sequence");
            let mut query =
                DiagnosticQuery::new(None, Severity::Warning, PrivacyClass::Internal, 4);
            let page = collector.query_page::<4>(&mut query);
            check(page.len() == 2, "privacy-filtered query count");
            check(
                (0..page.len()).all(|index| {
                    page.get(index)
                        .is_some_and(|event| event.privacy() <= PrivacyClass::Internal)
                }),
                "privacy ceiling",
            );
            collector
                .collect(event(
                    EventKind::Network,
                    Severity::Warning,
                    PrivacyClass::Public,
                    "system.network",
                    104,
                    4,
                ))
                .map_err(|error| match error {
                    jasper_lifecycle_model::diagnostics::CollectError::Store(error) => error,
                    jasper_lifecycle_model::diagnostics::CollectError::Schema(_) => {
                        DiagnosticStoreError::Corrupt
                    }
                })?;
            let status = collector.status();
            check(status.stats.len == 4, "append event count");
            check(status.stats.accepted == 4, "append accepted count");
            check(status.sequence == 5, "append sequence");
            Ok(("reopen", status.sequence))
        }
        Err(DiagnosticStoreError::Corrupt) => {
            let mut collector = DiagnosticCollector::format(VirtioDiagnosticIo { device })?;
            collector
                .collect(event(
                    EventKind::StorageCorruption,
                    Severity::Critical,
                    PrivacyClass::Public,
                    "system.storage",
                    101,
                    1,
                ))
                .map_err(|error| match error {
                    jasper_lifecycle_model::diagnostics::CollectError::Store(error) => error,
                    jasper_lifecycle_model::diagnostics::CollectError::Schema(_) => {
                        DiagnosticStoreError::Corrupt
                    }
                })?;
            collector
                .collect(event(
                    EventKind::ServiceCrash,
                    Severity::Warning,
                    PrivacyClass::Internal,
                    "system.service",
                    102,
                    2,
                ))
                .map_err(|error| match error {
                    jasper_lifecycle_model::diagnostics::CollectError::Store(error) => error,
                    jasper_lifecycle_model::diagnostics::CollectError::Schema(_) => {
                        DiagnosticStoreError::Corrupt
                    }
                })?;
            collector
                .collect(event(
                    EventKind::Network,
                    Severity::Critical,
                    PrivacyClass::Secret,
                    "system.network",
                    103,
                    3,
                ))
                .map_err(|error| match error {
                    jasper_lifecycle_model::diagnostics::CollectError::Store(error) => error,
                    jasper_lifecycle_model::diagnostics::CollectError::Schema(_) => {
                        DiagnosticStoreError::Corrupt
                    }
                })?;
            let status = collector.status();
            check(status.stats.len == 3, "format event count");
            check(status.stats.accepted == 3, "format accepted count");
            check(status.sequence == 4, "format sequence");
            Ok(("format", status.sequence))
        }
        Err(error) => Err(error),
    }
}

pub fn run() {
    kprintln!("[JSR-LIFE-DIAG] step=start");
    if let Err(error) = mmio::prepare_window() {
        check(false, error.name());
        return;
    }
    let before = baseline::baseline();
    let Some(device) = pci::table().devices().find(|device| {
        device.header.vendor == virtio::VIRTIO_VENDOR && virtio::is_blk_device(device.header.device)
    }) else {
        check(false, "no virtio-blk diagnostic device");
        return;
    };
    let result = BlockDevice::new(device, DATA_PAGES)
        .map_err(|_| DiagnosticStoreError::Io(DiagnosticIoError::Read));
    match result {
        Ok(mut blockdev) => match exercise(&mut blockdev) {
            Ok((phase, sequence)) => kprintln!(
                "[JSR-LIFE-DIAG] stage={} events={} sequence={} query=2 privacy=true append=true failed={}",
                phase,
                if phase == "format" { 3 } else { 4 },
                sequence,
                failed()
            ),
            Err(error) => {
                kprintln!("[JSR-LIFE-DIAG-FAIL] error={:?}", error);
                check(false, "diagnostic persistence exercise");
            }
        },
        Err(error) => {
            kprintln!("[JSR-LIFE-DIAG-FAIL] block={:?}", error);
            check(false, "diagnostic block setup");
        }
    }
    let after = baseline::baseline();
    check(after == before, "diagnostic resources return to baseline");
    kprintln!(
        "[JSR-LIFE-DIAG] summary failed={} resources={}",
        failed(),
        after == before
    );
}
