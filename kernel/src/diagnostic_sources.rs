//! Non-blocking kernel failure sources for the LC-1 diagnostic collector.
//!
//! Panic and boot-health failure paths append into a fixed-size local ring.
//! They never perform block I/O, allocate, or wait for a contended lock. A
//! normal collector later drains validated events into durable storage.

use core::sync::atomic::{AtomicU32, Ordering};

use jasper_lifecycle_model::diagnostics::{
    ClockQuality, CollectError, DiagnosticCollector, DiagnosticEvent, DiagnosticIo, EventInput,
    EventKind, PayloadKind, PrivacyClass, RecoveryAction, Severity, MAX_PAYLOAD_REFERENCE,
};

use crate::sync::IrqSpinLock;

const SOURCE_CAPACITY: usize = 4;

static STORED: AtomicU32 = AtomicU32::new(0);
static DROPPED: AtomicU32 = AtomicU32::new(0);
static CONTENDED: AtomicU32 = AtomicU32::new(0);

#[derive(Clone, Copy)]
pub struct SourceStats {
    pub stored: u32,
    pub dropped: u32,
    pub contended: u32,
    pub pending: usize,
}

struct SourceRing {
    events: [Option<DiagnosticEvent>; SOURCE_CAPACITY],
}

impl SourceRing {
    const fn new() -> Self {
        Self {
            events: [None; SOURCE_CAPACITY],
        }
    }

    fn len(&self) -> usize {
        self.events.iter().flatten().count()
    }

    fn push(&mut self, event: DiagnosticEvent) -> bool {
        let Some(slot) = self.events.iter_mut().find(|slot| slot.is_none()) else {
            return false;
        };
        *slot = Some(event);
        true
    }

    fn compact_after(&mut self, drained: usize) {
        let mut read = drained.min(self.events.len());
        let mut write = 0;
        while read < self.events.len() {
            if self.events[read].is_some() {
                self.events.swap(read, write);
                write += 1;
            }
            read += 1;
        }
        while write < self.events.len() {
            self.events[write] = None;
            write += 1;
        }
    }
}

static SOURCES: IrqSpinLock<SourceRing> = IrqSpinLock::new(SourceRing::new());

pub struct DrainReport {
    pub drained: usize,
    pub pending: usize,
}

fn record(input: EventInput<'_>) -> bool {
    let event = match DiagnosticEvent::new(input) {
        Ok(event) => event,
        Err(_) => {
            DROPPED.fetch_add(1, Ordering::Relaxed);
            return false;
        }
    };
    let Some(mut ring) = SOURCES.try_lock_bypass() else {
        CONTENDED.fetch_add(1, Ordering::Relaxed);
        DROPPED.fetch_add(1, Ordering::Relaxed);
        return false;
    };
    if ring.push(event) {
        STORED.fetch_add(1, Ordering::Relaxed);
        true
    } else {
        DROPPED.fetch_add(1, Ordering::Relaxed);
        false
    }
}

pub fn record_kernel_exception() -> bool {
    record(EventInput {
        kind: EventKind::KernelException,
        severity: Severity::Critical,
        privacy: PrivacyClass::Public,
        clock_quality: ClockQuality::Unknown,
        observed_at: 0,
        causes: &[],
        component: "kernel.panic",
        component_version: 1,
        transaction_id: 0,
        boot_id: 0,
        platform_profile: [0; 32],
        resource_pressure: [0; 4],
        recovery: RecoveryAction::None,
        payload_kind: PayloadKind::None,
        payload_reference: &[],
        payload_digest: [0; 32],
        redacted: true,
    })
}

pub fn record_boot_failure(reason: &str) -> bool {
    let payload: &[u8] =
        if !reason.is_empty() && reason.len() <= MAX_PAYLOAD_REFERENCE && reason.is_ascii() {
            reason.as_bytes()
        } else {
            b"boot-failure"
        };
    record(EventInput {
        kind: EventKind::UpdateBoot,
        severity: Severity::Critical,
        privacy: PrivacyClass::Internal,
        clock_quality: ClockQuality::Unknown,
        observed_at: 0,
        causes: &[],
        component: "kernel.health",
        component_version: 1,
        transaction_id: 0,
        boot_id: 0,
        platform_profile: [0; 32],
        resource_pressure: [0; 4],
        recovery: RecoveryAction::EnteredRecovery,
        payload_kind: PayloadKind::RedactedText,
        payload_reference: payload,
        payload_digest: [0; 32],
        redacted: true,
    })
}

pub fn stats() -> SourceStats {
    SourceStats {
        stored: STORED.load(Ordering::Relaxed),
        dropped: DROPPED.load(Ordering::Relaxed),
        contended: CONTENDED.load(Ordering::Relaxed),
        pending: SOURCES
            .try_lock_bypass()
            .map(|ring| ring.len())
            .unwrap_or(SOURCE_CAPACITY),
    }
}

fn event_input(event: &DiagnosticEvent) -> EventInput<'_> {
    EventInput {
        kind: event.kind(),
        severity: event.severity(),
        privacy: event.privacy(),
        clock_quality: event.clock_quality(),
        observed_at: event.observed_at(),
        causes: event.causes(),
        component: event.component(),
        component_version: event.component_version(),
        transaction_id: event.transaction_id(),
        boot_id: event.boot_id(),
        platform_profile: event.platform_profile(),
        resource_pressure: event.resource_pressure(),
        recovery: event.recovery(),
        payload_kind: event.payload_kind(),
        payload_reference: event.payload_reference(),
        payload_digest: event.payload_digest(),
        redacted: event.redacted(),
    }
}

pub fn drain_into<D: DiagnosticIo>(
    collector: &mut DiagnosticCollector<D>,
) -> Result<DrainReport, CollectError> {
    let Some(mut ring) = SOURCES.try_lock_bypass() else {
        return Ok(DrainReport {
            drained: 0,
            pending: SOURCE_CAPACITY,
        });
    };
    let mut drained = 0;
    while drained < ring.events.len() {
        let Some(event) = ring.events[drained] else {
            break;
        };
        collector.collect(event_input(&event))?;
        drained += 1;
    }
    ring.compact_after(drained);
    Ok(DrainReport {
        drained,
        pending: ring.len(),
    })
}
