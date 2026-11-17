//! Crash-safe persistent audit for Driver Host authority transitions.
//!
//! The journal stores only authority receipts, not live passes or requests.
//! Reopening therefore cannot revive a capability. An A/B metadata pair keeps
//! the previous complete receipt set until the next body and commit marker are
//! durable and read back. Host generations and terminal facts are replayed in
//! order so stale admission/reset/crash receipts fail closed.

use crate::fs::journal::{JournalError, SectorIo, SECTORS_PER_STORAGE_UNIT, STORAGE_UNIT_BYTES};
use alloc::boxed::Box;
use alloc::vec::Vec;

use super::{CrashReceipt, DeviceIdentity, HostToken, PassToken, QuiesceProof, ResetReceipt};

const FORMAT_MAGIC: &[u8; 8] = b"JSDHJNL1";
const MARKER_MAGIC: &[u8; 8] = b"JSDHMRK1";
const FORMAT_VERSION: u32 = 1;
const BODY_UNITS: usize = 2;
const SLOT_UNITS: usize = BODY_UNITS + 1;
const TOTAL_UNITS: usize = 2 * SLOT_UNITS;
const BODY_BYTES: usize = BODY_UNITS * STORAGE_UNIT_BYTES;
const HEADER_BYTES: usize = 16;
const EVENT_BYTES: usize = 64;
pub const MAX_DRIVER_HOST_EVENTS: usize = (BODY_BYTES - HEADER_BYTES) / EVENT_BYTES; // JASPER-HARDCODE-REVIEW: issue=33 source=storage-ABI-v1 reason=format-bound-derived-from-two-storage-units

/// One durable Driver Host authority transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DriverHostPersistentEvent {
    sequence: u64,
    kind: DriverHostPersistentEventKind,
    host_slot: u32,
    host_generation_before: u64,
    host_generation_after: u64,
    pass_generation: u64,
    device_identity: u32,
    device_generation: u32,
    cancelled: u32,
    revoked_passes: u32,
    quarantined_devices: u32,
    dma_quiesced: bool,
    irq_quiesced: bool,
}

/// The authoritative transition recorded by one persistent event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DriverHostPersistentEventKind {
    Registered,
    Admitted,
    Reset,
    Crashed,
    Recovered,
}

impl DriverHostPersistentEventKind {
    const fn raw(self) -> u8 {
        match self {
            Self::Registered => 1,
            Self::Admitted => 2,
            Self::Reset => 3,
            Self::Crashed => 4,
            Self::Recovered => 5,
        }
    }

    const fn from_raw(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Registered),
            2 => Some(Self::Admitted),
            3 => Some(Self::Reset),
            4 => Some(Self::Crashed),
            5 => Some(Self::Recovered),
            _ => None,
        }
    }
}

impl DriverHostPersistentEvent {
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    pub const fn kind(self) -> DriverHostPersistentEventKind {
        self.kind
    }

    pub const fn host_slot(self) -> u32 {
        self.host_slot
    }

    pub const fn host_generation_before(self) -> u64 {
        self.host_generation_before
    }

    pub const fn host_generation_after(self) -> u64 {
        self.host_generation_after
    }

    pub const fn pass_generation(self) -> u64 {
        self.pass_generation
    }

    pub const fn device_identity(self) -> u32 {
        self.device_identity
    }

    pub const fn device_generation(self) -> u32 {
        self.device_generation
    }

    pub const fn cancelled(self) -> u32 {
        self.cancelled
    }

    pub const fn revoked_passes(self) -> u32 {
        self.revoked_passes
    }

    pub const fn quarantined_devices(self) -> u32 {
        self.quarantined_devices
    }

    pub const fn dma_quiesced(self) -> bool {
        self.dma_quiesced
    }

    pub const fn irq_quiesced(self) -> bool {
        self.irq_quiesced
    }

    fn encode(self, out: &mut [u8]) {
        out[0] = self.kind.raw();
        out[1] = u8::from(self.dma_quiesced) | (u8::from(self.irq_quiesced) << 1);
        put_u32(out, 4, self.host_slot);
        put_u64(out, 8, self.sequence);
        put_u64(out, 16, self.host_generation_before);
        put_u64(out, 24, self.host_generation_after);
        put_u64(out, 32, self.pass_generation);
        put_u32(out, 40, self.device_identity);
        put_u32(out, 44, self.device_generation);
        put_u32(out, 48, self.cancelled);
        put_u32(out, 52, self.revoked_passes);
        put_u32(out, 56, self.quarantined_devices);
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != EVENT_BYTES || bytes[2..4] != [0, 0] || bytes[60..64] != [0, 0, 0, 0] {
            return None;
        }
        let flags = bytes[1];
        if flags & !3 != 0 {
            return None;
        }
        Some(Self {
            sequence: get_u64(bytes, 8),
            kind: DriverHostPersistentEventKind::from_raw(bytes[0])?,
            host_slot: get_u32(bytes, 4),
            host_generation_before: get_u64(bytes, 16),
            host_generation_after: get_u64(bytes, 24),
            pass_generation: get_u64(bytes, 32),
            device_identity: get_u32(bytes, 40),
            device_generation: get_u32(bytes, 44),
            cancelled: get_u32(bytes, 48),
            revoked_passes: get_u32(bytes, 52),
            quarantined_devices: get_u32(bytes, 56),
            dma_quiesced: flags & 1 != 0,
            irq_quiesced: flags & 2 != 0,
        })
    }
}

/// Persistent journal failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DriverHostJournalError {
    Io,
    InvalidFormat,
    Corrupt,
    Capacity,
    StaleGeneration,
    InvalidTransition,
}

impl DriverHostJournalError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Io => "system.driver-host.journal.error.io",
            Self::InvalidFormat => "system.driver-host.journal.error.format",
            Self::Corrupt => "system.driver-host.journal.error.corrupt",
            Self::Capacity => "system.driver-host.journal.error.capacity",
            Self::StaleGeneration => "system.driver-host.journal.error.stale_generation",
            Self::InvalidTransition => "system.driver-host.journal.error.transition",
        }
    }
}

/// Bounded crash-safe authority receipt journal.
pub struct DriverHostJournal<D: SectorIo, const HOSTS: usize> {
    device: D,
    sequence: u64,
    events: Box<[Option<DriverHostPersistentEvent>]>,
}

fn empty_events() -> Result<Box<[Option<DriverHostPersistentEvent>]>, DriverHostJournalError> {
    let mut events = Vec::new();
    events
        .try_reserve_exact(MAX_DRIVER_HOST_EVENTS)
        .map_err(|_| DriverHostJournalError::Capacity)?;
    events.resize(MAX_DRIVER_HOST_EVENTS, None);
    Ok(events.into_boxed_slice())
}

impl<D: SectorIo, const HOSTS: usize> DriverHostJournal<D, HOSTS> {
    /// Open an initialized journal, or format only a completely empty region.
    ///
    /// A non-zero region without a valid journal marker is rejected instead of
    /// being overwritten. This lets first boot initialize the reserved region
    /// while corrupt, foreign, or partially initialized storage fails closed.
    pub fn mount_with_status(mut device: D) -> Result<(Self, bool), DriverHostJournalError> {
        check_capacity(&device)?;
        let mut empty = true;
        let mut page = [0u8; STORAGE_UNIT_BYTES];
        for unit in 0..TOTAL_UNITS {
            device
                .read_unit(
                    (unit as u64)
                        .checked_mul(SECTORS_PER_STORAGE_UNIT)
                        .ok_or(DriverHostJournalError::Capacity)?,
                    &mut page,
                )
                .map_err(map_io)?;
            if page.iter().any(|byte| *byte != 0) {
                empty = false;
                break;
            }
        }
        if empty {
            Self::format(device).map(|journal| (journal, true))
        } else {
            Self::open(device).map(|journal| (journal, false))
        }
    }

    /// Open an initialized journal or initialize an empty reserved region.
    pub fn mount(device: D) -> Result<Self, DriverHostJournalError> {
        Self::mount_with_status(device).map(|(journal, _)| journal)
    }

    /// Initialize an empty authority journal.
    pub fn format(device: D) -> Result<Self, DriverHostJournalError> {
        check_capacity(&device)?;
        let mut journal = Self {
            device,
            sequence: 0,
            events: empty_events()?,
        };
        for slot in 0..2 {
            journal.write_unit(slot * SLOT_UNITS + BODY_UNITS, &[0u8; STORAGE_UNIT_BYTES])?;
        }
        journal.device.flush().map_err(map_io)?;
        journal.commit_slot(0)?;
        Ok(journal)
    }

    /// Open the newest complete A/B snapshot.
    pub fn open(mut device: D) -> Result<Self, DriverHostJournalError> {
        check_capacity(&device)?;
        let mut selected = None;
        for slot in 0..2 {
            if let Some((sequence, events)) = read_slot::<D, HOSTS>(&mut device, slot)? {
                if let Some((current, current_events)) = selected.as_ref() {
                    if sequence == *current && events != *current_events {
                        return Err(DriverHostJournalError::Corrupt);
                    }
                    if sequence <= *current {
                        continue;
                    }
                }
                selected = Some((sequence, events));
            }
        }
        let (sequence, events) = selected.ok_or(DriverHostJournalError::Corrupt)?;
        verify_chain::<HOSTS>(&events[..sequence as usize])?;
        Ok(Self {
            device,
            sequence,
            events,
        })
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn len(&self) -> usize {
        self.sequence as usize
    }

    pub fn is_empty(&self) -> bool {
        self.sequence == 0
    }

    pub fn event(&self, index: usize) -> Option<DriverHostPersistentEvent> {
        if index < self.sequence as usize {
            self.events[index]
        } else {
            None
        }
    }

    pub fn last(&self) -> Option<DriverHostPersistentEvent> {
        self.sequence
            .checked_sub(1)
            .and_then(|index| self.events[index as usize])
    }

    /// Persist a successful host registration.
    pub fn record_registration(
        &mut self,
        host: HostToken,
    ) -> Result<DriverHostPersistentEvent, DriverHostJournalError> {
        self.record(DriverHostPersistentEvent {
            sequence: 0,
            kind: DriverHostPersistentEventKind::Registered,
            host_slot: checked_slot(host.slot)?,
            host_generation_before: 0,
            host_generation_after: host.generation,
            pass_generation: 0,
            device_identity: 0,
            device_generation: 0,
            cancelled: 0,
            revoked_passes: 0,
            quarantined_devices: 0,
            dma_quiesced: false,
            irq_quiesced: false,
        })
    }

    /// Persist a successful device admission.
    pub fn record_admission(
        &mut self,
        host: HostToken,
        pass: PassToken,
        identity: DeviceIdentity,
    ) -> Result<DriverHostPersistentEvent, DriverHostJournalError> {
        if pass.host_generation != host.generation || !identity.is_valid() {
            return Err(DriverHostJournalError::InvalidTransition);
        }
        self.record(DriverHostPersistentEvent {
            sequence: 0,
            kind: DriverHostPersistentEventKind::Admitted,
            host_slot: checked_slot(host.slot)?,
            host_generation_before: host.generation,
            host_generation_after: host.generation,
            pass_generation: pass.generation,
            device_identity: identity.identity,
            device_generation: identity.generation,
            cancelled: 0,
            revoked_passes: 0,
            quarantined_devices: 0,
            dma_quiesced: false,
            irq_quiesced: false,
        })
    }

    /// Persist a completed orderly reset.
    pub fn record_reset(
        &mut self,
        host: HostToken,
        proof: QuiesceProof,
        receipt: ResetReceipt,
    ) -> Result<DriverHostPersistentEvent, DriverHostJournalError> {
        if receipt.token.slot != host.slot {
            return Err(DriverHostJournalError::InvalidTransition);
        }
        self.record(DriverHostPersistentEvent {
            sequence: 0,
            kind: DriverHostPersistentEventKind::Reset,
            host_slot: checked_slot(host.slot)?,
            host_generation_before: host.generation,
            host_generation_after: receipt.token.generation,
            pass_generation: 0,
            device_identity: 0,
            device_generation: 0,
            cancelled: checked_count(receipt.cancelled)?,
            revoked_passes: checked_count(receipt.revoked_passes)?,
            quarantined_devices: 0,
            dma_quiesced: proof.dma_quiesced,
            irq_quiesced: proof.irq_quiesced,
        })
    }

    /// Persist a crash with its quarantine decision.
    pub fn record_crash(
        &mut self,
        host: HostToken,
        proof: QuiesceProof,
        receipt: CrashReceipt,
    ) -> Result<DriverHostPersistentEvent, DriverHostJournalError> {
        self.record(DriverHostPersistentEvent {
            sequence: 0,
            kind: DriverHostPersistentEventKind::Crashed,
            host_slot: checked_slot(host.slot)?,
            host_generation_before: host.generation,
            host_generation_after: host.generation,
            pass_generation: 0,
            device_identity: 0,
            device_generation: 0,
            cancelled: checked_count(receipt.cancelled)?,
            revoked_passes: checked_count(receipt.revoked_passes)?,
            quarantined_devices: checked_count(receipt.quarantined_devices)?,
            dma_quiesced: proof.dma_quiesced,
            irq_quiesced: proof.irq_quiesced,
        })
    }

    /// Persist successful recovery and its fresh host generation.
    pub fn record_recovery(
        &mut self,
        crashed: HostToken,
        proof: QuiesceProof,
        recovered: HostToken,
    ) -> Result<DriverHostPersistentEvent, DriverHostJournalError> {
        if recovered.slot != crashed.slot {
            return Err(DriverHostJournalError::InvalidTransition);
        }
        self.record(DriverHostPersistentEvent {
            sequence: 0,
            kind: DriverHostPersistentEventKind::Recovered,
            host_slot: checked_slot(crashed.slot)?,
            host_generation_before: crashed.generation,
            host_generation_after: recovered.generation,
            pass_generation: 0,
            device_identity: 0,
            device_generation: 0,
            cancelled: 0,
            revoked_passes: 0,
            quarantined_devices: 0,
            dma_quiesced: proof.dma_quiesced,
            irq_quiesced: proof.irq_quiesced,
        })
    }

    fn record(
        &mut self,
        mut event: DriverHostPersistentEvent,
    ) -> Result<DriverHostPersistentEvent, DriverHostJournalError> {
        if self.len() >= MAX_DRIVER_HOST_EVENTS {
            return Err(DriverHostJournalError::Capacity);
        }
        let previous_sequence = self.sequence;
        let sequence = previous_sequence
            .checked_add(1)
            .ok_or(DriverHostJournalError::Capacity)?;
        event.sequence = sequence;
        self.validate_new_event(event)?;
        let index = previous_sequence as usize;
        self.events[index] = Some(event);
        self.sequence = sequence;
        if let Err(error) = self.commit_slot(((sequence as usize) & 1) as usize) {
            self.events[index] = None;
            self.sequence = previous_sequence;
            return Err(error);
        }
        Ok(event)
    }

    fn validate_new_event(
        &self,
        event: DriverHostPersistentEvent,
    ) -> Result<(), DriverHostJournalError> {
        if event.host_slot as usize >= HOSTS {
            return Err(DriverHostJournalError::Corrupt);
        }
        let previous = self.latest_for_host(event.host_slot as usize);
        if previous
            .is_some_and(|previous| previous.host_generation_after != event.host_generation_before)
        {
            return Err(DriverHostJournalError::StaleGeneration);
        }
        match event.kind {
            DriverHostPersistentEventKind::Registered => {
                if previous.is_some()
                    || event.host_generation_before != 0
                    || event.host_generation_after == 0
                    || event.pass_generation != 0
                    || event.device_identity != 0
                    || event.device_generation != 0
                {
                    return Err(DriverHostJournalError::InvalidTransition);
                }
            }
            DriverHostPersistentEventKind::Admitted => {
                if !host_can_operate(previous, event.host_generation_before)
                    || event.host_generation_after != event.host_generation_before
                    || event.pass_generation == 0
                    || event.device_identity == 0
                    || event.device_generation == 0
                    || event.cancelled != 0
                    || event.revoked_passes != 0
                    || event.quarantined_devices != 0
                {
                    return Err(DriverHostJournalError::InvalidTransition);
                }
            }
            DriverHostPersistentEventKind::Reset => {
                if !host_can_operate(previous, event.host_generation_before)
                    || event.host_generation_after != event.host_generation_before.saturating_add(1)
                    || !event.dma_quiesced
                    || !event.irq_quiesced
                {
                    return Err(DriverHostJournalError::InvalidTransition);
                }
            }
            DriverHostPersistentEventKind::Crashed => {
                if !host_can_operate(previous, event.host_generation_before)
                    || event.host_generation_after != event.host_generation_before
                {
                    return Err(DriverHostJournalError::InvalidTransition);
                }
            }
            DriverHostPersistentEventKind::Recovered => {
                if !previous.is_some_and(|previous| {
                    previous.kind == DriverHostPersistentEventKind::Crashed
                        && previous.host_generation_after == event.host_generation_before
                }) || event.host_generation_after
                    != event.host_generation_before.saturating_add(1)
                    || !event.dma_quiesced
                    || !event.irq_quiesced
                {
                    return Err(DriverHostJournalError::InvalidTransition);
                }
            }
        }
        Ok(())
    }

    fn latest_for_host(&self, host_slot: usize) -> Option<DriverHostPersistentEvent> {
        self.events[..self.sequence as usize]
            .iter()
            .flatten()
            .rev()
            .find(|event| event.host_slot as usize == host_slot)
            .copied()
    }

    fn commit_slot(&mut self, slot: usize) -> Result<(), DriverHostJournalError> {
        if slot >= 2 || self.sequence > MAX_DRIVER_HOST_EVENTS as u64 {
            return Err(DriverHostJournalError::Capacity);
        }
        let mut body = [0u8; BODY_BYTES];
        body[..8].copy_from_slice(FORMAT_MAGIC);
        put_u32(&mut body, 8, FORMAT_VERSION);
        put_u32(&mut body, 12, self.sequence as u32);
        for (index, event) in self.events[..self.sequence as usize]
            .iter()
            .flatten()
            .enumerate()
        {
            let at = HEADER_BYTES + index * EVENT_BYTES;
            event.encode(&mut body[at..at + EVENT_BYTES]);
        }
        let state_checksum = checksum(&body);
        let base = slot * SLOT_UNITS;
        for unit in 0..BODY_UNITS {
            let start = unit * STORAGE_UNIT_BYTES;
            let mut bytes = [0u8; STORAGE_UNIT_BYTES];
            bytes.copy_from_slice(&body[start..start + STORAGE_UNIT_BYTES]);
            self.write_unit(base + unit, &bytes)?;
        }
        let mut marker = [0u8; STORAGE_UNIT_BYTES];
        marker[..8].copy_from_slice(MARKER_MAGIC);
        put_u32(&mut marker, 8, FORMAT_VERSION);
        put_u64(&mut marker, 16, self.sequence);
        put_u64(&mut marker, 24, state_checksum);
        self.write_unit(base + BODY_UNITS, &marker)?;
        self.device.flush().map_err(map_io)?;

        let mut readback = [0u8; STORAGE_UNIT_BYTES];
        let marker_sector = ((base + BODY_UNITS) as u64)
            .checked_mul(SECTORS_PER_STORAGE_UNIT)
            .ok_or(DriverHostJournalError::Capacity)?;
        self.device
            .read_unit(marker_sector, &mut readback)
            .map_err(map_io)?;
        if readback != marker {
            return Err(DriverHostJournalError::Io);
        }
        Ok(())
    }

    fn write_unit(
        &mut self,
        unit: usize,
        bytes: &[u8; STORAGE_UNIT_BYTES],
    ) -> Result<(), DriverHostJournalError> {
        let sector = (unit as u64)
            .checked_mul(SECTORS_PER_STORAGE_UNIT)
            .ok_or(DriverHostJournalError::Capacity)?;
        self.device.write_unit(sector, bytes).map_err(map_io)
    }
}

fn read_slot<D: SectorIo, const HOSTS: usize>(
    device: &mut D,
    slot: usize,
) -> Result<
    Option<(
        u64,
        Box<[Option<DriverHostPersistentEvent>]>,
    )>,
    DriverHostJournalError,
> {
    let base = slot * SLOT_UNITS;
    let mut marker = [0u8; STORAGE_UNIT_BYTES];
    read_unit(device, base + BODY_UNITS, &mut marker)?;
    if marker.iter().all(|byte| *byte == 0) {
        return Ok(None);
    }
    if &marker[..8] != MARKER_MAGIC
        || get_u32(&marker, 8) != FORMAT_VERSION
        || marker[12..16].iter().any(|byte| *byte != 0)
        || marker[32..].iter().any(|byte| *byte != 0)
    {
        return Ok(None);
    }
    let sequence = get_u64(&marker, 16);
    if sequence > MAX_DRIVER_HOST_EVENTS as u64 {
        return Ok(None);
    }
    let mut body = [0u8; BODY_BYTES];
    for unit in 0..BODY_UNITS {
        let mut bytes = [0u8; STORAGE_UNIT_BYTES];
        read_unit(device, base + unit, &mut bytes)?;
        let start = unit * STORAGE_UNIT_BYTES;
        body[start..start + STORAGE_UNIT_BYTES].copy_from_slice(&bytes);
    }
    if &body[..8] != FORMAT_MAGIC
        || get_u32(&body, 8) != FORMAT_VERSION
        || u64::from(get_u32(&body, 12)) != sequence
        || get_u64(&marker, 24) != checksum(&body)
    {
        return Ok(None);
    }
    let mut events = empty_events()?;
    for index in 0..sequence as usize {
        let at = HEADER_BYTES + index * EVENT_BYTES;
        events[index] = DriverHostPersistentEvent::decode(&body[at..at + EVENT_BYTES]);
        if events[index].is_none() {
            return Ok(None);
        }
    }
    if verify_chain::<HOSTS>(&events[..sequence as usize]).is_err() {
        return Ok(None);
    }
    Ok(Some((sequence, events)))
}

fn verify_chain<const HOSTS: usize>(
    events: &[Option<DriverHostPersistentEvent>],
) -> Result<(), DriverHostJournalError> {
    let mut hosts_latest = [None::<DriverHostPersistentEvent>; HOSTS];
    for (index, entry) in events.iter().enumerate() {
        let event = entry.ok_or(DriverHostJournalError::Corrupt)?;
        if event.sequence != index as u64 + 1 {
            return Err(DriverHostJournalError::Corrupt);
        }
        let slot = event.host_slot as usize;
        if slot >= HOSTS {
            return Err(DriverHostJournalError::Corrupt);
        }
        let previous = hosts_latest[slot];
        match event.kind {
            DriverHostPersistentEventKind::Registered => {
                if previous.is_some()
                    || event.host_generation_before != 0
                    || event.host_generation_after == 0
                    || event.pass_generation != 0
                    || event.device_identity != 0
                    || event.device_generation != 0
                {
                    return Err(DriverHostJournalError::Corrupt);
                }
            }
            DriverHostPersistentEventKind::Admitted => {
                if !host_can_operate(previous, event.host_generation_before)
                    || event.host_generation_after != event.host_generation_before
                    || event.pass_generation == 0
                    || event.device_identity == 0
                    || event.device_generation == 0
                    || event.cancelled != 0
                    || event.revoked_passes != 0
                    || event.quarantined_devices != 0
                {
                    return Err(DriverHostJournalError::Corrupt);
                }
            }
            DriverHostPersistentEventKind::Reset => {
                if !host_can_operate(previous, event.host_generation_before)
                    || event.host_generation_after != event.host_generation_before.saturating_add(1)
                    || event.pass_generation != 0
                    || event.device_identity != 0
                    || event.device_generation != 0
                    || !event.dma_quiesced
                    || !event.irq_quiesced
                {
                    return Err(DriverHostJournalError::Corrupt);
                }
            }
            DriverHostPersistentEventKind::Crashed => {
                if !host_can_operate(previous, event.host_generation_before)
                    || event.host_generation_after != event.host_generation_before
                    || event.pass_generation != 0
                    || event.device_identity != 0
                    || event.device_generation != 0
                {
                    return Err(DriverHostJournalError::Corrupt);
                }
            }
            DriverHostPersistentEventKind::Recovered => {
                if !previous.is_some_and(|previous| {
                    previous.kind == DriverHostPersistentEventKind::Crashed
                        && previous.host_generation_after == event.host_generation_before
                }) || event.host_generation_after
                    != event.host_generation_before.saturating_add(1)
                    || event.pass_generation != 0
                    || event.device_identity != 0
                    || event.device_generation != 0
                    || event.cancelled != 0
                    || event.revoked_passes != 0
                    || event.quarantined_devices != 0
                    || !event.dma_quiesced
                    || !event.irq_quiesced
                {
                    return Err(DriverHostJournalError::Corrupt);
                }
            }
        }
        hosts_latest[slot] = Some(event);
    }
    Ok(())
}

fn host_can_operate(previous: Option<DriverHostPersistentEvent>, generation: u64) -> bool {
    previous.is_some_and(|event| {
        event.host_generation_after == generation
            && event.kind != DriverHostPersistentEventKind::Crashed
    })
}

fn check_capacity<D: SectorIo>(device: &D) -> Result<(), DriverHostJournalError> {
    let sectors = (TOTAL_UNITS as u64)
        .checked_mul(SECTORS_PER_STORAGE_UNIT)
        .ok_or(DriverHostJournalError::Capacity)?;
    if device.capacity_sectors() < sectors {
        return Err(DriverHostJournalError::Capacity);
    }
    Ok(())
}

fn read_unit<D: SectorIo>(
    device: &mut D,
    unit: usize,
    bytes: &mut [u8; STORAGE_UNIT_BYTES],
) -> Result<(), DriverHostJournalError> {
    let sector = (unit as u64)
        .checked_mul(SECTORS_PER_STORAGE_UNIT)
        .ok_or(DriverHostJournalError::Capacity)?;
    device.read_unit(sector, bytes).map_err(map_io)
}

fn checked_slot(slot: usize) -> Result<u32, DriverHostJournalError> {
    u32::try_from(slot).map_err(|_| DriverHostJournalError::Capacity)
}

fn checked_count(count: usize) -> Result<u32, DriverHostJournalError> {
    u32::try_from(count).map_err(|_| DriverHostJournalError::Capacity)
}

fn map_io(_: JournalError) -> DriverHostJournalError {
    DriverHostJournalError::Io
}

fn checksum(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn put_u32(out: &mut [u8], at: usize, value: u32) {
    out[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut [u8], at: usize, value: u64) {
    out[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn get_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn get_u64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver_host::{DeviceIdentity, DriverHostBroker, Needs, Policy};

    const UNITS: usize = 6;

    struct MemoryDisk {
        units: [[u8; STORAGE_UNIT_BYTES]; UNITS],
        fail_write: Option<usize>,
    }

    impl MemoryDisk {
        fn new() -> Self {
            Self {
                units: [[0; STORAGE_UNIT_BYTES]; UNITS],
                fail_write: None,
            }
        }
    }

    impl SectorIo for MemoryDisk {
        fn capacity_sectors(&self) -> u64 {
            (UNITS as u64) * SECTORS_PER_STORAGE_UNIT
        }

        fn read_unit(
            &mut self,
            sector: u64,
            out: &mut [u8; STORAGE_UNIT_BYTES],
        ) -> Result<(), JournalError> {
            let unit = usize::try_from(sector / SECTORS_PER_STORAGE_UNIT)
                .map_err(|_| JournalError::Storage)?;
            *out = *self.units.get(unit).ok_or(JournalError::Storage)?;
            Ok(())
        }

        fn write_unit(
            &mut self,
            sector: u64,
            bytes: &[u8; STORAGE_UNIT_BYTES],
        ) -> Result<(), JournalError> {
            let unit = usize::try_from(sector / SECTORS_PER_STORAGE_UNIT)
                .map_err(|_| JournalError::Storage)?;
            if self.fail_write == Some(unit) {
                return Err(JournalError::Storage);
            }
            let target = self.units.get_mut(unit).ok_or(JournalError::Storage)?;
            *target = *bytes;
            Ok(())
        }

        fn flush(&mut self) -> Result<(), JournalError> {
            Ok(())
        }
    }

    #[test]
    fn authority_receipts_survive_reopen_and_reject_stale_generations() {
        let disk = MemoryDisk::new();
        let mut journal = DriverHostJournal::<_, 2>::format(disk).unwrap();
        let mut broker = DriverHostBroker::<1, 2, 2, 2>::new();
        let identity = DeviceIdentity {
            identity: 0x1234,
            generation: 1,
        };
        let host = broker.register_host().unwrap();
        journal.record_registration(host).unwrap();
        broker.discover(identity).unwrap();
        let allowed = Needs::DEVICE.union(Needs::MMIO).union(Needs::IRQ);
        let pass = broker
            .admit(host, identity, allowed, Policy::new(allowed, 1, 0, 1))
            .unwrap();
        journal.record_admission(host, pass, identity).unwrap();
        let reset = broker.reset(host, QuiesceProof::CLEAN).unwrap();
        journal
            .record_reset(host, QuiesceProof::CLEAN, reset)
            .unwrap();
        let unclean = QuiesceProof {
            dma_quiesced: false,
            irq_quiesced: true,
        };
        let crashed = broker.crash(reset.token, unclean).unwrap();
        journal.record_crash(reset.token, unclean, crashed).unwrap();
        let recovered = broker.recover(reset.token, QuiesceProof::CLEAN).unwrap();
        journal
            .record_recovery(reset.token, QuiesceProof::CLEAN, recovered)
            .unwrap();

        let disk = journal.device;
        let mut opened = DriverHostJournal::<_, 2>::open(disk).unwrap();
        assert_eq!(opened.len(), 5);
        assert_eq!(
            opened.event(3).unwrap().quarantined_devices(),
            crashed.quarantined_devices as u32
        );
        assert_eq!(
            opened.last().unwrap().kind(),
            DriverHostPersistentEventKind::Recovered
        );
        assert_eq!(
            broker.reset(host, QuiesceProof::CLEAN),
            Err(crate::driver_host::Error::StaleHost)
        );
        let old_reset = ResetReceipt {
            cancelled: 0,
            revoked_passes: 0,
            token: host,
        };
        assert_eq!(
            opened.record_reset(host, QuiesceProof::CLEAN, old_reset),
            Err(DriverHostJournalError::StaleGeneration)
        );
    }

    #[test]
    fn mount_formats_only_an_empty_region_and_reopens_receipts() {
        let (mut journal, initialized) =
            DriverHostJournal::<_, 1>::mount_with_status(MemoryDisk::new()).unwrap();
        assert!(initialized);
        let mut broker = DriverHostBroker::<1, 1, 1, 1>::new();
        let identity = DeviceIdentity {
            identity: 0x1044,
            generation: 1,
        };
        let host = broker.register_host().unwrap();
        journal.record_registration(host).unwrap();
        broker.discover(identity).unwrap();
        let allowed = Needs::DEVICE.union(Needs::MMIO).union(Needs::IRQ);
        let pass = broker
            .admit(host, identity, allowed, Policy::new(allowed, 1, 0, 1))
            .unwrap();
        journal.record_admission(host, pass, identity).unwrap();

        let (reopened, initialized) =
            DriverHostJournal::<_, 1>::mount_with_status(journal.device).unwrap();
        assert!(!initialized);
        assert_eq!(reopened.len(), 2);
        assert_eq!(
            reopened.last().map(DriverHostPersistentEvent::kind),
            Some(DriverHostPersistentEventKind::Admitted)
        );

        let mut foreign = MemoryDisk::new();
        foreign.units[0][0] = 1;
        assert!(matches!(
            DriverHostJournal::<_, 1>::mount_with_status(foreign).err(),
            Some(
                DriverHostJournalError::InvalidFormat | DriverHostJournalError::Corrupt
            )
        ));
    }

    #[test]
    fn failed_marker_write_preserves_previous_complete_snapshot() {
        let mut journal = DriverHostJournal::<_, 1>::format(MemoryDisk::new()).unwrap();
        journal.device.fail_write = Some(5);
        let mut broker = DriverHostBroker::<1, 1, 1, 1>::new();
        let host = broker.register_host().unwrap();
        assert_eq!(
            journal.record_registration(host),
            Err(DriverHostJournalError::Io)
        );
        assert_eq!(journal.len(), 0);
        let disk = journal.device;
        let opened = DriverHostJournal::<_, 1>::open(disk).unwrap();
        assert!(opened.is_empty());
    }

    #[test]
    fn corrupt_newest_marker_falls_back_to_previous_complete_slot() {
        let mut journal = DriverHostJournal::<_, 1>::format(MemoryDisk::new()).unwrap();
        let mut broker = DriverHostBroker::<1, 1, 1, 1>::new();
        let host = broker.register_host().unwrap();
        journal.record_registration(host).unwrap();
        let reset = broker.reset(host, QuiesceProof::CLEAN).unwrap();
        journal
            .record_reset(host, QuiesceProof::CLEAN, reset)
            .unwrap();
        journal.device.units[2][0] ^= 1;
        let opened = DriverHostJournal::<_, 1>::open(journal.device).unwrap();
        assert_eq!(opened.len(), 1);
        assert_eq!(
            opened.last().unwrap().kind(),
            DriverHostPersistentEventKind::Registered
        );
    }
}
