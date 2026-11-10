//! Stable HWV-5 user-space VMM service ABI.
//!
//! This module is the single source of truth for the fixed service descriptor,
//! lifecycle generations and bounded VM-exit records shared by the kernel and
//! user-space VMM. It deliberately owns no Ring or vCPU object: those stay in
//! their existing subsystems, and the service consumes their outcomes.

use crate::hwvirt::Backend;

/// Version of the VMM service and VM-exit record layout.
pub const VMM_ABI_VERSION: u16 = 1;
/// Fixed byte length of [`VmmAbi`].
pub const VMM_ABI_BYTES: usize = 48;
/// Fixed byte length of [`VmExitRecord`].
pub const VM_EXIT_RECORD_BYTES: usize = 40;
/// A service may expose at most this many vCPUs in ABI version 1.
pub const MAX_SERVICE_VCPUS: u16 = 64;
/// User-visible control-page magic shared by acceptance and the service.
pub const VMM_CONTROL_MAGIC: u64 = 0x4857_5635_564d_4d31;
/// A fixed-size exit mailbox has eight slots in ABI version 1.
pub const VMM_EXIT_SLOTS: usize = 8;

/// Service capabilities advertised by the VMM ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmmFeatures(u64);

impl VmmFeatures {
    /// VM create/destroy lifecycle is represented.
    pub const VM_LIFECYCLE: Self = Self(1 << 0);
    /// vCPU state and run/halt transitions are represented.
    pub const VCPU_LIFECYCLE: Self = Self(1 << 1);
    /// VM exits are delivered as fixed records.
    pub const EXIT_EVENTS: Self = Self(1 << 2);
    /// A crashed service can be restarted with a new generation.
    pub const RESTART_GENERATION: Self = Self(1 << 3);

    /// All ABI-version-1 capabilities.
    pub const V1: Self = Self(
        Self::VM_LIFECYCLE.0
            | Self::VCPU_LIFECYCLE.0
            | Self::EXIT_EVENTS.0
            | Self::RESTART_GENERATION.0,
    );

    /// Raw bits.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Construct from bits only when no unknown capability is present.
    pub const fn from_bits(bits: u64) -> Option<Self> {
        if bits & !Self::V1.0 == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    /// Whether every bit in `required` is advertised.
    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }
}

/// Fixed-size service descriptor exchanged by the VMM supervisor and client.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmmAbi {
    pub version: u16,
    pub bytes: u16,
    pub backend: u8,
    pub state: u8,
    pub reserved0: u16,
    pub generation: u32,
    pub features: u64,
    pub max_vms: u16,
    pub max_vcpus: u16,
    pub max_guest_pages: u32,
    pub exit_record_bytes: u16,
    pub exit_slots: u16,
    pub abi_version: u32,
    pub reserved1: u32,
    pub reserved: [u8; 8],
}

const _: () = assert!(core::mem::size_of::<VmmAbi>() == VMM_ABI_BYTES);

impl VmmAbi {
    /// Construct the version-1 descriptor. `generation` must be non-zero and
    /// vCPU capacity must be in `1..=MAX_SERVICE_VCPUS`.
    pub fn new(
        backend: Backend,
        generation: u32,
        max_vms: u16,
        max_vcpus: u16,
        max_guest_pages: u32,
    ) -> Option<Self> {
        if generation == 0
            || max_vms == 0
            || max_vcpus == 0
            || max_vcpus > MAX_SERVICE_VCPUS
            || max_guest_pages == 0
        {
            return None;
        }
        Some(Self {
            version: VMM_ABI_VERSION,
            bytes: VMM_ABI_BYTES as u16,
            backend: backend_code(backend),
            state: ServiceState::Ready as u8,
            reserved0: 0,
            generation,
            features: VmmFeatures::V1.bits(),
            max_vms,
            max_vcpus,
            max_guest_pages,
            exit_record_bytes: VM_EXIT_RECORD_BYTES as u16,
            exit_slots: VMM_EXIT_SLOTS as u16,
            abi_version: crate::abi_version::NATIVE.packed() as u32,
            reserved1: 0,
            reserved: [0; 8],
        })
    }

    /// Validate and decode the exact fixed-size wire representation.
    pub fn decode(raw: &[u8; VMM_ABI_BYTES]) -> Option<Self> {
        let abi = Self {
            version: u16_at(raw, 0),
            bytes: u16_at(raw, 2),
            backend: raw[4],
            state: raw[5],
            reserved0: u16_at(raw, 6),
            generation: u32_at(raw, 8),
            features: u64_at(raw, 12),
            max_vms: u16_at(raw, 20),
            max_vcpus: u16_at(raw, 22),
            max_guest_pages: u32_at(raw, 24),
            exit_record_bytes: u16_at(raw, 28),
            exit_slots: u16_at(raw, 30),
            abi_version: u32_at(raw, 32),
            reserved1: u32_at(raw, 36),
            reserved: [
                raw[40], raw[41], raw[42], raw[43], raw[44], raw[45], raw[46], raw[47],
            ],
        };
        abi.validate().then_some(abi)
    }

    /// Exact little-endian wire form.
    pub fn encode(self) -> [u8; VMM_ABI_BYTES] {
        let mut raw = [0u8; VMM_ABI_BYTES];
        raw[0..2].copy_from_slice(&self.version.to_le_bytes());
        raw[2..4].copy_from_slice(&self.bytes.to_le_bytes());
        raw[4] = self.backend;
        raw[5] = self.state;
        raw[6..8].copy_from_slice(&self.reserved0.to_le_bytes());
        raw[8..12].copy_from_slice(&self.generation.to_le_bytes());
        raw[12..20].copy_from_slice(&self.features.to_le_bytes());
        raw[20..22].copy_from_slice(&self.max_vms.to_le_bytes());
        raw[22..24].copy_from_slice(&self.max_vcpus.to_le_bytes());
        raw[24..28].copy_from_slice(&self.max_guest_pages.to_le_bytes());
        raw[28..30].copy_from_slice(&self.exit_record_bytes.to_le_bytes());
        raw[30..32].copy_from_slice(&self.exit_slots.to_le_bytes());
        raw[32..36].copy_from_slice(&self.abi_version.to_le_bytes());
        raw[36..40].copy_from_slice(&self.reserved1.to_le_bytes());
        raw[40..48].copy_from_slice(&self.reserved);
        raw
    }

    /// Every field is checked; unknown versions, flags, backends and ABI widths
    /// fail closed rather than being silently ignored.
    pub fn validate(&self) -> bool {
        self.version == VMM_ABI_VERSION
            && self.bytes as usize == VMM_ABI_BYTES
            && backend_from_code(self.backend).is_some()
            && ServiceState::from_code(self.state).is_some()
            && self.reserved0 == 0
            && self.generation != 0
            && VmmFeatures::from_bits(self.features).is_some()
            && VmmFeatures::from_bits(self.features)
                .is_some_and(|features| features.contains(VmmFeatures::V1))
            && self.max_vms != 0
            && self.max_vcpus != 0
            && self.max_vcpus <= MAX_SERVICE_VCPUS
            && self.max_guest_pages != 0
            && self.exit_record_bytes as usize == VM_EXIT_RECORD_BYTES
            && self.exit_slots as usize == VMM_EXIT_SLOTS
            && self.abi_version != 0
            && self.reserved1 == 0
            && self.reserved == [0; 8]
    }

    /// Backend represented by a validated descriptor.
    pub fn backend(&self) -> Option<Backend> {
        backend_from_code(self.backend)
    }

    /// Lifecycle state represented by a validated descriptor.
    pub fn service_state(&self) -> Option<ServiceState> {
        ServiceState::from_code(self.state)
    }
}

/// Service lifecycle. Generations make stale descriptors and old service
/// instances distinguishable after a crash and restart.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceState {
    Detached = 0,
    Ready = 1,
    Running = 2,
    Failed = 3,
    Reclaimed = 4,
}

impl ServiceState {
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Detached),
            1 => Some(Self::Ready),
            2 => Some(Self::Running),
            3 => Some(Self::Failed),
            4 => Some(Self::Reclaimed),
            _ => None,
        }
    }
}

/// Service-generation state machine used by the kernel supervisor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceLifecycle {
    generation: u32,
    state: ServiceState,
}

impl ServiceLifecycle {
    /// First generation of a new service.
    pub const fn new() -> Self {
        Self { generation: 1, state: ServiceState::Detached }
    }

    pub const fn generation(self) -> u32 {
        self.generation
    }

    pub const fn state(self) -> ServiceState {
        self.state
    }

    /// Attach the process that owns the Ring and control page.
    pub fn attach(&mut self, generation: u32) -> bool {
        if self.state != ServiceState::Detached || generation != self.generation {
            return false;
        }
        self.state = ServiceState::Ready;
        true
    }

    /// Start one bounded VMM dispatch.
    pub fn begin(&mut self) -> bool {
        if self.state != ServiceState::Ready {
            return false;
        }
        self.state = ServiceState::Running;
        true
    }

    /// Return to Ready after a clean dispatch.
    pub fn finish(&mut self) -> bool {
        if self.state != ServiceState::Running {
            return false;
        }
        self.state = ServiceState::Ready;
        true
    }

    /// Process death permanently invalidates this generation.
    pub fn crash(&mut self) -> bool {
        if !matches!(self.state, ServiceState::Ready | ServiceState::Running) {
            return false;
        }
        self.state = ServiceState::Failed;
        true
    }

    /// Restart only from Failed and atomically advance the generation.
    pub fn recover(&mut self) -> Option<u32> {
        if self.state != ServiceState::Failed || self.generation == u32::MAX {
            return None;
        }
        self.generation += 1;
        self.state = ServiceState::Ready;
        Some(self.generation)
    }

    /// Terminal reclaim. Reusing the object never revives this generation.
    pub fn reclaim(&mut self) -> bool {
        if self.state == ServiceState::Reclaimed {
            return false;
        }
        self.state = ServiceState::Reclaimed;
        true
    }
}

impl Default for ServiceLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

/// One VM exit delivered to the VMM-facing side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmExitEvent {
    pub backend: Backend,
    pub reason: u32,
    pub qualification: u64,
    pub guest_physical: u64,
    pub vector: u8,
    pub instruction_length: u8,
}

impl VmExitEvent {
    /// Stable diagnostic name for the backend-independent event envelope.
    pub const fn name(self) -> &'static str {
        "system.hwvirt.vcpu.exit"
    }
}

/// Fixed-size user-visible exit record. It contains no pointers and can be
/// copied through a shared VMM control page or future messages unchanged.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmExitRecord {
    pub magic: u32,
    pub version: u16,
    pub bytes: u16,
    pub generation: u32,
    pub backend: u8,
    pub vector: u8,
    pub instruction_length: u8,
    pub reserved0: u8,
    pub reason: u32,
    pub qualification: u64,
    pub guest_physical: u64,
    pub reserved1: u32,
}

const _: () = assert!(core::mem::size_of::<VmExitRecord>() == VM_EXIT_RECORD_BYTES);

impl VmExitRecord {
    const MAGIC: u32 = 0x4558_4954;

    pub fn new(generation: u32, event: VmExitEvent) -> Option<Self> {
        if generation == 0 {
            return None;
        }
        Some(Self {
            magic: Self::MAGIC,
            version: VMM_ABI_VERSION,
            bytes: VM_EXIT_RECORD_BYTES as u16,
            generation,
            backend: backend_code(event.backend),
            vector: event.vector,
            instruction_length: event.instruction_length,
            reserved0: 0,
            reason: event.reason,
            qualification: event.qualification,
            guest_physical: event.guest_physical,
            reserved1: 0,
        })
    }

    pub fn decode(raw: &[u8; VM_EXIT_RECORD_BYTES]) -> Option<Self> {
        let record = Self {
            magic: u32_at(raw, 0),
            version: u16_at(raw, 4),
            bytes: u16_at(raw, 6),
            generation: u32_at(raw, 8),
            backend: raw[12],
            vector: raw[13],
            instruction_length: raw[14],
            reserved0: raw[15],
            reason: u32_at(raw, 16),
            qualification: u64_at(raw, 20),
            guest_physical: u64_at(raw, 28),
            reserved1: u32_at(raw, 36),
        };
        record.validate().then_some(record)
    }

    pub fn encode(self) -> [u8; VM_EXIT_RECORD_BYTES] {
        let mut raw = [0u8; VM_EXIT_RECORD_BYTES];
        raw[0..4].copy_from_slice(&self.magic.to_le_bytes());
        raw[4..6].copy_from_slice(&self.version.to_le_bytes());
        raw[6..8].copy_from_slice(&self.bytes.to_le_bytes());
        raw[8..12].copy_from_slice(&self.generation.to_le_bytes());
        raw[12] = self.backend;
        raw[13] = self.vector;
        raw[14] = self.instruction_length;
        raw[15] = self.reserved0;
        raw[16..20].copy_from_slice(&self.reason.to_le_bytes());
        raw[20..28].copy_from_slice(&self.qualification.to_le_bytes());
        raw[28..36].copy_from_slice(&self.guest_physical.to_le_bytes());
        raw[36..40].copy_from_slice(&self.reserved1.to_le_bytes());
        raw
    }

    pub fn validate(&self) -> bool {
        self.magic == Self::MAGIC
            && self.version == VMM_ABI_VERSION
            && self.bytes as usize == VM_EXIT_RECORD_BYTES
            && self.generation != 0
            && backend_from_code(self.backend).is_some()
            && self.reserved0 == 0
            && self.reserved1 == 0
    }

    pub fn event(&self) -> Option<VmExitEvent> {
        if !self.validate() {
            return None;
        }
        Some(VmExitEvent {
            backend: backend_from_code(self.backend)?,
            reason: self.reason,
            qualification: self.qualification,
            guest_physical: self.guest_physical,
            vector: self.vector,
            instruction_length: self.instruction_length,
        })
    }
}

const fn backend_code(backend: Backend) -> u8 {
    match backend {
        Backend::Vmx => 0,
        Backend::Svm => 1,
    }
}

const fn backend_from_code(code: u8) -> Option<Backend> {
    match code {
        0 => Some(Backend::Vmx),
        1 => Some(Backend::Svm),
        _ => None,
    }
}

fn u16_at(raw: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([raw[offset], raw[offset + 1]])
}

fn u32_at(raw: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        raw[offset],
        raw[offset + 1],
        raw[offset + 2],
        raw[offset + 3],
    ])
}

fn u64_at(raw: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        raw[offset],
        raw[offset + 1],
        raw[offset + 2],
        raw[offset + 3],
        raw[offset + 4],
        raw[offset + 5],
        raw[offset + 6],
        raw[offset + 7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> VmExitEvent {
        VmExitEvent {
            backend: Backend::Vmx,
            reason: 48,
            qualification: 0x1234,
            guest_physical: 0x20_0000,
            vector: 0,
            instruction_length: 3,
        }
    }

    #[test]
    fn service_abi_roundtrip_and_fail_closed_validation() {
        let abi = VmmAbi::new(Backend::Vmx, 7, 2, 8, 16384).unwrap();
        let raw = abi.encode();
        assert_eq!(VmmAbi::decode(&raw), Some(abi));
        assert!(abi.validate());
        let mut unknown = raw;
        unknown[12..20].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(VmmAbi::decode(&unknown).is_none());
        let mut generation = raw;
        generation[8..12].fill(0);
        assert!(VmmAbi::decode(&generation).is_none());
        let mut reserved = raw;
        reserved[47] = 1;
        assert!(VmmAbi::decode(&reserved).is_none());
    }

    #[test]
    fn exit_record_roundtrip_and_reserved_bytes_rejected() {
        let record = VmExitRecord::new(7, event()).unwrap();
        let raw = record.encode();
        assert_eq!(VmExitRecord::decode(&raw), Some(record));
        assert_eq!(record.event(), Some(event()));
        for offset in [0usize, 4, 6, 15, 36] {
            let mut bad = raw;
            bad[offset] ^= 1;
            assert!(VmExitRecord::decode(&bad).is_none(), "byte {offset}");
        }
        let mut bad_backend = raw;
        bad_backend[12] = 0xff;
        assert!(VmExitRecord::decode(&bad_backend).is_none());
    }

    #[test]
    fn lifecycle_generation_invalidates_old_service_after_crash() {
        let mut service = ServiceLifecycle::new();
        assert!(!service.begin());
        assert!(service.attach(1));
        assert!(service.begin());
        assert!(service.recover().is_none());
        assert!(service.crash());
        assert_eq!(service.state(), ServiceState::Failed);
        assert_eq!(service.recover(), Some(2));
        assert_eq!(service.state(), ServiceState::Ready);
        assert!(!service.attach(1));
        assert!(service.begin());
        assert!(service.finish());
        assert!(service.crash());
        assert_eq!(service.recover(), Some(3));
        assert!(service.reclaim());
        assert!(!service.reclaim());
        assert!(!service.attach(3));
    }
}
