//! HWV-7 GPU, heterogeneous-backend and unified-memory core contracts.
//!
//! 职责：验证 GPU 提交/完成生命周期、后端隔离要求、VF 世代和 U0–U4 能力阶梯。
//! 边界：不包含真实 GPU 命令、硬件队列或设备驱动。
//! Responsibility: fail-closed contracts for heterogeneous execution backends.

use crate::dma_quiesce::{quiesce_verdict, QuiesceVerdict, ResetOutcome};
use crate::iommu::DeviceId;
use crate::security_domain::DomainKey;

pub const QUEUE_CAPACITY: usize = 32;
pub const COMPLETION_CAPACITY: usize = 32;
pub const SUBMIT: u32 = 1 << 0;
pub const CANCEL: u32 = 1 << 1;
pub const CONTROL: u32 = 1 << 2;
pub const MAP_DEVICE: u32 = 1 << 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GpuBackend {
    VirtioGpu,
    Paravirtual,
    Passthrough,
    Mdev,
}

impl GpuBackend {
    pub const fn requires_iommu(self) -> bool {
        matches!(self, Self::Passthrough | Self::Mdev)
    }

    pub const fn exclusive(self) -> bool {
        matches!(self, Self::Passthrough | Self::Mdev)
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::VirtioGpu => "virtio-gpu",
            Self::Paravirtual => "paravirtual",
            Self::Passthrough => "passthrough",
            Self::Mdev => "mdev",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GpuIdentity {
    pub object: u64,
    pub generation: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GpuError {
    InvalidIdentity,
    InvalidBackend,
    MissingIommu,
    BackendBusy,
    WrongBackend,
    MissingRights,
    DuplicateRequest,
    QueueFull,
    RequestNotFound,
    InvalidTransition,
    StaleGeneration,
    CompletionFull,
    ResetUnsafe,
    TierOrder,
    TierUnsupported,
}

impl GpuError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidIdentity => "system.gpu.error.invalid_identity",
            Self::InvalidBackend => "system.gpu.error.invalid_backend",
            Self::MissingIommu => "system.gpu.error.missing_iommu",
            Self::BackendBusy => "system.gpu.error.backend_busy",
            Self::WrongBackend => "system.gpu.error.wrong_backend",
            Self::MissingRights => "system.gpu.error.rights",
            Self::DuplicateRequest => "system.gpu.error.duplicate_request",
            Self::QueueFull => "system.gpu.error.queue_full",
            Self::RequestNotFound => "system.gpu.error.request_not_found",
            Self::InvalidTransition => "system.gpu.error.invalid_transition",
            Self::StaleGeneration => "system.gpu.error.stale_generation",
            Self::CompletionFull => "system.gpu.error.completion_full",
            Self::ResetUnsafe => "system.gpu.error.reset_unsafe",
            Self::TierOrder => "system.gpu.error.memory_tier_order",
            Self::TierUnsupported => "system.gpu.error.memory_tier_unsupported",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestState {
    Submitted,
    Running,
    Completed,
    Cancelled,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GpuRequest {
    pub id: u64,
    pub generation: u32,
    pub state: RequestState,
    pub work_units: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Completion {
    pub sequence: u64,
    pub request: u64,
    pub queue_generation: u32,
    pub success: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GpuStats {
    pub submitted: u64,
    pub started: u64,
    pub completed: u64,
    pub cancelled: u64,
    pub failed: u64,
    pub resets: u64,
    pub doorbells: u64,
}

pub struct GpuQueue {
    identity: GpuIdentity,
    backend: GpuBackend,
    iommu: Option<DomainKey>,
    active: bool,
    requests: [Option<GpuRequest>; QUEUE_CAPACITY],
    completions: [Option<Completion>; COMPLETION_CAPACITY],
    completion_head: usize,
    completion_len: usize,
    next_request: u64,
    next_completion: u64,
    stats: GpuStats,
}

impl GpuQueue {
    pub fn bind(
        identity: GpuIdentity,
        backend: GpuBackend,
        iommu: Option<DomainKey>,
    ) -> Result<Self, GpuError> {
        if identity.object == 0 || identity.generation == 0 {
            return Err(GpuError::InvalidIdentity);
        }
        if backend.requires_iommu() && !iommu.is_some_and(|key| key.is_valid()) {
            return Err(GpuError::MissingIommu);
        }
        Ok(Self {
            identity,
            backend,
            iommu,
            active: true,
            requests: [None; QUEUE_CAPACITY],
            completions: [None; COMPLETION_CAPACITY],
            completion_head: 0,
            completion_len: 0,
            next_request: 1,
            next_completion: 1,
            stats: GpuStats::default(),
        })
    }

    pub const fn identity(&self) -> GpuIdentity {
        self.identity
    }

    pub const fn backend(&self) -> GpuBackend {
        self.backend
    }

    pub const fn iommu(&self) -> Option<DomainKey> {
        self.iommu
    }

    pub const fn stats(&self) -> GpuStats {
        self.stats
    }

    pub fn submit(
        &mut self,
        generation: u32,
        available_rights: u32,
        work_units: u32,
    ) -> Result<u64, GpuError> {
        self.check_generation(generation)?;
        if !self.active {
            return Err(GpuError::InvalidTransition);
        }
        if available_rights & SUBMIT == 0 {
            return Err(GpuError::MissingRights);
        }
        if work_units == 0 {
            return Err(GpuError::InvalidIdentity);
        }
        let slot = self
            .requests
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or(GpuError::QueueFull)?;
        let id = self.next_request;
        self.next_request = id.checked_add(1).ok_or(GpuError::QueueFull)?;
        *slot = Some(GpuRequest {
            id,
            generation,
            state: RequestState::Submitted,
            work_units,
        });
        self.stats.submitted = self.stats.submitted.saturating_add(1);
        Ok(id)
    }

    /// Doorbell publication is observable but never changes a request to complete.
    pub fn ring_doorbell(&mut self, generation: u32) -> Result<(), GpuError> {
        self.check_generation(generation)?;
        if !self.active {
            return Err(GpuError::InvalidTransition);
        }
        self.stats.doorbells = self.stats.doorbells.saturating_add(1);
        Ok(())
    }

    pub fn start(&mut self, request: u64) -> Result<(), GpuError> {
        let slot = self.request_slot(request)?;
        let entry = self.requests[slot]
            .as_mut()
            .ok_or(GpuError::RequestNotFound)?;
        if entry.state != RequestState::Submitted {
            return Err(GpuError::InvalidTransition);
        }
        entry.state = RequestState::Running;
        self.stats.started = self.stats.started.saturating_add(1);
        Ok(())
    }

    pub fn complete(&mut self, request: u64, success: bool) -> Result<Completion, GpuError> {
        let slot = self.request_slot(request)?;
        let entry = self.requests[slot].ok_or(GpuError::RequestNotFound)?;
        if entry.state != RequestState::Running {
            return Err(GpuError::InvalidTransition);
        }
        let next_completion = self
            .next_completion
            .checked_add(1)
            .ok_or(GpuError::CompletionFull)?;
        let completion = Completion {
            sequence: self.next_completion,
            request,
            queue_generation: self.identity.generation,
            success,
        };
        self.push_completion(completion)?;
        self.requests[slot]
            .as_mut()
            .ok_or(GpuError::RequestNotFound)?
            .state = if success {
            RequestState::Completed
        } else {
            RequestState::Failed
        };
        self.next_completion = next_completion;
        if success {
            self.stats.completed = self.stats.completed.saturating_add(1);
        } else {
            self.stats.failed = self.stats.failed.saturating_add(1);
        }
        Ok(completion)
    }

    pub fn cancel(
        &mut self,
        generation: u32,
        request: u64,
        available_rights: u32,
    ) -> Result<Completion, GpuError> {
        self.check_generation(generation)?;
        if available_rights & CANCEL == 0 {
            return Err(GpuError::MissingRights);
        }
        let slot = self.request_slot(request)?;
        let entry = self.requests[slot].ok_or(GpuError::RequestNotFound)?;
        if !matches!(entry.state, RequestState::Submitted | RequestState::Running) {
            return Err(GpuError::InvalidTransition);
        }
        let next_completion = self
            .next_completion
            .checked_add(1)
            .ok_or(GpuError::CompletionFull)?;
        let completion = Completion {
            sequence: self.next_completion,
            request,
            queue_generation: generation,
            success: false,
        };
        self.push_completion(completion)?;
        self.requests[slot]
            .as_mut()
            .ok_or(GpuError::RequestNotFound)?
            .state = RequestState::Cancelled;
        self.next_completion = next_completion;
        self.stats.cancelled = self.stats.cancelled.saturating_add(1);
        Ok(completion)
    }

    pub fn pop_completion(&mut self) -> Option<Completion> {
        if self.completion_len == 0 {
            return None;
        }
        let completion = self.completions[self.completion_head].take();
        self.completion_head = (self.completion_head + 1) % COMPLETION_CAPACITY;
        self.completion_len -= 1;
        if let Some(request) = completion {
            if let Some(slot) = self
                .requests
                .iter()
                .position(|value| value.is_some_and(|value| value.id == request.request))
            {
                self.requests[slot] = None;
            }
        }
        completion
    }

    pub fn reset(
        &mut self,
        generation: u32,
        reset: ResetOutcome,
        bus_master: Option<bool>,
    ) -> Result<GpuIdentity, GpuError> {
        self.check_generation(generation)?;
        if quiesce_verdict(reset, bus_master) == QuiesceVerdict::Quarantine {
            self.active = false;
            return Err(GpuError::ResetUnsafe);
        }
        let next = generation.checked_add(1).ok_or(GpuError::QueueFull)?;
        self.identity.generation = next;
        self.requests.fill(None);
        self.completions.fill(None);
        self.completion_head = 0;
        self.completion_len = 0;
        self.active = true;
        self.stats.resets = self.stats.resets.saturating_add(1);
        Ok(self.identity)
    }

    fn push_completion(&mut self, completion: Completion) -> Result<(), GpuError> {
        if self.completion_len == COMPLETION_CAPACITY {
            return Err(GpuError::CompletionFull);
        }
        let index = (self.completion_head + self.completion_len) % COMPLETION_CAPACITY;
        self.completions[index] = Some(completion);
        self.completion_len += 1;
        Ok(())
    }

    fn request_slot(&self, id: u64) -> Result<usize, GpuError> {
        self.requests
            .iter()
            .position(|entry| entry.is_some_and(|request| request.id == id))
            .ok_or(GpuError::RequestNotFound)
    }

    fn check_generation(&self, generation: u32) -> Result<(), GpuError> {
        if generation == self.identity.generation {
            Ok(())
        } else {
            Err(GpuError::StaleGeneration)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtualFunction {
    pub pf: DeviceId,
    pub id: u32,
    pub generation: u32,
    pub assigned: bool,
    pub quarantined: bool,
}

impl VirtualFunction {
    pub fn new(pf: DeviceId, id: u32) -> Result<Self, GpuError> {
        if pf.generation == 0 || id == 0 {
            return Err(GpuError::InvalidIdentity);
        }
        Ok(Self {
            pf,
            id,
            generation: 1,
            assigned: false,
            quarantined: false,
        })
    }

    pub fn assign(&mut self, iommu: Option<DomainKey>) -> Result<(), GpuError> {
        if self.quarantined {
            return Err(GpuError::InvalidTransition);
        }
        if !iommu.is_some_and(|domain| domain.is_valid()) {
            return Err(GpuError::MissingIommu);
        }
        if self.assigned {
            return Err(GpuError::BackendBusy);
        }
        self.assigned = true;
        Ok(())
    }

    pub fn release(
        &mut self,
        reset: ResetOutcome,
        bus_master: Option<bool>,
    ) -> Result<u32, GpuError> {
        if !self.assigned {
            return Err(GpuError::InvalidTransition);
        }
        self.assigned = false;
        let safe_reset = !matches!(
            quiesce_verdict(reset, bus_master),
            QuiesceVerdict::Quarantine
        );
        if !safe_reset {
            self.quarantined = true;
            return Err(GpuError::ResetUnsafe);
        }
        self.generation = self.generation.checked_add(1).ok_or(GpuError::QueueFull)?;
        Ok(self.generation)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum MemoryTier {
    U0,
    U1,
    U2,
    U3,
    U4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryTierState {
    highest: Option<MemoryTier>,
}

impl MemoryTierState {
    pub const fn new() -> Self {
        Self { highest: None }
    }

    pub const fn highest(&self) -> Option<MemoryTier> {
        self.highest
    }

    pub fn approve(&mut self, tier: MemoryTier, verified: bool) -> Result<(), GpuError> {
        if !verified {
            return Err(GpuError::TierUnsupported);
        }
        let expected = match self.highest {
            None => MemoryTier::U0,
            Some(MemoryTier::U0) => MemoryTier::U1,
            Some(MemoryTier::U1) => MemoryTier::U2,
            Some(MemoryTier::U2) => MemoryTier::U3,
            Some(MemoryTier::U3) => MemoryTier::U4,
            Some(MemoryTier::U4) => return Ok(()),
        };
        if tier != expected {
            return Err(GpuError::TierOrder);
        }
        self.highest = Some(tier);
        Ok(())
    }

    pub fn allows(&self, tier: MemoryTier) -> bool {
        self.highest.is_some_and(|highest| highest >= tier)
    }
}

impl Default for MemoryTierState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn queue(backend: GpuBackend, iommu: bool) -> GpuQueue {
        let domain = DomainKey {
            id: 1,
            generation: 1,
        };
        GpuQueue::bind(
            GpuIdentity {
                object: 1,
                generation: 1,
            },
            backend,
            iommu.then_some(domain),
        )
        .unwrap()
    }

    #[test]
    fn doorbell_does_not_complete_and_completion_requires_running() {
        let mut queue = queue(GpuBackend::VirtioGpu, false);
        let request = queue.submit(1, SUBMIT, 10).unwrap();
        queue.ring_doorbell(1).unwrap();
        assert_eq!(queue.stats().completed, 0);
        assert_eq!(
            queue.complete(request, true),
            Err(GpuError::InvalidTransition)
        );
        queue.start(request).unwrap();
        let completion = queue.complete(request, true).unwrap();
        assert!(completion.success);
        assert_eq!(queue.pop_completion(), Some(completion));
        assert_eq!(queue.stats().doorbells, 1);
    }

    #[test]
    fn consumed_completion_releases_the_request_slot() {
        let mut queue = queue(GpuBackend::VirtioGpu, false);
        let request = queue.submit(1, SUBMIT, 1).unwrap();
        queue.start(request).unwrap();
        let completion = queue.complete(request, true).unwrap();
        assert_eq!(queue.pop_completion(), Some(completion));
        assert_eq!(
            queue.complete(request, true),
            Err(GpuError::RequestNotFound)
        );
        let replacement = queue.submit(1, SUBMIT, 1).unwrap();
        assert_eq!(replacement, request + 1);
    }

    #[test]
    fn exclusive_backends_require_iommu_and_cancel_rights() {
        assert_eq!(
            GpuQueue::bind(
                GpuIdentity {
                    object: 1,
                    generation: 1
                },
                GpuBackend::Passthrough,
                None
            )
            .err(),
            Some(GpuError::MissingIommu)
        );
        let mut queue = queue(GpuBackend::Mdev, true);
        let request = queue.submit(1, SUBMIT, 4).unwrap();
        assert_eq!(queue.cancel(1, request, 0), Err(GpuError::MissingRights));
        let completion = queue.cancel(1, request, CANCEL).unwrap();
        assert!(!completion.success);
    }

    #[test]
    fn reset_revokes_old_completion_and_quarantine_fails_closed() {
        let mut queue = queue(GpuBackend::Passthrough, true);
        let request = queue.submit(1, SUBMIT, 4).unwrap();
        queue.start(request).unwrap();
        queue.complete(request, true).unwrap();
        let next = queue.reset(1, ResetOutcome::Done, Some(true)).unwrap();
        assert_eq!(next.generation, 2);
        assert_eq!(queue.pop_completion(), None);
        assert_eq!(queue.submit(1, SUBMIT, 4), Err(GpuError::StaleGeneration));
        assert_eq!(
            queue.reset(2, ResetOutcome::TimedOut, Some(true)),
            Err(GpuError::ResetUnsafe)
        );
        assert_eq!(queue.submit(2, SUBMIT, 4), Err(GpuError::InvalidTransition));
    }

    #[test]
    fn memory_tiers_cannot_skip_and_sriov_generation_never_revives() {
        let mut tiers = MemoryTierState::new();
        assert_eq!(
            tiers.approve(MemoryTier::U2, true),
            Err(GpuError::TierOrder)
        );
        for tier in [
            MemoryTier::U0,
            MemoryTier::U1,
            MemoryTier::U2,
            MemoryTier::U3,
            MemoryTier::U4,
        ] {
            tiers.approve(tier, true).unwrap();
        }
        assert!(tiers.allows(MemoryTier::U4));

        let device = DeviceId {
            segment: 0,
            bus: 1,
            device: 0,
            function: 0,
            generation: 1,
        };
        let domain = DomainKey {
            id: 1,
            generation: 1,
        };
        let mut vf = VirtualFunction::new(device, 1).unwrap();
        vf.assign(Some(domain)).unwrap();
        let generation = vf.release(ResetOutcome::Done, Some(false)).unwrap();
        assert_eq!(generation, 2);
        assert!(vf.release(ResetOutcome::Done, Some(false)).is_err());
        vf.assign(Some(domain)).unwrap();
        assert_eq!(
            vf.release(ResetOutcome::TimedOut, None),
            Err(GpuError::ResetUnsafe)
        );
        assert!(vf.quarantined);
        assert_eq!(vf.assign(Some(domain)), Err(GpuError::InvalidTransition));
    }
}
