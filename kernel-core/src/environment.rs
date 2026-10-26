//! Author: chatgpt. ENV-0 executable contract; not a second scheduling policy.
//! Pure admission/observation simulation. Hardware discovery and per-core locking
//! belong to platform adapters and KRN-2; no sensor can manufacture capacity.
use crate::{sched::Qos, smp::CpuSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceKind { Cpu, Gpu, Accelerator, MemoryBandwidth }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source { Firmware, ArchitecturalCounter, Hypervisor, Estimated }
/// Capacity units are specific to a resource, never interchangeable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resource {
    pub id: u32, pub kind: ResourceKind, pub capacity_units: u32,
    pub reserved_units: u32, pub locality: u32, pub source: Source,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sample {
    pub source: Source, pub timestamp: u64, pub valid_for: u64,
    pub confidence: u8, pub capacity_ceiling: u32,
}
impl Sample {
    /// Future, expired, confidence-zero, malformed confidence => unknown.
    pub fn valid(self, now: u64) -> bool {
        self.confidence > 0 && self.confidence <= 100
            && now.checked_sub(self.timestamp).is_some_and(|age| age < self.valid_for)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Confidence { Unknown, Degraded, Normal }
/// Hysteresis and rate limiting for *recovery*. Safety reductions are immediate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Recovery {
    pub state: Confidence, pub healthy_samples: u8, pub last_change: u64,
}
impl Recovery {
    pub fn update(&mut self, healthy: bool, now: u64, min_interval: u64) {
        if !healthy {
            self.state = Confidence::Degraded;
            self.healthy_samples = 0;
            self.last_change = now;
        } else {
            self.healthy_samples = self.healthy_samples.saturating_add(1);
            if self.healthy_samples >= 3
                && now.checked_sub(self.last_change).is_some_and(|dt| dt >= min_interval) {
                self.state = Confidence::Normal;
                self.last_change = now;
            }
        }
    }
}
/// Same declaration carries QoS (existing POL-1 type), hard budget/affinity and
/// exclusive placement. Soft preference cannot participate in admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Demand {
    pub task: u64, pub budget_units: u32, pub affinity: CpuSet,
    pub exclusive: bool, pub criticality: u8, pub qos: Qos,
    pub soft_energy_preference: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lease { pub demand: Demand, pub cpu: usize }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject { InvalidPlatform, InvalidDemand, Duplicate, Capacity, Slots, Stale, VersionExhausted }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event { CapacityLost { task: u64, cpu: usize }, ObservationUnknown { cpu: usize } }
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan<const N: usize> {
    revision: u64, resource: Resource, cpu: usize, ceiling: u32,
    base: [Option<Lease>; N], leases: [Option<Lease>; N],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admission<const N: usize> {
    revision: u64, resource: Resource, cpu: usize, ceiling: u32,
    leases: [Option<Lease>; N],
}
impl<const N: usize> Admission<N> {
    pub fn new(resource: Resource, cpu: usize) -> Result<Self, Reject> {
        if resource.kind != ResourceKind::Cpu || cpu >= crate::smp::MAX_CPUS
            || resource.reserved_units > resource.capacity_units {
            return Err(Reject::InvalidPlatform);
        }
        Ok(Self { revision: 0, resource, cpu,
            ceiling: resource.capacity_units - resource.reserved_units, leases: [None; N] })
    }
    pub fn revision(&self) -> u64 { self.revision }
    pub fn leases(&self) -> &[Option<Lease>; N] { &self.leases }
    pub fn ceiling(&self) -> u32 { self.ceiling }
    pub fn used(&self) -> u32 {
        // All insertion is checked; private leases cannot exceed u32 capacity.
        self.leases.iter().flatten().map(|l| l.demand.budget_units).sum()
    }
    pub fn propose(&self, demand: Demand) -> Result<Plan<N>, Reject> {
        if demand.budget_units == 0 || !demand.affinity.contains(self.cpu) {
            return Err(Reject::InvalidDemand);
        }
        if self.leases.iter().flatten().any(|l| l.demand.task == demand.task) {
            return Err(Reject::Duplicate);
        }
        let occupied = self.leases.iter().flatten().next().is_some();
        if (demand.exclusive && occupied)
            || self.leases.iter().flatten().any(|l| l.demand.exclusive)
            || self.used().checked_add(demand.budget_units).is_none_or(|u| u > self.ceiling) {
            return Err(Reject::Capacity);
        }
        let mut leases = self.leases;
        let slot = leases.iter_mut().find(|l| l.is_none()).ok_or(Reject::Slots)?;
        *slot = Some(Lease { demand, cpu: self.cpu });
        Ok(Plan { revision: self.revision, resource: self.resource, cpu: self.cpu,
            ceiling: self.ceiling, base: self.leases, leases })
    }
    /// Caller holds target core's lock. Check version and platform, then publish
    /// the entire state without fallible work/callbacks. No cross-core atomicity.
    pub fn commit(&mut self, plan: Plan<N>) -> Result<(), Reject> {
        if plan.revision != self.revision || plan.resource != self.resource
            || plan.cpu != self.cpu || plan.ceiling != self.ceiling || plan.base != self.leases {
            return Err(Reject::Stale);
        }
        let next = self.revision.checked_add(1).ok_or(Reject::VersionExhausted)?;
        self.leases = plan.leases;
        self.revision = next;
        Ok(())
    }
    /// Unknown samples retain the previous conservative ceiling and all leases.
    /// A valid sample can only reduce the ceiling; recovery needs explicit
    /// revalidation of static facts (ENV-1), never a high sensor reading.
    /// Emit is caller-owned bounded local storage, never a hardware/IPC callback.
    pub fn observe(&mut self, sample: Option<Sample>, now: u64,
        mut emit: impl FnMut(Event)) -> Result<(), Reject> {
        let Some(sample) = sample.filter(|s| s.valid(now)) else {
            emit(Event::ObservationUnknown { cpu: self.cpu });
            return Ok(());
        };
        let ceiling = self.ceiling.min(sample.capacity_ceiling);
        if ceiling == self.ceiling { return Ok(()); }
        let next = self.revision.checked_add(1).ok_or(Reject::VersionExhausted)?;
        self.ceiling = ceiling;
        self.revision = next; // invalidate all previously prepared plans
        // Stable tie break: lower criticality first, then lower task ID.
        while self.used() > ceiling {
            let slot = self.leases.iter().enumerate().filter_map(|(i, l)|
                l.map(|l| (i, l.demand.criticality, l.demand.task)))
                .min_by_key(|&(_, criticality, task)| (criticality, task)).unwrap().0;
            let lease = self.leases[slot].take().unwrap();
            emit(Event::CapacityLost { task: lease.demand.task, cpu: self.cpu });
        }
        Ok(())
    }
}
/// Sensor cost is a local CPU-time budget (0.5%), not a latency promise.
/// u128 comparison avoids overflow even for arbitrary full-width counters.
pub fn sampling_within_budget(cpu_time: u64, sampled_time: u64) -> bool {
    cpu_time != 0 && (sampled_time as u128) * 200 <= cpu_time as u128
}

#[cfg(test)]
mod tests {
    use super::*;
    fn resource() -> Resource { Resource { id: 0, kind: ResourceKind::Cpu,
        capacity_units: 1000, reserved_units: 100, locality: 0, source: Source::Firmware } }
    fn demand(task: u64, units: u32) -> Demand { Demand { task, budget_units: units,
        affinity: CpuSet::first(1), exclusive: false, criticality: task as u8,
        qos: Qos::Interactive, soft_energy_preference: 0 } }
    fn sample(value: u32) -> Sample { Sample { source: Source::ArchitecturalCounter,
        timestamp: 10, valid_for: 5, confidence: 80, capacity_ceiling: value } }
    #[test]
    fn invalid_observations_preserve_admitted_guarantees() {
        let mut a = Admission::<2>::new(resource(), 0).unwrap();
        a.commit(a.propose(demand(1, 800)).unwrap()).unwrap();
        let before = a.clone();
        for s in [None, Some(sample(0)), Some(Sample { confidence: 0, ..sample(0) }),
            Some(Sample { timestamp: u64::MAX, ..sample(0) })] {
            a.observe(s, 15, |_| {}).unwrap();
            assert_eq!(a, before);
        }
    }
    #[test]
    fn competing_hard_plans_only_one_can_commit() {
        let mut a = Admission::<2>::new(resource(), 0).unwrap();
        let first = a.propose(demand(1, 600)).unwrap();
        let second = a.propose(demand(2, 600)).unwrap();
        a.commit(first).unwrap();
        let before = a.clone();
        assert_eq!(a.commit(second), Err(Reject::Stale));
        assert_eq!(a, before);
        assert_eq!(a.propose(demand(2, 600)), Err(Reject::Capacity));
    }
    #[test]
    fn degradation_sheds_least_critical_and_invalidates_plan() {
        let mut a = Admission::<4>::new(resource(), 0).unwrap();
        for t in 1..=3 { a.commit(a.propose(demand(t, 250)).unwrap()).unwrap(); }
        let pending = a.propose(demand(4, 100)).unwrap();
        let mut events = std::vec::Vec::new();
        a.observe(Some(sample(300)), 11, |e| events.push(e)).unwrap();
        assert_eq!(events, [Event::CapacityLost { task: 1, cpu: 0 }, Event::CapacityLost { task: 2, cpu: 0 }]);
        assert_eq!(a.used(), 250);
        assert_eq!(a.commit(pending), Err(Reject::Stale));
        a.observe(Some(sample(u32::MAX)), 11, |_| {}).unwrap();
        assert_eq!(a.ceiling(), 300);
    }
    #[test]
    fn affinity_exclusive_and_platform_validation() {
        assert_eq!(Admission::<2>::new(Resource { reserved_units: 1001, ..resource() }, 0), Err(Reject::InvalidPlatform));
        let mut a = Admission::<2>::new(resource(), 0).unwrap();
        assert_eq!(a.propose(Demand { affinity: CpuSet::first(0), ..demand(1, 1) }), Err(Reject::InvalidDemand));
        a.commit(a.propose(Demand { exclusive: true, ..demand(1, 1) }).unwrap()).unwrap();
        assert_eq!(a.propose(demand(2, 1)), Err(Reject::Capacity));
    }
    #[test]
    fn soft_preferences_never_change_admission() {
        let a = Admission::<1>::new(resource(), 0).unwrap();
        for preference in 0..=u8::MAX {
            assert!(a.propose(Demand { soft_energy_preference: preference, ..demand(1, 900) }).is_ok());
            assert_eq!(a.propose(Demand { soft_energy_preference: preference, ..demand(1, 901) }), Err(Reject::Capacity));
        }
    }
    #[test]
    fn hysteresis_and_sampling_budget() {
        let mut r = Recovery { state: Confidence::Unknown, healthy_samples: 0, last_change: 0 };
        r.update(false, 10, 5);
        for t in 11..=14 { r.update(true, t, 5); assert_eq!(r.state, Confidence::Degraded); }
        r.update(true, 15, 5); assert_eq!(r.state, Confidence::Normal);
        r.update(false, 16, 5); assert_eq!(r.state, Confidence::Degraded);
        assert!(sampling_within_budget(1000, 5));
        assert!(!sampling_within_budget(1000, 6));
        assert!(!sampling_within_budget(0, 0));
        assert!(!sampling_within_budget(u64::MAX, u64::MAX));
    }
    #[test]
    fn rejected_boundaries_are_atomic() {
        let mut a = Admission::<1>::new(Resource { capacity_units: u32::MAX,
            reserved_units: 0, ..resource() }, 0).unwrap();
        a.commit(a.propose(demand(1, u32::MAX)).unwrap()).unwrap();
        let before = a.clone();
        assert_eq!(a.propose(demand(2, 1)), Err(Reject::Capacity));
        assert_eq!(a, before);
        let empty = Admission::<0>::new(resource(), 0).unwrap();
        assert_eq!(empty.propose(demand(1, 1)), Err(Reject::Slots));
        let mut exhausted = Admission::<1>::new(resource(), 0).unwrap();
        exhausted.revision = u64::MAX;
        let p = exhausted.propose(demand(1, 1)).unwrap();
        assert_eq!(exhausted.commit(p), Err(Reject::VersionExhausted));
        assert_eq!(exhausted.used(), 0);
        assert_eq!(exhausted.observe(Some(sample(0)), 11, |_| {}), Err(Reject::VersionExhausted));
        assert_eq!(exhausted.ceiling(), 900);
    }
    #[test]
    fn divergent_snapshot_cannot_overwrite_current_lease() {
        let mut a = Admission::<3>::new(resource(), 0).unwrap();
        let mut other = a.clone();
        a.commit(a.propose(demand(1, 100)).unwrap()).unwrap();
        other.commit(other.propose(demand(2, 100)).unwrap()).unwrap();
        let unrelated = other.propose(demand(3, 100)).unwrap();
        let before = a.clone();
        assert_eq!(a.commit(unrelated), Err(Reject::Stale));
        assert_eq!(a, before);
        assert!(sample(0).valid(10));
        assert!(!sample(0).valid(15));
        assert!(!sample(0).valid(9));
    }
    #[test]
    fn deterministic_sensor_failure_campaign() {
        let mut seed = 0x454e_5630_u64;
        let mut a = Admission::<4>::new(resource(), 0).unwrap();
        for task in 1..=4 { a.commit(a.propose(demand(task, 200)).unwrap()).unwrap(); }
        for _ in 0..4096 {
            seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
            let old = a.ceiling();
            let s = Sample { timestamp: seed & 31, valid_for: (seed >> 5) & 7,
                confidence: (seed >> 12) as u8, ..sample((seed >> 32) as u32) };
            a.observe(Some(s), 20, |_| {}).unwrap();
            assert!(a.ceiling() <= old && a.used() <= a.ceiling());
        }
    }
}
