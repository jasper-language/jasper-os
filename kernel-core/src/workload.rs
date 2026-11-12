//! Native workload identity, lifecycle and resource-admission contracts.
//!
//! This module is independent of Linux namespaces, cgroups, paths and UIDs.
//! A workload has a security-domain identity, explicit limits and one terminal state.
//!
//! 原生 Workload 身份、生命周期与资源准入契约。本模块独立于 Linux namespace、
//! cgroup、路径和 UID；Workload 具有安全域身份、显式资源上限和单一终态。

use crate::security_domain::DomainKey;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkloadKey {
    slot: u16,
    generation: u32,
}

impl WorkloadKey {
    pub const fn slot(self) -> u16 {
        self.slot
    }

    pub const fn generation(self) -> u32 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceLimits {
    pub cpu_permille: u32,
    pub memory_bytes: u64,
    pub threads: u32,
    pub ring_entries: u32,
}

impl ResourceLimits {
    pub const fn validate(self) -> Result<(), WorkloadError> {
        if self.cpu_permille == 0
            || self.cpu_permille > 1000
            || self.memory_bytes == 0
            || self.threads == 0
            || self.ring_entries == 0
        {
            Err(WorkloadError::InvalidLimit)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResourceUsage {
    pub memory_bytes: u64,
    pub threads: u32,
    pub ring_entries: u32,
}

impl ResourceUsage {
    fn checked_add(self, other: Self) -> Option<Self> {
        Some(Self {
            memory_bytes: self.memory_bytes.checked_add(other.memory_bytes)?,
            threads: self.threads.checked_add(other.threads)?,
            ring_entries: self.ring_entries.checked_add(other.ring_entries)?,
        })
    }

    fn checked_sub(self, other: Self) -> Option<Self> {
        Some(Self {
            memory_bytes: self.memory_bytes.checked_sub(other.memory_bytes)?,
            threads: self.threads.checked_sub(other.threads)?,
            ring_entries: self.ring_entries.checked_sub(other.ring_entries)?,
        })
    }

    fn within(self, limits: ResourceLimits) -> bool {
        self.memory_bytes <= limits.memory_bytes
            && self.threads <= limits.threads
            && self.ring_entries <= limits.ring_entries
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkloadState {
    Created,
    Ready,
    Running,
    Stopping,
    Stopped,
    Failed,
}

impl WorkloadState {
    pub const fn terminal(self) -> bool {
        matches!(self, Self::Stopped | Self::Failed)
    }

    fn can_transition(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Created, Self::Ready)
                | (Self::Ready, Self::Running)
                | (Self::Running, Self::Stopping)
                | (Self::Stopping, Self::Stopped)
                | (Self::Created, Self::Failed)
                | (Self::Ready, Self::Failed)
                | (Self::Running, Self::Failed)
                | (Self::Stopping, Self::Failed)
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkloadSnapshot {
    pub key: WorkloadKey,
    pub domain: DomainKey,
    pub state: WorkloadState,
    pub limits: ResourceLimits,
    pub usage: ResourceUsage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkloadError {
    InvalidDomain,
    InvalidKey,
    InvalidLimit,
    InvalidState,
    Quota,
    Capacity,
    IdExhausted,
}

impl WorkloadError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidDomain => "system.workload.error.domain",
            Self::InvalidKey => "system.workload.error.stale",
            Self::InvalidLimit => "system.workload.error.limit",
            Self::InvalidState => "system.workload.error.state",
            Self::Quota => "system.workload.error.quota",
            Self::Capacity => "system.workload.error.capacity",
            Self::IdExhausted => "system.workload.error.ids_exhausted",
        }
    }
}

#[derive(Clone, Copy)]
struct Record {
    key: WorkloadKey,
    domain: DomainKey,
    state: WorkloadState,
    limits: ResourceLimits,
    usage: ResourceUsage,
}

/// Fixed-capacity table. Every rejection leaves all records unchanged.
///
/// 固定容量表；任何拒绝都不改变已有记录。
pub struct WorkloadTable<const N: usize> {
    slots: [Option<Record>; N],
    generations: [u32; N],
}

impl<const N: usize> WorkloadTable<N> {
    pub const fn new() -> Self {
        Self {
            slots: [None; N],
            generations: [0; N],
        }
    }

    pub fn create(
        &mut self,
        domain: DomainKey,
        limits: ResourceLimits,
    ) -> Result<WorkloadKey, WorkloadError> {
        if !domain.is_valid() {
            return Err(WorkloadError::InvalidDomain);
        }
        limits.validate()?;
        let slot = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(WorkloadError::Capacity)?;
        let generation = self.generations[slot]
            .checked_add(1)
            .ok_or(WorkloadError::IdExhausted)?;
        let key = WorkloadKey {
            slot: slot as u16,
            generation,
        };
        self.generations[slot] = generation;
        self.slots[slot] = Some(Record {
            key,
            domain,
            state: WorkloadState::Created,
            limits,
            usage: ResourceUsage::default(),
        });
        Ok(key)
    }

    pub fn transition(
        &mut self,
        key: WorkloadKey,
        next: WorkloadState,
    ) -> Result<(), WorkloadError> {
        let record = self.record_mut(key)?;
        if !record.state.can_transition(next) {
            return Err(WorkloadError::InvalidState);
        }
        record.state = next;
        Ok(())
    }

    pub fn charge(&mut self, key: WorkloadKey, delta: ResourceUsage) -> Result<(), WorkloadError> {
        let record = self.record_mut(key)?;
        if record.state != WorkloadState::Running {
            return Err(WorkloadError::InvalidState);
        }
        let next = record
            .usage
            .checked_add(delta)
            .ok_or(WorkloadError::Quota)?;
        if !next.within(record.limits) {
            return Err(WorkloadError::Quota);
        }
        record.usage = next;
        Ok(())
    }

    pub fn release(&mut self, key: WorkloadKey, delta: ResourceUsage) -> Result<(), WorkloadError> {
        let record = self.record_mut(key)?;
        if !matches!(
            record.state,
            WorkloadState::Running | WorkloadState::Stopping
        ) {
            return Err(WorkloadError::InvalidState);
        }
        record.usage = record
            .usage
            .checked_sub(delta)
            .ok_or(WorkloadError::Quota)?;
        Ok(())
    }

    pub fn snapshot(&self, key: WorkloadKey) -> Result<WorkloadSnapshot, WorkloadError> {
        let record = self.record(key)?;
        Ok(WorkloadSnapshot {
            key: record.key,
            domain: record.domain,
            state: record.state,
            limits: record.limits,
            usage: record.usage,
        })
    }

    pub fn destroy(&mut self, key: WorkloadKey) -> Result<(), WorkloadError> {
        let index = key.slot as usize;
        let record = self.record(key)?;
        if !record.state.terminal() {
            return Err(WorkloadError::InvalidState);
        }
        if record.usage != ResourceUsage::default() {
            return Err(WorkloadError::Quota);
        }
        self.slots[index] = None;
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_some()).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn record(&self, key: WorkloadKey) -> Result<Record, WorkloadError> {
        self.slots
            .get(key.slot as usize)
            .and_then(|slot| *slot)
            .filter(|record| record.key == key)
            .ok_or(WorkloadError::InvalidKey)
    }

    fn record_mut(&mut self, key: WorkloadKey) -> Result<&mut Record, WorkloadError> {
        self.slots
            .get_mut(key.slot as usize)
            .and_then(Option::as_mut)
            .filter(|record| record.key == key)
            .ok_or(WorkloadError::InvalidKey)
    }
}

impl<const N: usize> Default for WorkloadTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOMAIN: DomainKey = DomainKey {
        id: 7,
        generation: 3,
    };
    const LIMITS: ResourceLimits = ResourceLimits {
        cpu_permille: 500,
        memory_bytes: 4096,
        threads: 4,
        ring_entries: 8,
    };

    #[test]
    fn identity_and_limits_fail_closed_without_partial_creation() {
        let mut table = WorkloadTable::<4>::new();
        assert_eq!(
            table.create(DomainKey::NONE, LIMITS),
            Err(WorkloadError::InvalidDomain)
        );
        assert_eq!(
            table.create(
                DOMAIN,
                ResourceLimits {
                    cpu_permille: 0,
                    ..LIMITS
                }
            ),
            Err(WorkloadError::InvalidLimit)
        );
        assert!(table.is_empty());
        let key = table.create(DOMAIN, LIMITS).unwrap();
        assert_eq!(table.snapshot(key).unwrap().state, WorkloadState::Created);
    }

    #[test]
    fn lifecycle_has_one_terminal_transition() {
        let mut table = WorkloadTable::<4>::new();
        let key = table.create(DOMAIN, LIMITS).unwrap();
        assert_eq!(
            table.transition(key, WorkloadState::Running),
            Err(WorkloadError::InvalidState)
        );
        table.transition(key, WorkloadState::Ready).unwrap();
        table.transition(key, WorkloadState::Running).unwrap();
        table.transition(key, WorkloadState::Stopping).unwrap();
        table.transition(key, WorkloadState::Stopped).unwrap();
        assert_eq!(
            table.transition(key, WorkloadState::Failed),
            Err(WorkloadError::InvalidState)
        );
    }

    #[test]
    fn quota_admission_is_exact_and_failure_atomic() {
        let mut table = WorkloadTable::<4>::new();
        let key = table.create(DOMAIN, LIMITS).unwrap();
        table.transition(key, WorkloadState::Ready).unwrap();
        table.transition(key, WorkloadState::Running).unwrap();
        let first = ResourceUsage {
            memory_bytes: 3072,
            threads: 3,
            ring_entries: 6,
        };
        table.charge(key, first).unwrap();
        let before = table.snapshot(key).unwrap().usage;
        assert_eq!(
            table.charge(
                key,
                ResourceUsage {
                    memory_bytes: 1025,
                    threads: 0,
                    ring_entries: 0,
                }
            ),
            Err(WorkloadError::Quota)
        );
        assert_eq!(table.snapshot(key).unwrap().usage, before);
        table
            .charge(
                key,
                ResourceUsage {
                    memory_bytes: 1024,
                    threads: 1,
                    ring_entries: 2,
                },
            )
            .unwrap();
        table.release(key, first).unwrap();
    }

    #[test]
    fn stale_generation_cannot_alias_reused_slot() {
        let mut table = WorkloadTable::<1>::new();
        let old = table.create(DOMAIN, LIMITS).unwrap();
        table.transition(old, WorkloadState::Failed).unwrap();
        table.destroy(old).unwrap();
        let new = table.create(DOMAIN, LIMITS).unwrap();
        assert_eq!(old.slot(), new.slot());
        assert_ne!(old.generation(), new.generation());
        assert_eq!(table.snapshot(old), Err(WorkloadError::InvalidKey));
        assert!(table.snapshot(new).is_ok());
    }

    #[test]
    fn workloads_have_independent_resource_accounts() {
        let mut table = WorkloadTable::<2>::new();
        let a = table.create(DOMAIN, LIMITS).unwrap();
        let b = table.create(DOMAIN, LIMITS).unwrap();
        for key in [a, b] {
            table.transition(key, WorkloadState::Ready).unwrap();
            table.transition(key, WorkloadState::Running).unwrap();
        }
        table
            .charge(
                a,
                ResourceUsage {
                    memory_bytes: 4096,
                    threads: 4,
                    ring_entries: 8,
                },
            )
            .unwrap();
        assert_eq!(table.snapshot(b).unwrap().usage, ResourceUsage::default());
    }
}
