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

    /// Pack the generation and slot into a non-zero ABI scalar.
    ///
    /// 将世代和槽位打包为非零 ABI 标量；系统调用返回值不能携带引用。
    pub const fn to_raw(self) -> u64 {
        ((self.generation as u64) << 16) | self.slot as u64
    }

    /// Decode a scalar candidate. Table lookup remains the authority for
    /// liveness and generation validity.
    ///
    /// 解码候选标识；是否仍存活与世代是否有效仍以 Workload 表为准。
    pub const fn from_raw(raw: u64) -> Option<Self> {
        if raw == 0 || raw >> 48 != 0 || (raw >> 16) as u32 == 0 {
            return None;
        }
        Some(Self {
            slot: raw as u16,
            generation: (raw >> 16) as u32,
        })
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

    fn attenuates(self, parent: Self) -> bool {
        self.cpu_permille <= parent.cpu_permille
            && self.memory_bytes <= parent.memory_bytes
            && self.threads <= parent.threads
            && self.ring_entries <= parent.ring_entries
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
    pub parent: Option<WorkloadKey>,
    pub domain: DomainKey,
    pub state: WorkloadState,
    pub limits: ResourceLimits,
    pub usage: ResourceUsage,
    pub children: u16,
    pub child_cpu_permille: u32,
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
    parent: Option<WorkloadKey>,
    domain: DomainKey,
    state: WorkloadState,
    limits: ResourceLimits,
    usage: ResourceUsage,
    children: u16,
    child_cpu_permille: u32,
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
        self.create_record(domain, limits, None)
    }

    /// Creates a child with an attenuated subset of a running parent's authority.
    ///
    /// 在运行中的父 Workload 下创建子对象；子安全域与父相同且资源上限不能放大。
    pub fn create_child(
        &mut self,
        parent: WorkloadKey,
        limits: ResourceLimits,
    ) -> Result<WorkloadKey, WorkloadError> {
        let parent_record = self.record(parent)?;
        if parent_record.state != WorkloadState::Running {
            return Err(WorkloadError::InvalidState);
        }
        if !limits.attenuates(parent_record.limits) {
            return Err(WorkloadError::Quota);
        }
        if parent_record.children == u16::MAX {
            return Err(WorkloadError::IdExhausted);
        }
        self.create_record(parent_record.domain, limits, Some(parent))
    }

    fn create_record(
        &mut self,
        domain: DomainKey,
        limits: ResourceLimits,
        parent: Option<WorkloadKey>,
    ) -> Result<WorkloadKey, WorkloadError> {
        if !domain.is_valid() {
            return Err(WorkloadError::InvalidDomain);
        }
        limits.validate()?;
        if let Some(parent) = parent {
            let record = self.record(parent)?;
            if record
                .child_cpu_permille
                .checked_add(limits.cpu_permille)
                .is_none_or(|committed| committed > record.limits.cpu_permille)
            {
                return Err(WorkloadError::Quota);
            }
        }
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
            parent,
            domain,
            state: WorkloadState::Created,
            limits,
            usage: ResourceUsage::default(),
            children: 0,
            child_cpu_permille: 0,
        });
        if let Some(parent) = parent {
            let parent = self.record_mut(parent)?;
            parent.children = parent
                .children
                .checked_add(1)
                .ok_or(WorkloadError::IdExhausted)?;
            parent.child_cpu_permille = parent
                .child_cpu_permille
                .checked_add(limits.cpu_permille)
                .expect("preflighted parent CPU commitment");
        }
        Ok(key)
    }

    pub fn transition(
        &mut self,
        key: WorkloadKey,
        next: WorkloadState,
    ) -> Result<(), WorkloadError> {
        let record = self.record(key)?;
        if !record.state.can_transition(next) {
            return Err(WorkloadError::InvalidState);
        }
        // "Stopped" is an observable completion fact, not merely a request to
        // stop. It cannot become true while resources or child workloads remain.
        if next == WorkloadState::Stopped
            && (record.usage != ResourceUsage::default() || record.children != 0)
        {
            return Err(WorkloadError::InvalidState);
        }
        self.record_mut(key)?.state = next;
        Ok(())
    }

    pub fn charge(&mut self, key: WorkloadKey, delta: ResourceUsage) -> Result<(), WorkloadError> {
        let (path, len) = self.path(key)?;
        if self.record(key)?.state != WorkloadState::Running {
            return Err(WorkloadError::InvalidState);
        }
        for current in path.iter().take(len) {
            let record = self.record(*current)?;
            let next = record
                .usage
                .checked_add(delta)
                .ok_or(WorkloadError::Quota)?;
            if !next.within(record.limits) {
                return Err(WorkloadError::Quota);
            }
        }
        for current in path.iter().take(len) {
            let record = self.record_mut(*current)?;
            record.usage = record
                .usage
                .checked_add(delta)
                .ok_or(WorkloadError::Quota)?;
        }
        Ok(())
    }

    pub fn release(&mut self, key: WorkloadKey, delta: ResourceUsage) -> Result<(), WorkloadError> {
        let (path, len) = self.path(key)?;
        if matches!(
            self.record(key)?.state,
            WorkloadState::Created | WorkloadState::Ready
        ) {
            return Err(WorkloadError::InvalidState);
        }
        for current in path.iter().take(len) {
            let record = self.record(*current)?;
            record
                .usage
                .checked_sub(delta)
                .ok_or(WorkloadError::Quota)?;
        }
        for current in path.iter().take(len) {
            let record = self.record_mut(*current)?;
            record.usage = record
                .usage
                .checked_sub(delta)
                .ok_or(WorkloadError::Quota)?;
        }
        Ok(())
    }

    pub fn snapshot(&self, key: WorkloadKey) -> Result<WorkloadSnapshot, WorkloadError> {
        let record = self.record(key)?;
        Ok(WorkloadSnapshot {
            key: record.key,
            parent: record.parent,
            domain: record.domain,
            state: record.state,
            limits: record.limits,
            usage: record.usage,
            children: record.children,
            child_cpu_permille: record.child_cpu_permille,
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
        if record.children != 0 {
            return Err(WorkloadError::InvalidState);
        }
        if let Some(parent) = record.parent {
            if self.record(parent)?.children == 0 {
                return Err(WorkloadError::InvalidState);
            }
            if self.record(parent)?.child_cpu_permille < record.limits.cpu_permille {
                return Err(WorkloadError::InvalidState);
            }
        }
        self.slots[index] = None;
        if let Some(parent) = record.parent {
            let parent = self.record_mut(parent)?;
            parent.children = parent
                .children
                .checked_sub(1)
                .expect("preflighted parent child count");
            parent.child_cpu_permille = parent
                .child_cpu_permille
                .checked_sub(record.limits.cpu_permille)
                .expect("preflighted parent CPU commitment");
        }
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

    fn path(&self, key: WorkloadKey) -> Result<([WorkloadKey; N], usize), WorkloadError> {
        let mut path = [key; N];
        let mut len = 0usize;
        let mut current = Some(key);
        while let Some(key) = current {
            if len == N {
                return Err(WorkloadError::InvalidState);
            }
            let record = self.record(key)?;
            path[len] = key;
            len += 1;
            current = record.parent;
        }
        Ok((path, len))
    }
}

/// One process/task object assigned to a native workload.
///
/// 一个绑定到原生 Workload 的进程或任务对象。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkloadMember {
    pub id: u64,
    pub workload: WorkloadKey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MembershipError {
    InvalidMember,
    AlreadyAttached,
    NotRunning,
    InvalidKey,
    Capacity,
}

impl MembershipError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidMember => "system.workload.member.error.invalid",
            Self::AlreadyAttached => "system.workload.member.error.attached",
            Self::NotRunning => "system.workload.member.error.not_running",
            Self::InvalidKey => "system.workload.member.error.stale",
            Self::Capacity => "system.workload.member.error.capacity",
        }
    }
}

/// Fixed-capacity member mapping. One member has at most one workload.
///
/// 固定容量成员映射；一个成员最多属于一个 Workload。
pub struct WorkloadMembers<const N: usize> {
    slots: [Option<WorkloadMember>; N],
}

impl<const N: usize> WorkloadMembers<N> {
    pub const fn new() -> Self {
        Self { slots: [None; N] }
    }

    pub fn attach<const W: usize>(
        &mut self,
        table: &WorkloadTable<W>,
        workload: WorkloadKey,
        member: u64,
    ) -> Result<(), MembershipError> {
        if member == 0 {
            return Err(MembershipError::InvalidMember);
        }
        if self.find(member).is_some() {
            return Err(MembershipError::AlreadyAttached);
        }
        if table
            .snapshot(workload)
            .map_err(|_| MembershipError::InvalidKey)?
            .state
            != WorkloadState::Running
        {
            return Err(MembershipError::NotRunning);
        }
        let slot = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(MembershipError::Capacity)?;
        self.slots[slot] = Some(WorkloadMember {
            id: member,
            workload,
        });
        Ok(())
    }

    pub fn detach(&mut self, workload: WorkloadKey, member: u64) -> Result<(), MembershipError> {
        let slot = self
            .slots
            .iter()
            .position(|entry| {
                entry.is_some_and(|entry| entry.id == member && entry.workload == workload)
            })
            .ok_or(MembershipError::InvalidMember)?;
        self.slots[slot] = None;
        Ok(())
    }

    /// Explicitly moves a member after validating the destination is Running.
    ///
    /// 目标 Workload 处于 Running 时显式迁移成员；失败不改动原绑定。
    pub fn reassign<const W: usize>(
        &mut self,
        table: &WorkloadTable<W>,
        member: u64,
        destination: WorkloadKey,
    ) -> Result<(), MembershipError> {
        let slot = self.find(member).ok_or(MembershipError::InvalidMember)?;
        if self.slots[slot].is_some_and(|entry| entry.workload == destination) {
            return Ok(());
        }
        if table
            .snapshot(destination)
            .map_err(|_| MembershipError::InvalidKey)?
            .state
            != WorkloadState::Running
        {
            return Err(MembershipError::NotRunning);
        }
        self.slots[slot] = Some(WorkloadMember {
            id: member,
            workload: destination,
        });
        Ok(())
    }

    pub fn get(&self, member: u64) -> Option<WorkloadMember> {
        self.find(member).and_then(|slot| self.slots[slot])
    }

    pub fn len(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_some()).count()
    }

    pub fn count_for(&self, workload: WorkloadKey) -> usize {
        self.slots
            .iter()
            .flatten()
            .filter(|member| member.workload == workload)
            .count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn find(&self, member: u64) -> Option<usize> {
        self.slots
            .iter()
            .position(|entry| entry.is_some_and(|entry| entry.id == member))
    }
}

impl<const N: usize> Default for WorkloadMembers<N> {
    fn default() -> Self {
        Self::new()
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
        assert_eq!(WorkloadKey::from_raw(key.to_raw()), Some(key));
        assert_eq!(WorkloadKey::from_raw(0), None);
        assert_eq!(WorkloadKey::from_raw(1 << 48), None);
        assert_eq!(WorkloadKey::from_raw(1), None);
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

    #[test]
    fn child_resources_roll_up_and_require_ordered_destruction() {
        let mut table = WorkloadTable::<4>::new();
        let parent = table.create(DOMAIN, LIMITS).unwrap();
        table.transition(parent, WorkloadState::Ready).unwrap();
        table.transition(parent, WorkloadState::Running).unwrap();
        let child = table.create_child(parent, LIMITS).unwrap();
        table.transition(child, WorkloadState::Ready).unwrap();
        table.transition(child, WorkloadState::Running).unwrap();
        assert_eq!(table.snapshot(child).unwrap().parent, Some(parent));
        assert_eq!(table.snapshot(parent).unwrap().children, 1);

        let child_usage = ResourceUsage {
            memory_bytes: 4096,
            threads: 4,
            ring_entries: 8,
        };
        table.charge(child, child_usage).unwrap();
        assert_eq!(table.snapshot(child).unwrap().usage, child_usage);
        assert_eq!(table.snapshot(parent).unwrap().usage, child_usage);
        let snapshot = table.snapshot(parent).unwrap();
        assert_eq!(
            table.charge(
                parent,
                ResourceUsage {
                    memory_bytes: 1,
                    threads: 0,
                    ring_entries: 0,
                }
            ),
            Err(WorkloadError::Quota)
        );
        assert_eq!(table.snapshot(parent).unwrap(), snapshot);

        table.transition(child, WorkloadState::Stopping).unwrap();
        table.release(child, child_usage).unwrap();
        table.transition(child, WorkloadState::Stopped).unwrap();
        assert_eq!(table.destroy(parent), Err(WorkloadError::InvalidState));
        table.destroy(child).unwrap();
        assert_eq!(table.snapshot(parent).unwrap().children, 0);
        table.transition(parent, WorkloadState::Stopping).unwrap();
        table.transition(parent, WorkloadState::Stopped).unwrap();
        table.destroy(parent).unwrap();
        assert!(table.is_empty());
    }

    #[test]
    fn child_cannot_expand_parent_limits_or_cross_domain() {
        let mut table = WorkloadTable::<2>::new();
        let parent = table.create(DOMAIN, LIMITS).unwrap();
        assert_eq!(
            table.create_child(parent, LIMITS),
            Err(WorkloadError::InvalidState)
        );
        table.transition(parent, WorkloadState::Ready).unwrap();
        table.transition(parent, WorkloadState::Running).unwrap();
        assert_eq!(
            table.create_child(
                parent,
                ResourceLimits {
                    memory_bytes: LIMITS.memory_bytes + 1,
                    ..LIMITS
                }
            ),
            Err(WorkloadError::Quota)
        );
        let child = table.create_child(parent, LIMITS).unwrap();
        assert_eq!(table.snapshot(child).unwrap().domain, DOMAIN);
    }

    #[test]
    fn child_cpu_limits_are_admitted_across_direct_siblings() {
        let mut table = WorkloadTable::<4>::new();
        let parent = table
            .create(
                DOMAIN,
                ResourceLimits {
                    cpu_permille: 500,
                    ..LIMITS
                },
            )
            .unwrap();
        table.transition(parent, WorkloadState::Ready).unwrap();
        table.transition(parent, WorkloadState::Running).unwrap();
        let first = table
            .create_child(
                parent,
                ResourceLimits {
                    cpu_permille: 300,
                    ..LIMITS
                },
            )
            .unwrap();
        let before = table.snapshot(parent).unwrap();
        assert_eq!(
            table.create_child(
                parent,
                ResourceLimits {
                    cpu_permille: 201,
                    ..LIMITS
                }
            ),
            Err(WorkloadError::Quota)
        );
        assert_eq!(table.snapshot(parent).unwrap(), before);
        let second = table
            .create_child(
                parent,
                ResourceLimits {
                    cpu_permille: 200,
                    ..LIMITS
                },
            )
            .unwrap();
        assert_eq!(table.snapshot(parent).unwrap().child_cpu_permille, 500);
        table.transition(first, WorkloadState::Failed).unwrap();
        table.destroy(first).unwrap();
        assert_eq!(table.snapshot(parent).unwrap().child_cpu_permille, 200);
        table.transition(second, WorkloadState::Failed).unwrap();
        table.destroy(second).unwrap();
        assert_eq!(table.snapshot(parent).unwrap().child_cpu_permille, 0);
    }

    #[test]
    fn member_assignment_is_exclusive_and_requires_running_workloads() {
        let mut table = WorkloadTable::<2>::new();
        let first = table.create(DOMAIN, LIMITS).unwrap();
        let second = table.create(DOMAIN, LIMITS).unwrap();
        let mut members = WorkloadMembers::<2>::new();
        assert_eq!(
            members.attach(&table, first, 41),
            Err(MembershipError::NotRunning)
        );
        assert_eq!(
            members.attach(&table, first, 0),
            Err(MembershipError::InvalidMember)
        );
        for key in [first, second] {
            table.transition(key, WorkloadState::Ready).unwrap();
            table.transition(key, WorkloadState::Running).unwrap();
        }
        members.attach(&table, first, 41).unwrap();
        assert_eq!(
            members.attach(&table, second, 41),
            Err(MembershipError::AlreadyAttached)
        );
        assert_eq!(members.get(41).unwrap().workload, first);
        members.reassign(&table, 41, second).unwrap();
        assert_eq!(members.get(41).unwrap().workload, second);
        members.detach(second, 41).unwrap();
        assert!(members.is_empty());
    }

    #[test]
    fn failed_member_reassignment_keeps_the_original_binding() {
        let mut table = WorkloadTable::<2>::new();
        let running = table.create(DOMAIN, LIMITS).unwrap();
        let created = table.create(DOMAIN, LIMITS).unwrap();
        table.transition(running, WorkloadState::Ready).unwrap();
        table.transition(running, WorkloadState::Running).unwrap();
        let mut members = WorkloadMembers::<1>::new();
        members.attach(&table, running, 99).unwrap();
        assert_eq!(
            members.reassign(&table, 99, created),
            Err(MembershipError::NotRunning)
        );
        assert_eq!(members.get(99).unwrap().workload, running);
    }

    #[test]
    fn failed_workload_can_release_resources_before_destroy() {
        let mut table = WorkloadTable::<1>::new();
        let key = table.create(DOMAIN, LIMITS).unwrap();
        table.transition(key, WorkloadState::Ready).unwrap();
        table.transition(key, WorkloadState::Running).unwrap();
        let usage = ResourceUsage {
            memory_bytes: 4096,
            threads: 2,
            ring_entries: 1,
        };
        table.charge(key, usage).unwrap();
        table.transition(key, WorkloadState::Failed).unwrap();
        table.release(key, usage).unwrap();
        assert_eq!(table.snapshot(key).unwrap().usage, ResourceUsage::default());
        table.destroy(key).unwrap();
        assert!(table.is_empty());
    }

    #[test]
    fn stopped_requires_resources_and_children_to_be_gone() {
        let mut table = WorkloadTable::<2>::new();
        let parent = table.create(DOMAIN, LIMITS).unwrap();
        table.transition(parent, WorkloadState::Ready).unwrap();
        table.transition(parent, WorkloadState::Running).unwrap();
        let usage = ResourceUsage {
            memory_bytes: 4096,
            threads: 1,
            ring_entries: 0,
        };
        table.charge(parent, usage).unwrap();
        let child = table.create_child(parent, LIMITS).unwrap();
        table.transition(parent, WorkloadState::Stopping).unwrap();

        let before = table.snapshot(parent).unwrap();
        assert_eq!(
            table.transition(parent, WorkloadState::Stopped),
            Err(WorkloadError::InvalidState)
        );
        assert_eq!(table.snapshot(parent).unwrap(), before);

        table.release(parent, usage).unwrap();
        assert_eq!(table.snapshot(parent).unwrap().children, 1);
        assert_eq!(
            table.transition(parent, WorkloadState::Stopped),
            Err(WorkloadError::InvalidState)
        );
        assert_eq!(
            table.snapshot(parent).unwrap().state,
            WorkloadState::Stopping
        );

        table.transition(child, WorkloadState::Failed).unwrap();
        table.destroy(child).unwrap();
        table.transition(parent, WorkloadState::Stopped).unwrap();
        assert_eq!(
            table.snapshot(parent).unwrap().state,
            WorkloadState::Stopped
        );
    }

    #[test]
    fn member_counts_are_scoped_per_workload() {
        let mut table = WorkloadTable::<2>::new();
        let first = table.create(DOMAIN, LIMITS).unwrap();
        let second = table.create(DOMAIN, LIMITS).unwrap();
        for key in [first, second] {
            table.transition(key, WorkloadState::Ready).unwrap();
            table.transition(key, WorkloadState::Running).unwrap();
        }
        let mut members = WorkloadMembers::<3>::new();
        members.attach(&table, first, 1).unwrap();
        members.attach(&table, first, 2).unwrap();
        members.attach(&table, second, 3).unwrap();
        assert_eq!(members.count_for(first), 2);
        assert_eq!(members.count_for(second), 1);
        members.detach(first, 1).unwrap();
        assert_eq!(members.count_for(first), 1);
    }

    #[test]
    fn shared_mapping_aliases_consume_independent_admitted_bytes() {
        let mut table = WorkloadTable::<1>::new();
        let key = table
            .create(
                DOMAIN,
                ResourceLimits {
                    memory_bytes: 8192,
                    ..LIMITS
                },
            )
            .unwrap();
        table.transition(key, WorkloadState::Ready).unwrap();
        table.transition(key, WorkloadState::Running).unwrap();
        let one_page = ResourceUsage {
            memory_bytes: crate::frame::FRAME_SIZE as u64,
            threads: 0,
            ring_entries: 0,
        };
        table.charge(key, one_page).unwrap();
        table.charge(key, one_page).unwrap();
        let before = table.snapshot(key).unwrap().usage;
        assert_eq!(table.charge(key, one_page), Err(WorkloadError::Quota));
        assert_eq!(table.snapshot(key).unwrap().usage, before);
        table.release(key, one_page).unwrap();
        table.release(key, one_page).unwrap();
        assert_eq!(table.snapshot(key).unwrap().usage, ResourceUsage::default());
    }
}
