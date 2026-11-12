//! Kernel-owned native workload registry and admission facade.
//!
//! 内核持有的原生 Workload 注册表与准入门面。

use kernel_core::security_domain::DomainKey;
use kernel_core::workload::{
    MembershipError, ResourceLimits, ResourceUsage, WorkloadError, WorkloadKey, WorkloadMembers,
    WorkloadSnapshot, WorkloadState, WorkloadTable,
};

use crate::sched::scheduler::CpuGroupId;
use crate::sync::IrqSpinLock;

pub const MAX_WORKLOADS: usize = 64;
pub const MAX_WORKLOAD_MEMBERS: usize = 256;

static WORKLOADS: IrqSpinLock<WorkloadTable<MAX_WORKLOADS>> =
    IrqSpinLock::new(WorkloadTable::new());
static MEMBERS: IrqSpinLock<WorkloadMembers<MAX_WORKLOAD_MEMBERS>> =
    IrqSpinLock::new(WorkloadMembers::new());
static CPU_GROUPS: IrqSpinLock<[Option<(WorkloadKey, CpuGroupId)>; MAX_WORKLOADS]> =
    IrqSpinLock::new([None; MAX_WORKLOADS]);

pub fn create(domain: DomainKey, limits: ResourceLimits) -> Result<WorkloadKey, WorkloadError> {
    WORKLOADS.lock().create(domain, limits)
}

pub fn create_child(
    parent: WorkloadKey,
    limits: ResourceLimits,
) -> Result<WorkloadKey, WorkloadError> {
    WORKLOADS.lock().create_child(parent, limits)
}

pub fn transition(key: WorkloadKey, next: WorkloadState) -> Result<(), WorkloadError> {
    WORKLOADS.lock().transition(key, next)
}

pub fn snapshot(key: WorkloadKey) -> Result<WorkloadSnapshot, WorkloadError> {
    WORKLOADS.lock().snapshot(key)
}

pub fn bind_member(key: WorkloadKey, member: u64) -> Result<(), MembershipError> {
    let workloads = WORKLOADS.lock();
    MEMBERS.lock().attach(&workloads, key, member)
}

pub fn unbind_member(key: WorkloadKey, member: u64) -> Result<(), MembershipError> {
    MEMBERS.lock().detach(key, member)
}

pub fn destroy(key: WorkloadKey) -> Result<(), WorkloadError> {
    let mut workloads = WORKLOADS.lock();
    let state = workloads.snapshot(key)?;
    if !state.state.terminal() {
        return Err(WorkloadError::InvalidState);
    }
    if state.usage != ResourceUsage::default() {
        return Err(WorkloadError::Quota);
    }
    if state.children != 0 {
        return Err(WorkloadError::InvalidState);
    }
    if MEMBERS.lock().count_for(key) != 0 {
        return Err(WorkloadError::InvalidState);
    }
    let mut groups = CPU_GROUPS.lock();
    if let Some(slot) = groups
        .iter()
        .position(|entry| entry.is_some_and(|(owner, _)| owner == key))
    {
        let (_, group) = groups[slot].ok_or(WorkloadError::InvalidState)?;
        crate::sched::release_cpu_group(group).map_err(|_| WorkloadError::Capacity)?;
        groups[slot] = None;
    }
    workloads.destroy(key)?;
    Ok(())
}

pub fn cpu_group(key: WorkloadKey) -> Result<CpuGroupId, WorkloadError> {
    let workloads = WORKLOADS.lock();
    let state = workloads.snapshot(key)?;
    if state.state != WorkloadState::Running {
        return Err(WorkloadError::InvalidState);
    }
    let limits = state.limits;
    let mut groups = CPU_GROUPS.lock();
    if let Some((_, group)) = groups.iter().flatten().find(|(owner, _)| *owner == key) {
        return Ok(*group);
    }
    let slot = groups
        .iter()
        .position(Option::is_none)
        .ok_or(WorkloadError::Capacity)?;
    let group =
        crate::sched::create_cpu_group(limits.cpu_permille).map_err(|_| WorkloadError::Capacity)?;
    groups[slot] = Some((key, group));
    Ok(group)
}

pub fn reserve_thread(key: WorkloadKey) -> Result<(), WorkloadError> {
    WORKLOADS.lock().charge(
        key,
        ResourceUsage {
            memory_bytes: 0,
            threads: 1,
            ring_entries: 0,
        },
    )
}

pub fn release_thread(key: WorkloadKey) {
    let _ = WORKLOADS.lock().release(
        key,
        ResourceUsage {
            memory_bytes: 0,
            threads: 1,
            ring_entries: 0,
        },
    );
}

pub fn reserve_memory(key: WorkloadKey, bytes: u64) -> Result<(), WorkloadError> {
    WORKLOADS.lock().charge(
        key,
        ResourceUsage {
            memory_bytes: bytes,
            threads: 0,
            ring_entries: 0,
        },
    )
}

pub fn reserve_ring_entries(key: WorkloadKey, entries: u32) -> Result<(), WorkloadError> {
    WORKLOADS.lock().charge(
        key,
        ResourceUsage {
            memory_bytes: 0,
            threads: 0,
            ring_entries: entries,
        },
    )
}

pub fn release_memory(key: WorkloadKey, bytes: u64) {
    let _ = WORKLOADS.lock().release(
        key,
        ResourceUsage {
            memory_bytes: bytes,
            threads: 0,
            ring_entries: 0,
        },
    );
}

pub fn release_ring_entries(key: WorkloadKey, entries: u32) {
    let _ = WORKLOADS.lock().release(
        key,
        ResourceUsage {
            memory_bytes: 0,
            threads: 0,
            ring_entries: entries,
        },
    );
}

pub fn usage(key: WorkloadKey) -> Option<ResourceUsage> {
    WORKLOADS.lock().snapshot(key).ok().map(|state| state.usage)
}
