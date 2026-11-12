//! Kernel-owned native workload registry and admission facade.
//!
//! 内核持有的原生 Workload 注册表与准入门面。

use kernel_core::security_domain::DomainKey;
use kernel_core::workload::{
    MembershipError, ResourceLimits, ResourceUsage, WorkloadError, WorkloadKey, WorkloadMembers,
    WorkloadSnapshot, WorkloadState, WorkloadTable,
};

use crate::sync::IrqSpinLock;

pub const MAX_WORKLOADS: usize = 64;
pub const MAX_WORKLOAD_MEMBERS: usize = 256;

static WORKLOADS: IrqSpinLock<WorkloadTable<MAX_WORKLOADS>> =
    IrqSpinLock::new(WorkloadTable::new());
static MEMBERS: IrqSpinLock<WorkloadMembers<MAX_WORKLOAD_MEMBERS>> =
    IrqSpinLock::new(WorkloadMembers::new());

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
    if MEMBERS.lock().count_for(key) != 0 {
        return Err(WorkloadError::InvalidState);
    }
    workloads.destroy(key)
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

pub fn usage(key: WorkloadKey) -> Option<ResourceUsage> {
    WORKLOADS.lock().snapshot(key).ok().map(|state| state.usage)
}
