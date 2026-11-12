//! Kernel-owned native workload registry and admission facade.
//!
//! 内核持有的原生 Workload 注册表与准入门面。

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::objtable::ObjId;
use kernel_core::security_domain::DomainKey;
use kernel_core::workload::{
    IoUsage, MembershipError, ResourceLimits, ResourceUsage, WorkloadError, WorkloadKey,
    WorkloadMembers, WorkloadSnapshot, WorkloadState, WorkloadTable,
};

use crate::sched::scheduler::CpuGroupId;
use crate::sync::IrqSpinLock;
use crate::proc;

pub const MAX_WORKLOADS: usize = 64;
pub const MAX_WORKLOAD_MEMBERS: usize = 256;

static WORKLOADS: IrqSpinLock<WorkloadTable<MAX_WORKLOADS>> =
    IrqSpinLock::new(WorkloadTable::new());
static MEMBERS: IrqSpinLock<WorkloadMembers<MAX_WORKLOAD_MEMBERS>> =
    IrqSpinLock::new(WorkloadMembers::new());
static CPU_GROUPS: IrqSpinLock<[Option<(WorkloadKey, CpuGroupId)>; MAX_WORKLOADS]> =
    IrqSpinLock::new([None; MAX_WORKLOADS]);
static MEMORY_RELEASE_FAILURES: AtomicU32 = AtomicU32::new(0);
static IO_ROLLBACK_FAILURES: AtomicU32 = AtomicU32::new(0);
pub const WORKLOAD_TERMINATED_CODE: i64 = -3;

pub fn create(domain: DomainKey, limits: ResourceLimits) -> Result<WorkloadKey, WorkloadError> {
    WORKLOADS.lock().create(domain, limits)
}

pub fn create_child(
    parent: WorkloadKey,
    limits: ResourceLimits,
) -> Result<WorkloadKey, WorkloadError> {
    WORKLOADS.lock().create_child(parent, limits)
}

/// Create a root or child Workload only inside the caller's authority domain.
///
/// 只允许在调用者权威域内创建根或子 Workload；父级域不匹配时拒绝。
pub fn create_in_domain(
    domain: DomainKey,
    parent: Option<WorkloadKey>,
    limits: ResourceLimits,
) -> Result<WorkloadKey, WorkloadError> {
    let key = match parent {
        None => create(domain, limits)?,
        Some(parent) => {
            let snapshot = WORKLOADS.lock().snapshot(parent)?;
            if snapshot.domain != domain {
                return Err(WorkloadError::InvalidDomain);
            }
            if snapshot.state != WorkloadState::Running {
                return Err(WorkloadError::InvalidState);
            }
            create_child(parent, limits)?
        }
    };
    if let Err(error) = transition(key, WorkloadState::Ready)
        .and_then(|()| transition(key, WorkloadState::Running))
    {
        let _ = transition(key, WorkloadState::Failed);
        let _ = destroy(key);
        return Err(error);
    }
    Ok(key)
}

/// Query one Workload only when it belongs to the caller's domain.
///
/// 仅查询与调用者同域的 Workload，跨域标识按不存在处理以免泄露对象信息。
pub fn snapshot_in_domain(
    domain: DomainKey,
    key: WorkloadKey,
) -> Result<WorkloadSnapshot, WorkloadError> {
    let snapshot = WORKLOADS.lock().snapshot(key)?;
    if snapshot.domain != domain {
        return Err(WorkloadError::InvalidKey);
    }
    Ok(snapshot)
}

/// Request a same-domain Workload to stop. The resource-draining `Stopped`
/// transition remains a separate lifecycle fact.
///
/// 请求同域 Workload 停止；真正进入 `Stopped` 仍必须满足资源与子级归零。
pub fn stop_in_domain(domain: DomainKey, key: WorkloadKey) -> Result<(), WorkloadError> {
    let snapshot = snapshot_in_domain(domain, key)?;
    match snapshot.state {
        WorkloadState::Running => transition(key, WorkloadState::Stopping),
        WorkloadState::Stopping => transition(key, WorkloadState::Stopped),
        _ => Err(WorkloadError::InvalidState),
    }
}

/// Force every same-domain member Process to exit through the normal process
/// cleanup path, after preventing new Workload resource admission.
///
/// 终止同域 Workload 的所有成员 Process；资源仍由正常退出清理归还，不伪造归零。
pub fn terminate_in_domain(domain: DomainKey, key: WorkloadKey) -> Result<(), WorkloadError> {
    let snapshot = snapshot_in_domain(domain, key)?;
    match snapshot.state {
        WorkloadState::Running => transition(key, WorkloadState::Stopping)?,
        WorkloadState::Stopping => {}
        _ => return Err(WorkloadError::InvalidState),
    }
    let members = MEMBERS.lock().count_for(key);
    for index in 0..members {
        let member = MEMBERS.lock().id_at_for(key, index);
        if let Some(pid) = member.and_then(ObjId::from_raw) {
            let _ = crate::proc::begin_exit(pid, WORKLOAD_TERMINATED_CODE);
        }
    }
    Ok(())
}

/// Destroy a same-domain terminal Workload after all resources are gone.
pub fn destroy_in_domain(domain: DomainKey, key: WorkloadKey) -> Result<(), WorkloadError> {
    let _ = snapshot_in_domain(domain, key)?;
    destroy(key)
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
    let state = WORKLOADS.lock().snapshot(key)?;
    if state.state != WorkloadState::Running {
        return Err(WorkloadError::InvalidState);
    }
    let limits = state.limits;
    {
        let groups = CPU_GROUPS.lock();
        if let Some((_, group)) = groups.iter().flatten().find(|(owner, _)| *owner == key) {
            return Ok(*group);
        }
    }
    let parent_group = match state.parent {
        Some(parent) => Some(cpu_group(parent)?),
        None => None,
    };
    let mut groups = CPU_GROUPS.lock();
    if let Some((_, group)) = groups.iter().flatten().find(|(owner, _)| *owner == key) {
        return Ok(*group);
    }
    let slot = groups
        .iter()
        .position(Option::is_none)
        .ok_or(WorkloadError::Capacity)?;
    let group = match parent_group {
        Some(parent) => crate::sched::create_child_cpu_group(parent, limits.cpu_permille),
        None => crate::sched::create_cpu_group(limits.cpu_permille),
    }
    .map_err(|_| WorkloadError::Capacity)?;
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

/// Atomically admits file/block I/O against the Workload of the calling
/// Process. The device is not an identity: an unbound process remains
/// explicitly untracked instead of borrowing an internal service identity.
pub fn begin_process_io(
    pid: ObjId,
    bytes: u64,
    ops: u64,
) -> Result<IoPermit, WorkloadError> {
    let workload = proc::workload_key(pid);
    if let Some(workload) = workload {
        WORKLOADS.lock().charge_io(workload, IoUsage { bytes, ops })?;
    }
    Ok(IoPermit {
        workload,
        usage: IoUsage { bytes, ops },
        committed: false,
    })
}

/// Admission token for one request. Dropping an uncommitted token reverses the
/// reservation, so a failed copy, mapping or block read leaves no budget
/// consumption behind.
pub struct IoPermit {
    workload: Option<WorkloadKey>,
    usage: IoUsage,
    committed: bool,
}

impl IoPermit {
    pub fn commit(mut self) {
        self.committed = true;
    }

    pub const fn workload(&self) -> Option<WorkloadKey> {
        self.workload
    }
}

impl Drop for IoPermit {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let Some(workload) = self.workload else {
            return;
        };
        if WORKLOADS.lock().refund_io(workload, self.usage).is_err() {
            IO_ROLLBACK_FAILURES.fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub fn release_memory(key: WorkloadKey, bytes: u64) {
    let released = WORKLOADS.lock().release(
        key,
        ResourceUsage {
            memory_bytes: bytes,
            threads: 0,
            ring_entries: 0,
        },
    );
    if released.is_err() {
        // Cleanup cannot recover from a stale/underflowed counter, but silently
        // pretending it succeeded would let a terminal workload look healthy.
        MEMORY_RELEASE_FAILURES.fetch_add(1, Ordering::Relaxed);
    }
}

/// Number of memory-credit releases rejected by the Workload registry.
pub fn memory_release_failures() -> u32 {
    MEMORY_RELEASE_FAILURES.load(Ordering::Acquire)
}

/// Number of failed I/O reservation reversals. Non-zero indicates an internal
/// accounting error and is surfaced by verification rather than hidden.
pub fn io_rollback_failures() -> u32 {
    IO_ROLLBACK_FAILURES.load(Ordering::Acquire)
}

/// RAII ownership for ordinary Memory-object backing bytes.
///
/// The transferable handle may outlive its creating Process, so the charge is
/// released by the final MemoryObject rather than by Process destruction.
pub struct MemoryCharge {
    workload: WorkloadKey,
    bytes: u64,
}

impl MemoryCharge {
    pub fn reserve(workload: WorkloadKey, bytes: u64) -> Result<Self, WorkloadError> {
        reserve_memory(workload, bytes)?;
        Ok(Self { workload, bytes })
    }
}

impl Drop for MemoryCharge {
    fn drop(&mut self) {
        release_memory(self.workload, self.bytes);
    }
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
