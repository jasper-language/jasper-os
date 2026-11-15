//! Kernel-owned native workload registry and admission facade.
//!
//! 内核持有的原生 Workload 注册表与准入门面。

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::objtable::ObjId;
use kernel_core::security_domain::DomainKey;
use kernel_core::workload::{
    IoRateLimits, IoRateSnapshot, IoUsage, MembershipError, ResourceLimits, ResourceUsage,
    WorkloadError, WorkloadKey, WorkloadMembers, WorkloadRegistryPlan, WorkloadSnapshot,
    WorkloadState, WorkloadTable, plan_workload_registry,
};
use spin::Once;

use crate::proc;
use crate::sched::scheduler::CpuGroupId;
use crate::sync::IrqSpinLock;

pub const MAX_WORKLOADS: usize = 64;
pub const MAX_WORKLOAD_MEMBERS: usize = 256;

pub(crate) static WORKLOADS: IrqSpinLock<WorkloadTable<MAX_WORKLOADS>> =
    IrqSpinLock::new(WorkloadTable::new());
static MEMBERS: IrqSpinLock<WorkloadMembers<MAX_WORKLOAD_MEMBERS>> =
    IrqSpinLock::new(WorkloadMembers::new());
static CPU_GROUPS: IrqSpinLock<[Option<(WorkloadKey, CpuGroupId)>; MAX_WORKLOADS]> =
    IrqSpinLock::new([None; MAX_WORKLOADS]);
static MEMORY_RELEASE_FAILURES: AtomicU32 = AtomicU32::new(0);
static IO_ROLLBACK_FAILURES: AtomicU32 = AtomicU32::new(0);
static REGISTRY_PLAN: Once<WorkloadRegistryPlan> = Once::new();
pub const WORKLOAD_TERMINATED_CODE: i64 = -3;

/// Admit runtime registry counts from task capacity and the heap budget.
pub fn init_registry(tasks: usize) -> bool {
    let memory_budget = crate::mm::heap::limit();
    let Some(plan) = plan_workload_registry(memory_budget, tasks) else {
        crate::kprintln!("[JSR-WORKLOAD] reject=registry_capacity tasks={tasks} budget={memory_budget}");
        return false;
    };
    let plan = WorkloadRegistryPlan {
        workloads: plan.workloads.min(MAX_WORKLOADS), // JASPER-HARDCODE-REVIEW: issue=33 source=runtime budget and fixed storage envelope reason=runtime admission only shrinks the current table and logs dynamic=false
        members: plan.members.min(MAX_WORKLOAD_MEMBERS), // JASPER-HARDCODE-REVIEW: issue=33 source=runtime budget and fixed storage envelope reason=runtime admission only shrinks the current table and logs dynamic=false
    };
    crate::kprintln!(
        "[JSR-WORKLOAD] capacity workloads={} members={} tasks={} budget={} fixed_workloads={} fixed_members={} dynamic=false",
        plan.workloads,
        plan.members,
        tasks,
        memory_budget,
        MAX_WORKLOADS,
        MAX_WORKLOAD_MEMBERS
    );
    REGISTRY_PLAN.call_once(|| plan);
    true
}

fn registry_plan() -> Option<WorkloadRegistryPlan> {
    REGISTRY_PLAN.get().copied()
}

pub fn create(domain: DomainKey, limits: ResourceLimits) -> Result<WorkloadKey, WorkloadError> {
    let mut workloads = WORKLOADS.lock();
    admit_workload(&workloads)?;
    workloads.create(domain, limits)
}

pub fn create_child(
    parent: WorkloadKey,
    limits: ResourceLimits,
) -> Result<WorkloadKey, WorkloadError> {
    let mut workloads = WORKLOADS.lock();
    create_child_locked(&mut workloads, parent, limits)
}

pub(crate) fn create_child_locked(
    workloads: &mut WorkloadTable<MAX_WORKLOADS>,
    parent: WorkloadKey,
    limits: ResourceLimits,
) -> Result<WorkloadKey, WorkloadError> {
    admit_workload(workloads)?;
    workloads.create_child(parent, limits)
}

pub(crate) fn admit_workload(
    workloads: &WorkloadTable<MAX_WORKLOADS>,
) -> Result<(), WorkloadError> {
    let plan = registry_plan().ok_or(WorkloadError::Capacity)?;
    (workloads.len() < plan.workloads)
        .then_some(())
        .ok_or(WorkloadError::Capacity)
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
    if let Err(error) =
        transition(key, WorkloadState::Ready).and_then(|()| transition(key, WorkloadState::Running))
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

/// Return the number of Process members bound to one same-domain Workload.
///
/// 返回同域 Workload 当前绑定的 Process 成员数。
pub fn member_count_in_domain(domain: DomainKey, key: WorkloadKey) -> Result<u32, WorkloadError> {
    let _ = snapshot_in_domain(domain, key)?;
    Ok(MEMBERS.lock().count_for(key) as u32)
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
    let mut members = MEMBERS.lock();
    let plan = registry_plan().ok_or(MembershipError::Capacity)?;
    if members.len() >= plan.members {
        return Err(MembershipError::Capacity);
    }
    members.attach(&workloads, key, member)
}

pub fn unbind_member(key: WorkloadKey, member: u64) -> Result<(), MembershipError> {
    MEMBERS.lock().detach(key, member)
}

pub fn destroy(key: WorkloadKey) -> Result<(), WorkloadError> {
    let mut workloads = WORKLOADS.lock();
    destroy_locked(&mut workloads, key)
}

/// Destroy a Workload while the caller owns the Workload table lock.
///
/// 调用方已持有 Workload 表锁时，执行完整的成员、资源与 CPU group 回收。
pub(crate) fn destroy_locked(
    workloads: &mut WorkloadTable<MAX_WORKLOADS>,
    key: WorkloadKey,
) -> Result<(), WorkloadError> {
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

/// Configure fixed-window I/O rates before a Workload starts.
///
/// 在 Workload 启动前配置固定窗口 I/O 速率。
pub fn configure_io_rate(key: WorkloadKey, limits: IoRateLimits) -> Result<(), WorkloadError> {
    WORKLOADS.lock().configure_io_rate(key, limits)
}

/// Return the current bounded rate policy and window consumption.
pub fn io_rate_snapshot(key: WorkloadKey) -> Result<IoRateSnapshot, WorkloadError> {
    WORKLOADS.lock().io_rate_snapshot(key)
}

/// Atomically admits file/block I/O against the Workload of the calling
/// Process. The device is not an identity: an unbound process remains
/// explicitly untracked instead of borrowing an internal service identity.
pub fn begin_process_io(pid: ObjId, bytes: u64, ops: u64) -> Result<IoPermit, WorkloadError> {
    let workload = proc::workload_key(pid);
    if let Some(workload) = workload {
        WORKLOADS
            .lock()
            .charge_io_at(workload, IoUsage { bytes, ops }, crate::sched::now_ns())?;
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
        if WORKLOADS
            .lock()
            .refund_io_at(workload, self.usage, crate::sched::now_ns())
            .is_err()
        {
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
