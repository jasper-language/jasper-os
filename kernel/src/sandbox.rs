//! Kernel-owned native Sandbox registry.
//!
//! The Sandbox registry stores only a stable sandbox generation and its root
//! Workload binding. Lifecycle, security domain, limits, usage, children and
//! CPU groups remain owned by the Workload subsystem.
//!
//! 内核持有的原生 Sandbox 注册面。Sandbox 只保存稳定世代与 root Workload
//! 绑定；生命周期、安全域、限额、使用量、子级和 CPU group 均归 Workload
//! 子系统唯一所有。
//!
//! # Lock order
//!
//! `SANDBOX -> WORKLOADS -> MEMBERS/CPU_GROUPS -> SCHED`.
//! The Sandbox lock is registered as the outermost global lock. No
//! Workload-only path acquires it, so there is no reverse edge. Destruction
//! keeps both registry locks across the kernel Workload destructor so CPU
//! groups are released before the Sandbox identity becomes observable as gone.

use kernel_core::sandbox::{SandboxError, SandboxKey, SandboxSnapshot, SandboxTable};
use kernel_core::security_domain::DomainKey;
use kernel_core::workload::{ResourceLimits, WorkloadKey, WorkloadSnapshot, WorkloadTable};

use crate::sync::IrqSpinLock;
use crate::workload::{MAX_WORKLOADS, WORKLOADS};

pub const MAX_SANDBOXES: usize = 64;

pub(crate) static SANDBOXES: IrqSpinLock<SandboxTable<MAX_SANDBOXES>> =
    IrqSpinLock::ranked(crate::lockorder::SANDBOX, SandboxTable::new());

/// Atomically create a root Workload and its stable Sandbox identity.
///
/// 原子创建 root Workload 与稳定 Sandbox 身份。
pub fn create_sandbox(
    domain: DomainKey,
    limits: ResourceLimits,
) -> Result<SandboxKey, SandboxError> {
    let mut sandboxes = SANDBOXES.lock();
    let mut workloads = WORKLOADS.lock();
    sandboxes.create(&mut workloads, domain, limits)
}

/// Advance a same-domain sandbox from `Created` to `Ready`.
pub fn mark_ready(domain: DomainKey, key: SandboxKey) -> Result<(), SandboxError> {
    let sandboxes = SANDBOXES.lock();
    let mut workloads = WORKLOADS.lock();
    let _ = checked_root(&sandboxes, &workloads, domain, key)?;
    sandboxes.mark_ready(&mut workloads, key)
}

/// Advance a same-domain sandbox from `Ready` to `Running`.
pub fn start(domain: DomainKey, key: SandboxKey) -> Result<(), SandboxError> {
    let sandboxes = SANDBOXES.lock();
    let mut workloads = WORKLOADS.lock();
    let _ = checked_root(&sandboxes, &workloads, domain, key)?;
    sandboxes.start(&mut workloads, key)
}

/// Request shutdown. `Stopping` prevents new resource, child and member
/// admission through the Workload subsystem.
///
/// 请求关闭；`Stopping` 由 Workload 统一阻止新资源、新子级和新成员准入。
pub fn request_stop(domain: DomainKey, key: SandboxKey) -> Result<(), SandboxError> {
    let sandboxes = SANDBOXES.lock();
    let mut workloads = WORKLOADS.lock();
    let _ = checked_root(&sandboxes, &workloads, domain, key)?;
    sandboxes.request_stop(&mut workloads, key)
}

/// Request shutdown, then complete it on the next call once the root Workload
/// has no members, resources or children.
///
/// 首次调用请求关闭；当 root Workload 已无成员、资源和子级时，再次调用完成
/// 关闭。两个阶段均委托 Workload 的权威生命周期与清理检查。
pub fn stop(domain: DomainKey, key: SandboxKey) -> Result<(), SandboxError> {
    let sandboxes = SANDBOXES.lock();
    let mut workloads = WORKLOADS.lock();
    let root = checked_root(&sandboxes, &workloads, domain, key)?;
    match workloads.snapshot(root)?.state {
        kernel_core::workload::WorkloadState::Running => {
            sandboxes.request_stop(&mut workloads, key)
        }
        kernel_core::workload::WorkloadState::Stopping => {
            sandboxes.complete_stop(&mut workloads, key)
        }
        _ => Err(SandboxError::Workload(
            kernel_core::workload::WorkloadError::InvalidState,
        )),
    }
}

/// Complete shutdown only after Workload usage and children are zero.
///
/// 仅当 Workload 使用量和子级归零后进入 `Stopped`。
pub fn complete_stop(domain: DomainKey, key: SandboxKey) -> Result<(), SandboxError> {
    let sandboxes = SANDBOXES.lock();
    let mut workloads = WORKLOADS.lock();
    let _ = checked_root(&sandboxes, &workloads, domain, key)?;
    sandboxes.complete_stop(&mut workloads, key)
}

/// Enter the single `Failed` terminal from any non-terminal state.
pub fn fail(domain: DomainKey, key: SandboxKey) -> Result<(), SandboxError> {
    let sandboxes = SANDBOXES.lock();
    let mut workloads = WORKLOADS.lock();
    let _ = checked_root(&sandboxes, &workloads, domain, key)?;
    sandboxes.fail(&mut workloads, key)
}

/// Query identity and current lifecycle from the root Workload.
pub fn snapshot(domain: DomainKey, key: SandboxKey) -> Result<SandboxSnapshot, SandboxError> {
    let sandboxes = SANDBOXES.lock();
    let workloads = WORKLOADS.lock();
    let root = checked_root(&sandboxes, &workloads, domain, key)?;
    let snapshot = sandboxes.snapshot(&workloads, key)?;
    if snapshot.root == root {
        Ok(snapshot)
    } else {
        Err(SandboxError::InvalidKey)
    }
}

/// Return the authoritative root Workload record for a same-domain sandbox.
pub fn root_snapshot(domain: DomainKey, key: SandboxKey) -> Result<WorkloadSnapshot, SandboxError> {
    let sandboxes = SANDBOXES.lock();
    let workloads = WORKLOADS.lock();
    let _ = checked_root(&sandboxes, &workloads, domain, key)?;
    sandboxes.root_snapshot(&workloads, key)
}

/// Destroy a same-domain terminal sandbox after the Workload destructor has
/// validated zero resource usage, zero children and zero members, and has
/// released any owned CPU group.
///
/// 在同域 Workload 的终态、零资源、零子级、零成员和 CPU group 回收全部
/// 成功后删除 Sandbox 身份。
pub fn destroy(domain: DomainKey, key: SandboxKey) -> Result<(), SandboxError> {
    let mut sandboxes = SANDBOXES.lock();
    if crate::sandbox_storage::blocks_destroy(key) {
        return Err(SandboxError::StorageInUse);
    }
    let mut workloads = WORKLOADS.lock();
    let _ = checked_root(&sandboxes, &workloads, domain, key)?;
    sandboxes.destroy_with(&mut workloads, key, |workloads, root| {
        crate::workload::destroy_locked(workloads, root)
    })
}

/// Number of live Sandbox identities, exposed for bounded diagnostics/tests.
pub fn count() -> usize {
    SANDBOXES.lock().len()
}

fn checked_root(
    sandboxes: &SandboxTable<MAX_SANDBOXES>,
    workloads: &WorkloadTable<MAX_WORKLOADS>,
    domain: DomainKey,
    key: SandboxKey,
) -> Result<WorkloadKey, SandboxError> {
    Ok(sandboxes.snapshot_in_domain(workloads, domain, key)?.root)
}
