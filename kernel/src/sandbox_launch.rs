//! Kernel-owned bounded Sandbox launch-plan registry.
//!
//! Every create/query revalidates Sandbox, root Workload, image, volume, resource
//! attenuation and external authority facts under the registered lock order.
//! Logical paths are never stored or consulted.

use kernel_core::sandbox_launch::{
    IntrinsicLaunchAuthority, LaunchError, LaunchPlanKey, LaunchPlanSnapshot, LaunchSpec,
    SandboxLaunchTable,
};
use kernel_core::security_domain::DomainKey;

use crate::sandbox::{MAX_SANDBOXES, SANDBOXES};
use crate::sandbox_storage::{MAX_IMAGES, MAX_LAYERS, MAX_VOLUMES, STORAGE};
use crate::sync::IrqSpinLock;
use crate::workload::{MAX_WORKLOADS, WORKLOADS};

pub const MAX_LAUNCH_PLANS: usize = 32;

/// Lock order: `SANDBOX -> SANDBOX_STORAGE -> WORKLOADS -> SANDBOX_LAUNCH`.
static LAUNCH: IrqSpinLock<SandboxLaunchTable<MAX_LAUNCH_PLANS>> =
    IrqSpinLock::ranked(crate::lockorder::SANDBOX_LAUNCH, SandboxLaunchTable::new());

/// Admit one immutable launch plan.
pub fn create(domain: DomainKey, spec: LaunchSpec<'_>) -> Result<LaunchPlanKey, LaunchError> {
    let sandboxes = SANDBOXES.lock();
    let storage = STORAGE.lock();
    let workloads = WORKLOADS.lock();
    let mut plans = LAUNCH.lock();
    plans.create_live(
        domain,
        &workloads,
        &sandboxes,
        &storage,
        &IntrinsicLaunchAuthority,
        spec,
    )
}

/// Query a plan only while every referenced authority is still live.
pub fn query(domain: DomainKey, key: LaunchPlanKey) -> Result<LaunchPlanSnapshot, LaunchError> {
    let sandboxes = SANDBOXES.lock();
    let storage = STORAGE.lock();
    let workloads = WORKLOADS.lock();
    let plans = LAUNCH.lock();
    plans.plan_live(
        domain,
        &workloads,
        &sandboxes,
        &storage,
        &IntrinsicLaunchAuthority,
        key,
    )
}

/// Destroy a same-domain plan identity and invalidate its generation.
pub fn destroy(domain: DomainKey, key: LaunchPlanKey) -> Result<(), LaunchError> {
    LAUNCH.lock().destroy(domain, key)
}

/// Bounded diagnostic count.
pub fn count() -> usize {
    LAUNCH.lock().count()
}

const _: () = assert!(MAX_SANDBOXES > 0);
const _: () = assert!(MAX_WORKLOADS > 0);
const _: () = assert!(MAX_IMAGES > 0);
const _: () = assert!(MAX_LAYERS > 0);
const _: () = assert!(MAX_VOLUMES > 0);
