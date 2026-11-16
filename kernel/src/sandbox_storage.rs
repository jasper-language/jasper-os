//! Kernel-owned Sandbox image and CoW volume registry.
//!
//! Every operation checks the caller's Sandbox in the authoritative Sandbox
//! table before touching storage. The registry never accepts a security domain
//! from users and never derives authority from a logical path.

use kernel_core::sandbox::{SandboxKey, SandboxTable};
use kernel_core::sandbox_image::{
    plan_sandbox_storage_registry, ImageKey, ImageLayerSpec, ImageSnapshot, ImageSpec,
    LayerSnapshot, SandboxStorageError, SandboxStorageRegistryPlan, SandboxStorageTable, VolumeKey,
    VolumeSnapshot,
};
use kernel_core::security_domain::DomainKey;
use spin::Once;

use crate::sandbox::SANDBOXES;
use crate::sync::IrqSpinLock;
use crate::workload::WORKLOADS;

/// Lock order: `SANDBOX -> SANDBOX_STORAGE -> WORKLOADS`.
pub(crate) static STORAGE: IrqSpinLock<SandboxStorageTable> = IrqSpinLock::ranked(
    crate::lockorder::SANDBOX_STORAGE,
    SandboxStorageTable::new(),
);
static REGISTRY_PLAN: Once<SandboxStorageRegistryPlan> = Once::new();

/// Admit storage metadata from runtime Sandbox capacity and the heap budget.
pub fn init_registry(sandbox_slots: usize) -> bool {
    let memory_budget = crate::mm::heap::limit();
    let Some(plan) = plan_sandbox_storage_registry(memory_budget, sandbox_slots) else {
        crate::kprintln!(
            "[JSR-SANDBOX-STORAGE] reject=registry_capacity sandboxes={sandbox_slots} budget={memory_budget}"
        );
        return false;
    };
    crate::kprintln!(
        "[JSR-SANDBOX-STORAGE] capacity images={} layers={} volumes={} sandboxes={} budget={} dynamic=true",
        plan.images,
        plan.layers,
        plan.volumes,
        sandbox_slots,
        memory_budget
    );
    REGISTRY_PLAN.call_once(|| plan);
    true
}

fn registry_plan() -> Option<SandboxStorageRegistryPlan> {
    REGISTRY_PLAN.get().copied()
}

fn sandbox_exists(
    sandboxes: &SandboxTable,
    workloads: &kernel_core::workload::WorkloadTable,
    domain: DomainKey,
    sandbox: SandboxKey,
    require_running: bool,
) -> bool {
    sandboxes
        .snapshot_in_domain(workloads, domain, sandbox)
        .is_ok_and(|snapshot| {
            !require_running || snapshot.state == kernel_core::workload::WorkloadState::Running
        })
}

pub fn add_image(
    domain: DomainKey,
    sandbox: SandboxKey,
    spec: ImageSpec,
    layers: &[ImageLayerSpec],
) -> Result<ImageKey, SandboxStorageError> {
    let sandboxes = SANDBOXES.lock();
    let mut storage = STORAGE.lock();
    let workloads = WORKLOADS.lock();
    if !sandbox_exists(&sandboxes, &workloads, domain, sandbox, true) {
        return Err(SandboxStorageError::InvalidImage);
    }
    let plan = registry_plan().ok_or(SandboxStorageError::Capacity)?;
    if storage.image_count() >= plan.images
        || storage
            .layer_count()
            .checked_add(layers.len())
            .is_none_or(|layers| layers > plan.layers)
    {
        return Err(SandboxStorageError::Capacity);
    }
    storage.add_image(domain, sandbox, spec, layers)
}

pub fn image(
    domain: DomainKey,
    sandbox: SandboxKey,
    key: ImageKey,
) -> Result<ImageSnapshot, SandboxStorageError> {
    let sandboxes = SANDBOXES.lock();
    let storage = STORAGE.lock();
    let workloads = WORKLOADS.lock();
    if !sandbox_exists(&sandboxes, &workloads, domain, sandbox, false) {
        return Err(SandboxStorageError::InvalidImage);
    }
    storage.image(domain, sandbox, key)
}

pub fn image_layer(
    domain: DomainKey,
    sandbox: SandboxKey,
    image: ImageKey,
    index: u16,
) -> Result<LayerSnapshot, SandboxStorageError> {
    let sandboxes = SANDBOXES.lock();
    let storage = STORAGE.lock();
    let workloads = WORKLOADS.lock();
    if !sandbox_exists(&sandboxes, &workloads, domain, sandbox, false) {
        return Err(SandboxStorageError::InvalidImage);
    }
    storage.image_layer(domain, sandbox, image, index)
}

pub fn destroy_image(
    domain: DomainKey,
    sandbox: SandboxKey,
    image: ImageKey,
) -> Result<(), SandboxStorageError> {
    let sandboxes = SANDBOXES.lock();
    let mut storage = STORAGE.lock();
    let workloads = WORKLOADS.lock();
    if !sandbox_exists(&sandboxes, &workloads, domain, sandbox, false) {
        return Err(SandboxStorageError::InvalidImage);
    }
    storage.destroy_image(domain, sandbox, image)
}

pub fn create_volume(
    domain: DomainKey,
    sandbox: SandboxKey,
    image: ImageKey,
    capacity_bytes: u64,
) -> Result<VolumeKey, SandboxStorageError> {
    let sandboxes = SANDBOXES.lock();
    let mut storage = STORAGE.lock();
    let workloads = WORKLOADS.lock();
    if !sandbox_exists(&sandboxes, &workloads, domain, sandbox, true) {
        return Err(SandboxStorageError::InvalidVolume);
    }
    if storage.volume_count()
        >= registry_plan()
            .ok_or(SandboxStorageError::Capacity)?
            .volumes
    {
        return Err(SandboxStorageError::Capacity);
    }
    storage.create_volume(domain, sandbox, image, capacity_bytes)
}

pub fn clone_volume(
    domain: DomainKey,
    sandbox: SandboxKey,
    parent: VolumeKey,
    capacity_bytes: u64,
) -> Result<VolumeKey, SandboxStorageError> {
    let sandboxes = SANDBOXES.lock();
    let mut storage = STORAGE.lock();
    let workloads = WORKLOADS.lock();
    if !sandbox_exists(&sandboxes, &workloads, domain, sandbox, true) {
        return Err(SandboxStorageError::InvalidVolume);
    }
    if storage.volume_count()
        >= registry_plan()
            .ok_or(SandboxStorageError::Capacity)?
            .volumes
    {
        return Err(SandboxStorageError::Capacity);
    }
    storage.clone_volume(domain, sandbox, parent, capacity_bytes)
}

pub fn volume(
    domain: DomainKey,
    sandbox: SandboxKey,
    key: VolumeKey,
) -> Result<VolumeSnapshot, SandboxStorageError> {
    let sandboxes = SANDBOXES.lock();
    let storage = STORAGE.lock();
    let workloads = WORKLOADS.lock();
    if !sandbox_exists(&sandboxes, &workloads, domain, sandbox, false) {
        return Err(SandboxStorageError::InvalidVolume);
    }
    storage.volume(domain, sandbox, key)
}

pub fn charge_volume(
    domain: DomainKey,
    sandbox: SandboxKey,
    key: VolumeKey,
    bytes: u64,
) -> Result<VolumeSnapshot, SandboxStorageError> {
    let sandboxes = SANDBOXES.lock();
    let mut storage = STORAGE.lock();
    let workloads = WORKLOADS.lock();
    if !sandbox_exists(&sandboxes, &workloads, domain, sandbox, true) {
        return Err(SandboxStorageError::InvalidVolume);
    }
    storage.charge_volume(domain, sandbox, key, bytes)
}

pub fn release_volume(
    domain: DomainKey,
    sandbox: SandboxKey,
    key: VolumeKey,
    bytes: u64,
) -> Result<VolumeSnapshot, SandboxStorageError> {
    let sandboxes = SANDBOXES.lock();
    let mut storage = STORAGE.lock();
    let workloads = WORKLOADS.lock();
    if !sandbox_exists(&sandboxes, &workloads, domain, sandbox, false) {
        return Err(SandboxStorageError::InvalidVolume);
    }
    storage.release_volume(domain, sandbox, key, bytes)
}

pub fn destroy_volume(
    domain: DomainKey,
    sandbox: SandboxKey,
    key: VolumeKey,
) -> Result<(), SandboxStorageError> {
    let sandboxes = SANDBOXES.lock();
    let mut storage = STORAGE.lock();
    let workloads = WORKLOADS.lock();
    if !sandbox_exists(&sandboxes, &workloads, domain, sandbox, false) {
        return Err(SandboxStorageError::InvalidVolume);
    }
    storage.destroy_volume(domain, sandbox, key)
}

/// Called by Sandbox destruction while the outer SANDBOX lock is held.
pub(crate) fn blocks_destroy(sandbox: SandboxKey) -> bool {
    STORAGE.lock().has_storage_for(sandbox)
}
