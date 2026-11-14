//! Kernel-owned bounded Sandbox launch-plan registry.
//!
//! Every create/query revalidates Sandbox, root Workload, image, volume, resource
//! attenuation and external authority facts under the registered lock order.
//! Logical paths are never stored or consulted.

use kernel_core::sandbox_launch::{
    CapabilitySet, DataScopeGrant, DeviceGrant, LaunchAuthority, LaunchError, LaunchPlanKey,
    LaunchPlanSnapshot, LaunchSpec, NetworkPolicyRef, SandboxLaunchTable,
};
use kernel_core::sandbox::SandboxKey;
use kernel_core::sandbox_image::{ContentDigest, ImageKey, VolumeKey};
use kernel_core::object::Rights;
use kernel_core::objtable::ObjId;
use kernel_core::security_domain::DomainKey;
use kernel_core::spawn_abi::{CPU_UNLIMITED, MAX_IMAGE_BYTES};
use kernel_core::workload::{ResourceUsage, WorkloadKey, WorkloadState};
use sha2::{Digest as _, Sha256};

use crate::kprintln;
use crate::proc::{self, DeviceAuthorityTicket};
use crate::sandbox::{MAX_SANDBOXES, SANDBOXES};
use crate::sandbox_storage::{MAX_IMAGES, MAX_LAYERS, MAX_VOLUMES, STORAGE};
use crate::sync::IrqSpinLock;
use crate::syscall::{table as abi, SyscallSet};
use crate::workload::{MAX_WORKLOADS, WORKLOADS};

pub const MAX_LAUNCH_PLANS: usize = 32;

/// Lock order: `SANDBOX -> SANDBOX_STORAGE -> WORKLOADS -> SANDBOX_LAUNCH`.
static LAUNCH: IrqSpinLock<SandboxLaunchTable<MAX_LAUNCH_PLANS>> =
    IrqSpinLock::ranked(crate::lockorder::SANDBOX_LAUNCH, SandboxLaunchTable::new());

const DEVICE_RIGHTS: Rights = Rights::READ
    .union(Rights::WRITE)
    .union(Rights::CONTROL)
    .union(Rights::MAP);

/// Device authority snapshot taken before Sandbox/Storage/Workload locks.
///
/// The production handle table is the sole device-grant authority. Data scopes
/// are bound to exact live volume generations and image ownership. NET policy
/// references are checked against the kernel-owned live policy registry.
#[derive(Clone, Copy)]
struct DataAuthorityTicket {
    volume: VolumeKey,
    image: ImageKey,
    writable: bool,
}

struct KernelLaunchAuthority {
    domain: DomainKey,
    sandbox: SandboxKey,
    root_capabilities: CapabilitySet,
    network_policy: Option<NetworkPolicyRef>,
    root_ticket: Option<DeviceAuthorityTicket>,
    device_tickets: [Option<DeviceAuthorityTicket>; kernel_core::sandbox_launch::MAX_DEVICE_GRANTS],
    data_tickets: [Option<DataAuthorityTicket>; kernel_core::sandbox_launch::MAX_DATA_SCOPES],
}

impl KernelLaunchAuthority {
    fn snapshot(
        domain: DomainKey,
        sandbox: SandboxKey,
        image: ImageKey,
        devices: &[DeviceGrant],
        data: &[DataScopeGrant],
        network_policy: Option<NetworkPolicyRef>,
    ) -> Self {
        let mut intrinsic =
            CapabilitySet::EXECUTE.union(CapabilitySet::DATA_READ).union(CapabilitySet::DATA_WRITE);
        if network_policy.is_some_and(|policy| crate::net_policy::live(domain, sandbox, policy)) {
            intrinsic = intrinsic.union(CapabilitySet::NETWORK);
        }
        let root_ticket = proc::device_authority_ticket(domain, None, Rights::NONE);
        if root_ticket.is_some() {
            intrinsic = intrinsic.union(CapabilitySet::DEVICE);
        }
        let mut device_tickets =
            [None; kernel_core::sandbox_launch::MAX_DEVICE_GRANTS];
        for (index, grant) in devices
            .iter()
            .copied()
            .take(device_tickets.len())
            .enumerate()
        {
            if grant.owner != domain {
                continue;
            }
            if grant.rights & !Rights::ALL.bits() != 0 {
                continue;
            }
            let rights = Rights::from_bits_truncate(grant.rights);
            if rights.is_empty() || !rights.difference(DEVICE_RIGHTS).is_empty() {
                continue;
            }
            let Some(object) = ObjId::from_raw(grant.object) else {
                continue;
            };
            if object.generation() != grant.generation {
                continue;
            }
            device_tickets[index] = proc::device_authority_ticket(domain, Some(object), rights);
        }
        let mut data_tickets =
            [None; kernel_core::sandbox_launch::MAX_DATA_SCOPES];
        for (index, grant) in data
            .iter()
            .copied()
            .take(data_tickets.len())
            .enumerate()
        {
            if grant.owner != domain || grant.grantee != domain {
                continue;
            }
            let Some(volume) = VolumeKey::from_raw(grant.object) else {
                continue;
            };
            if volume.to_raw() != grant.object || volume.generation() != grant.generation {
                continue;
            }
            if STORAGE
                .lock()
                .volume(domain, sandbox, volume)
                .is_ok_and(|snapshot| snapshot.image == image)
            {
                data_tickets[index] = Some(DataAuthorityTicket {
                    volume,
                    image,
                    writable: grant.writable,
                });
            }
        }
        Self {
            domain,
            sandbox,
            root_capabilities: intrinsic,
            network_policy,
            root_ticket,
            device_tickets,
            data_tickets,
        }
    }

    fn revalidate(&self) -> Result<(), LaunchError> {
        if self.root_capabilities.contains(CapabilitySet::DEVICE)
            && !self.root_ticket.is_some_and(|ticket| {
                proc::device_authority_ticket_live(self.domain, ticket)
            })
        {
            return Err(LaunchError::Capability);
        }
        if self
            .device_tickets
            .iter()
            .flatten()
            .any(|ticket| !proc::device_authority_ticket_live(self.domain, *ticket))
        {
            return Err(LaunchError::InvalidDevice);
        }
        let storage = STORAGE.lock();
        if self
            .data_tickets
            .iter()
            .flatten()
            .any(|ticket| {
                !storage
                    .volume(self.domain, self.sandbox, ticket.volume)
                    .is_ok_and(|snapshot| snapshot.image == ticket.image)
            })
        {
            return Err(LaunchError::InvalidData);
        }
        if self
            .network_policy
            .is_some_and(|policy| !crate::net_policy::live(self.domain, self.sandbox, policy))
        {
            return Err(LaunchError::InvalidNetwork);
        }
        Ok(())
    }
}

impl LaunchAuthority for KernelLaunchAuthority {
    fn root_capabilities(
        &self,
        domain: DomainKey,
        _sandbox: kernel_core::sandbox::SandboxKey,
        _root: kernel_core::workload::WorkloadKey,
    ) -> Option<CapabilitySet> {
        (domain == self.domain).then_some(self.root_capabilities)
    }

    fn device_grant_live(
        &self,
        domain: DomainKey,
        _sandbox: kernel_core::sandbox::SandboxKey,
        grant: DeviceGrant,
    ) -> bool {
        domain == self.domain
            && self
                .device_tickets
                .iter()
                .flatten()
                .any(|ticket| {
                    ObjId::from_raw(grant.object).is_some_and(|object| {
                        object.generation() == grant.generation
                            && ticket.matches(
                                object,
                                Rights::from_bits_truncate(grant.rights),
                            )
                    })
                })
    }

    fn data_scope_live(
        &self,
        domain: DomainKey,
        sandbox: SandboxKey,
        grant: DataScopeGrant,
    ) -> bool {
        domain == self.domain
            && sandbox == self.sandbox
            && grant.owner == domain
            && grant.grantee == domain
            && self
                .data_tickets
                .iter()
                .flatten()
                .any(|ticket| {
                    ticket.volume.to_raw() == grant.object && ticket.writable == grant.writable
                })
    }

    fn network_policy_live(
        &self,
        domain: DomainKey,
        sandbox: SandboxKey,
        policy: NetworkPolicyRef,
    ) -> bool {
        domain == self.domain
            && sandbox == self.sandbox
            && crate::net_policy::live(domain, sandbox, policy)
    }
}

/// Admit one immutable launch plan.
pub fn create(domain: DomainKey, spec: LaunchSpec<'_>) -> Result<LaunchPlanKey, LaunchError> {
    let authority = KernelLaunchAuthority::snapshot(
        domain,
        spec.sandbox,
        spec.image,
        spec.devices,
        spec.data,
        spec.network_policy,
    );
    let sandboxes = SANDBOXES.lock();
    let storage = STORAGE.lock();
    let workloads = WORKLOADS.lock();
    let mut plans = LAUNCH.lock();
    let key = plans.create_live(
        domain,
        &workloads,
        &sandboxes,
        &storage,
        &authority,
        spec,
    )?;
    drop(plans);
    drop(workloads);
    drop(storage);
    drop(sandboxes);
    if let Err(error) = authority.revalidate() {
        let _ = LAUNCH.lock().destroy(domain, key);
        return Err(error);
    }
    Ok(key)
}

/// Query a plan only while every referenced authority is still live.
pub fn query(domain: DomainKey, key: LaunchPlanKey) -> Result<LaunchPlanSnapshot, LaunchError> {
    let (plan, authority) = plan_authority(domain, key)?;
    let sandboxes = SANDBOXES.lock();
    let storage = STORAGE.lock();
    let workloads = WORKLOADS.lock();
    let plans = LAUNCH.lock();
    let result = plans.plan_live(
        domain,
        &workloads,
        &sandboxes,
        &storage,
        &authority,
        key,
    );
    drop(plans);
    drop(workloads);
    drop(storage);
    drop(sandboxes);
    result?;
    authority.revalidate()?;
    Ok(plan)
}

fn plan_authority(
    domain: DomainKey,
    key: LaunchPlanKey,
) -> Result<(LaunchPlanSnapshot, KernelLaunchAuthority), LaunchError> {
    let (plan, device_count, devices, data_count, data_scopes) = {
        let plans = LAUNCH.lock();
        let plan = plans.plan(domain, key)?;
        let mut devices = [None; kernel_core::sandbox_launch::MAX_DEVICE_GRANTS];
        for (index, slot) in devices.iter_mut().enumerate().take(plan.devices as usize) {
            *slot = Some(plans.device(domain, key, index as u16)?);
        }
        let mut data_scopes = [None; kernel_core::sandbox_launch::MAX_DATA_SCOPES];
        for (index, slot) in data_scopes
            .iter_mut()
            .enumerate()
            .take(plan.data_scopes as usize)
        {
            *slot = Some(plans.data_scope(domain, key, index as u16)?);
        }
        (
            plan,
            plan.devices as usize,
            devices,
            plan.data_scopes as usize,
            data_scopes,
        )
    };
    let mut device_grants = [DeviceGrant {
        object: 0,
        generation: 0,
        rights: 0,
        owner: DomainKey::NONE,
        grantee: DomainKey::NONE,
    }; kernel_core::sandbox_launch::MAX_DEVICE_GRANTS];
    for (target, source) in device_grants.iter_mut().zip(devices[..device_count].iter().flatten()) {
        *target = *source;
    }
    let mut data_grants = [DataScopeGrant {
        object: 0,
        generation: 0,
        owner: DomainKey::NONE,
        grantee: DomainKey::NONE,
        writable: false,
    }; kernel_core::sandbox_launch::MAX_DATA_SCOPES];
    for (target, source) in data_grants[..data_count]
        .iter_mut()
        .zip(data_scopes[..data_count].iter().flatten())
    {
        *target = *source;
    }
    let authority = KernelLaunchAuthority::snapshot(
        domain,
        plan.sandbox,
        plan.image,
        &device_grants[..device_count],
        &data_grants[..data_count],
        plan.network_policy,
    );
    Ok((plan, authority))
}

/// Start the bounded native child admitted by one launch plan.
///
/// The supplied ELF must hash to the plan's immutable image content. The plan
/// is consumed once, and the child is bound to a child Workload whose limits
/// are the admitted plan limits. No logical path participates in authority.
pub fn start(
    domain: DomainKey,
    key: LaunchPlanKey,
    image: &[u8],
) -> Result<kernel_core::object::HandleId, LaunchError> {
    if image.is_empty() || image.len() as u64 > MAX_IMAGE_BYTES {
        return Err(LaunchError::InvalidImage);
    }
    let (plan, authority) = plan_authority(domain, key)?;
    if !plan.capabilities.contains(CapabilitySet::EXECUTE) {
        return Err(LaunchError::Capability);
    }
    let digest: [u8; 32] = Sha256::digest(image).into();
    if ContentDigest::new(digest) != Some(plan.image_content) {
        return Err(LaunchError::Ownership);
    }

    let sandboxes = SANDBOXES.lock();
    let storage = STORAGE.lock();
    let workloads = WORKLOADS.lock();
    let plan = LAUNCH
        .lock()
        .begin_start(domain, &workloads, &sandboxes, &storage, &authority, key);
    drop(workloads);
    drop(storage);
    drop(sandboxes);
    let plan = plan?;
    if let Err(error) = authority.revalidate() {
        let _ = LAUNCH.lock().fail_start(domain, key);
        return Err(error);
    }

    let parent = proc::current_process().ok_or(LaunchError::InvalidRoot)?;
    let child_workload = match create_child_workload(domain, plan.root, plan.resources) {
        Ok(child) => child,
        Err(error) => {
            let _ = LAUNCH.lock().fail_start(domain, key);
            return Err(error);
        }
    };
    if let Err(error) = LAUNCH.lock().attach_child(domain, key, child_workload) {
        discard_child_workload(domain, child_workload);
        let _ = LAUNCH.lock().fail_start(domain, key);
        return Err(error);
    }

    let calls = SyscallSet::of(&[abi::SYSTEM_CONSOLE_WRITE, abi::SYSTEM_PROCESS_EXIT]);
    let spawned = match proc::spawn::spawn_child_with_workload(
        parent,
        image,
        calls,
        0,
        CPU_UNLIMITED,
        Some(child_workload),
    ) {
        Ok(spawned) => spawned,
        Err(_) => {
            discard_child_workload(domain, child_workload);
            let _ = LAUNCH.lock().fail_start(domain, key);
            return Err(LaunchError::Spawn);
        }
    };
    if proc::close_handle_for(parent, spawned.channel).is_err() {
        let _ = proc::close_handle_for(parent, spawned.process);
        discard_child_workload(domain, child_workload);
        let _ = LAUNCH.lock().fail_start(domain, key);
        return Err(LaunchError::Spawn);
    }
    kprintln!(
        "[JSR-SANDBOX-LAUNCH] started plan={:#x} child_handle={:#x} workload={:#x}",
        key.to_raw(),
        spawned.process.raw(),
        child_workload.to_raw()
    );
    Ok(spawned.process)
}

/// Destroy a same-domain plan identity and invalidate its generation.
pub fn destroy(domain: DomainKey, key: LaunchPlanKey) -> Result<(), LaunchError> {
    let child = {
        let plans = LAUNCH.lock();
        plans.child_workload(domain, key)?
    };
    if let Some(child) = child {
        crate::kobj::run_cleanup(32);
        let members = crate::workload::member_count_in_domain(domain, child)
            .map_err(LaunchError::Workload)?;
        if members != 0 {
            let _ = crate::workload::terminate_in_domain(domain, child);
            return Err(LaunchError::ChildNotTerminated);
        }
        let snapshot =
            crate::workload::snapshot_in_domain(domain, child).map_err(LaunchError::Workload)?;
        if snapshot.usage != ResourceUsage::default() || snapshot.children != 0 {
            return Err(LaunchError::ChildNotTerminated);
        }
        match snapshot.state {
            WorkloadState::Running => {
                crate::workload::transition(child, WorkloadState::Stopping)
                    .map_err(LaunchError::Workload)?;
                crate::workload::transition(child, WorkloadState::Stopped)
                    .map_err(LaunchError::Workload)?;
            }
            WorkloadState::Stopping => {
                crate::workload::transition(child, WorkloadState::Stopped)
                    .map_err(LaunchError::Workload)?;
            }
            WorkloadState::Stopped | WorkloadState::Failed => {}
            _ => return Err(LaunchError::ChildNotTerminated),
        }
        crate::workload::destroy_in_domain(domain, child).map_err(LaunchError::Workload)?;
    }
    LAUNCH.lock().destroy(domain, key)
}

fn create_child_workload(
    domain: DomainKey,
    root: WorkloadKey,
    resources: kernel_core::sandbox_launch::LaunchResources,
) -> Result<WorkloadKey, LaunchError> {
    let mut workloads = WORKLOADS.lock();
    let parent = workloads.snapshot(root).map_err(LaunchError::Workload)?;
    if parent.domain != domain || parent.state != WorkloadState::Running {
        return Err(LaunchError::InvalidRoot);
    }
    let child = workloads
        .create_child(root, resources.limits)
        .map_err(LaunchError::Workload)?;
    if let Some(rate) = resources.io_rate {
        if let Err(error) = workloads.configure_io_rate(child, rate) {
            let _ = workloads.transition(child, WorkloadState::Failed);
            let _ = workloads.destroy(child);
            return Err(LaunchError::Workload(error));
        }
    }
    if let Err(error) = workloads
        .transition(child, WorkloadState::Ready)
        .and_then(|()| workloads.transition(child, WorkloadState::Running))
    {
        let _ = workloads.transition(child, WorkloadState::Failed);
        let _ = workloads.destroy(child);
        return Err(LaunchError::Workload(error));
    }
    Ok(child)
}

fn discard_child_workload(domain: DomainKey, child: WorkloadKey) {
    crate::kobj::run_cleanup(32);
    let Ok(snapshot) = crate::workload::snapshot_in_domain(domain, child) else {
        return;
    };
    if crate::workload::member_count_in_domain(domain, child).unwrap_or(1) != 0
        || snapshot.usage != ResourceUsage::default()
        || snapshot.children != 0
    {
        let _ = crate::workload::terminate_in_domain(domain, child);
        return;
    }
    match snapshot.state {
        WorkloadState::Running => {
            let _ = crate::workload::transition(child, WorkloadState::Stopping);
        }
        WorkloadState::Stopping => {}
        WorkloadState::Stopped | WorkloadState::Failed => {}
        _ => {
            let _ = crate::workload::transition(child, WorkloadState::Failed);
        }
    }
    if let Ok(snapshot) = crate::workload::snapshot_in_domain(domain, child) {
        if snapshot.state == WorkloadState::Stopping {
            let _ = crate::workload::transition(child, WorkloadState::Stopped);
        }
    }
    let _ = crate::workload::destroy_in_domain(domain, child);
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
