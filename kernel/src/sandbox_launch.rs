//! Kernel-owned bounded Sandbox launch-plan registry.
//!
//! Every create/query revalidates Sandbox, root Workload, image, volume, resource
//! attenuation and external authority facts under the registered lock order.
//! Logical paths are never stored or consulted.

use kernel_core::sandbox_launch::{
    CapabilitySet, DataScopeGrant, DeviceGrant, LaunchAuthority, LaunchError, LaunchPlanKey,
    LaunchPlanSnapshot, LaunchSpec, NetworkPolicyRef, SandboxLaunchTable,
};
use kernel_core::object::Rights;
use kernel_core::objtable::ObjId;
use kernel_core::security_domain::DomainKey;

use crate::proc::{self, DeviceAuthorityTicket};
use crate::sandbox::{MAX_SANDBOXES, SANDBOXES};
use crate::sandbox_storage::{MAX_IMAGES, MAX_LAYERS, MAX_VOLUMES, STORAGE};
use crate::sync::IrqSpinLock;
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
/// and NET policy remain denied until their own live registries exist.
struct KernelLaunchAuthority {
    domain: DomainKey,
    root_capabilities: CapabilitySet,
    root_ticket: Option<DeviceAuthorityTicket>,
    device_tickets: [Option<DeviceAuthorityTicket>; kernel_core::sandbox_launch::MAX_DEVICE_GRANTS],
}

impl KernelLaunchAuthority {
    fn snapshot(
        domain: DomainKey,
        devices: &[DeviceGrant],
    ) -> Self {
        let mut intrinsic =
            CapabilitySet::EXECUTE.union(CapabilitySet::DATA_READ).union(CapabilitySet::DATA_WRITE);
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
        Self {
            domain,
            root_capabilities: intrinsic,
            root_ticket,
            device_tickets,
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
        _domain: DomainKey,
        _sandbox: kernel_core::sandbox::SandboxKey,
        _grant: DataScopeGrant,
    ) -> bool {
        false
    }

    fn network_policy_live(&self, _domain: DomainKey, _policy: NetworkPolicyRef) -> bool {
        false
    }
}

/// Admit one immutable launch plan.
pub fn create(domain: DomainKey, spec: LaunchSpec<'_>) -> Result<LaunchPlanKey, LaunchError> {
    let authority = KernelLaunchAuthority::snapshot(domain, spec.devices);
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
    let (plan, device_count, devices) = {
        let plans = LAUNCH.lock();
        let plan = plans.plan(domain, key)?;
        let mut devices = [None; kernel_core::sandbox_launch::MAX_DEVICE_GRANTS];
        for (index, slot) in devices.iter_mut().enumerate().take(plan.devices as usize) {
            *slot = Some(plans.device(domain, key, index as u16)?);
        }
        (plan, plan.devices as usize, devices)
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
    let authority = KernelLaunchAuthority::snapshot(domain, &device_grants[..device_count]);
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
