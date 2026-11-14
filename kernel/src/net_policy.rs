//! Kernel-owned live NET policy authority used by Sandbox launch admission.
//!
//! This registry is the single source of liveness for a policy reference. A
//! reference is valid only for the exact security domain, Sandbox scope and
//! installation generation that created it.

use kernel_core::net::{
    LiveNetworkPolicies, NetError, NetVersion, NetworkPolicy,
};
use kernel_core::sandbox::SandboxKey;
use kernel_core::sandbox_launch::NetworkPolicyRef;
use kernel_core::security_domain::DomainKey;

use crate::sync::IrqSpinLock;

const MAX_LIVE_POLICIES: usize = 32;

static POLICIES: IrqSpinLock<LiveNetworkPolicies<MAX_LIVE_POLICIES>> =
    IrqSpinLock::new(LiveNetworkPolicies::new());

pub(crate) fn install(
    domain: DomainKey,
    sandbox: SandboxKey,
    policy: NetworkPolicy,
) -> Result<NetworkPolicyRef, NetError> {
    POLICIES.lock().install(domain, sandbox.to_raw(), policy)?;
    Ok(reference(sandbox, policy))
}

pub(crate) fn live(
    domain: DomainKey,
    sandbox: SandboxKey,
    reference: NetworkPolicyRef,
) -> bool {
    reference.policy == sandbox.to_raw()
        && POLICIES
            .lock()
            .snapshot(domain, sandbox.to_raw(), reference.generation)
            .is_ok()
}

pub(crate) fn revoke(
    domain: DomainKey,
    sandbox: SandboxKey,
    reference: NetworkPolicyRef,
) -> Result<(), NetError> {
    if reference.policy != sandbox.to_raw() {
        return Err(NetError::Revoked);
    }
    POLICIES
        .lock()
        .revoke(domain, sandbox.to_raw(), reference.generation)
}

pub(crate) fn provision_default(
    domain: DomainKey,
    sandbox: SandboxKey,
) -> Result<NetworkPolicyRef, NetError> {
    install(
        domain,
        sandbox,
        NetworkPolicy {
            version: NetVersion::V1_0_0,
            allowed: kernel_core::net::NetCapabilities::NONE,
            required: kernel_core::net::NetCapabilities::NONE,
            epoch: 1,
        },
    )
}

pub(crate) fn revoke_scope(domain: DomainKey, sandbox: SandboxKey) -> bool {
    POLICIES
        .lock()
        .revoke_scope(domain, sandbox.to_raw())
}

const fn reference(sandbox: SandboxKey, policy: NetworkPolicy) -> NetworkPolicyRef {
    NetworkPolicyRef {
        policy: sandbox.to_raw(),
        generation: policy.epoch,
    }
}
