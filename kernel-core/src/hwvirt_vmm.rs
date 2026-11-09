//! Vendor-neutral HWV-4 VM-exit observation contract.
//!
//! VM exits are observations of the execution backend; this module does not
//! own the Ring or vCPU object. The kernel bridge delivers the observation as
//! one Ring completion, so cancellation and single-terminal rules remain owned
//! by the existing asynchronous Ring state machine.

use crate::hwvirt::Backend;

/// One VM exit delivered to the VMM-facing side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmExitEvent {
    pub backend: Backend,
    pub reason: u32,
    pub qualification: u64,
    pub guest_physical: u64,
    pub vector: u8,
    pub instruction_length: u8,
}

impl VmExitEvent {
    /// Stable diagnostic name for the backend-independent event envelope.
    pub const fn name(self) -> &'static str {
        "system.hwvirt.vcpu.exit"
    }
}
