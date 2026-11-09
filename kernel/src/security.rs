//! Kernel-side SEC-1 bootstrap and classification helpers.

use kernel_core::kobj_type::Kind;
use kernel_core::object::ObjectType;
use kernel_core::objtable::ObjId;
use kernel_core::security::{
    ApplicationIdentity, BootId, IdentityClass, ModuleIdentity, SecurityContext, SecurityError,
};

use crate::arch;
use crate::kobj::{self, Table};
use crate::sync::IrqSpinLock;

static BOOT_ID: IrqSpinLock<Option<BootId>> = IrqSpinLock::new(None);

fn mix64(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

/// Boot-scoped identity. The cycle seed separates boots on the same image; it
/// is not advertised as cryptographic randomness.
pub fn boot_id() -> BootId {
    let mut slot = BOOT_ID.lock();
    if let Some(id) = *slot {
        return id;
    }
    let seed = arch::cycles() ^ ((arch::cpu_index() as u64) << 32);
    let lo = mix64(seed ^ 0x5345_4331_424f_4f54);
    let mut hi = mix64(seed.rotate_left(29) ^ 0x4944_454e_5449_5459);
    if lo == 0 && hi == 0 {
        hi = 1;
    }
    let id = BootId::from_words([lo, hi]);
    *slot = Some(id);
    id
}

pub const fn identity_class(kind: Kind) -> IdentityClass {
    match kind {
        Kind::Process => IdentityClass::Process,
        Kind::Task => IdentityClass::Task,
        Kind::Memory => IdentityClass::Memory,
        Kind::Device | Kind::Interrupt | Kind::DmaMapping => IdentityClass::Device,
        Kind::Vcpu => IdentityClass::Vcpu,
        Kind::EventSource | Kind::Subscription => IdentityClass::Service,
        Kind::ExitState => IdentityClass::KernelObject,
        Kind::Event | Kind::Ring | Kind::Endpoint | Kind::Mutex | Kind::Timer => {
            IdentityClass::KernelObject
        }
    }
}

pub fn process_application_in(t: &Table, pid: ObjId) -> Option<ApplicationIdentity> {
    t.security(pid).ok()?.application
}

pub fn process_application(pid: ObjId) -> Option<ApplicationIdentity> {
    kobj::with(|t| process_application_in(t, pid))
}

pub fn bind_process_application_in(
    t: &mut Table,
    pid: ObjId,
    application: ApplicationIdentity,
) -> Result<SecurityContext, SecurityError> {
    match t.get(pid) {
        Ok(kobj::KObject::Process(_)) => {}
        _ => return Err(SecurityError::MissingMetadata),
    }
    t.bind_application(pid, application)
}

pub fn object_context(id: ObjId) -> Option<SecurityContext> {
    kobj::with(|t| t.security(id).ok())
}

pub fn require_active(id: ObjId) -> Result<SecurityContext, SecurityError> {
    object_context(id)
        .ok_or(SecurityError::MissingMetadata)?
        .require_active()
}

pub fn module_identity(name: &str, version: &str, generation: u32) -> ModuleIdentity {
    ModuleIdentity::from_name_version(boot_id(), name, version, generation)
}

/// Compatibility projection for the existing IPC `out_sender_app` field.
pub fn legacy_app_id(application: Option<ApplicationIdentity>) -> u32 {
    application
        .filter(|application| application.stable_id <= u32::MAX as u64)
        .map_or(0, |application| application.stable_id as u32)
}

/// Object type to security class, kept separate from the object-table type.
pub const fn identity_class_for_object(ty: ObjectType) -> IdentityClass {
    match ty {
        ObjectType::Process => IdentityClass::Process,
        ObjectType::Task => IdentityClass::Task,
        ObjectType::Memory => IdentityClass::Memory,
        ObjectType::Device | ObjectType::Interrupt | ObjectType::DmaMapping => {
            IdentityClass::Device
        }
        ObjectType::Vcpu => IdentityClass::Vcpu,
        ObjectType::EventSource | ObjectType::Subscription => IdentityClass::Service,
        ObjectType::Event
        | ObjectType::Timer
        | ObjectType::Ring
        | ObjectType::AddressSpace
        | ObjectType::Channel
        | ObjectType::Mutex => IdentityClass::KernelObject,
    }
}
