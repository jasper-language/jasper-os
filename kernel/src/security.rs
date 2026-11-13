//! Kernel-side SEC-1 bootstrap and classification helpers.

use kernel_core::kobj_type::Kind;
use kernel_core::object::ObjectType;
use kernel_core::objtable::ObjId;
use kernel_core::mac::{
    MacDenial, MacEffect, MacEngine, MacLabel, MacPolicy, MacPolicyPackage, MacRule,
    PolicyDigest, PolicySignature, PolicySignatureVerifier, PolicySlot, PolicySource, SubjectLabel,
};
use kernel_core::object::HandleId;
use kernel_core::security::{
    ApplicationIdentity, BootId, IdentityClass, ModuleIdentity, ObjectIdentity, SecurityContext,
    SecurityError, SecurityDomain,
};

use core::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::{Signature, VerifyingKey};

use crate::arch;
use crate::kobj::{self, Table};
use crate::kprintln;
use crate::sync::IrqSpinLock;

static BOOT_ID: IrqSpinLock<Option<BootId>> = IrqSpinLock::new(None);
static MAC: IrqSpinLock<MacEngine> = IrqSpinLock::new(MacEngine::new(PolicySlot::deny_all(
    PolicySource {
        authority_id: 0x4a53_524d_4143_0001,
        version: 1,
    },
)));
static MAC_AUDIT_DRAINED: AtomicU64 = AtomicU64::new(0);
static MAC_AUDIT_DENIED: AtomicU64 = AtomicU64::new(0);
static MAC_AUDIT_DIGEST: AtomicU64 = AtomicU64::new(0);
static MAC_AUDIT_OVERFLOW: AtomicU64 = AtomicU64::new(0);

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
        Kind::EventSource | Kind::Subscription | Kind::Installation => IdentityClass::Service,
        Kind::ExitState => IdentityClass::KernelObject,
        Kind::Event | Kind::Ring | Kind::Endpoint | Kind::Mutex | Kind::Timer => {
            IdentityClass::KernelObject
        }
    }
}

const MAC_CLASSES: [IdentityClass; 9] = [
    IdentityClass::KernelObject,
    IdentityClass::Process,
    IdentityClass::Task,
    IdentityClass::Memory,
    IdentityClass::Device,
    IdentityClass::Vcpu,
    IdentityClass::Service,
    IdentityClass::Module,
    IdentityClass::Bootstrap,
];

const MAC_EFFECTS: [MacEffect; 5] = [
    MacEffect::Observe,
    MacEffect::Read,
    MacEffect::Write,
    MacEffect::Control,
    MacEffect::Share,
];

struct BuiltinPolicyVerifier;

const BUILTIN_POLICY_PUBLIC_KEY: [u8; 32] = [
    0x17, 0xcb, 0x79, 0xfb, 0x2b, 0x41, 0x20, 0xf2, 0xb1, 0xec, 0x65, 0xe4, 0x19, 0x8d,
    0x6e, 0x08, 0xb2, 0x8e, 0x81, 0x3f, 0xeb, 0x01, 0xe4, 0xa4, 0x00, 0x83, 0x9b, 0x85,
    0xe1, 0x80, 0x80, 0xce,
];

const BUILTIN_POLICY_SIGNATURE: [u8; 64] = [
    0x04, 0xe6, 0x38, 0xe3, 0xd3, 0x26, 0x7f, 0xbf, 0x15, 0x66, 0x80, 0xe5, 0xf2, 0x4b,
    0x62, 0x30, 0xd2, 0x35, 0xd9, 0xff, 0x7c, 0x64, 0x37, 0x51, 0x0d, 0xd9, 0xe7, 0xc4,
    0xd0, 0xc1, 0x98, 0x48, 0x68, 0x74, 0xe4, 0x96, 0x87, 0xe8, 0xdd, 0x1f, 0xac, 0x78,
    0xfb, 0x92, 0x0c, 0x80, 0x0f, 0x04, 0x27, 0x09, 0x12, 0x01, 0x01, 0x71, 0x1e, 0x46,
    0xb0, 0x2a, 0x3f, 0xf8, 0xea, 0xaf, 0xc3, 0x0c,
];

impl PolicySignatureVerifier for BuiltinPolicyVerifier {
    fn verify(
        &self,
        source: PolicySource,
        digest: PolicyDigest,
        signature: PolicySignature,
    ) -> bool {
        if source != builtin_policy_source() || signature.0 != BUILTIN_POLICY_SIGNATURE {
            return false;
        }
        let Ok(key) = VerifyingKey::from_bytes(&BUILTIN_POLICY_PUBLIC_KEY) else {
            return false;
        };
        let signature = Signature::from_bytes(&signature.0);
        const DOMAIN: &[u8] = b"jasper.mac.policy.v1\0";
        let mut message = [0u8; 32 + DOMAIN.len()];
        message[..DOMAIN.len()].copy_from_slice(DOMAIN);
        message[DOMAIN.len()..].copy_from_slice(&digest.0);
        key.verify_strict(&message, &signature).is_ok()
    }
}

const fn builtin_policy_source() -> PolicySource {
    PolicySource {
        authority_id: 0x4a53_524d_4143_0001,
        version: 1,
    }
}

fn bootstrap_policy() -> MacPolicy {
    let source = builtin_policy_source();
    let mut package = MacPolicyPackage::empty(source);
    package.signature = PolicySignature(BUILTIN_POLICY_SIGNATURE);
    package
        .push(MacRule::new(
            SecurityDomain::SYSTEM,
            SecurityDomain::SYSTEM,
            &MAC_EFFECTS,
            &MAC_CLASSES,
        ))
        .expect("built-in MAC policy has fixed capacity");
    package
        .push(MacRule::new(
            SecurityDomain::USER,
            SecurityDomain::USER,
            &MAC_EFFECTS,
            &MAC_CLASSES,
        ))
        .expect("built-in MAC policy has fixed capacity");
    package
        .push(MacRule::new(
            SecurityDomain::USER,
            SecurityDomain::SYSTEM,
            &[MacEffect::Observe, MacEffect::Read, MacEffect::Write, MacEffect::Control],
            &[
                IdentityClass::Device,
                IdentityClass::Vcpu,
                IdentityClass::Service,
                IdentityClass::KernelObject,
                IdentityClass::Module,
            ],
        ))
        .expect("built-in MAC policy has fixed capacity");
    package.seal_digest();
    MacPolicy::compile_verified(package, source, &BuiltinPolicyVerifier)
        .expect("built-in MAC policy must be valid")
}

/// Install the explicit deny-by-default bootstrap policy.  This is safe to
/// call more than once; later manager reloads still advance the policy epoch.
pub fn init_mac() -> Result<(), MacDenial> {
    let mut engine = MAC.lock();
    let installed = engine.epoch() == 1;
    if installed {
        let _ = engine.replace_policy(bootstrap_policy())?;
    }
    let epoch = engine.epoch();
    drop(engine);
    if installed {
        kprintln!(
            "[JSR-SEC3] policy=installed epoch={} audit_capacity={}",
            epoch,
            kernel_core::mac::MAX_AUDIT_EVENTS
        );
    }
    Ok(())
}

fn subject_label(context: SecurityContext) -> SubjectLabel {
    SubjectLabel::from_label(context.mac)
}

fn authorize_label_pair(
    subject_context: SecurityContext,
    object_context: SecurityContext,
    effect: MacEffect,
) -> Result<(), MacDenial> {
    init_mac()?;
    MAC.lock()
        .authorize(
            subject_context.object,
            subject_label(subject_context),
            object_context.object,
            object_context.mac,
            effect,
        )
        .map(|_| ())
}

/// Authorize a non-KObject identity such as a network endpoint or file object
/// with an explicit class, generation and MAC label.
pub fn authorize_object_label(
    context: SecurityContext,
    class: IdentityClass,
    object_id: u64,
    generation: u32,
    label: MacLabel,
    effect: MacEffect,
) -> Result<(), MacDenial> {
    if object_id == 0 || generation == 0 {
        return Err(MacDenial::InvalidObjectLabel);
    }
    init_mac()?;
    MAC.lock()
        .authorize(
            context.object,
            subject_label(context),
            ObjectIdentity {
                boot_id: context.object.boot_id,
                class,
                object_id,
                generation,
            },
            label,
            effect,
        )
        .map(|_| ())
}

/// File objects use the generic labeled-object gate with the stable
/// KernelObject MAC class retained by the signed bootstrap policy.
pub fn authorize_file_label(
    context: SecurityContext,
    file_object_id: u64,
    file_generation: u32,
    label: MacLabel,
    effect: MacEffect,
) -> Result<(), MacDenial> {
    authorize_object_label(
        context,
        IdentityClass::KernelObject,
        file_object_id,
        file_generation,
        label,
        effect,
    )
}

/// Authorize a public syscall effect.  The first handle argument, when valid,
/// names the object label; otherwise the calling process object is the object
/// under policy.  Handle/Rights and SyscallSet remain independent gates.
pub fn authorize_syscall(
    pid: ObjId,
    first_arg: u64,
    operation: &'static str,
    effect: kernel_core::meta::Effects,
) -> Result<(), MacDenial> {
    let effect = match operation {
        "system.handle.duplicate" | "system.channel.send" => MacEffect::Share,
        "system.handle.close" | "system.handle.restrict" | "system.process.exit" => {
            MacEffect::Control
        }
        _ => MacEffect::from_effects(effect),
    };
    let (subject_context, object_context) = kobj::with(|t| {
        let subject = t.security(pid).ok()?.require_active().ok()?;
        let object = ObjId::from_raw(
            proc_target_in(t, pid, HandleId::from_raw(first_arg))
                .map(|id| id.raw())
                .unwrap_or_else(|| pid.raw()),
        )
        .and_then(|id| t.security(id).ok())
        .unwrap_or(subject);
        Some((subject, object))
    })
    .ok_or(MacDenial::NoPolicy)?;
    authorize_label_pair(subject_context, object_context, effect)
}

fn proc_target_in(t: &mut Table, pid: ObjId, handle: HandleId) -> Option<ObjId> {
    crate::proc::handle_in(t, pid, handle)
        .ok()
        .and_then(|(object, _)| ObjId::from_raw(object.id.0))
}

/// Authorize a delayed Ring target before the backend captures resources.
pub fn authorize_handle(pid: ObjId, handle: HandleId, effect: MacEffect) -> Result<(), MacDenial> {
    let (subject, object) = kobj::with(|t| {
        let subject = t.security(pid).ok()?.require_active().ok()?;
        let target = proc_target_in(t, pid, handle)?;
        let object = t.security(target).ok()?;
        Some((subject, object))
    })
    .ok_or(MacDenial::NoPolicy)?;
    authorize_label_pair(subject, object, effect)
}

/// Return a bounded decision queue for the audit consumer.
pub fn take_audit() -> Option<kernel_core::mac::MacDecision> {
    MAC.lock().drain_audit()
}

pub fn policy_epoch() -> u64 {
    MAC.lock().epoch()
}

pub fn audit_overflow_attempts() -> u64 {
    MAC.lock()
        .audit_overflow_attempts()
        .max(MAC_AUDIT_OVERFLOW.load(Ordering::Relaxed))
}

/// Commit all decisions produced by the current syscall. The queue is never
/// overwritten; callers always drain it before another syscall can consume the
/// bounded capacity.
pub fn flush_audit() {
    let mut engine = MAC.lock();
    let mut drained = 0u64;
    let mut denied = 0u64;
    let mut last_digest = MAC_AUDIT_DIGEST.load(Ordering::Relaxed);
    while let Some(decision) = engine.drain_audit() {
        drained = drained.saturating_add(1);
        if !decision.allowed {
            denied = denied.saturating_add(1);
        }
        last_digest = decision.digest;
    }
    let overflow = engine.audit_overflow_attempts();
    drop(engine);
    MAC_AUDIT_DRAINED.fetch_add(drained, Ordering::Relaxed);
    MAC_AUDIT_DENIED.fetch_add(denied, Ordering::Relaxed);
    MAC_AUDIT_DIGEST.store(last_digest, Ordering::Relaxed);
    MAC_AUDIT_OVERFLOW.store(overflow, Ordering::Relaxed);
}

pub fn audit_stats() -> (u64, u64, u64, u64) {
    (
        MAC_AUDIT_DRAINED.load(Ordering::Relaxed),
        MAC_AUDIT_DENIED.load(Ordering::Relaxed),
        MAC_AUDIT_DIGEST.load(Ordering::Relaxed),
        audit_overflow_attempts(),
    )
}

pub fn process_mac_label_in(t: &Table, pid: ObjId) -> Option<MacLabel> {
    Some(t.security(pid).ok()?.mac)
}

#[cfg(feature = "sec3-verify")]
pub fn set_mac_for_verify(id: ObjId, mac: MacLabel) -> Result<(), ()> {
    kobj::with(|t| t.set_mac_for_verify(id, mac).map_err(|_| ()))
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
        ObjectType::EventSource | ObjectType::Subscription | ObjectType::Installation => {
            IdentityClass::Service
        }
        ObjectType::Event
        | ObjectType::Timer
        | ObjectType::Ring
        | ObjectType::AddressSpace
        | ObjectType::Channel
        | ObjectType::Mutex => IdentityClass::KernelObject,
    }
}
