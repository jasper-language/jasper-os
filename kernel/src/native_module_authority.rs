//! Production SEC/PEP adapter for native module lifecycle operations.
//!
//! The caller's trusted `SecurityContext` and the lifecycle target's stable
//! ModuleKey are evaluated by the existing MAC engine. Module names, paths and
//! AppIDs are never consulted for authorization.

use kernel_core::mac::{class_bit, Integrity, MacEffect, MacLabel, Secrecy};
use kernel_core::native_install::{Actor, OwnerScope};
use kernel_core::native_module_lifecycle::{
    ModuleAuthority, ModuleOperation, ModulePep, ModuleTarget, SecuredModuleAuthority,
};
use kernel_core::security::{IdentityClass, SecurityContext, SecurityDomain};

use crate::security;

struct GlobalModulePep;

static MODULE_PEP: GlobalModulePep = GlobalModulePep;

impl ModulePep for GlobalModulePep {
    fn authorize(
        &self,
        context: SecurityContext,
        operation: ModuleOperation,
        target: ModuleTarget,
    ) -> bool {
        let Some(key) = target.key() else {
            return false;
        };
        let effect = match operation {
            ModuleOperation::Query => MacEffect::Read,
            ModuleOperation::Install
            | ModuleOperation::Start
            | ModuleOperation::Stop
            | ModuleOperation::Uninstall => MacEffect::Control,
        };
        let target_label = module_label(target.owner());
        let decision = security::authorize_object_label(
            context,
            IdentityClass::Module,
            key.to_raw(),
            key.generation(),
            target_label,
            effect,
        );
        #[cfg(feature = "sec3-verify")]
        if let Err(error) = decision {
            crate::kprintln!(
                "[JSR-NATIVE-MODULE-PEP] operation={:?} denial={} subject_domain={:?} subject_secrecy={} subject_integrity={} subject_classes={:#x} target_domain={:?} target_secrecy={} target_integrity={} target_classes={:#x} key={} generation={}",
                operation,
                error.name(),
                context.mac.domain,
                context.mac.secrecy,
                context.mac.integrity,
                context.mac.object_classes,
                target_label.domain,
                target_label.secrecy,
                target_label.integrity,
                target_label.object_classes,
                key.to_raw(),
                key.generation(),
            );
        }
        decision.is_ok()
    }
}

const fn module_label(owner: OwnerScope) -> MacLabel {
    match owner {
        OwnerScope::System => MacLabel::system(IdentityClass::Module),
        OwnerScope::Device(_)
        | OwnerScope::User(_)
        | OwnerScope::Group(_)
        | OwnerScope::Tenant(_)
        | OwnerScope::Workload(_) => MacLabel::new(
            SecurityDomain::USER,
            Secrecy::Internal,
            Integrity::Managed,
            class_bit(IdentityClass::Module),
        ),
    }
}

/// Authorize one lifecycle request against the current global MAC/PEP engine.
pub(crate) fn authorize(
    context: SecurityContext,
    actor: Actor<'_>,
    operation: ModuleOperation,
    target: ModuleTarget,
) -> bool {
    SecuredModuleAuthority::new(context, &MODULE_PEP)
        .is_some_and(|authority| authority.authorize(actor, operation, target))
}

#[cfg(feature = "sec3-verify")]
pub(crate) fn verify(pid: kernel_core::objtable::ObjId) -> bool {
    use kernel_core::native_install::Subject;
    use kernel_core::native_module_lifecycle::{
        ModuleKey, ModuleLifecycle, ModuleName, ModuleSpec, ModuleStatus, ModuleVersion,
        NativeModuleRegistry, ScopeModuleAuthority,
    };

    struct VerifyLifecycle;

    impl ModuleLifecycle for VerifyLifecycle {
        fn activate(&mut self, _: ModuleStatus) -> Result<(), &'static str> {
            Ok(())
        }

        fn deactivate(&mut self, _: ModuleStatus) -> Result<(), &'static str> {
            Ok(())
        }
    }

    let Some(context) = security::require_active(pid).ok() else {
        return false;
    };
    let Some(key) = ModuleKey::from_raw((9u64 << 16) | 1) else {
        return false;
    };
    let target = ModuleTarget::new(OwnerScope::User(7), key);
    let owner = Actor::new(&[Subject::User(7)]);
    let other = Actor::new(&[Subject::User(8)]);
    let scope_allowed = ScopeModuleAuthority.authorize(owner, ModuleOperation::Query, target);
    let pep_allowed = MODULE_PEP.authorize(context, ModuleOperation::Query, target);
    let allowed = |operation| authorize(context, owner, operation, target);
    let query = allowed(ModuleOperation::Query);
    let start = allowed(ModuleOperation::Start);
    let stop = allowed(ModuleOperation::Stop);
    let owner_denied = !authorize(context, other, ModuleOperation::Start, target);
    let inactive_denied = !authorize(
        SecurityContext::legacy(),
        owner,
        ModuleOperation::Query,
        target,
    );
    let wrong_class_denied = !authorize(
        SecurityContext::new(
            context.object.boot_id,
            IdentityClass::Memory,
            kernel_core::objtable::ObjId::from_raw(0x7a00).unwrap(),
            None,
            kernel_core::security::MetadataState::Active,
        ),
        owner,
        ModuleOperation::Query,
        target,
    );
    let lifecycle_ok = SecuredModuleAuthority::new(context, &MODULE_PEP).is_some_and(|authority| {
        let mut registry = NativeModuleRegistry::<1>::new();
        let Some(name) = ModuleName::new("verify.module") else {
            return false;
        };
        let spec = ModuleSpec {
            name,
            version: ModuleVersion::new(1, 0, 0),
            owner: OwnerScope::User(7),
            dependencies: &[],
        };
        let Ok(key) = registry.install(owner, &authority, spec) else {
            return false;
        };
        let mut lifecycle = VerifyLifecycle;
        registry
            .start_with(owner, &authority, key, &mut lifecycle)
            .is_ok()
            && registry
                .stop_with(owner, &authority, key, &mut lifecycle)
                .is_ok()
            && registry.uninstall(owner, &authority, key).is_ok()
            && registry.is_empty()
    });
    let ok = query
        && start
        && stop
        && owner_denied
        && inactive_denied
        && wrong_class_denied
        && lifecycle_ok;
    crate::kprintln!(
        "[JSR-NATIVE-MODULE-AUTH] scope={} pep={} query={} start={} stop={} owner_denied={} inactive_denied={} class_denied={} lifecycle={} ok={}",
        scope_allowed,
        pep_allowed,
        query,
        start,
        stop,
        owner_denied,
        inactive_denied,
        wrong_class_denied,
        lifecycle_ok,
        ok
    );
    ok
}
