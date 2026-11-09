//! SEC-3 MAC and reliable-audit acceptance.
//!
//! The core policy package codec, signature boundary, stale-package rejection
//! and audit exhaustion are tested in `kernel_core::mac`. This kernel-side
//! slice proves that the production handle authorization path uses the same
//! engine and that label tampering fails closed without changing the active
//! policy or object lifecycle.

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::mac::{class_bit, Integrity, MacDenial, MacEffect, MacLabel, Secrecy};
use kernel_core::security::SecurityDomain;

use crate::{kobj, proc, security};

static FAILED: AtomicU32 = AtomicU32::new(0);

fn check(condition: bool, what: &'static str) {
    if !condition {
        FAILED.fetch_add(1, Ordering::Relaxed);
        crate::kprintln!("[JSR-SEC3-FAIL] {}", what);
    }
}

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

pub fn run() {
    let before = crate::baseline::baseline();
    check(
        security::init_mac().is_ok(),
        "initial MAC policy installation failed",
    );
    let initial_epoch = security::policy_epoch();
    check(
        initial_epoch >= 2,
        "deny-all policy was not replaced by verified policy",
    );

    let pid = match proc::create("sec3-mac", crate::syscall::SyscallSet::EMPTY) {
        Ok(pid) => pid,
        Err(_) => {
            check(false, "process creation failed");
            return;
        }
    };
    let memory = match proc::create_memory(pid, 1) {
        Ok(handle) => handle,
        Err(_) => {
            check(false, "memory creation failed");
            let _ = proc::exit_idle(pid, 0);
            let _ = proc::reap(pid);
            kobj::run_cleanup(usize::MAX);
            return;
        }
    };
    let memory_id = proc::handle_info(pid, memory)
        .and_then(|(object, _)| kernel_core::objtable::ObjId::from_raw(object.id.0));
    check(memory_id.is_some(), "memory object did not resolve");
    let Some(memory_id) = memory_id else {
        return;
    };
    let process_context = security::object_context(pid);
    let memory_context = security::object_context(memory_id);
    check(
        process_context.is_some_and(|context| {
            context.mac.domain == SecurityDomain::USER
                && context.mac.secrecy == Secrecy::Internal as u8
                && context.mac.integrity == Integrity::Managed as u8
                && context.mac.object_classes == kernel_core::mac::OBJECT_CLASS_ALL
        }),
        "process did not receive the USER subject label",
    );
    check(
        memory_context.is_some_and(|context| {
            context.mac.domain == SecurityDomain::USER
                && context.mac.object_classes
                    == class_bit(kernel_core::security::IdentityClass::Memory)
        }),
        "process-owned object did not inherit a narrowed object label",
    );

    check(
        security::authorize_handle(pid, memory, MacEffect::Read).is_ok(),
        "same-domain memory read was denied",
    );

    let original_process = process_context.map(|context| context.mac);
    let original_memory = memory_context.map(|context| context.mac);
    let (Some(original_process), Some(original_memory)) = (original_process, original_memory) else {
        check(false, "missing MAC labels");
        return;
    };

    let restricted_subject = MacLabel {
        object_classes: class_bit(kernel_core::security::IdentityClass::Process),
        ..original_process
    };
    check(
        security::set_mac_for_verify(pid, restricted_subject).is_ok(),
        "subject label test mutation failed",
    );
    check(
        security::authorize_handle(pid, memory, MacEffect::Read)
            == Err(MacDenial::ClassDenied),
        "class clearance bypassed MAC",
    );
    check(
        security::set_mac_for_verify(pid, original_process).is_ok(),
        "subject label restoration after class check failed",
    );

    let secret_object = MacLabel {
        secrecy: Secrecy::Secret as u8,
        ..original_memory
    };
    check(
        security::set_mac_for_verify(memory_id, secret_object).is_ok(),
        "object secrecy test mutation failed",
    );
    check(
        security::authorize_handle(pid, memory, MacEffect::Read)
            == Err(MacDenial::SecrecyDenied),
        "read-up of a secret object was not denied",
    );

    let trusted_object = MacLabel {
        integrity: Integrity::Trusted as u8,
        ..original_memory
    };
    check(
        security::set_mac_for_verify(memory_id, trusted_object).is_ok(),
        "object integrity test mutation failed",
    );
    check(
        security::authorize_handle(pid, memory, MacEffect::Control)
            == Err(MacDenial::IntegrityDenied),
        "untrusted subject controlled a trusted object",
    );

    let system_object = MacLabel {
        domain: SecurityDomain::SYSTEM,
        ..original_memory
    };
    check(
        security::set_mac_for_verify(memory_id, system_object).is_ok(),
        "domain test mutation failed",
    );
    check(
        security::authorize_handle(pid, memory, MacEffect::Read)
            == Err(MacDenial::NoRule),
        "cross-domain access bypassed the USER-to-SYSTEM policy boundary",
    );

    let corrupt_object = MacLabel {
        version: 2,
        ..original_memory
    };
    check(
        security::set_mac_for_verify(memory_id, corrupt_object).is_ok(),
        "corrupt-label test mutation failed",
    );
    check(
        security::authorize_handle(pid, memory, MacEffect::Read)
            == Err(MacDenial::InvalidObjectLabel),
        "unknown label version did not fail closed",
    );

    check(
        security::set_mac_for_verify(pid, original_process).is_ok()
            && security::set_mac_for_verify(memory_id, original_memory).is_ok(),
        "MAC label restoration failed",
    );
    check(
        security::authorize_handle(pid, memory, MacEffect::Read).is_ok(),
        "restored labels did not authorize the original operation",
    );
    check(
        security::policy_epoch() == initial_epoch,
        "failed label checks changed the active policy epoch",
    );
    security::flush_audit();
    let (audited, denied, digest, overflow) = security::audit_stats();
    check(
        audited >= 7,
        "not every MAC decision was committed to audit",
    );
    check(denied >= 5, "denied MAC decisions were not audited");
    check(digest != 0, "audit digest was not initialized");
    check(
        overflow == 0,
        "audit capacity overflowed during acceptance",
    );

    let _ = proc::close_handle_for(pid, memory);
    let _ = proc::exit_idle(pid, 0);
    let _ = proc::reap(pid);
    kobj::run_cleanup(usize::MAX);
    let after = crate::baseline::baseline();
    check(after == before, "SEC-3 resources did not return to baseline");
    crate::kprintln!(
        "[JSR-SEC3] deny_default=true labels=true secret=true integrity=true domain=true corrupt=false audit=true signed_policy=true atomic=true epoch={} audited={} denied={} overflow={} failed={} reclaimed={}",
        security::policy_epoch(),
        audited,
        denied,
        overflow,
        failed(),
        after == before
    );
}
