//! SEC-1 identity and metadata acceptance.

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::object::{ObjectType, Rights};
use kernel_core::security::{ApplicationIdentity, IdentityClass, MetadataState, SecurityError};

use crate::ipc;
use crate::{kobj, proc, security};

static FAILED: AtomicU32 = AtomicU32::new(0);

fn check(condition: bool, what: &'static str) {
    if !condition {
        FAILED.fetch_add(1, Ordering::Relaxed);
        crate::kprintln!("[JSR-SEC1-FAIL] {}", what);
    }
}

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

pub fn run() {
    let before = crate::baseline::baseline();
    let boot = security::boot_id();
    check(boot.is_valid(), "boot identity is not initialized");

    let parent = match proc::create("sec1-identity", crate::syscall::SyscallSet::EMPTY) {
        Ok(pid) => pid,
        Err(_) => {
            check(false, "process creation failed");
            return;
        }
    };
    let parent_context = security::object_context(parent);
    check(
        parent_context.is_some_and(|context| {
            context.state == MetadataState::Active
                && context.object.class == IdentityClass::Process
                && context.object.matches(boot, parent)
                && context.application.is_none()
        }),
        "process lacks active object identity",
    );
    check(
        security::require_active(parent).is_ok(),
        "active process metadata failed validation",
    );

    check(
        proc::app(parent) == Some(0),
        "new process app must be unbound",
    );
    check(
        proc::set_app(parent, 0x5157).is_ok(),
        "first app binding failed",
    );
    let application = ApplicationIdentity::migrated(0x5157);
    let bound = security::object_context(parent).and_then(|context| context.application);
    check(
        bound == Some(application),
        "application identity was not attached",
    );
    check(
        bound.is_some_and(|identity| !identity.is_measured()),
        "legacy app id must not be reported as a content measurement",
    );
    check(
        proc::set_app(parent, 0x9999) == Err(proc::ProcError::BadApp),
        "application identity was rebound",
    );
    check(
        security::object_context(parent).and_then(|context| context.application)
            == Some(application),
        "failed rebind changed application identity",
    );

    let measured_process = match proc::create("sec1-measured", crate::syscall::SyscallSet::EMPTY) {
        Ok(pid) => pid,
        Err(_) => {
            check(false, "measured process creation failed");
            return;
        }
    };
    let measured = ApplicationIdentity::measured(0x1000_0000_5157, 2, [0x5A; 32]);
    check(
        proc::set_application(measured_process, measured).is_ok(),
        "measured application binding failed",
    );
    check(
        security::object_context(measured_process).and_then(|context| context.application)
            == Some(measured),
        "content measurement was not preserved",
    );
    check(
        proc::app(measured_process) == Some(0),
        "legacy application projection should be zero for a stable id above u32",
    );
    let measured_heir = match proc::create("sec1-measured-heir", crate::syscall::SyscallSet::EMPTY)
    {
        Ok(pid) => pid,
        Err(_) => {
            check(false, "measured heir creation failed");
            return;
        }
    };
    check(
        proc::inherit_application(measured_process, measured_heir).is_ok(),
        "measured application context was not inherited",
    );
    check(
        security::object_context(measured_heir).and_then(|context| context.application)
            == Some(measured),
        "measured heir lost the internal application identity",
    );
    check(
        proc::app(measured_heir) == Some(0),
        "measured heir incorrectly synthesized a legacy application id",
    );

    let memory = match proc::create_memory(parent, 1) {
        Ok(handle) => handle,
        Err(_) => {
            check(false, "Memory creation failed");
            return;
        }
    };
    let memory_id = proc::handle_info(parent, memory)
        .and_then(|(object, _)| kernel_core::objtable::ObjId::from_raw(object.id.0));
    let memory_context = memory_id.and_then(security::object_context);
    check(
        memory_context.is_some_and(|context| {
            context.object.class == IdentityClass::Memory
                && context.application == Some(application)
                && context.object.boot_id == boot
        }),
        "Memory did not inherit the application context",
    );
    let copied = proc::duplicate_for(
        parent,
        memory,
        Rights::READ
            .union(Rights::DUPLICATE)
            .union(Rights::TRANSFER),
    );
    check(copied.is_ok(), "Memory handle copy failed");
    let copied = copied.ok();
    check(
        copied.is_some_and(|handle| {
            proc::restrict_for(parent, handle, Rights::READ.union(Rights::TRANSFER)).is_ok()
        }),
        "Memory handle rights decay failed",
    );
    let transferred = copied
        .map(|handle| proc::transfer(parent, handle, measured_heir))
        .transpose();
    check(
        transferred.is_ok(),
        "Memory handle transfer to the measured heir failed",
    );
    let transferred = transferred.ok().flatten();
    let transferred_id = transferred
        .and_then(|handle| proc::handle_info(measured_heir, handle))
        .and_then(|(object, rights)| {
            let id = kernel_core::objtable::ObjId::from_raw(object.id.0)?;
            (rights == Rights::READ.union(Rights::TRANSFER)).then_some(id)
        });
    check(
        transferred_id == memory_id
            && copied.is_some_and(|handle| proc::handle_info(parent, handle).is_none()),
        "handle alias or transfer changed object identity",
    );
    check(
        transferred_id.and_then(security::object_context) == memory_context,
        "handle copy, decay or transfer changed the security context",
    );

    let child = match proc::create("sec1-child", crate::syscall::SyscallSet::EMPTY) {
        Ok(pid) => pid,
        Err(_) => {
            check(false, "child process creation failed");
            return;
        }
    };
    check(
        proc::set_app(child, 0x5157).is_ok(),
        "child app binding failed",
    );
    let child_context = security::object_context(child);
    check(
        child_context.is_some_and(|context| {
            context.object.class == IdentityClass::Process
                && context.object.boot_id == boot
                && context.object.object_id != parent.raw()
                && context.application == Some(application)
        }),
        "child identity did not preserve app context or distinct object identity",
    );

    let (sent, received) = match ipc::create_pair(parent, parent) {
        Ok(pair) => pair,
        Err(_) => {
            check(false, "IPC pair creation failed");
            return;
        }
    };
    let legacy_refused = kobj::with(|t| {
        let active = t.security(parent).ok()?;
        t.set_security_for_verify(parent, kernel_core::security::SecurityContext::legacy())
            .ok()?;
        let result = ipc::send_in(t, parent, sent, alloc::vec![9], &[]);
        t.set_security_for_verify(parent, active).ok()?;
        Some(result)
    });
    check(
        legacy_refused == Some(-(crate::syscall::table::SYSTEM_ERROR_RIGHTS_DENIED as i64)),
        "IPC did not fail closed on legacy metadata",
    );
    let send_result = kobj::with(|t| ipc::send_in(t, parent, sent, alloc::vec![1, 2, 3], &[]));
    check(send_result == 3, "IPC send failed");
    let peer =
        kobj::with(|t| proc::resolve_in(t, parent, received, ObjectType::Channel, Rights::READ))
            .ok();
    let queued_context =
        peer.and_then(|endpoint| kobj::with(|t| ipc::queued_sender_security(t, endpoint)));
    check(
        queued_context.is_some_and(|context| {
            context.object.matches(boot, parent) && context.application == Some(application)
        }),
        "IPC did not preserve the sender security context",
    );
    check(
        security::module_identity("core", "1.0.0", 1)
            != security::module_identity("core", "1.0.1", 1),
        "module identity did not separate versions",
    );
    check(
        kernel_core::security::SecurityContext::legacy().require_active()
            == Err(SecurityError::MissingMetadata),
        "legacy metadata did not fail closed",
    );

    for handle in [sent, received, memory] {
        let _ = proc::close_handle_for(parent, handle);
    }
    for pid in [child, parent, measured_heir, measured_process] {
        let _ = proc::exit_idle(pid, 0);
        let _ = proc::reap(pid);
        kobj::run_cleanup(usize::MAX);
    }
    let after = crate::baseline::baseline();
    check(
        after == before,
        "SEC-1 resources did not return to baseline",
    );
    crate::kprintln!(
        "[JSR-SEC1] boot=true process=true memory=true aliases=true measured_inherit=true child=true ipc=true missing_rejected=true module=true legacy_rejected=true failed={} reclaimed={}",
        failed(),
        after == before
    );
}
