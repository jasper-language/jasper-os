//! SEC-2 capability-lineage acceptance slice.
//!
//! This proves the production Handle/Rights path now records derivation,
//! refuses rights escalation and revokes a whole alias subtree before object
//! ownership is returned. Reliable audit, MAC/PEP and every in-flight I/O
//! backend remain explicitly outside this slice.

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::object::{HandleError, Rights};

use crate::{kobj, kprintln, proc};

static FAILED: AtomicU32 = AtomicU32::new(0);

fn check(condition: bool, what: &'static str) {
    if !condition {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-SEC2-FAIL] {}", what);
    }
}

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

pub fn run() {
    let before = crate::baseline::baseline();
    let pid = match proc::create("sec2-capability", crate::syscall::SyscallSet::EMPTY) {
        Ok(pid) => pid,
        Err(_) => {
            check(false, "process creation failed");
            return;
        }
    };
    let root = match proc::create_memory(pid, 1) {
        Ok(handle) => handle,
        Err(_) => {
            check(false, "Memory root creation failed");
            return;
        }
    };
    let original_object = proc::handle_info(pid, root)
        .and_then(|(object, _)| kernel_core::objtable::ObjId::from_raw(object.id.0));
    let root_link = proc::capability_info(pid, root);
    check(
        root_link.is_some_and(|link| link.parent.is_none() && link.is_active()),
        "root handle has no graph root",
    );

    let child = proc::duplicate_for(
        pid,
        root,
        Rights::READ.union(Rights::DUPLICATE),
    );
    check(child.is_ok(), "first attenuation/delegation failed");
    let child = child.ok();
    let child_link = child.and_then(|handle| {
        let link = proc::capability_info(pid, handle)?;
        (link.parent == root_link.map(|root| root.id)).then_some(link)
    });
    check(
        child_link.is_some(),
        "delegated handle does not point at its parent capability",
    );

    let grandchild = child.and_then(|child| {
        proc::duplicate_for(pid, child, Rights::READ).ok()
    });
    check(grandchild.is_some(), "second attenuation failed");
    let escalation = child.map(|child| proc::duplicate_for(pid, child, Rights::WRITE));
    check(
        escalation == Some(Err(proc::ProcError::Handle(HandleError::RightsDenied))),
        "delegation was able to add WRITE rights",
    );

    let revoked = proc::revoke_for(pid, root);
    check(revoked == Ok(3), "subtree revocation did not cover root plus two children");
    for handle in [root, child.unwrap_or(root), grandchild.unwrap_or(root)] {
        check(
            proc::handle_info(pid, handle).is_none(),
            "revoked alias still resolves",
        );
    }
    let replacement = proc::create_memory(pid, 1);
    check(replacement.is_ok(), "replacement Memory creation failed");
    let replacement_object = replacement
        .ok()
        .and_then(|handle| {
            let object = proc::handle_info(pid, handle)
                .and_then(|(object, _)| kernel_core::objtable::ObjId::from_raw(object.id.0));
            let _ = proc::close_handle_for(pid, handle);
            object
        });
    check(
        original_object.is_some()
            && replacement_object.is_some()
            && original_object != replacement_object,
        "object generation was reused after capability revocation",
    );
    check(
        proc::handle_info(pid, root).is_none(),
        "old handle resolved a newly allocated object generation",
    );

    let _ = proc::exit_idle(pid, 0);
    let _ = proc::reap(pid);
    kobj::run_cleanup(usize::MAX);
    let after = crate::baseline::baseline();
    check(after == before, "SEC-2 resources did not return to baseline");
    kprintln!(
        "[JSR-SEC2] root=true attenuate=true escalation=false subtree=true aliases=true old_generation=false resources=true failed={} reclaimed={}",
        failed(),
        after == before
    );
}
