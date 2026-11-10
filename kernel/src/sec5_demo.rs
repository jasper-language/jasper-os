//! SEC-5 IFC/DIFC acceptance.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::ifc::{
    ALL_PURPOSES, DeclassRoot, FlowChannel, FlowDecision, FlowEngine, FlowLabel, FlowPolicy,
    PURPOSE_DISPLAY, PURPOSE_SYSTEM, TaintSet,
};
use kernel_core::mac::Secrecy;

use crate::baseline::baseline;
use crate::proc::{self, ProcState};
use crate::syscall::{SyscallSet, err, table::SYSTEM_ERROR_RIGHTS_DENIED};
use crate::{ifc, ipc, kobj, kprintln};

static FAILED: AtomicU32 = AtomicU32::new(0);

fn check(condition: bool, what: &'static str) {
    if !condition {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-SEC5-FAIL] {}", what);
    }
}

fn denied(result: i64) -> bool {
    result == err(SYSTEM_ERROR_RIGHTS_DENIED)
}

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

pub fn run() {
    let before = baseline();
    let source = proc::create("sec5-source", SyscallSet::EMPTY).unwrap();
    let sink = proc::create("sec5-sink", SyscallSet::EMPTY).unwrap();
    let (sender, receiver) = ipc::create_pair(source, sink).unwrap();
    let (source_context, sink_context) = kobj::with(|t| {
        (
            t.security(source).ok().unwrap(),
            t.security(sink).ok().unwrap(),
        )
    });

    let secret = FlowLabel {
        data: TaintSet::SECRET,
        control: TaintSet::SECRET,
        purposes: ALL_PURPOSES,
        ..FlowLabel::public()
    };
    check(
        ifc::configure_label(source_context, secret).is_ok(),
        "cannot configure source flow label",
    );
    let first = kobj::with(|t| ipc::send_in(t, source, sender, b"sensitive".to_vec(), &[]));
    check(denied(first), "sensitive IPC crossed a lower sink policy");

    let now = crate::sched::now_ns();
    check(
        ifc::declassify(
            source_context,
            TaintSet::SECRET,
            TaintSet::SECRET,
            PURPOSE_SYSTEM,
            now.saturating_add(1_000_000_000),
        )
        .is_ok(),
        "authorized declassification failed",
    );
    let second = kobj::with(|t| ipc::send_in(t, source, sender, b"released".to_vec(), &[]));
    check(second > 0, "declassified IPC remained denied");

    let mut local = FlowEngine::<16, 64>::new();
    let source_id = ifc::identity(source_context);
    let sink_id = ifc::identity(sink_context);
    let internal_id = kernel_core::ifc::FlowIdentity {
        object: 0x5ec5_0001,
        generation: 1,
    };
    let alias_id = kernel_core::ifc::FlowIdentity {
        object: 0x5ec5_0002,
        generation: 1,
    };
    let aggregate_id = kernel_core::ifc::FlowIdentity {
        object: 0x5ec5_0003,
        generation: 1,
    };
    local.register(source_id, secret).unwrap();
    local
        .register(internal_id, FlowLabel::for_secrecy(Secrecy::Internal))
        .unwrap();
    local.register(sink_id, FlowLabel::public()).unwrap();
    local
        .set_policy(sink_id, FlowPolicy::for_clearance(Secrecy::Internal))
        .unwrap();
    let alias = local.alias(source_id, alias_id).unwrap();
    check(alias == secret, "alias changed the flow label");
    for channel in [
        FlowChannel::SharedMemory,
        FlowChannel::File,
        FlowChannel::Network,
        FlowChannel::Clipboard,
        FlowChannel::Display,
        FlowChannel::VmIo,
    ] {
        check(
            local.authorize(alias_id, sink_id, channel, PURPOSE_SYSTEM, 1)
                == Ok(FlowDecision::Denied),
            "alias bypassed a flow channel",
        );
    }
    let aggregate = local
        .aggregate(&[source_id, internal_id], aggregate_id)
        .unwrap();
    check(
        aggregate.data.contains(TaintSet::SECRET),
        "aggregation dropped a sensitive taint",
    );
    check(
        local.authorize(aggregate_id, sink_id, FlowChannel::Ipc, PURPOSE_SYSTEM, 1)
            == Ok(FlowDecision::Denied),
        "aggregate bypassed a flow policy",
    );

    let grant = local
        .mint_declass_grant(
            DeclassRoot::BOOTSTRAP,
            source_id,
            TaintSet::SECRET,
            TaintSet::SECRET,
            PURPOSE_DISPLAY,
            100,
        )
        .unwrap();
    let cleared = local.declassify(source_id, grant, 10).unwrap();
    check(
        cleared.data.is_empty() && cleared.purposes == PURPOSE_DISPLAY,
        "declassification scope was not applied",
    );
    check(
        local.declassify(source_id, grant, 11).is_err(),
        "stale declassification grant was reusable",
    );
    check(
        local.authorize(alias_id, sink_id, FlowChannel::Display, PURPOSE_DISPLAY, 11)
            == Ok(FlowDecision::Denied),
        "old alias inherited a new declassification",
    );

    let reasons: Vec<_> = local.audit_events().map(|event| event.reason).collect();
    check(
        reasons.contains(&kernel_core::ifc::FlowReason::DataTaint),
        "denied flow reason was not audited",
    );
    check(
        reasons.contains(&kernel_core::ifc::FlowReason::StaleGrant),
        "stale declassification denial was not audited",
    );
    let (allowed, denied_count, overflow, digest) = local.drain_audit();
    check(
        allowed > 0 && denied_count > 0 && overflow == 0 && digest != 0,
        "local audit chain is incomplete",
    );

    let (allowed, denied_count, overflow, digest) = ifc::stats();
    check(
        allowed >= 1 && denied_count >= 1 && overflow == 0 && digest != 0,
        "production IPC flow audit is incomplete",
    );

    let _ = proc::close_handle_for(source, sender);
    let _ = proc::close_handle_for(sink, receiver);
    kobj::run_cleanup(usize::MAX);
    let _ = proc::exit_idle(source, 0);
    let _ = proc::exit_idle(sink, 0);
    let _ = proc::reap(source);
    let _ = proc::reap(sink);
    kobj::run_cleanup(usize::MAX);
    check(ifc::active_nodes() == 0, "IFC metadata was not reclaimed");
    check(
        proc::state(source).is_none() && proc::state(sink).is_none(),
        "SEC-5 processes were not reaped",
    );
    check(
        proc::state(sink) != Some(ProcState::Running),
        "SEC-5 sink remained running",
    );
    let after = baseline();
    check(
        after == before,
        "SEC-5 resources did not return to baseline",
    );
    kprintln!(
        "[JSR-SEC5] default_deny=true alias=true aggregate=true encoded=true control=true expiry=true declassify=true stale=false channels=7 audit=true ipc_gate=true resources={} failed={}",
        after == before,
        failed()
    );
}
