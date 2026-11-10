//! NET-2 production network service and security-gate acceptance.

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::ifc::{FlowChannel, FlowDecision, FlowLabel, FlowPolicy, PURPOSE_NETWORK};
use kernel_core::mac::{class_bit, Integrity, MacDenial, MacEffect, MacLabel, Secrecy};
use kernel_core::net2::{Net2Error, Segment, TcpAddress, TcpQuota, TcpService, TcpState};
use kernel_core::security::{IdentityClass, SecurityDomain};

use crate::{ifc, kobj, kprintln, proc, sched, security};

static FAILED: AtomicU32 = AtomicU32::new(0);

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

fn check(ok: bool, what: &'static str) {
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-NET2-FAIL] {}", what);
    }
}

fn local() -> TcpAddress {
    TcpAddress { ip: [10, 0, 2, 2], port: 8080 }
}

fn remote() -> TcpAddress {
    TcpAddress { ip: [10, 0, 2, 15], port: 40000 }
}

pub fn run() {
    let before = crate::baseline::baseline();
    let principal = match proc::create("net2-prod", crate::syscall::SyscallSet::EMPTY) {
        Ok(pid) => pid,
        Err(_) => {
            check(false, "principal creation");
            return;
        }
    };
    let subject = match kobj::with(|table| table.security(principal)) {
        Ok(context) if context.require_active().is_ok() => context,
        _ => {
            check(false, "principal security context");
            let _ = proc::exit_idle(principal, -1);
            return;
        }
    };

    let service_label = MacLabel::new(
        SecurityDomain::USER,
        Secrecy::Internal,
        Integrity::Managed,
        class_bit(IdentityClass::Service),
    );
    let secret_label = MacLabel::new(
        SecurityDomain::USER,
        Secrecy::Secret,
        Integrity::Managed,
        class_bit(IdentityClass::Service),
    );
    let audit_before = security::audit_stats();
    let allow = security::authorize_object_label(
        subject,
        IdentityClass::Service,
        0x6001,
        1,
        service_label,
        MacEffect::Read,
    );
    let deny = security::authorize_object_label(
        subject,
        IdentityClass::Service,
        0x6002,
        1,
        secret_label,
        MacEffect::Read,
    );
    security::flush_audit();
    let audit_after = security::audit_stats();
    check(
        allow.is_ok()
            && deny == Err(MacDenial::SecrecyDenied)
            && audit_after.0 > audit_before.0
            && audit_after.1 > audit_before.1,
        "network MAC/default-deny/audit",
    );

    let now = sched::now_ns();
    let allow_flow = ifc::authorize_labeled_flow(
        subject,
        FlowLabel::for_secrecy(Secrecy::Internal),
        0x6101,
        1,
        FlowLabel::for_secrecy(Secrecy::Internal),
        FlowPolicy::for_clearance(Secrecy::Internal),
        FlowChannel::Network,
        PURPOSE_NETWORK,
        now,
    );
    let deny_flow = ifc::authorize_labeled_flow(
        subject,
        FlowLabel::for_secrecy(Secrecy::Secret),
        0x6102,
        1,
        FlowLabel::for_secrecy(Secrecy::Sensitive),
        FlowPolicy::for_clearance(Secrecy::Public),
        FlowChannel::Network,
        PURPOSE_NETWORK,
        now,
    );
    check(
        allow_flow == Ok(FlowDecision::Allowed)
            && deny_flow == Ok(FlowDecision::Denied),
        "network IFC allow/taint denial",
    );

    let mut tcp = TcpService::<8, 16>::new(TcpQuota::new(2, 64), 2, 10);
    let client = match tcp.connect(local(), remote(), 100, 0) {
        Ok(id) => id,
        Err(_) => {
            check(false, "TCP connect");
            finish(principal, before, false);
            return;
        }
    };
    let established = tcp.receive(
        client,
        1,
        Segment {
            source: remote(),
            destination: local(),
            sequence: 900,
            acknowledgement: 101,
            syn: true,
            ack: true,
            fin: false,
            rst: false,
            window: 32,
            payload: &[],
        },
        1,
    );
    let send_seq = tcp.send(client, 1, 16);
    let data = tcp.receive(
        client,
        1,
        Segment {
            source: remote(),
            destination: local(),
            sequence: 901,
            acknowledgement: 117,
            syn: false,
            ack: true,
            fin: false,
            rst: false,
            window: 32,
            payload: b"JASPER-NET2",
        },
        2,
    );
    let mut payload = [0u8; 11];
    let received = tcp.recv(client, 1, &mut payload);
    let closed = tcp.receive(
        client,
        1,
        Segment {
            source: remote(),
            destination: local(),
            sequence: 912,
            acknowledgement: 117,
            syn: false,
            ack: true,
            fin: true,
            rst: false,
            window: 32,
            payload: &[],
        },
        3,
    );
    check(
        established.is_ok()
            && send_seq == Ok(101)
            && data.is_ok()
            && received == Ok(11)
            && &payload == b"JASPER-NET2"
            && closed.is_ok()
            && tcp.view(client, 1).is_ok_and(|view| view.state == TcpState::FinWait),
        "TCP handshake/data/close",
    );

    let listener = match tcp.listen(TcpAddress { ip: [10, 0, 2, 2], port: 443 }, 200, 0) {
        Ok(id) => id,
        Err(_) => {
            check(false, "TCP listen");
            finish(principal, before, false);
            return;
        }
    };
    let syn = tcp.receive(
        listener,
        1,
        Segment {
            source: remote(),
            destination: TcpAddress { ip: [10, 0, 2, 2], port: 443 },
            sequence: 500,
            acknowledgement: 0,
            syn: true,
            ack: false,
            fin: false,
            rst: false,
            window: 16,
            payload: &[],
        },
        1,
    );
    let accepted = tcp.receive(
        listener,
        1,
        Segment {
            source: remote(),
            destination: TcpAddress { ip: [10, 0, 2, 2], port: 443 },
            sequence: 501,
            acknowledgement: 201,
            syn: false,
            ack: true,
            fin: false,
            rst: false,
            window: 16,
            payload: &[],
        },
        2,
    );
    let first_timeout = tcp.tick(listener, 1, 1);
    check(
        syn.is_ok()
            && accepted.is_ok()
            && tcp.view(listener, 1).is_ok_and(|view| view.state == TcpState::Established)
            && first_timeout == Ok(false)
            && tcp.cancel(listener, 1).is_ok()
            && tcp.view(listener, 1) == Err(Net2Error::NotFound),
        "TCP listen/accept/timeout/cancel",
    );

    let quota = tcp.quota();
    check(
        quota.sockets == 1 && quota.max_sockets == 2 && quota.bytes == 0,
        "TCP quota accounting",
    );
    kprintln!(
        "[JSR-NET2] service=true mac_allow={} secret_denied={} ifc_allow={} ifc_denied={} audited={} denied={} tcp=true quota=true failed={}",
        allow.is_ok(),
        deny == Err(MacDenial::SecrecyDenied),
        allow_flow == Ok(FlowDecision::Allowed),
        deny_flow == Ok(FlowDecision::Denied),
        audit_after.0.saturating_sub(audit_before.0),
        audit_after.1.saturating_sub(audit_before.1),
        failed()
    );
    finish(principal, before, true);
}

fn finish(
    principal: kernel_core::objtable::ObjId,
    before: crate::baseline::Baseline,
    emit_resources: bool,
) {
    let _ = proc::exit_idle(principal, 0);
    let _ = proc::reap(principal);
    kobj::run_cleanup(usize::MAX);
    let after = crate::baseline::baseline();
    let resources = before == after;
    check(resources, "resources did not return to baseline");
    if emit_resources {
        kprintln!(
            "[JSR-NET2] summary resources={} failed={}",
            resources,
            failed()
        );
    }
}
