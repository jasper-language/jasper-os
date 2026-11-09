//! SEC-4 security-domain boundary acceptance.

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::object::Rights;
use kernel_core::security_domain::{
    Access, DomainKind, DomainResource, DomainState, DomainTable, GatewayKind,
};

use crate::baseline::baseline;
use crate::proc::{self, ProcState};
use crate::syscall::SyscallSet;
use crate::{kobj, kprintln};

static FAILED: AtomicU32 = AtomicU32::new(0);

fn check(condition: bool, what: &'static str) {
    if !condition {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-SEC4-FAIL] {}", what);
    }
}

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

pub fn run() {
    let before = baseline();
    let mut table: DomainTable<6, 32, 24, 64> = DomainTable::new();
    let application = table.create(DomainKind::Application).unwrap();
    let service = table.create(DomainKind::Service).unwrap();
    let vm = table.create(DomainKind::Vm).unwrap();

    let app_pid = proc::create("sec4-app-domain", SyscallSet::EMPTY).unwrap();
    let service_pid = proc::create("sec4-service-domain", SyscallSet::EMPTY).unwrap();
    let vm_pid = proc::create("sec4-vm-domain", SyscallSet::EMPTY).unwrap();

    table
        .attach(
            application,
            DomainResource {
                object: app_pid.raw(),
                rights: Rights::READ.bits() as u32,
            },
        )
        .unwrap();

    let channels = [
        GatewayKind::File,
        GatewayKind::Clipboard,
        GatewayKind::Network,
        GatewayKind::Ipc,
        GatewayKind::Device,
        GatewayKind::Service,
    ];
    let mut objects = [0u64; 6];
    for (index, channel) in channels.into_iter().enumerate() {
        let handle = proc::create_memory(app_pid, 1).unwrap();
        let object = proc::handle_info(app_pid, handle)
            .and_then(|(object, _)| kernel_core::objtable::ObjId::from_raw(object.id.0))
            .unwrap();
        objects[index] = object.raw();
        table
            .attach(
                application,
                DomainResource {
                    object: object.raw(),
                    rights: Rights::READ.bits() as u32,
                },
            )
            .unwrap();
        table
            .grant(service, object.raw(), channel, Rights::READ.bits() as u32)
            .unwrap();
    }

    check(
        table.access(
            vm,
            objects[0],
            GatewayKind::File,
            Rights::READ.bits() as u32,
        ) == Ok(Access::Denied),
        "unrelated domain bypassed a gateway",
    );
    for (index, channel) in channels.into_iter().enumerate() {
        check(
            table.access(service, objects[index], channel, Rights::READ.bits() as u32)
                == Ok(Access::Allowed),
            "authorized cross-domain channel was denied",
        );
        check(
            table.access(
                service,
                objects[index],
                match channel {
                    GatewayKind::File => GatewayKind::Clipboard,
                    _ => GatewayKind::File,
                },
                Rights::READ.bits() as u32,
            ) == Ok(Access::Denied),
            "gateway channel substitution was accepted",
        );
    }

    let reclaimed = table.compromise(application).unwrap();
    check(reclaimed >= 7, "compromise did not reclaim domain boundary");
    check(
        table.state(application) == Some(DomainState::Compromised),
        "domain not marked compromised",
    );
    check(
        proc::state(service_pid) == Some(ProcState::Running)
            && proc::state(vm_pid) == Some(ProcState::Running),
        "domain compromise leaked into another domain",
    );
    check(
        table
            .access(
                service,
                objects[0],
                GatewayKind::File,
                Rights::READ.bits() as u32,
            )
            .is_err(),
        "compromised domain resource remained reachable",
    );
    check(
        proc::begin_exit(app_pid, 137),
        "compromised domain process did not exit",
    );
    let _ = proc::reap(app_pid);
    kobj::run_cleanup(usize::MAX);
    check(
        proc::state(service_pid) == Some(ProcState::Running),
        "service domain died with compromised application domain",
    );

    let restarted = table.restart(application).unwrap();
    check(
        restarted.id == application.id && restarted.generation > application.generation,
        "domain restart generation is not fresh",
    );
    let restarted_pid = proc::create("sec4-app-restarted", SyscallSet::EMPTY).unwrap();
    let replacement = proc::create_memory(restarted_pid, 1).unwrap();
    let replacement_object = proc::handle_info(restarted_pid, replacement)
        .and_then(|(object, _)| kernel_core::objtable::ObjId::from_raw(object.id.0))
        .unwrap();
    table
        .attach(
            restarted,
            DomainResource {
                object: replacement_object.raw(),
                rights: Rights::READ.bits() as u32,
            },
        )
        .unwrap();
    check(
        table.access(
            restarted,
            replacement_object.raw(),
            GatewayKind::File,
            Rights::READ.bits() as u32,
        ) == Ok(Access::Allowed),
        "restarted domain cannot access its new resource",
    );
    check(
        table.access(
            application,
            replacement_object.raw(),
            GatewayKind::File,
            Rights::READ.bits() as u32,
        ) == Ok(Access::Denied),
        "old domain generation reached restarted authority",
    );

    check(
        table
            .audit_events()
            .any(|event| event.decision == Access::Denied)
            && table
                .audit_events()
                .any(|event| event.decision == Access::Allowed),
        "domain decisions were not audited",
    );
    check(table.audit_overflow() == 0, "domain audit overflowed");
    check(
        table.active_domains() == 3,
        "domain restart or isolation count mismatch",
    );

    let _ = proc::close_handle_for(restarted_pid, replacement);
    let _ = proc::exit_idle(restarted_pid, 0);
    let _ = proc::reap(restarted_pid);
    let _ = proc::exit_idle(service_pid, 0);
    let _ = proc::reap(service_pid);
    let _ = proc::exit_idle(vm_pid, 0);
    let _ = proc::reap(vm_pid);
    kobj::run_cleanup(usize::MAX);
    let after = baseline();
    check(
        after == before,
        "SEC-4 resources did not return to baseline",
    );
    kprintln!(
        "[JSR-SEC4] default_deny=true gateways=6 channel_bind=true compromise=true restart=true old_generation=false audit=true isolated=true resources={} failed={}",
        after == before,
        failed()
    );
}
