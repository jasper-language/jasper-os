//! Issue #42 M10: PEP decisions, post-effect observations and bounded audit.

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::security_domain::{
    Access, DomainKind, DomainResource, DomainTable, DomainError, GatewayKind,
};
use kernel_core::security_observation::{Fact, Outcome, Scope, Service};

use crate::kprintln;

static FAILED: AtomicU32 = AtomicU32::new(0);

fn check(ok: bool, what: &'static str) {
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-SEC-OBSERVE-FAIL] {}", what);
    }
}

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

fn apply(
    observations: &mut Service<4>,
    fact: Fact,
    value: &mut u64,
) -> Result<(), kernel_core::security_observation::Error> {
    let reservation = observations.reserve()?;
    *value = value.saturating_add(1);
    observations
        .commit(reservation, fact, Outcome::Applied)
        .map(|_| ())
}

pub fn run() {
    FAILED.store(0, Ordering::Relaxed);
    let before = crate::baseline::baseline();
    let mut domains = DomainTable::<2, 1, 1, 2>::new();
    let app = domains.create(DomainKind::Application).unwrap();
    let service = domains.create(DomainKind::Service).unwrap();
    let resource = DomainResource {
        object: 0x5101,
        rights: 3,
    };
    domains.attach(service, resource).unwrap();
    let gateway = domains
        .grant(app, resource.object, GatewayKind::Ipc, 1)
        .unwrap();

    let fact = Fact {
        actor: app,
        owner: service,
        object: resource.object,
        channel: Some(GatewayKind::Ipc),
        requested: 1,
        decision: Access::Allowed,
    };
    let mut observations = Service::<4>::new();
    let mut protected_value = 0u64;

    let allowed = domains
        .access(app, resource.object, GatewayKind::Ipc, 1)
        .unwrap();
    check(allowed == Access::Allowed, "cross-domain gateway was denied");
    check(
        apply(&mut observations, fact, &mut protected_value).is_ok(),
        "post-effect observation was not committed",
    );
    check(protected_value == 1, "allowed effect did not commit");

    let observed = observations.visible(Scope::Subject(app)).count();
    let owner_observed = observations.visible(Scope::Owner(service)).count();
    let outsider = kernel_core::security_domain::DomainKey {
        id: 99,
        generation: 1,
    };
    check(
        observed == 1
            && owner_observed == 1
            && observations.visible(Scope::Subject(outsider)).count() == 0,
        "observation scope leaked or missed the committed event",
    );

    domains.revoke_gateway(gateway).unwrap();
    let denied = domains
        .access(app, resource.object, GatewayKind::Ipc, 1)
        .unwrap();
    check(
        denied == Access::Denied && protected_value == 1,
        "denied operation changed protected state",
    );

    // SEC-4 audit capacity is now full. The next decision must fail before the
    // caller reaches the protected effect.
    check(
        domains.access(app, resource.object, GatewayKind::Ipc, 1) == Err(DomainError::AuditFull),
        "domain audit exhaustion did not fail closed",
    );
    check(
        protected_value == 1,
        "audit-full rejection reached the protected effect",
    );

    for _ in 0..3 {
        check(
            apply(&mut observations, fact, &mut protected_value).is_ok(),
            "reserved observation buffer rejected a legal event",
        );
    }
    let reserved = observations.reserve();
    let before_capacity_reject = protected_value;
    if reserved.is_ok() {
        protected_value = protected_value.saturating_add(1);
    }
    check(
        reserved.is_err() && protected_value == before_capacity_reject,
        "observation-capacity failure allowed an unobservable effect",
    );

    let detached = domains.compromise(service).unwrap();
    check(
        detached == 1
            && domains.attached_resources() == 0
            && domains.active_gateways() == 0,
        "service compromise did not reclaim cross-domain state",
    );
    let restarted = domains.restart(service).unwrap();
    check(
        restarted.generation == service.generation + 1
            && domains
                .access(app, resource.object, GatewayKind::Ipc, 1)
                == Err(DomainError::InvalidResource),
        "restarted domain revived the old resource generation",
    );

    while observations.pop().is_some() {}
    observations.clear();
    let after = crate::baseline::baseline();
    check(after == before, "security observation matrix leaked resources");
    kprintln!(
        "[JSR-SEC-OBSERVE] pep_once=true after_effect=true deny_no_effect=true audit_full_no_effect=true observation_capacity_no_effect=true scope=true restart=false resources={} failed={}",
        after == before,
        failed()
    );
}
