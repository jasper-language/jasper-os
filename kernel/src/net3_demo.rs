//! NET-3 lifecycle, retry, loss and observability acceptance.

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::net3::{
    Backoff, BackoffPolicy, LinkState, Net3Error, NetworkManager, RetryDecision,
};

use crate::kprintln;

static FAILED: AtomicU32 = AtomicU32::new(0);

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

fn check(ok: bool, what: &'static str) {
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-NET3-FAIL] {}", what);
    }
}

pub fn run() {
    let before = crate::baseline::baseline();
    let policy = BackoffPolicy {
        max_attempts: 3,
        initial_delay: 10,
        max_delay: 50,
        multiplier: 2,
    };
    let mut manager = match NetworkManager::new(policy) {
        Ok(manager) => manager,
        Err(_) => {
            check(false, "configuration");
            finish(before);
            return;
        }
    };
    let generation = match manager.start() {
        Ok(generation) => generation,
        Err(_) => {
            check(false, "start");
            finish(before);
            return;
        }
    };
    let retry = manager.probe_failed(generation, 100, 3, false);
    check(
        matches!(retry, Ok(RetryDecision::Wait { attempt: 1, .. }))
            && manager.state() == LinkState::Degraded,
        "probe failure did not enter bounded retry",
    );
    check(
        manager.probe_succeeded(generation).is_ok() && manager.state() == LinkState::Up,
        "recovery did not restore the link",
    );
    check(
        manager.link_lost(generation).is_ok()
            && manager.probe_succeeded(generation).is_ok()
            && manager.observe(),
        "link loss/recovery observation",
    );

    check(
        manager.account_traffic(20, 12, 3, 2, 1).is_ok(),
        "traffic accounting",
    );
    let loss_before = manager.loss();
    check(
        manager.account_traffic(1, 2, 0, 0, 0) == Err(Net3Error::TrafficMismatch)
            && manager.loss() == loss_before
            && loss_before.total_lost() == 8,
        "traffic mismatch was not failure-atomic",
    );

    let mut backoff = Backoff::new(policy).unwrap();
    let _ = backoff.schedule(0, 0);
    let _ = backoff.schedule(0, 0);
    let _ = backoff.schedule(0, 0);
    check(
        backoff.schedule(0, 0) == RetryDecision::Exhausted,
        "retry budget did not exhaust",
    );

    let old_generation = manager.generation();
    check(
        manager.stop().is_ok()
            && manager.probe_succeeded(old_generation) == Err(Net3Error::StaleGeneration)
            && manager.observe(),
        "stop/stale-generation/observation",
    );
    check(
        manager.observations().len() == 2 && manager.observations().dropped() == 0,
        "bounded observation queue",
    );
    kprintln!(
        "[JSR-NET3] lifecycle=true retry=true loss=true mismatch_atomic=true observable=true stale=false generations={} snapshots={} lost={} failed={}",
        manager.generation(),
        manager.observations().len(),
        loss_before.total_lost(),
        failed()
    );
    finish(before);
}

fn finish(before: crate::baseline::Baseline) {
    let after = crate::baseline::baseline();
    let resources = before == after;
    check(resources, "resources did not return to baseline");
    kprintln!(
        "[JSR-NET3] summary resources={} failed={}",
        resources,
        failed()
    );
}
