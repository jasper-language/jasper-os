//! Milestone S-4: short, repeatable KRN-3 race campaign.
//!
//! Every complete round exercises the production remote-wake, mailbox fallback,
//! migration, affinity, PI and resource-accounting paths. The host asks for a
//! graceful stop only between rounds.

use crate::{balance_demo, baseline::baseline, kprintln, mm, pi_demo, scale_demo, sched, smp};

fn stop_requested() -> bool {
    crate::arch::soak_stop_requested()
}

fn audit_clean() -> bool {
    let audit = sched::queue_audit();
    audit.misplaced == 0
        && audit.count_mismatch == 0
        && audit.hook_errors == 0
        && audit.list_mismatch == 0
}

fn exercise_round() -> bool {
    scale_demo::run_s4_contracts()
        && balance_demo::run_s4_contracts()
        && pi_demo::run_s4_contracts()
        && audit_clean()
}

pub fn run() -> bool {
    let cpus = smp::online_set().len();
    if cpus != 8 {
        kprintln!("[JSR-S4] failure expected_cpus=8 actual={}", cpus);
        return false;
    }
    // Serial switch logging changes the interleaving and can make the warm-up
    // itself the dominant workload.
    sched::clear_observer();
    if !exercise_round() {
        kprintln!("[JSR-S4] failure warmup");
        return false;
    }
    let before = baseline();
    let heap = mm::heap::stats();
    let mut rounds = 0u64;
    kprintln!(
        "[JSR-S4] ready cpus=8 free_frames={} objects={} pending={} heap={:?}",
        before.free_frames,
        before.objects,
        before.pending,
        heap
    );
    loop {
        let functional = exercise_round();
        rounds = rounds.saturating_add(1);
        let after = baseline();
        let after_heap = mm::heap::stats();
        let conserved = after == before && after_heap == heap;
        let clean = functional && conserved && audit_clean();
        let (wake_queued, wake_fallback) = sched::remote_wake_stats();
        let (pi_queued, pi_fallback) = sched::remote_pi_stats();
        kprintln!(
            "[JSR-S4] progress rounds={} wake={}/{} pi={}/{} free_frames={} objects={} pending={} heap={:?} clean={}",
            rounds,
            wake_queued,
            wake_fallback,
            pi_queued,
            pi_fallback,
            after.free_frames,
            after.objects,
            after.pending,
            after_heap,
            clean
        );
        if !clean {
            kprintln!("[JSR-S4] failure invariant_or_resource");
            return false;
        }
        if stop_requested() {
            kprintln!(
                "[JSR-S4] complete rounds={} conserved=true deadlocks=0 invariant_violations=0",
                rounds
            );
            return true;
        }
    }
}
