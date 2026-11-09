//! USI-2 requests, capability notifications, subscription loss and cancellation.

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::assembly::Health;
use kernel_core::object::{ObjectType, Rights};
use kernel_core::objtable::ObjId;
use kernel_core::subscription::{Delivery, Event, Policy};
use kernel_core::subscription_abi::WaitArgs;

use crate::baseline::baseline;
use crate::subscription::{self, Read};
use crate::usi1_demo::{run_mode, usi_calls};
use crate::{assembly, kobj, kprintln, proc, ring, sched, service_catalog};

static FAILED: AtomicU32 = AtomicU32::new(0);

fn check(ok: bool, what: &'static str) {
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-USI2-FAIL] {}", what);
    }
}

fn object_id(pid: ObjId, handle: kernel_core::object::HandleId) -> ObjId {
    ObjId::from_raw(proc::handle_info(pid, handle).unwrap().0.id.0).unwrap()
}

fn event_value(read: Read) -> Option<u64> {
    match read {
        Read::Data(Delivery::Event(Event { value, .. })) => Some(value),
        Read::Data(Delivery::Resync(snapshot)) => Some(snapshot.value),
        Read::Empty | Read::Closed => None,
    }
}

fn capability_events() {
    // The global publisher intentionally outlives individual subscriptions, so
    // initialize it before taking the resource baseline.
    let _ = kobj::with(service_catalog::source_in).expect("capability event source");
    let before = baseline();
    for _ in 0..2 {
        let pid = proc::create("usi2-capability", crate::syscall::SyscallSet::EMPTY).unwrap();
        let source = kobj::with(service_catalog::source_in).unwrap();
        let cap = proc::grant(
            pid,
            source,
            ObjectType::EventSource,
            Rights::SUBSCRIBE,
        )
        .unwrap();
        let (sub, initial) = subscription::subscribe(pid, cap, Policy::State).unwrap();
        check(
            initial.value == u64::from(assembly::published_mask()),
            "capability snapshot",
        );

        assembly::report_health("devices", Health::Unhealthy).expect("withdraw devices");
        let withdrawn = u64::from(assembly::published_mask());
        check(
            event_value(subscription::take(pid, sub).unwrap()) == Some(withdrawn),
            "withdraw event",
        );
        check(withdrawn != initial.value, "withdraw changes mask");
        assembly::report_health("devices", Health::Unhealthy).expect("repeat health");
        check(
            subscription::take(pid, sub).unwrap() == Read::Empty,
            "unchanged mask no event",
        );
        assembly::report_health("devices", Health::Healthy).expect("restore devices");
        let restored = u64::from(assembly::published_mask());
        check(
            event_value(subscription::take(pid, sub).unwrap()) == Some(restored),
            "restore event",
        );
        check(restored == initial.value, "restore mask");

        let ring_handle = ring::create_for(pid, 4).unwrap();
        let ring_id = object_id(pid, ring_handle);
        let ptr = crate::arch::USER_WINDOW.0 + 0x180000;
        proc::map_anon(pid, ptr, 1, true).unwrap();
        let waiting =
            ring::submit_subscription_for(pid, ring_handle, sub, WaitArgs { ptr, capacity: 4 })
                .unwrap();
        check(ring::cancel_for(pid, ring_handle, waiting) == 0, "cancel wait");
        check(
            ring::reap_kernel(ring_id, 4)
                == alloc::vec![(
                    waiting,
                    crate::syscall::err(
                        crate::syscall::table::SYSTEM_ASYNC_ERROR_CANCELLED
                    )
                )],
            "single cancelled completion",
        );
        assembly::report_health("devices", Health::Unhealthy).expect("withdraw after cancel");
        check(
            event_value(subscription::take(pid, sub).unwrap())
                == Some(u64::from(assembly::published_mask())),
            "cancel does not consume later event",
        );
        assembly::report_health("devices", Health::Healthy).expect("restore after cancel");
        let _ = subscription::take(pid, sub).unwrap();

        proc::close_handle_for(pid, ring_handle).unwrap();
        proc::close_handle_for(pid, sub).unwrap();
        proc::close_handle_for(pid, cap).unwrap();
        check(proc::exit_idle(pid, 0), "exit subscriber");
        check(proc::reap(pid).is_some(), "reap subscriber");
        kobj::run_cleanup(usize::MAX);
    }
    let after = baseline();
    check(after == before, "capability event resources");
}

pub fn run() {
    let previous_preemption = sched::set_preemption(true);
    run_mode("usi2-idempotent", 5, usi_calls());
    run_mode("usi2-capability-client", 6, usi_calls());
    capability_events();
    sched::set_preemption(previous_preemption);
    let failed = FAILED.load(Ordering::Relaxed);
    kprintln!(
        "[JSR-USI2] summary idempotent={} capability={} cancel={} failed={}",
        failed == 0,
        failed == 0,
        failed == 0,
        failed
    );
}

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}
