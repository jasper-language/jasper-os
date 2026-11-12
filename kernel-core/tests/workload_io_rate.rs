//! Fixed-window I/O admission over the native Workload hierarchy.

use kernel_core::security_domain::DomainKey;
use kernel_core::workload::{
    IoRateLimits, IoRateUsage, IoUsage, ResourceLimits, WorkloadError, WorkloadState, WorkloadTable,
};

const DOMAIN: DomainKey = DomainKey {
    id: 17,
    generation: 4,
};

const LIMITS: ResourceLimits = ResourceLimits {
    cpu_permille: 1000,
    memory_bytes: 4096,
    threads: 4,
    ring_entries: 8,
    io_bytes: 1024,
    io_ops: 64,
};

fn runnable<const N: usize>(table: &mut WorkloadTable<N>, key: kernel_core::workload::WorkloadKey) {
    table.transition(key, WorkloadState::Ready).unwrap();
    table.transition(key, WorkloadState::Running).unwrap();
}

#[test]
fn rate_windows_charge_every_ancestor_and_reset_at_the_boundary() {
    let rate = IoRateLimits {
        bytes_per_window: 8,
        ops_per_window: 2,
        window_ns: 100,
    };
    let mut table = WorkloadTable::<3>::new();
    let root = table.create(DOMAIN, LIMITS).unwrap();
    table.configure_io_rate(root, rate).unwrap();
    runnable(&mut table, root);
    let child = table.create_child(root, LIMITS).unwrap();
    table.configure_io_rate(child, rate).unwrap();
    runnable(&mut table, child);

    let first = IoUsage { bytes: 6, ops: 1 };
    table.charge_io_at(child, first, 1).unwrap();
    for key in [root, child] {
        assert_eq!(
            table.io_rate_snapshot(key).unwrap().usage,
            IoRateUsage {
                window_start_ns: 1,
                bytes: 6,
                ops: 1,
            }
        );
    }

    assert_eq!(
        table.charge_io_at(child, IoUsage { bytes: 3, ops: 0 }, 99),
        Err(WorkloadError::Quota)
    );
    for key in [root, child] {
        assert_eq!(
            table.io_rate_snapshot(key).unwrap().usage,
            IoRateUsage {
                window_start_ns: 1,
                bytes: 6,
                ops: 1,
            },
            "rejection must not reset or partially charge an ancestor"
        );
    }

    // The previous window expires exactly at start + window_ns.
    table
        .charge_io_at(child, IoUsage { bytes: 1, ops: 1 }, 101)
        .unwrap();
    for key in [root, child] {
        assert_eq!(
            table.io_rate_snapshot(key).unwrap().usage,
            IoRateUsage {
                window_start_ns: 101,
                bytes: 1,
                ops: 1,
            }
        );
    }
}

#[test]
fn ancestor_rate_rejection_is_atomic_and_independent_of_lifetime_budget() {
    let leaf_rate = IoRateLimits {
        bytes_per_window: 16,
        ops_per_window: 2,
        window_ns: 50,
    };
    let root_rate = IoRateLimits {
        bytes_per_window: 4,
        ops_per_window: 4,
        window_ns: 50,
    };
    let mut table = WorkloadTable::<3>::new();
    let root = table.create(DOMAIN, LIMITS).unwrap();
    table.configure_io_rate(root, root_rate).unwrap();
    runnable(&mut table, root);
    let child = table.create_child(root, LIMITS).unwrap();
    table.configure_io_rate(child, leaf_rate).unwrap();
    runnable(&mut table, child);
    assert_eq!(
        table.charge_io(child, IoUsage { bytes: 1, ops: 1 }),
        Err(WorkloadError::InvalidState),
        "the legacy cumulative-only entry point cannot bypass a configured rate"
    );
    table
        .charge_io_at(child, IoUsage { bytes: 4, ops: 1 }, 10)
        .unwrap();

    let root_before = table.snapshot(root).unwrap();
    let child_before = table.snapshot(child).unwrap();
    let root_rate_before = table.io_rate_snapshot(root).unwrap();
    let child_rate_before = table.io_rate_snapshot(child).unwrap();

    assert_eq!(
        table.charge_io_at(child, IoUsage { bytes: 1, ops: 1 }, 11),
        Err(WorkloadError::Quota)
    );
    assert_eq!(
        table.charge_io_at(child, IoUsage { bytes: 0, ops: 2 }, 11),
        Err(WorkloadError::Quota),
        "operation rate is checked independently of bytes"
    );
    assert_eq!(table.snapshot(root).unwrap(), root_before);
    assert_eq!(table.snapshot(child).unwrap(), child_before);
    assert_eq!(table.io_rate_snapshot(root).unwrap(), root_rate_before);
    assert_eq!(table.io_rate_snapshot(child).unwrap(), child_rate_before);
}

#[test]
fn clock_regression_and_expired_rollback_cannot_mint_window_capacity() {
    let rate = IoRateLimits {
        bytes_per_window: 5,
        ops_per_window: 1,
        window_ns: 100,
    };
    let mut table = WorkloadTable::<1>::new();
    let key = table.create(DOMAIN, LIMITS).unwrap();
    table.configure_io_rate(key, rate).unwrap();
    runnable(&mut table, key);
    let delta = IoUsage { bytes: 5, ops: 1 };
    table.charge_io_at(key, delta, 100).unwrap();

    assert_eq!(
        table.charge_io_at(key, IoUsage { bytes: 1, ops: 0 }, 99),
        Err(WorkloadError::Quota),
        "a regressing clock must not reset the window"
    );
    table.refund_io_at(key, delta, 199).unwrap();
    assert_eq!(table.io_rate_snapshot(key).unwrap().usage.bytes, 0);
    table.charge_io_at(key, delta, 199).unwrap();

    // After expiry, rollback restores lifetime budget but does not create a
    // fresh partially-consumed window.
    table.refund_io_at(key, delta, 200).unwrap();
    assert_eq!(
        table.io_rate_snapshot(key).unwrap().usage,
        IoRateUsage {
            window_start_ns: 100,
            bytes: 5,
            ops: 1,
        }
    );
    table
        .charge_io_at(key, IoUsage { bytes: 5, ops: 1 }, 200)
        .unwrap();
    assert_eq!(
        table.io_rate_snapshot(key).unwrap().usage,
        IoRateUsage {
            window_start_ns: 200,
            bytes: 5,
            ops: 1,
        }
    );
}

#[test]
fn rate_policy_is_validated_and_frozen_after_start() {
    let mut table = WorkloadTable::<1>::new();
    let key = table.create(DOMAIN, LIMITS).unwrap();
    for invalid in [
        IoRateLimits {
            bytes_per_window: 0,
            ops_per_window: 1,
            window_ns: 1,
        },
        IoRateLimits {
            bytes_per_window: 1,
            ops_per_window: 0,
            window_ns: 1,
        },
        IoRateLimits {
            bytes_per_window: 1,
            ops_per_window: 1,
            window_ns: 0,
        },
    ] {
        assert_eq!(
            table.configure_io_rate(key, invalid),
            Err(WorkloadError::InvalidLimit)
        );
    }
    table
        .configure_io_rate(
            key,
            IoRateLimits {
                bytes_per_window: 1,
                ops_per_window: 1,
                window_ns: 1,
            },
        )
        .unwrap();
    runnable(&mut table, key);
    assert_eq!(
        table.configure_io_rate(
            key,
            IoRateLimits {
                bytes_per_window: 2,
                ops_per_window: 2,
                window_ns: 1,
            }
        ),
        Err(WorkloadError::InvalidState)
    );
}
