use kernel_core::security_domain::DomainKey;
use kernel_core::workload::{
    IoUsage, ResourceLimits, WorkloadError, WorkloadState, WorkloadTable,
};

#[test]
fn nested_io_budgets_are_consumed_once_per_ancestor_and_reject_atomically() {
    let limits = ResourceLimits {
        cpu_permille: 1000,
        memory_bytes: 4096,
        threads: 1,
        ring_entries: 1,
        io_bytes: 8,
        io_ops: 3,
    };
    let mut table = WorkloadTable::<3>::new();
    let root = table
        .create(
            DomainKey {
                id: 1,
                generation: 1,
            },
            limits,
        )
        .unwrap();
    table.transition(root, WorkloadState::Ready).unwrap();
    table.transition(root, WorkloadState::Running).unwrap();
    let child = table.create_child(root, limits).unwrap();
    table.transition(child, WorkloadState::Ready).unwrap();
    table.transition(child, WorkloadState::Running).unwrap();
    let leaf = table.create_child(child, limits).unwrap();
    table.transition(leaf, WorkloadState::Ready).unwrap();
    table.transition(leaf, WorkloadState::Running).unwrap();

    let first = IoUsage { bytes: 5, ops: 1 };
    table.charge_io(leaf, first).unwrap();
    for key in [root, child, leaf] {
        assert_eq!(table.snapshot(key).unwrap().io_usage, first);
    }

    let before = [root, child, leaf].map(|key| table.snapshot(key).unwrap());
    assert_eq!(
        table.charge_io(leaf, IoUsage { bytes: 4, ops: 1 }),
        Err(WorkloadError::Quota)
    );
    for (key, expected) in [root, child, leaf].into_iter().zip(before) {
        assert_eq!(table.snapshot(key).unwrap(), expected);
    }

    table.refund_io(leaf, first).unwrap();
    for key in [root, child, leaf] {
        assert_eq!(table.snapshot(key).unwrap().io_usage, IoUsage::default());
    }
    assert_eq!(
        table.refund_io(leaf, first),
        Err(WorkloadError::Quota),
        "rollback cannot mint budget"
    );
}
