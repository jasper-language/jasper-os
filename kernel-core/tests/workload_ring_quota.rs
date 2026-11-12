use kernel_core::security_domain::DomainKey;
use kernel_core::workload::{
    ResourceLimits, ResourceUsage, WorkloadError, WorkloadState, WorkloadTable,
};

#[test]
fn child_ring_entries_are_bounded_by_the_whole_ancestor_chain() {
    let domain = DomainKey {
        id: 1,
        generation: 1,
    };
    let limits = ResourceLimits {
        cpu_permille: 1000,
        memory_bytes: 4096,
        threads: 1,
        ring_entries: 8,
        io_bytes: 64 * 1024,
        io_ops: 32,
    };
    let mut table = WorkloadTable::<2>::new();
    let parent = table.create(domain, limits).unwrap();
    table.transition(parent, WorkloadState::Ready).unwrap();
    table.transition(parent, WorkloadState::Running).unwrap();
    let child = table.create_child(parent, limits).unwrap();
    table.transition(child, WorkloadState::Ready).unwrap();
    table.transition(child, WorkloadState::Running).unwrap();

    let all = ResourceUsage {
        memory_bytes: 0,
        threads: 0,
        ring_entries: 8,
    };
    table.charge(child, all).unwrap();
    assert_eq!(table.snapshot(child).unwrap().usage, all);
    assert_eq!(table.snapshot(parent).unwrap().usage, all);
    let before = table.snapshot(parent).unwrap();
    assert_eq!(
        table.charge(
            parent,
            ResourceUsage {
                memory_bytes: 0,
                threads: 0,
                ring_entries: 1,
            },
        ),
        Err(WorkloadError::Quota)
    );
    assert_eq!(table.snapshot(parent).unwrap(), before);
    table.release(child, all).unwrap();
    assert_eq!(
        table.snapshot(parent).unwrap().usage,
        ResourceUsage::default()
    );
}
