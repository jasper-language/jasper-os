use kernel_core::sandbox::{SandboxError, SandboxKey, SandboxTable};
use kernel_core::security_domain::DomainKey;
use kernel_core::workload::{
    ResourceLimits, ResourceUsage, WorkloadError, WorkloadState, WorkloadTable,
};

const DOMAIN: DomainKey = DomainKey {
    id: 17,
    generation: 4,
};
const LIMITS: ResourceLimits = ResourceLimits {
    cpu_permille: 500,
    memory_bytes: 16 * 1024,
    threads: 4,
    ring_entries: 8,
};

type Workloads = WorkloadTable<8>;
type Sandboxes = SandboxTable<4>;

fn running(workloads: &mut Workloads, sandboxes: &Sandboxes, key: SandboxKey) {
    sandboxes.mark_ready(workloads, key).unwrap();
    sandboxes.start(workloads, key).unwrap();
}

#[test]
fn sandbox_identity_is_stable_and_lifecycle_has_one_terminal() {
    let mut workloads = Workloads::new();
    let mut sandboxes = Sandboxes::new();
    let key = sandboxes.create(&mut workloads, DOMAIN, LIMITS).unwrap();
    let initial = sandboxes.snapshot(&workloads, key).unwrap();

    assert_eq!(initial.domain, DOMAIN);
    assert_eq!(initial.state, WorkloadState::Created);
    assert_eq!(
        initial.root,
        sandboxes.root_snapshot(&workloads, key).unwrap().key
    );
    assert_eq!(
        sandboxes.root_snapshot(&workloads, key).unwrap().parent,
        None
    );
    assert_eq!(SandboxKey::from_raw(key.to_raw()), Some(key));
    assert_eq!(SandboxKey::from_raw(0), None);
    assert_eq!(SandboxKey::from_raw(1 << 48), None);
    assert_eq!(SandboxKey::from_raw(1), None);

    assert_eq!(
        sandboxes.start(&mut workloads, key),
        Err(SandboxError::Workload(WorkloadError::InvalidState))
    );
    sandboxes.mark_ready(&mut workloads, key).unwrap();
    sandboxes.start(&mut workloads, key).unwrap();
    sandboxes.request_stop(&mut workloads, key).unwrap();
    sandboxes.complete_stop(&mut workloads, key).unwrap();

    let stopped = sandboxes.snapshot(&workloads, key).unwrap();
    assert_eq!(stopped.key, key);
    assert_eq!(stopped.root, initial.root);
    assert_eq!(stopped.domain, initial.domain);
    assert_eq!(stopped.state, WorkloadState::Stopped);
    assert_eq!(
        sandboxes.fail(&mut workloads, key),
        Err(SandboxError::Workload(WorkloadError::InvalidState))
    );
    assert_eq!(
        sandboxes.snapshot(&workloads, key).unwrap().state,
        WorkloadState::Stopped
    );
}

#[test]
fn stopping_rejects_new_children_and_waits_for_child_reclaim() {
    let mut workloads = Workloads::new();
    let mut sandboxes = Sandboxes::new();
    let key = sandboxes.create(&mut workloads, DOMAIN, LIMITS).unwrap();
    running(&mut workloads, &sandboxes, key);

    let child = sandboxes.launch_child(&mut workloads, key, LIMITS).unwrap();
    workloads.transition(child, WorkloadState::Ready).unwrap();
    workloads.transition(child, WorkloadState::Running).unwrap();
    sandboxes.request_stop(&mut workloads, key).unwrap();

    assert_eq!(
        sandboxes.launch_child(&mut workloads, key, LIMITS),
        Err(SandboxError::Workload(WorkloadError::InvalidState))
    );
    assert_eq!(
        sandboxes.start(&mut workloads, key),
        Err(SandboxError::Workload(WorkloadError::InvalidState))
    );
    assert_eq!(
        sandboxes.complete_stop(&mut workloads, key),
        Err(SandboxError::Workload(WorkloadError::InvalidState))
    );
    assert_eq!(
        sandboxes.root_snapshot(&workloads, key).unwrap().children,
        1
    );

    workloads.transition(child, WorkloadState::Failed).unwrap();
    workloads.destroy(child).unwrap();
    sandboxes.complete_stop(&mut workloads, key).unwrap();
    assert_eq!(
        sandboxes.root_snapshot(&workloads, key).unwrap().state,
        WorkloadState::Stopped
    );
}

#[test]
fn resources_are_released_through_workload_before_stopped() {
    let mut workloads = Workloads::new();
    let mut sandboxes = Sandboxes::new();
    let key = sandboxes.create(&mut workloads, DOMAIN, LIMITS).unwrap();
    running(&mut workloads, &sandboxes, key);
    let root = sandboxes.root_snapshot(&workloads, key).unwrap().key;
    let usage = ResourceUsage {
        memory_bytes: 4096,
        threads: 2,
        ring_entries: 3,
    };
    workloads.charge(root, usage).unwrap();

    sandboxes.request_stop(&mut workloads, key).unwrap();
    assert_eq!(
        workloads.charge(
            root,
            ResourceUsage {
                memory_bytes: 1,
                threads: 0,
                ring_entries: 0,
            }
        ),
        Err(WorkloadError::InvalidState)
    );
    assert_eq!(
        sandboxes.complete_stop(&mut workloads, key),
        Err(SandboxError::Workload(WorkloadError::InvalidState))
    );
    assert_eq!(
        sandboxes.root_snapshot(&workloads, key).unwrap().usage,
        usage
    );

    workloads.release(root, usage).unwrap();
    assert_eq!(
        sandboxes.root_snapshot(&workloads, key).unwrap().usage,
        ResourceUsage::default()
    );
    sandboxes.complete_stop(&mut workloads, key).unwrap();
    sandboxes.destroy(&mut workloads, key).unwrap();
    assert!(sandboxes.is_empty());
    assert!(workloads.is_empty());
}

#[test]
fn sandbox_state_is_read_from_workload_not_copied() {
    let mut workloads = Workloads::new();
    let mut sandboxes = Sandboxes::new();
    let key = sandboxes.create(&mut workloads, DOMAIN, LIMITS).unwrap();
    let root = sandboxes.root_snapshot(&workloads, key).unwrap().key;
    running(&mut workloads, &sandboxes, key);

    workloads.transition(root, WorkloadState::Stopping).unwrap();
    assert_eq!(
        sandboxes.snapshot(&workloads, key).unwrap().state,
        WorkloadState::Stopping
    );
    assert_eq!(sandboxes.snapshot(&workloads, key).unwrap().domain, DOMAIN);
}

#[test]
fn stale_sandbox_generation_cannot_alias_reused_slot() {
    let mut workloads = Workloads::new();
    let mut sandboxes = Sandboxes::new();
    let old = sandboxes.create(&mut workloads, DOMAIN, LIMITS).unwrap();
    sandboxes.fail(&mut workloads, old).unwrap();
    sandboxes.destroy(&mut workloads, old).unwrap();

    let new = sandboxes.create(&mut workloads, DOMAIN, LIMITS).unwrap();
    assert_eq!(old.slot(), new.slot());
    assert_ne!(old.generation(), new.generation());
    assert_eq!(
        sandboxes.snapshot(&workloads, old),
        Err(SandboxError::InvalidKey)
    );
    assert_eq!(
        sandboxes.fail(&mut workloads, old),
        Err(SandboxError::InvalidKey)
    );
    assert!(sandboxes.snapshot(&workloads, new).is_ok());
}

#[test]
fn adoption_requires_an_unbound_root_workload() {
    let mut workloads = Workloads::new();
    let mut sandboxes = Sandboxes::new();
    let root = workloads.create(DOMAIN, LIMITS).unwrap();
    let key = sandboxes.adopt(&workloads, root).unwrap();
    assert_eq!(
        sandboxes.adopt(&workloads, root),
        Err(SandboxError::RootAlreadyBound)
    );
    assert_eq!(
        sandboxes.snapshot(&workloads, key).unwrap().state,
        WorkloadState::Created
    );

    sandboxes.mark_ready(&mut workloads, key).unwrap();
    sandboxes.start(&mut workloads, key).unwrap();
    let child = workloads.create_child(root, LIMITS).unwrap();
    assert_eq!(
        sandboxes.adopt(&workloads, child),
        Err(SandboxError::InvalidRoot)
    );
}
