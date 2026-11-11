//! PEX-3 object-table sharding A/B contract.
//! PEX-3 对象表分片 A/B 契约测试。
//!
//! The test compares a central table with eight stable-slot shards while
//! preserving the production owner/internal-reference and cleanup protocol.
//! 测试在保留生产外部/内部引用与清理协议的前提下，比较中央表与八个稳定槽位分片。

use kernel_core::objtable::{Lifecycle, ObjError, ObjId, ObjectTable, Slot};

const SHARDS: usize = 8;
const SLOTS_PER_SHARD: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Value {
    Leaf(u64),
    Holder(ObjId),
}

#[derive(Debug, PartialEq, Eq)]
struct Trace {
    events: Vec<&'static str>,
    live: usize,
    pending: usize,
    destroyed: u64,
}

fn table<T: 'static>(capacity: usize) -> ObjectTable<T> {
    let mut table = ObjectTable::empty();
    table
        .install(
            Box::leak(
                (0..capacity)
                    .map(|_| Slot::VACANT)
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
            ),
            Box::leak(vec![0u32; capacity].into_boxed_slice()),
        )
        .expect("test storage must install");
    table
}

fn close_parent(
    table: &mut ObjectTable<Value>,
    parent: ObjId,
    child: ObjId,
    events: &mut Vec<&'static str>,
) {
    let released = table
        .release_owner_with_closing(parent, |table, current| {
            assert_eq!(table.get(current), Ok(&Value::Holder(child)));
            events.push("parent-closing");
        })
        .expect("parent owner release");
    assert!(released.became_unowned);
    assert!(!released.dead, "the child reference keeps the parent closing");
    assert_eq!(table.counts(parent), Ok((0, 1, Lifecycle::Closing)));
    assert!(table.release_internal(parent).expect("parent internal release").dead);
    assert_eq!(table.get(parent), Err(ObjError::Invalid));
    let gone = table.take_dead().expect("parent must enter cleanup");
    assert_eq!(gone.0, parent);
    let Value::Holder(held_child) = gone.1 else {
        panic!("parent payload changed");
    };
    assert_eq!(held_child, child);
    events.push("parent-destroyed");
}

fn central_trace() -> Trace {
    let mut table = table::<Value>(32);
    let mut events = Vec::new();

    let child = table.insert(Value::Leaf(7), 1, 1).expect("child insert");
    let parent = table
        .insert(Value::Holder(child), 1, 1)
        .expect("parent insert");
    assert_eq!(table.get(child), Ok(&Value::Leaf(7)));
    table.acquire_internal(child).expect("child internal acquire");
    table.release_internal(child).expect("child internal release");

    let child_release = table
        .release_owner_with_closing(child, |table, current| {
            assert_eq!(table.get(current), Ok(&Value::Leaf(7)));
            events.push("child-closing");
        })
        .expect("child owner release");
    assert!(child_release.became_unowned);
    assert!(!child_release.dead, "the parent reference keeps the child closing");
    assert_eq!(table.counts(child), Ok((0, 1, Lifecycle::Closing)));
    assert_eq!(table.acquire_owner(child), Err(ObjError::Invalid));
    events.push("child-closing-visible");

    close_parent(&mut table, parent, child, &mut events);
    assert!(table.release_internal(child).expect("holder release").dead);
    assert_eq!(table.get(child), Err(ObjError::Invalid));
    assert_eq!(table.take_dead().map(|(id, _)| id), Some(child));
    events.push("child-destroyed");

    let replacement = table.insert(Value::Leaf(8), 1, 0).expect("replacement insert");
    assert_eq!(replacement.index(), child.index());
    assert_ne!(replacement.generation(), child.generation());
    assert_eq!(table.get(child), Err(ObjError::Invalid));
    assert!(table.release_owner(replacement).expect("replacement release").dead);
    assert!(table.take_dead().is_some());

    Trace {
        events,
        live: table.live(),
        pending: table.pending(),
        destroyed: table.destroyed(),
    }
}

fn sharded_trace() -> Trace {
    let mut shards: Vec<ObjectTable<Value>> =
        (0..SHARDS).map(|_| table(SLOTS_PER_SHARD)).collect();
    let mut events = Vec::new();

    let child = shards[1].insert(Value::Leaf(7), 1, 1).expect("child insert");
    let parent = shards[0]
        .insert(Value::Holder(child), 1, 1)
        .expect("parent insert");
    assert_eq!(shards[1].get(child), Ok(&Value::Leaf(7)));
    shards[1].acquire_internal(child).expect("child internal acquire");
    shards[1]
        .release_internal(child)
        .expect("child internal release");

    let child_release = shards[1]
        .release_owner_with_closing(child, |table, current| {
            assert_eq!(table.get(current), Ok(&Value::Leaf(7)));
            events.push("child-closing");
        })
        .expect("child owner release");
    assert!(child_release.became_unowned);
    assert!(!child_release.dead, "the parent reference keeps the child closing");
    assert_eq!(shards[1].counts(child), Ok((0, 1, Lifecycle::Closing)));
    assert_eq!(shards[1].acquire_owner(child), Err(ObjError::Invalid));
    events.push("child-closing-visible");

    close_parent(&mut shards[0], parent, child, &mut events);
    assert!(shards[1].release_internal(child).expect("holder release").dead);
    assert_eq!(shards[1].get(child), Err(ObjError::Invalid));
    assert_eq!(shards[1].take_dead().map(|(id, _)| id), Some(child));
    events.push("child-destroyed");

    let replacement = shards[1]
        .insert(Value::Leaf(8), 1, 0)
        .expect("replacement insert");
    assert_eq!(replacement.index(), child.index());
    assert_ne!(replacement.generation(), child.generation());
    assert_eq!(shards[1].get(child), Err(ObjError::Invalid));
    assert!(
        shards[1]
            .release_owner(replacement)
            .expect("replacement release")
            .dead
    );
    assert!(shards[1].take_dead().is_some());

    Trace {
        events,
        live: shards.iter().map(ObjectTable::live).sum(),
        pending: shards.iter().map(ObjectTable::pending).sum(),
        destroyed: shards.iter().map(ObjectTable::destroyed).sum(),
    }
}

#[test]
fn central_and_sharded_paths_preserve_identical_lifecycle_results() {
    let central = central_trace();
    let sharded = sharded_trace();

    assert_eq!(central, sharded);
    assert_eq!(
        central.events,
        vec![
            "child-closing",
            "child-closing-visible",
            "parent-closing",
            "parent-destroyed",
            "child-destroyed",
        ]
    );
    assert_eq!((central.live, central.pending), (0, 0));
    assert_eq!(central.destroyed, 3);
}
