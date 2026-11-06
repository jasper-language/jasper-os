//! Issue #4 release-protocol interleavings over the production object table.
//! The test serializes operations at the object-table API boundary and enumerates every order.

use kernel_core::interrupt::InterruptLine;
use kernel_core::objtable::{drain, Lifecycle, ObjError, ObjId, ObjectTable, Slot};

fn table<T: 'static>(capacity: usize) -> ObjectTable<T> {
    let mut table = ObjectTable::empty();
    table
        .install(
            Box::leak((0..capacity).map(|_| Slot::VACANT).collect::<Vec<_>>().into_boxed_slice()),
            Box::leak(vec![0; capacity].into_boxed_slice()),
        )
        .unwrap();
    table
}

fn permutations<const N: usize>(mut visit: impl FnMut(&[usize; N])) -> usize {
    fn walk<const N: usize>(
        values: &mut [usize; N],
        position: usize,
        count: &mut usize,
        visit: &mut impl FnMut(&[usize; N]),
    ) {
        if position == N {
            *count += 1;
            visit(values);
            return;
        }
        for i in position..N {
            values.swap(position, i);
            walk(values, position + 1, count, visit);
            values.swap(position, i);
        }
    }
    let mut values = core::array::from_fn(|i| i);
    let mut count = 0;
    walk(&mut values, 0, &mut count, &mut visit);
    count
}

#[derive(Debug, PartialEq)]
enum Obj {
    Leaf(u8),
    Holder(ObjId),
    Waiting(InterruptLine<u64>),
}

#[test]
fn owner_close_and_internal_release_orders_have_one_effect_then_drain() {
    let count = permutations::<3>(|order| {
        let mut objects = table::<Obj>(2);
        let id = objects.insert(Obj::Leaf(7), 1, 2).unwrap();
        let mut close_hooks = 0;
        let mut owner_released = false;
        let mut internal_left = 2u32;
        for op in order {
            match op {
                0 => {
                    let released = objects
                        .release_owner_with_closing(id, |table, current| {
                            close_hooks += 1;
                            assert!(!owner_released);
                            owner_released = true;
                            assert_eq!(
                                table.counts(current),
                                Ok((0, internal_left, Lifecycle::Closing)),
                                "the hook observes the owner transition before changing internal refs"
                            );
                        })
                        .unwrap();
                    assert!(released.became_unowned);
                    assert_eq!(
                        released.dead,
                        internal_left == 0,
                        "only the final reference class decides death"
                    );
                }
                1 | 2 => {
                    assert!(internal_left > 0);
                    let released = objects.release_internal(id).unwrap();
                    assert!(!released.became_unowned);
                    internal_left -= 1;
                }
                _ => unreachable!(),
            }
            if owner_released && internal_left == 0 {
                assert_eq!(objects.counts(id), Err(ObjError::Invalid));
            } else {
                let counts = objects.counts(id).unwrap();
                assert_eq!(counts.0, if owner_released { 0 } else { 1 });
                assert!(counts.2 == Lifecycle::Live || counts.2 == Lifecycle::Closing);
            }
        }
        assert_eq!(close_hooks, 1, "{order:?}");
        assert_eq!(objects.counts(id), Err(ObjError::Invalid));
        assert_eq!(objects.pending(), 1);
        assert_eq!(objects.release_owner(id), Err(ObjError::Invalid), "double close after death");
        let (gone, value) = objects.take_dead().unwrap();
        assert_eq!((gone, value), (id, Obj::Leaf(7)));
        assert_eq!((objects.live(), objects.pending()), (0, 0), "{order:?}");
    });
    assert_eq!(count, 6);
}

#[test]
fn wait_cancel_delivery_and_last_close_have_one_completion_owner() {
    let count = permutations::<5>(|order| {
        let mut objects = table::<Obj>(2);
        let mut line = InterruptLine::new();
        assert_eq!(line.submit_wait(42), Ok(kernel_core::interrupt::Submitted::Parked));
        let id = objects.insert(Obj::Waiting(line), 1, 1).unwrap();
        let mut completion_owner = None;
        let mut owner_released = false;
        let mut cancelled = false;
        for op in order {
            if objects.counts(id) == Err(ObjError::Invalid) {
                match op {
                    2 | 3 => assert_eq!(objects.release_owner(id), Err(ObjError::Invalid)),
                    4 => assert_eq!(objects.release_internal(id), Err(ObjError::Invalid)),
                    _ => {}
                }
                continue;
            }
            match op {
                0 => {
                    let Ok(Obj::Waiting(line)) = objects.get_mut(id) else {
                        panic!("object remains addressable while closing is in progress")
                    };
                    if line.cancel(42) {
                        cancelled = true;
                        assert!(completion_owner.replace("cancel").is_none());
                    }
                }
                1 => {
                    let Ok(Obj::Waiting(line)) = objects.get_mut(id) else {
                        panic!("object remains addressable while closing is in progress")
                    };
                    if let Some((token, arrivals)) = line.arrive(3) {
                        assert_eq!((token, arrivals), (42, 3));
                        assert!(completion_owner.replace("delivery").is_none());
                    }
                }
                2 | 3 => {
                    let already_released = owner_released;
                    let result = objects.release_owner_with_closing(id, |table, current| {
                        let Ok(Obj::Waiting(line)) = table.get_mut(current) else {
                            panic!("closing hook owns the matching object kind")
                        };
                        if line.close().is_some() {
                            assert!(completion_owner.replace("closed").is_none());
                        }
                        owner_released = true;
                    });
                    if !already_released {
                        assert!(result.unwrap().became_unowned);
                    } else {
                        assert_eq!(result, Err(ObjError::Underflow));
                    }
                }
                4 => {
                    let released = objects.release_internal(id).unwrap();
                    assert!(!released.became_unowned);
                }
                _ => unreachable!(),
            }
        }
        assert!(owner_released, "{order:?}");
        if completion_owner.is_none() {
            assert!(cancelled, "without cancellation, delivery or close must own completion");
        }
        assert_eq!(objects.pending(), 1, "{order:?}");
        let (_, Obj::Waiting(mut line)) = objects.take_dead().unwrap() else {
            panic!("wait object kind changed")
        };
        assert!(line.is_closed(), "{order:?}");
        assert_eq!(line.waiter(), None, "{order:?}");
        assert_eq!(line.submit_wait(43), Err(kernel_core::interrupt::WaitError::Closed));
        assert_eq!((objects.live(), objects.pending()), (0, 0), "{order:?}");
    });
    assert_eq!(count, 120);
}

#[test]
fn cascade_cleanup_converges_with_one_item_per_round() {
    let mut objects = table::<Obj>(4);
    let child = objects.insert(Obj::Leaf(9), 0, 1).unwrap();
    let parent = objects.insert(Obj::Holder(child), 1, 1).unwrap();
    let mut closes = 0;
    objects
        .release_owner_with_closing(parent, |_, _| closes += 1)
        .unwrap();
    assert!(objects.release_internal(parent).unwrap().dead);
    assert_eq!(objects.pending(), 1);

    let first = drain(&mut objects, 1, |table, id, value| {
        assert_eq!(id, parent);
        let Obj::Holder(child) = value else {
            panic!("parent payload changed")
        };
        assert!(table.release_internal(child).unwrap().dead);
    });
    assert_eq!(first, 1);
    assert_eq!(objects.pending(), 1, "the parent hook enqueued the child after take_dead");
    assert_eq!(objects.counts(child), Err(ObjError::Invalid));

    let second = drain(&mut objects, 1, |_, _, _| {});
    assert_eq!(second, 1);
    assert_eq!((objects.live(), objects.pending()), (0, 0));
    assert_eq!(closes, 1);
}

#[test]
fn stale_generation_never_runs_the_reused_slots_closing_hook() {
    let mut objects = table::<Obj>(1);
    let old = objects.insert(Obj::Leaf(1), 1, 0).unwrap();
    assert!(objects.release_owner(old).unwrap().dead);
    let (gone, _) = objects.take_dead().unwrap();
    assert_eq!(gone, old);

    let current = objects.insert(Obj::Leaf(2), 1, 0).unwrap();
    assert_eq!(old.raw() & 0xffff_ffff, current.raw() & 0xffff_ffff);
    assert_ne!(old, current);
    let mut stale_hooks = 0;
    assert_eq!(
        objects.release_owner_with_closing(old, |_, _| stale_hooks += 1),
        Err(ObjError::Invalid)
    );
    assert_eq!(stale_hooks, 0);
    assert_eq!(objects.counts(current).unwrap(), (1, 0, Lifecycle::Live));
    assert!(objects.release_owner(current).unwrap().dead);
}
