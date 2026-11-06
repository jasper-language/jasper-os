//! Issue #4 release-protocol differential and Loom coverage.
//! Production ObjectTable logic is exercised directly; Loom serializes it with an adapter mutex.

use kernel_core::interrupt::{InterruptLine, Submitted};
use kernel_core::objtable::{Lifecycle, ObjError, ObjectTable, Slot};
use proptest::prelude::*;

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

#[derive(Debug)]
enum Obj {
    Value,
    Waiting(InterruptLine<u64>),
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, failure_persistence: None, ..ProptestConfig::default() })]

    /// Arbitrary release orders preserve the owner transition, run close at most once,
    /// reject duplicate close without side effects, and converge to an empty table.
    #[test]
    fn release_order_preserves_single_close_and_clean_convergence(
        internals in 0u8..8,
        ops in prop::collection::vec(0u8..3, 0..40),
    ) {
        let mut objects = table::<Obj>(4);
        let id = objects.insert(Obj::Value, 1, internals as u32).unwrap();
        let mut hooks = 0;
        let mut expected_owners = 1u32;
        let mut expected_internal = internals as u32;
        for op in ops {
            if objects.counts(id) == Err(ObjError::Invalid) {
                match op {
                    0 => prop_assert_eq!(
                        objects.release_owner_with_closing(id, |_, _| panic!("dead stale close ran hook")),
                        Err(ObjError::Invalid)
                    ),
                    _ => prop_assert_eq!(objects.release_internal(id), Err(ObjError::Invalid)),
                }
                continue;
            }
            match op {
                0 => {
                    if expected_owners == 0 {
                        let result = objects.release_owner_with_closing(id, |_, _| panic!("duplicate close ran a hook"));
                        prop_assert_eq!(result, Err(ObjError::Underflow));
                    } else {
                        let result = objects.release_owner_with_closing(id, |table, current| {
                            hooks += 1;
                            assert_eq!(
                                table.counts(current),
                                Ok((0, expected_internal, Lifecycle::Closing))
                            );
                        });
                        prop_assert!(matches!(result, Ok(released) if released.became_unowned));
                        expected_owners = 0;
                    }
                }
                1 | 2 => {
                    if expected_internal == 0 {
                        let result = objects.release_internal(id);
                        prop_assert_eq!(result, Err(ObjError::Underflow));
                    } else {
                        let result = objects.release_internal(id);
                        prop_assert!(result.is_ok());
                        expected_internal -= 1;
                    }
                }
                _ => unreachable!(),
            }
        }
        if expected_owners == 1 {
            let result = objects.release_owner_with_closing(id, |table, current| {
                hooks += 1;
                assert_eq!(
                    table.counts(current).map(|x| (x.0, x.2)),
                    Ok((0, Lifecycle::Closing))
                );
            });
            prop_assert!(result.is_ok());
        }
        while expected_internal > 0 {
            prop_assert!(objects.release_internal(id).is_ok());
            expected_internal -= 1;
        }
        prop_assert_eq!(hooks, 1);
        prop_assert!(objects.counts(id).is_err(), "both counts reached zero");
        prop_assert_eq!(objects.pending(), 1);
        prop_assert!(objects.take_dead().is_some());
        prop_assert_eq!((objects.live(), objects.pending()), (0, 0));
    }

    /// Close versus wait cancellation, delivery and duplicate close still has at
    /// most one completion owner and never leaves a waiter after close.
    #[test]
    fn wait_terminal_owner_is_unique_for_arbitrary_order(order in prop::collection::vec(0u8..5, 0..64)) {
        let mut objects = table::<Obj>(2);
        let mut line = InterruptLine::new();
        prop_assert_eq!(line.submit_wait(42), Ok(Submitted::Parked));
        let id = objects.insert(Obj::Waiting(line), 1, 1).unwrap();
        let mut completion_owner = None;
        let mut closed = false;
        let mut cancelled = false;
        for op in order {
            match op {
                0 => {
                    let Ok(Obj::Waiting(line)) = objects.get_mut(id) else { continue };
                    if line.cancel(42) {
                        cancelled = true;
                        prop_assert!(completion_owner.replace(0u8).is_none());
                    }
                }
                1 => {
                    let Ok(Obj::Waiting(line)) = objects.get_mut(id) else { continue };
                    if line.arrive(3).is_some() {
                        prop_assert!(completion_owner.replace(1).is_none());
                    }
                }
                2 => {
                    let result = objects.release_owner_with_closing(id, |table, current| {
                        let Ok(Obj::Waiting(line)) = table.get_mut(current) else { return };
                        if line.close().is_some() {
                            assert!(completion_owner.replace(2).is_none());
                        }
                        closed = true;
                    });
                    prop_assert!(
                        result.is_ok()
                            || result == Err(ObjError::Underflow)
                            || result == Err(ObjError::Invalid)
                    );
                }
                3 => {
                    let result = objects.release_internal(id);
                    prop_assert!(
                        result.is_ok()
                            || result == Err(ObjError::Underflow)
                            || result == Err(ObjError::Invalid)
                    );
                }
                _ => {
                    let Ok(Obj::Waiting(line)) = objects.get(id) else { continue };
                    prop_assert!(line.waiter().is_none() || !closed);
                }
            }
        }
        if !closed {
            objects
                .release_owner_with_closing(id, |table, current| {
                    let Ok(Obj::Waiting(line)) = table.get_mut(current) else { return };
                    if line.close().is_some() {
                        assert!(completion_owner.replace(2).is_none());
                    }
                    closed = true;
                })
                .unwrap();
        }
        let Ok(Obj::Waiting(line)) = objects.get(id) else {
            prop_assert!(objects.pending() <= 1);
            return Ok(());
        };
        prop_assert!(line.is_closed());
        prop_assert_eq!(line.waiter(), None);
        if completion_owner.is_none() {
            prop_assert!(cancelled);
        }
    }
}

#[test]
fn loom_last_owner_transition_runs_one_closing_hook() {
    loom::model(|| {
        let mut objects = table::<Obj>(1);
        let id = objects.insert(Obj::Value, 2, 1).unwrap();
        let shared = loom::sync::Arc::new(loom::sync::Mutex::new(objects));
        let hooks = loom::sync::Arc::new(loom::sync::atomic::AtomicUsize::new(0));

        let a = shared.clone();
        let ha = hooks.clone();
        let first = loom::thread::spawn(move || {
            let mut table = a.lock().unwrap();
            table
                .release_owner_with_closing(id, |_, _| {
                    ha.fetch_add(1, loom::sync::atomic::Ordering::SeqCst);
                })
                .unwrap();
        });
        let b = shared.clone();
        let hb = hooks.clone();
        let second = loom::thread::spawn(move || {
            let mut table = b.lock().unwrap();
            table
                .release_owner_with_closing(id, |_, _| {
                    hb.fetch_add(1, loom::sync::atomic::Ordering::SeqCst);
                })
                .unwrap();
        });
        first.join().unwrap();
        second.join().unwrap();

        assert_eq!(hooks.load(loom::sync::atomic::Ordering::SeqCst), 1);
        let mut table = shared.lock().unwrap();
        assert_eq!(table.counts(id).unwrap(), (0, 1, Lifecycle::Closing));
        assert!(table.release_internal(id).unwrap().dead);
        assert_eq!(table.pending(), 1);
        assert!(table.take_dead().is_some());
        assert_eq!((table.live(), table.pending()), (0, 0));
    });
}

#[test]
fn loom_wait_delivery_and_close_have_one_completion_owner() {
    loom::model(|| {
        let mut line = InterruptLine::new();
        line.submit_wait(42).unwrap();
        let state = loom::sync::Arc::new(loom::sync::Mutex::new((line, 0usize)));

        let delivered = state.clone();
        let arrival = loom::thread::spawn(move || {
            let mut state = delivered.lock().unwrap();
            if state.0.arrive(1).is_some() {
                state.1 += 1;
            }
        });
        let closed = state.clone();
        let close = loom::thread::spawn(move || {
            let mut state = closed.lock().unwrap();
            if state.0.close().is_some() {
                state.1 += 1;
            }
        });
        arrival.join().unwrap();
        close.join().unwrap();

        let state = state.lock().unwrap();
        assert_eq!(state.1, 1);
        assert!(state.0.is_closed());
        assert_eq!(state.0.waiter(), None);
    });
}
