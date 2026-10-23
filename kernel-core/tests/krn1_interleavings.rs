//! Bounded operation-order checking of real mechanisms. Author: chatgpt.
//! Operations are serialized at their public API boundary: this does not model
//! hardware memory ordering or instructions within a locked operation.
use kernel_core::async_ring::{AsyncRing, Exec, Submission, SubmitError};
use kernel_core::interrupt::InterruptLine;

fn permutations<const N: usize>(mut visit: impl FnMut(&[usize; N])) -> usize {
    fn walk<const N: usize>(a: &mut [usize; N], pos: usize, n: &mut usize,
                           visit: &mut impl FnMut(&[usize; N])) {
        if pos == N { *n += 1; visit(a); return; }
        for i in pos..N {
            a.swap(pos, i);
            walk(a, pos + 1, n, visit);
            a.swap(pos, i);
        }
    }
    let mut a = core::array::from_fn(|i| i);
    let mut count = 0;
    walk(&mut a, 0, &mut count, &mut visit);
    count
}

#[test]
fn krn1_ring_all_six_operation_orders() {
    for uses_buffer in [false, true] {
        for exec in [Exec::Abortable, Exec::NonAbortable] {
            let count = permutations::<6>(|order| {
                let mut ring = AsyncRing::<2, 2>::new(2).unwrap();
                let sub = Submission { op: 12, user_tag: 7, context: 99, uses_buffer };
                let id = ring.submit(sub).unwrap();
                ring.start(id, exec).unwrap();
                let mut decision = None;
                let mut reclaimed = 0;
                for op in order {
                    match op {
                        0 => { let _ = ring.cancel(id); }
                        1 => { ring.close(|_, _| {}); }
                        2 => { let _ = ring.finish(id, 17); }
                        3 => { let _ = ring.quiesce(id); }
                        4 => { ring.consume(usize::MAX); }
                        5 => { ring.close(|_, _| {}); }
                        _ => unreachable!(),
                    }
                    if let Some(Some(t)) = ring.decision(id) {
                        if let Some(old) = decision { assert_eq!(old, t, "{order:?}"); }
                        decision = Some(t);
                    }
                    while let Some(context) = ring.take_reclaimed() {
                        assert_eq!(context, 99);
                        reclaimed += 1;
                    }
                    let stats = ring.stats();
                    assert!(stats.published <= 1, "{order:?}");
                    assert!(stats.destroyed <= 1, "{order:?}");
                    assert!(reclaimed <= 1, "{order:?}");
                    assert_eq!(ring.credits() + ring.reserved() + ring.ready(), 2);
                    if ring.is_closing() {
                        assert_eq!(ring.submit(sub), Err(SubmitError::Closing));
                    }
                }
                // Supply backend quiescence after all racing control operations.
                let _ = ring.finish(id, 17);
                let _ = ring.quiesce(id);
                ring.close(|_, _| {});
                while let Some(context) = ring.take_reclaimed() {
                    assert_eq!(context, 99); reclaimed += 1;
                }
                assert_eq!(reclaimed, 1, "{order:?}");
                assert!(ring.is_drained(), "{order:?}");
                assert_eq!(ring.credits(), 2);
            });
            assert_eq!(count, 720);
        }
    }
}

#[test]
fn krn1_interrupt_cancel_close_arrival_orders() {
    let count = permutations::<4>(|order| {
        let mut line = InterruptLine::new();
        line.submit_wait(42).unwrap();
        let mut owners = 0;
        for op in order {
            match op {
                0 => { owners += usize::from(line.cancel(42)); }
                1 | 3 => { owners += usize::from(line.close().is_some()); }
                2 => {
                    if let Some((token, arrivals)) = line.arrive(3) {
                        assert_eq!((token, arrivals), (42, 3)); owners += 1;
                    }
                }
                _ => unreachable!(),
            }
            assert!(owners <= 1, "{order:?}");
            if line.is_closed() {
                assert!(line.waiter().is_none());
                assert!(line.submit_wait(43).is_err());
                assert_eq!(line.pending(), 0);
            }
        }
        assert_eq!(owners, 1, "{order:?}");
        assert!(line.is_closed());
    });
    assert_eq!(count, 24);
}
