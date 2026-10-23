//! Author: chatgpt. Execute the actual kernel ExitState source with a real
//! ObjectTable and a recording completion adapter. The adapter does not model
//! ring lifetime/refcounts or process teardown; those remain separate coverage.
extern crate alloc;
use kernel_core::objtable::{ObjectTable, Slot};

#[path = "../../kernel/src/exit_state.rs"]
mod exit_state;
mod kobj {
    pub enum KObject { ExitState(crate::exit_state::ExitState), #[allow(dead_code)] Other }
    pub type Table = kernel_core::objtable::ObjectTable<KObject>;
}
mod ring {
    use std::cell::RefCell;
    use kernel_core::objtable::ObjId;
    thread_local! { pub static COMPLETIONS: RefCell<Vec<(ObjId, u64, i64)>> = const { RefCell::new(Vec::new()) }; }
    pub fn complete_waiter_in(_: &mut crate::kobj::Table, ring: ObjId, req: u64, code: i64) {
        COMPLETIONS.with(|c| c.borrow_mut().push((ring, req, code)));
    }
}

#[test]
fn krn1_exit_cancel_and_duplicate_notification_orders() {
    // All 3! orders: cancel, original exit, duplicate exit with a different code.
    for a in 0..3 {
        for b in 0..3 {
            for c in 0..3 {
                if a == b || a == c || b == c { continue; }
                ring::COMPLETIONS.with(|x| x.borrow_mut().clear());
                let mut table = ObjectTable::empty();
                table.install(Box::leak((0..2).map(|_| Slot::VACANT).collect::<Vec<_>>().into_boxed_slice()),
                              Box::leak(vec![0; 2].into_boxed_slice())).unwrap();
                let id = exit_state::create_in(&mut table).unwrap();
                let waiter = (id, 7);
                exit_state::add_waiter_in(&mut table, id, waiter);
                let mut first_code = None;
                let mut cancelled = false;
                let mut expected_completions = 0;
                for op in [a, b, c] {
                    match op {
                        0 => { exit_state::remove_waiter_in(&mut table, id, waiter); cancelled = true; }
                        1 | 2 => {
                            let code = if op == 1 { -1 } else { 19 };
                            if first_code.is_none() {
                                first_code = Some(code);
                                expected_completions = usize::from(!cancelled);
                            }
                            exit_state::notify_in(&mut table, id, code);
                        }
                        _ => unreachable!(),
                    }
                    assert_eq!(exit_state::code_in(&mut table, id), first_code);
                    ring::COMPLETIONS.with(|x| {
                        let completions = x.borrow();
                        assert_eq!(completions.len(), expected_completions);
                        if let Some(&(r, req, value)) = completions.first() {
                            assert_eq!((r, req), waiter);
                            assert_eq!(value, exit_state::report(first_code.unwrap()));
                            assert!(value >= 0);
                        }
                    });
                }
                // Once exited, later requests read the stored code; no re-notify.
                assert_eq!(exit_state::report(-1), 0xffff_ffff);
                assert_eq!(exit_state::report(i64::MIN), 0);
            }
        }
    }
}
