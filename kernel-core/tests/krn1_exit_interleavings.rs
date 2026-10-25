//! Author: chatgpt. Execute the actual kernel ExitState source with a real
//! ObjectTable and a recording completion adapter. The adapter does not model
//! ring lifetime/refcounts or process teardown; those remain separate coverage.
extern crate alloc;
use kernel_core::objtable::{ObjectTable, Slot};

#[path = "../../kernel/src/exit_state.rs"]
mod exit_state;
mod kobj {
    pub enum KObject { Source(kernel_core::subscription::Snapshot), ExitState(crate::exit_state::ExitState), #[allow(dead_code)] Other }
    pub type Table = kernel_core::objtable::ObjectTable<KObject>;
    // This harness owns explicit local tables. Never silently emulate global cleanup.
    pub fn with<R>(_:impl FnOnce(&mut Table)->R)->R {panic!("global cleanup is outside this local-table adapter; use kernel fixture");}

}

// Recording source adapter for the actual ExitState attachment/notify code.
// Actual kernel source queues, locks, capabilities and destruction are separate QEMU coverage.
mod subscription {
    use kernel_core::{objtable::ObjId,subscription::Snapshot};
    use crate::kobj::{Table,KObject};
    #[derive(Debug)] pub enum Error {Invalid}
    pub fn create_publisher_in(t:&mut Table,snapshot:Snapshot)->Result<ObjId,Error> {
        t.insert(KObject::Source(snapshot),1,0).map_err(|_|Error::Invalid)
    }
    pub fn publish_in(t:&mut Table,id:ObjId,value:u64)->Result<(),Error> {
        match t.get_mut(id) {Ok(KObject::Source(snapshot))=>snapshot.publish(value).map(|_|()).map_err(|_|Error::Invalid),_=>Err(Error::Invalid)}
    }
    pub fn finish_publisher_in(t:&mut Table,id:ObjId) {assert!(t.release_owner(id).is_ok());}
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

#[test]
fn actual_exit_attachment_before_and_after_notification_preserves_snapshot() {
 let mut table=ObjectTable::empty();
 table.install(Box::leak((0..8).map(|_|Slot::VACANT).collect::<Vec<_>>().into_boxed_slice()),Box::leak(vec![0;8].into_boxed_slice())).unwrap();
 let es=exit_state::create_in(&mut table).unwrap();let source=exit_state::source_in(&mut table,es).unwrap();
 assert!(matches!(table.get(source),Ok(kobj::KObject::Source(s)) if s.version==0));
 exit_state::notify_in(&mut table,es,37);exit_state::notify_in(&mut table,es,99);
 assert!(matches!(table.get(source),Ok(kobj::KObject::Source(s)) if s.version==1 && s.value==37));
 assert_eq!(exit_state::source_in(&mut table,es).unwrap(),source);
 let late=exit_state::create_in(&mut table).unwrap();exit_state::notify_in(&mut table,late,19);
 let late_source=exit_state::source_in(&mut table,late).unwrap();
 assert!(matches!(table.get(late_source),Ok(kobj::KObject::Source(s)) if s.version==1 && s.value==19));
}
