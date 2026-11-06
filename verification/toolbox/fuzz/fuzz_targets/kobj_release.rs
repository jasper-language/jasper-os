#![no_main]
//! Differential fuzzing of the production ObjectTable closing transaction.
use kernel_core::objtable::{Lifecycle, ObjError, ObjectTable, Slot};
use std::sync::{Mutex, OnceLock};

#[derive(Debug)]
struct Value;

fn table() -> &'static Mutex<ObjectTable<Value>> {
    static TABLE: OnceLock<Mutex<ObjectTable<Value>>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table = ObjectTable::empty();
        table
            .install(
                Box::leak((0..4).map(|_| Slot::VACANT).collect::<Vec<_>>().into_boxed_slice()),
                Box::leak(vec![0; 4].into_boxed_slice()),
            )
            .unwrap();
        Mutex::new(table)
    })
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let internal = (data[0] & 7) as u32;
    let mut table = table().lock().unwrap();
    assert_eq!((table.live(), table.pending()), (0, 0), "previous input did not converge");
    let id = table.insert(Value, 1, internal).unwrap();
    let mut hooks = 0usize;
    let mut expected_owners = 1u32;
    let mut expected_internal = internal;
    for &op in &data[1..] {
        if table.counts(id) == Err(ObjError::Invalid) {
            match op % 3 {
                0 => assert_eq!(
                    table.release_owner_with_closing(id, |_, _| panic!("dead stale close ran hook")),
                    Err(ObjError::Invalid)
                ),
                _ => assert_eq!(table.release_internal(id), Err(ObjError::Invalid)),
            }
            continue;
        }
        match op % 3 {
            0 => {
                if expected_owners == 0 {
                    assert_eq!(
                        table.release_owner_with_closing(id, |_, _| panic!("duplicate close ran hook")),
                        Err(ObjError::Underflow)
                    );
                } else {
                    table
                        .release_owner_with_closing(id, |current, object| {
                            hooks += 1;
                            assert_eq!(
                                current.counts(object),
                                Ok((0, expected_internal, Lifecycle::Closing))
                            );
                        })
                        .unwrap();
                    expected_owners = 0;
                }
            }
            1 | 2 => {
                if expected_internal == 0 {
                    assert_eq!(table.release_internal(id), Err(ObjError::Underflow));
                } else {
                    table.release_internal(id).unwrap();
                    expected_internal -= 1;
                }
            }
            _ => unreachable!(),
        }
        assert!(hooks <= 1);
    }
    if expected_owners == 1 {
        table.release_owner_with_closing(id, |_, _| hooks += 1).unwrap();
    }
    while expected_internal > 0 {
        table.release_internal(id).unwrap();
        expected_internal -= 1;
    }
    assert_eq!(hooks, 1);
    assert_eq!(table.pending(), 1);
    assert!(matches!(table.take_dead(), Some((gone, Value)) if gone == id));
    assert_eq!((table.live(), table.pending()), (0, 0));
});
