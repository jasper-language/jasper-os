use kernel_core::inherited_mutex::{Claim, ReleaseError, State};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, failure_persistence: None, ..ProptestConfig::default() })]
    #[test]
    fn ownership_never_splits(ops in prop::collection::vec((0u8..5, 1u8..4), 1..129)) {
        let mut state = State::new();
        let mut reference: Option<u8> = None;
        let mut closed = false;
        for (op, who) in ops {
            match op {
                0 if !closed => match state.claim(who, reference.is_some()) {
                    Claim::Acquired { .. } => reference = Some(who),
                    Claim::WaitFor(owner) => prop_assert_eq!(Some(owner), reference),
                    Claim::Recursive => prop_assert_eq!(Some(who), reference),
                    Claim::Closed => prop_assert!(closed),
                },
                1 if !closed => {
                    let before = state;
                    match state.release(who, None) {
                        Ok(true) => { prop_assert_eq!(reference, Some(who)); reference = None; }
                        Ok(false) => prop_assert!(false, "release without successor must retire the owner ref"),
                        Err(ReleaseError::NotOwner) => prop_assert_eq!(state, before),
                        Err(ReleaseError::Closed) => prop_assert!(closed),
                    }
                }
                2 if !closed => { prop_assert_eq!(state.close(), reference.take()); closed = true; }
                _ => {}
            }
            prop_assert_eq!(state.owner(), reference);
            prop_assert_eq!(state.is_closed(), closed);
        }
    }
}

#[test]
fn serialized_direct_handoff_adapter() {
    loom::model(|| {
        let state = loom::sync::Arc::new(loom::sync::Mutex::new(State::new()));
        assert_eq!(state.lock().unwrap().claim(1u8, false), Claim::Acquired { reused_owner_ref: false });
        let other = state.clone();
        let waiter = loom::thread::spawn(move || {
            assert_eq!(other.lock().unwrap().claim(2, true), Claim::WaitFor(1));
        });
        waiter.join().unwrap();
        assert_eq!(state.lock().unwrap().release(1, Some(2)), Ok(false));
        assert_eq!(state.lock().unwrap().owner(), Some(2));
    });
}
