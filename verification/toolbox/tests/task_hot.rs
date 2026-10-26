use kernel_core::{
    task_hot::{Error, Slot},
    task_index::Token,
};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, failure_persistence: None, ..ProptestConfig::default() })]

    #[test]
    fn stale_generation_cannot_touch_reused_slot(
        slot_index in 0usize..4096,
        generation in any::<u64>(),
        first in any::<u64>(),
        second in any::<u64>(),
    ) {
        let old = Token { slot: slot_index, generation };
        let new = Token { slot: slot_index, generation: generation.wrapping_add(1) };
        let mut slot = Slot::empty(slot_index);
        slot.publish(old, first).unwrap();
        prop_assert_eq!(slot.retire(old), Ok(first));
        slot.publish(new, second).unwrap();
        prop_assert!(matches!(slot.get_mut(old), Err(Error::Stale)));
        prop_assert_eq!(slot.get(new), Ok(&second));
    }

    #[test]
    fn wrong_slot_is_atomic(
        owner_slot in 0usize..4096,
        delta in 1usize..4096,
        generation in any::<u64>(),
        value in any::<u32>(),
    ) {
        let owner = Token { slot: owner_slot, generation };
        let wrong = Token { slot: owner_slot.wrapping_add(delta), generation };
        prop_assume!(wrong.slot != owner.slot);
        let mut slot = Slot::empty(owner_slot);
        slot.publish(owner, value).unwrap();
        prop_assert_eq!(slot.retire(wrong), Err(Error::WrongSlot));
        prop_assert_eq!(slot.get(owner), Ok(&value));
    }
}

#[test]
fn loom_serializes_retire_and_stale_update() {
    loom::model(|| {
        let token = Token {
            slot: 1,
            generation: 7,
        };
        let state = loom::sync::Arc::new(loom::sync::Mutex::new(Slot::empty(1)));
        state.lock().unwrap().publish(token, 0u32).unwrap();

        let updater = state.clone();
        let update = loom::thread::spawn(move || {
            if let Ok(value) = updater.lock().unwrap().get_mut(token) {
                *value += 1;
            }
        });
        let retirer = state.clone();
        let retire = loom::thread::spawn(move || {
            let mut slot = retirer.lock().unwrap();
            if let Ok(value) = slot.retire(token) {
                let next = Token {
                    slot: 1,
                    generation: 8,
                };
                slot.publish(next, value + 10).unwrap();
            }
        });
        update.join().unwrap();
        retire.join().unwrap();

        let slot = state.lock().unwrap();
        assert!(matches!(slot.get(token), Err(Error::Stale)));
        let value = *slot
            .get(Token {
                slot: 1,
                generation: 8,
            })
            .unwrap();
        assert!(value == 10 || value == 11);
    });
}
