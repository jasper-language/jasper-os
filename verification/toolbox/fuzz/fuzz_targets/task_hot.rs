#![no_main]
use kernel_core::{
    task_hot::{Error, Slot},
    task_index::Token,
};

libfuzzer_sys::fuzz_target!(|data: [u8; 24]| {
    let slot_index = u16::from_le_bytes([data[0], data[1]]) as usize;
    let generation = u64::from_le_bytes(data[2..10].try_into().unwrap());
    let old = Token {
        slot: slot_index,
        generation,
    };
    let new = Token {
        slot: slot_index,
        generation: generation.wrapping_add(1),
    };
    let mut slot = Slot::empty(slot_index);
    let first = u64::from_le_bytes(data[10..18].try_into().unwrap());
    let second = u16::from_le_bytes(data[18..20].try_into().unwrap()) as u64;
    slot.publish(old, first).unwrap();
    assert_eq!(slot.retire(old), Ok(first));
    slot.publish(new, second).unwrap();
    assert!(matches!(slot.get_mut(old), Err(Error::Stale)));
    assert_eq!(slot.get(new), Ok(&second));
    let wrong = Token {
        slot: slot_index.wrapping_add(1),
        generation: new.generation,
    };
    assert_eq!(slot.retire(wrong), Err(Error::WrongSlot));
    assert_eq!(slot.get(new), Ok(&second));
});
