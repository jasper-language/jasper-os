// Author: chatgpt. FV-PROP: bounded wait-set operations match a Vec reference.
use kernel_core::{event_wait::{Key, SetError, WaitSet}, task_index::Token};
#[derive(Clone, Debug)]
struct Op { kind: u8, key: Key }
fn replay(ops: &[Op]) -> bool {
    let mut set = WaitSet::<4>::new(); let mut reference: Vec<Key> = Vec::new();
    for op in ops {
        match op.kind {
            0 => {
                let expected = if reference.iter().any(|k| k.task == op.key.task) { Err(SetError::DuplicateTask) }
                    else if reference.len() == 4 { Err(SetError::Full) }
                    else { reference.push(op.key); Ok(()) };
                if set.insert(op.key) != expected { return false; }
            }
            1 => {
                let expected = if let Some(i) = reference.iter().position(|k| *k == op.key) { reference.swap_remove(i); true } else { false };
                if set.remove(op.key) != expected { return false; }
            }
            _ => { if set.pop() != reference.pop() { return false; } }
        }
        if set.len() != reference.len() { return false; }
        let mut snapshot = set.clone(); let mut expected = reference.clone();
        while !expected.is_empty() { if snapshot.pop() != expected.pop() { return false; } }
        if snapshot.pop().is_some() { return false; }
    }
    true
}
#[test]
fn wait_set_matches_reference_with_shrinking() {
    let mut seed = 0x4556545741495453u64; let mut ops = Vec::new();
    for _ in 0..20_000 {
        seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
        ops.push(Op { kind: (seed % 3) as u8, key: Key {
            task: Token { slot: ((seed >> 8) % 8) as usize, generation: (seed >> 16) % 3 }, round: (seed >> 24) % 4 } });
    }
    if !replay(&ops) { let mut i = 0; while i < ops.len() {
        let mut smaller = ops.clone(); smaller.remove(i);
        if !replay(&smaller) { ops = smaller; } else { i += 1; }
    } panic!("minimal failing operations: {ops:?}"); }
}
#[test]
fn zero_capacity_refuses_without_registration() {
    let mut set = WaitSet::<0>::new(); let key = Key { task: Token { slot: 1, generation: 1 }, round: 1 };
    assert_eq!(set.insert(key), Err(SetError::Full)); assert!(!set.remove(key)); assert_eq!(set.pop(), None);
}
