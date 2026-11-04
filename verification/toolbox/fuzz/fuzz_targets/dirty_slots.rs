#![no_main]
//! 脏位图：任意操作序列下与有序集合参照实现差分，且不多不少只清除取走的那一位。
use kernel_core::dirty_slots::{is_marked, mark, mark_first, take_next};
use std::collections::BTreeSet;
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some((&words, rest)) = data.split_first() else { return };
    let mut w = vec![0u64; usize::from(words % 5)];
    let capacity = w.len() * 64;
    let mut reference = BTreeSet::new();
    // 每 3 字节一个操作：操作种类与 16 位槽位（可能越界）
    for ch in rest.chunks_exact(3) {
        let s = usize::from(u16::from_le_bytes([ch[1], ch[2]])) % 512;
        match ch[0] % 3 {
            0 => {
                assert_eq!(mark(&mut w, s), s < capacity);
                if s < capacity {
                    reference.insert(s);
                }
            }
            1 => {
                let expected = reference.range(s..).next().copied();
                assert_eq!(take_next(&mut w, s), expected);
                if let Some(e) = expected {
                    reference.remove(&e);
                }
            }
            _ => {
                mark_first(&mut w, s);
                reference.extend(0..s.min(capacity));
            }
        }
        assert_eq!(w.iter().map(|x| x.count_ones() as usize).sum::<usize>(), reference.len());
        assert!(reference.iter().all(|&t| is_marked(&w, t)));
    }
});
