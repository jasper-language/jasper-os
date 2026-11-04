//! 脏槽位位图（issue #2 第二片）：记录哪些槽位需要重新同步。存储由调用方提供，每个字 64 位，
//! 槽位 `s` 对应第 `s / 64` 个字的第 `s % 64` 位。所有操作都不分配内存，也不会失败；
//! 越界的 `mark` 是空操作，并返回 `false`。
//! Dirty-slot bitmap over caller-owned words. Nothing allocates or fails;
//! an out-of-range mark changes nothing and reports `false`.

/// 一个字的位数 / bits per word.
pub const WORD_BITS: usize = 64;

/// 容纳 `slots` 个槽位需要的字数 / words needed for `slots` slots.
pub const fn words_for(slots: usize) -> usize {
    slots.div_ceil(WORD_BITS)
}

/// 标记一个槽位；槽位不在存储范围内时不改状态并返回 `false`。
/// Marks one slot; an out-of-range slot changes nothing and returns `false`.
pub fn mark(words: &mut [u64], slot: usize) -> bool {
    match words.get_mut(slot / WORD_BITS) {
        Some(w) => {
            *w |= 1u64 << (slot % WORD_BITS);
            true
        }
        None => false,
    }
}

/// 槽位是否已标记（越界为否）/ whether a slot is marked (out of range is not).
pub fn is_marked(words: &[u64], slot: usize) -> bool {
    words.get(slot / WORD_BITS).is_some_and(|w| w & (1u64 << (slot % WORD_BITS)) != 0)
}

/// 标记前 `slots` 个槽位，超出存储的部分忽略；其余位不变。
/// Marks the first `slots` slots (clamped to storage); other bits are untouched.
pub fn mark_first(words: &mut [u64], slots: usize) {
    for (i, w) in words.iter_mut().enumerate() {
        let start = i.saturating_mul(WORD_BITS);
        if start >= slots {
            break;
        }
        let n = slots - start;
        *w |= if n >= WORD_BITS { u64::MAX } else { (1u64 << n) - 1 };
    }
}

/// 取走不小于 `from` 的最小已标记槽位：清除它的位并返回下标；其余位不变。没有则返回 `None`。
/// 一次排空的总工作量是 O(字数 + 已标记数)，与未标记的槽位数无关（只按字跳过）。
/// Takes the smallest marked slot at or above `from`, clearing only its bit.
pub fn take_next(words: &mut [u64], from: usize) -> Option<usize> {
    let mut index = from / WORD_BITS;
    let mut mask = u64::MAX << (from % WORD_BITS);
    while let Some(w) = words.get_mut(index) {
        let live = *w & mask;
        if live != 0 {
            let bit = live.trailing_zeros() as usize;
            *w &= !(1u64 << bit);
            return Some(index * WORD_BITS + bit);
        }
        mask = u64::MAX;
        index += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mark_take_in_order_and_clear_only_the_taken_bit() {
        let mut w = [0u64; 3];
        for s in [130, 0, 64, 63] {
            assert!(mark(&mut w, s));
        }
        assert!(mark(&mut w, 130), "重复标记是幂等的");
        assert_eq!(take_next(&mut w, 1), Some(63));
        assert!(is_marked(&w, 0), "小于 from 的位不受影响");
        assert_eq!(take_next(&mut w, 64), Some(64));
        assert_eq!(take_next(&mut w, 65), Some(130));
        assert_eq!(take_next(&mut w, 65), None);
        assert_eq!(take_next(&mut w, 0), Some(0));
        assert_eq!(w, [0; 3]);
    }

    #[test]
    fn out_of_range_is_a_no_op() {
        let mut w = [0u64; 1];
        assert!(!mark(&mut w, 64));
        assert!(!is_marked(&w, 64));
        assert_eq!(w, [0]);
        assert_eq!(take_next(&mut w, usize::MAX), None);
        let mut none: [u64; 0] = [];
        assert!(!mark(&mut none, 0));
        assert_eq!(take_next(&mut none, 0), None);
    }

    #[test]
    fn mark_first_covers_exactly_the_prefix() {
        for slots in [0, 1, 63, 64, 65, 127, 128, 129, 192, 500] {
            let mut w = [0u64; 3];
            mark_first(&mut w, slots);
            for s in 0..192 {
                assert_eq!(is_marked(&w, s), s < slots, "slots={slots} s={s}");
            }
        }
    }

    #[test]
    fn words_for_rounds_up() {
        assert_eq!((words_for(0), words_for(1), words_for(64), words_for(65)), (0, 1, 1, 2));
    }
}
