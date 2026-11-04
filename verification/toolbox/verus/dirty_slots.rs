// kernel_core::dirty_slots 的 Verus 伴随模型：结构与源码逐行对应，切片换成 Vec。
// 性质：mark 只新增指定槽位，越界不改状态；take_next 返回不小于 from 的最小已标记槽位，只清除这一位；
// 返回 None 时不小于 from 的槽位都没有标记且存储不变。
// 模型用逐位查找代替 trailing_zeros，一致性靠差分（tests/dirty_slots.rs、fuzz）。
// Companion model of kernel_core::dirty_slots; lowest-bit search stands in for trailing_zeros.
use vstd::prelude::*;

verus! {

pub open spec fn marked(words: Seq<u64>, s: int) -> bool {
    0 <= s && s / 64 < words.len() && (words[s / 64] & (1u64 << ((s % 64) as u64))) != 0
}

proof fn lemma_or(w: u64, a: u64, b: u64)
    requires a < 64, b < 64,
    ensures ((w | (1u64 << a)) & (1u64 << b)) != 0 <==> (a == b || (w & (1u64 << b)) != 0),
{
    assert(((w | (1u64 << a)) & (1u64 << b)) != 0 <==> (a == b || (w & (1u64 << b)) != 0)) by (bit_vector)
        requires a < 64, b < 64;
}

proof fn lemma_clear(w: u64, a: u64, b: u64)
    requires a < 64, b < 64,
    ensures ((w & !(1u64 << a)) & (1u64 << b)) != 0 <==> (a != b && (w & (1u64 << b)) != 0),
{
    assert(((w & !(1u64 << a)) & (1u64 << b)) != 0 <==> (a != b && (w & (1u64 << b)) != 0)) by (bit_vector)
        requires a < 64, b < 64;
}

proof fn lemma_mask(w: u64, a: u64, b: u64)
    requires a < 64, b < 64,
    ensures ((w & (0xffff_ffff_ffff_ffffu64 << a)) & (1u64 << b)) != 0 <==> (b >= a && (w & (1u64 << b)) != 0),
{
    assert(((w & (0xffff_ffff_ffff_ffffu64 << a)) & (1u64 << b)) != 0 <==> (b >= a && (w & (1u64 << b)) != 0)) by (bit_vector)
        requires a < 64, b < 64;
}

proof fn lemma_full_mask(w: u64, b: u64)
    requires b < 64,
    ensures ((w & 0xffff_ffff_ffff_ffffu64) & (1u64 << b)) != 0 <==> (w & (1u64 << b)) != 0,
{
    assert(((w & 0xffff_ffff_ffff_ffffu64) & (1u64 << b)) != 0 <==> (w & (1u64 << b)) != 0) by (bit_vector)
        requires b < 64;
}

proof fn lemma_word_nonzero_has_bit(w: u64, b: u64)
    requires b < 64, (w & (1u64 << b)) != 0,
    ensures w != 0,
{
    assert(w != 0) by (bit_vector) requires b < 64, (w & (1u64 << b)) != 0;
}

proof fn lemma_zero_has_no_bit(b: u64)
    requires b < 64,
    ensures (0u64 & (1u64 << b)) == 0,
{
    assert((0u64 & (1u64 << b)) == 0) by (bit_vector) requires b < 64;
}

/// 源码 `mark`。
fn mark(words: &mut Vec<u64>, slot: usize) -> (r: bool)
    ensures
        r == (slot / 64 < old(words).len()),
        final(words).len() == old(words).len(),
        r ==> marked(final(words)@, slot as int),
        forall|s: int| s != slot ==> marked(final(words)@, s) == marked(old(words)@, s),
        !r ==> final(words)@ == old(words)@,
{
    let index = slot / 64;
    if index < words.len() {
        let bit = (slot % 64) as u64;
        let w = words[index];
        words.set(index, w | (1u64 << bit));
        proof {
            lemma_or(w, bit, bit);
            assert forall|s: int| s != slot implies marked(words@, s) == marked(old(words)@, s) by {
                if 0 <= s && s / 64 == index as int {
                    assert(s % 64 != slot % 64);
                    lemma_or(w, bit, (s % 64) as u64);
                }
            }
        }
        true
    } else {
        false
    }
}

/// 源码 `live.trailing_zeros()`：最低的置位。
fn lowest_bit(live: u64) -> (b: u64)
    requires live != 0,
    ensures
        b < 64,
        (live & (1u64 << b)) != 0,
        forall|c: u64| c < b ==> (live & (1u64 << c)) == 0,
{
    let mut b: u64 = 0;
    while b < 64
        invariant b <= 64, forall|c: u64| c < b ==> (live & (1u64 << c)) == 0,
        decreases 64 - b,
    {
        if (live & (1u64 << b)) != 0 {
            return b;
        }
        b = b + 1;
    }
    proof {
        assert(live == 0) by (bit_vector)
            requires forall|c: u64| c < 64 ==> (live & (1u64 << c)) == 0;
    }
    0
}

/// 源码 `take_next`。
fn take_next(words: &mut Vec<u64>, from: usize) -> (r: Option<usize>)
    requires old(words).len() <= usize::MAX / 64,
    ensures
        final(words).len() == old(words).len(),
        r matches Some(s) ==> {
            &&& s >= from
            &&& marked(old(words)@, s as int)
            &&& !marked(final(words)@, s as int)
            &&& forall|t: int| from <= t < s ==> !marked(old(words)@, t)
            &&& forall|t: int| t != s ==> marked(final(words)@, t) == marked(old(words)@, t)
        },
        r is None ==> {
            &&& final(words)@ == old(words)@
            &&& forall|t: int| t >= from ==> !marked(old(words)@, t)
        },
{
    let mut index = from / 64;
    let first = (from % 64) as u64;
    let mut mask = 0xffff_ffff_ffff_ffffu64 << first;
    while index < words.len()
        invariant
            words@ == old(words)@,
            words.len() <= usize::MAX / 64,
            first == from % 64,
            index >= from / 64,
            index == from / 64 ==> mask == 0xffff_ffff_ffff_ffffu64 << first,
            index != from / 64 ==> mask == 0xffff_ffff_ffff_ffffu64,
            forall|t: int| from <= t && t / 64 < index ==> !marked(old(words)@, t),
        decreases words.len() - index,
    {
        let w = words[index];
        let live = w & mask;
        // 这个字里每一位：在 live 里 ⇔ 已标记且不小于 from。
        proof {
            assert forall|b: u64| b < 64 implies
                ((live & (1u64 << b)) != 0 <==>
                    ((w & (1u64 << b)) != 0 && index * 64 + b >= from)) by {
                if index == from / 64 {
                    lemma_mask(w, first, b);
                } else {
                    lemma_full_mask(w, b);
                }
            }
        }
        if live != 0 {
            let bit = lowest_bit(live);
            let s = index * 64 + bit as usize;
            words.set(index, w & !(1u64 << bit));
            proof {
                assert(s / 64 == index as int && s % 64 == bit as int);
                lemma_clear(w, bit, bit);
                assert forall|t: int| t != s implies marked(words@, t) == marked(old(words)@, t) by {
                    if 0 <= t && t / 64 == index as int {
                        assert(t % 64 != bit as int);
                        lemma_clear(w, bit, (t % 64) as u64);
                    }
                }
                assert forall|t: int| from <= t < s implies !marked(old(words)@, t) by {
                    if t / 64 == index as int {
                        let c = (t % 64) as u64;
                        assert(c < bit);
                        assert((live & (1u64 << c)) == 0);
                        assert(index * 64 + c >= from);
                    }
                }
            }
            return Some(s);
        }
        proof {
            assert forall|t: int| from <= t && t / 64 < index + 1 implies !marked(old(words)@, t) by {
                if t / 64 == index as int {
                    let c = (t % 64) as u64;
                    assert(index * 64 + c == t);
                    assert forall|x: u64| x < 64 && (live & (1u64 << x)) != 0 implies false by {
                        lemma_word_nonzero_has_bit(live, x);
                    }
                    assert((live & (1u64 << c)) == 0);
                }
            }
        }
        mask = 0xffff_ffff_ffff_ffffu64;
        index = index + 1;
    }
    None
}

fn main() {}

} // verus!
