// issue #1：系统调用能力集合（256 位定长位图）与 spawn 无状态准入规则的 Verus 规格证明。
// Verus proof of the 256-bit syscall capability set and the stateless spawn admission rule.
//
// 范围：kernel-core/src/syscall_set.rs 的 `from_id` / `contains` / `union` /
// `intersection` / `difference` / `is_subset_of`，以及 kernel-core/src/spawn_abi.rs 的 `check`。
// 生产代码用 `[u64; 4]` + const fn 循环，Verus 无法原样导入（const 上下文的 while、
// `core::mem::offset_of!` 断言、`impl Iterator` 等），因此这里按同一字运算重写四个字段的版本；
// 每个函数体逐字对应生产实现中的位运算式（`w & (1 << k) != 0`、`a & !b` 等）。
// 这是规格级证明：证明的是这组位运算满足集合语义，不是对编译后生产代码的证明；
// 生产 Rust 由同一套件中的 Kani harness 在实现级做有界证明。
use vstd::prelude::*;

verus! {

pub const MAX_IDS: u64 = 256;
pub const SPAWN_MAGIC: u32 = 0x4A53_5032;
pub const SPAWN_VERSION: u16 = 2;
pub const SPAWN_SIZE: u16 = 88;
pub const MAX_IMAGE_BYTES: u64 = 2 * 1024 * 1024;
pub const MIN_CPU_LIMIT: u32 = 10;
pub const CPU_UNLIMITED: u32 = 1000;

/// 4 个 64 位字：字 i 的位 k 表示操作 ID `64 * i + k`。
#[derive(Clone, Copy)]
pub struct Set4 {
    pub w0: u64,
    pub w1: u64,
    pub w2: u64,
    pub w3: u64,
}

pub open spec fn word(s: Set4, i: u64) -> u64 {
    if i == 0 { s.w0 } else if i == 1 { s.w1 } else if i == 2 { s.w2 } else { s.w3 }
}

pub open spec fn bit(x: u64, k: u64) -> bool {
    (x >> k) & 1u64 == 1u64
}

/// 集合语义：ID 被授予 ⇔ ID 在容量内且对应位为 1。
pub open spec fn granted(s: Set4, id: u64) -> bool {
    id < MAX_IDS && bit(word(s, id / 64), id % 64)
}

pub open spec fn subset(a: Set4, b: Set4) -> bool {
    forall|id: u64| #[trigger] granted(a, id) ==> granted(b, id)
}

proof fn bit_and(x: u64, y: u64, k: u64)
    requires k < 64,
    ensures bit(x & y, k) <==> (bit(x, k) && bit(y, k)),
{
    assert(k < 64u64 ==> (((x & y) >> k) & 1u64 == 1u64 <==> ((x >> k) & 1u64 == 1u64 && (y >> k) & 1u64 == 1u64))) by(bit_vector);
}

proof fn bit_or(x: u64, y: u64, k: u64)
    requires k < 64,
    ensures bit(x | y, k) <==> (bit(x, k) || bit(y, k)),
{
    assert(k < 64u64 ==> (((x | y) >> k) & 1u64 == 1u64 <==> ((x >> k) & 1u64 == 1u64 || (y >> k) & 1u64 == 1u64))) by(bit_vector);
}

proof fn bit_and_not(x: u64, y: u64, k: u64)
    requires k < 64,
    ensures bit(x & !y, k) <==> (bit(x, k) && !bit(y, k)),
{
    assert(k < 64u64 ==> (((x & !y) >> k) & 1u64 == 1u64 <==> ((x >> k) & 1u64 == 1u64 && !((y >> k) & 1u64 == 1u64)))) by(bit_vector);
}

proof fn bit_zero(k: u64)
    requires k < 64,
    ensures !bit(0u64, k),
{
    assert(k < 64u64 ==> (0u64 >> k) & 1u64 != 1u64) by(bit_vector);
}

proof fn bit_single(m: u64, k: u64)
    requires m < 64, k < 64,
    ensures bit(1u64 << m, k) <==> k == m,
{
    assert(m < 64u64 && k < 64u64 ==> ((((1u64 << m) >> k) & 1u64 == 1u64) <==> k == m)) by(bit_vector);
}

/// 生产实现的成员判定写法 `w & (1 << k) != 0` 与规格 `bit` 等价。
proof fn mask_test_is_bit(x: u64, k: u64)
    requires k < 64,
    ensures (x & (1u64 << k) != 0) <==> bit(x, k),
{
    assert(k < 64u64 ==> ((x & (1u64 << k) != 0u64) <==> ((x >> k) & 1u64 == 1u64))) by(bit_vector);
}

proof fn word_subset_bit(x: u64, y: u64, k: u64)
    requires x & !y == 0, k < 64,
    ensures bit(x, k) ==> bit(y, k),
{
    assert((x & !y) == 0u64 && k < 64u64 && (x >> k) & 1u64 == 1u64 ==> (y >> k) & 1u64 == 1u64) by(bit_vector);
}

/// 64 个位全为 0 ⇒ 字为 0（子集判定完备性的依据）。
proof fn all_bits_zero(x: u64)
    requires forall|j: u64| j < 64 ==> !#[trigger] bit(x, j),
    ensures x == 0,
{
    assert forall|j: u64| j < 64 implies (#[trigger] (x >> j)) & 1u64 == 0u64 by {
        assert(!bit(x, j));
        assert((x >> j) & 1u64 != 1u64 ==> (x >> j) & 1u64 == 0u64) by(bit_vector);
    }
    assert(
        (x >> 0u64) & 1u64 == 0u64 && (x >> 1u64) & 1u64 == 0u64 && (x >> 2u64) & 1u64 == 0u64 && (x >> 3u64) & 1u64 == 0u64
        && (x >> 4u64) & 1u64 == 0u64 && (x >> 5u64) & 1u64 == 0u64 && (x >> 6u64) & 1u64 == 0u64 && (x >> 7u64) & 1u64 == 0u64
        && (x >> 8u64) & 1u64 == 0u64 && (x >> 9u64) & 1u64 == 0u64 && (x >> 10u64) & 1u64 == 0u64 && (x >> 11u64) & 1u64 == 0u64
        && (x >> 12u64) & 1u64 == 0u64 && (x >> 13u64) & 1u64 == 0u64 && (x >> 14u64) & 1u64 == 0u64 && (x >> 15u64) & 1u64 == 0u64
        && (x >> 16u64) & 1u64 == 0u64 && (x >> 17u64) & 1u64 == 0u64 && (x >> 18u64) & 1u64 == 0u64 && (x >> 19u64) & 1u64 == 0u64
        && (x >> 20u64) & 1u64 == 0u64 && (x >> 21u64) & 1u64 == 0u64 && (x >> 22u64) & 1u64 == 0u64 && (x >> 23u64) & 1u64 == 0u64
        && (x >> 24u64) & 1u64 == 0u64 && (x >> 25u64) & 1u64 == 0u64 && (x >> 26u64) & 1u64 == 0u64 && (x >> 27u64) & 1u64 == 0u64
        && (x >> 28u64) & 1u64 == 0u64 && (x >> 29u64) & 1u64 == 0u64 && (x >> 30u64) & 1u64 == 0u64 && (x >> 31u64) & 1u64 == 0u64
        && (x >> 32u64) & 1u64 == 0u64 && (x >> 33u64) & 1u64 == 0u64 && (x >> 34u64) & 1u64 == 0u64 && (x >> 35u64) & 1u64 == 0u64
        && (x >> 36u64) & 1u64 == 0u64 && (x >> 37u64) & 1u64 == 0u64 && (x >> 38u64) & 1u64 == 0u64 && (x >> 39u64) & 1u64 == 0u64
        && (x >> 40u64) & 1u64 == 0u64 && (x >> 41u64) & 1u64 == 0u64 && (x >> 42u64) & 1u64 == 0u64 && (x >> 43u64) & 1u64 == 0u64
        && (x >> 44u64) & 1u64 == 0u64 && (x >> 45u64) & 1u64 == 0u64 && (x >> 46u64) & 1u64 == 0u64 && (x >> 47u64) & 1u64 == 0u64
        && (x >> 48u64) & 1u64 == 0u64 && (x >> 49u64) & 1u64 == 0u64 && (x >> 50u64) & 1u64 == 0u64 && (x >> 51u64) & 1u64 == 0u64
        && (x >> 52u64) & 1u64 == 0u64 && (x >> 53u64) & 1u64 == 0u64 && (x >> 54u64) & 1u64 == 0u64 && (x >> 55u64) & 1u64 == 0u64
        && (x >> 56u64) & 1u64 == 0u64 && (x >> 57u64) & 1u64 == 0u64 && (x >> 58u64) & 1u64 == 0u64 && (x >> 59u64) & 1u64 == 0u64
        && (x >> 60u64) & 1u64 == 0u64 && (x >> 61u64) & 1u64 == 0u64 && (x >> 62u64) & 1u64 == 0u64 && (x >> 63u64) & 1u64 == 0u64
        ==> x == 0u64) by(bit_vector);
}

/// 单字子集判定的完备性：字 i 中 a 的每一位都在 b 中 ⇒ `a & !b == 0`。
proof fn word_subset_complete(x: u64, y: u64)
    requires forall|k: u64| k < 64 ==> (#[trigger] bit(x, k) ==> bit(y, k)),
    ensures x & !y == 0,
{
    assert forall|k: u64| k < 64 implies !#[trigger] bit(x & !y, k) by {
        bit_and_not(x, y, k);
    }
    all_bits_zero(x & !y);
}

proof fn word_of_id(s: Set4, i: u64, k: u64)
    requires i < 4, k < 64,
    ensures ((64 * i + k) as u64) / 64 == i, ((64 * i + k) as u64) % 64 == k,
            granted(s, (64 * i + k) as u64) <==> bit(word(s, i), k),
{
}

proof fn subset_words(a: Set4, b: Set4, i: u64)
    requires subset(a, b), i < 4,
    ensures word(a, i) & !word(b, i) == 0,
{
    assert forall|k: u64| k < 64 implies (#[trigger] bit(word(a, i), k) ==> bit(word(b, i), k)) by {
        word_of_id(a, i, k);
        word_of_id(b, i, k);
        assert(granted(a, (64 * i + k) as u64) ==> granted(b, (64 * i + k) as u64));
    }
    word_subset_complete(word(a, i), word(b, i));
}

/// 生产：`SyscallSet::from_id`。
fn from_id(id: u64) -> (out: Option<Set4>)
    ensures
        id >= MAX_IDS ==> out.is_none(),
        id < MAX_IDS ==> (out.is_some() && forall|j: u64| #[trigger] granted(out.unwrap(), j) <==> j == id),
{
    if id >= 256 {
        return None;
    }
    let one: u64 = 1u64 << (id % 64);
    let i = id / 64;
    let s = if i == 0 {
        Set4 { w0: one, w1: 0, w2: 0, w3: 0 }
    } else if i == 1 {
        Set4 { w0: 0, w1: one, w2: 0, w3: 0 }
    } else if i == 2 {
        Set4 { w0: 0, w1: 0, w2: one, w3: 0 }
    } else {
        Set4 { w0: 0, w1: 0, w2: 0, w3: one }
    };
    proof {
        assert forall|j: u64| #[trigger] granted(s, j) <==> j == id by {
            if j < MAX_IDS {
                bit_single(id % 64, j % 64);
                bit_zero(j % 64);
            }
        }
    }
    Some(s)
}

/// 生产：`SyscallSet::contains`（`words[i / 64] & (1 << (i % 64)) != 0`）。
fn contains(s: Set4, id: u64) -> (r: bool)
    ensures r <==> granted(s, id),
{
    if id >= 256 {
        return false;
    }
    let i = id / 64;
    let w = if i == 0 { s.w0 } else if i == 1 { s.w1 } else if i == 2 { s.w2 } else { s.w3 };
    proof {
        mask_test_is_bit(w, id % 64);
    }
    w & (1u64 << (id % 64)) != 0
}

/// 生产：`SyscallSet::union`。
fn union(a: Set4, b: Set4) -> (out: Set4)
    ensures forall|id: u64| #[trigger] granted(out, id) <==> (granted(a, id) || granted(b, id)),
{
    let out = Set4 { w0: a.w0 | b.w0, w1: a.w1 | b.w1, w2: a.w2 | b.w2, w3: a.w3 | b.w3 };
    proof {
        assert forall|id: u64| #[trigger] granted(out, id) <==> (granted(a, id) || granted(b, id)) by {
            if id < MAX_IDS {
                bit_or(word(a, id / 64), word(b, id / 64), id % 64);
            }
        }
    }
    out
}

/// 生产：`SyscallSet::intersection`。
fn intersection(a: Set4, b: Set4) -> (out: Set4)
    ensures forall|id: u64| #[trigger] granted(out, id) <==> (granted(a, id) && granted(b, id)),
{
    let out = Set4 { w0: a.w0 & b.w0, w1: a.w1 & b.w1, w2: a.w2 & b.w2, w3: a.w3 & b.w3 };
    proof {
        assert forall|id: u64| #[trigger] granted(out, id) <==> (granted(a, id) && granted(b, id)) by {
            if id < MAX_IDS {
                bit_and(word(a, id / 64), word(b, id / 64), id % 64);
            }
        }
    }
    out
}

/// 生产：`SyscallSet::difference`（撤权：结果 ⊆ a，且与 b 不相交）。
fn difference(a: Set4, b: Set4) -> (out: Set4)
    ensures
        forall|id: u64| #[trigger] granted(out, id) <==> (granted(a, id) && !granted(b, id)),
        subset(out, a),
{
    let out = Set4 { w0: a.w0 & !b.w0, w1: a.w1 & !b.w1, w2: a.w2 & !b.w2, w3: a.w3 & !b.w3 };
    proof {
        assert forall|id: u64| #[trigger] granted(out, id) <==> (granted(a, id) && !granted(b, id)) by {
            if id < MAX_IDS {
                bit_and_not(word(a, id / 64), word(b, id / 64), id % 64);
            }
        }
    }
    out
}

/// 生产：`SyscallSet::is_subset_of`（逐字 `a & !b != 0` 即否）。可靠且完备。
fn is_subset_of(a: Set4, b: Set4) -> (r: bool)
    ensures r <==> subset(a, b),
{
    let r = a.w0 & !b.w0 == 0 && a.w1 & !b.w1 == 0 && a.w2 & !b.w2 == 0 && a.w3 & !b.w3 == 0;
    proof {
        if r {
            assert forall|id: u64| #[trigger] granted(a, id) implies granted(b, id) by {
                word_subset_bit(word(a, id / 64), word(b, id / 64), id % 64);
            }
        }
        if subset(a, b) {
            subset_words(a, b, 0);
            subset_words(a, b, 1);
            subset_words(a, b, 2);
            subset_words(a, b, 3);
        }
    }
    r
}

pub enum SpawnReject {
    Format,
    Reserved,
    ImageSize,
    UnknownCall,
    Escalation,
    CpuLimit,
}

/// 生产：`spawn_abi::check`，规则顺序与生产一致。
/// 通过 ⇒ 头部合法、保留位为 0、映像大小有界、请求 ⊆ 登记集合、请求 ⊆ 调用者集合、CPU 上限在界内。
fn check(
    magic: u32, version: u16, size: u16, flags: u32, image_len: u64,
    calls: Set4, caller: Set4, known: Set4, cpu: u32,
) -> (r: Result<(), SpawnReject>)
    ensures
        r.is_ok() <==> (
            magic == SPAWN_MAGIC && version == SPAWN_VERSION && size == SPAWN_SIZE && flags == 0
            && 0 < image_len && image_len <= MAX_IMAGE_BYTES
            && subset(calls, known) && subset(calls, caller)
            && MIN_CPU_LIMIT <= cpu && cpu <= CPU_UNLIMITED),
{
    if magic != SPAWN_MAGIC || version != SPAWN_VERSION || size != SPAWN_SIZE {
        return Err(SpawnReject::Format);
    }
    if flags != 0 {
        return Err(SpawnReject::Reserved);
    }
    if image_len == 0 || image_len > MAX_IMAGE_BYTES {
        return Err(SpawnReject::ImageSize);
    }
    if !is_subset_of(calls, known) {
        return Err(SpawnReject::UnknownCall);
    }
    if !is_subset_of(calls, caller) {
        return Err(SpawnReject::Escalation);
    }
    if cpu < MIN_CPU_LIMIT || cpu > CPU_UNLIMITED {
        return Err(SpawnReject::CpuLimit);
    }
    Ok(())
}

/// 子集关系传递：孙进程的授权仍不超出祖先（撤权不可借多级 spawn 提升）。
proof fn subset_transitive(a: Set4, b: Set4, c: Set4)
    requires subset(a, b), subset(b, c),
    ensures subset(a, c),
{
}

fn main() {}

} // verus!
