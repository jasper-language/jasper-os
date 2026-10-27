// issue #1 负例：只比较第一个字的子集判定（等价于旧 `u64` 能力集合把 ID≥64 静默忽略）。
// 本文件必须验证失败；若通过，说明规格未能区分高编号权限，套件判失败。
// Strict negative: a subset check that only inspects word 0 must NOT verify.
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

/// 错误实现：只看字 0。ID 64..255 的越权请求会被放行。
fn is_subset_of_low_word_only(a: Set4, b: Set4) -> (r: bool)
    ensures r ==> subset(a, b),
{
    let r = a.w0 & !b.w0 == 0;
    proof {
        if r {
            assert forall|id: u64| #[trigger] granted(a, id) implies granted(b, id) by {
                word_subset_bit(word(a, id / 64), word(b, id / 64), id % 64);
            }
        }
    }
    r
}

fn main() {}

} // verus!
