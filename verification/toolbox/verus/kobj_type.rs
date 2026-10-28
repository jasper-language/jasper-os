// 伴随模型（issue #4 第一片）：kernel_core::kobj_type::{check_grant, edge_ordered} 与
// kernel_core::object::Rights::{contains, intersect}（既有代码补链）。权限以 u32 位掩码建模，
// 种类以其声明下标建模。本文件不直接验证 Rust 源码；生产函数与模型的一致性由 Proptest / fuzz 差分保证。
// Companion model; production/model agreement is covered by the differential Proptest and fuzz targets.
use vstd::prelude::*;

verus! {

pub const TRANSFER: u32 = 0x40;

/// Rights::contains：a 包含 b 的全部位。
pub open spec fn contains(a: u32, b: u32) -> bool {
    a & b == b
}

/// 0 = Allowed，1 = WrongType，2 = NotTransferable，3 = RightsDenied（检查顺序与生产一致）。
fn check_grant(type_ok: bool, transferable: bool, ceiling: u32, rights: u32) -> (r: u8)
    ensures
        r == 0 <==> (type_ok && contains(ceiling, rights) && (rights & TRANSFER != 0 ==> transferable)),
        r == 1 <==> !type_ok,
        r == 2 <==> (type_ok && rights & TRANSFER != 0 && !transferable),
        r == 3 <==> (type_ok && (rights & TRANSFER == 0 || transferable) && !contains(ceiling, rights)),
{
    if !type_ok {
        return 1;
    }
    if rights & TRANSFER != 0 && !transferable {
        return 2;
    }
    if ceiling & rights != rights {
        return 3;
    }
    0
}

/// 登记表良构条件 3 的推论：上限含 TRANSFER ⇔ 可转移时，任何通过检查的权限都满足「含 TRANSFER ⇒ 可转移」，
/// 且这一条对后续降权（取子集）保持。
proof fn lemma_restrict_stays_within_ceiling(ceiling: u32, granted: u32, later: u32)
    requires
        contains(ceiling, granted),
        contains(granted, later),
    ensures
        contains(ceiling, later),
        (later & TRANSFER != 0) ==> (ceiling & TRANSFER != 0),
{
    assert(ceiling & later == later) by (bit_vector)
        requires ceiling & granted == granted, granted & later == later;
    assert((later & 0x40u32 != 0) ==> (ceiling & 0x40u32 != 0)) by (bit_vector)
        requires ceiling & later == later;
}

/// Rights::intersect 的结果被两边包含（降权只会更小）。
proof fn lemma_intersect_is_subset(a: u32, b: u32)
    ensures contains(a, a & b), contains(b, a & b),
{
    assert(a & (a & b) == a & b && b & (a & b) == a & b) by (bit_vector);
}

pub open spec fn ordered_path(p: Seq<nat>) -> bool {
    forall|i: int| 0 <= i < p.len() - 1 ==> #[trigger] p[i] < p[i + 1]
}

/// 每条强边都指向更靠后的种类 ⇒ 路径上的下标严格递增 ⇒ 长度 ≥ 2 的路径不会回到起点（类型层面无环）。
proof fn lemma_ordered_path_increases(p: Seq<nat>)
    requires ordered_path(p), p.len() >= 2,
    ensures p[0] < p[p.len() - 1],
    decreases p.len(),
{
    if p.len() > 2 {
        let q = p.drop_last();
        assert(ordered_path(q));
        lemma_ordered_path_increases(q);
        assert(p[p.len() - 2] < p[p.len() - 1]);
    }
}

proof fn lemma_no_cycle(p: Seq<nat>)
    requires ordered_path(p), p.len() >= 2,
    ensures p[0] != p[p.len() - 1],
{
    lemma_ordered_path_increases(p);
}

fn main() {}
}
