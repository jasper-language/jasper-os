// 伴随模型（issue #5 第一片）：kernel_core::ring_backend::{route, routes_well_formed} 的查找与
// 「编号非零且互不相同」检查，以 Vec<u32> 操作编号 + Vec<u8> 后端序号建模；另含 quota::reserve_u32 的
// 减法守卫等价式（补链）。本文件不直接验证 Rust 源码；生产函数与模型的一致性由 Proptest / fuzz 差分保证。
// Companion model; production/model agreement is covered by the differential Proptest and fuzz targets.
use vstd::prelude::*;

verus! {

pub open spec fn unique(ops: Seq<u32>) -> bool {
    forall|a: int, b: int| 0 <= a < ops.len() && 0 <= b < ops.len() && a != b ==> ops[a] != ops[b]
}

pub open spec fn nonzero(ops: Seq<u32>) -> bool {
    forall|a: int| 0 <= a < ops.len() ==> ops[a] != 0
}

/// route：返回第一条同编号路由的后端；无匹配 ⇔ None；表唯一时结果与任一同编号路由一致。
fn route(ops: &Vec<u32>, kinds: &Vec<u8>, op: u32) -> (r: Option<u8>)
    requires ops.len() == kinds.len(),
    ensures
        r.is_none() <==> (forall|a: int| 0 <= a < ops.len() ==> ops@[a] != op),
        r.is_some() ==> (exists|a: int| 0 <= a < ops.len() && ops@[a] == op && kinds@[a] == r.unwrap()),
        (r.is_some() && unique(ops@)) ==> (forall|a: int| 0 <= a < ops.len() && ops@[a] == op ==> kinds@[a] == r.unwrap()),
{
    let mut i: usize = 0;
    while i < ops.len()
        invariant
            0 <= i <= ops.len(),
            ops.len() == kinds.len(),
            forall|a: int| 0 <= a < i ==> ops@[a] != op,
        decreases ops.len() - i,
    {
        if ops[i] == op {
            assert(ops@[i as int] == op && kinds@[i as int] == kinds@[i as int]);
            return Some(kinds[i]);
        }
        i += 1;
    }
    None
}

/// routes_well_formed 的编号部分：结果为真 ⇔ 全部非零且互不相同。
fn distinct_nonzero(ops: &Vec<u32>) -> (b: bool)
    ensures b <==> (unique(ops@) && nonzero(ops@)),
{
    let mut i: usize = 0;
    while i < ops.len()
        invariant
            0 <= i <= ops.len(),
            forall|a: int| 0 <= a < i ==> ops@[a] != 0,
            forall|a: int, c: int| 0 <= a < i && 0 <= c < ops.len() && a != c ==> ops@[a] != ops@[c],
        decreases ops.len() - i,
    {
        if ops[i] == 0 {
            assert(!nonzero(ops@));
            return false;
        }
        let mut j: usize = i + 1;
        while j < ops.len()
            invariant
                0 <= i < ops.len(),
                i < j <= ops.len(),
                ops@[i as int] != 0,
                forall|a: int| 0 <= a < i ==> ops@[a] != 0,
                forall|a: int, c: int| 0 <= a < i && 0 <= c < ops.len() && a != c ==> ops@[a] != ops@[c],
                forall|c: int| i < c < j ==> ops@[i as int] != ops@[c],
            decreases ops.len() - j,
        {
            if ops[j] == ops[i] {
                assert(ops@[i as int] == ops@[j as int] && i != j);
                assert(!unique(ops@));
                return false;
            }
            j += 1;
        }
        assert forall|c: int| 0 <= c < ops.len() && i as int != c implies ops@[i as int] != ops@[c] by {
            if c < i {
                assert(ops@[c] != ops@[i as int]);
            }
        }
        i += 1;
    }
    true
}

/// quota::reserve_u32 的减法守卫伴随式：接受 ⇔ 数学和不超过上限，且结果等于数学和。
fn reserve_u32(current: u32, amount: u32, limit: u32) -> (r: Option<u32>)
    ensures
        r.is_some() <==> current as int + amount as int <= limit as int,
        r.is_some() ==> r.unwrap() as int == current as int + amount as int,
{
    if amount > limit || current > limit - amount { None } else { Some(current + amount) }
}

fn main() {}
}
