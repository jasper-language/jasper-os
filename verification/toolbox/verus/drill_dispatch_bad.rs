// 负例：把「运行过」判成「busy >= 0」（恒真）——空闲的处理器也被算作分派过，后置条件推不出（必须验证失败）。
use vstd::prelude::*;

verus! {

pub open spec fn ran(busy: Seq<u64>, i: int) -> bool {
    0 <= i < busy.len() && i < 32 && busy[i] > 0
}

pub fn dispatch_mask_counts_idle(busy: &[u64]) -> (m: u32)
    requires busy.len() >= 1, busy@[0] == 0,
    ensures
        forall|j: u32| j < 32 ==> (((m >> j) & 1u32) == 1u32 <==> ran(busy@, j as int)),
{
    let mut mask = 0u32;
    if busy[0] >= 0 {
        mask = mask | 1u32;
    }
    mask
}

fn main() {}

} // verus!
