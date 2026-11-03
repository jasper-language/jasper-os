// 负例：只比较时刻、不比较所有者的「无变化」判定是错的——跨核迁移会被漏掉。
// 本文件必须验证失败。
use vstd::prelude::*;

verus! {

pub struct Node { pub owner: nat, pub at: int, pub generation: int }

spec fn unchanged_by_time_only(o: Node, w: (nat, int)) -> bool { w.1 == o.at }

proof fn time_only_is_enough(o: Node, w: (nat, int))
    requires unchanged_by_time_only(o, w)
    ensures w.0 == o.owner,
{
}

fn main() {}
}
