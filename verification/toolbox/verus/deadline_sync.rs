// issue #2：DeadlineForest::sync 的决策模型。
// 节点用 (owner, at, generation) 表示；None = 不在任何堆中。
// 证明：① 只在「两边都不存在」或「同所有者同时刻同代次」时不写；
//       ② 成功后的节点恰好等于目标；③ 代次不同一律拒绝且不改状态。
use vstd::prelude::*;

verus! {

pub enum Outcome { Unchanged, Inserted, Rescheduled, Moved, Removed, Stale }

pub struct Node { pub owner: nat, pub at: int, pub generation: int }

spec fn decide(old: Option<Node>, generation: int, wanted: Option<(nat, int)>) -> Outcome {
    match old {
        Some(o) => if o.generation != generation { Outcome::Stale } else {
            match wanted {
                None => Outcome::Removed,
                Some(w) => if w.0 == o.owner && w.1 == o.at { Outcome::Unchanged }
                    else if w.0 == o.owner { Outcome::Rescheduled } else { Outcome::Moved },
            }
        },
        None => match wanted { None => Outcome::Unchanged, Some(_) => Outcome::Inserted },
    }
}

spec fn after(old: Option<Node>, generation: int, wanted: Option<(nat, int)>) -> Option<Node> {
    match decide(old, generation, wanted) {
        Outcome::Stale => old,
        _ => match wanted { None => None, Some(w) => Some(Node { owner: w.0, at: w.1, generation }) },
    }
}

spec fn same(a: Option<Node>, b: Option<Node>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => x.owner == y.owner && x.at == y.at && x.generation == y.generation,
        _ => false,
    }
}

proof fn unchanged_iff_target_already_published(old: Option<Node>, generation: int, wanted: Option<(nat, int)>)
    requires old matches Some(o) ==> o.generation == generation
    ensures
        (decide(old, generation, wanted) == Outcome::Unchanged) <==> same(old, after(old, generation, wanted)),
{
}

proof fn success_publishes_exactly_wanted(old: Option<Node>, generation: int, wanted: Option<(nat, int)>)
    requires decide(old, generation, wanted) != Outcome::Stale
    ensures
        match after(old, generation, wanted) {
            None => wanted is None,
            Some(n) => wanted == Some((n.owner, n.at)) && n.generation == generation,
        },
{
}

proof fn stale_generation_never_writes(o: Node, generation: int, wanted: Option<(nat, int)>)
    requires o.generation != generation
    ensures
        decide(Some(o), generation, wanted) == Outcome::Stale,
        same(after(Some(o), generation, wanted), Some(o)),
{
}

proof fn move_changes_owner_reschedule_keeps_it(o: Node, generation: int, w: (nat, int))
    requires o.generation == generation
    ensures
        decide(Some(o), generation, Some(w)) == Outcome::Moved ==> w.0 != o.owner,
        decide(Some(o), generation, Some(w)) == Outcome::Rescheduled ==> w.0 == o.owner && w.1 != o.at,
{
}

fn main() {}
}
