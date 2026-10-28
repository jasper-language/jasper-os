// 负例：报告「最后一处」失败步骤的判定必须无法满足同一规格（证明伴随规格确实约束了报告顺序）。
use vstd::prelude::*;

verus! {

fn last_failure(steps: &Vec<bool>) -> (r: Option<usize>)
    ensures
        r.is_none() <==> (forall|i: int| 0 <= i < steps.len() ==> steps[i]),
        r matches Some(k) ==> k < steps.len() && !steps[k as int] && (forall|i: int| 0 <= i < k ==> steps[i]),
{
    let mut i: usize = 0;
    let mut r: Option<usize> = None;
    while i < steps.len()
        invariant
            i <= steps.len(),
            r.is_none() <==> (forall|j: int| 0 <= j < i ==> steps[j]),
            r matches Some(k) ==> k < i && !steps[k as int],
        decreases steps.len() - i,
    {
        if !steps[i] {
            r = Some(i);
        }
        i += 1;
    }
    r
}

fn main() {}
}
