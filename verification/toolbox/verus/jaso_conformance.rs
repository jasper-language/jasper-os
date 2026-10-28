// `jaso::conformance::check` 的判定结构（伴随规格）：六个步骤（结构读取、信任、平台、运行时、依赖、能力）依次判定，
// 结果为 ok 当且仅当每一步都通过；否则报告的恰是第一处失败的步骤——前面各步都通过、该步失败。
// 依赖与能力两步各自是「每一项都被满足」的全称判定，同样以第一处不满足的项为准。
use vstd::prelude::*;

verus! {

/// 依次判定：返回第一个失败步骤的下标；全部通过返回 None。
fn first_failure(steps: &Vec<bool>) -> (r: Option<usize>)
    ensures
        r.is_none() <==> (forall|i: int| 0 <= i < steps.len() ==> steps[i]),
        r matches Some(k) ==> k < steps.len() && !steps[k as int] && (forall|i: int| 0 <= i < k ==> steps[i]),
{
    let mut i: usize = 0;
    while i < steps.len()
        invariant
            i <= steps.len(),
            forall|j: int| 0 <= j < i ==> steps[j],
        decreases steps.len() - i,
    {
        if !steps[i] {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// 能力步：每个请求都在授予表里，才通过（对应 `requires().any(|c| !GRANTED.contains(c))` 的否定）。
fn all_granted(requests: &Vec<u32>, granted: &Vec<u32>) -> (r: bool)
    ensures r <==> (forall|i: int| 0 <= i < requests.len() ==> granted@.contains(requests[i])),
{
    let mut i: usize = 0;
    while i < requests.len()
        invariant
            i <= requests.len(),
            forall|j: int| 0 <= j < i ==> granted@.contains(requests[j]),
        decreases requests.len() - i,
    {
        let mut found = false;
        let mut k: usize = 0;
        while k < granted.len()
            invariant
                i < requests.len(),
                k <= granted.len(),
                forall|j: int| 0 <= j < i ==> granted@.contains(requests[j]),
                found <==> (exists|m: int| 0 <= m < k && granted[m] == requests[i as int]),
            decreases granted.len() - k,
        {
            if granted[k] == requests[i] {
                found = true;
            }
            k += 1;
        }
        if !found {
            proof {
                if granted@.contains(requests[i as int]) {
                    let m = choose|m: int| 0 <= m < granted@.len() && granted@[m] == requests[i as int];
                    assert(granted[m] == requests[i as int]);
                }
            }
            return false;
        }
        proof {
            let m = choose|m: int| 0 <= m < granted.len() && granted[m] == requests[i as int];
            assert(granted@[m] == requests[i as int]);
            assert(granted@.contains(requests[i as int]));
        }
        i += 1;
    }
    true
}

fn main() {}
}
