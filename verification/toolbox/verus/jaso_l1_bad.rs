// 负例：去掉「没有运行中的依赖者」这一前提，stop 不再保持不变量（证明伴随规格确实依赖该前提）。
use vstd::prelude::*;

verus! {

spec fn holds(running: Seq<bool>, dep: spec_fn(int, int) -> bool) -> bool {
    forall|j: int, k: int| #![trigger dep(j, k)] 0 <= j < running.len() && 0 <= k < running.len() && running[j] && dep(j, k) ==> running[k]
}

proof fn stop_without_precondition(running: Seq<bool>, dep: spec_fn(int, int) -> bool, i: int)
    requires
        0 <= i < running.len(),
        holds(running, dep),
    ensures
        holds(running.update(i, false), dep),
{
}

fn main() {}

} // verus!
