// `.jaso` L1 模块表（`jaso::lifecycle::Registry`）与绑定一致性（`jaso::binding::check`）的伴随规格：
// ① stop 前提「没有运行中的依赖者」保持不变量「运行中模块的依赖都在运行中」；装入前提「依赖都在运行中」同样保持。
// ② 绑定判定：每个 fn 都属于导出集、每个导出都有 fn ⇒ 两个集合相等。
use vstd::prelude::*;

verus! {

spec fn holds(running: Seq<bool>, dep: spec_fn(int, int) -> bool) -> bool {
    forall|j: int, k: int| 0 <= j < running.len() && 0 <= k < running.len() && running[j] && dep(j, k) ==> running[k]
}

/// stop(i)：前提是没有运行中的依赖者。
proof fn stop_preserves(running: Seq<bool>, dep: spec_fn(int, int) -> bool, i: int)
    requires
        0 <= i < running.len(),
        holds(running, dep),
        forall|j: int| 0 <= j < running.len() && running[j] ==> !dep(j, i),
    ensures
        holds(running.update(i, false), dep),
{
    let after = running.update(i, false);
    assert forall|j: int, k: int| 0 <= j < after.len() && 0 <= k < after.len() && after[j] && dep(j, k) implies after[k] by {
        assert(running[j]);
        assert(running[k]);
        assert(k != i);
    }
}

/// load：新模块的依赖都在运行中；已有模块的依赖关系不因它改变（依赖只指向更早的模块）。
proof fn load_preserves(running: Seq<bool>, dep: spec_fn(int, int) -> bool)
    requires
        holds(running, dep),
        forall|k: int| 0 <= k < running.len() && dep(running.len() as int, k) ==> running[k],
        !dep(running.len() as int, running.len() as int),
        forall|j: int| 0 <= j < running.len() ==> !dep(j, running.len() as int),
    ensures
        holds(running.push(true), dep),
{
    let after = running.push(true);
    let n = running.len() as int;
    assert forall|j: int, k: int| 0 <= j < after.len() && 0 <= k < after.len() && after[j] && dep(j, k) implies after[k] by {
        if j == n {
            assert(k != n);
            assert(running[k]);
        } else {
            assert(running[j]);
            assert(k != n);
            assert(running[k]);
        }
    }
}

/// 绑定：判定通过 ⇔ 两个方向的包含都成立。
fn sets_agree(fns: &Vec<u32>, exports: &Vec<u32>) -> (r: bool)
    ensures
        r <==> (fns@.to_set() == exports@.to_set()),
{
    let mut i: usize = 0;
    while i < fns.len()
        invariant
            i <= fns.len(),
            forall|j: int| 0 <= j < i ==> exports@.contains(fns[j]),
        decreases fns.len() - i,
    {
        if !contains(exports, fns[i]) {
            assert(fns@.to_set().contains(fns[i as int]));
            assert(!exports@.to_set().contains(fns[i as int]));
            return false;
        }
        i += 1;
    }
    let mut i: usize = 0;
    while i < exports.len()
        invariant
            i <= exports.len(),
            forall|j: int| 0 <= j < fns.len() ==> exports@.contains(fns[j]),
            forall|j: int| 0 <= j < i ==> fns@.contains(exports[j]),
        decreases exports.len() - i,
    {
        if !contains(fns, exports[i]) {
            assert(exports@.to_set().contains(exports[i as int]));
            assert(!fns@.to_set().contains(exports[i as int]));
            return false;
        }
        i += 1;
    }
    assert(fns@.to_set() =~= exports@.to_set());
    true
}

fn contains(v: &Vec<u32>, x: u32) -> (r: bool)
    ensures
        r <==> v@.contains(x),
{
    let mut i: usize = 0;
    while i < v.len()
        invariant
            i <= v.len(),
            forall|j: int| 0 <= j < i ==> v[j] != x,
        decreases v.len() - i,
    {
        if v[i] == x {
            assert(v@[i as int] == x);
            return true;
        }
        i += 1;
    }
    false
}

fn main() {}

} // verus!
