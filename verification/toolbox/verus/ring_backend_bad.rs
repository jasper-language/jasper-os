// 故意错误的负例：查找从第二条路由开始（漏查第一条），「无匹配 ⇔ None」后置条件必须验证失败。
// Deliberately wrong negative: skipping the first route must fail the None postcondition.
use vstd::prelude::*;

verus! {
fn bad_route(ops: &Vec<u32>, op: u32) -> (r: bool)
    ensures r <==> (exists|a: int| 0 <= a < ops.len() && ops@[a] == op),
{
    let mut i: usize = 1;
    while i < ops.len()
        invariant 1 <= i, i <= ops.len() || ops.len() == 0,
        decreases ops.len() - i,
    {
        if ops[i] == op {
            return true;
        }
        i += 1;
    }
    false
}

fn main() {}
}
