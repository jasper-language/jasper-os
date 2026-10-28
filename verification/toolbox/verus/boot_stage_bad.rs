// 故意错误的负例：begin 漏掉依赖检查，「成功 ⇒ 直接依赖全部完成」后置条件必须验证失败。
// Deliberately wrong negative: a begin without the dependency check must fail its postcondition.
use vstd::prelude::*;

verus! {
pub open spec fn req(i: u32) -> u32 {
    if i == 0 { 0 } else if i == 5 { 0x18 } else { 0x1 }
}

fn bad_begin(started: u32, done: u32, failed: bool, s: u32) -> (r: u8)
    requires s < 10,
    ensures r == 0 ==> req(s) & !done == 0,
{
    if failed {
        return 1;
    }
    if started & (1u32 << s) != 0 {
        return 3;
    }
    0
}

fn main() {}
}
