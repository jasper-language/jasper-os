// 负例：若把容差也加到精确请求上，「精确请求不被推迟」必须验证失败。
// Negative: adding slack to precise requests must fail "precise is never delayed".
use vstd::prelude::*;

verus! {

fn latest_wrong(at: u64, precise: bool, slack: u64) -> (r: u64)
    ensures precise ==> r <= at,
{
    if slack <= u64::MAX - at { at + slack } else { u64::MAX }
}

fn main() {}
}
