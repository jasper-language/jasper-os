// CpuLimit::charge_batch 的迟到计数：闭式 = 逐个扣费时「第一个之后、扣费前余额已不为正」的个数。
// 规格按逐个扣费递归定义（第 i 次扣费前余额 = tokens − i·1000），实现与 kernel-core 闭式一致。
use vstd::prelude::*;

verus! {

pub open spec fn late_rec(t: int, n: int) -> int
    decreases n,
{
    if n <= 1 { 0 } else { late_rec(t, n - 1) + if t - 1000 * (n - 1) <= 0 { 1int } else { 0int } }
}

proof fn ceil_threshold(t: int, n: int)
    requires t > 0, n >= 0,
    ensures (t - 1000 * n <= 0) <==> (n >= (t + 999) / 1000),
{
    let k = (t + 999) / 1000;
    assert(1000 * k <= t + 999 && t + 999 < 1000 * k + 1000) by (nonlinear_arith) requires k == (t + 999) / 1000, t > 0;
    if n >= k {
        assert(1000 * n >= 1000 * k) by (nonlinear_arith) requires n >= k;
    } else {
        assert(1000 * n <= 1000 * (k - 1)) by (nonlinear_arith) requires n <= k - 1;
    }
}

proof fn late_closed(t: int, n: int)
    requires n >= 1,
    ensures
        t > 0 ==> late_rec(t, n) == n - if (t + 999) / 1000 < n { (t + 999) / 1000 } else { n },
        t <= 0 ==> late_rec(t, n) == n - 1,
    decreases n,
{
    if n > 1 {
        late_closed(t, n - 1);
        if t > 0 {
            ceil_threshold(t, n - 1);
            assert((t + 999) / 1000 >= 1) by (nonlinear_arith) requires t > 0;
        } else {
            assert(t - 1000 * (n - 1) <= 0) by (nonlinear_arith) requires t <= 0, n > 1;
        }
    } else if t > 0 {
        assert((t + 999) / 1000 >= 1) by (nonlinear_arith) requires t > 0;
    }
}

/// 与 kernel-core CpuLimit::charge_batch 的迟到部分同一闭式（tokens 为扣费前余额，limited = 上限 < 1000）。
pub fn batch_late(tokens: i32, limited: bool, ticks: u64) -> (late: u64)
    ensures
        ticks == 0 || !limited ==> late == 0,
        ticks >= 1 && limited ==> late as int == late_rec(tokens as int, ticks as int),
        late as int <= if ticks == 0 { 0 } else { ticks - 1 },
{
    if ticks == 0 {
        return 0;
    }
    if !limited {
        return 0;
    }
    let on_time: u64 = if tokens > 0 { ((tokens as u64) + 999) / 1000 } else { 1 };
    proof {
        late_closed(tokens as int, ticks as int);
        if tokens > 0 {
            assert(((tokens as int) + 999) / 1000 >= 1) by (nonlinear_arith) requires tokens > 0;
        }
    }
    ticks - if on_time < ticks { on_time } else { ticks }
}

fn main() {}

} // verus!
