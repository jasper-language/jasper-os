// 故意错误的负例：周期数少算一个（end 正好落在边界上时没有跨过去），「next 严格大于 end」必须验证失败。
// Deliberately wrong negative: one period short must fail the "next is past end" property.
use vstd::prelude::*;

verus! {
fn bad_next(next: u64, period: u64, end: u64) -> (r: u64)
    requires period > 0, end >= next, end <= 1000, next <= 1000, period <= 1000,
    ensures r > end,
{
    let periods = (end - next) / period;
    proof {
        assert(periods <= 1000) by (nonlinear_arith)
            requires periods == (end - next) as int / period as int, end - next <= 1000, period > 0;
        assert(periods * period <= 1000) by (nonlinear_arith)
            requires periods == (end - next) as int / period as int, end - next <= 1000, period > 0, end >= next;
    }
    next + periods * period
}

fn main() {}
}
