// issue #3 统一定时事件契约的 Verus 模型：仲裁不晚于任何事件源的最晚处理时刻、
// 精确请求不被容差推迟、周期边界是第一个未来相位点、关闭后旧身份永不匹配。
// Verus model of the unified timer-event contract (issue #3).
use vstd::prelude::*;
use vstd::arithmetic::div_mod::{lemma_fundamental_div_mod, lemma_mod_multiples_basic};

verus! {

pub open spec fn spec_latest(at: u64, precise: bool, slack: u64) -> int {
    if precise { at as int }
    else if at as int + slack as int <= u64::MAX as int { at as int + slack as int }
    else { u64::MAX as int }
}

// 与 kernel-core Urgency::latest 同构。 / Mirrors Urgency::latest.
fn latest(at: u64, precise: bool, slack: u64) -> (r: u64)
    ensures r as int == spec_latest(at, precise, slack), r >= at,
{
    if precise { at } else if slack <= u64::MAX - at { at + slack } else { u64::MAX }
}

// 与 Arbiter 逐个 offer 同构。 / Mirrors repeated Arbiter::offer.
fn arbitrate(srcs: &Vec<(u64, bool, u64)>) -> (r: Option<u64>)
    ensures
        r.is_none() <==> srcs.len() == 0,
        r.is_some() ==> forall|i: int| 0 <= i < srcs.len() ==>
            r.unwrap() as int <= spec_latest(srcs[i].0, srcs[i].1, srcs[i].2),
        r.is_some() ==> forall|i: int| 0 <= i < srcs.len() && srcs[i].1 ==> r.unwrap() <= srcs[i].0,
        r.is_some() ==> exists|i: int| 0 <= i < srcs.len() &&
            r.unwrap() as int == spec_latest(srcs[i].0, srcs[i].1, srcs[i].2),
{
    let mut earliest: Option<u64> = None;
    let mut k: usize = 0;
    while k < srcs.len()
        invariant
            k <= srcs.len(),
            earliest.is_none() <==> k == 0,
            earliest.is_some() ==> forall|i: int| 0 <= i < k ==>
                earliest.unwrap() as int <= spec_latest(srcs[i].0, srcs[i].1, srcs[i].2),
            earliest.is_some() ==> exists|i: int| 0 <= i < k &&
                earliest.unwrap() as int == spec_latest(srcs[i].0, srcs[i].1, srcs[i].2),
        decreases srcs.len() - k,
    {
        let (at, precise, slack) = srcs[k];
        let l = latest(at, precise, slack);
        earliest = match earliest {
            Some(old) if old <= l => Some(old),
            _ => Some(l),
        };
        k += 1;
    }
    earliest
}

// next_boundary：previous <= now、period > 0 时 next 是严格晚于 now 的第一个相位点。
// next_boundary is the first phase point strictly after now.
proof fn boundary_is_first_future_phase_point(now: int, previous: int, period: int)
    requires period > 0, previous <= now,
    ensures ({
        let next = previous + ((now - previous) / period + 1) * period;
        next > now && next - period <= now && (next - previous) % period == 0
    }),
{
    let d = now - previous;
    let q = d / period;
    lemma_fundamental_div_mod(d, period);
    assert(0 <= d % period < period) by (nonlinear_arith) requires period > 0, d >= 0;
    assert((q + 1) * period == q * period + period) by (nonlinear_arith);
    assert(d == period * q + d % period);
    lemma_mod_multiples_basic(q + 1, period);
}

// 身份：创建令代数加一，关闭前的代数严格更小 ⇒ 旧身份不匹配新身份。
// Identity: create bumps the generation, so an older identity never matches.
proof fn closed_identity_never_matches(old_generation: int, slot_generation: int)
    requires old_generation <= slot_generation, slot_generation < u64::MAX as int,
    ensures old_generation != slot_generation + 1,
{
}

fn main() {}
}
