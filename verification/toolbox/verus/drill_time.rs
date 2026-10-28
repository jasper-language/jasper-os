// 伴随模型：kernel_core::timer_units::counter_ns 与 kernel_core::drill 两个判据。
// 与 Rust 源的一致性靠 Proptest / fuzz 差分（tests/drill_time.rs、fuzz_targets/drill_time.rs）。
use vstd::prelude::*;
use vstd::arithmetic::div_mod::*;

verus! {

pub open spec fn floor_ns(e: int, hz: int) -> int recommends hz > 0 {
    (e * 1_000_000_000) / hz
}

pub fn counter_ns(elapsed: u64, hz: u64) -> (r: Option<u64>)
    ensures
        hz == 0 ==> r.is_none(),
        hz > 0 ==> (r.is_some() <==> floor_ns(elapsed as int, hz as int) <= u64::MAX as int),
        r.is_some() ==> r.unwrap() as int * hz as int <= elapsed as int * 1_000_000_000,
        r.is_some() ==> elapsed as int * 1_000_000_000 < (r.unwrap() as int + 1) * hz as int,
{
    if hz == 0 {
        return None;
    }
    assert(elapsed as int * 1_000_000_000 <= u64::MAX as int * 1_000_000_000) by (nonlinear_arith)
        requires elapsed as int <= u64::MAX as int;
    let p: u128 = (elapsed as u128) * 1_000_000_000u128;
    let q: u128 = p / (hz as u128);
    proof {
        let (pi, hi, qi) = (p as int, hz as int, q as int);
        lemma_fundamental_div_mod(pi, hi);
        lemma_mod_pos_bound(pi, hi);
        assert(qi == floor_ns(elapsed as int, hi));
        assert(qi * hi <= pi) by (nonlinear_arith)
            requires pi == hi * (pi / hi) + (pi % hi), 0 <= (pi % hi), qi == pi / hi;
        assert(pi < (qi + 1) * hi) by (nonlinear_arith)
            requires pi == hi * (pi / hi) + (pi % hi), (pi % hi) < hi, qi == pi / hi;
    }
    if q <= u64::MAX as u128 { Some(q as u64) } else { None }
}

proof fn counter_ns_monotone(e1: int, e2: int, hz: int)
    requires 0 <= e1 <= e2, hz > 0,
    ensures floor_ns(e1, hz) <= floor_ns(e2, hz),
{
    assert(e1 * 1_000_000_000 <= e2 * 1_000_000_000) by (nonlinear_arith) requires e1 <= e2;
    lemma_div_is_ordered(e1 * 1_000_000_000, e2 * 1_000_000_000, hz);
}

pub fn refill_consistent(quota: u32, remaining: u32, period_start: u64, now: u64) -> (ok: bool)
    ensures
        ok ==> 1 <= remaining <= quota,
        ok ==> quota - remaining <= (if now >= period_start { now - period_start } else { 0 }),
        now <= period_start ==> (ok <==> (remaining == quota && quota >= 1)),
{
    let elapsed = if now >= period_start { now - period_start } else { 0 };
    remaining >= 1 && remaining <= quota && ((quota - remaining) as u64) <= elapsed
}

pub fn preempt_step_continues(step: u32, min_steps: u32, switches: u64, min_switches: u64, now: u64, deadline: u64) -> (go: bool)
    ensures
        step < min_steps ==> go,
        !go ==> step >= min_steps,
        step >= min_steps && (now >= deadline || switches >= min_switches) ==> !go,
{
    step < min_steps || (switches < min_switches && now < deadline)
}

fn main() {}

} // verus!
