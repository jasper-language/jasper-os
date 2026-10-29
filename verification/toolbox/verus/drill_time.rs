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

// hog_continues：Rust 源以 covered.count_ones() 求到过的核数，此处以其值 covered_cores 建模
// （popcount 本身由 Kani hog_loop_bounded_full_domain 全域覆盖）。
pub open spec fn hog_go(now: u64, end: u64, covered_cores: u32, want_cores: u32, cutoff: u64) -> bool {
    now < end || (covered_cores < want_cores && now < cutoff)
}

pub fn hog_continues(now: u64, end: u64, covered_cores: u32, want_cores: u32, cutoff: u64) -> (go: bool)
    ensures
        go == hog_go(now, end, covered_cores, want_cores, cutoff),
        now < end ==> go,
        now >= end && now >= cutoff ==> !go,
        now >= end && covered_cores >= want_cores ==> !go,
        want_cores == 0 ==> (go <==> now < end),
{
    now < end || (covered_cores < want_cores && now < cutoff)
}

// 吃满任务的循环（时钟单调前进、覆盖数任意）必在 max(end, cutoff) 之前停止。
pub fn hog_loop_model(start: u64, end: u64, covered_cores: u32, want_cores: u32, cutoff: u64) -> (stop: u64)
    ensures
        !hog_go(stop, end, covered_cores, want_cores, cutoff),
        stop >= start,
        stop <= if start >= end && start >= cutoff { start } else if end >= cutoff { end } else { cutoff },
{
    let mut now = start;
    while hog_continues(now, end, covered_cores, want_cores, cutoff)
        invariant
            now >= start,
            now <= if start >= end && start >= cutoff { start } else if end >= cutoff { end } else { cutoff },
        decreases (if end >= cutoff { end } else { cutoff }) - now,
    {
        now = now + 1;
    }
    now
}

// dispatch_mask：前 32 个处理器中运行过任务（busy > 0）的那些位恰好置位，其余为 0。
pub open spec fn ran(busy: Seq<u64>, i: int) -> bool {
    0 <= i < busy.len() && i < 32 && busy[i] > 0
}

pub fn dispatch_mask(busy: &[u64]) -> (m: u32)
    ensures
        forall|j: u32| j < 32 ==> (((m >> j) & 1u32) == 1u32 <==> ran(busy@, j as int)),
{
    let mut mask = 0u32;
    let lim = if busy.len() < 32 { busy.len() } else { 32 };
    let mut i: usize = 0;
    assert forall|j: u32| j < 32 implies ((((0u32 >> j) & 1u32) == 1u32) == false) by {
        assert(((0u32 >> j) & 1u32) == 0u32) by (bit_vector);
    }
    while i < lim
        invariant
            i <= lim,
            lim <= 32,
            lim <= busy.len(),
            lim == busy.len() || lim == 32,
            forall|j: u32| #![trigger (mask >> j)] j < 32 ==> ((((mask >> j) & 1u32) == 1u32) <==> ((j as int) < (i as int) && ran(busy@, j as int))),
        decreases lim - i,
    {
        let k = i as u32;
        if busy[i] > 0 {
            let next = mask | (1u32 << k);
            assert forall|j: u32| #![trigger (next >> j)] j < 32 implies
                ((((next >> j) & 1u32) == 1u32) <==> ((j as int) < (i as int) + 1 && ran(busy@, j as int))) by {
                assert((((mask | (1u32 << k)) >> j) & 1u32 == 1u32) == ((((mask >> j) & 1u32) == 1u32) || j == k))
                    by (bit_vector) requires j < 32u32, k < 32u32;
                assert((((next >> j) & 1u32) == 1u32) == ((((mask >> j) & 1u32) == 1u32) || j == k));
                assert((((mask >> j) & 1u32) == 1u32) <==> ((j as int) < (i as int) && ran(busy@, j as int)));
                if j == k {
                    assert(j as int == i as int);
                    assert(ran(busy@, j as int));
                } else {
                    assert(j as int != i as int);
                }
            }
            mask = next;
        } else {
            assert forall|j: u32| #![trigger (mask >> j)] j < 32 implies
                ((((mask >> j) & 1u32) == 1u32) <==> ((j as int) < (i as int) + 1 && ran(busy@, j as int))) by {
                if j as int == i as int {
                    assert(!ran(busy@, j as int));
                }
            }
        }
        i += 1;
    }
    mask
}

fn main() {}

} // verus!
