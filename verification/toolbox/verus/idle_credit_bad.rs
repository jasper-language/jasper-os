// 负例（必须验证失败）：切入前不结算空闲（修复前的行为），任务被记整段空闲时长。
// 原伴随模型：kernel_core::timer_units::CreditLedger（及其内部 PeriodicCredit::advance）。
// 与 Rust 源的一致性靠 Proptest / fuzz 差分（tests/idle_credit.rs、fuzz_targets/idle_credit.rs）。
use vstd::prelude::*;
use vstd::arithmetic::div_mod::*;

verus! {

pub struct Credit { pub at: u64, pub period: u64, pub remainder: u64 }
pub struct Ledger { pub clock: Credit, pub idle_pending: u64 }

pub open spec fn wf(c: Credit) -> bool { c.period > 0 && c.remainder < c.period }

/// PeriodicCredit::advance：tick 数 × 周期 + 新余数 = 经过时长 + 旧余数（不铸造、不丢失），结果不截断。
pub fn advance(at: u64, period: u64, remainder: u64, now: u64) -> (r: Option<(u64, u64)>)
    requires period > 0, remainder < period,
    ensures
        r.is_none() <==> now < at,
        r.is_some() ==> r.unwrap().1 < period,
        r.is_some() ==> r.unwrap().0 as int * period as int + r.unwrap().1 as int
            == (now - at) as int + remainder as int,
{
    if now < at {
        return None;
    }
    let elapsed = now - at;
    let total: u128 = elapsed as u128 + remainder as u128;
    let p: u128 = period as u128;
    let q: u128 = total / p;
    let m: u128 = total % p;
    proof {
        let (ti, pi) = (total as int, p as int);
        lemma_fundamental_div_mod(ti, pi);
        lemma_mod_pos_bound(ti, pi);
        assert(q as int * pi + m as int == ti) by (nonlinear_arith)
            requires ti == pi * (ti / pi) + (ti % pi), q as int == ti / pi, m as int == ti % pi;
        // q ≤ u64::MAX：period = 1 时余数为 0、total ≤ u64::MAX；period ≥ 2 时 q ≤ total / 2 + 1。
        if pi == 1 {
            assert(q as int <= u64::MAX as int) by (nonlinear_arith)
                requires q as int * pi + m as int == ti, pi == 1, m >= 0, ti <= u64::MAX as int;
        } else {
            assert(q as int <= u64::MAX as int) by (nonlinear_arith)
                requires q as int * pi <= ti, pi >= 2, ti <= 2 * (u64::MAX as int), q >= 0;
        }
    }
    Some((q as u64, m as u64))
}

/// CreditLedger::settle_idle：空闲期间的 tick 记入待交付；失败（时间倒退 / 溢出）不改动。
pub fn settle_idle(l: &mut Ledger, now: u64) -> (r: Option<u64>)
    requires wf(old(l).clock),
    ensures
        wf(final(l).clock),
        r.is_none() ==> *final(l) == *old(l),
        r.is_some() ==> final(l).clock.at == now && final(l).clock.period == old(l).clock.period
            && final(l).idle_pending as int == old(l).idle_pending as int + r.unwrap() as int
            && r.unwrap() as int * final(l).clock.period as int + final(l).clock.remainder as int
                == (now - old(l).clock.at) as int + old(l).clock.remainder as int,
{
    match advance(l.clock.at, l.clock.period, l.clock.remainder, now) {
        None => None,
        Some((ticks, rem)) => {
            if l.idle_pending > u64::MAX - ticks {
                return None;
            }
            l.clock = Credit { at: now, period: l.clock.period, remainder: rem };
            l.idle_pending = l.idle_pending + ticks;
            Some(ticks)
        }
    }
}

/// CreditLedger::event：(当前执行流应记的 tick, 应交付的 tick)；交付 = 记账 + 待交付，待交付清零。
pub fn event(l: &mut Ledger, now: u64) -> (r: Option<(u64, u64)>)
    requires wf(old(l).clock),
    ensures
        wf(final(l).clock),
        r.is_none() ==> *final(l) == *old(l),
        r.is_some() ==> final(l).clock.at == now && final(l).clock.period == old(l).clock.period && final(l).idle_pending == 0
            && r.unwrap().1 as int == r.unwrap().0 as int + old(l).idle_pending as int
            && r.unwrap().0 as int * final(l).clock.period as int + final(l).clock.remainder as int
                == (now - old(l).clock.at) as int + old(l).clock.remainder as int,
{
    match advance(l.clock.at, l.clock.period, l.clock.remainder, now) {
        None => None,
        Some((ticks, rem)) => {
            if ticks > u64::MAX - l.idle_pending {
                return None;
            }
            let delivered = ticks + l.idle_pending;
            l.clock = Credit { at: now, period: l.clock.period, remainder: rem };
            l.idle_pending = 0;
            Some((ticks, delivered))
        }
    }
}

/// 调度器的用法：空闲在 s 结束、任务切入，之后在 t 到来一次高精度事件。
/// 切入的任务只被记 s 之后的 tick：charge × 周期 < (t − s) + 周期；空闲段 + 任务段交付合计守恒。
pub fn switch_in_then_event(l: &mut Ledger, s: u64, t: u64) -> (r: Option<(u64, u64, u64)>)
    requires wf(old(l).clock), old(l).idle_pending == 0, old(l).clock.at <= s, s <= t,
    ensures
        r.is_some() ==> (r.unwrap().1 as int) * (old(l).clock.period as int)
            < (t - s) as int + old(l).clock.period as int,
        r.is_some() ==> r.unwrap().2 == r.unwrap().0 + r.unwrap().1,
{
    let idle = 0u64;
    let ghost a1: int = l.clock.at as int;
    let ghost r1: int = l.clock.remainder as int;
    let ghost p1: int = l.clock.period as int;
    match event(l, t) {
        Some((charge, delivered)) => {
            proof {
                let pi = old(l).clock.period as int;
                assert(charge as int * pi <= (t - s) as int + pi - 1) by (nonlinear_arith)
                    requires charge as int * p1 + l.clock.remainder as int == (t as int - a1) + r1,
                        p1 == pi, a1 == s as int, r1 < pi, l.clock.remainder >= 0;
            }
            Some((idle, charge, delivered))
        }
        None => None,
    }
}

fn main() {}

} // verus!
