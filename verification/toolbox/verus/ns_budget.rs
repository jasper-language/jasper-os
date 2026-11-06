// kernel_core::ns_budget 的 Verus 伴随模型：结构与源码逐行对应，字段展开成参数。
// 性质：周期边界前进后 next 严格大于 end 且不超过 end + period；相位不变；剩余预算不超过配额；
// 同一周期内只减不增，且减少量恰好是运行区间；错误路径不改状态（模型返回 None）。
// Companion model of kernel_core::ns_budget; consistency with the source is checked differentially.
use vstd::prelude::*;

verus! {

pub struct Budget { pub quota: u64, pub period: u64, pub remaining: u64, pub next: u64 }

pub open spec fn well_formed(b: Budget) -> bool {
    0 < b.quota <= b.period && b.remaining <= b.quota
}

pub open spec fn sat_sub(a: int, b: int) -> int { if a >= b { a - b } else { 0 } }

pub open spec fn max(a: int, b: int) -> int { if a >= b { a } else { b } }

fn new(now: u64, quota: u64, period: u64) -> (r: Option<Budget>)
    ensures
        r.is_some() <==> (0 < quota <= period && now + period <= u64::MAX),
        r matches Some(b) ==> well_formed(b) && b.remaining == quota && b.next == now + period,
{
    if quota == 0 || period == 0 || quota > period {
        return None;
    }
    match now.checked_add(period) {
        Some(next) => Some(Budget { quota, period, remaining: quota, next }),
        None => None,
    }
}

/// 源码 `Budget::running_settle_at` 的启用分支。配额未耗尽时，检查点不晚于配额耗尽点
/// 和周期边界；剩余为零时只等周期边界。
fn running_settle_at(b: Budget, start: u64) -> (r: u64)
    requires well_formed(b),
    ensures
        r <= b.next,
        b.remaining > 0 ==> r <= start + b.remaining,
        b.remaining == 0 ==> r == b.next,
{
    if b.remaining == 0 {
        b.next
    } else {
        let quota_due = if b.remaining > u64::MAX - start { u64::MAX } else { start + b.remaining };
        if b.next < quota_due { b.next } else { quota_due }
    }
}

/// 源码 `Budget::settle`，只保留启用状态、时间不倒退之后的分支。
fn settle(b: Budget, start: u64, end: u64, running: bool) -> (r: Option<Budget>)
    requires well_formed(b), start <= end,
    ensures
        r matches Some(n) ==> {
            &&& well_formed(n)
            &&& n.quota == b.quota && n.period == b.period
            &&& n.next > end
            &&& end < b.next ==> {
                &&& n.next == b.next
                &&& n.remaining == (if running { sat_sub(b.remaining as int, end - start) } else { b.remaining as int })
            }
            &&& end >= b.next ==> {
                &&& n.next - n.period <= end
                &&& (n.next - b.next) % (b.period as int) == 0
                &&& n.remaining == (if running { sat_sub(b.quota as int, end - max(start as int, n.next - n.period)) } else { b.quota as int })
            }
        },
{
    if end >= b.next {
        let d = (end - b.next) / b.period;
        proof {
            assert(0 <= d <= end - b.next) by (nonlinear_arith)
                requires d == (end - b.next) as int / b.period as int, end >= b.next, b.period > 0;
        }
        let periods = match d.checked_add(1) { Some(v) => v, None => return None };
        let span = match periods.checked_mul(b.period) { Some(v) => v, None => return None };
        let next = match b.next.checked_add(span) { Some(v) => v, None => return None };
        proof {
            let (x, p, q) = ((end - b.next) as int, b.period as int, d as int);
            assert(x == q * p + x % p && 0 <= x % p < p) by (nonlinear_arith)
                requires p > 0, q == x / p, x >= 0;
            assert((q + 1) * p == q * p + p) by (nonlinear_arith);
            let sp = span as int;
            assert(sp == q * p + p);
            vstd::arithmetic::div_mod::lemma_mod_multiples_basic(q + 1, p);
            assert(sp % p == 0);
        }
        let prev = next - b.period;
        let begin = if start >= prev { start } else { prev };
        let remaining = if running {
            let used = end - begin;
            if b.quota >= used { b.quota - used } else { 0 }
        } else {
            b.quota
        };
        Some(Budget { quota: b.quota, period: b.period, remaining, next })
    } else {
        let remaining = if running {
            let used = end - start;
            if b.remaining >= used { b.remaining - used } else { 0 }
        } else {
            b.remaining
        };
        Some(Budget { quota: b.quota, period: b.period, remaining, next: b.next })
    }
}

/// 向上取整的千分比：配额不超过周期时不超过 1000，且不低估。
fn utilisation(quota: u64, period: u64) -> (r: Option<u128>)
    ensures
        r.is_some() <==> (0 < quota <= period),
        r matches Some(u) ==> u <= 1000 && u * period >= quota * 1000,
{
    if quota == 0 || period == 0 || quota > period {
        return None;
    }
    let (q, p) = (quota as u128, period as u128);
    proof {
        assert(q * 1000 <= p * 1000);
        assert(p * 1000 <= 1000 * 0x1_0000_0000_0000_0000) by (nonlinear_arith)
            requires p <= u64::MAX;
    }
    let scaled: u128 = q * 1000;
    let u = (scaled + p - 1) / p;
    proof {
        let (s, up, x) = (scaled as int, u as int, (scaled + p - 1) as int);
        assert(x == up * p + x % (p as int) && 0 <= x % (p as int) < p) by (nonlinear_arith)
            requires up == x / (p as int), p > 0, x >= 0;
        assert(up <= 1000) by (nonlinear_arith)
            requires x == s + p - 1, s <= p * 1000, up == x / (p as int), p > 0;
        assert(up * p >= s);
    }
    Some(u)
}

fn main() {}
}
