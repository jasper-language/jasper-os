// 伴随模型：kernel_core::timer_progress::Progress 的判定与记录。与生产代码同样的条件分支；
// 生产函数与模型的一致性由 Proptest / fuzz 差分保证。
// Companion model; production/model agreement is covered by the differential Proptest and fuzz targets.
use vstd::prelude::*;

verus! {

pub struct Progress { pub last_exit: u64, pub cost: u64, pub deferred: u32, pub short: u32 }

pub const MAX_SETTLE: u32 = 64;
pub const GRACE: u32 = 2;

impl Progress {
    fn remaining(&self, now: u64) -> (r: u64)
        ensures
            now < self.last_exit ==> r == 0,
            now >= self.last_exit ==> r as int == if now - self.last_exit >= self.cost { 0int } else { self.cost - (now - self.last_exit) },
            r <= self.cost,
    {
        if now < self.last_exit {
            return 0;
        }
        let window = now - self.last_exit;
        if window >= self.cost { 0 } else { self.cost - window }
    }

    /// 放行 ⇔ 还在宽限内，或时钟倒退，或距上次结束已过去至少 cost。
    fn admit(&self, now: u64) -> (r: bool)
        ensures r <==> admits(*self, now),
    {
        self.short < GRACE || self.remaining(now) == 0
    }

    fn record(&mut self, entry: u64, exit: u64, cap: u64)
        ensures
            final(self).last_exit == exit,
            final(self).deferred == old(self).deferred,
            final(self).cost <= cap,
            exit >= entry ==> final(self).cost as int == if exit - entry > cap { cap as int } else { exit - entry },
            exit < entry ==> final(self).cost == 0,
            long_window(*old(self), entry) ==> final(self).short == 0,
            !long_window(*old(self), entry) && old(self).short < GRACE ==> final(self).short == old(self).short + 1,
    {
        self.short = if self.remaining(entry) != 0 && self.short < GRACE { self.short + 1 } else { 0 };
        let cost = if exit >= entry { exit - entry } else { 0 };
        self.cost = if cost > cap { cap } else { cost };
        self.last_exit = exit;
    }

    fn defer(&mut self)
        ensures
            final(self).deferred as int == if old(self).deferred == u32::MAX { u32::MAX as int } else { old(self).deferred + 1 },
            final(self).last_exit == old(self).last_exit,
            final(self).cost == old(self).cost,
    {
        if self.deferred < u32::MAX {
            self.deferred = self.deferred + 1;
        }
    }

    fn take_deferred(&mut self) -> (n: u32)
        ensures
            n <= MAX_SETTLE,
            old(self).deferred <= MAX_SETTLE ==> n == old(self).deferred,
            old(self).deferred > MAX_SETTLE ==> n == MAX_SETTLE,
            final(self).deferred == 0,
            final(self).last_exit == old(self).last_exit,
            final(self).cost == old(self).cost,
    {
        let n = if self.deferred > MAX_SETTLE { MAX_SETTLE } else { self.deferred };
        self.deferred = 0;
        n
    }
}

pub open spec fn long_window(p: Progress, now: u64) -> bool {
    now < p.last_exit || now - p.last_exit >= p.cost
}

pub open spec fn admits(p: Progress, now: u64) -> bool {
    p.short < GRACE || long_window(p, now)
}

/// 连续短窗口不超过宽限：放行后的记录保持 short ≤ GRACE。
fn short_stays_within_grace(p: &mut Progress, entry: u64, exit: u64, cap: u64)
    requires old(p).short <= GRACE, admits(*old(p), entry),
    ensures final(p).short <= GRACE,
{
    p.record(entry, exit, cap);
}

/// 前进保证：宽限用尽之后，下一次完整事务之前必定留出 min(开销, cap)。
fn window_after_grace(p: &mut Progress, entry: u64, exit: u64, cap: u64, next: u64)
    requires
        entry <= exit, exit <= next,
        old(p).short == GRACE - 1,
        !long_window(*old(p), entry),
    ensures
        admits(*final(p), next) ==> next - exit >= if exit - entry > cap { cap as int } else { exit - entry },
{
    p.record(entry, exit, cap);
}

/// 不会停摆：时钟单调时，最多等 cap 就会放行；等够 remaining 之后一定放行。
fn admitted_after_remaining(p: &Progress, now: u64, cap: u64) -> (later: u64)
    requires
        p.cost <= cap,
        now >= p.last_exit,
        now as int + cap as int <= u64::MAX,
    ensures
        admits(*p, later),
        later as int <= now as int + cap as int,
        later >= now,
{
    now + p.remaining(now)
}

fn main() {}

} // verus!
