//! 统一定时事件契约（issue #3 第一切片）。
//! Unified timer-event contract (issue #3, first slice).
//!
//! 本模块只描述「对外语义」与「每核仲裁」，不规定后端算法：精确期限继续用
//! `deadline` 的索引堆，将来高数量、允许容差的普通超时可另接时间轮，路由由
//! 内核策略决定，不暴露给应用。所有时刻都是单调时钟纳秒。
//! This module fixes the external semantics and per-CPU arbitration only; the
//! backend (indexed heap today, possibly a hierarchical wheel later) is a
//! kernel routing policy that applications never see. All instants are
//! monotonic-clock nanoseconds.
//!
//! 三个部件 / three parts:
//! - [`Arbiter`]：每核把各类事件的「最晚必须处理时刻」取最小值，得到唯一的
//!   一次性硬件定时器编程时刻；精确请求不会因别人的容差而推迟。
//!   Per-CPU minimum of every source's latest acceptable instant; one one-shot
//!   hardware timer serves them all and slack never delays a precise request.
//! - [`TimerTable`]：`TimerId = (slot, generation)` 身份、一次/周期、取消、
//!   到期至多交付一次；关闭后旧身份永远失效（代数用尽的槽位永久退役，无 ABA）。
//!   Identity, one-shot/periodic arming, cancel and at-most-once expiry; a
//!   closed identity never matches again (an exhausted slot retires forever).
//! - [`OwnerBudget`]：按所有者计数的容量预算；任务定时器与通用定时器各用
//!   独立的预算实例，互不挤占。
//!   Per-owner capacity budget; task timers and general timers use separate
//!   instances so neither class can exhaust the other.
//!
//! 调用方负责串行化（每张表一把锁）；本模块不分配内存。
//! Callers serialize access (one lock per table); nothing here allocates.

/// 请求的时间容差。 / Timing tolerance of a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Urgency {
    /// 必须在 `at` 之后尽快处理，不得为合并而推迟。
    /// Handle as soon as possible after `at`; never deferred for coalescing.
    Precise,
    /// 可在 `[at, at + slack_ns]` 内任意时刻处理，便于与其他事件合并。
    /// May be handled anywhere in `[at, at + slack_ns]` so it can coalesce.
    Tolerant { slack_ns: u64 },
}

impl Urgency {
    /// 最晚必须处理时刻；加法溢出时饱和到 `u64::MAX`（单调时钟不可能到达）。
    /// Latest instant the event may be handled; saturates at `u64::MAX`.
    pub const fn latest(self, at: u64) -> u64 {
        match self {
            Urgency::Precise => at,
            Urgency::Tolerant { slack_ns } => at.saturating_add(slack_ns),
        }
    }
}

/// 一个定时请求的完整语义。 / Full semantics of one timer request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    /// 绝对到期时刻（相对期限由 [`Request::relative`] 换算）。
    /// Absolute expiry instant (relative deadlines go through [`Request::relative`]).
    pub at: u64,
    pub urgency: Urgency,
    /// 0 表示一次性；否则为周期纳秒，按相位对齐重新装填，错过的周期不累积。
    /// 0 means one-shot; otherwise the period, re-armed phase-aligned with
    /// missed periods skipped rather than accumulated.
    pub period_ns: u64,
}

impl Request {
    /// 相对期限：`now + after_ns`；溢出返回 `None`（拒绝而不是饱和成永不到期）。
    /// Relative deadline `now + after_ns`; overflow is rejected, not saturated.
    pub fn relative(now: u64, after_ns: u64, urgency: Urgency, period_ns: u64) -> Option<Self> {
        Some(Self { at: now.checked_add(after_ns)?, urgency, period_ns })
    }
    pub const fn latest(&self) -> u64 {
        self.urgency.latest(self.at)
    }
}

/// 严格晚于 `now` 的第一个周期边界，保持 `previous` 的相位；周期为 0 或不可表示时为 `None`。
/// First boundary strictly after `now` that keeps the phase of `previous`;
/// `None` for a zero period or an unrepresentable boundary.
pub fn next_boundary(now: u64, previous: u64, period: u64) -> Option<u64> {
    if period == 0 {
        return None;
    }
    if previous > now {
        return Some(previous);
    }
    let steps = (now as u128 - previous as u128) / period as u128 + 1;
    u64::try_from(previous as u128 + steps * period as u128).ok()
}

/// 每核仲裁器：逐个提交事件源，取最早的「最晚必须处理时刻」。
/// Per-CPU arbiter: offer every source, keep the earliest latest-instant.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Arbiter {
    earliest: Option<u64>,
}

impl Arbiter {
    pub const fn new() -> Self {
        Self { earliest: None }
    }
    /// 提交一个事件源。 / Offer one event source.
    pub fn offer(&mut self, at: u64, urgency: Urgency) {
        let latest = urgency.latest(at);
        self.earliest = Some(match self.earliest {
            Some(old) if old <= latest => old,
            _ => latest,
        });
    }
    /// 提交一个可能不存在的事件源。 / Offer an optional source.
    pub fn offer_opt(&mut self, at: Option<u64>, urgency: Urgency) {
        if let Some(at) = at {
            self.offer(at, urgency);
        }
    }
    /// 硬件定时器应编程的时刻；`None` 表示可以取消本核定时器。
    /// Instant to program the hardware timer at; `None` means cancel it.
    pub const fn program_at(&self) -> Option<u64> {
        self.earliest
    }
}

/// 已编程时刻与新时刻相同且仍在未来时无需重新编程。
/// Reprogramming is unnecessary when the target is unchanged and still future.
pub fn needs_reprogram(programmed: Option<u64>, at: Option<u64>, now: u64) -> bool {
    !(at == programmed && at.is_none_or(|at| at > now))
}

/// 一次性硬件定时器的装填延迟：至少 1 ns（已过期也要立即触发），至多 `max_ns`
/// （更远的期限由中间唤醒重新仲裁）。`max_ns` 为 0 时按 1 处理。
/// One-shot arm delay: at least 1 ns (already-due events still fire), at most
/// `max_ns` (farther deadlines are re-arbitrated on an intermediate wake).
pub fn arm_delay(at: u64, now: u64, max_ns: u64) -> u64 {
    at.saturating_sub(now).clamp(1, max_ns.max(1))
}

/// 定时器身份。 / Timer identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimerId {
    pub slot: u32,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// 没有空闲槽位。 / No free slot.
    Full,
    /// 所有者预算已满。 / Owner budget exhausted.
    Quota,
    /// 身份不存在、已关闭或代数不符。 / Unknown, closed or wrong-generation identity.
    Stale,
    /// 调用者不是所有者。 / Caller is not the owner.
    NotOwner,
    /// 周期装填溢出单调时钟。 / Periodic re-arm overflowed the clock.
    Overflow,
}

/// 取消结果：要么撤下了一个已装填请求，要么本来就未装填（可能已交付）。
/// Cancel outcome: either an armed request was withdrawn or nothing was armed
/// (possibly because it was already delivered).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cancelled {
    Disarmed(Request),
    NotArmed,
}

/// 一次到期交付。 / One expiry delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fired {
    pub owner: u32,
    /// 本次到期的请求时刻。 / The instant that expired.
    pub at: u64,
    /// 周期请求的下一次时刻（已重新装填）；一次性为 `None`。
    /// Next instant for a periodic request (already re-armed); `None` if one-shot.
    pub next: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Free,
    Idle,
    Armed(Request),
    /// 代数用尽，永久退役。 / Generation space exhausted; retired forever.
    Retired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Entry {
    generation: u64,
    owner: u32,
    state: State,
}

/// 按所有者计数的容量预算。 / Per-owner capacity budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnerBudget {
    used: u32,
    limit: u32,
}

impl OwnerBudget {
    pub const fn new(limit: u32) -> Self {
        Self { used: 0, limit }
    }
    pub const fn used(&self) -> u32 {
        self.used
    }
    pub const fn limit(&self) -> u32 {
        self.limit
    }
    fn charge(&mut self) -> Result<(), Error> {
        if self.used >= self.limit {
            return Err(Error::Quota);
        }
        self.used += 1;
        Ok(())
    }
    fn release(&mut self) {
        // 只由 close 调用，每个 create 恰好一次。 / Called once per create, from close.
        debug_assert!(self.used > 0);
        self.used = self.used.saturating_sub(1);
    }
}

/// 有界定时器身份表。 / Bounded timer identity table.
#[derive(Clone, Debug)]
pub struct TimerTable<const N: usize> {
    entries: [Entry; N],
    /// 空闲槽位栈（下标），`free_len` 之前有效。 / Free-slot stack.
    free: [u32; N],
    free_len: usize,
    armed: usize,
}

impl<const N: usize> Default for TimerTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> TimerTable<N> {
    pub const fn new() -> Self {
        assert!(N <= u32::MAX as usize);
        let mut free = [0u32; N];
        let mut i = 0;
        while i < N {
            // 倒序入栈，使最先分配 0 号槽位。 / Pushed in reverse so slot 0 is allocated first.
            free[i] = (N - 1 - i) as u32;
            i += 1;
        }
        Self {
            entries: [Entry { generation: 0, owner: 0, state: State::Free }; N],
            free,
            free_len: N,
            armed: 0,
        }
    }

    /// 存活（已创建未关闭）的定时器数。 / Number of live timers.
    pub fn live(&self) -> usize {
        self.entries.iter().filter(|e| matches!(e.state, State::Idle | State::Armed(_))).count()
    }
    /// 已装填数（O(1) 计数）。 / Number of armed timers (O(1) counter).
    pub const fn armed(&self) -> usize {
        self.armed
    }

    /// 创建一个未装填的定时器；新身份的代数严格大于该槽位以往所有代数。
    /// Create an unarmed timer; its generation exceeds every earlier one of the slot.
    pub fn create(&mut self, owner: u32, budget: &mut OwnerBudget) -> Result<TimerId, Error> {
        if self.free_len == 0 {
            return Err(Error::Full);
        }
        budget.charge()?;
        self.free_len -= 1;
        let slot = self.free[self.free_len];
        let e = &mut self.entries[slot as usize];
        // 进入空闲栈的槽位在关闭时已检查过代数仍可递增。
        // Slots on the free stack were checked at close to have a successor generation.
        e.generation += 1;
        e.owner = owner;
        e.state = State::Idle;
        Ok(TimerId { slot, generation: e.generation })
    }

    fn live_entry(&mut self, id: TimerId, owner: u32) -> Result<&mut Entry, Error> {
        let e = self.entries.get_mut(id.slot as usize).ok_or(Error::Stale)?;
        if e.generation != id.generation || !matches!(e.state, State::Idle | State::Armed(_)) {
            return Err(Error::Stale);
        }
        if e.owner != owner {
            return Err(Error::NotOwner);
        }
        Ok(e)
    }

    /// 装填或改装；返回被替换的旧请求。 / Arm or re-arm; returns the replaced request.
    pub fn arm(&mut self, id: TimerId, owner: u32, request: Request) -> Result<Option<Request>, Error> {
        let e = self.live_entry(id, owner)?;
        let old = match e.state {
            State::Armed(r) => Some(r),
            _ => None,
        };
        e.state = State::Armed(request);
        if old.is_none() {
            self.armed += 1;
        }
        Ok(old)
    }

    /// 取消；与到期竞争时二者恰有一方生效（调用方串行化）。
    /// Cancel; racing with expiry, exactly one side takes effect (callers serialize).
    pub fn cancel(&mut self, id: TimerId, owner: u32) -> Result<Cancelled, Error> {
        let e = self.live_entry(id, owner)?;
        match e.state {
            State::Armed(r) => {
                e.state = State::Idle;
                self.armed -= 1;
                Ok(Cancelled::Disarmed(r))
            }
            _ => Ok(Cancelled::NotArmed),
        }
    }

    /// 关闭并释放身份；已装填的请求一并撤下并返回，供后端删除节点。
    /// Close and free the identity; an armed request is withdrawn and returned
    /// so the backend can drop its node.
    pub fn close(&mut self, id: TimerId, owner: u32, budget: &mut OwnerBudget) -> Result<Option<Request>, Error> {
        let e = self.live_entry(id, owner)?;
        let old = match e.state {
            State::Armed(r) => Some(r),
            _ => None,
        };
        let retire = e.generation == u64::MAX;
        e.state = if retire { State::Retired } else { State::Free };
        if old.is_some() {
            self.armed -= 1;
        }
        budget.release();
        if !retire {
            self.free[self.free_len] = id.slot;
            self.free_len += 1;
        }
        Ok(old)
    }

    /// 后端发现 `(slot, generation)` 到期时调用：仅当身份仍有效、已装填且
    /// `at <= now` 时交付一次；周期请求按相位重新装填。陈旧或未到期返回 `Ok(None)`。
    /// Called by the backend for `(slot, generation)`: delivers once only if the
    /// identity is live, armed and due; periodic requests re-arm phase-aligned.
    /// Stale or not-yet-due identities return `Ok(None)`.
    pub fn expire(&mut self, id: TimerId, now: u64) -> Result<Option<Fired>, Error> {
        let Some(e) = self.entries.get_mut(id.slot as usize) else { return Ok(None) };
        if e.generation != id.generation {
            return Ok(None);
        }
        let State::Armed(r) = e.state else { return Ok(None) };
        if r.at > now {
            return Ok(None);
        }
        if r.period_ns == 0 {
            e.state = State::Idle;
            self.armed -= 1;
            return Ok(Some(Fired { owner: e.owner, at: r.at, next: None }));
        }
        let next = next_boundary(now, r.at, r.period_ns).ok_or(Error::Overflow)?;
        e.state = State::Armed(Request { at: next, ..r });
        Ok(Some(Fired { owner: e.owner, at: r.at, next: Some(next) }))
    }

    /// 查询已装填请求（只读）。 / Read the armed request, if any.
    pub fn armed_request(&self, id: TimerId) -> Option<Request> {
        let e = self.entries.get(id.slot as usize)?;
        match e.state {
            State::Armed(r) if e.generation == id.generation => Some(r),
            _ => None,
        }
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    fn any_urgency() -> Urgency {
        if kani::any() { Urgency::Precise } else { Urgency::Tolerant { slack_ns: kani::any() } }
    }

    #[kani::proof]
    fn arbiter_never_later_than_any_latest_instant() {
        let (a, b, c): (u64, u64, u64) = (kani::any(), kani::any(), kani::any());
        let (ua, ub) = (any_urgency(), any_urgency());
        let mut arb = Arbiter::new();
        arb.offer(a, ua);
        arb.offer(b, ub);
        arb.offer(c, Urgency::Precise);
        let at = arb.program_at().unwrap();
        assert!(at <= ua.latest(a) && at <= ub.latest(b) && at <= c);
        assert!(at == ua.latest(a) || at == ub.latest(b) || at == c);
    }

    #[kani::proof]
    #[kani::unwind(4)]
    fn closed_identity_never_touches_successor() {
        let mut t = TimerTable::<2>::new();
        let mut budget = OwnerBudget::new(2);
        let owner: u32 = kani::any();
        let old = t.create(owner, &mut budget).unwrap();
        let req = Request { at: kani::any(), urgency: Urgency::Precise, period_ns: 0 };
        t.arm(old, owner, req).unwrap();
        t.close(old, owner, &mut budget).unwrap();
        let new = t.create(owner, &mut budget).unwrap();
        assert!(new.slot == old.slot && new.generation > old.generation);
        t.arm(new, owner, req).unwrap();
        assert_eq!(t.arm(old, owner, req), Err(Error::Stale));
        assert_eq!(t.cancel(old, owner), Err(Error::Stale));
        assert_eq!(t.expire(old, u64::MAX), Ok(None));
        assert_eq!(t.armed_request(new), Some(req));
        assert_eq!(budget.used(), 1);
    }

    #[kani::proof]
    fn one_shot_expiry_is_delivered_at_most_once() {
        let mut t = TimerTable::<1>::new();
        let mut budget = OwnerBudget::new(1);
        let id = t.create(7, &mut budget).unwrap();
        let at: u64 = kani::any();
        let now: u64 = kani::any();
        t.arm(id, 7, Request { at, urgency: any_urgency(), period_ns: 0 }).unwrap();
        let first = t.expire(id, now).unwrap();
        assert_eq!(first.is_some(), at <= now);
        assert_eq!(t.expire(id, u64::MAX), if first.is_some() { Ok(None) } else { Ok(Some(Fired { owner: 7, at, next: None })) });
        assert_eq!(t.expire(id, u64::MAX), Ok(None));
        assert_eq!(t.armed(), 0);
    }

    #[kani::proof]
    #[kani::solver(cadical)]
    fn next_boundary_is_first_future_phase_point() {
        // 有界：previous、now 与 previous 的差、周期均取 8 位值（宽域 128 位除法求解
        // 不收敛；全域由 Verus 整数模型与 Proptest 覆盖）。
        // Bounded to 8-bit previous, gap and period; the full domain is covered
        // by the Verus integer model and Proptest.
        let previous = u64::from(kani::any::<u8>());
        let gap = u64::from(kani::any::<u8>());
        let now = if kani::any() { previous + gap } else { previous.saturating_sub(gap) };
        let period = u64::from(kani::any::<u8>());
        kani::assume(period > 0);
        if let Some(next) = next_boundary(now, previous, period) {
            assert!(next > now);
            if previous <= now {
                assert_eq!((next - previous) % period, 0);
                assert!(next - period <= now);
            } else {
                assert_eq!(next, previous);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arbitration_respects_precise_and_slack() {
        let mut arb = Arbiter::new();
        assert_eq!(arb.program_at(), None);
        arb.offer(100, Urgency::Tolerant { slack_ns: 50 });
        assert_eq!(arb.program_at(), Some(150));
        arb.offer(120, Urgency::Precise);
        assert_eq!(arb.program_at(), Some(120));
        arb.offer(u64::MAX - 1, Urgency::Tolerant { slack_ns: 9 });
        arb.offer_opt(None, Urgency::Precise);
        assert_eq!(arb.program_at(), Some(120));
        assert!(!needs_reprogram(Some(120), Some(120), 119));
        assert!(needs_reprogram(Some(120), Some(120), 120));
        assert!(needs_reprogram(Some(120), None, 0));
        assert!(!needs_reprogram(None, None, 0));
        assert_eq!(arm_delay(10, 20, 100), 1);
        assert_eq!(arm_delay(1_000, 0, 100), 100);
        assert_eq!(arm_delay(5, 0, 0), 1);
        assert_eq!(Request::relative(u64::MAX, 1, Urgency::Precise, 0), None);
    }

    #[test]
    fn lifecycle_budget_and_periodic_rearm() {
        let mut t = TimerTable::<2>::new();
        let mut task = OwnerBudget::new(1);
        let mut general = OwnerBudget::new(2);
        let a = t.create(1, &mut task).unwrap();
        assert_eq!(t.create(1, &mut task), Err(Error::Quota));
        let b = t.create(1, &mut general).unwrap();
        assert_eq!(t.create(2, &mut general), Err(Error::Full));
        assert_eq!(t.arm(a, 2, Request { at: 5, urgency: Urgency::Precise, period_ns: 0 }), Err(Error::NotOwner));
        let periodic = Request { at: 10, urgency: Urgency::Tolerant { slack_ns: 3 }, period_ns: 4 };
        assert_eq!(t.arm(b, 1, periodic), Ok(None));
        assert_eq!(t.expire(b, 9), Ok(None));
        assert_eq!(t.expire(b, 19), Ok(Some(Fired { owner: 1, at: 10, next: Some(22) })));
        assert_eq!(t.armed_request(b).map(|r| r.at), Some(22));
        assert_eq!(t.cancel(b, 1), Ok(Cancelled::Disarmed(Request { at: 22, ..periodic })));
        assert_eq!(t.cancel(b, 1), Ok(Cancelled::NotArmed));
        assert_eq!(t.close(b, 1, &mut general), Ok(None));
        assert_eq!(t.close(b, 1, &mut general), Err(Error::Stale));
        assert_eq!((t.live(), t.armed(), general.used()), (1, 0, 0));
        let c = t.create(3, &mut general).unwrap();
        assert_eq!((c.slot, c.generation), (b.slot, b.generation + 1));
    }

    #[test]
    fn exhausted_generation_retires_slot() {
        let mut t = TimerTable::<1>::new();
        let mut budget = OwnerBudget::new(1);
        t.entries[0].generation = u64::MAX - 1;
        let id = t.create(0, &mut budget).unwrap();
        assert_eq!(id.generation, u64::MAX);
        t.close(id, 0, &mut budget).unwrap();
        assert_eq!(t.create(0, &mut budget), Err(Error::Full));
        assert_eq!(t.expire(id, u64::MAX), Ok(None));
    }

    #[test]
    fn periodic_overflow_is_reported() {
        let mut t = TimerTable::<1>::new();
        let mut budget = OwnerBudget::new(1);
        let id = t.create(0, &mut budget).unwrap();
        t.arm(id, 0, Request { at: u64::MAX - 1, urgency: Urgency::Precise, period_ns: 2 }).unwrap();
        assert_eq!(t.expire(id, u64::MAX), Err(Error::Overflow));
        assert!(t.armed_request(id).is_some());
    }
}
