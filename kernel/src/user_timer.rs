//! User-visible timer objects (`system.time.timer.*`).
//!
//! A timer is a non-transferable handle owned by its creating process.  It
//! stores one Timed [`Request`] and at most one blocked waiter.  The waiter uses
//! the scheduler's existing absolute-nanosecond wait path, so expiry performs a
//! real hardware wake rather than a polling loop.  Object identity and
//! generation are independent from scheduler task slots.

use alloc::boxed::Box;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::sync::IrqSpinLock;
use kernel_core::deadline::{Deadline, DeadlineHeap, ABSENT};
use kernel_core::event_wait::Key;
use kernel_core::object::{HandleId, ObjectType, Rights};
use kernel_core::objtable::ObjId;
use kernel_core::timer_event::{next_boundary, Request, TimerId, Urgency};

use crate::kobj::{self, KObject, Table};
use crate::proc;
use crate::sched::{self, WaitDeadline};
use crate::syscall::err;
use crate::syscall::table::{
    SYSTEM_ASYNC_ERROR_CANCELLED, SYSTEM_ERROR_INVALID_ARGUMENT, SYSTEM_ERROR_QUOTA_EXCEEDED,
    SYSTEM_TIME_ERROR_BUSY,
};

/// General timer objects are independent from the scheduler task-timer table.
pub const MAX_TIMER_OBJECTS: u32 = 256;
/// One-shot or fixed-period user timer.
pub struct TimerObj {
    owner: ObjId,
    id: TimerId,
    coalesce_slot: usize,
    period_ns: u64,
    slack_ns: u64,
    request: Option<Request>,
    waiter: Option<Key>,
    closed: bool,
}

impl TimerObj {
    /// Stable object-local timer identity used by diagnostics and future backends.
    pub const fn identity(&self) -> TimerId { self.id }
}

static LIVE_TIMERS: AtomicU64 = AtomicU64::new(0);
static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static COALESCE_EARLIEST: AtomicU64 = AtomicU64::new(u64::MAX);
static COALESCE_WAKES: AtomicU64 = AtomicU64::new(0);
static COALESCE_EARLY: AtomicU64 = AtomicU64::new(0);

const TIMER_RIGHTS: Rights = kernel_core::kobj_type::Kind::Timer.contract().rights;

#[derive(Clone, Copy)]
struct Registration {
    timer: TimerId,
    key: Key,
    latest: u64,
}

struct Coalescer {
    allocated: [bool; MAX_TIMER_OBJECTS as usize],
    registrations: [Option<Registration>; MAX_TIMER_OBJECTS as usize],
    heap: DeadlineHeap,
    entries: [Deadline; MAX_TIMER_OBJECTS as usize],
    positions: [usize; MAX_TIMER_OBJECTS as usize],
}

impl Coalescer {
    const fn new() -> Self {
        Self {
            allocated: [false; MAX_TIMER_OBJECTS as usize],
            registrations: [None; MAX_TIMER_OBJECTS as usize],
            heap: DeadlineHeap::new(),
            entries: [Deadline::EMPTY; MAX_TIMER_OBJECTS as usize],
            positions: [ABSENT; MAX_TIMER_OBJECTS as usize],
        }
    }

    fn allocate(&mut self) -> Option<usize> {
        self.allocated.iter().position(|used| !used)
    }

    fn reserve(&mut self, slot: usize) {
        self.allocated[slot] = true;
    }

    fn free(&mut self, slot: usize) {
        self.registrations[slot] = None;
        self.allocated[slot] = false;
    }

    fn register(&mut self, slot: usize, timer: TimerId, at: u64, latest: u64, key: Key) {
        self.registrations[slot] = Some(Registration { timer, key, latest });
        self.heap
            .set(
                &mut self.entries,
                &mut self.positions,
                Deadline {
                    at,
                    slot,
                    generation: timer.generation,
                },
            )
            .expect("coalescer slot is unique and preallocated");
    }

    fn unregister(&mut self, slot: usize, timer: TimerId) {
        if self
            .registrations
            .get(slot)
            .and_then(|r| *r)
            .is_some_and(|r| r.timer == timer)
        {
            let _ = self
                .heap
                .remove(&mut self.entries, &mut self.positions, slot, timer.generation);
            self.registrations[slot] = None;
        }
    }

    fn next(&self) -> u64 {
        self.heap.next_at(&self.entries).unwrap_or(u64::MAX)
    }
}

static COALESCER: IrqSpinLock<Coalescer> = IrqSpinLock::new(Coalescer::new());

fn timer_mut(t: &mut Table, id: ObjId) -> Option<&mut TimerObj> {
    match t.get_mut(id) {
        Ok(KObject::Timer(timer)) => Some(timer),
        _ => None,
    }
}

fn resolve(t: &mut Table, pid: ObjId, raw: u64, rights: Rights) -> Result<ObjId, i64> {
    let id = proc::resolve_in(t, pid, HandleId::from_raw(raw), ObjectType::Timer, rights)
        .map_err(crate::syscall::proc_err)?;
    let owner = match t.get(id) {
        Ok(KObject::Timer(timer)) => timer.owner,
        _ => return Err(err(SYSTEM_ERROR_INVALID_ARGUMENT)),
    };
    if owner != pid { return Err(err(SYSTEM_ERROR_INVALID_ARGUMENT)); }
    Ok(id)
}

fn arm_request(timer: &TimerObj, at: u64) -> Request {
    Request {
        at,
        urgency: if timer.slack_ns == 0 {
            Urgency::Precise
        } else {
            Urgency::Tolerant { slack_ns: timer.slack_ns }
        },
        period_ns: timer.period_ns,
    }
}

/// Create a timer. `period_ns=0` is one-shot; `slack_ns=0` is precise.
pub fn sys_create(period_ns: u64, slack_ns: u64, flags: u64) -> i64 {
    if flags != 0 { return err(SYSTEM_ERROR_INVALID_ARGUMENT); }
    let Some(pid) = proc::current_process() else { return err(SYSTEM_ERROR_INVALID_ARGUMENT) };
    let live = LIVE_TIMERS.try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
        (n < u64::from(MAX_TIMER_OBJECTS)).then_some(n + 1)
    });
    if live.is_err() { return err(SYSTEM_ERROR_QUOTA_EXCEEDED); }
    let Ok(serial) = NEXT_ID.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1)) else {
        LIVE_TIMERS.fetch_sub(1, Ordering::AcqRel);
        return err(SYSTEM_ERROR_QUOTA_EXCEEDED);
    };
    let coalesce_slot = {
        let mut coalescer = COALESCER.lock();
        let Some(slot) = coalescer.allocate() else {
            LIVE_TIMERS.fetch_sub(1, Ordering::AcqRel);
            return err(SYSTEM_ERROR_QUOTA_EXCEEDED);
        };
        coalescer.reserve(slot);
        slot
    };
    let object = TimerObj {
        owner: pid,
        id: TimerId { slot: serial as u32, generation: serial },
        coalesce_slot,
        period_ns,
        slack_ns,
        request: None,
        waiter: None,
        closed: false,
    };
    match proc::grant_new(pid, KObject::Timer(Box::new(object)), ObjectType::Timer, TIMER_RIGHTS) {
        Ok(handle) => handle.raw() as i64,
        Err(error) => {
            COALESCER.lock().free(coalesce_slot);
            LIVE_TIMERS.fetch_sub(1, Ordering::AcqRel);
            crate::syscall::proc_err(error)
        }
    }
}

/// Arm using an absolute timestamp (`flags & 1`) or relative nanoseconds.
pub fn sys_arm(raw: u64, when_ns: u64, flags: u64) -> i64 {
    if flags & !1 != 0 { return err(SYSTEM_ERROR_INVALID_ARGUMENT); }
    let Some(pid) = proc::current_process() else { return err(SYSTEM_ERROR_INVALID_ARGUMENT) };
    let wake = kobj::with(|t| {
        let id = resolve(t, pid, raw, Rights::WRITE)?;
        let timer = timer_mut(t, id).ok_or_else(|| err(SYSTEM_ERROR_INVALID_ARGUMENT))?;
        if timer.closed { return Err(err(SYSTEM_ASYNC_ERROR_CANCELLED)); }
        let at = if flags & 1 != 0 {
            when_ns
        } else {
            match sched::now_ns().checked_add(when_ns) {
                Some(at) => at,
                None => return Err(err(SYSTEM_ERROR_INVALID_ARGUMENT)),
            }
        };
        timer.request = Some(arm_request(timer, at));
        Ok((timer.id, timer.coalesce_slot, timer.waiter))
    });
    match wake {
        Ok((timer, slot, waiter)) => {
            COALESCER.lock().unregister(slot, timer);
            if let Some(key) = waiter { sched::wake_event_wait(key); }
            0
        }
        Err(error) => error,
    }
}

/// Cancel the current request. Returns 1 if one was armed, 0 if already idle.
pub fn sys_cancel(raw: u64) -> i64 {
    let Some(pid) = proc::current_process() else { return err(SYSTEM_ERROR_INVALID_ARGUMENT) };
    let cancelled = kobj::with(|t| {
        let id = resolve(t, pid, raw, Rights::WRITE)?;
        let timer = timer_mut(t, id).ok_or_else(|| err(SYSTEM_ERROR_INVALID_ARGUMENT))?;
        if timer.closed { return Err(err(SYSTEM_ASYNC_ERROR_CANCELLED)); }
        let armed = timer.request.take().is_some();
        Ok((timer.id, timer.coalesce_slot, timer.waiter, if armed { 1 } else { 0 }))
    });
    match cancelled {
        Ok((timer, slot, waiter, result)) => {
            COALESCER.lock().unregister(slot, timer);
            if let Some(key) = waiter { sched::wake_event_wait(key); }
            result
        }
        Err(error) => error,
    }
}

/// Return nanoseconds until the current request's latest acceptable instant.
pub fn sys_remaining(raw: u64) -> i64 {
    let Some(pid) = proc::current_process() else { return err(SYSTEM_ERROR_INVALID_ARGUMENT) };
    kobj::with(|t| {
        let id = resolve(t, pid, raw, Rights::READ)?;
        let timer = timer_mut(t, id).ok_or_else(|| err(SYSTEM_ERROR_INVALID_ARGUMENT))?;
        if timer.closed { return Err(err(SYSTEM_ASYNC_ERROR_CANCELLED)); }
        Ok(timer.request.map_or(0, |r| r.latest().saturating_sub(sched::now_ns())) as i64)
    }).unwrap_or_else(|e| e)
}

fn advance(timer: &mut TimerObj) -> Result<(), i64> {
    let now = sched::now_ns();
    let Some(request) = timer.request.take() else { return Err(err(SYSTEM_ASYNC_ERROR_CANCELLED)); };
    if request.period_ns == 0 { return Ok(()); }
    let Some(next) = next_boundary(now, request.at, request.period_ns) else {
        timer.request = Some(request);
        return Err(err(SYSTEM_ERROR_INVALID_ARGUMENT));
    };
    timer.request = Some(Request { at: next, ..request });
    Ok(())
}

/// Wait for the next expiry. One waiter per timer; close/cancel wake it.
pub fn sys_wait(raw: u64) -> i64 {
    let Some(pid) = proc::current_process() else { return err(SYSTEM_ERROR_INVALID_ARGUMENT) };
    loop {
        enum Step {
            Done,
            Closed,
            Park(ObjId, TimerId, usize, Key, u64, u64),
            Recheck,
            Busy,
            Error(i64),
        }
        let step = kobj::with(|t| {
            let id = match resolve(t, pid, raw, Rights::WAIT) {
                Ok(id) => id,
                Err(e) => return Step::Error(e),
            };
            let (timer_id, slot, at, latest) = {
                let timer = match timer_mut(t, id) {
                    Some(timer) => timer,
                    None => return Step::Error(err(SYSTEM_ERROR_INVALID_ARGUMENT)),
                };
                if timer.closed { return Step::Closed; }
                if timer.waiter.is_some() { return Step::Busy; }
                let Some(request) = timer.request else { return Step::Closed; };
                (timer.id, timer.coalesce_slot, request.at, request.latest())
            };
            // `at` is the first acceptable delivery instant; `latest` only
            // selects the hardware fallback deadline and permits earlier
            // coalescing with another timer interrupt.
            if sched::now_ns() >= at {
                let timer = timer_mut(t, id).expect("retained live timer");
                return match advance(timer) {
                    Ok(()) => Step::Done,
                    Err(e) => Step::Error(e),
                };
            }
            if t.acquire_internal(id).is_err() { return Step::Error(err(SYSTEM_ERROR_QUOTA_EXCEEDED)); }
            match sched::enroll_event_wait(Some(WaitDeadline::Nanos(latest)), None) {
                Ok(Some(key)) => {
                    timer_mut(t, id).expect("retained live timer").waiter = Some(key);
                    Step::Park(id, timer_id, slot, key, at, latest)
                }
                Ok(None) => {
                    let _ = t.release_internal(id);
                    Step::Recheck
                }
                Err(()) => {
                    let _ = t.release_internal(id);
                    Step::Error(err(SYSTEM_ERROR_INVALID_ARGUMENT))
                }
            }
        });
        match step {
            Step::Done => return 0,
            Step::Recheck => continue,
            Step::Closed => return err(SYSTEM_ASYNC_ERROR_CANCELLED),
            Step::Busy => return err(SYSTEM_TIME_ERROR_BUSY),
            Step::Error(e) => return e,
            Step::Park(id, timer, slot, key, at, latest) => {
                COALESCER.lock().register(slot, timer, at, latest, key);
                COALESCE_EARLIEST.fetch_min(at, Ordering::Release);
                sched::yield_now();
                let closed = kobj::with(|t| {
                    if let Some(timer) = timer_mut(t, id) {
                        if timer.waiter == Some(key) { timer.waiter = None; }
                        let closed = timer.closed;
                        let _ = t.release_internal(id);
                        closed
                    } else {
                        let _ = t.release_internal(id);
                        false
                    }
                });
                if closed { return err(SYSTEM_ASYNC_ERROR_CANCELLED); }
            }
        }
    }
}

/// Closing hook: terminalize the timer and release the sole waiter.
pub fn close_in(t: &mut Table, id: ObjId) {
    let Some(timer) = timer_mut(t, id) else { return; };
    timer.closed = true;
    timer.request = None;
    {
        let mut coalescer = COALESCER.lock();
        coalescer.unregister(timer.coalesce_slot, timer.id);
        coalescer.free(timer.coalesce_slot);
    }
    if let Some(key) = timer.waiter.take() { sched::wake_event_wait(key); }
    LIVE_TIMERS.fetch_sub(1, Ordering::AcqRel);
}

/// Wake timers whose acceptable window started before `now`. This is called
/// from a real timer interrupt; the deadline heap makes the common path an
/// atomic load and only touches the scheduler when a timer is genuinely due.
pub fn wake_due(now: u64) {
    if COALESCE_EARLIEST.load(Ordering::Acquire) > now {
        return;
    }
    loop {
        let next = {
            let mut coalescer = COALESCER.lock();
            let Coalescer { heap, entries, positions, .. } = &mut *coalescer;
            let Some(deadline) = heap.pop_due(entries, positions, now) else {
                COALESCE_EARLIEST.store(u64::MAX, Ordering::Release);
                break;
            };
            let Some(registration) = coalescer.registrations[deadline.slot] else {
                COALESCE_EARLIEST.store(coalescer.next(), Ordering::Release);
                continue;
            };
            if registration.timer.generation != deadline.generation {
                COALESCE_EARLIEST.store(coalescer.next(), Ordering::Release);
                continue;
            }
            coalescer.registrations[deadline.slot] = None;
            COALESCE_EARLIEST.store(coalescer.next(), Ordering::Release);
            registration
        };
        if sched::wake_event_wait(next.key) {
            COALESCE_WAKES.fetch_add(1, Ordering::Relaxed);
            if now < next.latest {
                COALESCE_EARLY.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Diagnostic live timer-object count.
pub fn live() -> u64 { LIVE_TIMERS.load(Ordering::Acquire) }

/// `(object timer wakes, wakes inside a tolerance window before its latest instant)`
pub fn coalesce_stats() -> (u64, u64) {
    (
        COALESCE_WAKES.load(Ordering::Acquire),
        COALESCE_EARLY.load(Ordering::Acquire),
    )
}
