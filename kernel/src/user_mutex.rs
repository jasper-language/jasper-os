//! User-visible priority-inheriting mutex.
//!
//! The mutex stores only its current owner and terminal state. Wait edges,
//! transitive donation, cycle rejection and direct hand-off use the existing
//! scheduler turnstile graph, so this is not a second priority authority.

use alloc::boxed::Box;

use kernel_core::object::{HandleId, ObjectType, Rights};
use kernel_core::objtable::ObjId;
use kernel_core::inherited_mutex::{Claim, State};

use crate::kobj::{self, KObject};
use crate::proc;
use crate::sched;
use crate::syscall::table::{SYSTEM_ASYNC_ERROR_CANCELLED, SYSTEM_ERROR_INVALID_ARGUMENT,
    SYSTEM_ERROR_QUOTA_EXCEEDED, SYSTEM_ERROR_RIGHTS_DENIED, SYSTEM_HANDLE_ERROR_INVALID};
use crate::task::TaskId;

pub struct MutexObj {
    state: State<TaskId>,
}

impl MutexObj {
    pub const fn new() -> Self { Self { state: State::new() } }

    /// Stable because `KObject::Mutex` stores this value in a Box.
    fn wait_key(&self) -> u64 { self as *const Self as usize as u64 }
}

enum LockStep {
    Acquired,
    Blocked(ObjId),
    Closed,
    Error(i64),
}

const MUTEX_RIGHTS: Rights = Rights::WAIT
    .union(Rights::CONTROL)
    .union(Rights::DUPLICATE)
    .union(Rights::TRANSFER);

pub fn sys_create() -> i64 {
    let Some(pid) = proc::current_process() else { return crate::syscall::err(SYSTEM_ERROR_RIGHTS_DENIED) };
    match proc::grant_new(pid, KObject::Mutex(Box::new(MutexObj::new())), ObjectType::Mutex, MUTEX_RIGHTS) {
        Ok(h) => h.raw() as i64,
        Err(e) => crate::syscall::proc_err(e),
    }
}

#[cfg(feature = "rt3-verify")]
pub(crate) fn create_for(pid: ObjId) -> Result<HandleId, crate::proc::ProcError> {
    proc::grant_new(pid, KObject::Mutex(Box::new(MutexObj::new())), ObjectType::Mutex, MUTEX_RIGHTS)
}

/// Locks `handle`. A blocked invocation retains the object independently of
/// the process handle until it resumes and observes hand-off or closure.
pub fn sys_lock(raw: u64) -> i64 {
    let Some(pid) = proc::current_process() else { return crate::syscall::err(SYSTEM_ERROR_RIGHTS_DENIED) };
    let me = sched::current().0;
    let mut retained: Option<ObjId> = None;
    loop {
        let step = kobj::with(|t| {
            let id = match retained {
                Some(id) => id,
                None => match proc::resolve_in(t, pid, HandleId::from_raw(raw), ObjectType::Mutex, Rights::WAIT) {
                    Ok(id) => id,
                    Err(e) => return LockStep::Error(crate::syscall::proc_err(e)),
                },
            };

            let (owner, closed, key) = match t.get(id) {
                Ok(KObject::Mutex(m)) => (m.state.owner(), m.state.is_closed(), m.wait_key()),
                _ => return LockStep::Error(crate::syscall::err(SYSTEM_HANDLE_ERROR_INVALID)),
            };
            if closed { return LockStep::Closed; }
            // A previously-unowned mutex needs a new ownership reference.  It
            // must exist before `claim` publishes `owner = me`; otherwise a
            // quota failure would leave an owner without object liveness.
            let reserved_owner_ref = owner.is_none();
            if reserved_owner_ref && t.acquire_internal(id).is_err() {
                return LockStep::Error(crate::syscall::err(SYSTEM_ERROR_QUOTA_EXCEEDED));
            }
            let owner_live = owner.is_some_and(sched::task_is_live);
            let claim = match t.get_mut(id) { Ok(KObject::Mutex(m)) => m.state.claim(me, owner_live), _ => unreachable!() };
            match claim {
                Claim::Closed => {
                    if reserved_owner_ref { let _ = t.release_internal(id); }
                    return LockStep::Closed;
                }
                Claim::Recursive if retained.is_some() => {
                    let _ = t.release_internal(id); // waiter reference; ownership reference remains
                    return LockStep::Acquired;
                }
                Claim::Recursive => return LockStep::Error(crate::syscall::err(SYSTEM_ERROR_INVALID_ARGUMENT)),
                Claim::Acquired { reused_owner_ref } => {
                    debug_assert_eq!(reserved_owner_ref, !reused_owner_ref);
                    if retained.is_some() { let _ = t.release_internal(id); }
                    return LockStep::Acquired;
                }
                Claim::WaitFor(_) => {
                    debug_assert!(!reserved_owner_ref);
                }
            }

            if retained.is_none() && t.acquire_internal(id).is_err() { return LockStep::Error(crate::syscall::err(SYSTEM_ERROR_QUOTA_EXCEEDED)); }
            let Claim::WaitFor(owner) = claim else { unreachable!() };
            if sched::block_on_owner(owner, key).is_err() {
                if retained.is_none() { let _ = t.release_internal(id); }
                return LockStep::Error(crate::syscall::err(SYSTEM_ERROR_INVALID_ARGUMENT));
            }
            LockStep::Blocked(id)
        });

        match step {
            LockStep::Acquired => return 0,
            LockStep::Closed => {
                if let Some(id) = retained { kobj::with(|t| { let _ = t.release_internal(id); }); }
                return crate::syscall::err(SYSTEM_ASYNC_ERROR_CANCELLED);
            }
            LockStep::Error(error) => {
                if let Some(id) = retained { kobj::with(|t| { let _ = t.release_internal(id); }); }
                return error;
            }
            LockStep::Blocked(id) => {
                retained = Some(id);
                sched::yield_with_cause(sched::scheduler::Cause::BLOCK);
            }
        }
    }
}

pub fn sys_unlock(raw: u64) -> i64 {
    let Some(pid) = proc::current_process() else { return crate::syscall::err(SYSTEM_ERROR_RIGHTS_DENIED) };
    let me = sched::current().0;
    let result = kobj::with(|t| {
        let id = proc::resolve_in(t, pid, HandleId::from_raw(raw), ObjectType::Mutex, Rights::CONTROL)
            .map_err(crate::syscall::proc_err)?;
        let (owner, closed, key) = match t.get(id) {
            Ok(KObject::Mutex(m)) => (m.state.owner(), m.state.is_closed(), m.wait_key()),
            _ => return Err(crate::syscall::err(SYSTEM_HANDLE_ERROR_INVALID)),
        };
        if closed || owner != Some(me) { return Err(crate::syscall::err(SYSTEM_ERROR_RIGHTS_DENIED)); }
        #[cfg(feature = "rt3-verify")]
        crate::rt3_demo::observe_unlock(me, sched::current_qos(), sched::current_effective_qos());
        let next = sched::hand_off_object(key);
        let release_ref = match t.get_mut(id) {
            Ok(KObject::Mutex(m)) => m.state.release(me, next).map_err(|_| crate::syscall::err(SYSTEM_ERROR_RIGHTS_DENIED))?,
            _ => return Err(crate::syscall::err(SYSTEM_HANDLE_ERROR_INVALID)),
        };
        if release_ref { let _ = t.release_internal(id); }
        Ok(())
    });
    match result { Ok(()) => 0, Err(e) => e }
}

/// Last-handle closing action. It cancels exact wait edges before releasing the
/// ownership reference; resumed callers retain the object long enough to see
/// `closed` and return cancellation.
pub(crate) fn close_in(t: &mut kobj::Table, id: ObjId) {
    let (owner, key) = match t.get_mut(id) {
        Ok(KObject::Mutex(m)) if !m.state.is_closed() => {
            let key = m.wait_key();
            (m.state.close(), key)
        }
        _ => return,
    };
    if let Some(owner) = owner {
        sched::cancel_object_waiters(owner, key);
        let _ = t.release_internal(id); // ownership reference
    }
}
