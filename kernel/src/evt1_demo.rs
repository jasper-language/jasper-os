//! Author: chatgpt。独立EVT机制验收guest：与ring.enter共用真实等待函数。
//! 仅evt1-verify启用。计数为实际登记/恢复次数，不把TCG tick或cycles当物理延迟。
use core::sync::atomic::{AtomicU64, Ordering};
use kernel_core::{async_ring::Exec, object::HandleId, objtable::ObjId};
use crate::{kobj, kprintln, proc, ring, sched, task::TaskId, syscall::SyscallSet};
static PID: AtomicU64 = AtomicU64::new(0);
static HANDLE: AtomicU64 = AtomicU64::new(0);
static RING: AtomicU64 = AtomicU64::new(0);
static REQUEST: AtomicU64 = AtomicU64::new(0);
static MODE: AtomicU64 = AtomicU64::new(0);
static TARGET: AtomicU64 = AtomicU64::new(0);
static ENROLLED: AtomicU64 = AtomicU64::new(0);
static RESUMED: AtomicU64 = AtomicU64::new(0);
static DONE: AtomicU64 = AtomicU64::new(0);
static FAILED: AtomicU64 = AtomicU64::new(0);
fn check(ok: bool, label: &str) { if !ok { FAILED.fetch_add(1, Ordering::Relaxed); kprintln!("[JSR-EVT1-FAIL] {}", label); } }
fn pid() -> ObjId { ObjId::from_raw(PID.load(Ordering::Acquire)).unwrap() }
fn rid() -> ObjId { ObjId::from_raw(RING.load(Ordering::Acquire)).unwrap() }
/// 实际登记已经发布、对象锁已经释放，但尚未调用yield的验证边界。
pub fn enrolled(r: ObjId) {
    if MODE.load(Ordering::Acquire) == 1 {
        check(ring::manual_finish(r, REQUEST.load(Ordering::Acquire), 0), "enroll-yield gap completion");
    }
}
/// 实际入队事务内计数，释放guard后任务可能已被切走，不能在那里观测登记。
pub fn registered() { ENROLLED.fetch_add(1, Ordering::Release); }
/// 实际wait_ready_for从调度器恢复后计数；未被唤醒的等待者不执行此函数。
pub fn resumed() { RESUMED.fetch_add(1, Ordering::Release); }
fn waiter() {
    let result = ring::wait_ready_for(pid(), HandleId::from_raw(HANDLE.load(Ordering::Acquire)), 1);
    let mode = MODE.load(Ordering::Acquire);
    check(if mode == 2 { result.is_err() } else { result.is_ok() }, "wait terminal result");
    DONE.fetch_add(1, Ordering::Release);
}
fn controller() {
    let n = TARGET.load(Ordering::Acquire);
    let until = sched::timer_ticks() + 5000;
    while ENROLLED.load(Ordering::Acquire) < n && sched::timer_ticks() < until { sched::sleep_ticks(1); }
    check(ENROLLED.load(Ordering::Acquire) == n, "all simultaneous enrollments");
    let mode = MODE.load(Ordering::Acquire);
    if mode == 0 {
        let start = sched::timer_ticks();
        let before = RESUMED.load(Ordering::Acquire);
        let registered = ring::event_waiter_count(rid());
        check(registered == n as usize, "actual Ring waiter capacity");
        kprintln!("[JSR-EVT1-IDLE-BEGIN] waiters={} registered={}", n, registered);
        sched::sleep_ticks(crate::config::ACTIVE.clock.timer_hz as u64 * 10);
        let span = sched::timer_ticks() - start;
        let wakes = RESUMED.load(Ordering::Acquire) - before;
        check(wakes == 0 && ring::event_waiter_count(rid()) == n as usize, "idle window has no waiter resumes");
        kprintln!("[JSR-EVT1-IDLE] waiters={} registered={} ticks={} hz={} invalid_resumes={} clock=guest_ticks", n, registered, span, crate::config::ACTIVE.clock.timer_hz, wakes);
    }
    if mode == 2 { check(proc::exit_idle(pid(), 0), "exit closes waiting Ring"); }
    check(ring::manual_finish(rid(), REQUEST.load(Ordering::Acquire), 0), "broadcast completion/quiescence");
}
/// 四组真实kernel路径：检查登记到yield间完成、关闭/退出、期限、1000空闲等待者。
pub fn run() -> u64 {
    for (case, n) in [(1,1),(2,8),(3,8),(0,1000)] {
        let baseline = kobj::stats();
        let frames = crate::mm::frame::free_frames();
        ENROLLED.store(0, Ordering::Release); RESUMED.store(0, Ordering::Release); DONE.store(0, Ordering::Release);
        MODE.store(case, Ordering::Release); TARGET.store(n, Ordering::Release);
        let p = proc::create("evt1-mechanism", SyscallSet::EMPTY).expect("EVT process");
        let h = ring::create_for(p, 4).expect("EVT Ring");
        let r = ring::ring_of(p,h).unwrap();
        let req = if case == 3 {
            ring::submit_work_for(p,h,0,0,ring::Work::Wait { ticks: 40 }).unwrap()
        } else { ring::submit_manual(p,h,0,Some(Exec::NonAbortable),None).unwrap() };
        PID.store(p.raw(), Ordering::Release); HANDLE.store(h.raw(), Ordering::Release);
        RING.store(r.raw(), Ordering::Release); REQUEST.store(req, Ordering::Release);
        for i in 0..n { check(sched::spawn(TaskId(70000 + case*2000+i), "evt1-waiter", waiter).is_ok(), "spawn waiter capacity"); }
        if case == 0 || case == 2 { check(sched::spawn(TaskId(79000+case), "evt1-controller", controller).is_ok(), "spawn controller"); }
        sched::run();
        check(DONE.load(Ordering::Acquire) == n, "all waiters returned");
        check(ring::event_waiter_count(r) == 0, "all registrations removed");
        if case != 2 { check(proc::exit_idle(p,0), "case process exit"); }
        check(proc::reap(p).is_some(), "process reap");
        kobj::run_cleanup(usize::MAX);
        let resources = kobj::stats().0 == baseline.0 && kobj::stats().1 == baseline.1 && crate::mm::frame::free_frames() == frames;
        check(resources, "objects pending frames conserved");
        kprintln!("[JSR-EVT1-CASE] case={} waiters={} enrolled={} resumed={} done={} resources={} failed={}", case,n,ENROLLED.load(Ordering::Acquire),RESUMED.load(Ordering::Acquire),DONE.load(Ordering::Acquire),resources,FAILED.load(Ordering::Acquire));
    }
    FAILED.load(Ordering::Acquire)
}
