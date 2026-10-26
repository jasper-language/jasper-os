//! Actual scheduler admission drill, kernel API rather than CPL3/EDF claim.
use core::sync::atomic::{AtomicBool,AtomicU32,AtomicU64,Ordering};
use kernel_core::smp::CpuSet;
use crate::{sched,task::TaskId,kprintln};
static FIRST:AtomicU64=AtomicU64::new(0);
static EARLY:AtomicU64=AtomicU64::new(0);
static LATE:AtomicU64=AtomicU64::new(0);
pub fn record_dispatch(id:TaskId) {
 if id.0==EARLY.load(Ordering::Relaxed) || id.0==LATE.load(Ordering::Relaxed) {
  let _=FIRST.compare_exchange(0,id.0,Ordering::Relaxed,Ordering::Relaxed);
 }
}
static ORDER:AtomicU32=AtomicU32::new(0);
fn early(){ORDER.fetch_update(Ordering::SeqCst,Ordering::SeqCst,|x|Some(x*10+1)).unwrap();}
fn late(){ORDER.fetch_update(Ordering::SeqCst,Ordering::SeqCst,|x|Some(x*10+2)).unwrap();}
static GO:AtomicBool=AtomicBool::new(false);
fn worker() {while !GO.load(Ordering::Acquire) {sched::yield_now();}}
fn only(c:usize)->CpuSet {let mut s=CpuSet::EMPTY;s.insert(c);s}
pub fn run() {
 assert_eq!(sched::online_cpus().len(),4);
 if !crate::profile::has_capability("sched.realtime") {profile_denial();return;}
 for pass in 0..2u64 {
  let before=crate::baseline::baseline();GO.store(false,Ordering::Release);
  let ids=[TaskId(98000+pass*10),TaskId(98001+pass*10),TaskId(98002+pass*10)];
  // Stable setup observation: do not confuse ordinary tick/refill with rejection mutation.
  let irq=crate::arch::irq_save_disable();
  for (i,id) in ids.iter().copied().enumerate() {sched::spawn_on(id,"rt1-admit",worker,None,only(if i==2 {1}else{0})).unwrap();}
  assert!(sched::set_rt(ids[0],4,10));assert!(sched::set_rt(ids[1],4,10));
  let old=sched::rt_state(ids[0]).unwrap();
  assert!(!sched::set_rt(ids[0],6,10));assert_eq!(sched::rt_state(ids[0]),Some(old));
  assert!(!sched::set_rt(ids[0],0,10));assert_eq!(sched::rt_state(ids[0]),Some(old));
  assert!(sched::set_rt(ids[2],8,10));
  assert_eq!(sched::set_affinity(ids[0],only(1)),Err(sched::AffinityError::RtPartition));
  assert_eq!(sched::rt_state(ids[0]),Some(old));
  assert!(sched::set_rt(ids[0],4,10));assert_eq!(sched::rt_state(ids[0]),Some(old));
  assert!(sched::set_rt(ids[0],0,0));
  let disabled=sched::rt_state(ids[0]).unwrap();assert_eq!(disabled,(0,0,old.2));
  assert!(!sched::set_rt(ids[0],4,10));assert_eq!(sched::rt_state(ids[0]),Some(disabled));
  assert!(sched::set_rt(ids[0],0,0));assert_eq!(sched::rt_state(ids[0]),Some(disabled));
  // Publish the release before restoring IRQs: a preempted controller must not
  // leave an unlimited worker spinning on a flag it alone can release.
  GO.store(true,Ordering::Release);
  crate::arch::irq_restore(irq);sched::run();
  assert!(sched::rt_state(ids[0]).is_none());
  let next=TaskId(98003+pass*10);sched::spawn_on(next,"rt1-reuse",worker,None,only(0)).unwrap();
  assert!(sched::set_rt(next,9,10));sched::run();
  ORDER.store(0,Ordering::SeqCst);
  let irq=crate::arch::irq_save_disable();
  let slow=TaskId(98100+pass*10);let fast=TaskId(98101+pass*10);
  FIRST.store(0,Ordering::Relaxed);EARLY.store(fast.0,Ordering::Relaxed);LATE.store(slow.0,Ordering::Relaxed);
  sched::spawn_on(slow,"rt1-edf-late",late,None,only(0)).unwrap();
  sched::spawn_on(fast,"rt1-edf-early",early,None,only(0)).unwrap();
  assert!(sched::set_rt(slow,1,20));assert!(sched::set_rt(fast,1,10));
  crate::arch::irq_restore(irq);sched::run();
  assert_eq!(FIRST.load(Ordering::Relaxed),fast.0,"earliest deadline must dispatch first");
  assert!(matches!(ORDER.load(Ordering::SeqCst),12|21),"both workers must finish exactly once");
  if pass==1 {assert_eq!(before,crate::baseline::baseline());}
 }
 capacity_contract();
 user_contracts();
 crate::rtclass_demo::run();assert_eq!(crate::rtclass_demo::failed(),0);
 crate::arbiter_demo::run();assert_eq!(crate::arbiter_demo::failed(),0);
 kprintln!("[JSR-RT1-EDF] first_dispatch=early both_completed=true absolute_deadline=true failed=0");
 kprintln!("[JSR-RT1-ADMISSION] cpus=4 canonical=true rejected_unchanged=true partition_guard=true exit_release=true resources=true failed=0");
}

fn user_contracts() {
 use crate::{proc,syscall::{SyscallSet,table::*}};
 use kernel_core::paging::MapFlags;
 for pass in 0..2 {
  let before=crate::baseline::baseline();
  for permitted in [false,true] {
   let mut calls=SyscallSet::of(&[SYSTEM_TASK_SPAWN,SYSTEM_TASK_WAIT,SYSTEM_TASK_YIELD,SYSTEM_TASK_EXIT,SYSTEM_PROCESS_EXIT,SYSTEM_CONSOLE_WRITE,SYSTEM_HANDLE_DUPLICATE,SYSTEM_TASK_AFFINITY_GET,SYSTEM_TASK_AFFINITY_SET]);
   if permitted {calls=calls.union(SyscallSet::of(&[SYSTEM_TASK_RT_SET]));}
   let pid=proc::create("rt1-user",calls).unwrap();
   let entry=proc::load_elf(pid,include_bytes!(env!("JSR_USER_RING"))).unwrap();let base=crate::arch::USER_WINDOW.0;
   for page in 1..=4 {proc::map_new(pid,base+0xc00000-page*4096,MapFlags::USER|MapFlags::WRITE).unwrap();}
   proc::spawn_thread_affinity(pid,"rt1-user",entry,base+0xc00000,3,u64::from(permitted),Some(only(0))).unwrap();
   sched::run();assert_eq!(proc::state(pid),Some(proc::ProcState::Exited {code:0}));
   assert!(proc::reap(pid).is_some());
  }
  if pass==1 {assert_eq!(before,crate::baseline::baseline());}
 }
 kprintln!("[JSR-RT1-CPL3] capability=true syscall_gate=true affinity=true descriptor=true exit=true resources=true failed=0");
}

fn capacity_contract() {
 let cap=crate::rt::admission_capacity();assert!(cap>0);
 let irq=crate::arch::irq_save_disable();GO.store(false,Ordering::Release);
 for i in 0..=cap {
  let id=TaskId(98500+i as u64);sched::spawn_on(id,"rt1-capacity",worker,None,only(0)).unwrap();
  let old=sched::rt_state(id);
  if i<cap {assert!(sched::set_rt(id,1,1000));}
  else {assert!(!sched::set_rt(id,1,1000));assert_eq!(sched::rt_state(id),old);}
 }
 // Idempotence does not require another capacity slot.
 assert!(sched::set_rt(TaskId(98500),1,1000));
 GO.store(true,Ordering::Release);crate::arch::irq_restore(irq);sched::run();
 let id=TaskId(98600);sched::spawn_on(id,"rt1-capacity-reuse",worker,None,only(0)).unwrap();
 assert!(sched::set_rt(id,1,1000));sched::run();
 kprintln!("[JSR-RT1-CAPACITY] boot_limit={} reject_atomic=true idempotent=true exit_release=true failed=0",cap);
}

fn profile_denial() {
 use crate::{proc,syscall::{SyscallSet,table::*}};
 use kernel_core::paging::MapFlags;
 for pass in 0..2 {
  let before=crate::baseline::baseline();
  let calls=SyscallSet::of(&[SYSTEM_TASK_RT_SET,SYSTEM_CONSOLE_WRITE,SYSTEM_TASK_EXIT,SYSTEM_PROCESS_EXIT]);
  let pid=proc::create("rt1-no-realtime",calls).unwrap();
  let entry=proc::load_elf(pid,include_bytes!(env!("JSR_USER_RING"))).unwrap();let base=crate::arch::USER_WINDOW.0;
  for page in 1..=4 {proc::map_new(pid,base+0xc00000-page*4096,MapFlags::USER|MapFlags::WRITE).unwrap();}
  proc::spawn_thread_affinity(pid,"rt1-profile-deny",entry,base+0xc00000,4,0,Some(only(0))).unwrap();
  sched::run();assert_eq!(proc::state(pid),Some(proc::ProcState::Exited {code:0}));assert!(proc::reap(pid).is_some());
  if pass==1 {assert_eq!(before,crate::baseline::baseline());}
 }
 assert_eq!(sched::rt_utilisation(),0);
 kprintln!("[JSR-RT1-PROFILE] realtime=false syscall_allowed=true rejected=true resources=true failed=0");
}
