//! RT-2 hardware register programming drill; no actual one-shot IRQ/latency claim.
use core::sync::atomic::{AtomicBool,AtomicU32,Ordering};
use crate::{sched,task::TaskId,kprintln};
static ARMED:AtomicBool=AtomicBool::new(false);
static FIRED:AtomicBool=AtomicBool::new(false);
static IRQ_TICKS:AtomicU32=AtomicU32::new(0);
/// Opt-in diagnostic ownership: never charge a full legacy tick for this IRQ.
/// This does not yet implement scheduler deadline delivery.
pub fn timer_irq()->bool {
 if crate::arch::cpu_index()!=1 || !ARMED.swap(false,Ordering::AcqRel) {return false;}
 IRQ_TICKS.store(crate::smp::percpu::this().ticks() as u32,Ordering::Relaxed);
 crate::arch::timer_resume();FIRED.store(true,Ordering::Release);true
}
static DONE:AtomicBool=AtomicBool::new(false);
fn probe() {
 assert_eq!(crate::arch::cpu_index(),1);
 let irq=crate::arch::irq_save_disable();
 assert!(crate::arch::timer_verify_ns_programming());
 let before=crate::smp::percpu::this().ticks() as u32;
 FIRED.store(false,Ordering::Relaxed);ARMED.store(true,Ordering::Release);
 assert!(unsafe {crate::arch::timer_arm_after_ns(1_000_000)});
 crate::arch::irq_restore(irq);
 let deadline=sched::timer_ticks()+20;
 while !FIRED.load(Ordering::Acquire) {assert!(sched::timer_ticks()<deadline,"one-shot IRQ not delivered");core::hint::spin_loop();}
 assert_eq!(IRQ_TICKS.load(Ordering::Relaxed),before,"probe IRQ must not mint a legacy tick");
 DONE.store(true,Ordering::Release);
}
pub fn run() {
 for pass in 0..2 {
  let before=crate::baseline::baseline();DONE.store(false,Ordering::Release);
  let mut set=kernel_core::smp::CpuSet::EMPTY;set.insert(1);
  sched::spawn_on(TaskId(98700+pass),"rt2-lapic-probe",probe,None,set).unwrap();sched::run();
  assert!(DONE.load(Ordering::Acquire));if pass==1 {assert_eq!(before,crate::baseline::baseline());}
 }
 assert!(sched::enable_highres());
 integration();
 kprintln!("[JSR-RT2-IRQ] delivered=true no_legacy_credit=true periodic_restored=true failed=0");
 kprintln!("[JSR-RT2-LAPIC] cpu=1 ns_programmed=true overflow_unchanged=true periodic_restored=true resources=true failed=0");
}

static KILL_PID:kernel_core::sync::Atomic64=kernel_core::sync::Atomic64::new(0);
static KILL_TASK:kernel_core::sync::Atomic64=kernel_core::sync::Atomic64::new(0);
static FIRST_TIMER_SLOT:kernel_core::sync::Atomic64=kernel_core::sync::Atomic64::new(0);
static FIRST_TIMER_GENERATION:kernel_core::sync::Atomic64=kernel_core::sync::Atomic64::new(0);
static FIRST_TIMER_OWNER:kernel_core::sync::Atomic64=kernel_core::sync::Atomic64::new(0);

fn timer_identity_worker(pass:u64){
 let (id,owner)=sched::current_timer_identity().expect("worker owns timer identity");
 let deadline=crate::hrtime::now().unwrap().checked_add(500_000).unwrap();
 sched::sleep_until_ns(deadline).unwrap();
 assert!(crate::hrtime::now().unwrap()>=deadline);
 assert_eq!(sched::current_timer_identity(),Some((id,owner)));
 if pass==0 {
  FIRST_TIMER_SLOT.store(u64::from(id.slot),Ordering::Release);
  FIRST_TIMER_GENERATION.store(id.generation,Ordering::Release);
  FIRST_TIMER_OWNER.store(u64::from(owner),Ordering::Release);
 }else{
  let old=kernel_core::timer_event::TimerId{
   slot:u32::try_from(FIRST_TIMER_SLOT.load(Ordering::Acquire)).unwrap(),
   generation:FIRST_TIMER_GENERATION.load(Ordering::Acquire),
  };
  assert_eq!(id.slot,old.slot);
  assert!(id.generation>old.generation);
  assert!(sched::reject_stale_timer(old,u32::try_from(FIRST_TIMER_OWNER.load(Ordering::Acquire)).unwrap()));
  let audit=sched::timer_identity_audit();
  assert_eq!((audit.live,audit.budget_used,audit.stale_rejections),(1,1,1));
 }
}
fn timer_identity_first(){timer_identity_worker(0)}
fn timer_identity_second(){timer_identity_worker(1)}

fn timer_identity_contract(){
 let mut cpu=kernel_core::smp::CpuSet::EMPTY;cpu.insert(0);
 for entry in [timer_identity_first as fn(),timer_identity_second] {
  sched::spawn_on(TaskId(98850),"issue3-timer-identity",entry,None,cpu).unwrap();
  sched::run();
 }
 let audit=sched::timer_identity_audit();
 assert_eq!((audit.live,audit.armed,audit.budget_used,audit.stale_rejections),(0,0,0,1));
 kprintln!("[JSR-TIMER-ID] normal=2 stale_rejected={} live={} armed={} budget={}/{} failed=0",
  audit.stale_rejections,audit.live,audit.armed,audit.budget_used,audit.budget_limit);
}

fn canceller(){
 let end=crate::hrtime::now().unwrap()+200_000_000;
 let task=TaskId(KILL_TASK.load(Ordering::Acquire));
 while !sched::ns_sleeping(task){assert!(crate::hrtime::now().unwrap()<end,"ns wait never enrolled");sched::yield_now();}
 let pid=kernel_core::objtable::ObjId::from_raw(KILL_PID.load(Ordering::Acquire)).unwrap();assert!(crate::proc::begin_exit(pid,-7));
}
fn ns_waiter(){
 let start=crate::hrtime::now().unwrap();let deadline=start+1_000_000;
 while crate::hrtime::now().unwrap()<deadline{sched::sleep_until_ns(deadline).unwrap();}
 assert!(crate::hrtime::now().unwrap()>=deadline);
}
fn integration(){
 use crate::{proc,syscall::{SyscallSet,table::*}};
 use kernel_core::paging::MapFlags;
 timer_identity_contract();
 for pass in 0..2u64 {
  let before=crate::baseline::baseline();
  for cpu in 0..2 {let mut set=kernel_core::smp::CpuSet::EMPTY;set.insert(cpu);sched::spawn_on(TaskId(98800+pass*10+cpu as u64),"rt2-ns-wait",ns_waiter,None,set).unwrap();}
  sched::run();
  for cpu in 0..2 {
   let calls=SyscallSet::of(&[SYSTEM_TIME_DEADLINE_GET,SYSTEM_TIME_DEADLINE_WAIT,SYSTEM_TASK_RT_DEADLINE_SET,SYSTEM_TASK_SPAWN,SYSTEM_TASK_WAIT,SYSTEM_TASK_YIELD,SYSTEM_TASK_EXIT,SYSTEM_PROCESS_EXIT,SYSTEM_CONSOLE_WRITE]);
   let pid=proc::create("rt2-user",calls).unwrap();let entry=proc::load_elf(pid,include_bytes!(env!("JSR_USER_RING"))).unwrap();let base=crate::arch::USER_WINDOW.0;
   for page in 1..=4 {proc::map_new(pid,base+0xc00000-page*4096,MapFlags::USER|MapFlags::WRITE).unwrap();}
   let mut set=kernel_core::smp::CpuSet::EMPTY;set.insert(cpu);
   proc::spawn_thread_affinity(pid,"rt2-user",entry,base+0xc00000,5,0,Some(set)).unwrap();
   sched::run();assert_eq!(proc::state(pid),Some(proc::ProcState::Exited {code:0}));assert!(proc::reap(pid).is_some());
  }
  let calls=SyscallSet::of(&[SYSTEM_TIME_DEADLINE_GET,SYSTEM_TIME_DEADLINE_WAIT,SYSTEM_TASK_EXIT,SYSTEM_PROCESS_EXIT]);
  let pid=proc::create("rt2-cancel",calls).unwrap();let entry=proc::load_elf(pid,include_bytes!(env!("JSR_USER_RING"))).unwrap();let base=crate::arch::USER_WINDOW.0;
  for page in 1..=4 {proc::map_new(pid,base+0xc00000-page*4096,MapFlags::USER|MapFlags::WRITE).unwrap();}
  let mut cpu0=kernel_core::smp::CpuSet::EMPTY;cpu0.insert(0);let mut cpu1=kernel_core::smp::CpuSet::EMPTY;cpu1.insert(1);
  let (task,_)=proc::spawn_thread_affinity(pid,"rt2-cancel-wait",entry,base+0xc00000,6,0,Some(cpu0)).unwrap();
  KILL_PID.store(pid.raw(),Ordering::Release);KILL_TASK.store(task.0,Ordering::Release);
  sched::spawn_on(TaskId(98900+pass),"rt2-canceller",canceller,None,cpu1).unwrap();sched::run();
  assert_eq!(proc::state(pid),Some(proc::ProcState::Exited {code:-7}));assert!(proc::reap(pid).is_some());
  assert_eq!(sched::rt_utilisation(),0);if pass==1 {assert_eq!(before,crate::baseline::baseline());}
 }
 kprintln!("[JSR-RT2-INTEGRATION] ns_sleep=true bsp_ap=true cpl3=true ns_budget=true exit_cancel=true resources=true failed=0");
}
