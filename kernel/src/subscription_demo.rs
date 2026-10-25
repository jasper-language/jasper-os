//! Actual kernel object/quota/lifetime integration; no user ABI/concurrency claim.
use kernel_core::{object::{ObjectType,Rights},objtable::ObjId,subscription::{Policy,Delivery,Event}};
use crate::{proc,kobj,subscription::{self,Read},syscall::SyscallSet};
fn identity(pid:ObjId,h:kernel_core::object::HandleId)->ObjId {
 ObjId::from_raw(proc::handle_info(pid,h).unwrap().0.id.0).unwrap()
}
pub fn run() {
 pressure_events();
 crate::irqring_demo::run();assert_eq!(crate::irqring_demo::failed(),0);
 cpl3_exit_event();
 ring_batches();
 quota_limit();
 // Same-shape warmup followed by measured resource baseline.
 for pass in 0..2 {
  let before=crate::baseline::baseline();
  let a=proc::create("evt2-source",SyscallSet::EMPTY).unwrap();
  let b=proc::create("evt2-subscriber",SyscallSet::EMPTY).unwrap();
  // First real event adapter: process exit, including a post-exit initial snapshot.
  let target=proc::grant(b,a,ObjectType::Process,Rights::WAIT.union(Rights::SUBSCRIBE)).unwrap();
  let exit_source=subscription::exit_source(b,target,ObjectType::Process).unwrap();
  let (exit_sub,initial_exit)=subscription::subscribe(b,exit_source,Policy::State).unwrap();
  assert_eq!(initial_exit.version,0);
  let root=subscription::create_source(a,9).unwrap();let source=identity(a,root);
  let grant=proc::grant(b,source,ObjectType::EventSource,Rights::SUBSCRIBE).unwrap();
  let denied=proc::grant(b,source,ObjectType::EventSource,Rights::READ).unwrap();
  assert!(subscription::subscribe(b,denied,Policy::Events).is_err());
  let (slow,snapshot)=subscription::subscribe(b,grant,Policy::Events).unwrap();
  let (fast,other)=subscription::subscribe(b,grant,Policy::State).unwrap();
  assert_eq!(snapshot,other);assert_eq!(snapshot.version,0);assert_eq!(snapshot.value,9);
  assert_eq!(proc::subscription_quota(b).unwrap().mapped,3);
  assert_eq!(proc::subscription_quota(b).unwrap().pinned,48);
  for n in 1..=20 {
   kobj::with(|t|subscription::publish_in(t,source,n)).unwrap();
   assert_eq!(subscription::take(b,fast).unwrap(),Read::Data(Delivery::Event(Event {first:n,last:n,value:n})));
  }
  assert_eq!(subscription::take(b,slow).unwrap(),Read::Data(Delivery::Resync(kernel_core::subscription::Snapshot {version:20,value:20})));
  // Creator exit closes one owner; subscriber capability still retains source ownership.
  assert!(proc::exit_idle(a,0));
  assert_eq!(subscription::take(b,exit_sub).unwrap(),Read::Data(Delivery::Event(Event {first:1,last:1,value:0})));
  let (late,late_snapshot)=subscription::subscribe(b,exit_source,Policy::State).unwrap();
  assert_eq!(late_snapshot.version,1);assert_eq!(late_snapshot.value,0);
  assert_eq!(subscription::take(b,late).unwrap(),Read::Empty);
  proc::close_handle_for(b,target).unwrap();assert!(proc::reap(a).is_some());
  proc::close_handle_for(b,exit_sub).unwrap();proc::close_handle_for(b,late).unwrap();proc::close_handle_for(b,exit_source).unwrap();kobj::run_cleanup(usize::MAX);
  kobj::with(|t|subscription::publish_in(t,source,21)).unwrap();
  proc::close_handle_for(b,denied).unwrap();proc::close_handle_for(b,grant).unwrap();
  assert!(kobj::with(|t|subscription::publish_in(t,source,22)).is_err());
  assert_eq!(subscription::take(b,slow).unwrap(),Read::Data(Delivery::Event(Event {first:21,last:21,value:21})));
  assert_eq!(subscription::take(b,slow).unwrap(),Read::Closed);
  proc::close_handle_for(b,slow).unwrap();assert!(proc::close_handle_for(b,slow).is_err());
  kobj::run_cleanup(usize::MAX);
  assert_eq!(proc::subscription_quota(b).unwrap().mapped,1);
  assert!(proc::exit_idle(b,0));assert!(proc::reap(b).is_some());
  let after=crate::baseline::baseline();
  if pass==1 {assert_eq!(before,after);crate::kprintln!("[JSR-EVT2-OBJECTS] snapshot=true broadcast=true overflow=true rights=true source_close=true exit=true quota_return=true resources=true failed=0");}
 }
}

fn ring_batches() {
 use crate::{ring,syscall::{table::*,err}};
 use kernel_core::subscription_abi::WaitArgs;
 for pass in 0..2 {
  let before=crate::baseline::baseline();
  let pid=proc::create("evt2-ring",SyscallSet::of(&[SYSTEM_EVENT_SUBSCRIPTION_WAIT])).unwrap();
  let root=subscription::create_source(pid,0).unwrap();let source=identity(pid,root);
  let (sub,_)=subscription::subscribe(pid,root,Policy::Events).unwrap();
  let rh=ring::create_for(pid,8).unwrap();let rid=identity(pid,rh);
  let va=crate::arch::USER_WINDOW.0+0x180000;proc::map_anon(pid,va,1,true).unwrap();
  let args=WaitArgs {ptr:va,capacity:4};
  let first=ring::submit_subscription_for(pid,rh,sub,args).unwrap();
  assert!(ring::reap_kernel(rid,8).is_empty());
  let pins=proc::memory_quota(pid).unwrap().pinned;
  assert_eq!(pins,1);
  assert_eq!(ring::submit_subscription_for(pid,rh,sub,args),Err(err(SYSTEM_EVENT_ERROR_BUSY)));
  assert_eq!(proc::memory_quota(pid).unwrap().pinned,pins);
  kobj::with(|t|subscription::publish_in(t,source,17)).unwrap();
  assert_eq!(ring::reap_kernel(rid,8),alloc::vec![(first,1)]);
  assert_eq!(proc::read_u64(pid,va),Some(1));assert_eq!(proc::read_u64(pid,va+8),Some(1));assert_eq!(proc::read_u64(pid,va+24),Some(17));
  assert_eq!(proc::memory_quota(pid).unwrap().pinned,0);
  let cancelled=ring::submit_subscription_for(pid,rh,sub,args).unwrap();
  assert_eq!(ring::cancel_for(pid,rh,cancelled),0);
  assert_eq!(ring::reap_kernel(rid,8),alloc::vec![(cancelled,err(SYSTEM_ASYNC_ERROR_CANCELLED))]);
  for value in 18..=20 {kobj::with(|t|subscription::publish_in(t,source,value)).unwrap();}
  let batch=ring::submit_subscription_for(pid,rh,sub,args).unwrap();
  assert_eq!(ring::reap_kernel(rid,8),alloc::vec![(batch,3)]);
  assert_eq!(proc::read_u64(pid,va+24),Some(18));assert_eq!(proc::read_u64(pid,va+88),Some(20));
  let closing=ring::submit_subscription_for(pid,rh,sub,args).unwrap();
  proc::close_handle_for(pid,sub).unwrap();
  assert_eq!(ring::reap_kernel(rid,8),alloc::vec![(closing,err(SYSTEM_EVENT_ERROR_CLOSED))]);
  let (next,_)=subscription::subscribe(pid,root,Policy::Events).unwrap();
  let source_closing=ring::submit_subscription_for(pid,rh,next,args).unwrap();
  proc::close_handle_for(pid,root).unwrap();
  assert_eq!(ring::reap_kernel(rid,8),alloc::vec![(source_closing,err(SYSTEM_EVENT_ERROR_CLOSED))]);
  assert_eq!(proc::memory_quota(pid).unwrap().pinned,0);
  assert!(proc::exit_idle(pid,0));assert!(proc::reap(pid).is_some());
  let after=crate::baseline::baseline();
  if pass==1 {assert_eq!(before,after);crate::kprintln!("[JSR-EVT2-RING] immediate=true parked=true batch=3 cancel=true busy_atomic=true sub_close=true source_close=true pins=true resources=true failed=0");}
 }
}

fn quota_limit() {
 for pass in 0..2 {
  let before=crate::baseline::baseline();let pid=proc::create("evt2-quota",SyscallSet::EMPTY).unwrap();
  let root=subscription::create_source(pid,0).unwrap();let mut handles=alloc::vec::Vec::new();
  for _ in 0..subscription::PROCESS_SUBSCRIPTIONS {handles.push(subscription::subscribe(pid,root,Policy::Events).unwrap().0);}
  assert!(proc::free_handle_slots(pid)>0);
  let quota=proc::subscription_quota(pid).unwrap();let live=kobj::stats();let frames=crate::mm::frame::free_frames();
  assert_eq!(quota.mapped,32);assert_eq!(quota.pinned,512);
  assert!(matches!(subscription::subscribe(pid,root,Policy::Events),Err(subscription::Error::Quota)));
  assert_eq!(proc::subscription_quota(pid).unwrap(),quota);assert_eq!(kobj::stats(),live);assert_eq!(crate::mm::frame::free_frames(),frames);
  proc::close_handle_for(pid,handles.pop().unwrap()).unwrap();kobj::run_cleanup(usize::MAX);
  assert_eq!(proc::subscription_quota(pid).unwrap().mapped,31);
  handles.push(subscription::subscribe(pid,root,Policy::Events).unwrap().0);
  assert_eq!(proc::subscription_quota(pid).unwrap(),quota);
  assert!(proc::exit_idle(pid,0));assert!(proc::reap(pid).is_some());let after=crate::baseline::baseline();
  if pass==1 {assert_eq!(before,after);crate::kprintln!("[JSR-EVT2-QUOTA] subscriptions=32 slots=512 refused=true atomic=true retry=true exit=true resources=true failed=0");}
 }
}

use core::sync::atomic::{AtomicU64,Ordering};
static CPL_TARGET:AtomicU64=AtomicU64::new(0);
static CPL_CLIENT:AtomicU64=AtomicU64::new(0);
fn exit_controller() {
 let client=ObjId::from_raw(CPL_CLIENT.load(Ordering::Acquire)).unwrap();
 for _ in 0..1000 {
  if proc::ring_quota(client).is_some_and(|q|q.in_flight==1) {
   let target=ObjId::from_raw(CPL_TARGET.load(Ordering::Acquire)).unwrap();assert!(proc::exit_idle(target,37));return;
  }
  crate::sched::sleep_ticks(1);
 }
 panic!("EVT2 CPL3 pending request never registered");
}
fn cpl3_exit_event() {
 use crate::syscall::table::*;
 for pass in 0..2 {
  let before=crate::baseline::baseline();
  let target=proc::create("evt2-cpl-target",SyscallSet::EMPTY).unwrap();
  let allowed=SyscallSet::of(&[SYSTEM_EVENT_SOURCE_CREATE,SYSTEM_EVENT_SUBSCRIPTION_CREATE,SYSTEM_EVENT_SUBSCRIPTION_WAIT,SYSTEM_ASYNC_RING_CREATE,SYSTEM_ASYNC_RING_ENTER,SYSTEM_HANDLE_CLOSE,SYSTEM_HANDLE_RESTRICT,SYSTEM_CONSOLE_WRITE,SYSTEM_TASK_EXIT,SYSTEM_TASK_SPAWN,SYSTEM_TASK_YIELD,SYSTEM_TIME_WAIT,SYSTEM_PROCESS_SPAWN]);
  let client=proc::create("evt2-cpl-client",allowed).unwrap();
  let cap=proc::grant(client,target,ObjectType::Process,Rights::WAIT.union(Rights::SUBSCRIBE)).unwrap();
  let image=include_bytes!(env!("JSR_USER_RING"));let entry=proc::load_elf(client,image).unwrap();let base=crate::arch::USER_WINDOW.0;
  for page in 1..=4 {proc::map_new(client,base+0xc00000-page*4096,kernel_core::paging::MapFlags::USER|kernel_core::paging::MapFlags::WRITE).unwrap();}
  CPL_TARGET.store(target.raw(),Ordering::Release);CPL_CLIENT.store(client.raw(),Ordering::Release);
  let mut affinity=kernel_core::smp::CpuSet::EMPTY;affinity.insert(usize::from(crate::smp::cpu_count()>1));
  proc::spawn_thread_affinity(client,"evt2-cpl-client",entry,base+0xc00000,2,cap.raw(),Some(affinity)).unwrap();
  crate::sched::spawn(crate::task::TaskId(89000+pass),"evt2-exit-controller",exit_controller).unwrap();
  crate::sched::run();
  assert_eq!(proc::state(client),Some(proc::ProcState::Exited {code:0}));assert_eq!(proc::state(target),Some(proc::ProcState::Exited {code:37}));
  assert_eq!(proc::subscription_quota(client).unwrap(),kernel_core::memory_object::Usage::default());
  assert_eq!(proc::memory_quota(client).unwrap().pinned,0);
  assert!(proc::reap(client).is_some() && proc::reap(target).is_some());let after=crate::baseline::baseline();
  if pass==1 {assert_eq!(before,after);crate::kprintln!("[JSR-EVT2-CPL3] source=true snapshot=true parked=true record=true late_snapshot=true rights=true exit=true resources=true failed=0");}
 }
}

fn pressure_events() {
 use crate::{ring,mm::pressure,syscall::table::*};
 use kernel_core::{pressure::PressureParams,subscription_abi::WaitArgs};
 // The single lazily initialized global publisher is intentional bounded kernel state.
 let source=kobj::with(pressure::source_in).unwrap();
 for pass in 0..2 {
  let old=pressure::set_params(PressureParams::new(2,1,0).unwrap());pressure::sync_events();
  let before=crate::baseline::baseline();let pid=proc::create("evt2-pressure",SyscallSet::of(&[SYSTEM_EVENT_SUBSCRIPTION_WAIT])).unwrap();
  let cap=proc::grant(pid,source,ObjectType::EventSource,Rights::SUBSCRIBE).unwrap();
  assert!(subscription::subscribe(pid,cap,Policy::Count).is_err());
  let (sub,snapshot)=subscription::subscribe(pid,cap,Policy::State).unwrap();assert_eq!(snapshot.value,0);
  let va=crate::arch::USER_WINDOW.0+0x180000;proc::map_anon(pid,va,1,true).unwrap();let rh=ring::create_for(pid,4).unwrap();let rid=identity(pid,rh);
  let args=WaitArgs {ptr:va,capacity:4};let req=ring::submit_subscription_for(pid,rh,sub,args).unwrap();
  assert!(ring::reap_kernel(rid,4).is_empty());
  pressure::set_params(PressureParams::new(1000,999,0).unwrap());pressure::sync_events();
  assert_eq!(ring::reap_kernel(rid,4),alloc::vec![(req,1)]);assert_eq!(proc::read_u64(pid,va+24),Some(2));
  pressure::set_params(PressureParams::new(2,1,0).unwrap());pressure::sync_events();
  let req=ring::submit_subscription_for(pid,rh,sub,args).unwrap();
  assert_eq!(ring::reap_kernel(rid,4),alloc::vec![(req,1)]);assert_eq!(proc::read_u64(pid,va+24),Some(0));
  pressure::note_frame_change();pressure::sync_events();assert_eq!(subscription::take(pid,sub).unwrap(),Read::Empty);
  assert!(proc::exit_idle(pid,0));assert!(proc::reap(pid).is_some());let after=crate::baseline::baseline();pressure::set_params(old);pressure::sync_events();
  if pass==1 {assert_eq!(before,after);crate::kprintln!("[JSR-EVT2-PRESSURE] state=true normal_critical_normal=true ring=true unchanged_no_event=true resources=true failed=0");}
 }
}
