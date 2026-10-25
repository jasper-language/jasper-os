//! Bounded actual-kernel-API broadcast drill; kernel workers, not CPL3 clients.
use core::sync::atomic::{AtomicU64,Ordering};
use kernel_core::{object::HandleId,objtable::ObjId,subscription::{Policy,Delivery},smp::CpuSet};
use crate::{proc,kobj,sched,subscription::{self,Read},task::TaskId,syscall::SyscallSet};
static PID:AtomicU64=AtomicU64::new(0);
static SOURCE:AtomicU64=AtomicU64::new(0);
static ROOT:AtomicU64=AtomicU64::new(0);
static COUNT:AtomicU64=AtomicU64::new(0);
static READY:AtomicU64=AtomicU64::new(0);
static HANDLES:[AtomicU64;8]=[const {AtomicU64::new(0)};8];
static CURSORS:[AtomicU64;8]=[const {AtomicU64::new(0)};8];
static RESYNCS:[AtomicU64;8]=[const {AtomicU64::new(0)};8];
fn pid()->ObjId {ObjId::from_raw(PID.load(Ordering::Acquire)).unwrap()}
fn consumer() {
 let cpu=crate::arch::cpu_index();assert!((1..8).contains(&cpu));
 let handle=HandleId::from_raw(HANDLES[cpu].load(Ordering::Acquire));
 let count=COUNT.load(Ordering::Acquire);let mut cursor=0;let mut observed=0;let mut synchronized=0;let mut resyncs=0;
 READY.fetch_add(1,Ordering::AcqRel);
 while cursor<count {
  match subscription::take(pid(),handle).unwrap() {
   Read::Data(Delivery::Event(event))=>{
    assert_eq!(event.first,cursor+1);assert_eq!(event.last,event.first);assert_eq!(event.value,event.last);
    cursor=event.last;observed+=1;
   },
   Read::Data(Delivery::Resync(snapshot))=>{
    assert!(snapshot.version>cursor && snapshot.version<=count);assert_eq!(snapshot.value,snapshot.version);
    synchronized+=snapshot.version-cursor;cursor=snapshot.version;resyncs+=1;
   },
   Read::Empty=>sched::yield_now(),
   Read::Closed=>panic!("broadcast source closed before final sequence"),
  }
 }
 assert_eq!(observed+synchronized,count);
 CURSORS[cpu].store(cursor,Ordering::Release);RESYNCS[cpu].store(resyncs,Ordering::Release);
}
fn publisher() {
 assert_eq!(crate::arch::cpu_index(),0);
 while READY.load(Ordering::Acquire)!=7 {sched::yield_now();}
 let source=ObjId::from_raw(SOURCE.load(Ordering::Acquire)).unwrap();
 for value in 1..=COUNT.load(Ordering::Acquire) {
  kobj::with(|t|subscription::publish_in(t,source,value)).unwrap();
  if value%4096==0 {sched::yield_now();}
 }
 proc::close_handle_for(pid(),HandleId::from_raw(ROOT.load(Ordering::Acquire))).unwrap();
}
pub fn run() {
 assert_eq!(crate::smp::cpu_count(),8,"broadcast fixture requires eight CPUs");
 for pass in 0..2 {
  let before=crate::baseline::baseline();let process=proc::create("evt2-broadcast",SyscallSet::EMPTY).unwrap();
  let root=subscription::create_source(process,0).unwrap();let source=ObjId::from_raw(proc::handle_info(process,root).unwrap().0.id.0).unwrap();
  PID.store(process.raw(),Ordering::Release);SOURCE.store(source.raw(),Ordering::Release);ROOT.store(root.raw(),Ordering::Release);
  COUNT.store(if pass==0 {4096}else{1_000_000},Ordering::Release);READY.store(0,Ordering::Release);
  for cpu in 1..8 {
   let (handle,snapshot)=subscription::subscribe(process,root,Policy::Events).unwrap();assert_eq!(snapshot.version,0);
   HANDLES[cpu].store(handle.raw(),Ordering::Release);CURSORS[cpu].store(0,Ordering::Release);RESYNCS[cpu].store(0,Ordering::Release);
  }
  for cpu in 0..8 {
   let mut affinity=CpuSet::EMPTY;affinity.insert(cpu);
   sched::spawn_on(TaskId(97000+pass*16+cpu as u64),"evt2-broadcast",if cpu==0 {publisher}else{consumer},None,affinity).unwrap();
  }
  sched::run();
  for cpu in 1..8 {assert_eq!(CURSORS[cpu].load(Ordering::Acquire),COUNT.load(Ordering::Acquire));}
  assert!(proc::exit_idle(process,0));assert!(proc::reap(process).is_some());let after=crate::baseline::baseline();
  if pass==1 {
   assert_eq!(before,after);
   for cpu in 1..8 {crate::kprintln!("[JSR-EVT2-BROADCAST-SUB] cpu={} final={} resyncs={} continuous_or_resync=true",cpu,CURSORS[cpu].load(Ordering::Acquire),RESYNCS[cpu].load(Ordering::Acquire));}
   crate::kprintln!("[JSR-EVT2-BROADCAST] cpus=8 events=1000000 subscribers=7 all_final=true sequence=true bounded=true resources=true failed=0");
  }
 }
}
