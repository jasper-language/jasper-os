//! EVT-2 internal object integration. Object-table lock serializes all operations.
//! Source -> subscribers stores non-owning generation-checked IDs; each subscription
//! holds one internal source reference. The reference graph has no ownership cycle.
use alloc::{boxed::Box,vec::Vec};
use kernel_core::{object::{HandleId,ObjectType,Rights},objtable::ObjId,
 subscription::{Snapshot,Queue,Policy,Delivery}};
use crate::{kobj::{self,KObject,Table},proc::{self,ProcError}};
pub const QUEUE_SLOTS:usize=16;
const MAX_SUBSCRIPTIONS:u64=64;
pub(crate) const PROCESS_SUBSCRIPTIONS:u64=32;
pub(crate) const PROCESS_QUEUE_SLOTS:u64=512;

pub struct Source { snapshot:Snapshot, subscribers:Vec<ObjId>, closed:bool, publisher_owned:bool, policies:u8 }
pub struct Subscription {
 source:ObjId, queue:Queue<QUEUE_SLOTS>, closed:bool, linked:bool, waiter:Option<(ObjId,u64)>,
 // Independent charge account survives process exit; no Process ownership edge.
 _charge:crate::mm::memory_quota::Charge,
}
#[derive(Debug)]
pub enum Error { Process(ProcError), Closed, Busy, Policy, Quota, Allocation, Invalid, Exhausted }
impl From<ProcError> for Error {fn from(e:ProcError)->Self {Self::Process(e)}}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Read { Data(Delivery), Empty, Closed }
pub fn create_source(pid:ObjId,value:u64)->Result<HandleId,Error> {
 let obj=Box::try_new(Source {snapshot:Snapshot {version:0,value},subscribers:Vec::new(),closed:false,publisher_owned:false,policies:7}).map_err(|_|Error::Allocation)?;
 Ok(proc::grant_new(pid,KObject::EventSource(obj),ObjectType::EventSource,
  Rights::READ.union(Rights::SUBSCRIBE).union(Rights::DUPLICATE))?)
}
pub fn subscribe(pid:ObjId,handle:HandleId,policy:Policy)->Result<(HandleId,Snapshot),Error> {
 kobj::with(|t|subscribe_in(t,pid,handle,policy))
}
pub(crate) fn subscribe_in(t:&mut Table,pid:ObjId,handle:HandleId,policy:Policy)->Result<(HandleId,Snapshot),Error> {

  let id=proc::resolve_in(t,pid,handle,ObjectType::EventSource,Rights::SUBSCRIBE)?;
  let snapshot=match t.get_mut(id) {
   Ok(KObject::EventSource(s)) if !s.closed=>{
    let bit=match policy {Policy::Events=>1,Policy::State=>2,Policy::Count=>4};
    if s.policies & bit==0 {return Err(Error::Policy);}
    if s.subscribers.len()>=MAX_SUBSCRIPTIONS as usize {return Err(Error::Quota);}
    s.subscribers.try_reserve(1).map_err(|_|Error::Allocation)?;s.snapshot
   },_=>return Err(Error::Closed),
  };
  let charge=proc::subscription_charge_in(t,pid,QUEUE_SLOTS as u64).ok_or(Error::Quota)?;
  let sub=Box::try_new(Subscription {source:id,queue:Queue::new(snapshot,policy),closed:false,linked:false,waiter:None,_charge:charge}).map_err(|_|Error::Allocation)?;
  t.acquire_internal(id).map_err(|_|Error::Invalid)?;
  let result=proc::grant_new_in(t,pid,KObject::Subscription(sub),ObjectType::Subscription,Rights::READ.union(Rights::WAIT));
  match result {
   Ok((handle,subid))=>{
    if let Ok(KObject::Subscription(sub))=t.get_mut(subid) {sub.linked=true;}
    // The source is retained; no guard was released since capacity reservation.
    let Ok(KObject::EventSource(s))=t.get_mut(id) else {unreachable!()};
    s.subscribers.push(subid);Ok((handle,snapshot))
   },
   Err(e)=>{let _=t.release_internal(id);Err(Error::Process(e))}
  }

}
/// Kernel publishers resolve the source identity, never user-selected raw pointers.
/// No allocation after publication begins. Object lock prevents partial observation.
pub(crate) fn publish_value_in(t:&mut Table,id:ObjId,value:u64,snapshot_value:u64)->Result<(),Error> {
 let (event,subscribers)=match t.get_mut(id) {
  Ok(KObject::EventSource(s)) if !s.closed=>{
   // Bounded stack snapshot avoids a source borrow while accessing subscriptions.
   let mut ids=[None;MAX_SUBSCRIPTIONS as usize];
   for (slot,id) in ids.iter_mut().zip(&s.subscribers) {*slot=Some(*id);}
   (s.snapshot.publish(snapshot_value).map_err(|_|Error::Exhausted)?,ids)
  },_=>return Err(Error::Closed),
 };
 for subid in subscribers.into_iter().flatten() {
  if let Ok(KObject::Subscription(sub))=t.get_mut(subid) {
   if sub.source==id && !sub.closed {
    // Contiguous source version invariant; failure is never silently ignored.
    assert!(sub.queue.publish(Snapshot {version:event.version,value}).is_ok(),"subscription sequence diverged");
   }
  }
 }
 for subid in subscribers.into_iter().flatten() {notify_in(t,subid);}
 Ok(())
}
pub(crate) fn publish_in(t:&mut Table,id:ObjId,value:u64)->Result<(),Error> {publish_value_in(t,id,value,value)}
pub fn take(pid:ObjId,handle:HandleId)->Result<Read,Error> {
 kobj::with(|t| {
  let id=proc::resolve_in(t,pid,handle,ObjectType::Subscription,Rights::READ)?;
  let (delivery,closed,source)={
   let Ok(KObject::Subscription(sub))=t.get_mut(id) else {return Err(Error::Invalid)};
   if sub.waiter.is_some() {return Err(Error::Busy);}
   (sub.queue.take(),sub.closed,sub.source)
  };
  let source_closed=match t.get(source) {Ok(KObject::EventSource(s))=>s.closed,_=>true};
  let delivery=delivery.map(|event|resync_snapshot_in(t,source,event));
  Ok(match delivery {Some(event)=>Read::Data(event),None if closed || source_closed=>Read::Closed,None=>Read::Empty})
 })
}
pub(crate) fn close_in(t:&mut Table,id:ObjId) {
 if let Ok(KObject::Subscription(sub))=t.get_mut(id) {sub.closed=true;}
 notify_in(t,id);
 let source=match t.get_mut(id) {
  Ok(KObject::Subscription(sub))=>{sub.closed=true;
   if sub.linked {sub.linked=false;Some(sub.source)} else {None}},
  _=>None,
 };
 if let Some(source)=source {
  if let Ok(KObject::EventSource(s))=t.get_mut(source) {s.subscribers.retain(|x|*x!=id);}
  let _=t.release_internal(source);
  return;
 }
 if let Ok(KObject::EventSource(s))=t.get_mut(id) {if !s.publisher_owned {s.closed=true;}}
 notify_source_in(t,id);
 // Do not mark subscription.closed here: it also records whether its owning
 // source reference was released. Source closure is queried separately later.
}

/// A live publisher anchors one external owner so ObjectTable does not enter Closing
/// when the last user capability closes. Subscription edges remain internal refs.
pub(crate) fn create_publisher_in(t:&mut Table,snapshot:Snapshot)->Result<ObjId,Error> {
 let source=Box::try_new(Source {snapshot,subscribers:Vec::new(),closed:false,publisher_owned:true,policies:7}).map_err(|_|Error::Allocation)?;
 t.insert(KObject::EventSource(source),1,0).map_err(|_|Error::Allocation)
}
pub(crate) fn finish_publisher_in(t:&mut Table,id:ObjId) {
 if let Ok(KObject::EventSource(source))=t.get_mut(id) {source.closed=true;source.publisher_owned=false;}
 notify_source_in(t,id);
 let _=kobj::release_owner_in(t,id);
}
/// Requires both WAIT and SUBSCRIBE on the target Process/Task; no raw-id authority.
pub fn exit_source(pid:ObjId,target:HandleId,ty:ObjectType)->Result<HandleId,Error> {
 kobj::with(|t| {
  proc::resolve_in(t,pid,target,ty,Rights::WAIT.union(Rights::SUBSCRIBE))?;
  let es=proc::acquire_exit_state_in(t,pid,target,ty)?;
  let result=crate::exit_state::source_in(t,es).and_then(|source|
   proc::grant_in(t,pid,source,ObjectType::EventSource,Rights::READ.union(Rights::SUBSCRIBE)).map_err(Error::Process));
  let _=t.release_internal(es);result
 })
}

use crate::syscall::{err,table::*};
use kernel_core::subscription_abi::{WaitArgs,RECORD_BYTES,MAX_BATCH};
pub(crate) struct WaitTarget {pub sub:ObjId,buffer:crate::mm::pin::PinnedRange,capacity:usize}
pub(crate) enum Attempt {Empty,Done(i64)}
pub(crate) fn prepare_wait_in(t:&mut Table,pid:ObjId,h:HandleId,args:WaitArgs)->Result<WaitTarget,i64> {
 let sub=proc::resolve_in(t,pid,h,ObjectType::Subscription,Rights::WAIT).map_err(|_|err(SYSTEM_HANDLE_ERROR_RIGHTS_DENIED))?;
 if args.capacity==0 || args.capacity as usize>MAX_BATCH {return Err(err(SYSTEM_ERROR_INVALID_ARGUMENT));}
 let buffer=proc::pin_user_in(t,pid,args.ptr,args.capacity as usize*RECORD_BYTES,true).map_err(|_|err(SYSTEM_MEMORY_ERROR_INVALID_ADDRESS))?;
 t.acquire_internal(sub).map_err(|_|err(SYSTEM_HANDLE_ERROR_INVALID))?;
 Ok(WaitTarget {sub,buffer,capacity:args.capacity as usize})
}
pub(crate) fn check_wait_in(t:&mut Table,sub:ObjId)->Result<(),i64> {
 match t.get(sub) {Ok(KObject::Subscription(s)) if s.waiter.is_none()=>Ok(()),Ok(KObject::Subscription(_))=>Err(err(SYSTEM_EVENT_ERROR_BUSY)),_=>Err(err(SYSTEM_HANDLE_ERROR_INVALID))}
}
pub(crate) fn deliver_in(t:&mut Table,target:&WaitTarget)->Attempt {
 let (mut queue,closed,source)=match t.get(target.sub) {Ok(KObject::Subscription(s))=>(s.queue.clone(),s.closed,s.source),_=>return Attempt::Done(err(SYSTEM_HANDLE_ERROR_INVALID))};
 let mut bytes=[0;MAX_BATCH*RECORD_BYTES];let mut count=0;
 while count<target.capacity {let Some(event)=queue.take() else {break};bytes[count*RECORD_BYTES..(count+1)*RECORD_BYTES].copy_from_slice(&kernel_core::subscription_abi::encode(resync_snapshot_in(t,source,event)));count+=1;}
 if count>0 {
  if !target.buffer.write_at(0,&bytes[..count*RECORD_BYTES]) {return Attempt::Done(err(SYSTEM_MEMORY_ERROR_INVALID_ADDRESS));}
  if let Ok(KObject::Subscription(s))=t.get_mut(target.sub) {s.queue=queue;}
  return Attempt::Done(count as i64);
 }
 let closed=closed || !matches!(t.get(source),Ok(KObject::EventSource(s)) if !s.closed);
 if closed {Attempt::Done(err(SYSTEM_EVENT_ERROR_CLOSED))} else {Attempt::Empty}
}
pub(crate) fn enroll_in(t:&mut Table,sub:ObjId,waiter:(ObjId,u64)) {
 if let Ok(KObject::Subscription(s))=t.get_mut(sub) {assert!(s.waiter.is_none());s.waiter=Some(waiter);}
}
pub(crate) fn release_target_in(t:&mut Table,target:WaitTarget,waiter:Option<(ObjId,u64)>) {
 if let Ok(KObject::Subscription(s))=t.get_mut(target.sub) {if waiter.is_some() && s.waiter==waiter {s.waiter=None;}}
 let _=t.release_internal(target.sub);drop(target);
}
fn notify_in(t:&mut Table,id:ObjId) {
 let waiter=match t.get(id) {Ok(KObject::Subscription(s))=>s.waiter,_=>None};
 if let Some((ring,req))=waiter {crate::ring::poll_subscription_in(t,ring,req);}
}
fn notify_source_in(t:&mut Table,id:ObjId) {
 let mut ids=[None;MAX_SUBSCRIPTIONS as usize];
 if let Ok(KObject::EventSource(s))=t.get(id) {for (slot,id) in ids.iter_mut().zip(&s.subscribers) {*slot=Some(*id);}}
 for id in ids.into_iter().flatten() {notify_in(t,id);}
}

fn report_error(e:Error)->i64 {
 match e {
  Error::Process(e)=>match e {
   ProcError::Handle(kernel_core::object::HandleError::RightsDenied)=>err(SYSTEM_HANDLE_ERROR_RIGHTS_DENIED),
   ProcError::Handle(kernel_core::object::HandleError::TableFull)=>err(SYSTEM_HANDLE_ERROR_TABLE_FULL),
   ProcError::Handle(_)=>err(SYSTEM_HANDLE_ERROR_INVALID),
   _=>err(SYSTEM_ERROR_RIGHTS_DENIED),
  },
  Error::Policy=>err(SYSTEM_ERROR_INVALID_ARGUMENT),Error::Busy=>err(SYSTEM_EVENT_ERROR_BUSY),Error::Closed=>err(SYSTEM_EVENT_ERROR_CLOSED),Error::Quota=>err(SYSTEM_ERROR_QUOTA_EXCEEDED),
  Error::Allocation=>err(SYSTEM_MEMORY_ERROR_OUT_OF_MEMORY),Error::Invalid=>err(SYSTEM_HANDLE_ERROR_INVALID),Error::Exhausted=>err(SYSTEM_ASYNC_ERROR_ID_EXHAUSTED),
 }
}
pub fn sys_source(ptr:u64)->i64 {
 let Some(pid)=proc::current_process() else {return err(SYSTEM_ERROR_RIGHTS_DENIED)};
 let mut bytes=[0;kernel_core::subscription_abi::SOURCE_BYTES];
 if let Err(e)=crate::mm::user::copy_from_user(&mut bytes,ptr,kernel_core::subscription_abi::SOURCE_BYTES) {return crate::ring::user_err(e);}
 let Some(args)=kernel_core::subscription_abi::SourceArgs::decode(&bytes) else {return err(SYSTEM_ERROR_INVALID_ARGUMENT)};
 match args.kind {
  0|1=>match exit_source(pid,crate::syscall::handle_arg(args.target),if args.kind==0 {ObjectType::Process}else{ObjectType::Task}) {Ok(handle)=>handle.raw() as i64,Err(e)=>report_error(e)},
  2=>kobj::with(|t| {
   let irq=match proc::resolve_in(t,pid,crate::syscall::handle_arg(args.target),ObjectType::Interrupt,Rights::SUBSCRIBE) {Ok(id)=>id,Err(e)=>return report_error(Error::Process(e))};
   match crate::interrupt::source_in(t,irq).and_then(|source|proc::grant_in(t,pid,source,ObjectType::EventSource,Rights::READ.union(Rights::SUBSCRIBE)).map_err(Error::Process)) {Ok(handle)=>handle.raw() as i64,Err(e)=>report_error(e)}
  }),
  3=>{
   if args.target!=0 {return err(SYSTEM_ERROR_INVALID_ARGUMENT);}
   kobj::with(|t| match crate::mm::pressure::source_in(t).and_then(|source|proc::grant_in(t,pid,source,ObjectType::EventSource,Rights::READ.union(Rights::SUBSCRIBE)).map_err(Error::Process)) {Ok(handle)=>handle.raw() as i64,Err(e)=>report_error(e)})
  },
  _=>err(SYSTEM_ERROR_UNSUPPORTED),
 }
}
pub fn sys_subscribe(source:u64,ptr:u64)->i64 {
 let Some(pid)=proc::current_process() else {return err(SYSTEM_ERROR_RIGHTS_DENIED)};
 let mut bytes=[0;kernel_core::subscription_abi::SUBSCRIBE_BYTES];
 if let Err(e)=crate::mm::user::copy_from_user(&mut bytes,ptr,kernel_core::subscription_abi::SUBSCRIBE_BYTES) {return crate::ring::user_err(e);}
 let Some(args)=kernel_core::subscription_abi::SubscribeArgs::decode(&bytes) else {return err(SYSTEM_ERROR_INVALID_ARGUMENT)};
 kobj::with(|t| {
  let Some(output)=ptr.checked_add(16) else {return err(SYSTEM_ERROR_INVALID_ARGUMENT)};
  let pin=match proc::pin_user_in(t,pid,output,16,true) {Ok(pin)=>pin,Err(_)=>return err(SYSTEM_MEMORY_ERROR_INVALID_ADDRESS)};
  match subscribe_in(t,pid,crate::syscall::handle_arg(source),args.policy) {
   Ok((handle,snapshot))=>{let mut out=[0;16];out[..8].copy_from_slice(&snapshot.version.to_le_bytes());out[8..].copy_from_slice(&snapshot.value.to_le_bytes());assert!(pin.write_at(0,&out));handle.raw() as i64},
   Err(e)=>report_error(e),
  }
 })
}

fn resync_snapshot_in(t:&Table,source:ObjId,event:Delivery)->Delivery {
 match event {Delivery::Resync(_)=>match t.get(source) {Ok(KObject::EventSource(s))=>Delivery::Resync(s.snapshot),_=>event},_=>event}
}

pub(crate) fn snapshot_in(t:&Table,id:ObjId)->Option<Snapshot> {match t.get(id) {Ok(KObject::EventSource(s))=>Some(s.snapshot),_=>None}}
pub(crate) fn policies_in(t:&mut Table,id:ObjId,policies:u8) {if let Ok(KObject::EventSource(s))=t.get_mut(id){s.policies=policies;}}
