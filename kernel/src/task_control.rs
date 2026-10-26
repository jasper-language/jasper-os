//! RT-1 capability entrypoints. No object guard crosses a context switch.
use kernel_core::{object::{ObjectType,Rights},objtable::ObjId,smp::CpuSet};
use crate::{proc,kobj::{self,KObject},sched,syscall::{self,err,table::*},task::TaskId};
fn target(t:&mut kobj::Table,pid:ObjId,raw:u64)->Result<TaskId,i64> {
 let object=proc::resolve_in(t,pid,syscall::handle_arg(raw),ObjectType::Task,Rights::CONTROL).map_err(syscall::proc_err)?;
 let Ok(KObject::Task(task))=t.get(object) else {return Err(err(SYSTEM_HANDLE_ERROR_INVALID));};
 let (id,owner)=(task.task,task.process);
 if !proc::running_in(t,owner) {return Err(err(SYSTEM_ERROR_RIGHTS_DENIED));}
 Ok(id)
}
fn read(ptr:u64)->Result<[u8;32],i64> {
 let mut b=[0;32];crate::mm::user::copy_from_user(&mut b,ptr,32).map_err(crate::ring::user_err)?;Ok(b)
}
pub fn rt_set(ptr:u64)->i64 {
 if !crate::profile::has_capability("sched.realtime") {return err(SYSTEM_ERROR_RIGHTS_DENIED);}
 let Some(pid)=proc::current_process() else {return err(SYSTEM_ERROR_RIGHTS_DENIED);};
 let b=match read(ptr) {Ok(b)=>b,Err(e)=>return e};
 let Some(a)=kernel_core::rt_abi::SetArgs::decode(&b) else {return err(SYSTEM_ERROR_INVALID_ARGUMENT);};
 kobj::with(|t|match target(t,pid,a.target) {
  Ok(id)=>if sched::set_rt(id,a.quota,a.period) {0}else{err(SYSTEM_ERROR_QUOTA_EXCEEDED)},Err(e)=>e,
 })
}
pub fn affinity_set(ptr:u64)->i64 {
 let Some(pid)=proc::current_process() else {return err(SYSTEM_ERROR_RIGHTS_DENIED);};
 let b=match read(ptr) {Ok(b)=>b,Err(e)=>return e};
 let Some(a)=kernel_core::rt_abi::AffinityArgs::decode(&b) else {return err(SYSTEM_ERROR_INVALID_ARGUMENT);};
 let mut set=CpuSet::EMPTY;for c in 0..32 {if a.cpus&(1u64<<c)!=0 {set.insert(c);}}
 let result=kobj::with(|t|match target(t,pid,a.target) {Ok(id)=>sched::set_affinity_deferred(id,set).map_err(|_|err(SYSTEM_ERROR_INVALID_ARGUMENT)),Err(e)=>Err(e)});
 match result {Ok(stay)=>{if !stay {sched::yield_now();}0},Err(e)=>e}
}
pub fn affinity_get(raw:u64)->i64 {
 let Some(pid)=proc::current_process() else {return err(SYSTEM_ERROR_RIGHTS_DENIED);};
 kobj::with(|t|match target(t,pid,raw) {Ok(id)=>sched::task_affinity(id).map(|s|i64::from(s.bits())).unwrap_or(err(SYSTEM_HANDLE_ERROR_INVALID)),Err(e)=>e})
}

pub fn rt_set_ns(ptr:u64)->i64 {
 if !crate::profile::has_capability("sched.realtime"){return err(SYSTEM_ERROR_RIGHTS_DENIED);}
 if !crate::hrtime::enabled(){return err(SYSTEM_ERROR_UNSUPPORTED);}
 let Some(pid)=proc::current_process() else{return err(SYSTEM_ERROR_RIGHTS_DENIED);};
 let mut b=[0;40];if let Err(e)=crate::mm::user::copy_from_user(&mut b,ptr,40){return crate::ring::user_err(e);}
 let Some(a)=kernel_core::rt_abi::SetNsArgs::decode(&b) else{return err(SYSTEM_ERROR_INVALID_ARGUMENT);};
 kobj::with(|t|match target(t,pid,a.target) {Ok(id)=>if sched::set_rt_ns(id,a.quota_ns,a.period_ns){0}else{err(SYSTEM_ERROR_QUOTA_EXCEEDED)},Err(e)=>e})
}
