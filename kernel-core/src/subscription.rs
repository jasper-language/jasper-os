//! Heap-admitted subscription queue. The caller serializes snapshot/enrollment/publication.
//! This module neither locks nor wakes tasks and owns no kernel object references.
#[cfg(feature = "subscription-dynamic")]
use alloc::collections::VecDeque;
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Snapshot { pub version:u64, pub value:u64 }
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Event { pub first:u64, pub last:u64, pub value:u64 }
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Policy { Events, State, Count }
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Delivery { Event(Event), Resync(Snapshot) }
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Error { Sequence, Exhausted }
impl Snapshot {
    /// Exhaustion leaves the source unchanged. No sentinel sequence numbers.
    pub fn publish(&mut self,value:u64)->Result<Self,Error> {
        let version=self.version.checked_add(1).ok_or(Error::Exhausted)?;
        *self=Self {version,value};Ok(*self)
    }
}
#[cfg(feature = "subscription-dynamic")]
pub struct Queue {
    entries:VecDeque<Event>,latest:Snapshot,resync:bool,policy:Policy,
}
#[cfg(feature = "subscription-dynamic")]
impl Queue {
    pub const fn new(snapshot:Snapshot,policy:Policy)->Self {
        Self {entries:VecDeque::new(),latest:snapshot,resync:false,policy}
    }
    fn require_resync(&mut self) { self.entries.clear();self.resync=true; }
    pub fn accepts(&self,version:u64)->bool {self.latest.version.checked_add(1)==Some(version)}
    pub fn resync_to(&mut self,snapshot:Snapshot) {self.latest=snapshot;self.require_resync();}
    pub fn publish(&mut self,snapshot:Snapshot)->Result<(),Error> {
        if !self.accepts(snapshot.version) {return Err(Error::Sequence);}
        self.latest=snapshot;
        if self.resync {return Ok(());}
        if !self.entries.is_empty() && self.policy!=Policy::Events {
            let old=*self.entries.back().expect("non-empty subscription queue");
            let value=if self.policy==Policy::State {Some(snapshot.value)} else {old.value.checked_add(snapshot.value)};
            match value {
                Some(value)=>*self.entries.back_mut().expect("non-empty subscription queue")=Event {first:old.first,last:snapshot.version,value},
                None=>self.require_resync(),
            }
        } else if self.entries.try_reserve(1).is_err() {
            self.require_resync();
        } else {
            self.entries.push_back(Event {first:snapshot.version,last:snapshot.version,value:snapshot.value});
        }
        Ok(())
    }
    pub fn peek(&self)->Option<Delivery> {
        if self.resync {return Some(Delivery::Resync(self.latest));}
        self.entries.front().copied().map(Delivery::Event)
    }
    /// One caller can repeatedly take up to its batch limit in one locked transaction.
    pub fn take(&mut self)->Option<Delivery> {
        if self.resync {self.resync=false;return Some(Delivery::Resync(self.latest));}
        self.entries.pop_front().map(Delivery::Event)
    }
    pub fn queued(&self)->usize {self.entries.len()}
}

#[cfg(all(test, feature = "subscription-dynamic"))]
mod tests {
 use super::*;
 #[test]
 fn divergence_is_recovered_as_one_resync_snapshot() {
  let mut queue=Queue::new(Snapshot {version:1,value:10},Policy::Events);
  assert!(queue.accepts(2));assert!(!queue.accepts(3));
  queue.publish(Snapshot {version:2,value:20}).unwrap();
  queue.resync_to(Snapshot {version:9,value:90});
  assert_eq!(queue.take(),Some(Delivery::Resync(Snapshot {version:9,value:90})));
  assert_eq!(queue.take(),None);assert!(queue.accepts(10));
 }
}

#[cfg(kani)]
mod proofs {
 use super::*;
 #[kani::proof]
 fn snapshot_publish_never_wraps() {
  let version:u64=kani::any();let value:u64=kani::any();let next:u64=kani::any();
  let mut source=Snapshot {version,value};let old=source;
  let result=source.publish(next);
  if version==u64::MAX {assert_eq!(result,Err(Error::Exhausted));assert_eq!(source,old);}
  else {assert_eq!(result,Ok(Snapshot {version:version+1,value:next}));assert_eq!(source.version,version+1);}
 }
}
