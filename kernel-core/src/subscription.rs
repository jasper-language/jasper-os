//! Bounded subscription queue. The caller serializes snapshot/enrollment/publication.
//! This module neither locks nor wakes tasks and owns no kernel object references.
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
#[derive(Clone)]
pub struct Queue<const N:usize> {
    entries:[Option<Event>;N],head:usize,len:usize,latest:Snapshot,
    resync:bool,policy:Policy,
}
impl<const N:usize> Queue<N> {
    pub const fn new(snapshot:Snapshot,policy:Policy)->Self {
        Self {entries:[None;N],head:0,len:0,latest:snapshot,resync:false,policy}
    }
    fn require_resync(&mut self) { self.entries.fill(None);self.head=0;self.len=0;self.resync=true; }
    pub fn publish(&mut self,snapshot:Snapshot)->Result<(),Error> {
        if self.latest.version.checked_add(1)!=Some(snapshot.version) {return Err(Error::Sequence);}
        self.latest=snapshot;
        if self.resync {return Ok(());}
        if N==0 {self.require_resync();return Ok(());}
        if self.len>0 && self.policy!=Policy::Events {
            let index=(self.head+self.len-1)%N;
            let old=self.entries[index].unwrap();
            let value=if self.policy==Policy::State {Some(snapshot.value)} else {old.value.checked_add(snapshot.value)};
            match value {
                Some(value)=>self.entries[index]=Some(Event {first:old.first,last:snapshot.version,value}),
                None=>self.require_resync(),
            }
        } else if self.len==N { self.require_resync(); }
        else {
            self.entries[(self.head+self.len)%N]=Some(Event {first:snapshot.version,last:snapshot.version,value:snapshot.value});
            self.len+=1;
        }
        Ok(())
    }
    /// One caller can repeatedly take up to its batch limit in one locked transaction.
    pub fn take(&mut self)->Option<Delivery> {
        if self.resync {self.resync=false;return Some(Delivery::Resync(self.latest));}
        if self.len==0 {return None;}
        let event=self.entries[self.head].take().unwrap();
        self.head=(self.head+1)%N;self.len-=1;Some(Delivery::Event(event))
    }
    pub const fn queued(&self)->usize {self.len}
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
