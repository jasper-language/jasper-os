//! Versioned batch wait descriptor and fixed event records; no pointers dereferenced here.
use crate::subscription::{Delivery,Event,Snapshot};
pub const WAIT_BYTES:usize=24;
pub const RECORD_BYTES:usize=32;
pub const MAX_BATCH:usize=16;
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct WaitArgs {pub ptr:u64,pub capacity:u32}
impl WaitArgs {
 pub fn decode(bytes:&[u8;WAIT_BYTES])->Option<Self> {
  if u16::from_le_bytes(bytes[0..2].try_into().ok()?)!=1 || u16::from_le_bytes(bytes[2..4].try_into().ok()?)!=WAIT_BYTES as u16 || bytes[16..24]!=[0;8] {return None;}
  let capacity=u32::from_le_bytes(bytes[4..8].try_into().ok()?);
  if capacity==0 || capacity>MAX_BATCH as u32 {return None;}
  let ptr=u64::from_le_bytes(bytes[8..16].try_into().ok()?);ptr.checked_add(capacity as u64*RECORD_BYTES as u64)?;
  Some(Self {ptr,capacity})
 }
}
pub fn encode(delivery:Delivery)->[u8;RECORD_BYTES] {
 let (kind,first,last,value)=match delivery {Delivery::Event(Event {first,last,value})=>(1u64,first,last,value),Delivery::Resync(Snapshot {version,value})=>(2,version,version,value)};
 let mut bytes=[0;RECORD_BYTES];for (i,n) in [kind,first,last,value].into_iter().enumerate(){bytes[i*8..i*8+8].copy_from_slice(&n.to_le_bytes());}bytes
}

pub const SOURCE_BYTES:usize=24;
pub const SUBSCRIBE_BYTES:usize=32;
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct SourceArgs {pub kind:u32,pub target:u64}
impl SourceArgs {
 pub fn decode(b:&[u8;SOURCE_BYTES])->Option<Self> {
  if b[..2]!=1u16.to_le_bytes() || b[2..4]!=(SOURCE_BYTES as u16).to_le_bytes() || b[16..24]!=[0;8] {return None;}
  let kind=u32::from_le_bytes(b[4..8].try_into().ok()?);if kind>3 {return None;}
  Some(Self {kind,target:u64::from_le_bytes(b[8..16].try_into().ok()?)})
 }
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct SubscribeArgs {pub policy:crate::subscription::Policy}
impl SubscribeArgs {
 pub fn decode(b:&[u8;SUBSCRIBE_BYTES])->Option<Self> {
  if b[..2]!=1u16.to_le_bytes() || b[2..4]!=(SUBSCRIBE_BYTES as u16).to_le_bytes() || b[8..12]!=16u32.to_le_bytes() || b[12..16]!=[0;4] {return None;}
  let policy=match u32::from_le_bytes(b[4..8].try_into().ok()?) {0=>crate::subscription::Policy::Events,1=>crate::subscription::Policy::State,2=>crate::subscription::Policy::Count,_=>return None};
  Some(Self {policy})
 }
}
