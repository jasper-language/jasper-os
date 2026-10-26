//! RT-1 versioned descriptors. Tick units for RT-1; RT-2 must use a new
//! explicit time-unit contract rather than silently changing these fields.
pub const VERSION:u32=1;
pub const BYTES:usize=32;
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
#[repr(C)]
pub struct SetArgs {pub version:u32,pub bytes:u32,pub quota:u32,pub period:u32,pub target:u64,pub reserved:u64}
const _: [();BYTES]=[();core::mem::size_of::<SetArgs>()];
impl SetArgs {
 pub fn decode(b:&[u8;BYTES])->Option<Self> {
  let x=Self {version:u32::from_le_bytes(b[0..4].try_into().ok()?),bytes:u32::from_le_bytes(b[4..8].try_into().ok()?),quota:u32::from_le_bytes(b[8..12].try_into().ok()?),period:u32::from_le_bytes(b[12..16].try_into().ok()?),target:u64::from_le_bytes(b[16..24].try_into().ok()?),reserved:u64::from_le_bytes(b[24..32].try_into().ok()?)};
  if x.version!=VERSION || x.bytes!=BYTES as u32 || x.reserved!=0 || (x.quota==0)!=(x.period==0) || x.quota>x.period {return None;} Some(x)
 }
}
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
#[repr(C)]
pub struct AffinityArgs {pub version:u32,pub bytes:u32,pub target:u64,pub cpus:u64,pub reserved:u64}
const _: [();BYTES]=[();core::mem::size_of::<AffinityArgs>()];
impl AffinityArgs {
 pub fn decode(b:&[u8;BYTES])->Option<Self> {
  let x=Self {version:u32::from_le_bytes(b[0..4].try_into().ok()?),bytes:u32::from_le_bytes(b[4..8].try_into().ok()?),target:u64::from_le_bytes(b[8..16].try_into().ok()?),cpus:u64::from_le_bytes(b[16..24].try_into().ok()?),reserved:u64::from_le_bytes(b[24..32].try_into().ok()?)};
  if x.version!=VERSION || x.bytes!=BYTES as u32 || x.reserved!=0 || x.cpus==0 || x.cpus>u32::MAX as u64 {return None;} Some(x)
 }
}
#[cfg(test)]
mod tests {
 use super::*;
 #[test] fn shapes_units_and_full_width_target() {
  let mut b=[0u8;BYTES];b[..4].copy_from_slice(&1u32.to_le_bytes());b[4..8].copy_from_slice(&32u32.to_le_bytes());b[8..12].copy_from_slice(&2u32.to_le_bytes());b[12..16].copy_from_slice(&10u32.to_le_bytes());b[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
  assert_eq!(SetArgs::decode(&b).unwrap().target,u64::MAX);
  b[8..12].copy_from_slice(&0u32.to_le_bytes());assert!(SetArgs::decode(&b).is_none());
  b[12..16].copy_from_slice(&0u32.to_le_bytes());assert!(SetArgs::decode(&b).is_some());
  for i in [0,4,24] {let mut bad=b;bad[i]^=2;assert!(SetArgs::decode(&bad).is_none());}
 }
 #[test] fn affinity_mask_rejects_truncation() {
  let mut b=[0u8;BYTES];b[..4].copy_from_slice(&1u32.to_le_bytes());b[4..8].copy_from_slice(&32u32.to_le_bytes());b[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
  assert!(AffinityArgs::decode(&b).is_none());b[16..24].copy_from_slice(&u64::from(u32::MAX).to_le_bytes());assert_eq!(AffinityArgs::decode(&b).unwrap().target,u64::MAX);
  b[16..24].copy_from_slice(&(1u64<<32).to_le_bytes());assert!(AffinityArgs::decode(&b).is_none());
 }
}

/// RT-2 independent ns contract; RT-1 SetArgs remains32bytes with tick units.
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
#[repr(C)]
pub struct SetNsArgs {pub version:u32,pub bytes:u32,pub quota_ns:u64,pub period_ns:u64,pub target:u64,pub reserved:u64}
impl SetNsArgs {
 pub const BYTES:usize=40;
 pub fn decode(b:&[u8;40])->Option<Self> {
  let x=Self {version:u32::from_le_bytes(b[..4].try_into().ok()?),bytes:u32::from_le_bytes(b[4..8].try_into().ok()?),quota_ns:u64::from_le_bytes(b[8..16].try_into().ok()?),period_ns:u64::from_le_bytes(b[16..24].try_into().ok()?),target:u64::from_le_bytes(b[24..32].try_into().ok()?),reserved:u64::from_le_bytes(b[32..40].try_into().ok()?)};
  if x.version!=1 || x.bytes!=40 || x.reserved!=0 || (x.quota_ns==0)!=(x.period_ns==0) || x.quota_ns>x.period_ns{return None;}Some(x)
 }
}
#[cfg(test)]mod ns_tests {
 use super::*;
 #[test]fn ns_descriptor_is_independent_and_strict(){
  assert_eq!(core::mem::size_of::<SetNsArgs>(),40);let mut b=[0;40];b[..4].copy_from_slice(&1u32.to_le_bytes());b[4..8].copy_from_slice(&40u32.to_le_bytes());
  b[8..16].copy_from_slice(&1u64.to_le_bytes());b[16..24].copy_from_slice(&10u64.to_le_bytes());b[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
  assert_eq!(SetNsArgs::decode(&b).unwrap().target,u64::MAX);b[32]=1;assert!(SetNsArgs::decode(&b).is_none());b[32]=0;
  b[4..8].copy_from_slice(&32u32.to_le_bytes());assert!(SetNsArgs::decode(&b).is_none());
 }
}
