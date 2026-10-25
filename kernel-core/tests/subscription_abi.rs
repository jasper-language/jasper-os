use kernel_core::subscription_abi::*;
#[test]
fn strict_wait_contract() {
 let mut bytes=[0;WAIT_BYTES];bytes[..2].copy_from_slice(&1u16.to_le_bytes());bytes[2..4].copy_from_slice(&24u16.to_le_bytes());bytes[4..8].copy_from_slice(&16u32.to_le_bytes());
 assert_eq!(WaitArgs::decode(&bytes),Some(WaitArgs {ptr:0,capacity:16}));
 for i in [0,2,16,23] {let mut bad=bytes;bad[i]^=1;assert!(WaitArgs::decode(&bad).is_none());}
 for capacity in [0,17,u32::MAX] {let mut bad=bytes;bad[4..8].copy_from_slice(&capacity.to_le_bytes());assert!(WaitArgs::decode(&bad).is_none());}
 bytes[8..16].copy_from_slice(&u64::MAX.to_le_bytes());assert!(WaitArgs::decode(&bytes).is_none());
}
#[test]
fn resync_is_distinct_from_event() {
 use kernel_core::subscription::*;
 let s=Snapshot {version:4,value:9};let a=encode(Delivery::Resync(s));let b=encode(Delivery::Event(Event {first:4,last:4,value:9}));
 assert_eq!(&a[..8],&2u64.to_le_bytes());assert_eq!(&b[..8],&1u64.to_le_bytes());assert_eq!(&a[8..],&b[8..]);
}
#[test]
fn creation_descriptors_reject_unknown_and_keep_output_separate() {
 let mut source=[0;SOURCE_BYTES];source[..2].copy_from_slice(&1u16.to_le_bytes());source[2..4].copy_from_slice(&24u16.to_le_bytes());source[8..16].copy_from_slice(&0xffff000100000002u64.to_le_bytes());
 assert_eq!(SourceArgs::decode(&source).unwrap().target,0xffff000100000002);
 for i in [0,2,16,23] {let mut bad=source;bad[i]^=1;assert!(SourceArgs::decode(&bad).is_none());}
 source[4..8].copy_from_slice(&4u32.to_le_bytes());assert!(SourceArgs::decode(&source).is_none());
 let mut sub=[0;SUBSCRIBE_BYTES];sub[..2].copy_from_slice(&1u16.to_le_bytes());sub[2..4].copy_from_slice(&32u16.to_le_bytes());sub[8..12].copy_from_slice(&16u32.to_le_bytes());sub[16..].fill(0xff);
 assert!(SubscribeArgs::decode(&sub).is_some());
 for i in [0,2,8,12] {let mut bad=sub;bad[i]^=1;assert!(SubscribeArgs::decode(&bad).is_none());}
}
