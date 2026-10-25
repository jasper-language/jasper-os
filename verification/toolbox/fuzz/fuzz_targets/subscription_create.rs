#![no_main]
use kernel_core::subscription_abi::*;
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
 if let Ok(bytes)=<&[u8;SOURCE_BYTES]>::try_from(data) {
  if let Some(source)=SourceArgs::decode(bytes) {assert!(source.kind<=3);assert_eq!(source.target,u64::from_le_bytes(bytes[8..16].try_into().unwrap()));assert_eq!(&bytes[16..24],&[0;8]);}
 }
 if let Ok(bytes)=<&[u8;SUBSCRIBE_BYTES]>::try_from(data) {
  if SubscribeArgs::decode(bytes).is_some() {assert_eq!(&bytes[8..12],&16u32.to_le_bytes());assert_eq!(&bytes[12..16],&[0;4]);}
 }
});
