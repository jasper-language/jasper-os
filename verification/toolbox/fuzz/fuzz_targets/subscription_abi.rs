#![no_main]
use kernel_core::subscription_abi::*;
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
 if data.len()!=WAIT_BYTES {return;}
 let bytes:&[u8;WAIT_BYTES]=data.try_into().unwrap();
 if let Some(args)=WaitArgs::decode(bytes) {assert!((1..=16).contains(&args.capacity));assert!(args.ptr.checked_add(args.capacity as u64*32).is_some());assert_eq!(&bytes[16..24],&[0;8]);}
});
