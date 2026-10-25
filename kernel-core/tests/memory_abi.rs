// Author: chatgpt. Layout and strict version/length/flag contracts; address semantics checked separately.
use kernel_core::memory_abi::{MapArgs,MAP_ARGS_BYTES};
#[test]
fn shm_map_descriptor_layout_roundtrip() {
    assert_eq!(core::mem::size_of::<MapArgs>(),40);
    assert_eq!(core::mem::offset_of!(MapArgs,address),8);
    assert_eq!(core::mem::offset_of!(MapArgs,offset_pages),16);
    assert_eq!(core::mem::offset_of!(MapArgs,pages),24);
    assert_eq!(core::mem::offset_of!(MapArgs,flags),32);
    for v in [0,1,4096,u32::MAX as u64,u64::MAX] {
        for writable in [false,true] {
            let a=MapArgs::new(v,v.rotate_left(17),v.rotate_left(33),writable);
            let b=a.encode(); assert_eq!(MapArgs::decode(&b),Some(a));
            assert_eq!(&b[8..16],&v.to_le_bytes());
        }
    }
}
#[test]
fn shm_map_descriptor_rejects_unknown_fields() {
    let original=MapArgs::new(0x1000,0,1,true).encode();
    for version in [0u32,2,u32::MAX] {
        let mut b=original;b[0..4].copy_from_slice(&version.to_le_bytes());assert_eq!(MapArgs::decode(&b),None);
    }
    for len in [0,MAP_ARGS_BYTES as u32-1,MAP_ARGS_BYTES as u32+1,u32::MAX] {
        let mut b=original;b[4..8].copy_from_slice(&len.to_le_bytes());assert_eq!(MapArgs::decode(&b),None);
    }
    for bit in 1..32 { let mut b=original;b[32..36].copy_from_slice(&(1u32<<bit).to_le_bytes());assert_eq!(MapArgs::decode(&b),None); }
    for bit in 0..32 { let mut b=original;b[36..40].copy_from_slice(&(1u32<<bit).to_le_bytes());assert_eq!(MapArgs::decode(&b),None); }
}
