use kernel_core::extension_abi::*;
#[test]
fn reserved_header_requires_exact_version_and_length() {
    let mut b=[0u8;16]; b[..4].copy_from_slice(&1u32.to_le_bytes()); b[4..8].copy_from_slice(&16u32.to_le_bytes());
    assert!(Header::decode(&b,16).is_some());
    assert!(Header::decode(&b[..8],16).is_none());
    assert!(Header::decode(&b,8).is_none());
    for version in [0,2,u32::MAX] { b[..4].copy_from_slice(&version.to_le_bytes()); assert!(Header::decode(&b,16).is_none()); }
}
#[test]
fn segments_preserve_full_handles_and_reject_unknown_or_wrapping_shapes() {
    let mut b=[0u8;32]; b[8..16].copy_from_slice(&u64::MAX.to_le_bytes()); b[24..32].copy_from_slice(&1u64.to_le_bytes());
    assert_eq!(Segment::decode(&b).unwrap().source,Source::Memory(u64::MAX));
    b[..4].copy_from_slice(&1u32.to_le_bytes()); assert!(Segment::decode(&b).is_none());
    b[8..16].copy_from_slice(&4u64.to_le_bytes()); assert!(Segment::decode(&b).is_some());
    b[16..24].copy_from_slice(&u64::MAX.to_le_bytes()); assert!(Segment::decode(&b).is_none());
    b[16..24].fill(0); b[..4].copy_from_slice(&2u32.to_le_bytes()); assert!(Segment::decode(&b).is_none());
    b[..4].fill(0); b[4]=1; assert!(Segment::decode(&b).is_none());
}
#[test]
fn reserved_service_and_syscall_v2_boundaries() {
    let mut s=[0u8;8]; s[..4].copy_from_slice(&1u32.to_le_bytes());s[4..6].copy_from_slice(&1u16.to_le_bytes());s[6..8].copy_from_slice(&8u16.to_le_bytes());
    assert!(ServiceHeader::decode(&s).is_some());s[6]=7;assert!(ServiceHeader::decode(&s).is_none());
    let mut b=[0u8;40];b[..4].copy_from_slice(&2u32.to_le_bytes());b[4..8].copy_from_slice(&40u32.to_le_bytes());
    for id in [1usize,63,64,127,128,255] { b[8+id/8] |= 1 << (id%8); }
    let set=SyscallSetV2::decode(&b).unwrap();for id in [1,63,64,127,128,255] { assert!(set.contains(id)); }
    for id in [0,2,256,u64::MAX] { assert!(!set.contains(id)); }
    b[8]|=1;assert!(SyscallSetV2::decode(&b).is_none());b[8]&=!1;b[0]=1;assert!(SyscallSetV2::decode(&b).is_none());
    assert_eq!(SQE_REGISTERED_BUFFER,1 << 31);
}
#[test]
fn borrow_and_control_reject_unversioned_or_ambiguous_requests() {
    let mut b=[0u8;BORROW_BYTES];b[..4].copy_from_slice(&1u32.to_le_bytes());b[4..8].copy_from_slice(&48u32.to_le_bytes());
    b[8..16].copy_from_slice(&u64::MAX.to_le_bytes());b[24..32].copy_from_slice(&1u64.to_le_bytes());b[32..40].copy_from_slice(&9u64.to_le_bytes());
    assert_eq!(BorrowDesc::decode(&b).unwrap().memory,u64::MAX);
    b[40]=1;assert!(BorrowDesc::decode(&b).is_none());b[40]=0;
    b[16..24].copy_from_slice(&u64::MAX.to_le_bytes());assert!(BorrowDesc::decode(&b).is_none());
    b[16..24].fill(0);b[32..40].fill(0);assert!(BorrowDesc::decode(&b).is_none());
    let mut c=[0u8;CONTROL_BYTES];c[..4].copy_from_slice(&1u32.to_le_bytes());c[4..8].copy_from_slice(&32u32.to_le_bytes());
    assert!(ControlDesc::decode(&c).is_some());c[24]=1;assert!(ControlDesc::decode(&c).is_none());
}

#[test]
fn sqe_flags_preserve_legacy_invalid_and_explicitly_reject_reserved() {
    assert_eq!(check_sqe_flags(0),Ok(()));
    assert_eq!(check_sqe_flags(SQE_REGISTERED_BUFFER),Err(FlagError::Unsupported));
    for bad in [1,2,0x7fff_ffff,u32::MAX,SQE_REGISTERED_BUFFER|1] { assert_eq!(check_sqe_flags(bad),Err(FlagError::Invalid)); }
}
