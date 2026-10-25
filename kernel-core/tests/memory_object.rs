// Author: chatgpt. Admission contracts and independent wide-integer quota reference.
use kernel_core::object::ObjectType;
use kernel_core::{memory_object::{Error, MapRange, Usage}, object::Rights};
#[test]
fn memory_object_range_and_rights_contract() {
    let rw = Rights::READ.union(Rights::WRITE).union(Rights::MAP);
    for bits in 0..256 {
        let rights = Rights::from_bits_truncate(bits);
        for writable in [false, true] {
            let result = MapRange::checked(8, 2, 3, 0x1000, (0x1000, 0x10000), 8, rights, writable);
            let need = if writable { 0x83 } else { 0x81 };
            assert_eq!(result.is_ok(), bits & need == need);
        }
    }
    for (object, offset, pages, va, max) in [
        (8,0,0,0x1000,8), (8,7,2,0x1000,8), (8,u64::MAX,1,0x1000,8),
        (u64::MAX,0,u64::MAX,0x1000,u64::MAX), (8,0,1,0x1001,8),
        (8,0,2,0xf000,8), (8,0,1,0,8), (8,0,2,0x1000,1),
    ] { assert_eq!(MapRange::checked(object,offset,pages,va,(0x1000,0x10000),max,rw,true),Err(Error::Range)); }
    assert_eq!(MapRange::checked(8,7,1,0xf000,(0x1000,0x10000),8,rw,true).unwrap().end,0x10000);
}
#[derive(Clone, Debug)]
struct Op { release: bool, mapped: u64, pinned: u64 }
fn replay(ops: &[Op]) -> bool {
    let mut actual = Usage::default(); let mut expected = (0u128,0u128);
    let limits = Usage { mapped: 128, pinned: 64 };
    for op in ops {
        let m = op.mapped as u128; let p = op.pinned as u128;
        let before = actual;
        let accepted = if op.release { m <= expected.0 && p <= expected.1 }
            else { expected.0 + m <= 128 && expected.1 + p <= 64 };
        let result = if op.release { actual.release(op.mapped,op.pinned) }
            else { actual.reserve(op.mapped,op.pinned,limits) };
        if result.is_ok() != accepted { return false; }
        if accepted { if op.release { expected.0 -= m; expected.1 -= p; }
            else { expected.0 += m; expected.1 += p; } }
        else if before != actual { return false; }
        if (actual.mapped as u128,actual.pinned as u128) != expected { return false; }
    }
    true
}
#[test]
fn memory_object_quota_reference_with_shrinking() {
    let mut seed = 0x53484d3151554f54u64; let mut ops = Vec::new();
    for i in 0..20_000 {
        seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
        ops.push(Op { release: seed & 1 == 0, mapped: if i % 41 == 0 { u64::MAX } else { (seed >> 8) % 20 },
            pinned: if i % 43 == 0 { u64::MAX } else { (seed >> 24) % 12 } });
    }
    if !replay(&ops) { let mut i=0; while i<ops.len() { let mut smaller=ops.clone(); smaller.remove(i);
        if !replay(&smaller) { ops=smaller; } else { i+=1; } }
        panic!("minimal failing operations: {ops:?}"); }
    let mut u=Usage { mapped:u64::MAX,pinned:u64::MAX };
    assert_eq!(u.reserve(1,0,u),Err(Error::Quota));
    assert_eq!(u,Usage { mapped:u64::MAX,pinned:u64::MAX });
    assert_eq!(u.release(u64::MAX,u64::MAX),Ok(()));
    assert_eq!(u.release(0,1),Err(Error::Accounting)); assert_eq!(u,Usage::default());
}

#[test]
fn memory_object_is_transferable_leaf_not_address_space() {
    assert!(ObjectType::Memory.is_transferable_v1());
    assert_eq!(ObjectType::Memory.type_name(), "Memory");
    assert!(!ObjectType::AddressSpace.is_transferable_v1());
}
