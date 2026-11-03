#![no_main]
//! issue #4 第一片：句柄创建检查与参照实现的差分；Rights 位运算补链。
use kernel_core::kobj_type::{check_grant, kind_for_handle, GrantCheck, Kind, REGISTRY};
use kernel_core::object::{ObjectType, Rights};
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if data.len() < 10 {
        return;
    }
    let k = Kind::ALL[data[0] as usize % Kind::COUNT];
    let ty = ObjectType::ALL[data[1] as usize % ObjectType::ALL.len()];
    let a = u32::from_le_bytes(data[2..6].try_into().unwrap());
    let b = u32::from_le_bytes(data[6..10].try_into().unwrap());
    let (ra, rb) = (Rights::from_bits_truncate(a), Rights::from_bits_truncate(b));
    let all = Rights::ALL.bits();
    assert_eq!(ra.intersect(rb).bits(), a & b & all);
    assert_eq!(ra.union(rb).bits(), (a | b) & all);
    assert_eq!(ra.contains(rb), (a & all) & (b & all) == (b & all));
    let c = &REGISTRY[k.index()];
    let expect = if c.handle != Some(ty) {
        GrantCheck::WrongType
    } else if ra.bits() & Rights::TRANSFER.bits() != 0 && !c.transferable {
        GrantCheck::NotTransferable
    } else if ra.bits() & !c.rights.bits() != 0 {
        GrantCheck::RightsDenied
    } else {
        GrantCheck::Allowed
    };
    let got = check_grant(k, ty, ra);
    assert_eq!(got, expect);
    // 降权闭包：通过检查的权限取任意子集后仍通过。
    if got == GrantCheck::Allowed {
        assert_eq!(check_grant(k, ty, ra.intersect(rb)), GrantCheck::Allowed);
    }
    assert_eq!(kind_for_handle(ty).map(|x| x == k).unwrap_or(false), c.handle == Some(ty));
});
