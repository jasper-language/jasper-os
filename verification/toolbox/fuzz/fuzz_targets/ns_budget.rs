//! 任意预算与结算序列：不崩溃（溢出、下溢、除零）；错误不改状态；剩余不超过配额；边界不后退。
#![no_main]
use kernel_core::ns_budget::{utilisation, Budget};
use libfuzzer_sys::fuzz_target;

fn word(d: &[u8]) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[..8]);
    u64::from_le_bytes(b)
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 24 {
        return;
    }
    let (q, p, now) = (word(data), word(&data[8..]), word(&data[16..]));
    let u = utilisation(q, p);
    let Ok(mut b) = Budget::new(now, q, p) else {
        return;
    };
    assert!(u.is_ok_and(|u| u <= 1000));
    for ev in data[24..].chunks_exact(17) {
        let (start, end) = (word(ev), word(&ev[8..]));
        let old = b;
        match b.settle(start, end, ev[16] & 1 != 0) {
            Ok(()) => {
                assert!(b.remaining <= b.quota);
                assert!(b.next >= old.next);
                assert!(end < b.next);
            }
            Err(_) => assert_eq!(b, old),
        }
    }
});
