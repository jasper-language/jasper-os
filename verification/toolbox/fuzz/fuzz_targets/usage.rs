#![no_main]
use kernel_core::memory_object::Usage;
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if data.len()!=48 { return; }
    let word=|i:usize| u64::from_le_bytes(data[i*8..i*8+8].try_into().unwrap());
    let old=Usage { mapped:word(0),pinned:word(1) };
    let (m,p,lm,lp)=(word(2),word(3),word(4),word(5));
    let mut actual=old;
    let r=actual.reserve(m,p,Usage { mapped:lm,pinned:lp });
    let allowed=old.mapped as u128+m as u128<=lm as u128 && old.pinned as u128+p as u128<=lp as u128;
    assert_eq!(r.is_ok(),allowed);
    if allowed { assert_eq!(actual.mapped as u128,old.mapped as u128+m as u128); assert_eq!(actual.pinned as u128,old.pinned as u128+p as u128);actual.release(m,p).unwrap(); }
    assert_eq!(actual,old);
});
