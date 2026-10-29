#![no_main]
// counter_ns 与 drill 判据对任意输入的差分与性质。
libfuzzer_sys::fuzz_target!(|b: [u8; 40]| {
    let w = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
    let (e, hz, d) = (w(0), w(8), w(16));
    let r = kernel_core::timer_units::counter_ns(e, hz);
    if hz == 0 {
        assert_eq!(r, None);
    } else {
        let p = u128::from(e) * 1_000_000_000;
        match r {
            Some(n) => {
                assert!(u128::from(n) * u128::from(hz) <= p && p < (u128::from(n) + 1) * u128::from(hz));
                if let Some(m) = kernel_core::timer_units::counter_ns(e.saturating_add(d), hz) { assert!(m >= n); }
            }
            None => assert!(p / u128::from(hz) > u128::from(u64::MAX)),
        }
    }
    let (q, rem) = (u32::from_le_bytes(b[24..28].try_into().unwrap()), u32::from_le_bytes(b[28..32].try_into().unwrap()));
    let (s, n) = (w(32) >> 1, w(32) >> 1 ^ u64::from(b[0]));
    let ok = kernel_core::drill::refill_consistent(q, rem, s, n);
    if ok { assert!(rem >= 1 && rem <= q && u64::from(q - rem) <= n.saturating_sub(s)); }
    if n <= s { assert_eq!(ok, rem == q && q >= 1); }
    let go = kernel_core::drill::preempt_step_continues(q, rem, e, d, hz, w(32));
    if !go { assert!(q >= rem); }
    if q >= rem && (hz >= w(32) || e >= d) { assert!(!go); }
    let (now, end, cut, want) = (e, d, hz, u32::from(b[1] & 15));
    let go = kernel_core::drill::hog_continues(now, end, rem, want, cut);
    assert_eq!(go, now < end || (rem.count_ones() < want && now < cut));
    if now >= end && (now >= cut || rem.count_ones() >= want) { assert!(!go); }
    if want == 0 { assert_eq!(go, now < end); }
    // dispatch_mask：40 字节当作至多 40 个处理器的运行 tick（每字节一核，长度取自首字节），逐位与参考一致。
    let len = usize::from(b[0]) % 41;
    let busy: Vec<u64> = b[..len].iter().map(|&x| u64::from(x)).collect();
    let m = kernel_core::drill::dispatch_mask(&busy);
    for i in 0..32 { assert_eq!(m >> i & 1 == 1, i < len && busy[i] > 0); }
    assert!(m.count_ones() as usize <= len.min(32));
});
