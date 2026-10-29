#![no_main]
// CpuLimit::charge_batch 与逐个扣费差分：任意上限、桶容量、前序操作（≤ 32 步）、补交 tick 数（≤ 255）。
use kernel_core::sched::limit::{CpuLimit, CpuLimitStats, MAX_BURST_TICKS, UNLIMITED};
libfuzzer_sys::fuzz_target!(|b: [u8; 40]| {
    let limit = u32::from(u16::from_le_bytes([b[0], b[1]])) % UNLIMITED + 1;
    let burst = u32::from(b[2]) % MAX_BURST_TICKS + 1;
    let ticks = u64::from(b[3]);
    let mut base = CpuLimit::new(limit, burst).unwrap();
    for &op in &b[8..] {
        match op % 3 { 0 => base.charge(), 1 => base.on_tick(true, true), _ => base.on_tick(false, op & 4 != 0) }
    }
    let mut batch = base;
    let late = batch.charge_batch(ticks);
    let mut single = base;
    let mut ref_late = 0;
    for i in 0..ticks {
        if i > 0 && !single.eligible() { ref_late += 1; }
        single.charge();
    }
    assert_eq!(late, ref_late);
    assert_eq!(batch.stats().late_ticks, base.stats().late_ticks + late);
    let strip = |s: CpuLimitStats| CpuLimitStats { late_ticks: 0, ..s };
    assert_eq!(strip(batch.stats()), strip(single.stats()));
    assert_eq!(batch.eligible(), single.eligible());
    assert!(late <= ticks.saturating_sub(1));
    if limit == UNLIMITED { assert_eq!(late, 0); }
    // 任意 64 位补交数不 panic，计数饱和。
    let big = u64::from_le_bytes(b[0..8].try_into().unwrap());
    let mut far = batch;
    let l2 = far.charge_batch(big);
    assert!(l2 <= big.saturating_sub(1));
    assert_eq!(far.stats().used_ticks, batch.stats().used_ticks.saturating_add(big));
});
