//! Host adapters call production kernel-core; no hardware emulation claims.

#[cfg(kani)]
#[kani::proof]
#[kani::unwind(10)]
fn limit_admitted_eight_steps() {
    use kernel_core::sched::limit::CpuLimit;
    let rate:u16=kani::any();let burst:u8=kani::any();
    kani::assume(rate>=1 && rate<=1000 && burst>=1 && burst<=64);
    let mut bucket=CpuLimit::new(rate as u32,burst as u32).unwrap();
    for step in 1..=8u64 {
        let wants:bool=kani::any();let run=wants && bucket.eligible();
        bucket.on_tick(run,wants);
        assert!(bucket.stats().used_ticks<=bucket.bound(step));
    }
}
