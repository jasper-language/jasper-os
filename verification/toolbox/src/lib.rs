//! Host adapters call production kernel-core; no hardware emulation claims.

#[cfg(kani)]
#[kani::proof]
#[kani::unwind(10)]
fn budget_admitted_eight_steps() {
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

#[cfg(kani)]
#[kani::proof]
fn rt_partition_admission_safety() {
 let loads:[u16;2]=kani::any();let mask:u8=kani::any();
 let q:u8=kani::any();let p:u8=kani::any();
 let wide=[u32::from(loads[0]),u32::from(loads[1])];let saved=wide;
 if let Ok(c)=kernel_core::rt_partition::place(&wide,u64::from(mask),u32::from(q),u32::from(p),900) {
  assert!(c<2);assert!(mask&(1<<c)!=0);
  let added=kernel_core::rt_partition::utilisation(u32::from(q),u32::from(p)).unwrap();
  assert!(wide[c]+added<=900);
 }
 assert_eq!(wide,saved);
}

#[cfg(kani)]
#[kani::proof]
#[kani::unwind(6)]
fn rt_edf_three_candidates() {
 let deadlines:[u64;3]=kani::any();
 let chosen=kernel_core::rt_partition::edf([(0,deadlines[0]),(1,deadlines[1]),(2,deadlines[2])]).unwrap();
 assert!(chosen<3);
 for i in 0..3 {assert!((deadlines[chosen],chosen)<=(deadlines[i],i));}
}

#[cfg(kani)]
#[kani::proof]
fn timer_counts_non_early() {
 let ns:u16=kani::any();let hz:u32=kani::any();
 if let Ok(count)=kernel_core::timer_units::oneshot_counts(u64::from(ns),u64::from(hz)) {
  assert!(hz>0 && count>0);
  let product=u128::from(ns)*u128::from(hz);
  assert!(u128::from(count)*1_000_000_000>=product);
  if count>1 {assert!(u128::from(count-1)*1_000_000_000<product);}
 }
}

#[cfg(kani)]
#[kani::proof]
fn elapsed_credit_two_units() {
 let a:u8=kani::any();let b:u8=kani::any();
 let lo=u64::from(a.min(b));let hi=u64::from(a.max(b));
 let mut credit=kernel_core::timer_units::PeriodicCredit::new(0,2).unwrap();
 let first=credit.advance(lo).unwrap();assert_eq!(credit.advance(lo),Ok(0));
 let last=credit.advance(hi).unwrap();assert_eq!(first+last,hi/2);
}
#[cfg(kani)]
#[kani::proof]
#[kani::unwind(7)]
fn ns_budget_six_intervals() {
 let mut b=kernel_core::ns_budget::Budget::new(0,2,4).unwrap();
 for i in 0..6 {let run:bool=kani::any();b.settle(i,i+1,run).unwrap();assert!(b.remaining<=2);assert!(b.next>i+1);}
 let next=b.next;b.disable();assert_eq!(b.next,next);assert_eq!(b.remaining,0);
}

#[cfg(kani)]
#[kani::proof]
fn inherited_mutex_two_callers() {
    use kernel_core::inherited_mutex::{Claim, State};
    let first: u8 = kani::any();
    let second: u8 = kani::any();
    kani::assume(first >= 1 && first <= 2 && second >= 1 && second <= 2);
    let mut state = State::new();
    assert_eq!(state.claim(first, false), Claim::Acquired { reused_owner_ref: false });
    let result = state.claim(second, true);
    if first == second { assert_eq!(result, Claim::Recursive); }
    else { assert_eq!(result, Claim::WaitFor(first)); }
    assert_eq!(state.owner(), Some(first));
}
