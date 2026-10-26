use proptest::prelude::*;
use kernel_core::timer_units::{oneshot_counts,Error};
proptest! {
 #![proptest_config(ProptestConfig {cases:128,failure_persistence:None,..ProptestConfig::default()})]
 #[test]
 fn conversion_is_minimal_non_early(ns in any::<u64>(), hz in any::<u64>()) {
  match oneshot_counts(ns,hz) {
   Ok(n)=> {
    prop_assert!(hz>0 && n>0);
    let product=u128::from(ns)*u128::from(hz);
    prop_assert!(u128::from(n)*1_000_000_000>=product);
    if n>1 {prop_assert!(u128::from(n-1)*1_000_000_000<product);}
   },
   Err(Error::Uncalibrated)=>prop_assert_eq!(hz,0),
   Err(Error::OutOfRange)=>prop_assert!(u128::from(ns)*u128::from(hz)>u128::from(u32::MAX)*1_000_000_000),
  }
 }
}
#[test]
fn calibration_publication_mutex_adapter() {
 loom::model(|| {
  let hz=loom::sync::Arc::new(loom::sync::Mutex::new(0u64));let other=hz.clone();
  let writer=loom::thread::spawn(move||*other.lock().unwrap()=3_000_000);
  let sample=*hz.lock().unwrap();
  let result=oneshot_counts(1_000,sample);
  if sample==0 {assert_eq!(result,Err(Error::Uncalibrated));}else{assert_eq!(result,Ok(3));}
  writer.join().unwrap();
 });
}
proptest! {
 #![proptest_config(ProptestConfig {cases:128,failure_persistence:None,..ProptestConfig::default()})]
 #[test]
 fn fractional_credit_matches_absolute_reference(period in 1u64..=u64::MAX,mut times in prop::collection::vec(any::<u64>(),0..32)) {
  times.sort();let mut credit=kernel_core::timer_units::PeriodicCredit::new(0,period).unwrap();
  let mut charged=0u128;
  for now in times {charged+=u128::from(credit.advance(now).unwrap());prop_assert_eq!(charged,u128::from(now)/u128::from(period));}
 }
}
#[test]
fn elapsed_credit_mutex_adapter() {
 loom::model(|| {
  let state=loom::sync::Arc::new(loom::sync::Mutex::new((kernel_core::timer_units::PeriodicCredit::new(0,2).unwrap(),0u64)));
  let other=state.clone();let worker=loom::thread::spawn(move||{let mut x=other.lock().unwrap();if let Ok(n)=x.0.advance(1){x.1+=n;}});
  {let mut x=state.lock().unwrap();if let Ok(n)=x.0.advance(2){x.1+=n;}}
  worker.join().unwrap();let mut x=state.lock().unwrap();assert_eq!(x.0.advance(2),Ok(0));assert_eq!(x.1,1);
 });
}
proptest! {
 #![proptest_config(ProptestConfig {cases:128,failure_persistence:None,..ProptestConfig::default()})]
 #[test]
 fn calibrated_range_conversion(ns in 0u64..=1_000_000_000,hz in 1u64..=1_000_000_000) {
  let n=oneshot_counts(ns,hz).unwrap();let product=u128::from(ns)*u128::from(hz);
  prop_assert!(n>0 && u128::from(n)*1_000_000_000>=product);
  if n>1 {prop_assert!(u128::from(n-1)*1_000_000_000<product);}
 }
}
proptest! {
 #![proptest_config(ProptestConfig {cases:128,failure_persistence:None,..ProptestConfig::default()})]
 #[test]
 fn ns_budget_matches_unit_execution(q in 1u64..=8,p in 1u64..=8,run in prop::collection::vec(any::<bool>(),32)) {
  if q<=p {
   let mut b=kernel_core::ns_budget::Budget::new(0,q,p).unwrap();let mut expected=q;
   for (i,running) in run.into_iter().enumerate() {
    let end=i as u64+1;
    // Boundary refill occurs after execution of the preceding open interval.
    if end%p==0 {expected=q;}else if running {expected=expected.saturating_sub(1);}
    b.settle(end-1,end,running).unwrap();prop_assert_eq!(b.remaining,expected);
    prop_assert!(b.remaining<=q && b.next>end);
   }
  }
 }
}
