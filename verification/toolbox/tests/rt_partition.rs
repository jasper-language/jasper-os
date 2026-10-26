use kernel_core::rt_partition::{place,utilisation};
use proptest::prelude::*;
proptest! {
 #![proptest_config(ProptestConfig {cases:128,failure_persistence:None,..ProptestConfig::default()})]
 #[test]
 fn placement_matches_wide_reference(a in 0u32..=1000,b in 0u32..=1000,q in 1u32..=1000,p in 1u32..=1000,mask in 0u64..4) {
  let loads=[a,b];let saved=loads;let got=place(&loads,mask,q,p,900);
  if q<=p {
   let added=(u64::from(q)*1000).div_ceil(u64::from(p));
   let expected=(0..2).filter(|c| mask&(1<<c)!=0 && u64::from(loads[*c])+added<=900).min_by_key(|c|(loads[*c],*c));
   prop_assert_eq!(got.ok(),expected);
   prop_assert_eq!(utilisation(q,p).unwrap() as u64,added);
  } else {prop_assert!(got.is_err());}
  prop_assert_eq!(loads,saved);
 }
}
#[test]
fn serialized_admission_adapter() {
 loom::model(|| {
  let loads=loom::sync::Arc::new(loom::sync::Mutex::new([0u32;2]));let other=loads.clone();
  let worker=loom::thread::spawn(move || {let mut l=other.lock().unwrap();let c=place(&*l,3,1,2,900).unwrap();l[c]+=500;});
  {let mut l=loads.lock().unwrap();let c=place(&*l,3,1,2,900).unwrap();l[c]+=500;}
  worker.join().unwrap();assert_eq!(*loads.lock().unwrap(),[500,500]);
 });
}

proptest! {
 #![proptest_config(ProptestConfig {cases:128,failure_persistence:None,..ProptestConfig::default()})]
 #[test]
 fn edf_matches_sorted_reference(items in prop::collection::vec((0usize..128, any::<u64>()),0..64)) {
  let mut sorted=items.clone();sorted.sort_by_key(|(slot,deadline)|(*deadline,*slot));
  prop_assert_eq!(kernel_core::rt_partition::edf(items.iter().copied()),sorted.first().map(|x|x.0));
  let reversed:Vec<_>=items.iter().copied().rev().collect();
  prop_assert_eq!(kernel_core::rt_partition::edf(reversed),sorted.first().map(|x|x.0));
 }
}

#[test]
fn edf_publication_mutex_adapter() {
 loom::model(|| {
  let q=loom::sync::Arc::new(loom::sync::Mutex::new(Vec::new()));let other=q.clone();
  let worker=loom::thread::spawn(move||other.lock().unwrap().push((1,10u64)));
  q.lock().unwrap().push((2,20));worker.join().unwrap();
  assert_eq!(kernel_core::rt_partition::edf(q.lock().unwrap().iter().copied()),Some(1));
 });
}
