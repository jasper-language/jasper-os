use kernel_core::sched::limit::CpuLimit;
use proptest::prelude::*;
proptest! {
 #![proptest_config(ProptestConfig {cases:128,failure_persistence:None,..ProptestConfig::default()})]
 #[test]
 fn admitted_ticks_preserve_bound(rate in 1u32..=1000,burst in 1u32..=64,work in prop::collection::vec(any::<bool>(),1..129)) {
  let mut bucket=CpuLimit::new(rate,burst).unwrap();let mut used=0;
  for (i,wants) in work.into_iter().enumerate() {
   let run=wants && bucket.eligible();if run {used+=1;}
   bucket.on_tick(run,wants);
   prop_assert_eq!(bucket.stats().used_ticks,used);
   prop_assert!(used<=bucket.bound(i as u64+1));
  }
 }
}
#[test]
fn serialized_charge_snapshot_adapter() {
 loom::model(|| {
  let bucket=loom::sync::Arc::new(loom::sync::Mutex::new(CpuLimit::new(250,4).unwrap()));
  let other=bucket.clone();
  let worker=loom::thread::spawn(move || {other.lock().unwrap().charge();});
  let before=bucket.lock().unwrap().stats().used_ticks;
  worker.join().unwrap();
  let after=bucket.lock().unwrap().stats().used_ticks;
  assert!(before<=after);assert_eq!(after,1);
 });
}
