#![no_main]
libfuzzer_sys::fuzz_target!(|bytes:[u8;16]| {
 let ns=u64::from_le_bytes(bytes[..8].try_into().unwrap());
 let hz=u64::from_le_bytes(bytes[8..].try_into().unwrap());
 let quota=u64::from(bytes[0]%8+1);let budget_period=quota+u64::from(bytes[1]%8);
 let mut budget=kernel_core::ns_budget::Budget::new(0,quota,budget_period).unwrap();
 for i in 0..8u64 {budget.settle(i,i+1,bytes[i as usize]&1!=0).unwrap();assert!(budget.remaining<=quota && budget.next>i+1);}
 let period=hz.max(1);
 let mut credit=kernel_core::timer_units::PeriodicCredit::new(0,period).unwrap();
 let first=credit.advance(ns/2).unwrap();assert_eq!(credit.advance(ns/2),Ok(0));
 let second=credit.advance(ns).unwrap();assert_eq!(u128::from(first)+u128::from(second),u128::from(ns)/u128::from(period));
 if let Ok(count)=kernel_core::timer_units::oneshot_counts(ns,hz) {
  assert!(hz>0 && count>0);
  let product=u128::from(ns)*u128::from(hz);
  assert!(u128::from(count)*1_000_000_000>=product);
  if count>1 {assert!(u128::from(count-1)*1_000_000_000<product);}
 }
});
