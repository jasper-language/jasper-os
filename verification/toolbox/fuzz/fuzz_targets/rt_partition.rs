#![no_main]
libfuzzer_sys::fuzz_target!(|data:[u8;5]| {
 let loads=[u32::from(data[0])*4,u32::from(data[1])*4];let saved=loads;
 let q=u32::from(data[2]);let p=u32::from(data[3]);let mask=u64::from(data[4]);
 if let Ok(cpu)=kernel_core::rt_partition::place(&loads,mask,q,p,900) {
  assert!(cpu<2 && mask&(1<<cpu)!=0);
  assert!(loads[cpu]+kernel_core::rt_partition::utilisation(q,p).unwrap()<=900);
 }
 assert_eq!(loads,saved);
 let jobs=[(0,u64::from(data[0])),(1,u64::from(data[1])),(2,u64::from(data[2]))];
 let chosen=kernel_core::rt_partition::edf(jobs).unwrap();
 assert!(jobs.iter().all(|&(slot,d)| (jobs[chosen].1,chosen)<=(d,slot)));
});
