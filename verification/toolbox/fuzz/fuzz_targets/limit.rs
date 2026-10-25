#![no_main]
use kernel_core::sched::limit::CpuLimit;
libfuzzer_sys::fuzz_target!(|data:&[u8]| {
 if data.len()<3 {return;}
 let rate=1+u16::from_le_bytes([data[0],data[1]]) as u32%1000;
 let mut bucket=CpuLimit::new(rate,1+data[2] as u32%64).unwrap();let mut used=0;
 for (i,b) in data[3..].iter().take(128).enumerate() {
  let wants=b&1!=0;let run=wants && bucket.eligible();if run {used+=1;}
  bucket.on_tick(run,wants);assert_eq!(bucket.stats().used_ticks,used);
  assert!(used<=bucket.bound(i as u64+1));
 }
});
