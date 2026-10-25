#![no_main]
use kernel_core::subscription::*;
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
 let mut source=Snapshot {version:0,value:0};let mut q=Queue::<2>::new(source,Policy::Events);
 let mut cursor=0u64;
 for byte in data.iter().take(256) {
  if byte&1==0 {let event=source.publish(*byte as u64).unwrap();q.publish(event).unwrap();}
  else if let Some(delivery)=q.take() {match delivery {
   Delivery::Resync(snapshot)=>{assert!(snapshot.version>=cursor);cursor=snapshot.version;},
   Delivery::Event(event)=>{assert_eq!(event.first,cursor+1);assert_eq!(event.first,event.last);cursor=event.last;}
  }}
  assert!(q.queued()<=2);
 }
});
