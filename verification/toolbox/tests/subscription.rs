use kernel_core::subscription::*;
use proptest::prelude::*;
#[derive(Default)]
struct Reference { pending:Vec<Event>, resync:bool, latest:u64 }
impl Reference {
 fn publish(&mut self,version:u64,value:u64,policy:Policy) {
  self.latest=value;
  if self.resync {return;}
  if policy!=Policy::Events && !self.pending.is_empty() {
   let event=&mut self.pending[0];event.last=version;
   if policy==Policy::State {event.value=value;} else if let Some(sum)=event.value.checked_add(value) {event.value=sum;} else {self.pending.clear();self.resync=true;}
  } else if self.pending.len()==4 {self.pending.clear();self.resync=true;}
  else {self.pending.push(Event {first:version,last:version,value});}
 }
 fn take(&mut self,version:u64)->Option<Delivery> {
  if self.resync {self.resync=false;Some(Delivery::Resync(Snapshot {version,value:self.latest}))}
  else if self.pending.is_empty() {None} else {Some(Delivery::Event(self.pending.remove(0)))}
 }
}
proptest! {
 #![proptest_config(ProptestConfig {failure_persistence:None,..ProptestConfig::default()})]
 #[test]
 fn queues_match_independent_vec(policy in 0u8..3, steps in prop::collection::vec((any::<u8>(),any::<u64>()),0..129)) {
  let policy=[Policy::Events,Policy::State,Policy::Count][policy as usize];
  let mut source=Snapshot {version:0,value:0};let mut actual=Queue::<4>::new(source,policy);let mut reference=Reference::default();
  for (op,value) in steps {
   if op%3==0 {prop_assert_eq!(actual.take(),reference.take(source.version));}
   else {let event=source.publish(value).unwrap();actual.publish(event).unwrap();reference.publish(source.version,value,policy);}
   prop_assert_eq!(actual.queued(),reference.pending.len());
  }
  loop {let expected=reference.take(source.version);prop_assert_eq!(actual.take(),expected);if expected.is_none(){break;}}
 }
}
#[test]
fn loom_snapshot_enrollment_publication() {
 loom::model(|| {
  let shared=loom::sync::Arc::new(loom::sync::Mutex::new((Snapshot {version:0,value:0},None::<Queue<2>>)));
  let publisher=shared.clone();
  let thread=loom::thread::spawn(move || {let mut locked=publisher.lock().unwrap();let event=locked.0.publish(7).unwrap();if let Some(queue)=locked.1.as_mut(){queue.publish(event).unwrap();}});
  let snapshot={let mut locked=shared.lock().unwrap();let snapshot=locked.0;locked.1=Some(Queue::new(snapshot,Policy::Events));snapshot};
  thread.join().unwrap();let mut locked=shared.lock().unwrap();
  if snapshot.version==0 {assert_eq!(locked.1.as_mut().unwrap().take(),Some(Delivery::Event(Event {first:1,last:1,value:7})));}
  else {assert_eq!(snapshot.value,7);assert_eq!(locked.1.as_mut().unwrap().take(),None);}
 });
}
