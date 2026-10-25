use kernel_core::subscription::*;
#[test]
fn independent_subscribers_overflow_and_resume() {
    let mut source=Snapshot {version:0,value:0};
    let mut slow=Queue::<2>::new(source,Policy::Events);
    let mut fast=Queue::<2>::new(source,Policy::Events);
    for version in 1..=1000 {
        let event=source.publish(version*7).unwrap();
        slow.publish(event).unwrap();fast.publish(event).unwrap();
        assert_eq!(fast.take(),Some(Delivery::Event(Event {first:version,last:version,value:version*7})));
        assert_eq!(fast.take(),None);assert!(slow.queued()<=2);
        if version%5==0 {assert_eq!(slow.take(),Some(Delivery::Resync(event)));assert_eq!(slow.take(),None);}
    }
    let event=source.publish(1).unwrap();slow.publish(event).unwrap();
    assert_eq!(slow.take(),Some(Delivery::Event(Event {first:1001,last:1001,value:1})));
}
#[test]
fn merging_zero_capacity_and_sequence_rejection() {
    let initial=Snapshot {version:8,value:77};
    let mut state=Queue::<1>::new(initial,Policy::State);
    let mut count=Queue::<1>::new(initial,Policy::Count);
    let mut zero=Queue::<0>::new(initial,Policy::Events);
    for version in 9..=11 {let s=Snapshot {version,value:version};state.publish(s).unwrap();count.publish(s).unwrap();zero.publish(s).unwrap();}
    assert_eq!(state.take(),Some(Delivery::Event(Event {first:9,last:11,value:11})));
    assert_eq!(count.take(),Some(Delivery::Event(Event {first:9,last:11,value:30})));
    assert_eq!(zero.take(),Some(Delivery::Resync(Snapshot {version:11,value:11})));
    assert_eq!(state.publish(Snapshot {version:13,value:3}),Err(Error::Sequence));
    assert_eq!(state.take(),None);
    state.publish(Snapshot {version:12,value:9}).unwrap();
    let mut source=Snapshot {version:u64::MAX,value:4};let old=source;
    assert_eq!(source.publish(9),Err(Error::Exhausted));assert_eq!(source,old);
    let mut count=Queue::<1>::new(initial,Policy::Count);
    count.publish(Snapshot {version:9,value:u64::MAX}).unwrap();count.publish(Snapshot {version:10,value:1}).unwrap();
    assert_eq!(count.take(),Some(Delivery::Resync(Snapshot {version:10,value:1})));
}
