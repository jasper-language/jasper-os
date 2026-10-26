use kernel_core::percpu_migration::{CpuPair, Migration, Owner, PiEnqueue, PiMailbox, PiMessage, PiSlot, TaskToken};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, failure_persistence: None, ..ProptestConfig::default() })]
    #[test]
    fn ordered_migration_finishes_at_exactly_one_cpu(source in any::<u16>(), destination in any::<u16>(), commit in any::<bool>()) {
        prop_assume!(source != destination);
        let token=TaskToken { slot: 11, generation: 7 };
        let mut migration=Migration::begin(token,Owner::Cpu(source),destination).unwrap();
        let locks=migration.locks();
        prop_assert_eq!(locks,CpuPair { first: source.min(destination), second: source.max(destination) });
        migration.detach().unwrap(); prop_assert_eq!(migration.owner(),Owner::Transit);
        if commit { migration.commit().unwrap(); prop_assert_eq!(migration.owner(),Owner::Cpu(destination)); }
        else { migration.abort().unwrap(); prop_assert_eq!(migration.owner(),Owner::Cpu(source)); }
    }
    #[test]
    fn stale_pi_never_applies(slot in any::<u32>(), sent in any::<u64>(), live in any::<u64>(), priority in any::<u8>()) {
        prop_assume!(sent != live);
        let mut mailbox=PiSlot::new();
        let msg=PiMessage { token:TaskToken {slot,generation:sent}, round:1, priority };
        prop_assert!(mailbox.publish(msg)); prop_assert_eq!(mailbox.consume(TaskToken {slot,generation:live}),None);
        prop_assert_eq!(mailbox.consume(TaskToken {slot,generation:sent}),None);
    }
    #[test]
    fn bounded_pi_mailbox_keeps_latest_round(rounds in prop::collection::vec(1u64..u64::MAX, 1..64)) {
        let token=TaskToken {slot:9,generation:3};
        let mut q=PiMailbox::<2>::new();
        let mut latest=0;
        for round in rounds {
            let result=q.push(PiMessage {token,round,priority:(round&3) as u8});
            if round>latest { prop_assert!(matches!(result,PiEnqueue::Queued|PiEnqueue::Replaced)); latest=round; }
            else { prop_assert_eq!(result,PiEnqueue::Stale); }
            prop_assert_eq!(q.len(),1);
        }
        prop_assert_eq!(q.pop().unwrap().round,latest);
        prop_assert_eq!(q.pop(),None);
    }
}

#[test]
fn loom_serializes_publish_and_consume_without_double_apply() {
    loom::model(|| {
        let cell=loom::sync::Arc::new(loom::sync::Mutex::new((PiSlot::new(),0u8)));
        let producer=cell.clone();
        let p=loom::thread::spawn(move|| {
            let mut state=producer.lock().unwrap();
            state.0.publish(PiMessage { token:TaskToken {slot:1,generation:2},round:1,priority:8 });
        });
        let consumer=cell.clone();
        let c=loom::thread::spawn(move|| {
            let mut state=consumer.lock().unwrap();
            if state.0.consume(TaskToken {slot:1,generation:2}).is_some() { state.1+=1; }
        });
        p.join().unwrap(); c.join().unwrap();
        let mut state=cell.lock().unwrap();
        if state.0.consume(TaskToken {slot:1,generation:2}).is_some() { state.1+=1; }
        assert_eq!(state.1,1);
    });
}
