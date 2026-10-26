#![no_main]
use kernel_core::percpu_migration::{Migration,Owner,PiEnqueue,PiMailbox,PiMessage,PiSlot,TaskToken};
libfuzzer_sys::fuzz_target!(|data:[u8;12]| {
    let source=u16::from_le_bytes([data[0],data[1]]);
    let destination=u16::from_le_bytes([data[2],data[3]]);
    let token=TaskToken {slot:u32::from_le_bytes([data[4],data[5],data[6],data[7]]),generation:u64::from(data[8])};
    if source!=destination {
        let mut m=Migration::begin(token,Owner::Cpu(source),destination).unwrap();
        let locks=m.locks(); assert!(locks.first<locks.second);
        m.detach().unwrap();
        if data[9]&1==0 {m.commit().unwrap();assert_eq!(m.owner(),Owner::Cpu(destination));}
        else {m.abort().unwrap();assert_eq!(m.owner(),Owner::Cpu(source));}
    }
    let mut p=PiSlot::new(); let message=PiMessage {token,round:u64::from(data[10])+1,priority:data[11]};
    assert!(p.publish(message)); let first=p.consume(token); let second=p.consume(token);
    assert_eq!(first,Some(message)); assert!(second.is_none());
    let mut q=PiMailbox::<2>::new(); assert_eq!(q.push(message),PiEnqueue::Queued);
    let newer=PiMessage {round:message.round+1,..message}; assert_eq!(q.push(newer),PiEnqueue::Replaced);
    assert_eq!(q.pop(),Some(newer));assert_eq!(q.pop(),None);
});
