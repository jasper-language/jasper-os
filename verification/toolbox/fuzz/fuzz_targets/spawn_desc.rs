#![no_main]
//! issue #1：任意字节作为 spawn 参数块 + 调用者集合 + 登记集合，校验解码与准入规则。
//! Fuzz spawn descriptor decoding and admission over arbitrary bytes.
use kernel_core::spawn_abi::{check, SpawnDesc, SpawnReject, SPAWN_DESC_SIZE};
use kernel_core::syscall_set::{SyscallSet, BYTES, MAX_IDS};
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if data.len() < SPAWN_DESC_SIZE + 2 * BYTES + 8 {
        return;
    }
    let raw: [u8; SPAWN_DESC_SIZE] = data[..SPAWN_DESC_SIZE].try_into().unwrap();
    let caller = SyscallSet::decode(data[SPAWN_DESC_SIZE..SPAWN_DESC_SIZE + BYTES].try_into().unwrap());
    let known = SyscallSet::decode(data[SPAWN_DESC_SIZE + BYTES..SPAWN_DESC_SIZE + 2 * BYTES].try_into().unwrap());
    let probe = u64::from_le_bytes(data[SPAWN_DESC_SIZE + 2 * BYTES..SPAWN_DESC_SIZE + 2 * BYTES + 8].try_into().unwrap());
    let Ok(d) = SpawnDesc::decode(&raw) else {
        assert!(raw[0..8] != SpawnDesc::default().encode()[0..8]);
        return;
    };
    assert_eq!(d.encode(), raw);
    match check(&d, caller, known) {
        Ok(()) => {
            assert!(d.calls.is_subset_of(caller) && d.calls.is_subset_of(known));
            if d.calls.contains(probe) {
                assert!(caller.contains(probe) && known.contains(probe) && probe < MAX_IDS as u64);
            }
        }
        Err(SpawnReject::Escalation) => assert!(!d.calls.is_subset_of(caller) && d.calls.is_subset_of(known)),
        Err(SpawnReject::UnknownCall) => assert!(!d.calls.is_subset_of(known)),
        Err(_) => {}
    }
});
