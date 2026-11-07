//! 任意 UTF-8 文本不得让 ABI 契约快照检查 panic。
//! Arbitrary UTF-8 text must never panic the ABI contract snapshot checker.

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = core::str::from_utf8(data) {
        let _ = kernel_core::abi_contract::snapshot_version(text);
        let mut split = text.len() / 2;
        while !text.is_char_boundary(split) {
            split -= 1;
        }
        let (a, b) = text.split_at(split);
        if let Ok(version) = kernel_core::abi_contract::snapshot_version(a) {
            let _ = kernel_core::abi_contract::check_snapshot_set(
                a,
                &[kernel_core::abi_contract::Snapshot { version, text: b }],
            );
        }
    }
});
