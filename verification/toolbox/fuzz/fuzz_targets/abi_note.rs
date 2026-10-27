#![no_main]
//! ABI 章解析的覆盖引导 fuzz（issue #8）：任意输入都不能让解析器 panic，
//! 且只要解析成功，重新编码必须与输入逐字节一致（不存在部分接受）。
use kernel_core::abi_version;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if data.len() < abi_version::NOTE_BYTES {
        assert!(abi_version::parse_note(data).is_err());
        return;
    }
    let head = &data[..abi_version::NOTE_BYTES];
    let tail = &data[abi_version::NOTE_BYTES..];
    // 额外字节必须导致截断拒绝，而不是按前缀解释。
    if !tail.is_empty() {
        assert_eq!(
            abi_version::parse_note(data),
            Err(abi_version::NoteError::Truncated)
        );
    }
    match abi_version::parse_note(head) {
        Ok(program) => assert_eq!(abi_version::encode_note(program), head, "accepted note is not canonical"),
        Err(_) => {}
    }
});
