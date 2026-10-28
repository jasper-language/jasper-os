#![no_main]
//! ELF 节头表 / ABI 章定位的覆盖引导 fuzz（issue #8）：
//! 首字节为偶数时把其余字节当作完整映像；为奇数时以合法夹具为底，按 (偏移, 字节) 对改写。
//! 两种模式下解析都不能 panic；被接受的 ABI 要求必须在映像中以规范编码逐字节出现；
//! 错误只能是解析器登记过的分类。
use kernel_core::abi_version;
use kernel_core::elf::{self, ElfClass};

#[allow(dead_code)]
mod fixture {
    include!("../../tests/fixture/elf_abi.rs");
}
use fixture::*;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else { return };
    let img = if mode & 1 == 0 {
        rest.to_vec()
    } else {
        let mut img = fixture_elf(&abi_version::encode_note(abi_version::ProgramAbi::native_requirement()));
        for pair in rest.chunks_exact(3) {
            let off = u16::from_le_bytes([pair[0], pair[1]]) as usize % FIXTURE_LEN;
            img[off] = pair[2];
        }
        img
    };
    if let Ok(parsed) = elf::parse(&img, FIXTURE_MACHINE, ElfClass::Elf64) {
        if let Some(program) = parsed.abi() {
            let note = abi_version::encode_note(program);
            assert!(img.windows(note.len()).any(|w| w == note), "accepted stamp not present in image");
        }
    }
});
