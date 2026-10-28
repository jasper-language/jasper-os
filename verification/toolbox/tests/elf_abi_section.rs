//! ELF 节头表与 ABI 章节定位的性质测试（issue #8 第一片补链）。
//! Property tests for ELF section-table parsing and ABI-note lookup in `kernel_core::elf::parse`.
//!
//! 节头表来自不可信的程序映像：任何字节都不能让解析 panic；被接受的 ABI 要求必须恰好来自
//! 文件中一份规范编码的章；节头表损坏、章重复、章类型不符都必须明确拒绝，不能退化成「没有章」。

#[path = "fixture/elf_abi.rs"]
#[allow(dead_code)]
mod fixture;

use fixture::*;
use kernel_core::abi_version::{self, ProgramAbi};
use kernel_core::elf::{self, ElfClass, ElfError};
use proptest::prelude::*;

fn parse(img: &[u8]) -> Result<elf::ElfImage, ElfError> {
    elf::parse(img, FIXTURE_MACHINE, ElfClass::Elf64)
}

fn arb_program() -> impl Strategy<Value = ProgramAbi> {
    (any::<u16>(), any::<u16>(), any::<u16>()).prop_map(|(major, min_minor, patch)| ProgramAbi { major, min_minor, patch })
}

/// 被接受的 ABI 要求必须在映像中以规范编码逐字节出现（不存在「拼出来」的要求）。
fn stamp_is_literally_present(img: &[u8], program: ProgramAbi) -> bool {
    let note = abi_version::encode_note(program);
    img.windows(note.len()).any(|w| w == note)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, failure_persistence: None, ..ProptestConfig::default() })]

    /// 任意合法章：解析结果与盖章值完全一致。
    #[test]
    fn stamped_fixture_roundtrips(program in arb_program()) {
        let img = fixture_elf(&abi_version::encode_note(program));
        prop_assert_eq!(parse(&img).unwrap().abi(), Some(program));
    }

    /// 任意改写节头表、字符串表或章所在区域的若干字节：不 panic；
    /// 结果只能是 Ok（ABI 要求为空或在文件中规范出现）或明确的节/章错误。
    #[test]
    fn mutated_sections_never_panic_and_never_invent_a_stamp(
        program in arb_program(),
        edits in proptest::collection::vec((FIXTURE_SHOFF..FIXTURE_NOTE + 28, any::<u8>()), 1..12),
    ) {
        let mut img = fixture_elf(&abi_version::encode_note(program));
        for (off, byte) in edits {
            img[off] = byte;
        }
        match parse(&img) {
            Ok(parsed) => {
                if let Some(found) = parsed.abi() {
                    prop_assert!(stamp_is_literally_present(&img, found));
                }
            }
            Err(e) => prop_assert!(matches!(e, ElfError::BadSection | ElfError::BadAbiNote), "unexpected {:?}", e),
        }
    }

    /// 任意节头表偏移 / 表项数 / 字符串表下标：越界或不支持的组合一律 BadSection，不 panic。
    #[test]
    fn arbitrary_section_header_fields_are_bounded(
        shoff in any::<u64>(), shentsize in any::<u16>(), shnum in any::<u16>(), shstrndx in any::<u16>(),
    ) {
        let mut img = fixture_elf(&abi_version::encode_note(ProgramAbi::native_requirement()));
        img[40..48].copy_from_slice(&shoff.to_le_bytes());
        img[58..60].copy_from_slice(&shentsize.to_le_bytes());
        img[60..62].copy_from_slice(&shnum.to_le_bytes());
        img[62..64].copy_from_slice(&shstrndx.to_le_bytes());
        let in_bounds = shoff != 0
            && shentsize == 64
            && shnum != 0
            && shstrndx < shnum
            && (shoff as u128) + (shnum as u128) * 64 <= img.len() as u128;
        match parse(&img) {
            Ok(_) => prop_assert!(shoff == 0 || in_bounds),
            Err(e) => {
                prop_assert!(!(shoff == 0), "shoff=0 must mean no section table");
                prop_assert!(matches!(e, ElfError::BadSection | ElfError::BadAbiNote), "unexpected {:?}", e);
            }
        }
    }

    /// 章的 sh_offset / sh_size 任意：越界一律 BadAbiNote；被接受时必须恰为 28 字节规范章。
    #[test]
    fn note_section_extent_is_checked(off in any::<u64>(), size in any::<u64>()) {
        let program = ProgramAbi::native_requirement();
        let mut img = fixture_elf(&abi_version::encode_note(program));
        fixture_section(&mut img, 2, 11, 7, off, size);
        match parse(&img) {
            Ok(parsed) => {
                prop_assert_eq!(size, 28);
                let found = parsed.abi().unwrap();
                let start = off as usize;
                prop_assert_eq!(&img[start..start + 28], &abi_version::encode_note(found)[..]);
            }
            Err(e) => prop_assert_eq!(e, ElfError::BadAbiNote),
        }
    }
}

/// 确定性用例（同时作为 Miri 用例）：缺节头表、重复章、章类型不符、字符串表越界、
/// 节名无 NUL 结尾、扩展字符串表下标，逐项给出精确分类。
#[test]
fn section_rejections_under_miri() {
    let program = ProgramAbi { major: 1, min_minor: 2, patch: 3 };
    let good = fixture_elf(&abi_version::encode_note(program));
    assert_eq!(parse(&good).unwrap().abi(), Some(program));

    // 没有节头表：解析成功但没有章（装载策略层以 Missing 拒绝）。
    let mut none = good.clone();
    none[40..48].copy_from_slice(&0u64.to_le_bytes());
    assert_eq!(parse(&none).unwrap().abi(), None);

    // 节名改成 .shstrtab：没有 ABI 章。
    let mut renamed = good.clone();
    fixture_section(&mut renamed, 2, 1, 7, FIXTURE_NOTE as u64, 28);
    assert_eq!(parse(&renamed).unwrap().abi(), None);

    // 两个同名 ABI 章：拒绝，不能任选其一。
    let mut dup = good.clone();
    dup[60..62].copy_from_slice(&4u16.to_le_bytes());
    fixture_section(&mut dup, 3, 11, 7, FIXTURE_NOTE as u64, 28);
    assert_eq!(parse(&dup).unwrap_err(), ElfError::BadAbiNote);

    // 章节类型为 SHT_NOBITS：拒绝。
    let mut nobits = good.clone();
    fixture_section(&mut nobits, 2, 11, 8, FIXTURE_NOTE as u64, 28);
    assert_eq!(parse(&nobits).unwrap_err(), ElfError::BadAbiNote);

    // 字符串表越出文件：BadSection。
    let mut strtab_oob = good.clone();
    fixture_section(&mut strtab_oob, 1, 1, 3, (FIXTURE_LEN - 4) as u64, 16);
    assert_eq!(parse(&strtab_oob).unwrap_err(), ElfError::BadSection);

    // 节名偏移指向字符串表末尾之后：BadSection。
    let mut name_oob = good.clone();
    fixture_section(&mut name_oob, 2, FIXTURE_NAMES.len() as u32 + 1, 7, FIXTURE_NOTE as u64, 28);
    assert_eq!(parse(&name_oob).unwrap_err(), ElfError::BadSection);

    // 字符串表截短到最后一个名字的 NUL 之前：名字无结尾，BadSection。
    let mut unterminated = good.clone();
    fixture_section(&mut unterminated, 1, 1, 3, FIXTURE_STRTAB as u64, FIXTURE_NAMES.len() as u64 - 1);
    assert_eq!(parse(&unterminated).unwrap_err(), ElfError::BadSection);

    // 扩展字符串表下标（SHN_XINDEX）：不支持，明确拒绝。
    let mut xindex = good.clone();
    xindex[62..64].copy_from_slice(&0xffffu16.to_le_bytes());
    assert_eq!(parse(&xindex).unwrap_err(), ElfError::BadSection);

    // 章内容少一字节（节长度 27）：BadAbiNote。
    let mut short = good;
    fixture_section(&mut short, 2, 11, 7, FIXTURE_NOTE as u64, 27);
    assert_eq!(parse(&short).unwrap_err(), ElfError::BadAbiNote);
}
