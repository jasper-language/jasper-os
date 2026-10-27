//! 原生 ABI 世代的性质测试（issue #8）：章编解码、兼容性判定与错误分类。
//! Property tests for the native ABI generation: note roundtrip, compatibility and rejection classes.
//!
//! 固定种子由 Proptest 默认策略给出，失败用例可复现；`failure_persistence` 关闭，
//! 避免在仓库里留下随机回归文件（固定回归由本文件的确定性用例承担）。

use kernel_core::abi_version::{self, AbiReject, AbiVersion, NoteError, ProgramAbi, NOTE_BYTES};
use proptest::prelude::*;

/// 任意程序 ABI 要求。
fn arb_program() -> impl Strategy<Value = ProgramAbi> {
    (any::<u16>(), any::<u16>(), any::<u16>()).prop_map(|(major, min_minor, patch)| ProgramAbi {
        major,
        min_minor,
        patch,
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, failure_persistence: None, ..ProptestConfig::default() })]

    /// 编码后再解析必须逐字段还原，且编码长度固定。
    #[test]
    fn note_roundtrip_is_exact(program in arb_program()) {
        let bytes = abi_version::encode_note(program);
        prop_assert_eq!(bytes.len(), NOTE_BYTES);
        prop_assert_eq!(&bytes[12..20], b"JASPER\0\0");
        prop_assert_eq!(abi_version::parse_note(&bytes), Ok(program));
    }

    /// 解析器接受的 28 字节输入必须**恰好**是规范编码：不存在「前缀合法」或忽略保留字节的放行。
    #[test]
    fn accepted_notes_are_exactly_canonical(raw in proptest::array::uniform28(any::<u8>())) {
        if let Ok(program) = abi_version::parse_note(&raw) {
            prop_assert_eq!(abi_version::encode_note(program), raw);
        }
    }

    /// 任意长度不是 28 的输入都必须被拒绝（截断而不是按前缀解释）。
    #[test]
    fn wrong_length_is_always_truncated(raw in proptest::collection::vec(any::<u8>(), 0..128)) {
        prop_assume!(raw.len() != NOTE_BYTES);
        prop_assert_eq!(abi_version::parse_note(&raw), Err(NoteError::Truncated));
    }

    /// 兼容性判定与规格完全一致：同主版本且 min_minor ≤ kernel.minor，Patch 不参与。
    #[test]
    fn compatibility_is_major_then_minor(
        program in arb_program(),
        kmaj in any::<u16>(),
        kmin in any::<u16>(),
        kpatch in any::<u16>(),
    ) {
        let kernel = AbiVersion::new(kmaj, kmin, kpatch);
        let expected = program.major == kmaj && program.min_minor <= kmin;
        prop_assert_eq!(abi_version::compatible(program, kernel).is_ok(), expected);
        match abi_version::compatible(program, kernel) {
            Ok(()) => {
                prop_assert_eq!(program.major, kmaj);
                prop_assert!(program.min_minor <= kmin);
            }
            Err(AbiReject::MajorMismatch { program: p, kernel: k }) => {
                prop_assert!(program.major != kmaj);
                prop_assert_eq!((p, k), (program.major, kmaj));
            }
            Err(AbiReject::MinorTooNew { required, kernel: k }) => {
                prop_assert_eq!(program.major, kmaj);
                prop_assert!(program.min_minor > kmin);
                prop_assert_eq!((required, k), (program.min_minor, kmin));
            }
            Err(other) => prop_assert!(false, "兼容性判定产生未登记的错误类别：{:?}", other),
        }
    }

    /// 没有章与有章的处理必须分开：`check_image` 只在 `None` 时报告 Missing。
    #[test]
    fn check_image_separates_missing_from_incompatible(program in arb_program(), kmaj in any::<u16>(), kmin in any::<u16>()) {
        let kernel = AbiVersion::new(kmaj, kmin, 0);
        prop_assert_eq!(abi_version::check_image(None, kernel), Err(AbiReject::Missing));
        prop_assert_eq!(abi_version::check_image(Some(program), kernel), abi_version::compatible(program, kernel).map(|_| program));
    }

    /// 64 位打包/解包是双射；保留高位非 0 时解包必须拒绝。
    #[test]
    fn packed_roundtrip_and_reserved_bits(major in any::<u16>(), minor in any::<u16>(), patch in any::<u16>(), high in any::<u16>()) {
        let version = AbiVersion::new(major, minor, patch);
        prop_assert_eq!(AbiVersion::unpack(version.packed()), Some(version));
        let reserved = version.packed() | ((high as u64) << 48);
        if high == 0 {
            prop_assert_eq!(AbiVersion::unpack(reserved), Some(version));
        } else {
            prop_assert_eq!(AbiVersion::unpack(reserved), None);
        }
    }
}

/// Miri 只执行确定性路径（Proptest 的随机驱动与收缩在 Miri 下不必要且很慢）。
/// 该用例同时锁定「少一字节必须拒绝」的回归。
#[test]
fn note_roundtrip_under_miri() {
    let program = ProgramAbi { major: 1, min_minor: 9, patch: 4 };
    let bytes = abi_version::encode_note(program);
    assert_eq!(abi_version::parse_note(&bytes), Ok(program));
    assert_eq!(abi_version::parse_note(&bytes[..NOTE_BYTES - 1]), Err(NoteError::Truncated));

    let version = AbiVersion::new(1, 9, 4);
    assert_eq!(AbiVersion::unpack(version.packed()), Some(version));
    assert_eq!(AbiVersion::unpack(version.packed() | (1 << 48)), None);
}
