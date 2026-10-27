//! Kani 有界证明（只在 `cargo kani -p jaso` 下编译）：结构读取里决定偏移与长度的数值部分对任意输入不 panic、
//! 接受的结果落在输入之内并满足 SPEC 的取值与一致性规则。
//!
//! 范围：名字字段的 UTF-8 与字符集判定（`from_utf8`、逐字符检查）不在 Kani 范围内——符号化展开代价过高，
//! 由属性测试与 cargo-fuzz 覆盖；摘要（SHA-256）与整个文件的组合同样不在范围内。

use crate::platform::{numeric_fields, PLATFORM_RECORD};
use crate::{export_name_range, extension_layout, range_within, FloatAbi, Target, EXPORT_SIZE};

/// `range_within` 与宽整数上的数学定义一致（不回绕），对任意 `total`。
#[kani::proof]
fn range_within_is_exact() {
    let (off, len): (u32, u32) = (kani::any(), kani::any());
    let total: usize = kani::any();
    assert_eq!(range_within(off, len, total), off as u128 + len as u128 <= total as u128);
}

/// 扩展段数值布局：任意 ≤ 24 字节的段内容，不 panic；接受时内容起点按 8 对齐、在名字之后不超过 7 字节、在段内。
#[kani::proof]
#[kani::unwind(10)]
fn extension_layout_is_bounded() {
    let b: [u8; 24] = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= b.len());
    if let Some((version, name_len, at)) = extension_layout(&b[..n]) {
        assert!(version >= 1 && name_len >= 1 && name_len <= 64);
        assert!(at % 8 == 0 && at >= 8 + name_len && at < 8 + name_len + 8 && at <= n);
    }
}

/// 平台记录数值字段：任意 64 字节，不 panic；接受时满足托管一致性与原生指针宽度规则。
#[kani::proof]
#[kani::unwind(10)]
fn platform_record_rules() {
    let b: [u8; PLATFORM_RECORD] = kani::any();
    if let Some((isa, pointer_bytes, float_abi, target)) = numeric_fields(&b) {
        let managed = isa.is_none();
        assert_eq!(managed, target == Target::Jvm);
        assert_eq!(managed, pointer_bytes == 0);
        assert_eq!(managed, float_abi == FloatAbi::None);
        if let Some(a) = isa {
            assert_eq!(pointer_bytes as u32, a.pointer_bytes());
        }
        assert!(b[6] == 0 && b[7] == 0);
    }
}

/// 导出项名字范围：任意 40 字节的表与任意在表内的项下标，不 panic；接受时范围非空、≤ 128 字节、在表内。
#[kani::proof]
fn export_entry_is_bounded() {
    let b: [u8; 40] = kani::any();
    let i: u32 = kani::any();
    kani::assume(4 + (i as usize + 1) * EXPORT_SIZE <= b.len());
    if let Some(r) = export_name_range(&b, i) {
        assert!(r.start < r.end && r.end - r.start <= 128 && r.end <= b.len());
    }
}
