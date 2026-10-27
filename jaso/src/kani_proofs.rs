//! Kani 有界证明（只在 `cargo kani -p jaso` 下编译）：结构读取中逐字段解析的那几块对任意输入不 panic，
//! 接受的结果其借用切片都落在输入之内，且满足 SPEC 的取值与一致性规则。
//! 摘要（SHA-256）与整个文件的组合不在 Kani 范围内（由属性测试与 cargo-fuzz 覆盖）。

use crate::platform::{Platform, PLATFORM_RECORD};
use crate::{export_at, parse_extension, range_within, FloatAbi, Target, EXPORT_SIZE};

/// `range_within` 与宽整数上的数学定义一致（不回绕）。
#[kani::proof]
fn range_within_is_exact() {
    let (off, len): (u32, u32) = (kani::any(), kani::any());
    let total: u64 = kani::any();
    kani::assume(total <= u32::MAX as u64 + 1);
    assert_eq!(range_within(off, len, total as usize), off as u64 + len as u64 <= total);
}

/// 扩展段布局：任意 ≤ 24 字节的段内容与任意目录标志，解析不 panic；接受时名字合规且内容起点按 8 对齐、在段内。
#[kani::proof]
#[kani::unwind(25)]
fn extension_layout_is_bounded() {
    let b: [u8; 24] = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= b.len());
    let flags: u32 = kani::any();
    if let Some(e) = parse_extension(&b[..n], flags) {
        let at = n - e.content.len();
        assert!(at % 8 == 0 && at >= 8 + e.name.len() && at <= n);
        assert!(e.version >= 1 && !e.name.is_empty() && e.name.len() <= 16);
        assert!(e.name.bytes().any(|c| c == b'.'));
        assert_eq!(e.critical, flags & 1 != 0);
    }
}

/// 平台记录：任意 64 字节，解析不 panic；接受时满足「isa = 0 ⇔ target = jvm ⇔ pointer_bytes = 0 ⇔ float_abi = none」与指针宽度规则。
#[kani::proof]
#[kani::unwind(34)]
fn platform_record_rules() {
    let b: [u8; PLATFORM_RECORD] = kani::any();
    if let Some(p) = Platform::parse(&b) {
        let managed = p.isa.is_none();
        assert_eq!(managed, p.target == Target::Jvm);
        assert_eq!(managed, p.pointer_bytes == 0);
        assert_eq!(managed, p.float_abi == FloatAbi::None);
        if let Some(a) = p.isa {
            assert_eq!(p.pointer_bytes as u32, a.pointer_bytes());
        }
        assert!(!p.abi.is_empty() && p.abi.len() <= 16 && p.isa_ext.len() <= 32);
    }
}

/// 导出项：任意 40 字节的表与任意下标（项在表内），读取不 panic；接受时名字切片在表内、长度 1–128。
#[kani::proof]
#[kani::unwind(41)]
fn export_entry_is_bounded() {
    let b: [u8; 40] = kani::any();
    let i: u32 = kani::any();
    kani::assume(4 + (i as usize + 1) * EXPORT_SIZE <= b.len());
    if let Some(e) = export_at(&b, i) {
        let start = e.name.as_ptr() as usize - b.as_ptr() as usize;
        assert!(start + e.name.len() <= b.len());
        assert!(!e.name.is_empty() && e.name.len() <= 128);
    }
}
