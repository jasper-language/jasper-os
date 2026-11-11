//! Linux `utsname` identity encoding for the compatibility service.
//!
//! 兼容服务负责生成稳定的 Linux 身份字段；本模块只负责 ABI 字节布局，不做
//! 用户地址访问，也不把 POSIX 语义加入 Jasper 原生 ABI。

/// Size of one Linux x86_64 `utsname` field.
/// Linux x86_64 `utsname` 单个字段的字节数。
pub const LINUX_UTSNAME_FIELD_BYTES: usize = 65;

/// Size of Linux x86_64 `struct utsname`.
/// Linux x86_64 `struct utsname` 的总字节数。
pub const LINUX_UTSNAME_BYTES: usize = LINUX_UTSNAME_FIELD_BYTES * 6;

const UTSNAME_FIELDS: [&[u8]; 6] = [
    b"Linux",
    b"jasper",
    b"0.0.1",
    b"Jasper-OS Linux ABI 3.1.0",
    b"x86_64",
    b"localdomain",
];

/// Encodes the complete Linux x86_64 `utsname` value.
/// 编码完整的 Linux x86_64 `utsname` 值。
pub const fn linux_utsname() -> [u8; LINUX_UTSNAME_BYTES] {
    let mut encoded = [0u8; LINUX_UTSNAME_BYTES];
    let mut field = 0;
    while field < UTSNAME_FIELDS.len() {
        let value = UTSNAME_FIELDS[field];
        let field_start = field * LINUX_UTSNAME_FIELD_BYTES;
        let mut index = 0;
        while index < value.len() {
            encoded[field_start + index] = value[index];
            index += 1;
        }
        field += 1;
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(bytes: &[u8], index: usize) -> &[u8] {
        let start = index * LINUX_UTSNAME_FIELD_BYTES;
        &bytes[start..start + LINUX_UTSNAME_FIELD_BYTES]
    }

    #[test]
    fn utsname_matches_linux_x86_64_layout_and_identity() {
        let encoded = linux_utsname();
        let expected: [&[u8]; 6] = [
            b"Linux",
            b"jasper",
            b"0.0.1",
            b"Jasper-OS Linux ABI 3.1.0",
            b"x86_64",
            b"localdomain",
        ];
        assert_eq!(encoded.len(), 390);
        for (index, value) in expected.into_iter().enumerate() {
            let field = field(&encoded, index);
            assert_eq!(&field[..value.len()], value);
            assert!(field[value.len()..].iter().all(|byte| *byte == 0));
        }
    }
}
