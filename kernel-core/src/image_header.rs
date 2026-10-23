//! AArch64 Linux `Image` 头的只读解析与校验（PDA-1）。
//! Read-only parser and validator for the AArch64 Linux `Image` header.
//!
//! # 为什么需要它
//! `fastboot boot` / ABL 交给内核的原始镜像按 Linux arm64 boot protocol 带头部。
//! 内核在跳入主流程之前必须确认这个头确实描述的是本镜像：魔数、大小、字节序与
//! 放置约定任何一项不符，都说明引导器装错了对象或镜像被截断。这里把判断做成
//! 纯函数，既能在启动路径上真实执行，也能在宿主上做固定种子的属性测试。
//!
//! # 边界
//! * 只解析 64 字节固定头，不解析 `code0` / `code1` 指令，不做重定位。
//! * 头来自引导器，按**不可信输入**处理：所有读取都先检查长度，错误是带规范名的枚举，
//!   绝不 panic、绝不越界。
//! * `text_offset` 在 Linux 新版本中已废弃，但仍是装载器使用的字段；这里只校验它与
//!   2 MiB 放置约定一致，不声称内核可被放到任意物理地址（本内核按链接地址运行）。

/// Linux arm64 `Image` 头长度（字节）。
pub const HEADER_LEN: usize = 64;
/// `text_offset` 字段偏移。
pub const TEXT_OFFSET_OFFSET: usize = 0x08;
/// `image_size` 字段偏移。
pub const IMAGE_SIZE_OFFSET: usize = 0x10;
/// `flags` 字段偏移。
pub const FLAGS_OFFSET: usize = 0x18;
/// `magic` 字段偏移。
pub const MAGIC_OFFSET: usize = 0x38;
/// 魔数 `ARM\x64`（小端读出的 u32）。
pub const MAGIC: u32 = 0x644d_5241;
/// 魔数的字节序列。
pub const MAGIC_BYTES: [u8; 4] = *b"ARM\x64";
/// flags bit 0：0 = 小端，1 = 大端。
pub const FLAG_BIG_ENDIAN: u64 = 1 << 0;
/// flags bit 3：1 = 内核可放在物理内存任意 2 MiB 对齐位置。
pub const FLAG_PLACE_ANYWHERE: u64 = 1 << 3;
/// 规范允许的 flags 位；其余位保留，必须为 0。
pub const KNOWN_FLAGS: u64 = FLAG_BIG_ENDIAN | FLAG_PLACE_ANYWHERE;
/// 放置粒度：Linux arm64 要求映像从 2 MiB 边界开始。
pub const IMAGE_ALIGN: u64 = 2 * 1024 * 1024;
/// `text_offset` 的上限：超过 1 TiB 的字段没有现实意义，按损坏处理。
pub const MAX_TEXT_OFFSET: u64 = 1 << 40;

/// 已通过校验的 `Image` 头。
/// A validated arm64 Image header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageHeader {
    /// 装载器应使用的 RAM 基址偏移。
    pub text_offset: u64,
    /// 映像有效字节数（含头部，含 BSS）。
    pub image_size: u64,
    /// 头部的 flags 原始值。
    pub flags: u64,
}

impl ImageHeader {
    /// 是否声明“内核可放在任意物理内存位置”。
    ///
    /// 本内核当前不是位置无关代码，因此启动路径会把这一位为 1 的镜像视为不可安全运行；
    /// 解析器本身仍如实返回字段，拒绝策略由调用者决定。
    pub const fn place_anywhere(self) -> bool {
        self.flags & FLAG_PLACE_ANYWHERE != 0
    }
}

/// `Image` 头校验失败的原因（规范名用于串口日志与接口登记）。
/// Structured rejection reasons for an arm64 Image header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageHeaderError {
    /// 输入短于 64 字节。
    Truncated,
    /// 偏移 0x38 的魔数不是 `ARM\x64`。
    BadMagic,
    /// flags bit 0 声明大端；本内核只构建小端镜像。
    BigEndian,
    /// flags 含保留位。
    UnknownFlags,
    /// `text_offset` 不是 2 MiB 的倍数。
    MisalignedTextOffset,
    /// `text_offset` 超出合理上限。
    TextOffsetTooLarge,
    /// `image_size` 小于头长度。
    ImageTooSmall,
    /// `image_size` 与实际链接的映像跨度不一致。
    ImageSizeMismatch,
    /// 头部声明“可放任意位置”，但本镜像按固定链接地址运行。
    NotRelocatable,
}

impl ImageHeaderError {
    /// 规范错误名（与 `abi/system-ids.txt` 的命名约定一致）。
    pub const fn name(self) -> &'static str {
        match self {
            ImageHeaderError::Truncated => "system.boot.error.image_truncated",
            ImageHeaderError::BadMagic => "system.boot.error.image_bad_magic",
            ImageHeaderError::BigEndian => "system.boot.error.image_big_endian",
            ImageHeaderError::UnknownFlags => "system.boot.error.image_unknown_flags",
            ImageHeaderError::MisalignedTextOffset => "system.boot.error.image_bad_text_offset",
            ImageHeaderError::TextOffsetTooLarge => "system.boot.error.image_text_offset_too_large",
            ImageHeaderError::ImageTooSmall => "system.boot.error.image_too_small",
            ImageHeaderError::ImageSizeMismatch => "system.boot.error.image_size_mismatch",
            ImageHeaderError::NotRelocatable => "system.boot.error.image_not_relocatable",
        }
    }
}

fn le32(bytes: &[u8], offset: usize) -> Option<u32> {
    let s = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn le64(bytes: &[u8], offset: usize) -> Option<u64> {
    let lo = u64::from(le32(bytes, offset)?);
    let hi = u64::from(le32(bytes, offset.checked_add(4)?)?);
    Some(lo | (hi << 32))
}

/// 解析并校验 `bytes` 开头的 `Image` 头。
///
/// `expected_image_size` 是同一镜像在链接视图中的真实跨度（`__image_end - __image_start`）；
/// 头部声明的 `image_size` 必须与它完全一致，才能保证后续读取的内存范围就是已验证的范围。
/// 这里刻意不接受“声明值小于真实值”这种看似安全的放宽：那会让启动路径少校验一段
/// 仍可能被执行的代码。
pub fn parse(bytes: &[u8], expected_image_size: u64) -> Result<ImageHeader, ImageHeaderError> {
    if bytes.len() < HEADER_LEN {
        return Err(ImageHeaderError::Truncated);
    }
    let magic = le32(bytes, MAGIC_OFFSET).ok_or(ImageHeaderError::Truncated)?;
    if magic != MAGIC {
        return Err(ImageHeaderError::BadMagic);
    }
    let header = ImageHeader {
        text_offset: le64(bytes, TEXT_OFFSET_OFFSET).ok_or(ImageHeaderError::Truncated)?,
        image_size: le64(bytes, IMAGE_SIZE_OFFSET).ok_or(ImageHeaderError::Truncated)?,
        flags: le64(bytes, FLAGS_OFFSET).ok_or(ImageHeaderError::Truncated)?,
    };
    if header.flags & FLAG_BIG_ENDIAN != 0 {
        return Err(ImageHeaderError::BigEndian);
    }
    if header.flags & !KNOWN_FLAGS != 0 {
        return Err(ImageHeaderError::UnknownFlags);
    }
    if header.place_anywhere() {
        return Err(ImageHeaderError::NotRelocatable);
    }
    if header.text_offset % IMAGE_ALIGN != 0 {
        return Err(ImageHeaderError::MisalignedTextOffset);
    }
    if header.text_offset > MAX_TEXT_OFFSET {
        return Err(ImageHeaderError::TextOffsetTooLarge);
    }
    if header.image_size < HEADER_LEN as u64 {
        return Err(ImageHeaderError::ImageTooSmall);
    }
    if header.image_size != expected_image_size {
        return Err(ImageHeaderError::ImageSizeMismatch);
    }
    Ok(header)
}

#[cfg(test)]
mod tests {
    use super::*;

    const IMAGE_SIZE: u64 = 0x40_0000;

    /// 构造一个合法头（与链接脚本生成的字段一致）。
    fn valid_header() -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        // code0 / code1 不属于解析范围，留 0。
        out[TEXT_OFFSET_OFFSET..TEXT_OFFSET_OFFSET + 8].copy_from_slice(&0u64.to_le_bytes());
        out[IMAGE_SIZE_OFFSET..IMAGE_SIZE_OFFSET + 8].copy_from_slice(&IMAGE_SIZE.to_le_bytes());
        out[FLAGS_OFFSET..FLAGS_OFFSET + 8].copy_from_slice(&0u64.to_le_bytes());
        out[MAGIC_OFFSET..MAGIC_OFFSET + 4].copy_from_slice(&MAGIC_BYTES);
        out
    }

    /// 固定种子的 xorshift64*：仓库不引入第三方依赖，失败可逐次复现。
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }
    }

    #[test]
    fn accepts_the_link_script_shape() {
        let header = parse(&valid_header(), IMAGE_SIZE).expect("合法头");
        assert_eq!(header.text_offset, 0);
        assert_eq!(header.image_size, IMAGE_SIZE);
        assert_eq!(header.flags, 0);
        assert!(!header.place_anywhere());
    }

    #[test]
    fn every_truncation_below_header_len_is_rejected() {
        let header = valid_header();
        for cut in 0..HEADER_LEN {
            assert_eq!(parse(&header[..cut], IMAGE_SIZE), Err(ImageHeaderError::Truncated), "cut={cut}");
        }
    }

    #[test]
    fn bad_magic_and_fields_are_rejected_with_structured_names() {
        let cases: &[(&str, ImageHeaderError, fn(&mut [u8; HEADER_LEN]))] = &[
            ("magic", ImageHeaderError::BadMagic, |h| h[MAGIC_OFFSET] ^= 0xff),
            ("big endian", ImageHeaderError::BigEndian, |h| {
                let flags = u64::from_le_bytes(h[FLAGS_OFFSET..FLAGS_OFFSET + 8].try_into().unwrap());
                h[FLAGS_OFFSET..FLAGS_OFFSET + 8].copy_from_slice(&(flags | FLAG_BIG_ENDIAN).to_le_bytes());
            }),
            ("unknown flag", ImageHeaderError::UnknownFlags, |h| {
                let flags = u64::from_le_bytes(h[FLAGS_OFFSET..FLAGS_OFFSET + 8].try_into().unwrap());
                h[FLAGS_OFFSET..FLAGS_OFFSET + 8].copy_from_slice(&(flags | (1 << 1)).to_le_bytes());
            }),
            ("place anywhere", ImageHeaderError::NotRelocatable, |h| {
                let flags = u64::from_le_bytes(h[FLAGS_OFFSET..FLAGS_OFFSET + 8].try_into().unwrap());
                h[FLAGS_OFFSET..FLAGS_OFFSET + 8].copy_from_slice(&(flags | FLAG_PLACE_ANYWHERE).to_le_bytes());
            }),
            ("misaligned text", ImageHeaderError::MisalignedTextOffset, |h| {
                h[TEXT_OFFSET_OFFSET..TEXT_OFFSET_OFFSET + 8].copy_from_slice(&0x1000u64.to_le_bytes());
            }),
            ("huge text", ImageHeaderError::TextOffsetTooLarge, |h| {
                h[TEXT_OFFSET_OFFSET..TEXT_OFFSET_OFFSET + 8].copy_from_slice(&(MAX_TEXT_OFFSET + IMAGE_ALIGN).to_le_bytes());
            }),
            ("tiny image", ImageHeaderError::ImageTooSmall, |h| {
                h[IMAGE_SIZE_OFFSET..IMAGE_SIZE_OFFSET + 8].copy_from_slice(&(HEADER_LEN as u64 - 1).to_le_bytes());
            }),
            ("wrong size", ImageHeaderError::ImageSizeMismatch, |h| {
                h[IMAGE_SIZE_OFFSET..IMAGE_SIZE_OFFSET + 8].copy_from_slice(&(IMAGE_SIZE + 1).to_le_bytes());
            }),
        ];
        for (label, expected, mutate) in cases {
            let mut header = valid_header();
            mutate(&mut header);
            let error = parse(&header, IMAGE_SIZE).expect_err(label);
            assert_eq!(error, *expected, "{label}");
            assert!(error.name().starts_with("system.boot.error.image_"), "{label}");
        }
    }

    #[test]
    fn fixed_seed_mutations_never_panic_and_preserve_invariants() {
        // 种子固定：失败时同一个变异序列可以逐字节重放。
        let mut rng = Rng(0x50_4441_494d_4147);
        let base = valid_header();
        let mut accepted = 0usize;
        for round in 0..4000 {
            let mut data = base;
            let flips = 1 + (rng.next() % 4) as usize;
            for _ in 0..flips {
                let offset = (rng.next() % HEADER_LEN as u64) as usize;
                let bit = (rng.next() % 8) as u32;
                data[offset] ^= 1 << bit;
            }
            match parse(&data, IMAGE_SIZE) {
                Ok(header) => {
                    accepted += 1;
                    assert_eq!(header.image_size, IMAGE_SIZE, "round={round}");
                    assert!(header.text_offset % IMAGE_ALIGN == 0, "round={round}");
                    assert!(header.text_offset <= MAX_TEXT_OFFSET, "round={round}");
                    assert_eq!(header.flags & FLAG_BIG_ENDIAN, 0, "round={round}");
                    assert_eq!(header.flags & !KNOWN_FLAGS, 0, "round={round}");
                    assert!(!header.place_anywhere(), "round={round}");
                    assert_eq!(data[MAGIC_OFFSET..MAGIC_OFFSET + 4], MAGIC_BYTES, "round={round}");
                }
                Err(error) => {
                    assert!(error.name().starts_with("system.boot.error.image_"), "round={round}");
                }
            }
        }
        assert!(accepted > 0, "变异仍应保留一部分可接受输入");
    }
}
