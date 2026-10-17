//! ELF64 可执行文件解析（M5.1-pre）：只做解析与校验，不分配内存、不碰硬件。
//! ELF64 executable parsing: validation only, no allocation, no hardware access.
//!
//! # 接受什么
//! * 64 位、小端、`ET_EXEC`（静态链接、固定地址的可执行文件）
//! * 机器类型由调用者给出（每个 ISA 一个值，如 x86_64 = 62），本模块不写死任何架构
//! * 只处理 `PT_LOAD` 段；`PT_INTERP`（需要动态链接器）与 `PT_DYNAMIC` 一律拒绝——
//!   当前不支持动态链接，宁可明确拒绝也不加载一个跑不起来的程序
//!
//! # 校验（任何一条不满足都返回带规范名的错误，装载器绝不做「尽力而为」）
//! * 魔数、类别、字节序、版本、类型、机器类型
//! * 程序头表完整落在文件内，表项大小正确
//! * 每个装载段：`filesz ≤ memsz`；文件数据 `[offset, offset+filesz)` 在文件内；地址不溢出；
//!   `vaddr` 与 `offset` 模页对齐一致（否则无法按页映射）
//! * 装载段之间虚拟地址不重叠；入口点落在某个可执行段内
//! * 段数不超过 [`MAX_SEGMENTS`]
//!
//! 「段地址是否位于用户可用的虚拟窗口」属于装载策略，由内核装载器另行检查。

/// 页大小（段对齐检查用）。
pub const PAGE: u64 = 4096;
/// 最多接受的装载段数。
pub const MAX_SEGMENTS: usize = 16;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const ET_EXEC: u16 = 2;

/// 段权限（来自 `p_flags`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegFlags {
    /// 可读。
    pub read: bool,
    /// 可写。
    pub write: bool,
    /// 可执行。
    pub execute: bool,
}

/// 一个装载段。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    /// 目标虚拟地址。
    pub vaddr: u64,
    /// 内存中的大小（≥ 文件中的大小；多出部分清零，即 BSS）。
    pub memsz: u64,
    /// 文件中的偏移。
    pub offset: u64,
    /// 文件中的大小。
    pub filesz: u64,
    /// 权限。
    pub flags: SegFlags,
}

impl Segment {
    /// 段在文件中的字节。
    pub fn file_bytes<'a>(&self, image: &'a [u8]) -> &'a [u8] {
        &image[self.offset as usize..(self.offset + self.filesz) as usize]
    }
}

/// 解析结果。
#[derive(Debug, Clone, Copy)]
pub struct ElfImage {
    /// 入口地址。
    pub entry: u64,
    segs: [Option<Segment>; MAX_SEGMENTS],
    count: usize,
}

impl ElfImage {
    /// 全部装载段（按程序头顺序）。
    pub fn segments(&self) -> impl Iterator<Item = &Segment> {
        self.segs[..self.count].iter().filter_map(|s| s.as_ref())
    }

    /// 装载段个数。
    pub fn segment_count(&self) -> usize {
        self.count
    }
}

/// ELF 解析错误（`system.elf.error.*`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfError {
    /// 文件太短或某个结构越过文件末尾。
    Truncated,
    /// 不是 ELF，或不是 64 位小端版本 1。
    BadHeader,
    /// 不是静态可执行文件（ET_EXEC）。
    NotExecutable,
    /// 机器类型与目标架构不符。
    WrongMachine,
    /// 需要动态链接（PT_INTERP / PT_DYNAMIC）。
    Dynamic,
    /// 段字段非法（filesz > memsz、地址溢出、对齐不一致）。
    BadSegment,
    /// 装载段相互重叠。
    Overlap,
    /// 入口不在任何可执行段内。
    BadEntry,
    /// 装载段过多。
    TooManySegments,
}

impl ElfError {
    /// 规范错误名。
    pub const fn name(self) -> &'static str {
        match self {
            ElfError::Truncated => "system.elf.error.truncated",
            ElfError::BadHeader => "system.elf.error.bad_header",
            ElfError::NotExecutable => "system.elf.error.not_executable",
            ElfError::WrongMachine => "system.elf.error.wrong_machine",
            ElfError::Dynamic => "system.elf.error.dynamic",
            ElfError::BadSegment => "system.elf.error.bad_segment",
            ElfError::Overlap => "system.elf.error.overlap",
            ElfError::BadEntry => "system.elf.error.bad_entry",
            ElfError::TooManySegments => "system.elf.error.too_many_segments",
        }
    }
}

fn u16_at(b: &[u8], off: usize) -> Result<u16, ElfError> {
    let s = b.get(off..off + 2).ok_or(ElfError::Truncated)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}
fn u32_at(b: &[u8], off: usize) -> Result<u32, ElfError> {
    let s = b.get(off..off + 4).ok_or(ElfError::Truncated)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn u64_at(b: &[u8], off: usize) -> Result<u64, ElfError> {
    let s = b.get(off..off + 8).ok_or(ElfError::Truncated)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Ok(u64::from_le_bytes(a))
}

/// 解析并校验一个 ELF64 静态可执行文件。`machine` 为目标架构的 `e_machine` 值。
pub fn parse(image: &[u8], machine: u16) -> Result<ElfImage, ElfError> {
    if image.len() < 64 {
        return Err(ElfError::Truncated);
    }
    if &image[0..4] != b"\x7fELF" || image[4] != 2 || image[5] != 1 || image[6] != 1 {
        return Err(ElfError::BadHeader);
    }
    if u16_at(image, 16)? != ET_EXEC {
        return Err(ElfError::NotExecutable);
    }
    if u16_at(image, 18)? != machine {
        return Err(ElfError::WrongMachine);
    }
    let entry = u64_at(image, 24)?;
    let phoff = u64_at(image, 32)? as usize;
    let phentsize = u16_at(image, 54)? as usize;
    let phnum = u16_at(image, 56)? as usize;
    if phentsize != 56 {
        return Err(ElfError::BadHeader);
    }
    let table_end = phnum.checked_mul(56).and_then(|n| n.checked_add(phoff)).ok_or(ElfError::Truncated)?;
    if table_end > image.len() {
        return Err(ElfError::Truncated);
    }

    let mut out = ElfImage { entry, segs: [None; MAX_SEGMENTS], count: 0 };
    for i in 0..phnum {
        let ph = phoff + i * 56;
        let ty = u32_at(image, ph)?;
        match ty {
            PT_INTERP | PT_DYNAMIC => return Err(ElfError::Dynamic),
            PT_LOAD => {}
            _ => continue,
        }
        let pflags = u32_at(image, ph + 4)?;
        let offset = u64_at(image, ph + 8)?;
        let vaddr = u64_at(image, ph + 16)?;
        let filesz = u64_at(image, ph + 32)?;
        let memsz = u64_at(image, ph + 40)?;
        if memsz == 0 {
            continue;
        }
        let file_end = offset.checked_add(filesz).ok_or(ElfError::BadSegment)?;
        if filesz > memsz || file_end > image.len() as u64 || vaddr.checked_add(memsz).is_none() || vaddr % PAGE != offset % PAGE {
            return Err(ElfError::BadSegment);
        }
        if out.count == MAX_SEGMENTS {
            return Err(ElfError::TooManySegments);
        }
        let seg = Segment {
            vaddr,
            memsz,
            offset,
            filesz,
            flags: SegFlags { read: pflags & 4 != 0, write: pflags & 2 != 0, execute: pflags & 1 != 0 },
        };
        // 按页粒度检查重叠（装载按页映射，同页两段也算冲突）
        let lo = seg.vaddr - seg.vaddr % PAGE;
        let hi = (seg.vaddr + seg.memsz).div_ceil(PAGE) * PAGE;
        for other in out.segments() {
            let olo = other.vaddr - other.vaddr % PAGE;
            let ohi = (other.vaddr + other.memsz).div_ceil(PAGE) * PAGE;
            if lo < ohi && olo < hi {
                return Err(ElfError::Overlap);
            }
        }
        out.segs[out.count] = Some(seg);
        out.count += 1;
    }
    let entry_ok = out.segments().any(|s| s.flags.execute && entry >= s.vaddr && entry < s.vaddr + s.memsz);
    if !entry_ok {
        return Err(ElfError::BadEntry);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const X86_64: u16 = 62;

    /// 构造一个最小 ELF：一个可执行段（代码）+ 可选的第二段。
    fn build(segs: &[(u32, u64, u64, u64, u64, u32)], entry: u64) -> Vec<u8> {
        // (类型, 偏移, 虚拟地址, filesz, memsz, flags)
        let phoff = 64usize;
        let mut b = vec![0u8; 0x3000];
        b[0..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
        b[6] = 1;
        b[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        b[18..20].copy_from_slice(&X86_64.to_le_bytes());
        b[24..32].copy_from_slice(&entry.to_le_bytes());
        b[32..40].copy_from_slice(&(phoff as u64).to_le_bytes());
        b[54..56].copy_from_slice(&56u16.to_le_bytes());
        b[56..58].copy_from_slice(&(segs.len() as u16).to_le_bytes());
        for (i, &(ty, off, va, fsz, msz, fl)) in segs.iter().enumerate() {
            let p = phoff + i * 56;
            b[p..p + 4].copy_from_slice(&ty.to_le_bytes());
            b[p + 4..p + 8].copy_from_slice(&fl.to_le_bytes());
            b[p + 8..p + 16].copy_from_slice(&off.to_le_bytes());
            b[p + 16..p + 24].copy_from_slice(&va.to_le_bytes());
            b[p + 32..p + 40].copy_from_slice(&fsz.to_le_bytes());
            b[p + 40..p + 48].copy_from_slice(&msz.to_le_bytes());
        }
        b
    }

    const CODE: u64 = 0x1000_0040_0000;

    #[test]
    fn parses_code_and_bss_segments() {
        let img = build(&[(PT_LOAD, 0x1000, CODE, 0x100, 0x100, 5), (PT_LOAD, 0x2000, CODE + 0x1000, 0x10, 0x3000, 6)], CODE + 8);
        let e = parse(&img, X86_64).unwrap();
        assert_eq!(e.entry, CODE + 8);
        assert_eq!(e.segment_count(), 2);
        let segs: Vec<_> = e.segments().copied().collect();
        assert!(segs[0].flags.execute && !segs[0].flags.write);
        assert!(segs[1].flags.write && !segs[1].flags.execute);
        assert_eq!(segs[1].memsz - segs[1].filesz, 0x3000 - 0x10, "BSS 部分");
        assert_eq!(segs[0].file_bytes(&img).len(), 0x100);
    }

    #[test]
    fn rejects_malformed_images() {
        let ok = build(&[(PT_LOAD, 0x1000, CODE, 0x100, 0x100, 5)], CODE);
        assert_eq!(parse(&ok[..40], X86_64).unwrap_err(), ElfError::Truncated);
        let mut bad = ok.clone();
        bad[0] = 0;
        assert_eq!(parse(&bad, X86_64).unwrap_err(), ElfError::BadHeader);
        let mut dyn_exe = ok.clone();
        dyn_exe[16] = 3; // ET_DYN
        assert_eq!(parse(&dyn_exe, X86_64).unwrap_err(), ElfError::NotExecutable);
        assert_eq!(parse(&ok, 183).unwrap_err(), ElfError::WrongMachine, "aarch64 目标拒绝 x86_64 镜像");
        let interp = build(&[(PT_INTERP, 0x1000, 0, 0x10, 0x10, 4), (PT_LOAD, 0x1000, CODE, 0x100, 0x100, 5)], CODE);
        assert_eq!(parse(&interp, X86_64).unwrap_err(), ElfError::Dynamic);
        let big = build(&[(PT_LOAD, 0x1000, CODE, 0x200, 0x100, 5)], CODE);
        assert_eq!(parse(&big, X86_64).unwrap_err(), ElfError::BadSegment, "filesz > memsz");
        let past_end = build(&[(PT_LOAD, 0x2f00, CODE + 0xf00, 0x200, 0x200, 5)], CODE + 0xf00);
        assert_eq!(parse(&past_end, X86_64).unwrap_err(), ElfError::BadSegment, "文件数据越界");
        let misaligned = build(&[(PT_LOAD, 0x1010, CODE, 0x10, 0x10, 5)], CODE);
        assert_eq!(parse(&misaligned, X86_64).unwrap_err(), ElfError::BadSegment, "vaddr/offset 模页不一致");
        let overlap = build(&[(PT_LOAD, 0x1000, CODE, 0x100, 0x100, 5), (PT_LOAD, 0x1000, CODE + 0x80, 0x10, 0x10, 6)], CODE);
        assert!(matches!(parse(&overlap, X86_64), Err(ElfError::BadSegment) | Err(ElfError::Overlap)));
        let entry_in_data = build(&[(PT_LOAD, 0x1000, CODE, 0x100, 0x100, 6)], CODE);
        assert_eq!(parse(&entry_in_data, X86_64).unwrap_err(), ElfError::BadEntry, "入口不在可执行段");
        assert_eq!(ElfError::Dynamic.name(), "system.elf.error.dynamic");
    }
}
