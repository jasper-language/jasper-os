//! 从位置无关的 ELF64 映像（static-pie）打包 `.jaso`。
//! Packs a position-independent ELF64 image into a `.jaso` file.
//!
//! # 输入要求
//! * ELF64、小端、`ET_DYN`（位置无关），`e_machine` 与目标指令集一致
//! * 可装入段（`PT_LOAD`）互不共用页；段起点按页向下取整，前面补零（不把相邻段的字节带进来）
//! * 动态重定位只允许「基址 + 加数」一种（x86_64 `R_X86_64_RELATIVE`、AArch64 `R_AARCH64_RELATIVE`、
//!   RISC-V `R_RISCV_RELATIVE`）；出现其它种类、`DT_REL`、PLT 重定位或 `DT_NEEDED` 即拒绝——
//!   模块不按名字导入任何外部符号，宿主能力只经 [`crate::HostV0`] 表提供
//! * 导出 = 动态符号表中已定义的全局函数；动态符号表里有未定义的符号即拒绝

use alloc::string::String;
use alloc::vec::Vec;

use crate::build::{Builder, SegmentIn};
use crate::{Arch, JasoError, Stage, FLAG_R, FLAG_W, FLAG_X, PAGE};

/// 打包错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackError {
    /// 不是受支持的 ELF（附原因）。
    BadElf(&'static str),
    /// ELF 的机器类型与目标指令集不符。
    WrongMachine { elf: u16, want: Arch },
    /// 不支持的动态重定位种类。
    UnsupportedReloc(u32),
    /// 不支持的动态段条目（如 `DT_NEEDED`、PLT 重定位）。
    UnsupportedDynamic(u64),
    /// 动态符号表中有未定义的符号。
    UndefinedSymbol(String),
    /// 两个可装入段共用了同一页。
    SegmentsSharePage,
    /// 生成的文件没有通过格式校验。
    Format(JasoError),
}

fn rd<const N: usize>(b: &[u8], o: usize) -> Result<[u8; N], PackError> {
    b.get(o..o.checked_add(N).ok_or(PackError::BadElf("偏移溢出"))?)
        .ok_or(PackError::BadElf("越界"))?
        .try_into()
        .map_err(|_| PackError::BadElf("越界"))
}
fn u16_(b: &[u8], o: usize) -> Result<u16, PackError> {
    Ok(u16::from_le_bytes(rd(b, o)?))
}
fn u32_(b: &[u8], o: usize) -> Result<u32, PackError> {
    Ok(u32::from_le_bytes(rd(b, o)?))
}
fn u64_(b: &[u8], o: usize) -> Result<u64, PackError> {
    Ok(u64::from_le_bytes(rd(b, o)?))
}

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const SHT_DYNSYM: u32 = 11;
const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const DT_PLTRELSZ: u64 = 2;
const DT_RELA: u64 = 7;
const DT_RELASZ: u64 = 8;
const DT_RELAENT: u64 = 9;
const DT_REL: u64 = 17;
const DT_JMPREL: u64 = 23;

fn machine(a: Arch) -> u16 {
    match a {
        Arch::X86_64 => 62,
        Arch::Aarch64 => 183,
        Arch::Riscv64 | Arch::Riscv32 => 243,
    }
}

fn relative_type(a: Arch) -> u32 {
    match a {
        Arch::X86_64 => 8,
        Arch::Aarch64 => 1027,
        Arch::Riscv64 | Arch::Riscv32 => 3,
    }
}

struct Load {
    vaddr: u64,
    offset: u64,
    filesz: u64,
    memsz: u64,
    flags: u32,
}

/// 由 ELF 虚拟地址找文件偏移（只在可装入段的文件部分内）。
fn file_off(loads: &[Load], va: u64, len: u64) -> Result<usize, PackError> {
    for l in loads {
        if va >= l.vaddr && va.checked_add(len).is_some_and(|e| e <= l.vaddr + l.filesz) {
            return usize::try_from(l.offset + (va - l.vaddr)).map_err(|_| PackError::BadElf("偏移过大"));
        }
    }
    Err(PackError::BadElf("地址不在任何可装入段的文件部分内"))
}

/// 把 ELF 映像打包为 `.jaso`。
pub fn from_elf(elf: &[u8], manifest: &str, arch: Arch, stage: Stage) -> Result<Vec<u8>, PackError> {
    if elf.get(..4) != Some(b"\x7fELF") {
        return Err(PackError::BadElf("魔数"));
    }
    if elf.get(4) != Some(&2) || elf.get(5) != Some(&1) {
        return Err(PackError::BadElf("只支持 ELF64 小端"));
    }
    if u16_(elf, 16)? != 3 {
        return Err(PackError::BadElf("不是位置无关映像（ET_DYN）"));
    }
    let m = u16_(elf, 18)?;
    if m != machine(arch) {
        return Err(PackError::WrongMachine { elf: m, want: arch });
    }
    let (phoff, shoff) = (u64_(elf, 32)? as usize, u64_(elf, 40)? as usize);
    let (phentsize, phnum) = (u16_(elf, 54)? as usize, u16_(elf, 56)? as usize);
    let (shentsize, shnum) = (u16_(elf, 58)? as usize, u16_(elf, 60)? as usize);
    if phentsize != 56 || (shnum > 0 && shentsize != 64) {
        return Err(PackError::BadElf("表项大小"));
    }

    let mut loads = Vec::new();
    let mut dynamic: Option<(u64, u64)> = None;
    for i in 0..phnum {
        let o = phoff + i * phentsize;
        let (ty, pf) = (u32_(elf, o)?, u32_(elf, o + 4)?);
        let (offset, vaddr, filesz, memsz) = (u64_(elf, o + 8)?, u64_(elf, o + 16)?, u64_(elf, o + 32)?, u64_(elf, o + 40)?);
        match ty {
            PT_LOAD if memsz > 0 => {
                if filesz > memsz || offset.checked_add(filesz).is_none_or(|e| e > elf.len() as u64) {
                    return Err(PackError::BadElf("可装入段越界"));
                }
                // ELF 的 p_flags：X=1、W=2、R=4
                let mut flags = 0;
                if pf & 4 != 0 {
                    flags |= FLAG_R;
                }
                if pf & 2 != 0 {
                    flags |= FLAG_W;
                }
                if pf & 1 != 0 {
                    flags |= FLAG_X;
                }
                loads.push(Load { vaddr, offset, filesz, memsz, flags });
            }
            PT_DYNAMIC => dynamic = Some((offset, filesz)),
            _ => {}
        }
    }
    if loads.is_empty() {
        return Err(PackError::BadElf("没有可装入段"));
    }

    // 映像段：起点按页向下取整，前面补零
    let mut segments = Vec::new();
    for l in &loads {
        let pad = l.vaddr % PAGE as u64;
        let start = l.vaddr - pad;
        let vaddr = u32::try_from(start).map_err(|_| PackError::BadElf("地址超出 32 位"))?;
        let mem_size = u32::try_from(l.memsz + pad).map_err(|_| PackError::BadElf("段过大"))?;
        let mut data = alloc::vec![0u8; pad as usize];
        data.extend_from_slice(&elf[l.offset as usize..(l.offset + l.filesz) as usize]);
        segments.push(SegmentIn { vaddr, mem_size, flags: l.flags, data });
    }
    for (i, a) in segments.iter().enumerate() {
        for b in &segments[i + 1..] {
            let span = |s: &SegmentIn| (s.vaddr as u64, s.vaddr as u64 + (s.mem_size as u64).div_ceil(PAGE as u64) * PAGE as u64);
            let (x, y) = (span(a), span(b));
            if x.0 < y.1 && y.0 < x.1 {
                return Err(PackError::SegmentsSharePage);
            }
        }
    }

    // 动态段：只接受 RELA 形式的「基址 + 加数」重定位
    let mut relocs = Vec::new();
    if let Some((doff, dsz)) = dynamic {
        let (mut rela, mut relasz, mut relaent) = (0u64, 0u64, 24u64);
        let mut o = doff as usize;
        let end = (doff + dsz) as usize;
        while o + 16 <= end {
            let (tag, val) = (u64_(elf, o)?, u64_(elf, o + 8)?);
            match tag {
                DT_NULL => break,
                DT_RELA => rela = val,
                DT_RELASZ => relasz = val,
                DT_RELAENT => relaent = val,
                DT_NEEDED | DT_REL | DT_JMPREL => return Err(PackError::UnsupportedDynamic(tag)),
                DT_PLTRELSZ if val != 0 => return Err(PackError::UnsupportedDynamic(tag)),
                _ => {}
            }
            o += 16;
        }
        if relasz > 0 {
            if relaent != 24 || relasz % 24 != 0 {
                return Err(PackError::BadElf("RELA 表项大小"));
            }
            let base = file_off(&loads, rela, relasz)?;
            for i in 0..(relasz / 24) as usize {
                let e = base + i * 24;
                let (off, info, addend) = (u64_(elf, e)?, u64_(elf, e + 8)?, u64_(elf, e + 16)?);
                let ty = (info & 0xFFFF_FFFF) as u32;
                if ty != relative_type(arch) || info >> 32 != 0 {
                    return Err(PackError::UnsupportedReloc(ty));
                }
                let off = u32::try_from(off).map_err(|_| PackError::BadElf("重定位位置超出 32 位"))?;
                relocs.push((off, addend));
            }
        }
    }

    // 导出：动态符号表中已定义的全局函数；有未定义符号即拒绝
    let mut exports = Vec::new();
    for i in 0..shnum {
        let o = shoff + i * shentsize;
        if u32_(elf, o + 4)? != SHT_DYNSYM {
            continue;
        }
        let (symoff, symsz, link, entsize) = (u64_(elf, o + 24)? as usize, u64_(elf, o + 32)? as usize, u32_(elf, o + 40)? as usize, u64_(elf, o + 56)? as usize);
        if entsize != 24 {
            return Err(PackError::BadElf("符号表项大小"));
        }
        let so = shoff + link * shentsize;
        let (stroff, strsz) = (u64_(elf, so + 24)? as usize, u64_(elf, so + 32)? as usize);
        let strtab = elf.get(stroff..stroff + strsz).ok_or(PackError::BadElf("字符串表越界"))?;
        for k in 1..symsz / 24 {
            let s = symoff + k * 24;
            let (name, info, shndx, value) = (u32_(elf, s)? as usize, elf[s + 4], u16_(elf, s + 6)?, u64_(elf, s + 8)?);
            let raw = strtab.get(name..).ok_or(PackError::BadElf("符号名越界"))?;
            let n = raw.iter().position(|&c| c == 0).ok_or(PackError::BadElf("符号名未结束"))?;
            let sym = core::str::from_utf8(&raw[..n]).map_err(|_| PackError::BadElf("符号名不是 UTF-8"))?;
            if shndx == 0 {
                if !sym.is_empty() {
                    return Err(PackError::UndefinedSymbol(sym.into()));
                }
                continue;
            }
            let (bind, ty) = (info >> 4, info & 0xF);
            if (bind == 1 || bind == 2) && ty == 2 {
                let v = u32::try_from(value).map_err(|_| PackError::BadElf("符号地址超出 32 位"))?;
                exports.push((sym.as_bytes().to_vec(), v));
            }
        }
    }
    exports.sort();

    let b = Builder { arch, stage, manifest: manifest.as_bytes().to_vec(), segments, exports, relocs };
    b.finish().map_err(PackError::Format)
}
