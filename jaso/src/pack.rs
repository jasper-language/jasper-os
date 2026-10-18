//! 从位置无关的 ELF64 映像（static-pie）打包 `.jaso`。
//! Packs a position-independent ELF64 image into a `.jaso` file.
//!
//! # 输入要求
//! * ELF64、小端、`ET_DYN`（位置无关），`e_machine` 与目标指令集一致
//! * 可装入段（`PT_LOAD`）互不共用页；段起点按页向下取整，前面补零（不把相邻段的字节带进来）
//! * 动态重定位只允许「基址 + 加数」一种（x86_64 `R_X86_64_RELATIVE`、AArch64 `R_AARCH64_RELATIVE`、
//!   RISC-V `R_RISCV_RELATIVE`）；出现其它种类、`DT_REL`、PLT 重定位或 `DT_NEEDED` 即拒绝——
//!   模块不按名字导入任何外部符号，宿主能力只经 [`crate::HostV0`] 表提供
//! * 导出 = 清单 `core.exports` 声明的名字，每个都必须是动态符号表中已定义的全局函数（链接器顺带导出的其它符号一律不收）；
//!   动态符号表里有未定义的符号即拒绝

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
    /// 清单声明的导出不是映像中已定义的全局函数。
    MissingExport(String),
    /// 清单本身不合法。
    Manifest(crate::ManifestError),
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

    // 导出：清单声明的名字，逐个在动态符号表中找已定义的全局函数；有未定义符号即拒绝
    let declared = crate::Manifest::parse(manifest).map_err(PackError::Manifest)?;
    let mut defined: Vec<(Vec<u8>, u32)> = Vec::new();
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
                defined.push((sym.as_bytes().to_vec(), v));
            }
        }
    }
    let mut exports = Vec::new();
    for name in declared.exports() {
        let hit = defined.iter().find(|(n, _)| n == name.as_bytes()).ok_or_else(|| PackError::MissingExport(name.into()))?;
        exports.push(hit.clone());
    }

    let b = Builder { arch, stage, manifest: manifest.as_bytes().to_vec(), segments, exports, relocs };
    b.finish().map_err(PackError::Format)
}

/// 指令集 → 裸机目标三元组。
///
/// AArch64 与 RISC-V 用软浮点目标：内核不在上下文切换时保存浮点 / SIMD 寄存器，并让它们的任何访问陷入，
/// 模块因此不得生成使用这些寄存器的代码（与内嵌用户程序、内核本身一致）。
pub fn target_triple(a: Arch) -> &'static str {
    match a {
        Arch::X86_64 => "x86_64-unknown-none",
        Arch::Aarch64 => "aarch64-unknown-none-softfloat",
        Arch::Riscv64 => "riscv64imac-unknown-none-elf",
        Arch::Riscv32 => "riscv32imac-unknown-none-elf",
    }
}

/// 构建脚本所针对的指令集（读 cargo 传给构建脚本的 `CARGO_CFG_TARGET_ARCH`）；不在支持之列或不在构建脚本中时返回原因。
/// The ISA a build script is building for.
pub fn build_target_arch() -> Result<Arch, String> {
    let name = std::env::var("CARGO_CFG_TARGET_ARCH").map_err(|_| String::from("不在构建脚本中：缺少 CARGO_CFG_TARGET_ARCH"))?;
    Arch::from_name(&name).ok_or_else(|| alloc::format!("不支持的指令集：{}", name))
}

/// 位置无关映像所需的额外编译参数。
///
/// x86_64 裸机目标默认就是位置无关的，不需要额外参数。AArch64 / RISC-V 裸机目标默认是静态重定位模型：
/// * `-Crelocation-model=pic`：本工作区编译的代码按位置无关生成；
/// * `-znotext`：工具链预编译的 `core` / `alloc` 不是位置无关的，其只读数据里有绝对地址；允许链接器把它们
///   变成「基址 + 加数」重定位留在只读段里。这与格式的约定一致：装载器在设置最终段权限之前完成重定位，
///   而 `.jaso` 校验拒绝任何落在可执行段内的重定位（代码里若出现绝对地址，打包即失败）。
fn pic_rustflags(a: Arch) -> Option<&'static str> {
    match a {
        Arch::X86_64 => None,
        Arch::Aarch64 | Arch::Riscv64 | Arch::Riscv32 => Some("\"-Crelocation-model=pic\", \"-Clink-arg=-znotext\""),
    }
}

/// 构建工作区 `workspace` 中的模块 crate `package`（目录 `dir`，含 `jaso.manifest`），并打包为运行时装载的 `.jaso`。
///
/// 用独立的 `target_dir` 调用 cargo（供其它 crate 的构建脚本使用时，避免与外层构建争用同一目录的锁）。
/// 失败时返回可读的原因。
pub fn build_module(
    workspace: &std::path::Path,
    package: &str,
    dir: &std::path::Path,
    target_dir: &std::path::Path,
    arch: Arch,
) -> Result<Vec<u8>, String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let triple = target_triple(arch);
    let mut cmd = std::process::Command::new(cargo);
    cmd.current_dir(workspace).env_remove("CARGO_ENCODED_RUSTFLAGS").env_remove("RUSTFLAGS").env_remove("CARGO_TARGET_DIR");
    if let Some(flags) = pic_rustflags(arch) {
        // 以 `--config` 追加，不覆盖工作区配置里为该目标写的其它编译参数
        cmd.arg("--config").arg(alloc::format!("target.{}.rustflags=[{}]", triple, flags));
    }
    let status = cmd
        .args(["build", "--release", "--target", triple, "-p", package, "--target-dir"])
        .arg(target_dir)
        .status()
        .map_err(|e| alloc::format!("无法启动 cargo：{}", e))?;
    if !status.success() {
        return Err(alloc::format!("模块 {} 构建失败", package));
    }
    let elf_path = target_dir.join(triple).join("release").join(package);
    let elf = std::fs::read(&elf_path).map_err(|e| alloc::format!("读取 {} 失败：{}", elf_path.display(), e))?;
    let manifest = std::fs::read_to_string(dir.join("jaso.manifest")).map_err(|e| alloc::format!("读取清单失败：{}", e))?;
    from_elf(&elf, &manifest, arch, Stage::Runtime).map_err(|e| alloc::format!("打包 {} 失败：{:?}", package, e))
}

#[cfg(test)]
mod pack_target_tests {
    use super::*;

    #[test]
    fn triples_and_pic_flags_per_arch() {
        // AArch64 必须是软浮点目标；只有非 x86_64 需要额外的位置无关参数
        assert_eq!(target_triple(Arch::Aarch64), "aarch64-unknown-none-softfloat");
        assert_eq!(target_triple(Arch::X86_64), "x86_64-unknown-none");
        // RISC-V 同样不得用带浮点扩展（F/D）的目标
        assert_eq!(target_triple(Arch::Riscv64), "riscv64imac-unknown-none-elf");
        assert_eq!(pic_rustflags(Arch::X86_64), None);
        for a in [Arch::Aarch64, Arch::Riscv64, Arch::Riscv32] {
            let f = pic_rustflags(a).unwrap();
            assert!(f.contains("relocation-model=pic") && f.contains("-znotext"), "{:?}", a);
        }
    }

    #[test]
    fn build_target_arch_reads_cargo_cfg_and_rejects_unknown() {
        // 本测试是唯一读写该变量的测试，顺序执行三种情形
        std::env::set_var("CARGO_CFG_TARGET_ARCH", "aarch64");
        assert_eq!(build_target_arch(), Ok(Arch::Aarch64));
        std::env::set_var("CARGO_CFG_TARGET_ARCH", "mips");
        assert!(build_target_arch().unwrap_err().contains("mips"));
        std::env::remove_var("CARGO_CFG_TARGET_ARCH");
        assert!(build_target_arch().is_err());
    }
}
