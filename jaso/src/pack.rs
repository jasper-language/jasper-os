//! 从位置无关的 ELF 映像（static-pie）打包 `.jaso`。
//! Packs a position-independent ELF32/ELF64 image into a `.jaso` file.
//!
//! # 输入要求
//! * 小端、`ET_DYN`（位置无关），`e_machine` 与目标指令集一致；ELF 类别与指令集的指针宽度一致
//!   （RISC-V32 为 ELF32，其余为 ELF64）。两种类别只是字段宽度与位置不同，由 [`Layout`] 描述，解析逻辑共用
//! * 可装入段（`PT_LOAD`）互不共用页；段起点按页向下取整，前面补零（不把相邻段的字节带进来）
//! * 动态重定位只允许「基址 + 加数」一种（x86_64 `R_X86_64_RELATIVE`、AArch64 `R_AARCH64_RELATIVE`、
//!   RISC-V `R_RISCV_RELATIVE`），按指针宽度写成 `.jaso` 的 64 位或 32 位重定位；出现其它种类、`DT_REL`、PLT 重定位或 `DT_NEEDED` 即拒绝——
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

/// ELF 类别相关的字段布局（偏移以字节计；「字」= 该类别的地址宽度，ELF32 为 4、ELF64 为 8）。
/// Field layout of one ELF class.
struct Layout {
    /// 地址宽度（4 或 8）。
    word: usize,
    /// 文件头：e_phoff、e_shoff、e_phentsize（其后依次为 e_phnum、e_shentsize、e_shnum，各 2 字节）。
    phoff: usize,
    shoff: usize,
    phentsize_at: usize,
    /// 程序头大小与其中 p_flags、p_offset、p_vaddr、p_filesz、p_memsz 的偏移。
    phent: usize,
    p_flags: usize,
    p_offset: usize,
    p_vaddr: usize,
    p_filesz: usize,
    p_memsz: usize,
    /// 节头大小与其中 sh_offset、sh_size、sh_link、sh_entsize 的偏移（sh_type 两类均在 4）。
    shent: usize,
    sh_offset: usize,
    sh_size: usize,
    sh_link: usize,
    sh_entsize: usize,
    /// 动态段条目大小（d_tag 与 d_val 各一个字）。
    dynent: usize,
    /// RELA 条目大小；r_info 中类型与符号的拆分位数（ELF32：低 8 位为类型；ELF64：低 32 位为类型）。
    relaent: usize,
    rinfo_type_bits: u32,
    /// 符号表项大小与其中 st_info、st_shndx、st_value 的偏移（st_name 两类均在 0）。
    syment: usize,
    st_info: usize,
    st_shndx: usize,
    st_value: usize,
}

const ELF32: Layout = Layout {
    word: 4,
    phoff: 28,
    shoff: 32,
    phentsize_at: 42,
    phent: 32,
    p_flags: 24,
    p_offset: 4,
    p_vaddr: 8,
    p_filesz: 16,
    p_memsz: 20,
    shent: 40,
    sh_offset: 16,
    sh_size: 20,
    sh_link: 24,
    sh_entsize: 36,
    dynent: 8,
    relaent: 12,
    rinfo_type_bits: 8,
    syment: 16,
    st_info: 12,
    st_shndx: 14,
    st_value: 4,
};

const ELF64: Layout = Layout {
    word: 8,
    phoff: 32,
    shoff: 40,
    phentsize_at: 54,
    phent: 56,
    p_flags: 4,
    p_offset: 8,
    p_vaddr: 16,
    p_filesz: 32,
    p_memsz: 40,
    shent: 64,
    sh_offset: 24,
    sh_size: 32,
    sh_link: 40,
    sh_entsize: 56,
    dynent: 16,
    relaent: 24,
    rinfo_type_bits: 32,
    syment: 24,
    st_info: 4,
    st_shndx: 6,
    st_value: 8,
};

impl Layout {
    /// 读一个字（零扩展为 u64）。
    fn w(&self, b: &[u8], o: usize) -> Result<u64, PackError> {
        if self.word == 4 {
            u32_(b, o).map(u64::from)
        } else {
            u64_(b, o)
        }
    }

    /// 读一个字并转为文件内偏移 / 长度。
    fn off(&self, b: &[u8], o: usize) -> Result<usize, PackError> {
        usize::try_from(self.w(b, o)?).map_err(|_| PackError::BadElf("偏移过大"))
    }
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
    if elf.get(5) != Some(&1) {
        return Err(PackError::BadElf("只支持小端"));
    }
    // ELF 类别：1 = ELF32、2 = ELF64；必须与指令集的指针宽度一致
    let lay = match (elf.get(4), arch.pointer_bytes()) {
        (Some(&1), 4) => &ELF32,
        (Some(&2), 8) => &ELF64,
        _ => return Err(PackError::BadElf("ELF 类别与指令集的指针宽度不符")),
    };
    if u16_(elf, 16)? != 3 {
        return Err(PackError::BadElf("不是位置无关映像（ET_DYN）"));
    }
    let m = u16_(elf, 18)?;
    if m != machine(arch) {
        return Err(PackError::WrongMachine { elf: m, want: arch });
    }
    let (phoff, shoff) = (lay.off(elf, lay.phoff)?, lay.off(elf, lay.shoff)?);
    let h = lay.phentsize_at;
    let (phentsize, phnum) = (u16_(elf, h)? as usize, u16_(elf, h + 2)? as usize);
    let (shentsize, shnum) = (u16_(elf, h + 4)? as usize, u16_(elf, h + 6)? as usize);
    if phentsize != lay.phent || (shnum > 0 && shentsize != lay.shent) {
        return Err(PackError::BadElf("表项大小"));
    }

    let mut loads = Vec::new();
    let mut dynamic: Option<(u64, u64)> = None;
    for i in 0..phnum {
        let o = phoff + i * phentsize;
        let (ty, pf) = (u32_(elf, o)?, u32_(elf, o + lay.p_flags)?);
        let (offset, vaddr) = (lay.w(elf, o + lay.p_offset)?, lay.w(elf, o + lay.p_vaddr)?);
        let (filesz, memsz) = (lay.w(elf, o + lay.p_filesz)?, lay.w(elf, o + lay.p_memsz)?);
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
        let (mut rela, mut relasz, mut relaent) = (0u64, 0u64, lay.relaent as u64);
        let mut o = usize::try_from(doff).map_err(|_| PackError::BadElf("偏移过大"))?;
        let end = usize::try_from(doff.saturating_add(dsz)).map_err(|_| PackError::BadElf("偏移过大"))?;
        while o + lay.dynent <= end {
            let (tag, val) = (lay.w(elf, o)?, lay.w(elf, o + lay.word)?);
            match tag {
                DT_NULL => break,
                DT_RELA => rela = val,
                DT_RELASZ => relasz = val,
                DT_RELAENT => relaent = val,
                DT_NEEDED | DT_REL | DT_JMPREL => return Err(PackError::UnsupportedDynamic(tag)),
                DT_PLTRELSZ if val != 0 => return Err(PackError::UnsupportedDynamic(tag)),
                _ => {}
            }
            o += lay.dynent;
        }
        if relasz > 0 {
            let ent = lay.relaent as u64;
            if relaent != ent || relasz % ent != 0 {
                return Err(PackError::BadElf("RELA 表项大小"));
            }
            let base = file_off(&loads, rela, relasz)?;
            let type_mask = (1u64 << lay.rinfo_type_bits) - 1;
            for i in 0..(relasz / ent) as usize {
                let e = base + i * lay.relaent;
                let (off, info, addend) = (lay.w(elf, e)?, lay.w(elf, e + lay.word)?, lay.w(elf, e + 2 * lay.word)?);
                let ty = (info & type_mask) as u32;
                if ty != relative_type(arch) || info >> lay.rinfo_type_bits != 0 {
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
        let (symoff, symsz) = (lay.off(elf, o + lay.sh_offset)?, lay.off(elf, o + lay.sh_size)?);
        let (link, entsize) = (u32_(elf, o + lay.sh_link)? as usize, lay.off(elf, o + lay.sh_entsize)?);
        if entsize != lay.syment {
            return Err(PackError::BadElf("符号表项大小"));
        }
        let so = shoff + link * shentsize;
        let (stroff, strsz) = (lay.off(elf, so + lay.sh_offset)?, lay.off(elf, so + lay.sh_size)?);
        let strtab = elf.get(stroff..stroff.saturating_add(strsz)).ok_or(PackError::BadElf("字符串表越界"))?;
        for k in 1..symsz / lay.syment {
            let s = symoff + k * lay.syment;
            let name = u32_(elf, s)? as usize;
            let (info, shndx, value) = (rd::<1>(elf, s + lay.st_info)?[0], u16_(elf, s + lay.st_shndx)?, lay.w(elf, s + lay.st_value)?);
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

/// 需要从源码重新编译标准库（`core` / `alloc`）的指令集所用的额外 cargo 参数。
///
/// RISC-V32 裸机目标预编译的 `core` / `alloc` 采用绝对寻址（`lui` + 低 12 位，`R_RISCV_HI20` / `LO12`）：
/// 这类重定位在**代码**里，`-znotext` 也无法把它们变成「基址 + 加数」，位置无关映像因此链接失败。
/// 所以该目标连同标准库一起按位置无关模型编译（`-Zbuild-std`，需要 nightly 与 `rust-src`）；
/// `compiler-builtins-mem` 提供 `memcpy` 等基础函数（裸机目标上没有 C 库）。其余指令集的预编译库
/// 代码本身已是 PC 相对寻址，不需要这一步。
fn build_std_args(a: Arch) -> &'static [&'static str] {
    match a {
        Arch::Riscv32 => &["-Zbuild-std=core,alloc", "-Zbuild-std-features=compiler-builtins-mem"],
        Arch::X86_64 | Arch::Aarch64 | Arch::Riscv64 => &[],
    }
}

/// 开发用发布者（[`crate::trust::DEVELOPMENT_PUBLISHER`]）的签名密钥：种子由公开的固定字符串派生，**任何人都能用它签名**，
/// 只适合开发与验收；正式发布须使用私有密钥，并把对应公钥写进装载方的受信发布者表。
/// The development signing key. Its seed is public: development and testing only.
pub fn development_signer() -> crate::build::Signer {
    signer_from_phrase(b"jasper-os development publisher seed v0")
}

/// 以 SHA-256(`phrase`) 为种子建立签名密钥：只用于种子可以公开的场合（开发、验收）。
/// Builds a signer seeded with SHA-256 of a public phrase (development/testing only).
pub fn signer_from_phrase(phrase: &[u8]) -> crate::build::Signer {
    use sha2::{Digest, Sha256};
    let mut seed = [0u8; 32];
    seed.copy_from_slice(Sha256::digest(phrase).as_slice());
    crate::build::Signer::from_seed(&seed)
}

/// 对一个已打包的 `.jaso` 重新签名：保留清单、各段、导出与重定位，替换（或新增）签名段。
/// Re-signs a packed `.jaso` file with `signer`.
pub fn sign(bytes: &[u8], signer: &crate::build::Signer) -> Result<Vec<u8>, JasoError> {
    Builder::from_image(&crate::Image::parse(bytes)?).finish_signed(signer)
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
        .args(["build", "--release", "--target", triple, "-p", package])
        .args(build_std_args(arch))
        .arg("--target-dir")
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
        // 只有 RISC-V32 需要从源码按位置无关模型重编标准库
        assert_eq!(target_triple(Arch::Riscv32), "riscv32imac-unknown-none-elf");
        assert!(build_std_args(Arch::Riscv32).iter().any(|a| a.starts_with("-Zbuild-std=")));
        for a in [Arch::X86_64, Arch::Aarch64, Arch::Riscv64] {
            assert!(build_std_args(a).is_empty(), "{:?}", a);
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

    /// 合成一个最小的 RISC-V32 位置无关 ELF32：代码段（导出 f_one / f_two）、数据段（动态段 + 一条
    /// R_RISCV_RELATIVE，类型 `rel_type`、位置 `rel_off`）、动态符号表与字符串表。
    fn elf32(rel_type: u32, rel_off: u32) -> std::vec::Vec<u8> {
        let mut f = std::vec![0u8; 0x3300];
        let put16 = |f: &mut [u8], o: usize, v: u16| f[o..o + 2].copy_from_slice(&v.to_le_bytes());
        let put32 = |f: &mut [u8], o: usize, v: u32| f[o..o + 4].copy_from_slice(&v.to_le_bytes());
        f[..4].copy_from_slice(b"\x7fELF");
        (f[4], f[5], f[6]) = (1, 1, 1);
        put16(&mut f, 16, 3); // ET_DYN
        put16(&mut f, 18, 243); // RISC-V
        put32(&mut f, 28, 52); // e_phoff
        put32(&mut f, 32, 0x3200); // e_shoff
        (put16(&mut f, 42, 32), put16(&mut f, 44, 3), put16(&mut f, 46, 40), put16(&mut f, 48, 3));
        // 程序头：代码段、数据段、动态段
        for (i, (ty, off, size, flags)) in [(PT_LOAD, 0x1000, 0x10, 5), (PT_LOAD, 0x2000, 0x300, 6), (PT_DYNAMIC, 0x2000, 32, 6)].into_iter().enumerate() {
            let o = 52 + i * 32;
            (put32(&mut f, o, ty), put32(&mut f, o + 4, off), put32(&mut f, o + 8, off));
            (put32(&mut f, o + 16, size), put32(&mut f, o + 20, size), put32(&mut f, o + 24, flags));
        }
        // 动态段：RELA = 0x2100、RELASZ = 12、RELAENT = 12、NULL
        for (i, (tag, val)) in [(DT_RELA, 0x2100u32), (DT_RELASZ, 12), (DT_RELAENT, 12), (DT_NULL, 0)].into_iter().enumerate() {
            (put32(&mut f, 0x2000 + i * 8, tag as u32), put32(&mut f, 0x2004 + i * 8, val));
        }
        (put32(&mut f, 0x2100, rel_off), put32(&mut f, 0x2104, rel_type), put32(&mut f, 0x2108, 0x1000));
        // 字符串表与动态符号表（空项 + 两个全局函数）
        f[0x3100..0x310d].copy_from_slice(b"\0f_one\0f_two\0");
        for (i, (name, value)) in [(1u32, 0x1000u32), (7, 0x1008)].into_iter().enumerate() {
            let o = 0x3000 + (i + 1) * 16;
            (put32(&mut f, o, name), put32(&mut f, o + 4, value), put32(&mut f, o + 8, 8));
            (f[o + 12] = 0x12, put16(&mut f, o + 14, 1));
        }
        // 节头：空、.dynsym（链接到 .dynstr）、.dynstr
        let o = 0x3200 + 40;
        (put32(&mut f, o + 4, SHT_DYNSYM), put32(&mut f, o + 16, 0x3000), put32(&mut f, o + 20, 48));
        (put32(&mut f, o + 24, 2), put32(&mut f, o + 36, 16));
        let o = 0x3200 + 80;
        (put32(&mut f, o + 4, 3), put32(&mut f, o + 16, 0x3100), put32(&mut f, o + 20, 13));
        f
    }

    const MANIFEST32: &str = "core.name = demo.rv32\ncore.version = 1.0.0\ncore.abi = c.v0\ncore.host = jaso.host.v0\ncore.exports = f_one, f_two\n";

    #[test]
    fn elf32_packs_with_four_byte_relocations() {
        let out = from_elf(&elf32(3, 0x2200), MANIFEST32, Arch::Riscv32, Stage::Runtime).unwrap();
        let img = crate::Image::parse(&out).unwrap();
        assert_eq!(img.arch, Arch::Riscv32);
        let r: std::vec::Vec<_> = img.relocs().collect();
        assert_eq!(r.len(), 1);
        assert_eq!((r[0].offset, r[0].kind, r[0].addend), (0x2200, crate::RELOC_RELATIVE32, 0x1000));
        assert_eq!(img.exports().map(|e| e.value).collect::<std::vec::Vec<_>>(), [0x1000, 0x1008]);
        // 4 字节对齐（而非 8 字节）的位置在 32 位指令集上是合法的
        assert!(from_elf(&elf32(3, 0x2204), MANIFEST32, Arch::Riscv32, Stage::Runtime).is_ok());
    }

    #[test]
    fn elf32_rejections() {
        // ELF32 不能打包成 64 位指令集的模块（反之亦然：类别与指针宽度必须一致）
        for a in [Arch::Riscv64, Arch::X86_64, Arch::Aarch64] {
            assert_eq!(from_elf(&elf32(3, 0x2200), MANIFEST32, a, Stage::Runtime), Err(PackError::BadElf("ELF 类别与指令集的指针宽度不符")));
        }
        let mut as64 = elf32(3, 0x2200);
        as64[4] = 2;
        assert_eq!(from_elf(&as64, MANIFEST32, Arch::Riscv32, Stage::Runtime), Err(PackError::BadElf("ELF 类别与指令集的指针宽度不符")));
        // 非「基址 + 加数」的重定位（R_RISCV_32 = 1）、带符号引用的重定位都被拒绝
        assert_eq!(from_elf(&elf32(1, 0x2200), MANIFEST32, Arch::Riscv32, Stage::Runtime), Err(PackError::UnsupportedReloc(1)));
        assert_eq!(from_elf(&elf32(3 | 1 << 8, 0x2200), MANIFEST32, Arch::Riscv32, Stage::Runtime), Err(PackError::UnsupportedReloc(3)));
        // 写入位置未按 4 字节对齐、或落在可执行段内：格式校验拒绝
        assert_eq!(from_elf(&elf32(3, 0x2202), MANIFEST32, Arch::Riscv32, Stage::Runtime), Err(PackError::Format(JasoError::RelocOutOfRange)));
        assert_eq!(from_elf(&elf32(3, 0x1004), MANIFEST32, Arch::Riscv32, Stage::Runtime), Err(PackError::Format(JasoError::RelocOutOfRange)));
        // 截断的文件不 panic，只报越界
        let full = elf32(3, 0x2200);
        for cut in [10, 60, 0x2104, 0x3210] {
            assert!(from_elf(&full[..cut], MANIFEST32, Arch::Riscv32, Stage::Runtime).is_err());
        }
    }
}
