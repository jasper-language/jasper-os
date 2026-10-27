//! 平台描述（SPEC §6.1）与按宿主平台选择镜像（SPEC §12.2 第 3 步）。
//! Platform records and host-platform matching.

use crate::Arch;

/// 平台记录长度。
pub const PLATFORM_RECORD: usize = 64;
/// 平台记录数上限。
pub const MAX_PLATFORMS: u32 = 16;
/// `isa_ext` 字段长度。
const ISA_EXT_FIELD: usize = 32;
/// `abi` 字段长度。
const ABI_FIELD: usize = 16;
/// 单个 `isa_ext` 记号的长度上限。
const MAX_ISA_EXT_TOKEN: usize = 15;

/// 浮点调用约定。
/// Floating-point calling convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloatAbi {
    /// 无（只用于托管平台）。
    None = 0,
    /// 软浮点（不经浮点寄存器传参）。
    Soft = 1,
    /// 硬浮点。
    Hard = 2,
}

impl FloatAbi {
    const fn from_u8(v: u8) -> Option<FloatAbi> {
        match v {
            0 => Some(FloatAbi::None),
            1 => Some(FloatAbi::Soft),
            2 => Some(FloatAbi::Hard),
            _ => None,
        }
    }

    /// 名字。
    pub const fn name(self) -> &'static str {
        match self {
            FloatAbi::None => "none",
            FloatAbi::Soft => "soft",
            FloatAbi::Hard => "hard",
        }
    }
}

/// 目标运行环境。
/// Target environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// jasper-os。
    JasperOs = 1,
    /// JVM（托管）。
    Jvm = 2,
    /// 常规宿主操作系统进程。
    Host = 3,
}

impl Target {
    const fn from_u16(v: u16) -> Option<Target> {
        match v {
            1 => Some(Target::JasperOs),
            2 => Some(Target::Jvm),
            3 => Some(Target::Host),
            _ => None,
        }
    }

    /// 名字。
    pub const fn name(self) -> &'static str {
        match self {
            Target::JasperOs => "jasper-os",
            Target::Jvm => "jvm",
            Target::Host => "host",
        }
    }
}

/// 一条平台记录（已校验）。
/// A validated platform record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Platform<'a> {
    /// 指令集；托管平台为 `None`。
    pub isa: Option<Arch>,
    /// 指针宽度（字节）；托管平台为 0。
    pub pointer_bytes: u8,
    /// 浮点调用约定。
    pub float_abi: FloatAbi,
    /// 目标运行环境。
    pub target: Target,
    /// 指令集扩展记号（逗号分隔，可为空）。
    pub isa_ext: &'a str,
    /// 调用约定名，如 `c.v1`、`jvm.52`。
    pub abi: &'a str,
}

/// 字段 `b` 是否「名字 + 零填充」：第一个零字节之后全为零；返回名字部分。
fn nul_padded(b: &[u8]) -> Option<&str> {
    let n = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    if b[n..].iter().any(|&c| c != 0) {
        return None;
    }
    core::str::from_utf8(&b[..n]).ok()
}

fn isa_ext_ok(s: &str) -> bool {
    if s.is_empty() {
        return true;
    }
    s.split(',').enumerate().all(|(i, t)| {
        !t.is_empty()
            && t.len() <= MAX_ISA_EXT_TOKEN
            && t.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
            && !s.split(',').take(i).any(|p| p == t)
    })
}

pub(crate) fn abi_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= ABI_FIELD && s.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'.' || c == b'_')
}

impl<'a> Platform<'a> {
    /// 解析并校验一条 64 字节的记录（SPEC §6.1 的全部取值与一致性规则）；不合格返回 `None`。
    pub(crate) fn parse(b: &'a [u8]) -> Option<Platform<'a>> {
        if b.len() != PLATFORM_RECORD {
            return None;
        }
        let isa_v = u16::from_le_bytes([b[0], b[1]]);
        let isa = match isa_v {
            0 => None,
            v => Some(Arch::from_u16(v)?),
        };
        let pointer_bytes = b[2];
        let float_abi = FloatAbi::from_u8(b[3])?;
        let target = Target::from_u16(u16::from_le_bytes([b[4], b[5]]))?;
        if b[6] != 0 || b[7] != 0 || b[56..64].iter().any(|&c| c != 0) {
            return None;
        }
        let isa_ext = nul_padded(&b[8..8 + ISA_EXT_FIELD])?;
        let abi = nul_padded(&b[40..40 + ABI_FIELD])?;
        if !isa_ext_ok(isa_ext) || !abi_ok(abi) {
            return None;
        }
        // isa = 0 ⇔ target = jvm ⇔ pointer_bytes = 0 ⇔ float_abi = none
        let managed = isa.is_none();
        if managed != (target == Target::Jvm) || managed != (pointer_bytes == 0) || managed != (float_abi == FloatAbi::None) {
            return None;
        }
        if let Some(a) = isa {
            if pointer_bytes as u32 != a.pointer_bytes() {
                return None;
            }
        }
        Some(Platform { isa, pointer_bytes, float_abi, target, isa_ext, abi })
    }

    /// 指令集扩展记号。
    pub fn isa_ext_tokens(&self) -> impl Iterator<Item = &'a str> {
        self.isa_ext.split(',').filter(|t| !t.is_empty())
    }

    /// 与宿主平台比较：全部相符返回 `None`，否则返回第一个不符的字段（顺序：isa、isa_ext、target、abi、float_abi、pointer_bytes）。
    pub fn mismatch(&self, host: &HostPlatform<'_>) -> Option<PlatformMismatch> {
        let isa_name = |a: Option<Arch>| a.map_or("none", Arch::name);
        if self.isa != host.isa {
            return Some(PlatformMismatch::new(PlatformField::Isa, isa_name(host.isa), isa_name(self.isa)));
        }
        if let Some(t) = self.isa_ext_tokens().find(|t| !host.isa_ext.contains(t)) {
            return Some(PlatformMismatch::new(PlatformField::IsaExt, "-", t));
        }
        if self.target != host.target {
            return Some(PlatformMismatch::new(PlatformField::Target, host.target.name(), self.target.name()));
        }
        if self.abi != host.abi {
            return Some(PlatformMismatch::new(PlatformField::Abi, host.abi, self.abi));
        }
        if self.float_abi != host.float_abi {
            return Some(PlatformMismatch::new(PlatformField::FloatAbi, host.float_abi.name(), self.float_abi.name()));
        }
        if self.pointer_bytes != host.pointer_bytes {
            const W: [&str; 9] = ["0", "1", "2", "3", "4", "5", "6", "7", "8"];
            let w = |n: u8| W.get(n as usize).copied().unwrap_or("?");
            return Some(PlatformMismatch::new(PlatformField::PointerBytes, w(host.pointer_bytes), w(self.pointer_bytes)));
        }
        None
    }
}

/// 宿主平台：装载器所在环境的描述，用来选择镜像。
/// The host platform a loader selects images for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostPlatform<'a> {
    /// 指令集；托管运行时为 `None`。
    pub isa: Option<Arch>,
    /// 宿主支持的指令集扩展。
    pub isa_ext: &'a [&'a str],
    /// 目标运行环境。
    pub target: Target,
    /// 指针宽度。
    pub pointer_bytes: u8,
    /// 浮点调用约定。
    pub float_abi: FloatAbi,
    /// 调用约定名。
    pub abi: &'a str,
}

impl HostPlatform<'static> {
    /// 本程序（jasper-os 用户态原生代码）所在的平台：本指令集、无扩展要求、软浮点、`c.v1`。
    ///
    /// jasper-os 的全部原生目标都是软浮点（内核不在切换时保存浮点 / SIMD 寄存器）。
    pub const fn jasper_os_native() -> Option<HostPlatform<'static>> {
        match Arch::current() {
            Some(a) => Some(HostPlatform {
                isa: Some(a),
                isa_ext: &[],
                target: Target::JasperOs,
                pointer_bytes: a.pointer_bytes() as u8,
                float_abi: FloatAbi::Soft,
                abi: crate::ABI_C_V1,
            }),
            None => None,
        }
    }
}

/// 不符的平台字段。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformField {
    /// 指令集。
    Isa,
    /// 指令集扩展。
    IsaExt,
    /// 目标运行环境。
    Target,
    /// 调用约定。
    Abi,
    /// 浮点调用约定。
    FloatAbi,
    /// 指针宽度。
    PointerBytes,
}

/// 一个短文本值（内联存放，不借用输入；超长部分截断）。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ShortText {
    buf: [u8; 16],
    len: u8,
}

impl ShortText {
    pub(crate) fn new(s: &str) -> ShortText {
        let mut n = s.len().min(16);
        while !s.is_char_boundary(n) {
            n -= 1;
        }
        let mut buf = [0u8; 16];
        buf[..n].copy_from_slice(&s.as_bytes()[..n]);
        ShortText { buf, len: n as u8 }
    }

    /// 文本。
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len as usize]).unwrap_or("")
    }
}

impl core::fmt::Debug for ShortText {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(self.as_str(), f)
    }
}

/// 平台不符（`platform.mismatch`）：第一个不符的字段，宿主期望值与文件实际值。
/// The first field of image 0 that differs from the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlatformMismatch {
    /// 字段。
    pub field: PlatformField,
    /// 宿主的值。
    pub expected: ShortText,
    /// 文件中的值。
    pub actual: ShortText,
}

impl PlatformMismatch {
    fn new(field: PlatformField, expected: &str, actual: &str) -> PlatformMismatch {
        PlatformMismatch { field, expected: ShortText::new(expected), actual: ShortText::new(actual) }
    }
}
