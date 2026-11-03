//! 一致性判定（SPEC §14）：在固定的**一致性上下文**里对一个文件做 L1 装载的第 1–6a 步，给出 `ok` 或一个稳定错误码。
//! Conformance check: L1 load steps 1–6a (SPEC §12.2) in the fixed conformance context of SPEC §14.
//!
//! 每个实现都用同一上下文跑 `jaso/vectors/` 的全部向量，结果必须与 `<名>.expect` 一致。
//! 这里不映射、不链接、不调用任何代码（第 7 步以后不属于一致性判定）。

use crate::code::ErrorCode;
use crate::platform::{FloatAbi, HostPlatform, Target};
use crate::trust::{Publisher, TrustMode, TrustPolicy, DEVELOPMENT_NAMESPACE, DEVELOPMENT_PUBLISHER};
use crate::{Arch, Jaso, ModuleKind, ABI_C_V1};

/// 一致性上下文的原生宿主平台：x86_64、无扩展、jasper-os、8 字节指针、硬浮点、`c.v1`。
pub const NATIVE_HOST: HostPlatform<'static> =
    HostPlatform { isa: Some(Arch::X86_64), isa_ext: &[], target: Target::JasperOs, pointer_bytes: 8, float_abi: FloatAbi::Hard, abi: ABI_C_V1 };

/// 一致性上下文的托管宿主平台（Managed 文件）：无指令集、JVM、`jvm.52`；指针宽度 0、浮点约定 none（托管平台记录的唯一合法取值）。
pub const MANAGED_HOST: HostPlatform<'static> =
    HostPlatform { isa: None, isa_ext: &[], target: Target::Jvm, pointer_bytes: 0, float_abi: FloatAbi::None, abi: "jvm.52" };

/// 宿主运行时版本。
pub const RUNTIME_VERSION: (u32, u32, u32) = (0, 1, 0);

/// 已装入的模块：(名字, 版本)。
pub const LOADED: [(&str, (u32, u32, u32)); 1] = [("jaso-base", (1, 2, 0))];

/// 调用方授予的能力。
pub const GRANTED: [&str; 2] = ["log", "alloc"];

/// 按一致性上下文判定 `bytes`：结构读取 → 信任（强制模式，唯一受信发布者 `jasper.dev`、命名空间 `jaso-`、公钥 `dev_key`）
/// → 平台 → 运行时版本 → 依赖 → 能力 → 绑定，第一处失败的码即结果。
///
/// `dev_key` 是与向量一同公开的开发用公钥（`jaso/vectors/jasper.dev.pub`）；不是合法曲线点时视为配置错误，按 `trust.key` 处理
/// ——这样任何输入都不会 panic，也不会因为错误配置而放行。
pub fn check(bytes: &[u8], dev_key: [u8; 32]) -> Result<(), ErrorCode> {
    let f = Jaso::parse(bytes).map_err(|e| e.code())?;
    let publishers = [Publisher { name: DEVELOPMENT_PUBLISHER, namespace: DEVELOPMENT_NAMESPACE, key: dev_key }];
    let policy = TrustPolicy::new(&publishers, TrustMode::Enforce).map_err(|_| ErrorCode::TrustKey)?;
    policy.verify(&f).map_err(|e| e.code())?;
    let host = if f.kind == ModuleKind::Managed { &MANAGED_HOST } else { &NATIVE_HOST };
    f.select(host).map_err(|_| ErrorCode::PlatformMismatch)?;
    if f.manifest.runtime.is_some_and(|r| !r.contains(RUNTIME_VERSION)) {
        return Err(ErrorCode::DependencyRuntime);
    }
    for d in f.manifest.depends() {
        let ok = LOADED.iter().any(|(name, v)| *name == d.name && d.range.is_none_or(|r| r.contains(*v)));
        if !ok {
            return Err(ErrorCode::DependencyUnsatisfied);
        }
    }
    if f.manifest.requires().any(|c| !GRANTED.contains(&c)) {
        return Err(ErrorCode::CapabilityDenied);
    }
    crate::binding::check_file(&f).map_err(|e| e.code())
}

/// `.expect` 文件的一行：`ok` 或码名。
pub fn expect_line(r: Result<(), ErrorCode>) -> &'static str {
    match r {
        Ok(()) => "ok",
        Err(c) => c.name(),
    }
}
