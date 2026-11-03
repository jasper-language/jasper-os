//! 内核态 `.jaso` 的准入门（SPEC §12.2 第 2 步）：只接受 `build` / `boot` 阶段、由白名单发布者签名的文件；系统运行之后一律拒绝。
//! The admission gate for kernel-mode `.jaso` files: `build`/`boot` stage only, allow-listed signature only, never at run time.
//!
//! 内核目前没有运行期装载路径：系统调用表里没有装载模块的调用，内核也不依赖本 crate（验收 JB-OS2 同时检查这两点）。
//! 将来任何内核态装载都必须经过这道门；运行期的请求在读取文件之前就被拒绝。

use crate::trust::{Provenance, TrustError, TrustMode, TrustPolicy};
use crate::{Jaso, JasoError, Stage};

/// 请求发生的阶段。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelPhase {
    /// 构建期。
    Build,
    /// 启动期。
    Boot,
    /// 系统已运行。
    Running,
}

/// 内核态装载被拒的原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelLoadError {
    /// 系统已运行：内核态模块不能在运行期装载。
    RuntimeLoad,
    /// 信任策略不是强制模式。
    DevelopmentPolicy,
    /// 文件未通过结构读取。
    Format(JasoError),
    /// 文件的装载阶段与请求的阶段不符（`runtime` 阶段的文件永远不符）。
    Stage(Stage),
    /// 签名不在白名单内。
    Untrusted(TrustError),
}

/// 判定一个内核态装载请求；通过时返回解析后的文件。
pub fn admit_kernel<'a>(bytes: &'a [u8], allow: &TrustPolicy<'_>, phase: KernelPhase) -> Result<Jaso<'a>, KernelLoadError> {
    let want = match phase {
        KernelPhase::Running => return Err(KernelLoadError::RuntimeLoad),
        KernelPhase::Build => Stage::Build,
        KernelPhase::Boot => Stage::Boot,
    };
    if allow.mode() != TrustMode::Enforce {
        return Err(KernelLoadError::DevelopmentPolicy);
    }
    let f = Jaso::parse(bytes).map_err(KernelLoadError::Format)?;
    if f.stage != want {
        return Err(KernelLoadError::Stage(f.stage));
    }
    match allow.verify(&f).map_err(KernelLoadError::Untrusted)? {
        Provenance::Signed { .. } => Ok(f),
        // 强制模式不会放行未签名文件；这里仍按未签名拒绝，不依赖对方实现
        Provenance::UnsignedDevelopment => Err(KernelLoadError::Untrusted(TrustError::Unsigned)),
    }
}
