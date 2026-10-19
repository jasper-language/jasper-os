//! 电源状态协调接口（PSCI）的纯协议部分：调用途径、函数号、版本判定与返回码解码。
//! Pure PSCI protocol: conduit, function identifiers, version check and return-code decoding.
//!
//! # 职责与边界
//! * 只负责「怎么解读」：调用途径来自设备树 `method` 属性的文本，返回码来自固件寄存器的原始值；
//!   真正发出 `hvc` / `smc` 指令的代码在 AArch64 指令集层，这里没有任何汇编。
//! * 固件返回值是不可信输入：未知的返回码一律解码为「内部失败」，不会被当成成功。
//!
//! # 为什么放在 kernel-core
//! 返回码到处理器启动错误的映射决定了「哪些失败可以重试、哪些说明处理器不存在」，
//! 与指令集无关，放在这里可以在宿主上覆盖全部分支。

use crate::smp::SmpError;

/// 查询协议版本（32 位调用约定）。
/// PSCI_VERSION function identifier.
pub const FN_VERSION: u32 = 0x8400_0000;
/// 启动一个处理器（64 位调用约定：目标亲和性、入口物理地址、上下文值）。
/// CPU_ON (SMC64) function identifier.
pub const FN_CPU_ON_64: u32 = 0xC400_0003;

/// 发出调用的途径（设备树 `method`）。
/// How PSCI calls are issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conduit {
    /// 经虚拟化层调用（`hvc #0`）。
    Hvc,
    /// 经安全监控层调用（`smc #0`）。
    Smc,
}

impl Conduit {
    /// 由设备树 `method` 属性的文本得到调用途径；未知文本返回 `None`（调用者不得猜测，否则会陷入未定义指令异常）。
    /// Parse the device tree `method` text.
    pub fn from_method(method: &str) -> Option<Conduit> {
        match method {
            "hvc" => Some(Conduit::Hvc),
            "smc" => Some(Conduit::Smc),
            _ => None,
        }
    }
}

/// 版本号是否支持本内核使用的调用（`CPU_ON` 的标准函数号自 0.2 起固定）。
/// 版本值高 16 位为主版本、低 16 位为次版本；负值（调用本身被拒）不支持。
/// Whether the reported version supports the calls this kernel uses (>= 0.2).
pub fn version_supported(raw: i64) -> bool {
    if raw < 0 || raw > u32::MAX as i64 {
        return false;
    }
    let v = raw as u32;
    let (major, minor) = (v >> 16, v & 0xFFFF);
    major >= 1 || minor >= 2
}

/// 固件返回的错误。
/// Error returned by the firmware.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsciError {
    /// 不支持该调用。
    NotSupported,
    /// 参数非法（例如目标亲和性不存在）。
    InvalidParameters,
    /// 被拒绝。
    Denied,
    /// 目标处理器已在运行。
    AlreadyOn,
    /// 目标处理器正在启动中。
    OnPending,
    /// 固件内部失败（也用于无法识别的返回码）。
    InternalFailure,
    /// 目标处理器不存在。
    NotPresent,
    /// 目标处理器已被停用。
    Disabled,
    /// 入口地址非法。
    InvalidAddress,
}

impl PsciError {
    /// 规范名。
    /// Canonical name.
    pub const fn name(self) -> &'static str {
        match self {
            PsciError::NotSupported => "system.firmware.psci.error.not_supported",
            PsciError::InvalidParameters => "system.firmware.psci.error.invalid_parameters",
            PsciError::Denied => "system.firmware.psci.error.denied",
            PsciError::AlreadyOn => "system.firmware.psci.error.already_on",
            PsciError::OnPending => "system.firmware.psci.error.on_pending",
            PsciError::InternalFailure => "system.firmware.psci.error.internal_failure",
            PsciError::NotPresent => "system.firmware.psci.error.not_present",
            PsciError::Disabled => "system.firmware.psci.error.disabled",
            PsciError::InvalidAddress => "system.firmware.psci.error.invalid_address",
        }
    }

    /// 映射为处理器启动错误：说明「处理器不存在 / 不可用」的归为 [`SmpError::NoSuchCpu`]，
    /// 「已在运行 / 正在启动」归为 [`SmpError::BadState`]（不得再次启动），其余归为 [`SmpError::StartFailed`]。
    /// Map to a processor start-up error.
    pub const fn to_smp(self) -> SmpError {
        match self {
            PsciError::InvalidParameters | PsciError::NotPresent | PsciError::Disabled => SmpError::NoSuchCpu,
            PsciError::AlreadyOn | PsciError::OnPending => SmpError::BadState,
            PsciError::NotSupported | PsciError::Denied | PsciError::InternalFailure | PsciError::InvalidAddress => {
                SmpError::StartFailed
            }
        }
    }
}

/// 解码一次调用的返回值（寄存器原值按有符号数解释）：0 为成功，规范内的负值为对应错误，其余一律为内部失败。
/// Decode a call's return value.
pub fn decode(ret: i64) -> Result<(), PsciError> {
    match ret {
        0 => Ok(()),
        -1 => Err(PsciError::NotSupported),
        -2 => Err(PsciError::InvalidParameters),
        -3 => Err(PsciError::Denied),
        -4 => Err(PsciError::AlreadyOn),
        -5 => Err(PsciError::OnPending),
        -7 => Err(PsciError::NotPresent),
        -8 => Err(PsciError::Disabled),
        -9 => Err(PsciError::InvalidAddress),
        _ => Err(PsciError::InternalFailure),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conduit_from_method_known_and_unknown() {
        assert_eq!(Conduit::from_method("hvc"), Some(Conduit::Hvc));
        assert_eq!(Conduit::from_method("smc"), Some(Conduit::Smc));
        assert_eq!(Conduit::from_method("HVC"), None, "大小写不同不猜测");
        assert_eq!(Conduit::from_method(""), None);
        assert_eq!(Conduit::from_method("spin-table"), None);
    }

    #[test]
    fn version_check_accepts_0_2_and_later_only() {
        assert!(version_supported(0x0000_0002), "0.2");
        assert!(version_supported(0x0001_0000), "1.0");
        assert!(version_supported(0x0001_0003), "1.3");
        assert!(!version_supported(0x0000_0001), "0.1 函数号不固定");
        assert!(!version_supported(0), "0.0");
        assert!(!version_supported(-1), "调用本身不被支持");
        assert!(!version_supported(1 << 40), "超出 32 位的垃圾值");
    }

    #[test]
    fn decode_success_errors_and_garbage() {
        assert_eq!(decode(0), Ok(()));
        let table = [
            (-1, PsciError::NotSupported, SmpError::StartFailed),
            (-2, PsciError::InvalidParameters, SmpError::NoSuchCpu),
            (-3, PsciError::Denied, SmpError::StartFailed),
            (-4, PsciError::AlreadyOn, SmpError::BadState),
            (-5, PsciError::OnPending, SmpError::BadState),
            (-6, PsciError::InternalFailure, SmpError::StartFailed),
            (-7, PsciError::NotPresent, SmpError::NoSuchCpu),
            (-8, PsciError::Disabled, SmpError::NoSuchCpu),
            (-9, PsciError::InvalidAddress, SmpError::StartFailed),
        ];
        for (raw, e, s) in table {
            assert_eq!(decode(raw), Err(e), "返回码 {raw}");
            assert_eq!(e.to_smp(), s);
            assert!(e.name().starts_with("system.firmware.psci.error."));
        }
        // 未知返回码（正数、越界负数）绝不当成成功
        for raw in [1, 2, -10, i64::MIN, i64::MAX, 0xFFFF_FFFF] {
            assert_eq!(decode(raw), Err(PsciError::InternalFailure), "返回码 {raw}");
        }
    }
}
