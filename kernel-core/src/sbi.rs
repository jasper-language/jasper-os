//! 监管态二进制接口（SBI）的纯协议部分：处理器状态管理（HSM）与核间中断（IPI）扩展的编号、返回码与状态解码。
//! Pure SBI protocol for the HSM and IPI extensions: identifiers, error decoding and hart-state decoding.
//!
//! # 职责与边界
//! * 只负责「怎么解读」：返回码与处理器状态来自固件寄存器的原始值；真正发出 `ecall` 的代码在 RISC-V 指令集层，
//!   这里没有任何汇编。
//! * 固件返回值是不可信输入：未知的错误码一律解码为「失败」，未知的处理器状态解码为 `None`，都不会被当成成功或可启动。
//!
//! # 为什么放在 kernel-core
//! 错误码到处理器启动错误的映射决定了「哪些失败说明处理器不存在、哪些说明它已在运行」，
//! 与寄存器宽度无关（RV32 与 RV64 相同），放在这里可以在宿主上覆盖全部分支。

use crate::smp::SmpError;

/// 处理器状态管理扩展（"HSM"）。
/// Hart State Management extension identifier.
pub const EID_HSM: usize = 0x0048_534D;
/// HSM：启动一个处理器（hart 号、入口物理地址、交给入口的不透明值）。
/// HSM `hart_start`.
pub const FID_HART_START: usize = 0;
/// HSM：查询一个处理器的状态。
/// HSM `hart_get_status`.
pub const FID_HART_GET_STATUS: usize = 2;
/// 核间中断扩展（"sPI"）。
/// IPI extension identifier.
pub const EID_IPI: usize = 0x0073_5049;
/// IPI：向一组处理器发送监管态软件中断（处理器位图、位图基准 hart 号）。
/// IPI `send_ipi`.
pub const FID_SEND_IPI: usize = 0;

/// 固件返回的错误。
/// Error returned by the firmware.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbiError {
    /// 失败（也用于无法识别的错误码）。
    Failed,
    /// 不支持该调用。
    NotSupported,
    /// 参数非法（例如 hart 号不存在）。
    InvalidParam,
    /// 被拒绝。
    Denied,
    /// 地址非法（入口不可执行或不存在）。
    InvalidAddress,
    /// 目标已处于请求的状态（处理器已在运行）。
    AlreadyAvailable,
    /// 目标正在向请求的状态迁移（处理器正在启动）。
    AlreadyStarted,
    /// 目标已经停止。
    AlreadyStopped,
}

impl SbiError {
    /// 规范名。
    /// Canonical name.
    pub const fn name(self) -> &'static str {
        match self {
            SbiError::Failed => "system.firmware.sbi.error.failed",
            SbiError::NotSupported => "system.firmware.sbi.error.not_supported",
            SbiError::InvalidParam => "system.firmware.sbi.error.invalid_param",
            SbiError::Denied => "system.firmware.sbi.error.denied",
            SbiError::InvalidAddress => "system.firmware.sbi.error.invalid_address",
            SbiError::AlreadyAvailable => "system.firmware.sbi.error.already_available",
            SbiError::AlreadyStarted => "system.firmware.sbi.error.already_started",
            SbiError::AlreadyStopped => "system.firmware.sbi.error.already_stopped",
        }
    }

    /// 映射为处理器启动错误：说明「处理器不存在」的归为 [`SmpError::NoSuchCpu`]，
    /// 「已在运行 / 正在启动」归为 [`SmpError::BadState`]（不得再次启动），其余归为 [`SmpError::StartFailed`]。
    /// Map to a processor start-up error.
    pub const fn to_smp(self) -> SmpError {
        match self {
            SbiError::InvalidParam => SmpError::NoSuchCpu,
            SbiError::AlreadyAvailable | SbiError::AlreadyStarted => SmpError::BadState,
            SbiError::Failed
            | SbiError::NotSupported
            | SbiError::Denied
            | SbiError::InvalidAddress
            | SbiError::AlreadyStopped => SmpError::StartFailed,
        }
    }
}

/// 解码一次调用的错误码（寄存器原值按有符号数解释）：0 为成功，规范内的负值为对应错误，其余一律为失败。
/// Decode a call's error code.
pub fn decode(error: i64) -> Result<(), SbiError> {
    match error {
        0 => Ok(()),
        -2 => Err(SbiError::NotSupported),
        -3 => Err(SbiError::InvalidParam),
        -4 => Err(SbiError::Denied),
        -5 => Err(SbiError::InvalidAddress),
        -6 => Err(SbiError::AlreadyAvailable),
        -7 => Err(SbiError::AlreadyStarted),
        -8 => Err(SbiError::AlreadyStopped),
        _ => Err(SbiError::Failed),
    }
}

/// HSM 报告的处理器状态。
/// Hart state reported by HSM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HartState {
    /// 正在运行。
    Started,
    /// 已停止（可以启动）。
    Stopped,
    /// 正在启动。
    StartPending,
    /// 正在停止。
    StopPending,
    /// 已挂起。
    Suspended,
    /// 正在挂起。
    SuspendPending,
    /// 正在恢复。
    ResumePending,
}

impl HartState {
    /// 由状态值解码；规范之外的值返回 `None`（调用者不得把它当成可启动）。
    /// Decode a status value.
    pub fn decode(value: u64) -> Option<HartState> {
        Some(match value {
            0 => HartState::Started,
            1 => HartState::Stopped,
            2 => HartState::StartPending,
            3 => HartState::StopPending,
            4 => HartState::Suspended,
            5 => HartState::SuspendPending,
            6 => HartState::ResumePending,
            _ => return None,
        })
    }

    /// 是否可以对它发出启动请求（只有「已停止」可以）。
    /// Whether `hart_start` may be issued.
    pub const fn startable(self) -> bool {
        matches!(self, HartState::Stopped)
    }
}

/// `send_ipi` 的参数：只含一个处理器的位图与基准（位图第 0 位 = 基准 hart 号本身），
/// 与寄存器宽度无关、hart 号可以任意大。
/// `send_ipi` arguments addressing exactly one hart.
pub const fn single_hart_mask(hart: usize) -> (usize, usize) {
    (1, hart)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_success_errors_and_garbage() {
        assert_eq!(decode(0), Ok(()));
        assert_eq!(decode(-1), Err(SbiError::Failed));
        assert_eq!(decode(-3), Err(SbiError::InvalidParam));
        assert_eq!(decode(-5), Err(SbiError::InvalidAddress));
        assert_eq!(decode(-6), Err(SbiError::AlreadyAvailable));
        assert_eq!(decode(-7), Err(SbiError::AlreadyStarted));
        assert_eq!(decode(-8), Err(SbiError::AlreadyStopped));
        assert_eq!(decode(1), Err(SbiError::Failed), "正值不是成功");
        assert_eq!(decode(-99), Err(SbiError::Failed), "未知错误码不是成功");
        assert_eq!(decode(i64::MIN), Err(SbiError::Failed));
    }

    #[test]
    fn errors_map_to_start_failures() {
        assert_eq!(SbiError::InvalidParam.to_smp(), SmpError::NoSuchCpu);
        assert_eq!(SbiError::AlreadyAvailable.to_smp(), SmpError::BadState);
        assert_eq!(SbiError::AlreadyStarted.to_smp(), SmpError::BadState);
        for e in [SbiError::Failed, SbiError::NotSupported, SbiError::Denied, SbiError::InvalidAddress, SbiError::AlreadyStopped] {
            assert_eq!(e.to_smp(), SmpError::StartFailed, "{:?}", e);
            assert!(e.name().starts_with("system.firmware.sbi.error."));
        }
    }

    #[test]
    fn hart_state_decode_and_startable() {
        assert_eq!(HartState::decode(1), Some(HartState::Stopped));
        assert!(HartState::Stopped.startable());
        for v in [0, 2, 3, 4, 5, 6] {
            let s = HartState::decode(v).expect("规范内的状态");
            assert!(!s.startable(), "{:?} 不可启动", s);
        }
        assert_eq!(HartState::decode(7), None, "规范之外的状态");
        assert_eq!(HartState::decode(u64::MAX), None);
        assert_eq!(single_hart_mask(5), (1, 5));
    }
}
