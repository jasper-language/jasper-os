//! 监管态二进制接口（SBI）调用：内核经 `ecall` 请求固件（如 OpenSBI）提供的机器态服务。
//! Supervisor Binary Interface calls to the machine-mode firmware.
//!
//! 只实现本内核用到的三项：探测扩展是否存在（基础扩展）、设置下一次定时器中断（TIME 扩展）、
//! 以「系统故障」为原因关机（系统复位扩展；仅在找不到仿真器测试设备时作为退出的后备路径）。
//! 调用约定：`a7` = 扩展号，`a6` = 功能号，参数在 `a0`–`a5`；返回 `a0` = 错误码、`a1` = 值。

/// 基础扩展。
const EID_BASE: u64 = 0x10;
/// 基础扩展：探测扩展。
const FID_PROBE_EXTENSION: u64 = 3;
/// TIME 扩展（"TIME"）。
pub const EID_TIME: u64 = 0x5449_4d45;
/// TIME 扩展：设置定时器。
const FID_SET_TIMER: u64 = 0;
/// 系统复位扩展（"SRST"）。
const EID_SRST: u64 = 0x5352_5354;
/// 系统复位扩展：复位。
const FID_SYSTEM_RESET: u64 = 0;
/// 复位类型：关机。
const RESET_SHUTDOWN: u64 = 0;
/// 复位原因：系统故障。
const REASON_SYSTEM_FAILURE: u64 = 1;

/// 一次 SBI 调用的结果。
struct SbiRet {
    error: i64,
    value: u64,
}

fn call(eid: u64, fid: u64, arg0: u64, arg1: u64) -> SbiRet {
    let (error, value): (i64, u64);
    // SAFETY：按 SBI 调用约定陷入固件；固件只修改 a0/a1 作为返回值。
    unsafe {
        core::arch::asm!(
            "ecall",
            inlateout("a0") arg0 => error,
            inlateout("a1") arg1 => value,
            in("a6") fid,
            in("a7") eid,
            options(nostack)
        );
    }
    SbiRet { error, value }
}

/// 固件是否实现了扩展 `eid`。
pub fn has_extension(eid: u64) -> bool {
    let r = call(EID_BASE, FID_PROBE_EXTENSION, eid, 0);
    r.error == 0 && r.value != 0
}

/// 让固件在 `time` 计数器到达 `deadline` 时触发监管态定时器中断；同时撤下当前挂起的定时器中断。
pub fn set_timer(deadline: u64) {
    let _ = call(EID_TIME, FID_SET_TIMER, deadline, 0);
}

/// 请求固件以「系统故障」为原因关机。固件不支持时返回（调用者随后停机）。
pub fn shutdown_failure() {
    if has_extension(EID_SRST) {
        let _ = call(EID_SRST, FID_SYSTEM_RESET, RESET_SHUTDOWN, REASON_SYSTEM_FAILURE);
    }
}
