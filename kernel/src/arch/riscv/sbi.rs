//! 监管态二进制接口（SBI）调用：内核经 `ecall` 请求固件（如 OpenSBI）提供的机器态服务。
//! Supervisor Binary Interface calls to the machine-mode firmware.
//!
//! 只实现本内核用到的几项：探测扩展是否存在（基础扩展）、设置下一次定时器中断（TIME 扩展）、
//! 以「系统故障」为原因关机（系统复位扩展；仅在找不到仿真器测试设备时作为退出的后备路径）、
//! 启动与查询处理器（HSM 扩展）、发送核间中断（IPI 扩展）。HSM / IPI 的编号与返回值解读在 `kernel_core::sbi`。
//! 调用约定：`a7` = 扩展号，`a6` = 功能号，参数在 `a0`–`a5`；返回 `a0` = 错误码、`a1` = 值。
//! 寄存器与 XLEN 同宽：RV32 上 64 位的定时器截止时刻按规范拆成 `a0`（低 32 位）与 `a1`（高 32 位）。

/// 基础扩展。
const EID_BASE: usize = 0x10;
/// 基础扩展：探测扩展。
const FID_PROBE_EXTENSION: usize = 3;
/// TIME 扩展（"TIME"）。
pub const EID_TIME: usize = 0x5449_4d45;
/// TIME 扩展：设置定时器。
const FID_SET_TIMER: usize = 0;
/// 系统复位扩展（"SRST"）。
const EID_SRST: usize = 0x5352_5354;
/// 系统复位扩展：复位。
const FID_SYSTEM_RESET: usize = 0;
/// 复位类型：关机。
const RESET_SHUTDOWN: usize = 0;
/// 复位原因：系统故障。
const REASON_SYSTEM_FAILURE: usize = 1;

/// 一次 SBI 调用的结果。
struct SbiRet {
    error: isize,
    value: usize,
}

fn call(eid: usize, fid: usize, arg0: usize, arg1: usize) -> SbiRet {
    call3(eid, fid, arg0, arg1, 0)
}

fn call3(eid: usize, fid: usize, arg0: usize, arg1: usize, arg2: usize) -> SbiRet {
    let (error, value): (isize, usize);
    // SAFETY：按 SBI 调用约定陷入固件；固件只修改 a0/a1 作为返回值。
    unsafe {
        core::arch::asm!(
            "ecall",
            inlateout("a0") arg0 => error,
            inlateout("a1") arg1 => value,
            in("a2") arg2,
            in("a6") fid,
            in("a7") eid,
            options(nostack)
        );
    }
    SbiRet { error, value }
}

/// 固件是否实现了扩展 `eid`。
pub fn has_extension(eid: usize) -> bool {
    let r = call(EID_BASE, FID_PROBE_EXTENSION, eid, 0);
    r.error == 0 && r.value != 0
}

/// 让固件在 `time` 计数器到达 `deadline` 时触发监管态定时器中断；同时撤下当前挂起的定时器中断。
pub fn set_timer(deadline: u64) {
    #[cfg(target_arch = "riscv64")]
    let _ = call(EID_TIME, FID_SET_TIMER, deadline as usize, 0);
    #[cfg(target_arch = "riscv32")]
    let _ = call(EID_TIME, FID_SET_TIMER, deadline as u32 as usize, (deadline >> 32) as usize);
}

/// 请求固件以「系统故障」为原因关机。固件不支持时返回（调用者随后停机）。
pub fn shutdown_failure() {
    if has_extension(EID_SRST) {
        let _ = call(EID_SRST, FID_SYSTEM_RESET, RESET_SHUTDOWN, REASON_SYSTEM_FAILURE);
    }
}

/// 请求固件从 `entry`（物理地址，地址转换关闭、监管态）启动处理器 `hart`，入口处 `a0` = hart 号、`a1` = `opaque`。
/// 返回固件的原始错误码（按有符号数解释）。
pub fn hart_start(hart: usize, entry: usize, opaque: usize) -> i64 {
    call3(kernel_core::sbi::EID_HSM, kernel_core::sbi::FID_HART_START, hart, entry, opaque).error as i64
}

/// 查询处理器 `hart` 的状态：成功返回原始状态值，失败返回原始错误码。
pub fn hart_status(hart: usize) -> Result<u64, i64> {
    let r = call(kernel_core::sbi::EID_HSM, kernel_core::sbi::FID_HART_GET_STATUS, hart, 0);
    if r.error == 0 {
        Ok(r.value as u64)
    } else {
        Err(r.error as i64)
    }
}

/// 向处理器 `hart` 发送监管态软件中断，返回固件的原始错误码。
pub fn send_ipi(hart: usize) -> i64 {
    let (mask, base) = kernel_core::sbi::single_hart_mask(hart);
    call(kernel_core::sbi::EID_IPI, kernel_core::sbi::FID_SEND_IPI, mask, base).error as i64
}
