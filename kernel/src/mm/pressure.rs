//! 内存压力服务：按全局空闲帧判级，按请求者的服务质量档位准入。
//! Memory-pressure service: level from global free frames, admission by the requester's QoS class.
//!
//! 职责：把 `kernel_core::pressure` 的纯判定接到真实的页帧分配器上，并保存生效参数与统计。
//! 边界：只做**准入**（在分配任何帧之前调用），不分配、不回收；每进程的帧配额仍由进程模块负责，
//! 两者叠加——配额限制单个进程的总量，压力准入在全局紧张时先拒绝低档请求。
//! 内存紧张时拒绝而不是换页：本内核没有换页，被拒的请求立刻得到「内存不足」错误，已有的映射不受影响。

use kernel_core::pressure::{PressureLevel, PressureParams, PressureStats, Refusal};

use crate::mm::frame;
use crate::sched::policy::Qos;
use crate::sync::IrqSpinLock;

struct State {
    params: PressureParams,
    stats: PressureStats,
}

static STATE: IrqSpinLock<State> = IrqSpinLock::ranked(crate::lockorder::MEMORY_PRESSURE, State { params: crate::config::ACTIVE.memory.pressure, stats: PressureStats::new() });

/// 为 `requester`（有效档位；`None` = 内核内部）申请 `frames` 个帧做准入判定，并记入统计。
/// 成功返回分配后的级别。
/// Admission check for `frames` frames on behalf of `requester`.
pub fn admit(requester: Option<Qos>, frames: usize) -> Result<PressureLevel, Refusal> {
    let free = frame::free_frames();
    let total = frame::usable_frames();
    let mut st = STATE.lock();
    let r = st.params.admit(requester, frames, free, total);
    st.stats.record(requester, r);
    r
}

/// 当前压力级别。
pub fn level() -> PressureLevel {
    let (free, total) = (frame::free_frames(), frame::usable_frames());
    STATE.lock().params.level(free, total)
}

/// 生效参数。
pub fn params() -> PressureParams {
    STATE.lock().params
}

/// 替换参数（构建期配置档或管理者调用）；返回旧参数。参数已由 `PressureParams::new` 校验。
pub fn set_params(p: PressureParams) -> PressureParams {
    core::mem::replace(&mut STATE.lock().params, p)
}

/// 统计快照。
pub fn stats() -> PressureStats {
    STATE.lock().stats
}

/// 清零统计（每个测量场景开始前调用）。
pub fn reset_stats() {
    STATE.lock().stats = PressureStats::new();
}
