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
    // 准入使用当前 Profile 声明的内存策略（standard 压力感知 / compact 固定阈值）。
    let r = st.params.admit_with(crate::config::ACTIVE.policy.memory, requester, frames, free, total);
    st.stats.record(requester, r);
    r
}

/// 当前压力级别。
pub fn level() -> PressureLevel {
    let (free, total) = (frame::free_frames(), frame::usable_frames());
    STATE
        .lock()
        .params
        .level_with(crate::config::ACTIVE.policy.memory, free, total)
}

/// 生效参数。
pub fn params() -> PressureParams {
    STATE.lock().params
}

/// 替换参数（构建期配置档或管理者调用）；返回旧参数。参数已由 `PressureParams::new` 校验。
pub fn set_params(p: PressureParams) -> PressureParams {
    let old=core::mem::replace(&mut STATE.lock().params, p);
    note_frame_change();old
}

/// 统计快照。
pub fn stats() -> PressureStats {
    STATE.lock().stats
}

/// 清零统计（每个测量场景开始前调用）。
pub fn reset_stats() {
    STATE.lock().stats = PressureStats::new();
}

// One bounded global publisher, lazy initialized; independent of creating Process.
// Frame/pressure locks only set a dirty bit. Object delivery runs after those locks.
use core::sync::atomic::{AtomicBool,AtomicU64,Ordering};
use kernel_core::objtable::ObjId;
static EVENT_SOURCE:AtomicU64=AtomicU64::new(0);
static EVENT_DIRTY:AtomicBool=AtomicBool::new(false);
static EVENT_EXHAUSTED:AtomicBool=AtomicBool::new(false);
fn event_value()->u64 {match level() {PressureLevel::Normal=>0,PressureLevel::Low=>1,PressureLevel::Critical=>2}}
pub(crate) fn note_frame_change() {
 if EVENT_SOURCE.load(Ordering::Acquire)!=0 {EVENT_DIRTY.store(true,Ordering::Release);}
}
pub(crate) fn source_in(t:&mut crate::kobj::Table)->Result<ObjId,crate::subscription::Error> {
 if EVENT_EXHAUSTED.load(Ordering::Acquire) {return Err(crate::subscription::Error::Exhausted);}
 if let Some(id)=ObjId::from_raw(EVENT_SOURCE.load(Ordering::Acquire)) {sync_in(t,id);return Ok(id);}
 let id=crate::subscription::create_publisher_in(t,kernel_core::subscription::Snapshot {version:0,value:event_value()})?;
 crate::subscription::policies_in(t,id,2); // State source; not an additive count.
 EVENT_SOURCE.store(id.raw(),Ordering::Release);EVENT_DIRTY.store(true,Ordering::Release);Ok(id)
}
fn sync_in(t:&mut crate::kobj::Table,id:ObjId) {
 EVENT_DIRTY.swap(false,Ordering::AcqRel);
 let value=event_value();
 if crate::subscription::snapshot_in(t,id).is_some_and(|s|s.value!=value) {
  if crate::subscription::publish_in(t,id,value).is_err() {
   EVENT_EXHAUSTED.store(true,Ordering::Release);EVENT_SOURCE.store(0,Ordering::Release);
   crate::subscription::finish_publisher_in(t,id);
  }
 }
}
/// Called without locks at syscall exit and the BSP timer dispatch boundary.
/// State coalescing samples the latest pressure; no event or wake for unchanged state.
pub(crate) fn sync_events() {
 let Some(id)=ObjId::from_raw(EVENT_SOURCE.load(Ordering::Acquire)) else {return};
 if !EVENT_DIRTY.load(Ordering::Acquire) {return;}
 crate::kobj::with(|t|sync_in(t,id));
}
