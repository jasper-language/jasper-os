//! 内核全局结构化事件追踪器（`system.trace` 领域的内核实例）。
//!
//! # 职责
//! 持有唯一的 [`Tracer`]（保留最近 [`CAPACITY`] 条事件），提供 [`emit`] / [`stats`] / [`with`]。
//! 追踪器的机制（环形缓冲、序号、截断）在 `kernel-core::trace`，宿主已测；这里只决定
//! 「放在哪、用什么锁」：用 [`IrqSpinLock`]，因此中断上下文与任务都能安全记录事件。
//!
//! # 边界
//! 不负责呈现：默认不装观察者（避免每条事件都刷串口）；需要时调用者用 [`set_sink`] 接上。

use kernel_core::trace::{Tag, TraceSink, Tracer};

use crate::sync::IrqSpinLock;

/// 追踪缓冲容量（条）。
pub const CAPACITY: usize = 32;

static TRACER: IrqSpinLock<Tracer<CAPACITY>> = IrqSpinLock::new(Tracer::new());

/// 记录一条结构化事件，返回序号。
pub fn emit(name: &'static str, tags: &[Tag]) -> u64 {
    TRACER.lock().emit(name, tags)
}

/// 安装观察者。
pub fn set_sink(sink: TraceSink) {
    TRACER.lock().set_sink(sink);
}

/// `(缓冲中保留的条数, 迄今记录的总数)`。
pub fn stats() -> (usize, u64) {
    let t = TRACER.lock();
    (t.len(), t.total())
}

/// 在锁内只读访问追踪器（闭包内不得再调用本模块的函数，否则自锁）。
pub fn with<R>(f: impl FnOnce(&Tracer<CAPACITY>) -> R) -> R {
    f(&TRACER.lock())
}
