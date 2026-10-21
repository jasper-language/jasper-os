//! virtio 拆除时的静默化裁决：复位结果与总线主控读回共同决定队列页是归还还是隔离。
//! Quiescence verdict for virtio teardown: the reset outcome and the bus-master readback decide whether queue pages are released or quarantined.
//!
//! # 职责
//! * 把两个已经发生的事实——设备复位是否成功（[`ResetOutcome`]）、总线主控位读回是开还是关
//!   （`Option<bool>`）——映射为唯一的拆除裁决 [`QuiesceVerdict`]。
//! * 复位成功 ⇒ 设备已经停止使用队列内存，页帧可以安全归还；复位超时 ⇒ 设备可能仍在向队列页发起
//!   DMA 写，必须先关总线主控并读回确认：读回为「已关」才允许归还，读回仍开或读不回来都按不可信处理。
//!
//! # 边界
//! * 只做纯决策：不碰任何寄存器、不分配也不归还内存。关总线主控、读回与隔离动作由调用方执行。
//! * 读回的类型是 `Option<bool>`：`None` 表示读不回来（后端不可达），按最保守的一档处理，
//!   绝不把「读不到」当成「已经关掉」。
//!
//! # 为什么放在 kernel-core
//! 裁决与指令集、引导方式、设备型号都无关；放在这里可以在宿主上穷举全部输入组合并逐条测试成功与失败路径。

/// 复位的结果。
/// Outcome of a device reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetOutcome {
    /// 复位在限定时间内完成，设备已停止使用队列内存。
    /// The reset completed within the bound; the device no longer touches queue memory.
    Done,
    /// 复位超时：设备状态没有归零，它是否仍在发起 DMA 未知。
    /// The reset timed out; whether the device still issues DMA writes is unknown.
    TimedOut,
}

/// 拆除裁决：队列页立即归还、确认总线主控已关后归还，或永久隔离。
/// Teardown verdict: release the queue pages, release after bus master was confirmed off, or quarantine them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuiesceVerdict {
    /// 复位成功：队列页立即归还分配器。
    /// The reset succeeded; return the queue pages to the allocator.
    Released,
    /// 复位超时但读回确认总线主控已关：设备不会再写队列页，页帧可以归还。
    /// The reset timed out but the readback confirmed bus master is off, so the pages may be returned.
    ReleasedBusMasterOff,
    /// 设备不可信（总线主控仍开，或读回失败）：队列页永久隔离，不得归还。
    /// The device is not trustworthy; the queue pages are quarantined and never returned.
    Quarantine,
}

/// 按复位结果与总线主控读回给出拆除裁决。
///
/// `bus_master_readback` 只在复位超时才有意义：`Some(false)` 表示读回确认总线主控已关；
/// `Some(true)` 表示仍开；`None` 表示读不回来。复位成功时读回被忽略（设备已停止使用队列内存）。
/// Produces the teardown verdict from the reset outcome and the bus-master readback.
pub fn quiesce_verdict(reset: ResetOutcome, bus_master_readback: Option<bool>) -> QuiesceVerdict {
    match reset {
        ResetOutcome::Done => QuiesceVerdict::Released,
        ResetOutcome::TimedOut => match bus_master_readback {
            Some(false) => QuiesceVerdict::ReleasedBusMasterOff,
            Some(true) | None => QuiesceVerdict::Quarantine,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quiesce_done_releases_whatever_the_readback_says() {
        assert_eq!(quiesce_verdict(ResetOutcome::Done, None), QuiesceVerdict::Released);
        assert_eq!(quiesce_verdict(ResetOutcome::Done, Some(false)), QuiesceVerdict::Released);
        assert_eq!(quiesce_verdict(ResetOutcome::Done, Some(true)), QuiesceVerdict::Released);
    }

    #[test]
    fn quiesce_timeout_with_bus_master_off_releases() {
        assert_eq!(
            quiesce_verdict(ResetOutcome::TimedOut, Some(false)),
            QuiesceVerdict::ReleasedBusMasterOff
        );
    }

    #[test]
    fn quiesce_timeout_with_bus_master_still_on_quarantines() {
        assert_eq!(quiesce_verdict(ResetOutcome::TimedOut, Some(true)), QuiesceVerdict::Quarantine);
    }

    #[test]
    fn quiesce_timeout_with_unreadable_readback_quarantines() {
        assert_eq!(quiesce_verdict(ResetOutcome::TimedOut, None), QuiesceVerdict::Quarantine);
    }
}
