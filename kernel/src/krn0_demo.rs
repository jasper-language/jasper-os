//! 中断到达计数回绕自检 + virtio 拆除时的 DMA 静默化自检。
//! Boot-time self-checks: interrupt arrival counting across the `u32` wrap, and virtio DMA teardown.
//!
//! # 做什么
//! * 用一个局部计数器（初值 `u32::MAX - 3`），经分发器**同一个**递增函数 [`irq::count_arrival`] 记 6 次到达，
//!   再用中断对象**同一个**求差函数 [`arrivals_since`] 计算增量，必须为 6；
//!   边界：两次读数相同 ⇒ 增量为 0（不得把当前读数整体当成新到达）。
//! * 在真实 virtio-rng 设备上反复「复位 → 协商 → 建立队列 → 开总线主控」，再按三种方式拆除，
//!   核对队列页的去向：真实复位成功 ⇒ 归还；注入复位超时 + 真实关总线主控并读回为「已关」⇒ 归还；
//!   注入复位超时 + 读回仍开 ⇒ 队列页被隔离（[`virtio::quarantined_frames`] 增加、空闲帧等量减少）。
//!   最后 64 轮交替三种场景，核对隔离数只来自不可信轮次且空闲帧与隔离计数守恒。
//!   每个场景开始时的真实复位都必须成功：设备被注入超时后仍可恢复。
//!
//! # 边界与原因
//! * 不写任何真实槽位的计数：真实计数被中断对象与其他演练按读数差使用，人为改写会破坏它们；
//!   局部计数器走的是与真实路径完全相同的代码，因此足以证明回绕下不丢到达。
//! * DMA 拆除只在注入闭包里伪造「复位超时」与「读回结果」这两步观测；关总线主控、读回与隔离
//!   都是真实动作。没有 virtio-rng 设备时如实输出 `skipped` 行并视为成功，不伪造设备。
//!
//! 输出 `[JSR-KRN0] case=…` 与 `[JSR-KRN0] summary irq_count failed=<n>`、`summary dma_teardown failed=<n>`；
//! 不符时输出 `[JSR-KRN0-FAIL] <原因>` 并计入失败数。

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::dma_quiesce::{QuiesceVerdict, ResetOutcome};
use kernel_core::interrupt::arrivals_since;

use crate::virtio::{self, Queue, VirtioPci};
use crate::{irq, kprintln, mm, mmio, pci};

/// 回绕用例的起始读数。
/// Starting reading of the wrap case.
const WRAP_START: u32 = u32::MAX - 3;
/// 回绕用例记的到达次数。
/// Arrivals counted in the wrap case.
const WRAP_ARRIVALS: u32 = 6;

/// DMA 拆除演练的轮数。
/// Number of rounds in the DMA teardown case.
const DMA_ROUNDS: u64 = 64;
/// 多轮循环里三种拆除场景的排列方式：轮号除以 3。
/// Scenario rotation across rounds: the round number modulo 3.
const DMA_SCENARIOS: u64 = 3;
/// DMA 拆除演练使用的队列与 MSI-X 表项（队列 0，表项 0）。
/// Queue and MSI-X entry used by the DMA teardown case.
const DMA_QUEUE_ENTRY: u16 = 0;

static FAILED: AtomicU32 = AtomicU32::new(0);
/// DMA 拆除自检的断言失败次数（与回绕自检分开计数，各自的汇总行互不掺入）。
/// Failed assertions of the DMA teardown self-check, counted separately.
static DMA_FAILED: AtomicU32 = AtomicU32::new(0);

fn check(ok: bool, what: &str) {
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-KRN0-FAIL] {}", what);
    }
}

/// 记录一次 DMA 拆除自检的断言；失败时打印原因。
fn dma_check(ok: bool, what: &str) {
    if !ok {
        DMA_FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-KRN0-FAIL] {}", what);
    }
}

/// 运行自检并输出汇总。
/// Run the self-check and emit the summary.
pub fn run() {
    let counter = AtomicU32::new(WRAP_START);
    let seen = counter.load(Ordering::Acquire);
    for _ in 0..WRAP_ARRIVALS {
        irq::count_arrival(&counter);
    }
    let now = counter.load(Ordering::Acquire);
    let delta = arrivals_since(seen, now);
    let wrapped = now < seen;
    let ok = delta == WRAP_ARRIVALS && wrapped;
    check(wrapped, "计数器没有跨越 u32 回绕");
    check(delta == WRAP_ARRIVALS, "回绕后的到达增量不等于实际到达次数");
    kprintln!(
        "[JSR-KRN0] case=irq_count_wrap start={} arrivals={} delta={} ok={}",
        seen,
        WRAP_ARRIVALS,
        delta,
        ok
    );

    let same = counter.load(Ordering::Acquire);
    let delta_same = arrivals_since(same, counter.load(Ordering::Acquire));
    check(delta_same == 0, "读数未变时增量不为 0");
    kprintln!("[JSR-KRN0] case=irq_count_same delta={} ok={}", delta_same, delta_same == 0);

    kprintln!("[JSR-KRN0] summary irq_count failed={}", failed());
}

/// 断言失败次数（回绕自检与 DMA 拆除自检合计）。
/// Number of failed assertions across both self-checks.
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed) + DMA_FAILED.load(Ordering::Relaxed)
}

/// 拆除裁决在串口输出里的名字。
/// Verdict name used in the serial output.
fn verdict_name(verdict: QuiesceVerdict) -> &'static str {
    match verdict {
        QuiesceVerdict::Released => "released",
        QuiesceVerdict::ReleasedBusMasterOff => "bus_master_off",
        QuiesceVerdict::Quarantine => "quarantine",
    }
}

/// 运行 DMA 拆除自检并输出汇总：在真实 virtio-rng 上按三种方式拆除队列，核对页帧去向。
/// Runs the DMA teardown self-check on the real virtio-rng device and emits the summary.
pub fn run_dma() {
    let Some(device) = pci::table()
        .devices()
        .find(|d| d.header.vendor == virtio::VIRTIO_VENDOR && virtio::is_rng_device(d.header.device))
    else {
        kprintln!("[JSR-KRN0] dma_teardown skipped=no_device");
        return;
    };
    if let Err(e) = mmio::prepare_window() {
        dma_check(false, e.name());
    }
    let handle = match VirtioPci::new(device) {
        Ok(handle) => handle,
        Err(e) => {
            dma_check(false, e.name());
            kprintln!("[JSR-KRN0] summary dma_teardown failed={}", DMA_FAILED.load(Ordering::Relaxed));
            return;
        }
    };
    let baseline = mm::frame::free_frames();
    let quarantined0 = virtio::quarantined_frames();
    dma_reset_ok(&handle, baseline);
    dma_reset_timeout_bm_off(&handle, baseline);
    dma_reset_timeout_untrusted(&handle, baseline);
    dma_rounds(&handle, baseline, quarantined0);
    kprintln!("[JSR-KRN0] summary dma_teardown failed={}", DMA_FAILED.load(Ordering::Relaxed));
}

/// 在真实设备上建立一条可拆除的队列：真实复位（必须成功）、协商 `VIRTIO_F_VERSION_1`、
/// 建立队列 0、打开总线主控。任何一步失败都记一次断言失败并返回 `None`（不再继续这个场景）。
fn dma_setup(handle: &VirtioPci) -> Option<Queue> {
    if handle.reset().is_err() {
        dma_check(false, "拆除场景开始时的真实复位没有成功");
        return None;
    }
    if handle.negotiate_version_1().is_err() {
        dma_check(false, "拆除场景的特性协商失败");
        return None;
    }
    let mut queue = match Queue::new() {
        Ok(queue) => queue,
        Err(e) => {
            dma_check(false, e.name());
            return None;
        }
    };
    if handle.setup_queue(&mut queue, DMA_QUEUE_ENTRY).is_err() {
        dma_check(false, "拆除场景无法建立队列 0");
        return None;
    }
    if pci::set_bus_master(handle.bdf(), true).is_err() {
        dma_check(false, "拆除场景无法打开总线主控");
        return None;
    }
    Some(queue)
}

/// 场景一：真实复位成功 ⇒ 裁决为释放，队列页归还分配器，空闲帧回到基线。
fn dma_reset_ok(handle: &VirtioPci, baseline: usize) {
    let Some(queue) = dma_setup(handle) else { return };
    let verdict = virtio::quiesce(handle, queue, true);
    let released = verdict == QuiesceVerdict::Released;
    let frames_back = mm::frame::free_frames() == baseline;
    dma_check(released, "真实复位成功后没有走释放路径");
    dma_check(frames_back, "真实复位成功后队列页没有回到基线");
    kprintln!(
        "[JSR-KRN0] case=dma_reset_ok verdict={} frames_back={} ok={}",
        verdict_name(verdict),
        frames_back,
        released && frames_back
    );
}

/// 场景二：注入复位超时，真实关闭总线主控并真实读回 ⇒ 读回为「已关」，队列页归还。
fn dma_reset_timeout_bm_off(handle: &VirtioPci, baseline: usize) {
    let Some(queue) = dma_setup(handle) else { return };
    let bdf = handle.bdf();
    // 只有复位这一步是注入的；关总线主控与读回都走真实路径。
    let verdict = virtio::quiesce_with(
        handle,
        queue,
        true,
        || ResetOutcome::TimedOut,
        || pci::bus_master_enabled(bdf).ok(),
    );
    let bus_master_off = verdict == QuiesceVerdict::ReleasedBusMasterOff;
    let readback_off = matches!(pci::bus_master_enabled(bdf), Ok(false));
    let frames_back = mm::frame::free_frames() == baseline;
    dma_check(bus_master_off, "总线主控读回为「已关」后没有走释放路径");
    dma_check(readback_off, "关闭总线主控后的读回不是「已关」");
    dma_check(frames_back, "总线主控读回为「已关」后队列页没有回到基线");
    kprintln!(
        "[JSR-KRN0] case=dma_reset_timeout_bm_off verdict={} readback={} frames_back={} ok={}",
        verdict_name(verdict),
        if readback_off { "off" } else { "on" },
        frames_back,
        bus_master_off && readback_off && frames_back
    );
}

/// 场景三：注入复位超时 + 注入读回「总线主控仍开」⇒ 设备不可信，队列页被隔离且永不归还。
fn dma_reset_timeout_untrusted(handle: &VirtioPci, baseline: usize) {
    let Some(queue) = dma_setup(handle) else { return };
    let before = virtio::quarantined_frames();
    // 注入的读回声称总线主控仍开：即便真实寄存器已被关掉，设备仍按不可信处理。
    let verdict = virtio::quiesce_with(handle, queue, true, || ResetOutcome::TimedOut, || Some(true));
    let held = virtio::quarantined_frames() - before;
    let quarantined = verdict == QuiesceVerdict::Quarantine;
    let missing = baseline.saturating_sub(mm::frame::free_frames());
    let held_ok = held == virtio::QUEUE_PAGES && missing == virtio::QUEUE_PAGES;
    dma_check(quarantined, "读回仍开时没有走隔离路径");
    dma_check(held_ok, "隔离后隔离计数与空闲帧的减少量不一致");
    kprintln!(
        "[JSR-KRN0] case=dma_reset_timeout_untrusted verdict={} held={} ok={}",
        verdict_name(verdict),
        held,
        quarantined && held_ok
    );
}

/// 场景四：[`DMA_ROUNDS`] 轮交替三种场景，核对每轮裁决、隔离数只来自不可信轮次、页帧守恒。
fn dma_rounds(handle: &VirtioPci, baseline: usize, quarantined0: usize) {
    let start_frames = mm::frame::free_frames();
    let start_quarantined = virtio::quarantined_frames();
    let mut untrusted = 0u64;
    let mut verdicts_ok = true;
    for round in 0..DMA_ROUNDS {
        let Some(queue) = dma_setup(handle) else {
            verdicts_ok = false;
            break;
        };
        let bdf = handle.bdf();
        let verdict = match round % DMA_SCENARIOS {
            0 => virtio::quiesce(handle, queue, true),
            1 => virtio::quiesce_with(
                handle,
                queue,
                true,
                || ResetOutcome::TimedOut,
                || pci::bus_master_enabled(bdf).ok(),
            ),
            _ => {
                let verdict =
                    virtio::quiesce_with(handle, queue, true, || ResetOutcome::TimedOut, || Some(true));
                if verdict == QuiesceVerdict::Quarantine {
                    untrusted += 1;
                }
                verdict
            }
        };
        let expected = match round % DMA_SCENARIOS {
            0 => QuiesceVerdict::Released,
            1 => QuiesceVerdict::ReleasedBusMasterOff,
            _ => QuiesceVerdict::Quarantine,
        };
        verdicts_ok &= verdict == expected;
    }
    let quarantined = virtio::quarantined_frames() - start_quarantined;
    let held_ok = quarantined as u64 == untrusted * virtio::QUEUE_PAGES as u64;
    let conserved = mm::frame::free_frames() + (virtio::quarantined_frames() - quarantined0) == baseline
        && start_frames == mm::frame::free_frames() + quarantined;
    let ok = verdicts_ok && held_ok && conserved;
    dma_check(verdicts_ok, "多轮拆除中有用例没有得到预期裁决");
    dma_check(held_ok, "多轮拆除的隔离数与不可信轮数不一致");
    dma_check(conserved, "多轮拆除后空闲帧与隔离计数不守恒");
    kprintln!(
        "[JSR-KRN0] case=dma_rounds rounds={} quarantined={} conserved={} ok={}",
        DMA_ROUNDS,
        quarantined,
        conserved,
        ok
    );
}
