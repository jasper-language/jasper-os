//! DRV-2B 演练：真实 virtio-rng 设备经 MSI-X 投递、改核、屏蔽与待决释放。
//! DRV-2B demo: real virtio-rng MSI-X delivery, retargeting, masking and pending release.
//!
//! # 职责
//! * 在已枚举的 PCI 设备表里找 virtio-rng，映射 MSI-X 表 / PBA 与现代 virtio 能力窗口。
//! * 为每个在线处理器分配并绑定一个 MSI 向量，把 MSI-X 表项 0 指向目标处理器，
//!   再让设备真正消费一个 64 字节随机数请求；只有目标处理器收到中断且处理函数恰好调用一次。
//! * 依次把表项改到其他在线处理器（单处理器时改到同核的第二个向量），每次都重新投递。
//! * 屏蔽表项后提交请求：设备置 PBA 待决位且不送达；解除屏蔽后待决位清除并恰好送达一次。
//! * 拒绝路径（越界向量 / 越界表项 / 越界处理器）在写任何寄存器之前被拒，表项与控制字段不变。
//! * 收尾复位设备、关闭 MSI-X、解绑并释放向量；页帧必须回到演练前的基线。
//!
//! # 边界
//! * 只处理一个 virtio-rng 功能与队列 0；不实现多队列、事件抑制或配置中断。
//! * 不含任何指令集专有值；MSI 消息由 [`crate::arch::msi_message`] 组合。
//! * 没有 virtio-rng 时如实输出 `skipped` 行并成功返回，不伪造设备。
//!
//! 每次送达输出 `[JSR-MSIX] dev … ok=true`，最后输出 `[JSR-MSIX] summary …`；
//! 断言失败输出 `[JSR-MSIX-FAIL] <原因>`，失败数进入 kmain 的失败列表。

use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::msi::{Vector, VectorPool};
use kernel_core::pci::{self as core_pci, MsixEntry};
use kernel_core::smp::{CpuSet, MAX_CPUS};

use crate::pci::Device;
use crate::virtio::{self, Queue, VirtioPci, BUFFER_BYTES};
use crate::{arch, irq, kprintln, mm, mmio, msix::MsixDevice, pci, sched};

/// 断言失败次数（验收要求为 0）。
static FAILED: AtomicU32 = AtomicU32::new(0);
/// 断言总数。
static CHECKS: AtomicU32 = AtomicU32::new(0);
/// 所有送达共用的处理函数调用次数（证明向量确实分发到处理函数）。
static HANDLED: AtomicU32 = AtomicU32::new(0);

/// 单次等待的 tick 上界（定时器 100 Hz 时约 2 秒）。
const WAIT_TICKS: u64 = 200;
/// 定时器未推进时的自旋上界，保证等待一定返回。
const MAX_SPINS: u64 = 50_000_000;
/// 确认「没有第二次送达」时的短暂自旋次数。
const SETTLE_SPINS: u64 = 200_000;
/// virtio-rng 使用的 MSI-X 表项下标（队列 0 的向量）。
const QUEUE_ENTRY: u16 = 0;

/// 记录一次断言；失败时打印原因。
fn check(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-MSIX-FAIL] {}", what);
    }
}

/// 断言失败次数。
/// Number of failed assertions.
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

/// 送达处理函数：只计数，证明 MSI-X 向量确实进入分发器并调用登记的处理函数。
fn handler() {
    HANDLED.fetch_add(1, Ordering::Relaxed);
}

/// 有界等待条件成立；tick 与自旋双重上界，绝不无限等待。
fn wait_until(mut cond: impl FnMut() -> bool) -> bool {
    let start = sched::timer_ticks();
    let mut spins = 0u64;
    loop {
        if cond() {
            return true;
        }
        if sched::timer_ticks().wrapping_sub(start) >= WAIT_TICKS || spins >= MAX_SPINS {
            return cond();
        }
        spins += 1;
        core::hint::spin_loop();
    }
}

/// 短暂自旋，用于确认没有第二次送达。
fn settle() {
    for _ in 0..SETTLE_SPINS {
        core::hint::spin_loop();
    }
}

/// 查找第一个 virtio-rng 功能；没有时返回 `None`。
fn find_rng() -> Option<&'static Device> {
    pci::table()
        .devices()
        .find(|device| device.header.vendor == virtio::VIRTIO_VENDOR && virtio::is_rng_device(device.header.device))
}

/// 一次演练的计数结果。
#[derive(Default, Clone, Copy)]
struct Outcome {
    /// 发起的送达次数。
    attempted: u32,
    /// 成功的送达次数。
    delivered: u32,
    /// 成功改核次数。
    retargets: u32,
    /// 屏蔽期间置待决位、解除屏蔽后送达并清除。
    masked_pending: bool,
}

/// 设备演练句柄：丢弃时先关 MSI-X，再把队列交给统一静默化路径（复位失败时隔离而不是归还队列页）。
struct Rig {
    virtio: VirtioPci,
    msix: MsixDevice,
    /// 队列用 `ManuallyDrop` 包住：丢弃时先取出来交给 [`virtio::quiesce`] 决定归还还是隔离。
    queue: ManuallyDrop<Queue>,
    notify_off: u16,
    /// 演练前总线主控位是否已打开；丢弃时恢复。
    bus_master_was_on: bool,
}

impl Rig {
    /// 复位设备、协商 `VIRTIO_F_VERSION_1`、建立队列 0、编程并启用 MSI-X 表项 0。
    fn new(device: &Device, cpu: usize, vector: u8) -> Result<Rig, &'static str> {
        let virtio = VirtioPci::new(device).map_err(|e| e.name())?;
        let mut msix = MsixDevice::new(device).map_err(|e| e.name())?;
        virtio.reset().map_err(|e| e.name())?;
        virtio.negotiate_version_1().map_err(|e| e.name())?;
        let mut queue = Queue::new().map_err(|e| e.name())?;
        let notify_off = virtio.setup_queue(&mut queue, QUEUE_ENTRY).map_err(|e| e.name())?;
        msix.program(QUEUE_ENTRY, cpu, vector, true).map_err(|e| e.name())?;
        msix.enable().map_err(|e| e.name())?;
        // MSI-X 消息与队列 DMA 都是设备发起的内存写：DRIVER_OK 之前必须打开总线主控。
        let bus_master_was_on = pci::set_bus_master(virtio.bdf(), true).map_err(|e| e.name())?;
        virtio.add_status(virtio::STATUS_DRIVER_OK);
        Ok(Rig { virtio, msix, queue: ManuallyDrop::new(queue), notify_off, bus_master_was_on })
    }

    /// 设备地址。
    fn bdf(&self) -> core_pci::Bdf {
        self.virtio.bdf()
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        // 先关闭 MSI-X（设备不再发消息），再把队列交给统一静默化路径：
        // 真实复位；复位超时就关总线主控并读回确认；读回不可信时隔离队列页而不是归还。
        let _ = self.msix.disable();
        // SAFETY：队列只在本函数里取走一次，取走后本结构不再使用该字段。
        let queue = unsafe { ManuallyDrop::take(&mut self.queue) };
        let _ = virtio::quiesce(&self.virtio, queue, !self.bus_master_was_on);
    }
}

/// 运行演练并输出汇总。
/// Run the demo and emit the summary.
pub fn run() {
    let Some(device) = find_rng() else {
        kprintln!("[JSR-MSIX] skipped reason=no_virtio_rng ok=true");
        return;
    };

    // 投递目标包含引导处理器：必须开中断，收尾时恢复调用前的状态。
    let was_enabled = arch::irq_save_disable();
    arch::irq_enable();
    let online = sched::online_cpus();
    let cpus = online.len();
    check(cpus > 0, "没有在线处理器");

    let mut outcome = Outcome::default();
    let mut frames_back = false;

    let mut vectors = [None; MAX_CPUS];
    let mut extra_vector = None;
    let mut masked_pending = false;

    if let Some(range) = arch::msi_vector_range() {
        match VectorPool::new(range.first, range.count, online) {
            Ok(pool) => {
                if prepare_vectors(&pool, online, &mut vectors, &mut extra_vector) {
                    mmio::prepare_window().map_or_else(
                        |e| check(false, e.name()),
                        |_| {
                            let baseline = mm::frame::free_frames();
                            match exercise(device, online, &vectors, extra_vector) {
                                Ok(result) => {
                                    outcome = result;
                                    masked_pending = result.masked_pending;
                                }
                                Err(reason) => check(false, reason),
                            }
                            frames_back = mm::frame::free_frames() == baseline;
                            check(frames_back, "页帧没有回到演练前的基线");
                        },
                    );
                }
                release_vectors(&pool, online, &vectors, extra_vector);
            }
            Err(e) => check(false, e.name()),
        }
    } else {
        check(false, "平台未提供 MSI 向量范围");
    }

    kprintln!(
        "[JSR-MSIX] summary cpus={} delivered={}/{} retargets={} masked_pending={} checks={} failed={} frames_back={}",
        cpus,
        outcome.delivered,
        outcome.attempted,
        outcome.retargets,
        if masked_pending && outcome.masked_pending { "ok" } else { "failed" },
        CHECKS.load(Ordering::Relaxed),
        FAILED.load(Ordering::Relaxed),
        if frames_back { "true" } else { "false" }
    );
    arch::irq_restore(was_enabled);
}

/// 为每个在线处理器分配并绑定一个向量；单处理器时再准备同核的第二个向量用于改向量。
fn prepare_vectors(
    pool: &VectorPool,
    online: CpuSet,
    vectors: &mut [Option<u8>; MAX_CPUS],
    extra: &mut Option<u8>,
) -> bool {
    let mut ok = true;
    for cpu in online.iter() {
        match pool.alloc(cpu) {
            Ok(vector) => match irq::msi_bind(cpu, vector.get(), Some(handler)) {
                Ok(()) => vectors[cpu] = Some(vector.get()),
                Err(e) => {
                    check(false, e.name());
                    ok = false;
                }
            },
            Err(e) => {
                check(false, e.name());
                ok = false;
            }
        }
    }
    if online.len() == 1 {
        let cpu = online.iter().next().unwrap_or(0);
        match pool.alloc(cpu) {
            Ok(vector) => match irq::msi_bind(cpu, vector.get(), Some(handler)) {
                Ok(()) => *extra = Some(vector.get()),
                Err(e) => {
                    check(false, e.name());
                    ok = false;
                }
            },
            Err(e) => {
                check(false, e.name());
                ok = false;
            }
        }
    }
    ok
}

/// 解绑并释放本轮取得的向量。
fn release_vectors(
    pool: &VectorPool,
    online: CpuSet,
    vectors: &[Option<u8>; MAX_CPUS],
    extra: Option<u8>,
) {
    for cpu in online.iter() {
        if let Some(vector) = vectors[cpu] {
            let _ = irq::msi_bind(cpu, vector, None);
            let _ = pool.free(cpu, Vector::new(vector));
        }
    }
    if let Some(vector) = extra {
        if let Some(cpu) = online.iter().next() {
            let _ = irq::msi_bind(cpu, vector, None);
            let _ = pool.free(cpu, Vector::new(vector));
        }
    }
}

/// 建立设备并完成全部送达、改核、屏蔽 / 待决、拒绝路径检查。
fn exercise(
    device: &Device,
    online: CpuSet,
    vectors: &[Option<u8>; MAX_CPUS],
    extra: Option<u8>,
) -> Result<Outcome, &'static str> {
    let Some(first) = online.iter().next() else {
        return Err("没有在线处理器");
    };
    let Some(first_vector) = vectors[first] else {
        return Err("引导处理器没有 MSI 向量");
    };

    let mut rig = Rig::new(device, first, first_vector)?;
    let queue_size = rig.queue.size();
    check(queue_size >= 2, "设备队列大小不可用");
    check(rig.virtio.status() & virtio::STATUS_DRIVER_OK != 0, "DRIVER_OK 没有置位");
    let bdf = rig.bdf();

    let mut outcome = Outcome::default();
    let mut target_cpu = first;
    let mut target_vector = first_vector;

    if deliver(&mut rig, bdf, target_cpu, target_vector, online, vectors, &mut outcome) {
        // 初始送达已经发生；以下改核都基于它继续。
    } else {
        return Ok(outcome);
    }

    for cpu in online.iter().skip(1) {
        let Some(vector) = vectors[cpu] else {
            check(false, "目标处理器没有 MSI 向量");
            continue;
        };
        if rig.msix.program(QUEUE_ENTRY, cpu, vector, true).is_err() {
            check(false, "改核时编程 MSI-X 表项失败");
            continue;
        }
        target_cpu = cpu;
        target_vector = vector;
        if deliver(&mut rig, bdf, cpu, vector, online, vectors, &mut outcome) {
            outcome.retargets = outcome.retargets.saturating_add(1);
        } else {
            return Ok(outcome);
        }
    }

    // 单处理器时没有别的核可改：改到同核的第二个向量，仍是一次真实改目标。
    if online.len() == 1 {
        if let Some(vector) = extra {
            if rig.msix.program(QUEUE_ENTRY, first, vector, true).is_err() {
                check(false, "同核改向量时编程 MSI-X 表项失败");
            } else {
                target_cpu = first;
                target_vector = vector;
                if deliver(&mut rig, bdf, first, vector, online, vectors, &mut outcome) {
                    outcome.retargets = outcome.retargets.saturating_add(1);
                }
            }
        } else {
            check(false, "单处理器改向量缺少第二个向量");
        }
    }

    outcome.masked_pending = mask_and_release(&mut rig, bdf, target_cpu, target_vector);
    rejection_check(&mut rig, target_cpu, target_vector);
    Ok(outcome)
}

/// 提交一个请求并等待「设备消费 + 目标处理器收到 MSI-X + 处理函数恰好一次」。
fn deliver(
    rig: &mut Rig,
    bdf: core_pci::Bdf,
    cpu: usize,
    vector: u8,
    online: CpuSet,
    vectors: &[Option<u8>; MAX_CPUS],
    outcome: &mut Outcome,
) -> bool {
    outcome.attempted = outcome.attempted.saturating_add(1);
    let mut before = [0u32; MAX_CPUS];
    for other in online.iter() {
        if let Some(own) = vectors[other] {
            before[other] = irq::msi_count(other, own);
        }
    }
    // 目标向量可能不是该核的常驻向量（单处理器改向量演练），单独取基线。
    let before_target = irq::msi_count(cpu, vector);
    let before_handled = HANDLED.load(Ordering::Relaxed);
    let before_spurious = irq::msi_spurious(cpu);

    let mut used_len = 0u32;
    let start = sched::timer_ticks();
    if let Err(e) = rig.queue.submit(0) {
        check(false, e.name());
        return false;
    }
    if let Err(e) = rig.virtio.notify(rig.notify_off) {
        check(false, e.name());
        return false;
    }
    let used = wait_until(|| match rig.queue.take_used() {
        Some((_, len)) => {
            used_len = len;
            true
        }
        None => false,
    });
    let arrived = wait_until(|| irq::msi_count(cpu, vector) != before_target);
    let latency = sched::timer_ticks().wrapping_sub(start);
    let handled = wait_until(|| HANDLED.load(Ordering::Relaxed) > before_handled);
    settle();
    let handled_once = HANDLED.load(Ordering::Relaxed) == before_handled + 1;

    // 目标向量恰好一次；其余每个核的常驻向量（目标核的常驻向量若不是目标向量也算）都不得收到。
    let mut only_target = irq::msi_count(cpu, vector).wrapping_sub(before_target) == 1;
    for other in online.iter() {
        let Some(own) = vectors[other] else { continue };
        if other == cpu && own == vector {
            continue;
        }
        only_target &= irq::msi_count(other, own).wrapping_sub(before[other]) == 0;
    }

    let ok = used && used_len == BUFFER_BYTES as u32 && arrived && only_target && handled && handled_once;
    check(used, "设备没有消费缓冲区");
    check(used_len == BUFFER_BYTES as u32, "设备写入字节数不是缓冲区大小");
    check(arrived, "目标处理器没有收到 MSI-X");
    check(only_target, "MSI-X 没有恰好送达目标处理器");
    check(handled && handled_once, "处理函数没有恰好调用一次");
    check(irq::msi_spurious(cpu) == before_spurious, "已绑定向量被记为伪 MSI");

    kprintln!(
        "[JSR-MSIX] dev bdf={:02x}:{:02x}.{} queue_size={} vector_cpu={} latency_ticks={} ok={}",
        bdf.bus(),
        bdf.device(),
        bdf.function(),
        rig.queue.size(),
        cpu,
        latency,
        ok
    );
    if ok {
        outcome.delivered = outcome.delivered.saturating_add(1);
    }
    ok
}

/// 屏蔽表项后提交请求：待决位置位且不送达；解除屏蔽后清除待决位并恰好送达一次。
fn mask_and_release(rig: &mut Rig, bdf: core_pci::Bdf, cpu: usize, vector: u8) -> bool {
    let pending_before = rig.msix.pending(QUEUE_ENTRY).unwrap_or(true);
    check(!pending_before, "屏蔽前 PBA 已有待决位");
    if rig.msix.mask(QUEUE_ENTRY).is_err() {
        check(false, "屏蔽 MSI-X 表项失败");
        return false;
    }
    let masked = rig.msix.entry(QUEUE_ENTRY).map(|entry: MsixEntry| entry.masked()).unwrap_or(false);
    check(masked, "表项屏蔽位没有置位");

    let before_count = irq::msi_count(cpu, vector);
    let before_handled = HANDLED.load(Ordering::Relaxed);
    if rig.queue.submit(0).is_err() || rig.virtio.notify(rig.notify_off).is_err() {
        check(false, "屏蔽期间提交请求失败");
        return false;
    }
    let used = wait_until(|| rig.queue.take_used().is_some());
    check(used, "屏蔽期间设备没有消费缓冲区");
    let pending = wait_until(|| rig.msix.pending(QUEUE_ENTRY).unwrap_or(false));
    check(pending, "屏蔽期间没有置 PBA 待决位");
    let not_delivered = irq::msi_count(cpu, vector) == before_count;
    check(not_delivered, "屏蔽期间仍然送达");

    if rig.msix.unmask(QUEUE_ENTRY).is_err() {
        check(false, "解除屏蔽失败");
        return false;
    }
    let arrived = wait_until(|| irq::msi_count(cpu, vector) > before_count);
    let handled = wait_until(|| HANDLED.load(Ordering::Relaxed) > before_handled);
    settle();
    let cleared = wait_until(|| !rig.msix.pending(QUEUE_ENTRY).unwrap_or(true));
    let once = HANDLED.load(Ordering::Relaxed) == before_handled + 1;
    check(arrived, "解除屏蔽后没有送达");
    check(handled && once, "解除屏蔽后处理函数没有恰好调用一次");
    check(cleared, "送达后 PBA 待决位没有清除");

    kprintln!(
        "[JSR-MSIX] pending dev bdf={:02x}:{:02x}.{} vector_cpu={} masked=true released=true ok={}",
        bdf.bus(),
        bdf.device(),
        bdf.function(),
        cpu,
        pending && arrived && cleared && not_delivered && once
    );
    pending && arrived && cleared && not_delivered && once && masked && used
}

/// 越界向量 / 越界表项 / 越界处理器全部被拒，表项与控制字段不变。
fn rejection_check(rig: &mut Rig, cpu: usize, vector: u8) {
    let Ok(entry_before) = rig.msix.entry(QUEUE_ENTRY) else {
        check(false, "读取拒绝路径前的表项失败");
        return;
    };
    let Ok(control_before) = rig.msix.control() else {
        check(false, "读取拒绝路径前的 MSI-X 控制字段失败");
        return;
    };

    let out_of_range = arch::msi_vector_range()
        .and_then(|range| range.first.checked_sub(1))
        .unwrap_or(0xFF);
    check(
        rig.msix.program(QUEUE_ENTRY, cpu, out_of_range, true).is_err(),
        "越界向量未被拒绝",
    );
    check(
        rig.msix.program(rig.msix.table_size(), cpu, vector, true).is_err(),
        "越界表项未被拒绝",
    );
    check(
        rig.msix.program(QUEUE_ENTRY, MAX_CPUS, vector, true).is_err(),
        "越界处理器未被拒绝",
    );

    check(
        rig.msix.entry(QUEUE_ENTRY).map(|entry| entry == entry_before).unwrap_or(false),
        "拒绝路径改变了表项",
    );
    check(
        rig.msix.control().map(|control| control == control_before).unwrap_or(false),
        "拒绝路径改变了 MSI-X 控制字段",
    );
}
