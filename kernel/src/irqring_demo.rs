//! DRV-2C-1 演练：真实 virtio-rng 的 MSI-X 中断经中断对象成为用户 Ring 上的一条完成。
//! DRV-2C-1 demo: a real virtio-rng MSI-X interrupt becomes one completion on a user ring via an interrupt object.
//!
//! # 做什么
//! * 内核侧持有 virtio 队列与 DMA 页（用户态 DMA 不在本步范围内），只启动设备、不碰 MSI-X 表。
//! * 用户程序 `user-irqprobe` 打开设备、建立 Ring，经 `system.device.interrupt.create` 把表项 0 绑定到某个处理器，
//!   再经 Ring 提交 `system.device.interrupt.wait` 并进入等待。
//! * 内核驱动任务观察中断对象的状态（有未完成的等待、绑定序号是新的）后才让设备消费一个 64 字节请求——
//!   不靠固定延时猜测对方进度。多处理器时依次绑定到每个在线处理器各做一轮，单处理器时做两轮。
//!   每轮核对：用户收到恰好一次完成且结果为 1（用户侧断言）、只有目标核的向量计数加一、分发恰好一次、
//!   已用环推进 1、任何处理器都没有伪 MSI。
//! * 取消语义：用户取消一个等待后停在一个长时间的 `system.time.wait` 上；驱动确认此时没有等待者后让设备产生中断，
//!   确认到达已记入中断对象（待交付 1 次），再取消那个时间等待；用户随即提交的新等待必须立刻以 1 完成。
//! * 用户程序退出后核对：向量全部归还、表项已屏蔽、功能 MSI-X 已关闭、页帧与对象数回到基线。
//!
//! 输出 `[JSR-IRQRING] round=…`、`[JSR-IRQRING] summary …`；失败输出 `[JSR-IRQRING-FAIL] <原因>` 并计入失败数。
//! 没有 virtio-rng 时输出 `skipped` 行并视为成功。

use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use kernel_core::frame::FRAME_SIZE;
use kernel_core::paging::MapFlags;
use kernel_core::pci::Bdf;
use kernel_core::smp::MAX_CPUS;
use spin::Mutex;

use crate::mm::frame;
use crate::pci::Device;
use crate::proc::{self, ProcState};
use crate::syscall::{table as abi, SyscallSet};
use crate::task::TaskId;
use crate::virtio::{self, Queue, VirtioPci, BUFFER_BYTES};
use crate::{arch, interrupt, irq, kobj, kprintln, mmio, pci, ring, sched};

/// 用户栈顶部在私有窗口内的偏移（与其它 ELF 演练一致）。
const STACK_OFF: u64 = 0xC0_0000;
/// 驱动任务的任务号。
const DRIVER_TASK: u64 = 12_000;
/// 驱动任务等待单个条件的 tick 上界（定时器 100 Hz 时约 10 秒）。
const WAIT_TICKS: u64 = 1_000;
/// virtio-rng 队列 0 使用的 MSI-X 表项。
const QUEUE_ENTRY: u16 = 0;
/// 用户程序报告的退出码各字段（与 `user-irqprobe` 一致）。
const EXIT_REJECTS_OK: u32 = 0xFF;
const EXIT_REJECTS_TOTAL_SHIFT: u32 = 8;
const EXIT_ROUNDS_SHIFT: u32 = 16;
const EXIT_CANCEL_OK: i64 = 1 << 24;
const EXIT_CLOSE_OK: i64 = 1 << 25;
const EXIT_FAILED: i64 = 1 << 26;

/// 内嵌的用户程序 `user-irqprobe`（由 `kernel/build.rs` 在 x86_64 上构建）。
static USER_IRQPROBE: &[u8] = include_bytes!(env!("JSR_USER_IRQPROBE"));

static CHECKS: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);

/// 驱动任务与演练主体共享的状态（驱动任务开始时取走设备，结束时放回）。
static RIG: Mutex<Slot> = Mutex::new(Slot(None));

/// 设备的交接位：演练主体放入，驱动任务取走使用后放回。
struct Slot(Option<Rig>);

// SAFETY：队列里的裸指针指向内核独占的 DMA 页（经物理映射访问），不与任何线程绑定；
// 同一时刻只有持有这把锁、或从交接位取走设备的那一个任务访问它。
unsafe impl Send for Slot {}
/// 驱动任务的输入：设备地址（打包）、轮数、用户进程。
static TARGET_BDF: AtomicU32 = AtomicU32::new(0);
static ROUNDS: AtomicU32 = AtomicU32::new(0);
static USER_PID: AtomicU64 = AtomicU64::new(0);
/// 驱动任务的输出：成功的轮数、取消语义是否成立、是否已结束。
static ROUNDS_OK: AtomicU32 = AtomicU32::new(0);
static CANCEL_OK: AtomicBool = AtomicBool::new(false);
static DRIVER_DONE: AtomicBool = AtomicBool::new(false);

fn check(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-IRQRING-FAIL] {}", what);
    }
}

/// 断言失败次数。
/// Number of failed assertions.
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

/// 内核侧持有的设备（中断风暴演练复用）：丢弃时先复位设备，再把队列交给统一静默化路径。
/// Kernel-held virtio-rng device used by the interrupt demos.
pub(crate) struct Rig {
    virtio: VirtioPci,
    /// 队列用 `ManuallyDrop` 包住：丢弃时先取出来交给 [`virtio::quiesce`] 决定归还还是隔离。
    pub(crate) queue: ManuallyDrop<Queue>,
    notify_off: u16,
    bus_master_was_on: bool,
}

impl Rig {
    /// 复位设备、协商 `VIRTIO_F_VERSION_1`、建立队列 0（中断走表项 0）、打开总线主控并置 DRIVER_OK。
    /// MSI-X 表项由用户程序经中断对象绑定，这里不碰。
    /// Reset and start the device with queue 0 on MSI-X entry 0.
    pub(crate) fn new(device: &Device) -> Result<Rig, &'static str> {
        let virtio = VirtioPci::new(device).map_err(|e| e.name())?;
        virtio.reset().map_err(|e| e.name())?;
        virtio.negotiate_version_1().map_err(|e| e.name())?;
        let mut queue = Queue::new().map_err(|e| e.name())?;
        let notify_off = virtio.setup_queue(&mut queue, QUEUE_ENTRY).map_err(|e| e.name())?;
        let bus_master_was_on = pci::set_bus_master(virtio.bdf(), true).map_err(|e| e.name())?;
        virtio.add_status(virtio::STATUS_DRIVER_OK);
        Ok(Rig { virtio, queue: ManuallyDrop::new(queue), notify_off, bus_master_was_on })
    }

    /// 把 0 号描述符放回可用环并通知设备（不等待、不分配内存；中断上下文可调用）。
    /// Republish descriptor 0 and notify the device.
    pub(crate) fn kick(&mut self) -> Result<(), &'static str> {
        self.queue.submit(0).map_err(|e| e.name())?;
        self.virtio.notify(self.notify_off).map_err(|e| e.name())
    }

    /// 让设备消费一个请求并等它出现在已用环上；返回写入的字节数。
    fn fire(&mut self) -> Result<u32, &'static str> {
        self.kick()?;
        let mut len = None;
        let used = wait_ticks(|| {
            if let Some((_, l)) = self.queue.take_used() {
                len = Some(l);
            }
            len.is_some()
        });
        match (used, len) {
            (true, Some(l)) => Ok(l),
            _ => Err("设备没有消费缓冲区"),
        }
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        // 统一静默化路径：真实复位；复位超时就关总线主控并读回确认；读回不可信时隔离队列页而不是归还。
        // 设备在这里停下，随后字段按声明顺序取消映射。
        // SAFETY：队列只在本函数里取走一次，取走后本结构不再使用该字段。
        let queue = unsafe { ManuallyDrop::take(&mut self.queue) };
        let _ = virtio::quiesce(&self.virtio, queue, !self.bus_master_was_on);
    }
}

/// 有界等待条件成立：每个 tick 醒来检查一次（期间处理器交给用户线程），绝不无限等待。
fn wait_ticks(mut cond: impl FnMut() -> bool) -> bool {
    let start = sched::timer_ticks();
    loop {
        if cond() {
            return true;
        }
        if sched::timer_ticks().wrapping_sub(start) >= WAIT_TICKS || user_gone() {
            return cond();
        }
        sched::pause();
    }
}

/// 用户进程是否已经退出（退出后不再有人等待，驱动任务不必继续）。
fn user_gone() -> bool {
    let pid = USER_PID.load(Ordering::Relaxed);
    match kernel_core::objtable::ObjId::from_raw(pid) {
        Some(id) => !matches!(proc::state(id), Some(ProcState::Running)),
        None => true,
    }
}

fn target_bdf() -> Option<Bdf> {
    kernel_core::device::unpack_bdf(TARGET_BDF.load(Ordering::Relaxed))
}

/// 驱动失败时终止用户程序：它可能正停在等不到的等待上，终止后演练才能回收并报告失败。
fn abort_user() {
    if let Some(id) = kernel_core::objtable::ObjId::from_raw(USER_PID.load(Ordering::Relaxed)) {
        if proc::begin_exit(id, -2) {
            kprintln!("[JSR-IRQRING-FAIL] driver aborted the user program");
        }
    }
}

/// 每个在线处理器上的伪 MSI 计数快照。
fn spurious_snapshot() -> [u32; MAX_CPUS] {
    let mut s = [0u32; MAX_CPUS];
    for cpu in sched::online_cpus().iter() {
        s[cpu] = irq::msi_spurious(cpu);
    }
    s
}

/// 驱动任务：按用户程序建立的绑定逐轮产生中断，最后完成取消语义的那一步。
fn driver() {
    let mut rig = RIG.lock().0.take();
    if let (Some(r), Some(bdf)) = (rig.as_mut(), target_bdf()) {
        let rounds = ROUNDS.load(Ordering::Relaxed);
        let mut last_serial = Some(0u64);
        for round in 0..rounds {
            last_serial = last_serial.and_then(|s| drive_round(r, bdf, round, s));
        }
        let cancel = last_serial.map(|s| drive_cancel(r, bdf, s)).unwrap_or(false);
        CANCEL_OK.store(cancel, Ordering::Relaxed);
        if !cancel {
            abort_user();
        }
    } else {
        abort_user();
    }
    RIG.lock().0 = rig;
    DRIVER_DONE.store(true, Ordering::Release);
}

/// 一轮：等到一个新绑定上有未完成的等待 → 产生中断 → 核对送达。返回该绑定的序号；等不到绑定或没有送达返回 `None`。
fn drive_round(rig: &mut Rig, bdf: Bdf, round: u32, last_serial: u64) -> Option<u64> {
    let mut found = None;
    let bound = wait_ticks(|| {
        found = interrupt::bound_object(bdf, QUEUE_ENTRY)
            .and_then(|id| interrupt::view(id).map(|v| (id, v)))
            .filter(|(_, v)| v.waiting && v.serial > last_serial);
        found.is_some()
    });
    let Some((id, v)) = found.filter(|_| bound) else {
        check(false, "用户程序没有建立带等待的中断绑定");
        return None;
    };
    #[cfg(feature="evt2-verify")]
    let observer={
        use kernel_core::{object::{ObjectType,Rights},subscription::Policy};
        let pid=proc::create("evt2-irq-observer",SyscallSet::EMPTY).unwrap();
        let source=kobj::with(|t|interrupt::source_in(t,id)).unwrap();
        let cap=proc::grant(pid,source,ObjectType::EventSource,Rights::SUBSCRIBE).unwrap();
        let (sub,snapshot)=crate::subscription::subscribe(pid,cap,Policy::Count).unwrap();assert_eq!(snapshot.value,0);
        (pid,sub)
    };
    let before_count = irq::msi_count(v.cpu, v.vector);
    let before_dispatched = interrupt::dispatched();
    let before_deliveries = interrupt::deliveries();
    let before_spurious = spurious_snapshot();
    let start = sched::timer_ticks();
    let used = rig.fire();
    // 交付可能由用户线程的推进完成，随后用户立即关闭句柄：以全局交付计数核对，不依赖对象仍然存在
    let delivered = wait_ticks(|| {
        let _ = interrupt::view(id);
        interrupt::deliveries() != before_deliveries
    });
    let latency = sched::timer_ticks().wrapping_sub(start);
    // 再给一个 tick，确认没有第二次到达或第二次已用项
    sched::pause();
    let delivered = delivered && interrupt::deliveries() - before_deliveries == 1;
    let count_ok = irq::msi_count(v.cpu, v.vector).wrapping_sub(before_count) == 1;
    let dispatched_ok = interrupt::dispatched() - before_dispatched == 1;
    let spurious_ok = spurious_snapshot() == before_spurious;
    let used_ok = matches!(used, Ok(len) if len == BUFFER_BYTES as u32) && rig.queue.take_used().is_none();
    #[cfg(feature="evt2-verify")]
    {
        use kernel_core::subscription::{Delivery,Event};
        assert_eq!(crate::subscription::take(observer.0,observer.1).unwrap(),crate::subscription::Read::Data(Delivery::Event(Event {first:1,last:1,value:1})));
        assert!(proc::exit_idle(observer.0,0));assert!(proc::reap(observer.0).is_some());kobj::run_cleanup(usize::MAX);
        kprintln!("[JSR-EVT2-IRQ] cpu={} delivered=true delta=1 snapshot_total=0 resources_cleanup=true",v.cpu);
    }
    let ok = delivered && count_ok && dispatched_ok && spurious_ok && used_ok;
    check(used_ok, "已用环没有恰好推进 1 项（或写入字节数不对）");
    check(delivered, "中断没有成为一次完成");
    check(count_ok, "目标处理器的向量计数没有恰好加一");
    check(dispatched_ok, "中断对象的处理函数没有恰好分发一次");
    check(spurious_ok, "出现伪 MSI");
    kprintln!(
        "[JSR-IRQRING] round={} cpu={} delivered={} latency_ticks={} ok={}",
        round,
        v.cpu,
        if delivered { 1 } else { 0 },
        latency,
        ok
    );
    if ok {
        ROUNDS_OK.fetch_add(1, Ordering::Relaxed);
    }
    // 没有送达时用户仍停在等待上，不能进入下一轮
    delivered.then_some(v.serial)
}

/// 取消语义：用户取消等待后停在时间等待上；此时产生的中断必须记为待交付，供下一次等待立即取走。
fn drive_cancel(rig: &mut Rig, bdf: Bdf, last_serial: u64) -> bool {
    let mut found = None;
    let parked = wait_ticks(|| {
        found = interrupt::bound_object(bdf, QUEUE_ENTRY)
            .and_then(|id| interrupt::view(id).map(|v| (id, v)))
            .filter(|(_, v)| v.serial > last_serial && v.cancels >= 1 && !v.waiting)
            .filter(|(_, v)| v.last_ring.map(ring::running_time_waits).unwrap_or(0) >= 1);
        found.is_some()
    });
    let Some((id, v)) = found.filter(|_| parked) else {
        check(false, "用户程序没有在取消等待后停在时间等待上");
        return false;
    };
    let before_count = irq::msi_count(v.cpu, v.vector);
    let used = rig.fire();
    let arrived = wait_ticks(|| irq::msi_count(v.cpu, v.vector) != before_count);
    let retained = interrupt::view(id).map(|a| a.pending == 1 && !a.waiting && a.delivered == v.delivered).unwrap_or(false);
    let released = v.last_ring.map(ring::kernel_cancel_time_waits).unwrap_or(0) == 1;
    check(used.is_ok(), "取消演练：设备没有消费缓冲区");
    check(arrived, "取消演练：中断没有到达");
    check(retained, "取消演练：没有等待者时到达的中断没有记为待交付");
    check(released, "取消演练：无法放行用户的时间等待");
    used.is_ok() && arrived && retained && released
}

/// 运行演练并输出汇总。
/// Run the demo and emit the summary.
pub fn run() {
    let Some(device) = pci::table()
        .devices()
        .find(|d| d.header.vendor == virtio::VIRTIO_VENDOR && virtio::is_rng_device(d.header.device))
    else {
        kprintln!("[JSR-IRQRING] skipped reason=no_virtio_rng ok=true");
        return;
    };
    let bdf = device.bdf;
    let online = sched::online_cpus();
    let cpus = online.len();
    let rounds = if cpus == 1 { 2 } else { cpus as u32 };
    let mut mask = 0u64;
    for cpu in online.iter() {
        mask |= 1 << cpu;
    }

    let was_enabled = arch::irq_save_disable();
    arch::irq_enable();
    if let Err(e) = mmio::prepare_window() {
        check(false, e.name());
    }
    let frames_before = frame::free_frames();
    let (live_before, _, _) = kobj::stats();
    let vectors_before = interrupt::vectors_allocated();

    let mut exit_code = None;
    match Rig::new(device) {
        Ok(rig) => {
            RIG.lock().0 = Some(rig);
            TARGET_BDF.store(kernel_core::device::pack_bdf(bdf), Ordering::Relaxed);
            ROUNDS.store(rounds, Ordering::Relaxed);
            exit_code = run_user(mask, kernel_core::device::pack_bdf(bdf));
            // 设备在这里复位、队列页归还
            drop(RIG.lock().0.take());
        }
        Err(reason) => check(false, reason),
    }
    check(DRIVER_DONE.load(Ordering::Acquire), "驱动任务没有结束");

    let code = exit_code.unwrap_or(-1);
    let rejects_ok = if code >= 0 { (code as u32) & EXIT_REJECTS_OK } else { 0 };
    let rejects_total = if code >= 0 { ((code as u32) >> EXIT_REJECTS_TOTAL_SHIFT) & 0xFF } else { 0 };
    let user_rounds = if code >= 0 { ((code as u32) >> EXIT_ROUNDS_SHIFT) & 0xFF } else { 0 };
    let user_cancel = code >= 0 && code & EXIT_CANCEL_OK != 0;
    let close_ok = code >= 0 && code & EXIT_CLOSE_OK != 0;
    check(code >= 0 && code & EXIT_FAILED == 0, "用户程序报告断言失败");
    check(rejects_total >= 6 && rejects_ok == rejects_total, "拒绝路径未全部按预期被拒");
    check(user_rounds == rounds, "用户程序收到的完成轮数不对");
    check(close_ok, "关闭中断句柄没有以已关闭终态完成未完成的等待");
    let cancel_ok = user_cancel && CANCEL_OK.load(Ordering::Relaxed);
    check(cancel_ok, "取消后到达的中断没有交给下一次等待");
    let delivered = ROUNDS_OK.load(Ordering::Relaxed).min(user_rounds);

    kobj::run_cleanup(usize::MAX);
    let vectors_back = interrupt::vectors_allocated() == vectors_before;
    let msix = interrupt::msix_state(bdf, QUEUE_ENTRY);
    check(vectors_back, "向量没有全部归还");
    check(msix.map(|(n, enabled, masked)| n == 0 && !enabled && masked).unwrap_or(false), "表项未屏蔽或功能 MSI-X 未关闭");
    let (live_after, pending_after, _) = kobj::stats();
    check(live_after == live_before && pending_after == 0, "对象数 / 清理队列未回到基线（有残留句柄）");
    let frames_back = frame::free_frames() == frames_before;
    check(frames_back, "页帧没有回到演练前的基线");
    arch::irq_restore(was_enabled);

    kprintln!(
        "[JSR-IRQRING] summary cpus={} rounds={} delivered={}/{} rejects={}/{} cancel={} close_cancels_wait={} vectors_back={} frames_back={} failed={}",
        cpus,
        rounds,
        delivered,
        rounds,
        rejects_ok,
        rejects_total,
        if cancel_ok { "ok" } else { "failed" },
        if close_ok { "ok" } else { "failed" },
        vectors_back,
        frames_back,
        failed()
    );
}

/// 装载并运行用户程序与驱动任务，回收进程；返回用户程序的退出码。
fn run_user(cpu_mask: u64, bdf: u32) -> Option<i64> {
    let allowed = SyscallSet::of(&[
        abi::SYSTEM_CONSOLE_WRITE,
        abi::SYSTEM_DEVICE_OPEN,
        abi::SYSTEM_DEVICE_INTERRUPT_CREATE,
        abi::SYSTEM_DEVICE_INTERRUPT_WAIT,
        abi::SYSTEM_ASYNC_RING_CREATE,
        abi::SYSTEM_ASYNC_RING_ENTER,
        abi::SYSTEM_ASYNC_CANCEL,
        abi::SYSTEM_TIME_WAIT,
        abi::SYSTEM_HANDLE_RESTRICT,
        abi::SYSTEM_HANDLE_CLOSE,
        abi::SYSTEM_TASK_EXIT,
    ]);
    let base = arch::USER_WINDOW.0;
    let pid = proc::create("irqprobe", allowed).ok()?;
    let fail = |stage: &str| {
        kprintln!("[JSR-IRQRING-FAIL] stage={}", stage);
        FAILED.fetch_add(1, Ordering::Relaxed);
        proc::exit_idle(pid, -1);
        proc::reap(pid);
        kobj::run_cleanup(usize::MAX);
        None
    };
    let Ok(entry) = proc::load_elf(pid, USER_IRQPROBE) else { return fail("load") };
    if proc::map_new(pid, base + STACK_OFF - FRAME_SIZE, MapFlags::USER | MapFlags::WRITE).is_err() {
        return fail("stack");
    }
    USER_PID.store(pid.raw(), Ordering::Relaxed);
    if proc::spawn_thread(pid, "irqprobe", entry, base + STACK_OFF, cpu_mask, bdf as u64).is_err() {
        return fail("thread");
    }
    if sched::spawn(TaskId(DRIVER_TASK), "irqring-driver", driver).is_err() {
        // 没有驱动任务时用户程序会等不到中断：直接终止它，以便回收并报告失败
        check(false, "无法创建驱动任务");
        abort_user();
        DRIVER_DONE.store(true, Ordering::Release);
    }
    sched::run();
    let code = match proc::state(pid) {
        Some(ProcState::Exited { code }) => Some(code),
        _ => None,
    };
    proc::reap(pid);
    kobj::run_cleanup(usize::MAX);
    code
}
