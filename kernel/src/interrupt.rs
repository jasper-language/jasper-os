//! 设备中断对象（`system.device.interrupt.*`）：把一个 MSI-X 表项绑定到某个处理器的向量，
//! 到达经异步环成为用户态的一条完成记录。
//! Device-interrupt objects: bind one MSI-X entry to a processor vector and surface arrivals as ring completions.
//!
//! # 职责
//! * `system.device.interrupt.create(device, entry, cpu)`：经带 `CONTROL` 的设备句柄，从该处理器的向量池分配向量、
//!   登记分发处理函数、编程并解除屏蔽表项、打开功能的 MSI-X，返回带 `WAIT | CONTROL` 的中断句柄。
//!   任一检查失败都在改动硬件之前返回结构化错误；编程失败则逐步回滚，不留向量、表项或句柄。
//! * `system.device.interrupt.wait` 只能经 Ring 提交（同步系统调用直接拒绝）：交付规则由
//!   [`kernel_core::interrupt::InterruptLine`] 决定，Ring 只负责提交 / 取消 / 完成的状态机。
//! * 关闭中断句柄（含进程退出时回收句柄表）：屏蔽表项、解除分发登记、归还向量、以「已关闭」终态完成未完成的等待；
//!   同一功能的全部表项都解绑后关闭该功能的 MSI-X。
//!
//! # 到达如何变成完成
//! 中断处理函数只计数（分发器按 `[处理器][向量]` 计到达次数，处理函数另记一次分发），不取锁、不分配内存。
//! 到达在下一个推进点并入中断对象：等待者所在的 Ring 每次推进（`enter` 的等待循环每个 tick 醒来一次）、
//! 提交新的等待、或任何人查询该对象时，读取到达计数的增量交给状态机；有等待者就完成它。
//!
//! # 边界
//! * 只管理 MSI-X；不做中断预算、风暴抑制或负载均衡改向，不涉及用户态 DMA。
//! * 不含任何指令集专有值：向量范围与消息组合来自 [`crate::arch`]，表项读写经 [`crate::msix`]。
//! * 功能的 MSI-X 表映射在首次绑定时建立并常驻（映射槽位不回收，常驻避免反复占用窗口）；
//!   最后一个表项解绑时只清除功能使能。
//!
//! # 锁
//! 绑定登记表一把锁（级别在对象表之后）：绑定与关闭都在对象表锁内取它；分发处理函数不取任何锁。

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use kernel_core::interrupt::{InterruptLine, Submitted, WaitError};
use kernel_core::msi::{MsiError, Vector, VectorPool};
use kernel_core::object::{HandleId, ObjectType, Rights};
use kernel_core::objtable::ObjId;
use kernel_core::pci::{self as core_pci, Bdf};
use spin::Once;

use crate::kobj::{self, KObject, Table};
use crate::msix::{MsixDevice, MsixError};
use crate::proc::{self, ProcError};
use crate::sync::IrqSpinLock;
use crate::syscall::err;
use crate::syscall::table::*;
use crate::{arch, irq, kprintln, sched};

/// 中断句柄的权限：经 Ring 等待（WAIT）、控制绑定（CONTROL）。可经 restrict 降权，不可复制或传递。
/// Rights of an interrupt handle.
pub const INTERRUPT_RIGHTS: Rights = Rights::WAIT.union(Rights::CONTROL);

/// 等待者令牌：（Ring 对象，请求 ID）。
/// Waiter token: (ring object, request id).
pub type Waiter = (ObjId, u64);

/// 中断内核对象。
/// The interrupt kernel object.
pub struct InterruptObj {
    bdf: Bdf,
    entry: u16,
    cpu: usize,
    vector: u8,
    /// 已并入状态机的分发器到达计数（读数与它的差就是新到达）。
    seen: u32,
    /// 全局递增的绑定序号（区分同一表项的先后两次绑定）。
    serial: u64,
    line: InterruptLine<Waiter>,
    /// 被取消的等待次数（诊断用）。
    cancels: u32,
    /// 最近一次登记等待的 Ring（诊断用）。
    last_ring: Option<ObjId>,
}

/// 中断对象的可观测状态（演练与诊断用）。
/// Observable state of an interrupt object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterruptView {
    /// 绑定序号。
    pub serial: u64,
    /// 目标处理器。
    pub cpu: usize,
    /// 目标向量。
    pub vector: u8,
    /// 是否有未完成的等待。
    pub waiting: bool,
    /// 已到达未交付的次数。
    pub pending: u32,
    /// 已完成的等待次数。
    pub delivered: u64,
    /// 被取消的等待次数。
    pub cancels: u32,
    /// 最近一次登记等待的 Ring。
    pub last_ring: Option<ObjId>,
}

/// 一个表项的绑定登记。
struct Bound {
    entry: u16,
    cpu: usize,
    vector: u8,
    /// 绑定成功后对应的中断对象（建立句柄之前为 `None`）。
    obj: Option<ObjId>,
}

/// 一个 PCI 功能的 MSI-X 状态：常驻的表映射与当前已绑定的表项。
struct DeviceIrq {
    bdf: Bdf,
    msix: MsixDevice,
    bound: Vec<Bound>,
}

/// 绑定登记表。
static DEVICES: IrqSpinLock<Vec<DeviceIrq>> = IrqSpinLock::ranked(crate::lockorder::DEVICE_IRQ, Vec::new());
/// 中断对象共用的每核向量池（首次绑定时按当时的在线处理器建立）。
static POOL: Once<Option<VectorPool>> = Once::new();
/// 分发到中断对象处理函数的次数。
static DISPATCHED: AtomicU64 = AtomicU64::new(0);
/// 以到达完成的等待总数（到达时交付与提交时立即交付都算）。
static DELIVERIES: AtomicU64 = AtomicU64::new(0);
/// 下一个绑定序号。
static SERIAL: AtomicU64 = AtomicU64::new(1);

fn pool() -> Option<&'static VectorPool> {
    POOL.call_once(|| {
        let range = arch::msi_vector_range()?;
        VectorPool::new(range.first, range.count, sched::online_cpus()).ok()
    })
    .as_ref()
}

/// 分发处理函数（中断上下文）：只计数；到达次数本身由分发器按处理器与向量记录。
fn on_arrival() {
    DISPATCHED.fetch_add(1, Ordering::Relaxed);
}

/// 分发到中断对象的到达总数。
/// Total arrivals dispatched to interrupt objects.
pub fn dispatched() -> u64 {
    DISPATCHED.load(Ordering::Relaxed)
}

/// 以到达完成的等待总数（中断对象关闭后仍可核对）。
/// Total waits completed by arrivals, observable after the object is closed.
pub fn deliveries() -> u64 {
    DELIVERIES.load(Ordering::Relaxed)
}

fn perr(e: ProcError) -> i64 {
    crate::syscall::proc_err(e)
}

fn msix_err(e: MsixError) -> i64 {
    err(match e {
        MsixError::EntryOutOfRange => SYSTEM_DEVICE_ERROR_ENTRY_OUT_OF_RANGE,
        MsixError::CpuOffline => SYSTEM_DEVICE_ERROR_CPU_OFFLINE,
        MsixError::NoCapability => SYSTEM_DEVICE_ERROR_NO_MSIX,
        _ => SYSTEM_ERROR_UNSUPPORTED,
    })
}

fn wait_err(e: WaitError) -> i64 {
    err(match e {
        WaitError::Busy => SYSTEM_DEVICE_ERROR_INTERRUPT_BUSY,
        WaitError::Closed => SYSTEM_DEVICE_ERROR_INTERRUPT_CLOSED,
    })
}

fn obj_mut(t: &mut Table, id: ObjId) -> Option<&mut InterruptObj> {
    match t.get_mut(id) {
        Ok(KObject::Interrupt(o)) => Some(o),
        _ => None,
    }
}

// ———————————————————————— 绑定 ————————————————————————

/// `system.device.interrupt.create(device, entry, cpu)`：返回中断句柄。
/// Binds one MSI-X entry of the device behind `device` to `cpu`.
pub fn sys_bind(device: u64, entry: u64, cpu: u64) -> i64 {
    let Some(pid) = proc::current_process() else {
        return err(SYSTEM_ERROR_RIGHTS_DENIED);
    };
    match bind_for(pid, crate::syscall::handle_arg(device), entry, cpu) {
        Ok(h) => h.raw() as i64,
        Err(e) => e,
    }
}

/// 以进程 `pid` 的身份绑定。全有或全无：失败时不占向量、不改表项、不建句柄。
///
/// 检查顺序：设备句柄（类型、`CONTROL`）→ 设备有 MSI-X → 表项在表内 → 处理器在线 → 表项未绑定 → 向量可分配。
/// Binds on behalf of `pid`; all-or-nothing.
pub fn bind_for(pid: ObjId, device: HandleId, entry: u64, cpu: u64) -> Result<HandleId, i64> {
    kobj::with(|t| {
        let dev = proc::resolve_in(t, pid, device, ObjectType::Device, Rights::CONTROL).map_err(perr)?;
        let bdf = match t.get(dev) {
            Ok(KObject::Device(d)) => d.bdf,
            _ => return Err(err(SYSTEM_HANDLE_ERROR_INVALID)),
        };
        let pci_dev = crate::pci::table().find(bdf).ok_or(err(SYSTEM_DEVICE_ERROR_NOT_FOUND))?;
        let capability = pci_dev.msix.ok_or(err(SYSTEM_DEVICE_ERROR_NO_MSIX))?;
        let entry = u16::try_from(entry)
            .ok()
            .filter(|e| *e < capability.table().table_size())
            .ok_or(err(SYSTEM_DEVICE_ERROR_ENTRY_OUT_OF_RANGE))?;
        let cpu = usize::try_from(cpu)
            .ok()
            .filter(|c| sched::online_cpus().contains(*c))
            .ok_or(err(SYSTEM_DEVICE_ERROR_CPU_OFFLINE))?;
        let pool = pool().ok_or(err(SYSTEM_ERROR_UNSUPPORTED))?;

        let (vector, seen) = {
            let mut devices = DEVICES.lock();
            if devices.iter().any(|d| d.bdf == bdf && d.bound.iter().any(|b| b.entry == entry)) {
                return Err(err(SYSTEM_DEVICE_ERROR_ALREADY_BOUND));
            }
            let index = match devices.iter().position(|d| d.bdf == bdf) {
                Some(i) => i,
                None => {
                    let msix = MsixDevice::new(pci_dev).map_err(msix_err)?;
                    devices.push(DeviceIrq { bdf, msix, bound: Vec::new() });
                    devices.len() - 1
                }
            };
            let vector = pool.alloc(cpu).map_err(|e| {
                err(match e {
                    MsiError::Exhausted => SYSTEM_DEVICE_ERROR_INTERRUPT_SLOTS_EXHAUSTED,
                    _ => SYSTEM_DEVICE_ERROR_CPU_OFFLINE,
                })
            })?;
            let v = vector.get();
            if irq::msi_bind(cpu, v, Some(on_arrival)).is_err() {
                let _ = pool.free(cpu, vector);
                return Err(err(SYSTEM_ERROR_UNSUPPORTED));
            }
            let seen = irq::msi_count(cpu, v);
            let d = &mut devices[index];
            let programmed = d.msix.program(entry, cpu, v, true).and_then(|_| d.msix.enable());
            if let Err(e) = programmed {
                let _ = d.msix.mask(entry);
                if d.bound.is_empty() {
                    let _ = d.msix.disable();
                }
                let _ = irq::msi_bind(cpu, v, None);
                let _ = pool.free(cpu, vector);
                return Err(msix_err(e));
            }
            d.bound.push(Bound { entry, cpu, vector: v, obj: None });
            (v, seen)
        };

        let serial = SERIAL.fetch_add(1, Ordering::Relaxed);
        let obj = InterruptObj {
            bdf,
            entry,
            cpu,
            vector,
            seen,
            serial,
            line: InterruptLine::new(),
            cancels: 0,
            last_ring: None,
        };
        match proc::grant_new_in(t, pid, KObject::Interrupt(Box::new(obj)), ObjectType::Interrupt, INTERRUPT_RIGHTS) {
            Ok((h, id)) => {
                let mut devices = DEVICES.lock();
                if let Some(b) = devices
                    .iter_mut()
                    .find(|d| d.bdf == bdf)
                    .and_then(|d| d.bound.iter_mut().find(|b| b.entry == entry))
                {
                    b.obj = Some(id);
                }
                drop(devices);
                kprintln!(
                    "[JSR-IRQOBJ] event=bind bdf=0x{:06x} entry={} cpu={} vector={} serial={}",
                    kernel_core::device::pack_bdf(bdf),
                    entry,
                    cpu,
                    vector,
                    serial
                );
                Ok(h)
            }
            Err(e) => {
                // 句柄没能放进句柄表：若对象曾建立，它的关闭动作已经解绑；否则在这里解绑（幂等）。
                unbind_hw(bdf, entry);
                Err(perr(e))
            }
        }
    })
}

/// 解除 `(bdf, entry)` 的绑定（幂等；未绑定时什么也不做）：屏蔽表项 → 解除分发登记 → 归还向量；
/// 该功能的最后一个表项解绑时关闭功能的 MSI-X。返回是否确实解绑。
fn unbind_hw(bdf: Bdf, entry: u16) -> bool {
    let mut devices = DEVICES.lock();
    let Some(d) = devices.iter_mut().find(|d| d.bdf == bdf) else { return false };
    let Some(i) = d.bound.iter().position(|b| b.entry == entry) else { return false };
    let b = d.bound.swap_remove(i);
    let _ = d.msix.mask(entry);
    if d.bound.is_empty() {
        let _ = d.msix.disable();
    }
    let _ = irq::msi_bind(b.cpu, b.vector, None);
    if let Some(pool) = pool() {
        let _ = pool.free(b.cpu, Vector::new(b.vector));
    }
    true
}

// ———————————————————————— 到达与等待 ————————————————————————

/// 把中断对象 `id` 的新到达并入状态机（锁内）；有等待者就以交付次数完成它并推进其 Ring。
///
/// 分发器计数小于已记读数只可能是计数被清零：此时把当前读数整体视为新到达。
/// Folds new arrivals of `id` into its state machine, completing the parked waiter if any.
pub(crate) fn sync_in(t: &mut Table, id: ObjId) {
    let Some(o) = obj_mut(t, id) else { return };
    if o.line.is_closed() {
        return;
    }
    let now = irq::msi_count(o.cpu, o.vector);
    let delta = if now >= o.seen { now - o.seen } else { now };
    o.seen = now;
    if let Some(((ring, req), n)) = o.line.arrive(delta) {
        DELIVERIES.fetch_add(1, Ordering::Relaxed);
        crate::ring::complete_waiter_in(t, ring, req, n as i64);
    }
}

/// 为一条 `interrupt.wait` 提交解析中断句柄（须带 `WAIT`）并取得对象的一个内部引用（锁内）。
/// Resolves the interrupt handle of a wait submission and takes an internal reference.
pub(crate) fn prepare_wait_in(t: &mut Table, pid: ObjId, h: HandleId) -> Result<ObjId, i64> {
    let id = proc::resolve_in(t, pid, h, ObjectType::Interrupt, Rights::WAIT).map_err(perr)?;
    t.acquire_internal(id).map_err(|_| err(SYSTEM_HANDLE_ERROR_INVALID))?;
    Ok(id)
}

/// 提交前的预检（锁内，不改变等待状态）：先并入已到达的中断，再检查是否忙 / 已关闭。
/// Pre-submission check: busy or closed lines refuse the wait.
pub(crate) fn check_wait_in(t: &mut Table, id: ObjId) -> Result<(), i64> {
    sync_in(t, id);
    let o = obj_mut(t, id).ok_or(err(SYSTEM_DEVICE_ERROR_INTERRUPT_CLOSED))?;
    o.line.can_wait().map_err(wait_err)
}

/// 登记等待（锁内，已通过 [`check_wait_in`]）：已有到达 ⇒ 返回交付次数（立即完成）；否则登记并返回 `None`。
/// Parks `waiter`, or returns the pending count when arrivals are already there.
pub(crate) fn submit_wait_in(t: &mut Table, id: ObjId, waiter: Waiter) -> Result<Option<i64>, i64> {
    let o = obj_mut(t, id).ok_or(err(SYSTEM_DEVICE_ERROR_INTERRUPT_CLOSED))?;
    o.last_ring = Some(waiter.0);
    match o.line.submit_wait(waiter).map_err(wait_err)? {
        Submitted::Ready(n) => {
            DELIVERIES.fetch_add(1, Ordering::Relaxed);
            Ok(Some(n as i64))
        }
        Submitted::Parked => Ok(None),
    }
}

/// 撤销等待登记（锁内；请求被取消或已结束时由 Ring 调用）。已到达的次数保留到下一次等待。
/// Withdraws the waiter; pending arrivals stay for the next wait.
pub(crate) fn cancel_wait_in(t: &mut Table, id: ObjId, waiter: Waiter) {
    if let Some(o) = obj_mut(t, id) {
        if o.line.cancel(waiter) {
            o.cancels = o.cancels.saturating_add(1);
        }
    }
}

// ———————————————————————— 关闭 ————————————————————————

/// closing 动作（外部所有权归零时由对象表调用）：关闭状态机、解绑硬件、以「已关闭」终态完成未完成的等待。
/// Closing action: close the line, unbind the hardware and complete any outstanding wait as closed.
pub fn close_in(t: &mut Table, id: ObjId) {
    let Some(o) = obj_mut(t, id) else { return };
    let waiter = o.line.close();
    let (bdf, entry, serial) = (o.bdf, o.entry, o.serial);
    let unbound = unbind_hw(bdf, entry);
    if let Some((ring, req)) = waiter {
        crate::ring::complete_waiter_in(t, ring, req, err(SYSTEM_DEVICE_ERROR_INTERRUPT_CLOSED));
    }
    kprintln!(
        "[JSR-IRQOBJ] event=close bdf=0x{:06x} entry={} serial={} unbound={} cancelled_wait={}",
        kernel_core::device::pack_bdf(bdf),
        entry,
        serial,
        unbound,
        waiter.is_some()
    );
}

// ———————————————————————— 诊断 ————————————————————————

/// `(bdf, entry)` 当前绑定的中断对象（句柄已建立的才算）。
/// The interrupt object currently bound to `(bdf, entry)`.
pub fn bound_object(bdf: Bdf, entry: u16) -> Option<ObjId> {
    let devices = DEVICES.lock();
    devices.iter().find(|d| d.bdf == bdf)?.bound.iter().find(|b| b.entry == entry)?.obj
}

/// 中断对象的可观测状态（先并入已到达的中断；对象已不存在返回 `None`）。
/// Observable state of `id`, after folding in new arrivals.
pub fn view(id: ObjId) -> Option<InterruptView> {
    kobj::with(|t| {
        sync_in(t, id);
        let o = obj_mut(t, id)?;
        Some(InterruptView {
            serial: o.serial,
            cpu: o.cpu,
            vector: o.vector,
            waiting: o.line.waiter().is_some(),
            pending: o.line.pending(),
            delivered: o.line.delivered(),
            cancels: o.cancels,
            last_ring: o.last_ring,
        })
    })
}

/// 中断对象占用的向量总数（全部在线处理器之和）。
/// Vectors currently held by interrupt objects across all processors.
pub fn vectors_allocated() -> usize {
    match pool() {
        Some(p) => sched::online_cpus().iter().map(|c| p.allocated(c)).sum(),
        None => 0,
    }
}

/// 功能 `bdf` 的 MSI-X 状态：（已绑定表项数，功能使能位，表项 `entry` 是否屏蔽）；从未绑定过返回 `None`。
/// MSI-X state of `bdf`: bound entries, global enable, and whether `entry` is masked.
pub fn msix_state(bdf: Bdf, entry: u16) -> Option<(usize, bool, bool)> {
    let devices = DEVICES.lock();
    let d = devices.iter().find(|d| d.bdf == bdf)?;
    let enabled = d.msix.control().map(core_pci::msix_control_enabled).ok()?;
    let masked = d.msix.entry(entry).map(|e| e.masked()).ok()?;
    Some((d.bound.len(), enabled, masked))
}
