//! DRV-1C 演练：设备内核对象与 `system.device.list` / `open` / `get`。
//! DRV-1C demo: the Device kernel object and the device system calls.
//!
//! # 做什么
//! * 装载并运行用户态 `user-devprobe`（角色 0）：列举设备、按类别 / 厂商过滤、打开 virtio-net、读取完整描述，
//!   并验证非法 BDF、无权限、已关闭句柄、权限越级复制、缓冲区不足等拒绝路径。启动时没有挂 virtio-net 则
//!   只记录跳过（设备由启动方加挂并核对）。
//! * 再以角色 1 运行同一程序，但**不授予**任何设备系统调用：所有设备调用必须在分发层被拒。
//! * 主体结束后核对对象数、清理队列与空闲页帧回到演练前的基线——设备句柄关闭只销毁设备对象，
//!   启动期设备表项常驻，不因句柄关闭而消失。
//!
//! 用户程序的每个断言在串口输出 `[JSR-DEV] …` 行，并以退出码 0/1 给出总判定；本文件只负责调度、
//! 回收与基线核对，不重复用户态已经做过的断言。

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::frame::FRAME_SIZE;
use kernel_core::paging::MapFlags;

use crate::mm::frame;
use crate::proc::{self, ProcState};
use crate::syscall::{table as abi, SyscallSet};
use crate::{arch, kobj, kprintln, sched};

/// 用户栈顶部在私有窗口内的偏移（与其它 ELF 演练一致）。
const STACK_OFF: u64 = 0xC0_0000;

/// virtio 设备的 PCI 厂商号。
const VIRTIO_VENDOR: u16 = 0x1AF4;
/// PCI 网络控制器类别。
const NET_CLASS: u8 = 0x02;

/// 内嵌的用户程序 `user-devprobe`（由 `kernel/build.rs` 在 x86_64 上构建）。
static USER_DEVPROBE: &[u8] = include_bytes!(env!("JSR_USER_DEVPROBE"));

static CHECKS: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);

fn check(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-DRV1C-FAIL] {}", what);
    }
}

/// 断言失败次数。
/// Number of failed assertions.
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

/// 运行一次用户态演练并回收进程；返回 (退出码正确, 回收是否完成)。
fn run_role(name: &'static str, role: u64, allowed: SyscallSet) -> bool {
    let base = arch::USER_WINDOW.0;
    let Ok(pid) = proc::create(name, allowed) else {
        kprintln!("[JSR-DRV1C] error role={} stage=create", role);
        return false;
    };
    let entry = match proc::load_elf(pid, USER_DEVPROBE) {
        Ok(entry) => entry,
        Err(e) => {
            kprintln!("[JSR-DRV1C] error role={} stage=load reason={}", role, e.name());
            proc::exit_idle(pid, -1);
            proc::reap(pid);
            kobj::run_cleanup(usize::MAX);
            return false;
        }
    };
    if proc::map_new(pid, base + STACK_OFF - FRAME_SIZE, MapFlags::USER | MapFlags::WRITE).is_err() {
        kprintln!("[JSR-DRV1C] error role={} stage=stack", role);
        proc::exit_idle(pid, -1);
        proc::reap(pid);
        kobj::run_cleanup(usize::MAX);
        return false;
    }
    if proc::spawn_thread(pid, name, entry, base + STACK_OFF, role, 0).is_err() {
        kprintln!("[JSR-DRV1C] error role={} stage=thread", role);
        proc::exit_idle(pid, -1);
        proc::reap(pid);
        kobj::run_cleanup(usize::MAX);
        return false;
    }
    sched::run();
    let state = proc::state(pid);
    let mut ok = state == Some(ProcState::Exited { code: 0 });
    kprintln!("[JSR-DRV1C] case=role{} exit={:?} ok={}", role, state, ok);
    // DRV-1D：角色 2 故意留一个打开的设备句柄退出；进程退出流程必须同时撤销它的 BAR 映射。
    if role == 2 {
        let maps = proc::device_map_count(pid).unwrap_or(usize::MAX);
        let revoked = maps == 0;
        kprintln!("[JSR-DRV1D] case=exit_revoke maps={} ok={}", maps, revoked);
        ok &= revoked;
    }
    proc::reap(pid);
    kobj::run_cleanup(usize::MAX);
    ok
}

fn driver_host_calls() -> SyscallSet {
    SyscallSet::of(&[
        abi::SYSTEM_CONSOLE_WRITE,
        abi::SYSTEM_DEVICE_LIST,
        abi::SYSTEM_DEVICE_OPEN,
        abi::SYSTEM_DEVICE_GET,
        abi::SYSTEM_DEVICE_CAPABILITY_LIST,
        abi::SYSTEM_DEVICE_MAP,
        abi::SYSTEM_DEVICE_INTERRUPT_CREATE,
        abi::SYSTEM_DEVICE_INTERRUPT_WAIT,
        abi::SYSTEM_MEMORY_OBJECT_CREATE,
        abi::SYSTEM_MEMORY_OBJECT_MAP,
        abi::SYSTEM_MEMORY_OBJECT_UNMAP,
        abi::SYSTEM_MEMORY_DMA_MAP,
        abi::SYSTEM_TIME_WAIT,
        abi::SYSTEM_ASYNC_RING_CREATE,
        abi::SYSTEM_ASYNC_RING_ENTER,
        abi::SYSTEM_HANDLE_CLOSE,
        abi::SYSTEM_TASK_EXIT,
    ])
}

#[cfg(feature = "iommu-dma-verify")]
fn driver_queue_calls() -> SyscallSet {
    let ids = [
        abi::SYSTEM_CONSOLE_WRITE,
        abi::SYSTEM_DEVICE_LIST,
        abi::SYSTEM_DEVICE_OPEN,
        abi::SYSTEM_DEVICE_GET,
        abi::SYSTEM_DEVICE_CAPABILITY_LIST,
        abi::SYSTEM_DEVICE_MAP,
        abi::SYSTEM_DEVICE_VIRTIO_SUBMIT,
        abi::SYSTEM_DEVICE_INTERRUPT_CREATE,
        abi::SYSTEM_DEVICE_INTERRUPT_WAIT,
        abi::SYSTEM_MEMORY_OBJECT_CREATE,
        abi::SYSTEM_MEMORY_OBJECT_MAP,
        abi::SYSTEM_MEMORY_OBJECT_UNMAP,
        abi::SYSTEM_MEMORY_DMA_MAP,
        abi::SYSTEM_TIME_WAIT,
        abi::SYSTEM_ASYNC_RING_CREATE,
        abi::SYSTEM_ASYNC_RING_ENTER,
        abi::SYSTEM_HANDLE_CLOSE,
        abi::SYSTEM_TASK_EXIT,
    ];
    SyscallSet::try_of(&ids).unwrap_or(SyscallSet::EMPTY)
}

fn has_virtio_rng() -> bool {
    crate::pci::table().devices().any(|device| {
        device.header.vendor == VIRTIO_VENDOR
            && crate::virtio::is_rng_device(device.header.device)
    })
}

/// Run only the DC-1 capability-composition role.
///
/// Returns `None` when the required virtio-rng device is absent.
pub(crate) fn run_driver_host() -> Option<bool> {
    if !has_virtio_rng() {
        kprintln!("[JSR-DC1] case=role6 skipped=true reason=no-virtio-rng");
        return None;
    }
    let before = crate::baseline::baseline();
    let ok = run_role("driver-host", 6, driver_host_calls());
    let after = crate::baseline::baseline();
    kprintln!(
        "[JSR-DC1] cleanup resources={} ok={}",
        after == before,
        after == before && ok
    );
    Some(ok && after == before)
}

/// Run the real user-space split-virtqueue role under the VT-d acceptance.
///
/// 在 VT-d 验收下运行真实用户态 split virtqueue；
/// 未发现 virtio-rng 或资源未回基线均失败关闭。
#[cfg(all(feature = "iommu-dma-verify", target_arch = "x86_64"))]
pub(crate) fn run_driver_queue() -> bool {
    if !has_virtio_rng() {
        check(false, "iommu queue work requires virtio-rng");
        return false;
    }
    // The kernel virtio notify transport uses the process-wide MMIO window.
    // Initialize its page-table cache before taking the before/after baseline so
    // a one-time static reservation is not misreported as a per-operation leak.
    // 内核 virtio 通知传输使用进程级 MMIO 窗口；先初始化其页表缓存，避免把
    // 一次性静态预留误报为每次操作泄漏。
    if crate::mmio::prepare_window().is_err() {
        check(false, "kernel MMIO window initialization failed");
        return false;
    }
    let before = crate::baseline::baseline();
    let ok = run_role("driver-queue", 7, driver_queue_calls());
    let after = crate::baseline::baseline();
    kprintln!(
        "[JSR-DC1-BASELINE] before={:?} after={:?}",
        before,
        after
    );
    check(after == before, "driver queue resources did not return to baseline");
    let ok = ok && after == before;
    if !ok {
        check(false, "user-space virtqueue work failed");
    }
    ok
}

/// 运行 DRV-1C 演练并输出汇总（`failed` 进入内核的失败计数）。
/// Runs the DRV-1C demo and emits the summary.
pub fn run() {
    let free_before = frame::free_frames();
    let (live_before, pending_before, _) = kobj::stats();

    // 角色 0：设备调用全部授予。
    let granted = SyscallSet::of(&[
        abi::SYSTEM_CONSOLE_WRITE,
        abi::SYSTEM_DEVICE_LIST,
        abi::SYSTEM_DEVICE_OPEN,
        abi::SYSTEM_DEVICE_GET,
        abi::SYSTEM_HANDLE_DUPLICATE,
        abi::SYSTEM_HANDLE_CLOSE,
        abi::SYSTEM_TASK_EXIT,
    ]);
    // 角色 0 需要一块 virtio-net 作为打开对象；没有挂这类设备的普通启动只记录跳过，
    // 设备是否齐全由启动方（验收脚本加挂的设备与其检查项）核对，不让普通启动因此判失败。
    let has_net = crate::pci::table()
        .devices()
        .any(|device| device.header.vendor == VIRTIO_VENDOR && device.header.class == NET_CLASS);
    if has_net {
        check(run_role("device-probe", 0, granted), "设备演练（角色 0）未以退出码 0 结束");
    } else {
        kprintln!("[JSR-DRV1C] case=role0 skipped=true reason=no-virtio-net");
    }

    // 角色 1：不授予任何设备系统调用，设备调用必须被分发层拒绝。
    let denied = SyscallSet::of(&[abi::SYSTEM_CONSOLE_WRITE, abi::SYSTEM_TASK_EXIT]);
    check(run_role("device-nocap", 1, denied), "无设备访问能力的拒绝演练（角色 1）未以退出码 0 结束");

    // 角色 2（DRV-1D）：授予设备列举 / 打开 / 读取 / 能力列举 / 映射与关闭。
    if has_net {
        let mapping = SyscallSet::of(&[
            abi::SYSTEM_CONSOLE_WRITE,
            abi::SYSTEM_DEVICE_LIST,
            abi::SYSTEM_DEVICE_OPEN,
            abi::SYSTEM_DEVICE_GET,
            abi::SYSTEM_DEVICE_CAPABILITY_LIST,
            abi::SYSTEM_DEVICE_MAP,
            abi::SYSTEM_HANDLE_CLOSE,
            abi::SYSTEM_TASK_EXIT,
        ]);
        check(run_role("device-map", 2, mapping), "设备 BAR 映射演练（角色 2）未以退出码 0 结束");
    } else {
        kprintln!("[JSR-DRV1D] case=role2 skipped=true reason=no-virtio-net");
    }

    // 角色 3（DRV-1D）：设备读取可用，但没有 `system.device.map`；映射必须在分发层被拒。
    let no_map = SyscallSet::of(&[
        abi::SYSTEM_CONSOLE_WRITE,
        abi::SYSTEM_DEVICE_LIST,
        abi::SYSTEM_DEVICE_OPEN,
        abi::SYSTEM_DEVICE_GET,
        abi::SYSTEM_TASK_EXIT,
    ]);
    check(run_role("device-nomap", 3, no_map), "无映射能力的拒绝演练（角色 3）未以退出码 0 结束");

    // DC-1 capability-composition slice: one user process combines Device,
    // MMIO, Memory/DMA, IRQ and Ring. Actual virtqueue DMA remains blocked on
    // translating user-visible IOVA through an admitted IOMMU backend.
    if has_virtio_rng() {
        let driver_host = driver_host_calls();
        check(
            run_role("driver-host", 6, driver_host),
            "DC-1 用户态 Driver Host 能力组合未以退出码 0 结束",
        );
    } else {
        kprintln!("[JSR-DC1] case=role6 skipped=true reason=no-virtio-rng");
    }

    kobj::run_cleanup(usize::MAX);
    let (live_after, pending_after, _) = kobj::stats();
    let free_after = frame::free_frames();
    check(
        live_after == live_before && pending_after == 0,
        "设备演练后对象数 / 清理队列未回到基线",
    );
    check(free_after == free_before, "设备演练后空闲页帧未回到基线");

    kprintln!(
        "[JSR-DRV1C] summary objects={}/{} pending={}->{} frames={}/{} checks={} failed={}",
        live_after,
        live_before,
        pending_before,
        pending_after,
        free_after,
        free_before,
        CHECKS.load(Ordering::Relaxed),
        failed()
    );
}
