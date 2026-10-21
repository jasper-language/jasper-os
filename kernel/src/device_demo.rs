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
    let ok = state == Some(ProcState::Exited { code: 0 });
    kprintln!("[JSR-DRV1C] case=role{} exit={:?} ok={}", role, state, ok);
    proc::reap(pid);
    kobj::run_cleanup(usize::MAX);
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
