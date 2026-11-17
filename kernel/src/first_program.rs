//! 生产首程序装载、执行和资源回收。
//! Production first-program load, execution and resource reclamation.
//!
//! 本模块只依赖正式进程、调度、用户内存和系统调用接口；验收演练反向复用同一镜像，
//! 生产入口不依赖任何 `*_demo` 模块。
//! This module depends only on production process, scheduler, user-memory and syscall
//! interfaces. Verification exercises reuse the same image, while production never depends
//! on a `*_demo` module.

use kernel_core::paging::MapFlags;

use crate::arch;
use crate::mm::frame;
use crate::syscall::{table as abi, SyscallSet};
use crate::{kobj, kprintln, proc, sched};

/// 生产首程序用户栈相对私有窗口的顶端偏移。
/// User-stack top offset relative to the private user window.
const STACK_OFF: u64 = 0xC0_0000;

/// 内嵌的 `user-hello` ELF，由 `kernel/build.rs` 从独立用户 crate 构建。
/// Embedded `user-hello` ELF built from its standalone user crate by `kernel/build.rs`.
static USER_HELLO: &[u8] = include_bytes!(env!("JSR_USER_HELLO"));

#[cfg(feature = "sandbox-launch-verify")]
static USER_SANDBOXPROBE: &[u8] = include_bytes!(env!("JSR_USER_SANDBOXPROBE"));

#[cfg(feature = "native-install-abi-verify")]
static USER_INSTALLPROBE: &[u8] = include_bytes!(env!("JSR_USER_INSTALLPROBE"));

#[cfg(feature = "update-agent-verify")]
static USER_AGENTPROBE: &[u8] = include_bytes!(env!("JSR_USER_AGENTPROBE"));

#[cfg(feature = "native-install-list-cli-verify")]
static USER_UPDATE_LIST_CLI: &[u8] = include_bytes!(env!("JSR_USER_CLI"));

/// 内嵌 Jasper 原生 CLI 映像。 Embedded Jasper native CLI image.
#[cfg(all(
    feature = "terminal-session-verify",
    not(any(
        feature = "sandbox-launch-verify",
        feature = "native-install-abi-verify",
        feature = "update-agent-verify"
    ))
))]
static USER_CLI: &[u8] = include_bytes!(env!("JSR_USER_CLI"));

/// 返回生产首程序使用的同一份不可变 ELF 镜像。
/// Returns the same immutable ELF image used by the production first program.
pub(crate) fn image() -> &'static [u8] {
    #[cfg(feature = "native-install-list-cli-verify")]
    {
        return USER_UPDATE_LIST_CLI;
    }
    #[cfg(feature = "update-agent-verify")]
    {
        return USER_AGENTPROBE;
    }
    #[cfg(all(
        feature = "native-install-abi-verify",
        not(any(
            feature = "update-agent-verify",
            feature = "native-install-list-cli-verify"
        ))
    ))]
    {
        return USER_INSTALLPROBE;
    }
    #[cfg(all(
        feature = "sandbox-launch-verify",
        not(any(feature = "native-install-abi-verify", feature = "update-agent-verify"))
    ))]
    {
        return USER_SANDBOXPROBE;
    }
    #[cfg(all(
        feature = "terminal-session-verify",
        not(any(
            feature = "sandbox-launch-verify",
            feature = "native-install-abi-verify",
            feature = "update-agent-verify"
        ))
    ))]
    {
        return USER_CLI;
    }
    #[cfg(not(any(
        feature = "terminal-session-verify",
        feature = "sandbox-launch-verify",
        feature = "native-install-abi-verify",
        feature = "update-agent-verify"
    )))]
    {
        USER_HELLO
    }
}

/// 装载并运行生产首程序，要求退出码为 0 且页帧全部归还。
/// Loads and runs the production first program; requires exit code zero and full frame reclamation.
pub(crate) fn run() -> (Option<proc::ProcState>, bool) {
    #[cfg(all(feature = "terminal-session-verify", feature = "lifecycle-ab-health"))]
    {
        let frames_before_backend = frame::free_frames();
        if let Err(error) = crate::lifecycle_health::init_control_backend() {
            crate::kprintln!(
                "[JSR-PROD-DIAG] update_backend=false reason={}",
                error.name()
            );
            return (None, false);
        }
        crate::kprintln!(
            "[JSR-UPDATE-BACKEND] frames_before={} frames_after={}",
            frames_before_backend,
            frame::free_frames()
        );
    }
    #[cfg(feature = "native-install-abi-verify")]
    if let Err(error) = crate::native_install_abi::warmup() {
        kprintln!(
            "[JSR-PROD-DIAG] native_install_backend=false reason={}",
            error.name()
        );
        return (None, false);
    }
    let free_before = frame::free_frames();
    let (heap_total_before, heap_free_before, _, heap_mapped_before) = crate::mm::heap::stats();
    let heap_used_before = heap_total_before.saturating_sub(heap_free_before);
    #[cfg(feature = "native-install-abi-verify")]
    let allowed = SyscallSet::of(&[
        abi::SYSTEM_CONSOLE_WRITE,
        abi::SYSTEM_MEMORY_MAP,
        abi::SYSTEM_PROCESS_EXIT,
        abi::SYSTEM_INSTALL_PACKAGE_WRITE,
        abi::SYSTEM_INSTALL_REGISTRATION_CREATE,
        abi::SYSTEM_INSTALL_GRANT_CREATE,
        abi::SYSTEM_INSTALL_QUERY,
        abi::SYSTEM_INSTALL_UPDATE_LIST,
        abi::SYSTEM_INSTALL_HANDLE_CREATE,
        abi::SYSTEM_INSTALL_HANDLE_QUERY,
        abi::SYSTEM_HANDLE_DUPLICATE,
        abi::SYSTEM_HANDLE_RESTRICT,
        abi::SYSTEM_HANDLE_CLOSE,
    ]);
    #[cfg(feature = "native-install-list-cli-verify")]
    let allowed = allowed.union(SyscallSet::of(&[
        abi::SYSTEM_TERMINAL_READ,
        abi::SYSTEM_TERMINAL_WRITE,
        abi::SYSTEM_UPDATE_CONTROL_GET,
        abi::SYSTEM_UPDATE_STATUS_QUERY,
        abi::SYSTEM_UPDATE_ACTION_RECOVER,
        abi::SYSTEM_UPDATE_ACTION_ARCHIVE,
        abi::SYSTEM_INSTALL_UPDATE_LIST,
    ]));
    #[cfg(feature = "sandbox-launch-verify")]
    #[cfg(not(feature = "native-install-abi-verify"))]
    let allowed = SyscallSet::of(&[
        abi::SYSTEM_CONSOLE_WRITE,
        abi::SYSTEM_MEMORY_MAP,
        abi::SYSTEM_PROCESS_EXIT,
        abi::SYSTEM_PROCESS_WAIT,
        abi::SYSTEM_HANDLE_CLOSE,
        abi::SYSTEM_SANDBOX_CREATE,
        abi::SYSTEM_SANDBOX_STOP,
        abi::SYSTEM_SANDBOX_DESTROY,
        abi::SYSTEM_SANDBOX_IMAGE_LOAD,
        abi::SYSTEM_SANDBOX_IMAGE_DESTROY,
        abi::SYSTEM_SANDBOX_VOLUME_CREATE,
        abi::SYSTEM_SANDBOX_VOLUME_DESTROY,
        abi::SYSTEM_SANDBOX_LAUNCH_CREATE,
        abi::SYSTEM_SANDBOX_LAUNCH_QUERY,
        abi::SYSTEM_SANDBOX_LAUNCH_DESTROY,
        abi::SYSTEM_SANDBOX_LAUNCH_START,
        abi::SYSTEM_DEVICE_LIST,
        abi::SYSTEM_DEVICE_OPEN,
    ]);
    #[cfg(all(
        feature = "terminal-session-verify",
        not(any(
            feature = "sandbox-launch-verify",
            feature = "native-install-abi-verify"
        ))
    ))]
    let allowed = SyscallSet::of(&[
        abi::SYSTEM_CONSOLE_WRITE,
        abi::SYSTEM_TERMINAL_READ,
        abi::SYSTEM_TERMINAL_WRITE,
        abi::SYSTEM_MEMORY_MAP,
        abi::SYSTEM_PROCESS_EXIT,
        abi::SYSTEM_UPDATE_CONTROL_GET,
        abi::SYSTEM_UPDATE_STATUS_QUERY,
        abi::SYSTEM_UPDATE_ACTION_RECOVER,
        abi::SYSTEM_UPDATE_ACTION_ARCHIVE,
    ]);
    #[cfg(all(feature = "terminal-session-verify", feature = "update-agent-verify"))]
    let allowed = allowed.union(SyscallSet::of(&[
        abi::SYSTEM_CONSOLE_WRITE,
        abi::SYSTEM_TERMINAL_READ,
        abi::SYSTEM_TERMINAL_WRITE,
        abi::SYSTEM_MEMORY_MAP,
        abi::SYSTEM_MEMORY_UNMAP,
        abi::SYSTEM_MEMORY_PROTECT,
        abi::SYSTEM_PROCESS_EXIT,
        abi::SYSTEM_TASK_EXIT,
        abi::SYSTEM_TASK_YIELD,
        abi::SYSTEM_TASK_WAIT,
        abi::SYSTEM_PROCESS_SPAWN,
        abi::SYSTEM_PROCESS_WAIT,
        abi::SYSTEM_CHANNEL_SEND,
        abi::SYSTEM_CHANNEL_RECV,
        abi::SYSTEM_HANDLE_CLOSE,
        abi::SYSTEM_TIME_NOW,
        abi::SYSTEM_UPDATE_CONTROL_GET,
        abi::SYSTEM_UPDATE_STATUS_QUERY,
        abi::SYSTEM_UPDATE_ACTION_RECOVER,
        abi::SYSTEM_UPDATE_ACTION_ARCHIVE,
    ]));
    #[cfg(not(any(
        feature = "terminal-session-verify",
        feature = "sandbox-launch-verify",
        feature = "native-install-abi-verify"
    )))]
    let allowed = SyscallSet::of(&[
        abi::SYSTEM_CONSOLE_WRITE,
        abi::SYSTEM_ABI_GET,
        abi::SYSTEM_TASK_EXIT,
    ]);
    let pid = match proc::create("first-program", allowed) {
        Ok(pid) => pid,
        Err(error) => {
            kprintln!("[JSR-PROD-DIAG] first_program create={error:?}");
            return (None, false);
        }
    };
    #[cfg(feature = "update-agent-verify")]
    if proc::set_app(pid, 0x5541_4447).is_err() {
        kprintln!("[JSR-PROD-DIAG] first_program application_bind=false");
        let _ = proc::reap(pid);
        kobj::run_cleanup(usize::MAX);
        return (None, false);
    }
    #[cfg(all(target_arch = "x86_64", feature = "native-install-abi-verify"))]
    {
        use kernel_core::mac::{Integrity, MacLabel, Secrecy, OBJECT_CLASS_ALL};
        use kernel_core::security::{
            IdentityClass, MetadataState, SecurityContext, SecurityDomain,
        };

        let mut context = SecurityContext::new(
            crate::security::boot_id(),
            IdentityClass::Process,
            pid,
            None,
            MetadataState::Active,
        );
        context.mac = MacLabel::new(
            SecurityDomain::SYSTEM,
            Secrecy::Internal,
            Integrity::Trusted,
            OBJECT_CLASS_ALL,
        );
        if kobj::with(|table| table.set_security_for_verify(pid, context)).is_err() {
            let _ = proc::reap(pid);
            kobj::run_cleanup(usize::MAX);
            return (None, false);
        }
    }
    let base = arch::USER_WINDOW.0;
    let started = match proc::load_elf(pid, image()) {
        Ok(entry) => {
            proc::map_new(
                pid,
                base + STACK_OFF - kernel_core::frame::FRAME_SIZE,
                MapFlags::USER | MapFlags::WRITE,
            )
            .is_ok()
                && proc::spawn_thread(pid, "first-program", entry, base + STACK_OFF, 0, 0).is_ok()
        }
        Err(error) => {
            kprintln!("[JSR-PROD-DIAG] first_program load={error:?}");
            false
        }
    };
    if started {
        sched::run();
    }
    let state = proc::state(pid);
    let _ = proc::reap(pid);
    // reap 只释放所有权；对象销毁由统一清理阶段完成。
    // reap releases ownership only; the common cleanup phase destroys objects.
    kobj::run_cleanup(usize::MAX);
    let free_after = frame::free_frames();
    let (heap_total_after, heap_free_after, _, heap_mapped_after) = crate::mm::heap::stats();
    let heap_used_after = heap_total_after.saturating_sub(heap_free_after);
    let heap_growth_frames = (heap_mapped_after.saturating_sub(heap_mapped_before)
        / kernel_core::frame::FRAME_SIZE) as usize;
    let frames_reclaimed = free_after.saturating_add(heap_growth_frames) == free_before;
    let heap_reclaimed = heap_used_after <= heap_used_before;
    if !frames_reclaimed || !heap_reclaimed {
        let (live, pending, _) = kobj::stats();
        let (pins, orphaned) = crate::mm::pin::stats();
        crate::kprintln!(
            "[JSR-PROD-DIAG] first_program frames={}/{} heap_growth_frames={} heap_used={}/{} live={} pending={} pins={} orphaned={}",
            free_after,
            free_before,
            heap_growth_frames,
            heap_used_after,
            heap_used_before,
            live,
            pending,
            pins,
            orphaned
        );
    }
    (state, frames_reclaimed && heap_reclaimed)
}
