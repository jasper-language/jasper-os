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
use crate::{kobj, proc, sched};

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

/// 内嵌 Jasper 原生 CLI 映像。 Embedded Jasper native CLI image.
#[cfg(all(
    feature = "terminal-session-verify",
    not(any(
        feature = "sandbox-launch-verify",
        feature = "native-install-abi-verify"
    ))
))]
static USER_CLI: &[u8] = include_bytes!(env!("JSR_USER_CLI"));

/// 返回生产首程序使用的同一份不可变 ELF 镜像。
/// Returns the same immutable ELF image used by the production first program.
pub(crate) fn image() -> &'static [u8] {
    #[cfg(feature = "native-install-abi-verify")]
    {
        USER_INSTALLPROBE
    }
    #[cfg(feature = "sandbox-launch-verify")]
    #[cfg(not(feature = "native-install-abi-verify"))]
    {
        USER_SANDBOXPROBE
    }
    #[cfg(all(
        feature = "terminal-session-verify",
        not(any(
            feature = "sandbox-launch-verify",
            feature = "native-install-abi-verify"
        ))
    ))]
    {
        USER_CLI
    }
    #[cfg(not(any(
        feature = "terminal-session-verify",
        feature = "sandbox-launch-verify",
        feature = "native-install-abi-verify"
    )))]
    {
        USER_HELLO
    }
}

/// 装载并运行生产首程序，要求退出码为 0 且页帧全部归还。
/// Loads and runs the production first program; requires exit code zero and full frame reclamation.
pub(crate) fn run() -> (Option<proc::ProcState>, bool) {
    let free_before = frame::free_frames();
    #[cfg(feature = "native-install-abi-verify")]
    let allowed = SyscallSet::of(&[
        abi::SYSTEM_CONSOLE_WRITE,
        abi::SYSTEM_MEMORY_MAP,
        abi::SYSTEM_PROCESS_EXIT,
        abi::SYSTEM_INSTALL_PACKAGE_WRITE,
        abi::SYSTEM_INSTALL_REGISTRATION_CREATE,
        abi::SYSTEM_INSTALL_GRANT_CREATE,
        abi::SYSTEM_INSTALL_QUERY,
        abi::SYSTEM_INSTALL_HANDLE_CREATE,
        abi::SYSTEM_INSTALL_HANDLE_QUERY,
        abi::SYSTEM_HANDLE_DUPLICATE,
        abi::SYSTEM_HANDLE_RESTRICT,
        abi::SYSTEM_HANDLE_CLOSE,
    ]);
    #[cfg(feature = "sandbox-launch-verify")]
    #[cfg(not(feature = "native-install-abi-verify"))]
    let allowed = SyscallSet::of(&[
        abi::SYSTEM_CONSOLE_WRITE,
        abi::SYSTEM_MEMORY_MAP,
        abi::SYSTEM_PROCESS_EXIT,
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
    ]);
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
    let Ok(pid) = proc::create("first-program", allowed) else {
        return (None, false);
    };
    #[cfg(all(target_arch = "x86_64", feature = "native-install-abi-verify"))]
    {
        use kernel_core::mac::MacLabel;
        use kernel_core::security::{IdentityClass, MetadataState, SecurityContext};

        let mut context = SecurityContext::new(
            crate::security::boot_id(),
            IdentityClass::Process,
            pid,
            None,
            MetadataState::Active,
        );
        context.mac = MacLabel::system(IdentityClass::Process);
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
        Err(_) => false,
    };
    if started {
        sched::run();
    }
    let state = proc::state(pid);
    let _ = proc::reap(pid);
    // reap 只释放所有权；对象销毁由统一清理阶段完成。
    // reap releases ownership only; the common cleanup phase destroys objects.
    kobj::run_cleanup(usize::MAX);
    (state, frame::free_frames() == free_before)
}
