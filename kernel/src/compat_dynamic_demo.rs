//! Real unmodified Ubuntu dynamic ELF execution through `ld-linux`.
//!
//! 职责：运行未修改的 Ubuntu `true` 与 `getconf`，由上游 `ld-linux` 装载真实
//! libc，完成重定位、TLS 和初始化。
//! Responsibility: run unmodified Ubuntu fixtures through the upstream interpreter,
//! Jasper page tables, Ring 3 and Linux syscall compatibility.

use core::sync::atomic::{AtomicU32, Ordering};

use compat_core::syscall::{LinuxSyscall, LinuxSyscallSet};
use jasper_compat_loader::{
    build_initial_stack, map_image, plan_dynamic_program, run_process_entry,
    stack_input_for_program, ImageLayout, ProgramStackInput,
};
use kernel_core::objtable::ObjId;
use kernel_core::security::ApplicationIdentity;
use sha2::{Digest as _, Sha256};

use crate::compat_elf::{JasperExecutionBackend, JasperLoaderMemory};
use crate::mm::frame::free_frames;
use crate::proc::{self, ProcState};
use crate::{arch, kobj, kprintln, sched};

static TRUE: &[u8] = include_bytes!(env!("JSR_UBUNTU_TRUE"));
static GETCONF: &[u8] = include_bytes!(env!("JSR_UBUNTU_GETCONF"));
static PRINTF: &[u8] = include_bytes!(env!("JSR_UBUNTU_PRINTF"));
#[cfg(feature = "compat-pthread-verify")]
static PTHREAD: &[u8] = include_bytes!(env!("JSR_UBUNTU_PTHREAD"));
#[cfg(feature = "compat-signal-verify")]
static SIGNAL: &[u8] = include_bytes!(env!("JSR_UBUNTU_SIGNAL"));
#[cfg(feature = "compat-signal-verify")]
static SIGRETURN_XSTATE: &[u8] = include_bytes!(env!("JSR_UBUNTU_SIGRETURN_XSTATE"));
#[cfg(feature = "compat-xstate-matrix-verify")]
static XSTATE_MATRIX: &[u8] = include_bytes!(env!("JSR_UBUNTU_XSTATE_MATRIX"));
#[cfg(feature = "compat-xstate-matrix-verify")]
static XSTATE_FALLBACK: &[u8] = include_bytes!(env!("JSR_UBUNTU_XSTATE_FALLBACK"));
static INTERPRETER: &[u8] = include_bytes!(env!("JSR_UBUNTU_LD_LINUX"));
static FAILED: AtomicU32 = AtomicU32::new(0);

const EXECUTABLE_BASE: u64 = arch::USER_WINDOW.0 + 0x40_0000;
const INTERPRETER_BASE: u64 = arch::USER_WINDOW.0 + 0x20_0000_0000;
const STACK_TOP: u64 = arch::USER_WINDOW.0 + 0x10_0000_0000;
const STACK_RESERVE_BYTES: u64 = 8 * 1024 * 1024;
const PROGRAM_DEADLINE_TICKS: u64 = 3000;

#[derive(Clone, Copy)]
struct ProgramResult {
    mapped: bool,
    interpreter_entered: bool,
    exited_zero: bool,
    resources: bool,
    syscalls: u32,
    heap_used_before: usize,
    heap_used_after: usize,
}

impl ProgramResult {
    const FAILED: Self = Self {
        mapped: false,
        interpreter_entered: false,
        exited_zero: false,
        resources: false,
        syscalls: 0,
        heap_used_before: 0,
        heap_used_after: 0,
    };
}

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

fn check(ok: bool, stage: &'static str) {
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-COMPAT-DYNAMIC-FAIL] stage={}", stage);
    }
}

fn cleanup(pid: ObjId) {
    let _ = proc::reap(pid);
    kobj::run_cleanup(usize::MAX);
}

fn application_identity(name: &str, executable: &[u8]) -> ApplicationIdentity {
    let mut id = 0xcbf2_9ce4_8422_2325u64;
    for byte in name.as_bytes() {
        id ^= u64::from(*byte);
        id = id.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let measurement: [u8; 32] = Sha256::digest(executable).into();
    ApplicationIdentity::measured(id, 1, measurement)
}

fn allowed_calls() -> LinuxSyscallSet {
    LinuxSyscallSet::of(&[
        LinuxSyscall::Read,
        LinuxSyscall::Pread64,
        LinuxSyscall::Pwrite64,
        LinuxSyscall::ReadV,
        LinuxSyscall::PreadV,
        LinuxSyscall::PwriteV,
        LinuxSyscall::PreadV2,
        LinuxSyscall::PwriteV2,
        LinuxSyscall::ProcessVmReadV,
        LinuxSyscall::ProcessVmWriteV,
        LinuxSyscall::ReadLinkAt,
        LinuxSyscall::Write,
        LinuxSyscall::WriteV,
        LinuxSyscall::GetDents,
        LinuxSyscall::GetDents64,
        LinuxSyscall::Close,
        LinuxSyscall::CloseRange,
        LinuxSyscall::Dup,
        LinuxSyscall::Dup2,
        LinuxSyscall::Dup3,
        LinuxSyscall::Pipe,
        LinuxSyscall::Pipe2,
        LinuxSyscall::Socket,
        LinuxSyscall::Bind,
        LinuxSyscall::Listen,
        LinuxSyscall::Connect,
        LinuxSyscall::Accept,
        LinuxSyscall::Accept4,
        LinuxSyscall::SocketPair,
        LinuxSyscall::EventFd,
        LinuxSyscall::EventFd2,
        LinuxSyscall::TimerFdCreate,
        LinuxSyscall::TimerFdSettime,
        LinuxSyscall::TimerFdGettime,
        LinuxSyscall::TimerCreate,
        LinuxSyscall::TimerSettime,
        LinuxSyscall::TimerGettime,
        LinuxSyscall::TimerGetoverrun,
        LinuxSyscall::TimerDelete,
        LinuxSyscall::SendMsg,
        LinuxSyscall::RecvMsg,
        LinuxSyscall::Sendmmsg,
        LinuxSyscall::Recvmmsg,
        LinuxSyscall::SendTo,
        LinuxSyscall::RecvFrom,
        LinuxSyscall::Shutdown,
        LinuxSyscall::GetSockName,
        LinuxSyscall::GetPeerName,
        LinuxSyscall::GetSockOpt,
        LinuxSyscall::SetSockOpt,
        LinuxSyscall::Chdir,
        LinuxSyscall::Open,
        LinuxSyscall::OpenAt,
        LinuxSyscall::OpenAt2,
        LinuxSyscall::Creat,
        LinuxSyscall::Fchdir,
        LinuxSyscall::Chmod,
        LinuxSyscall::Fchmod,
        LinuxSyscall::FchmodAt,
        LinuxSyscall::FchmodAt2,
        LinuxSyscall::Fchown,
        LinuxSyscall::Chown,
        LinuxSyscall::FchownAt,
        LinuxSyscall::Lchown,
        LinuxSyscall::Mkdir,
        LinuxSyscall::MkdirAt,
        LinuxSyscall::Mknod,
        LinuxSyscall::MknodAt,
        LinuxSyscall::Unlink,
        LinuxSyscall::UnlinkAt,
        LinuxSyscall::Rmdir,
        LinuxSyscall::Rename,
        LinuxSyscall::RenameAt,
        LinuxSyscall::RenameAt2,
        LinuxSyscall::Link,
        LinuxSyscall::LinkAt,
        LinuxSyscall::Symlink,
        LinuxSyscall::SymlinkAt,
        LinuxSyscall::Umask,
        LinuxSyscall::Setxattr,
        LinuxSyscall::LSetxattr,
        LinuxSyscall::FSetxattr,
        LinuxSyscall::Getxattr,
        LinuxSyscall::LGetxattr,
        LinuxSyscall::FGetxattr,
        LinuxSyscall::Listxattr,
        LinuxSyscall::LListxattr,
        LinuxSyscall::FListxattr,
        LinuxSyscall::Removexattr,
        LinuxSyscall::LRemovexattr,
        LinuxSyscall::FRemovexattr,
        LinuxSyscall::Setxattrat,
        LinuxSyscall::Getxattrat,
        LinuxSyscall::Listxattrat,
        LinuxSyscall::Removexattrat,
        LinuxSyscall::Fstat,
        LinuxSyscall::Stat,
        LinuxSyscall::Lstat,
        LinuxSyscall::Fstatfs,
        LinuxSyscall::Fsync,
        LinuxSyscall::Utime,
        LinuxSyscall::Utimes,
        LinuxSyscall::UtimensAt,
        LinuxSyscall::FutimesAt,
        LinuxSyscall::Fdatasync,
        LinuxSyscall::Ftruncate,
        LinuxSyscall::Truncate,
        LinuxSyscall::Fallocate,
        LinuxSyscall::ReadAhead,
        LinuxSyscall::Fadvise64,
        LinuxSyscall::SyncFileRange,
        LinuxSyscall::MemfdCreate,
        LinuxSyscall::MemfdSecret,
        LinuxSyscall::Sync,
        LinuxSyscall::Syncfs,
        LinuxSyscall::NewFstatAt,
        LinuxSyscall::Statx,
        LinuxSyscall::Fcntl,
        LinuxSyscall::Flock,
        LinuxSyscall::Poll,
        LinuxSyscall::PPoll,
        LinuxSyscall::Select,
        LinuxSyscall::PSelect6,
        LinuxSyscall::Ioctl,
        LinuxSyscall::StatFs,
        LinuxSyscall::ReadLink,
        LinuxSyscall::SendFile,
        LinuxSyscall::CopyFileRange,
        LinuxSyscall::Splice,
        LinuxSyscall::Vmsplice,
        LinuxSyscall::Tee,
        LinuxSyscall::Brk,
        LinuxSyscall::Access,
        LinuxSyscall::FaccessAt,
        LinuxSyscall::FaccessAt2,
        LinuxSyscall::Prctl,
        LinuxSyscall::ArchPrctl,
        LinuxSyscall::CapGet,
        LinuxSyscall::CapSet,
        LinuxSyscall::IoprioGet,
        LinuxSyscall::IoprioSet,
        LinuxSyscall::Personality,
        LinuxSyscall::RestartSyscall,
        LinuxSyscall::RemapFilePages,
        LinuxSyscall::Vhangup,
        LinuxSyscall::GetThreadArea,
        LinuxSyscall::SetThreadArea,
        LinuxSyscall::ModifyLdt,
        LinuxSyscall::LegacySysctl,
        LinuxSyscall::LegacyAfs,
        LinuxSyscall::LegacyCreateModule,
        LinuxSyscall::LegacyGetKernelSyms,
        LinuxSyscall::LegacyQueryModule,
        LinuxSyscall::LegacyNfsservctl,
        LinuxSyscall::LegacyGetpmsg,
        LinuxSyscall::LegacyPutpmsg,
        LinuxSyscall::LegacyEpollCtlOld,
        LinuxSyscall::LegacyEpollWaitOld,
        LinuxSyscall::LegacyTuxcall,
        LinuxSyscall::LegacyVserver,
        LinuxSyscall::LegacySecurity,
        LinuxSyscall::LegacyUstat,
        LinuxSyscall::LegacyUselib,
        LinuxSyscall::LegacySysfs,
        LinuxSyscall::AddKey,
        LinuxSyscall::RequestKey,
        LinuxSyscall::Keyctl,
        LinuxSyscall::Cachestat,
        LinuxSyscall::FanotifyInit,
        LinuxSyscall::FanotifyMark,
        LinuxSyscall::FileGetattr,
        LinuxSyscall::FileSetattr,
        LinuxSyscall::FsConfig,
        LinuxSyscall::FsMount,
        LinuxSyscall::FsOpen,
        LinuxSyscall::FsPick,
        LinuxSyscall::GetMempolicy,
        LinuxSyscall::SetMempolicy,
        LinuxSyscall::SetMempolicyHomeNode,
        LinuxSyscall::Mbind,
        LinuxSyscall::MigratePages,
        LinuxSyscall::MovePages,
        LinuxSyscall::LandlockCreateRuleset,
        LinuxSyscall::LandlockAddRule,
        LinuxSyscall::LandlockRestrictSelf,
        LinuxSyscall::Listmount,
        LinuxSyscall::Statmount,
        LinuxSyscall::Listns,
        LinuxSyscall::LookupDcookie,
        LinuxSyscall::LsmGetSelfAttr,
        LinuxSyscall::LsmSetSelfAttr,
        LinuxSyscall::LsmListModules,
        LinuxSyscall::MapShadowStack,
        LinuxSyscall::MountSetattr,
        LinuxSyscall::MoveMount,
        LinuxSyscall::NameToHandleAt,
        LinuxSyscall::OpenByHandleAt,
        LinuxSyscall::OpenTree,
        LinuxSyscall::OpenTreeAttr,
        LinuxSyscall::PkeyAlloc,
        LinuxSyscall::PkeyFree,
        LinuxSyscall::PkeyMprotect,
        LinuxSyscall::ProcessMadvise,
        LinuxSyscall::ProcessMrelease,
        LinuxSyscall::RseqSliceYield,
        LinuxSyscall::Seccomp,
        LinuxSyscall::Uprobe,
        LinuxSyscall::Uretprobe,
        LinuxSyscall::Userfaultfd,
        LinuxSyscall::Mount,
        LinuxSyscall::Umount2,
        LinuxSyscall::PivotRoot,
        LinuxSyscall::Chroot,
        LinuxSyscall::Swapon,
        LinuxSyscall::Swapoff,
        LinuxSyscall::InitModule,
        LinuxSyscall::FinitModule,
        LinuxSyscall::DeleteModule,
        LinuxSyscall::Acct,
        LinuxSyscall::Iopl,
        LinuxSyscall::Ioperm,
        LinuxSyscall::KexecLoad,
        LinuxSyscall::KexecFileLoad,
        LinuxSyscall::Quotactl,
        LinuxSyscall::QuotactlFd,
        LinuxSyscall::Bpf,
        LinuxSyscall::PerfEventOpen,
        LinuxSyscall::Ptrace,
        LinuxSyscall::Setns,
        LinuxSyscall::Unshare,
        LinuxSyscall::Syslog,
        LinuxSyscall::Adjtimex,
        LinuxSyscall::ClockAdjtime,
        LinuxSyscall::ClockSettime,
        LinuxSyscall::Settimeofday,
        LinuxSyscall::Sethostname,
        LinuxSyscall::Setdomainname,
        LinuxSyscall::Reboot,
        LinuxSyscall::ClockGettime,
        LinuxSyscall::ClockGetres,
        LinuxSyscall::Nanosleep,
        LinuxSyscall::Pause,
        LinuxSyscall::ClockNanosleep,
        LinuxSyscall::Mremap,
        LinuxSyscall::Mseal,
        LinuxSyscall::Getrlimit,
        LinuxSyscall::Setrlimit,
        LinuxSyscall::EpollCreate,
        LinuxSyscall::EpollCreate1,
        LinuxSyscall::EpollCtl,
        LinuxSyscall::EpollWait,
        LinuxSyscall::EpollPWait,
        LinuxSyscall::EpollPWait2,
        LinuxSyscall::IoUringSetup,
        LinuxSyscall::IoUringEnter,
        LinuxSyscall::IoUringRegister,
        LinuxSyscall::IoSetup,
        LinuxSyscall::IoDestroy,
        LinuxSyscall::IoSubmit,
        LinuxSyscall::IoCancel,
        LinuxSyscall::IoGetevents,
        LinuxSyscall::IoPgetevents,
        LinuxSyscall::RtSigAction,
        LinuxSyscall::RtSigPending,
        LinuxSyscall::RtSigqueueinfo,
        LinuxSyscall::RtSigProcMask,
        LinuxSyscall::RtSigsuspend,
        LinuxSyscall::RtSigtimedwait,
        LinuxSyscall::RtTgsigqueueinfo,
        LinuxSyscall::RtSigReturn,
        LinuxSyscall::Tkill,
        LinuxSyscall::Tgkill,
        LinuxSyscall::SchedYield,
        LinuxSyscall::Sigaltstack,
        LinuxSyscall::Signalfd,
        LinuxSyscall::Signalfd4,
        LinuxSyscall::InotifyInit,
        LinuxSyscall::InotifyInit1,
        LinuxSyscall::InotifyAddWatch,
        LinuxSyscall::InotifyRmWatch,
        LinuxSyscall::Kill,
        LinuxSyscall::Kcmp,
        LinuxSyscall::Uname,
        LinuxSyscall::Mmap,
        LinuxSyscall::Munmap,
        LinuxSyscall::Mprotect,
        LinuxSyscall::Msync,
        LinuxSyscall::MsgGet,
        LinuxSyscall::MsgSend,
        LinuxSyscall::MsgReceive,
        LinuxSyscall::MsgCtl,
        LinuxSyscall::SemGet,
        LinuxSyscall::SemOp,
        LinuxSyscall::SemTimedOp,
        LinuxSyscall::SemCtl,
        LinuxSyscall::ShmGet,
        LinuxSyscall::ShmAt,
        LinuxSyscall::ShmDt,
        LinuxSyscall::ShmCtl,
        LinuxSyscall::MqOpen,
        LinuxSyscall::MqUnlink,
        LinuxSyscall::MqTimedsend,
        LinuxSyscall::MqTimedreceive,
        LinuxSyscall::MqNotify,
        LinuxSyscall::MqGetsetattr,
        LinuxSyscall::MinCore,
        LinuxSyscall::Madvise,
        LinuxSyscall::Membarrier,
        LinuxSyscall::Mlock,
        LinuxSyscall::Mlock2,
        LinuxSyscall::Mlockall,
        LinuxSyscall::Munlock,
        LinuxSyscall::Munlockall,
        LinuxSyscall::Clone,
        LinuxSyscall::Fork,
        LinuxSyscall::Clone3,
        LinuxSyscall::Vfork,
        LinuxSyscall::Execve,
        LinuxSyscall::Execveat,
        LinuxSyscall::Futex,
        LinuxSyscall::FutexWait,
        LinuxSyscall::FutexWake,
        LinuxSyscall::FutexRequeue,
        LinuxSyscall::FutexWaitv,
        LinuxSyscall::Exit,
        LinuxSyscall::ExitGroup,
        LinuxSyscall::GetPid,
        LinuxSyscall::GetPpid,
        LinuxSyscall::GetPgid,
        LinuxSyscall::GetPgrp,
        LinuxSyscall::GetSid,
        LinuxSyscall::SetPgid,
        LinuxSyscall::SetSid,
        LinuxSyscall::GetTid,
        LinuxSyscall::GetRandom,
        LinuxSyscall::GetTimeOfDay,
        LinuxSyscall::Getrusage,
        LinuxSyscall::GetItimer,
        LinuxSyscall::Time,
        LinuxSyscall::Times,
        LinuxSyscall::Alarm,
        LinuxSyscall::SetItimer,
        LinuxSyscall::Getcwd,
        LinuxSyscall::GetUid,
        LinuxSyscall::GetEuid,
        LinuxSyscall::GetGid,
        LinuxSyscall::GetEgid,
        LinuxSyscall::SetUid,
        LinuxSyscall::SetGid,
        LinuxSyscall::SetReUid,
        LinuxSyscall::SetReGid,
        LinuxSyscall::SetResUid,
        LinuxSyscall::SetResGid,
        LinuxSyscall::SetFsuid,
        LinuxSyscall::SetFsgid,
        LinuxSyscall::GetGroups,
        LinuxSyscall::SetGroups,
        LinuxSyscall::GetResUid,
        LinuxSyscall::GetResGid,
        LinuxSyscall::GetPriority,
        LinuxSyscall::SetPriority,
        LinuxSyscall::Lseek,
        LinuxSyscall::GetCpu,
        LinuxSyscall::Sysinfo,
        LinuxSyscall::SchedGetAffinity,
        LinuxSyscall::SchedGetParam,
        LinuxSyscall::SchedSetAffinity,
        LinuxSyscall::SchedSetScheduler,
        LinuxSyscall::SchedGetScheduler,
        LinuxSyscall::SchedSetParam,
        LinuxSyscall::SchedGetPriorityMax,
        LinuxSyscall::SchedGetPriorityMin,
        LinuxSyscall::SchedRrGetInterval,
        LinuxSyscall::SchedGetAttr,
        LinuxSyscall::SchedSetAttr,
        LinuxSyscall::SetTidAddress,
        LinuxSyscall::GetRobustList,
        LinuxSyscall::SetRobustList,
        LinuxSyscall::Rseq,
        LinuxSyscall::Prlimit64,
        LinuxSyscall::Wait4,
        LinuxSyscall::WaitId,
        LinuxSyscall::PidfdOpen,
        LinuxSyscall::PidfdSendSignal,
        LinuxSyscall::PidfdGetFd,
    ])
}

pub fn run() {
    let frames_before = free_frames();
    check(crate::linux_vfs::fixture_nonempty(), "libc_fixture");

    let true_argv: [&[u8]; 1] = [b"/usr/bin/true"];
    let true_warm = run_program(
        "ubuntu-dynamic-true-warm",
        TRUE,
        INTERPRETER,
        &true_argv,
        frames_before,
        false,
    );
    check(
        true_warm.interpreter_entered && true_warm.exited_zero,
        "true_warm",
    );
    let true_baseline = free_frames();
    let true_result = run_program(
        "ubuntu-dynamic-true",
        TRUE,
        INTERPRETER,
        &true_argv,
        true_baseline,
        true,
    );
    kprintln!(
        "[JSR-COMPAT-DYNAMIC] fixture=ubuntu-x86_64 executable=true ld_linux=true libc=true mapped={} entry=interpreter true interpreter_syscalls={} syscall_delta={} exit_zero={} frames_before={} resources={} failed={}",
        true_result.mapped,
        true_result.interpreter_entered,
        true_result.syscalls,
        true_result.exited_zero,
        true_baseline,
        true_result.resources,
        failed()
    );

    let getconf_argv: [&[u8]; 2] = [b"/usr/bin/getconf", b"GNU_LIBC_VERSION"];
    let getconf_result = run_program(
        "ubuntu-dynamic-getconf",
        GETCONF,
        INTERPRETER,
        &getconf_argv,
        frames_before,
        true,
    );
    kprintln!(
        "[JSR-COMPAT-DYNAMIC-GETCONF] fixture=ubuntu-x86_64 executable=getconf mapped={} entry=interpreter true interpreter_syscalls={} syscall_delta={} exit_zero={} resources={} failed={}",
        getconf_result.mapped,
        getconf_result.interpreter_entered,
        getconf_result.syscalls,
        getconf_result.exited_zero,
        getconf_result.resources,
        failed()
    );

    let printf_argv: [&[u8]; 3] = [b"/usr/bin/printf", b"jasper-%s\n", b"dynamic"];
    let printf_warm = run_program(
        "ubuntu-dynamic-printf-warm",
        PRINTF,
        INTERPRETER,
        &printf_argv,
        frames_before,
        false,
    );
    check(
        printf_warm.interpreter_entered && printf_warm.exited_zero,
        "printf_warm",
    );
    let printf_baseline = free_frames();
    let printf_result = run_program(
        "ubuntu-dynamic-printf",
        PRINTF,
        INTERPRETER,
        &printf_argv,
        printf_baseline,
        true,
    );
    kprintln!(
        "[JSR-COMPAT-DYNAMIC-PRINTF] fixture=ubuntu-x86_64 executable=printf libraries=6 mapped={} entry=interpreter true interpreter_syscalls={} syscall_delta={} exit_zero={} resources={} failed={}",
        printf_result.mapped,
        printf_result.interpreter_entered,
        printf_result.syscalls,
        printf_result.exited_zero,
        printf_result.resources,
        failed()
    );

    #[cfg(feature = "compat-pthread-verify")]
    let pthread_result = {
        let pthread_argv: [&[u8]; 1] = [b"/usr/bin/jasper-pthread-basic"];
        let pthread_baseline = free_frames();
        let result = run_program(
            "ubuntu-dynamic-pthread",
            PTHREAD,
            INTERPRETER,
            &pthread_argv,
            pthread_baseline,
            true,
        );
        kprintln!(
            "[JSR-COMPAT-PTHREAD] fixture=ubuntu-x86_64 executable=pthread-basic mapped={} entry=interpreter true interpreter_syscalls={} syscall_delta={} exit_zero={} resources={} failed={}",
            result.mapped,
            result.interpreter_entered,
            result.syscalls,
            result.exited_zero,
            result.resources,
            failed()
        );
        result
    };

    #[cfg(feature = "compat-signal-verify")]
    let signal_result = {
        let signal_argv: [&[u8]; 1] = [b"/usr/bin/jasper-signal-basic"];
        let signal_baseline = free_frames();
        let result = run_program(
            "ubuntu-dynamic-signal",
            SIGNAL,
            INTERPRETER,
            &signal_argv,
            signal_baseline,
            true,
        );
        kprintln!(
            "[JSR-COMPAT-SIGNAL] fixture=ubuntu-x86_64 executable=signal-basic mapped={} entry=interpreter true interpreter_syscalls={} syscall_delta={} exit_zero={} resources={} failed={}",
            result.mapped,
            result.interpreter_entered,
            result.syscalls,
            result.exited_zero,
            result.resources,
            failed()
        );
        result
    };

    #[cfg(feature = "compat-signal-verify")]
    let sigreturn_xstate_result = {
        let sigreturn_argv: [&[u8]; 1] = [b"/usr/bin/jasper-sigreturn-xstate"];
        let sigreturn_baseline = free_frames();
        let result = run_program(
            "ubuntu-dynamic-sigreturn-xstate",
            SIGRETURN_XSTATE,
            INTERPRETER,
            &sigreturn_argv,
            sigreturn_baseline,
            true,
        );
        kprintln!(
            "[JSR-COMPAT-SIGRETURN-XSTATE] fixture=ubuntu-x86_64 executable=sigreturn-xstate mapped={} entry=interpreter true interpreter_syscalls={} syscall_delta={} exit_zero={} resources={} failed={}",
            result.mapped,
            result.interpreter_entered,
            result.syscalls,
            result.exited_zero,
            result.resources,
            failed()
        );
        result
    };

    #[cfg(feature = "compat-xstate-matrix-verify")]
    let xstate_matrix_result = {
        if arch::x86_64::xstate::mask() == 0 {
            kprintln!("[JSR-COMPAT-XSTATE-MATRIX] skipped=no_xsave");
            None
        } else {
            let matrix_argv: [&[u8]; 1] = [b"/usr/bin/jasper-xstate-matrix"];
            // The first process grows the kernel heap while creating five Linux
            // threads. Run one unmeasured warmup so the measured run proves that
            // scheduler/XSAVE churn itself returns every frame and heap byte.
            let online = sched::online_cpus();
            kprintln!(
                "[JSR-COMPAT-XSTATE-MATRIX] scheduler_online={:#x}",
                u64::from(online.bits())
            );
            let _ = run_program_on(
                "ubuntu-dynamic-xstate-matrix-warmup",
                XSTATE_MATRIX,
                INTERPRETER,
                &matrix_argv,
                free_frames(),
                false,
                online,
            );
            let matrix_baseline = free_frames();
            let result = run_program_on(
                "ubuntu-dynamic-xstate-matrix",
                XSTATE_MATRIX,
                INTERPRETER,
                &matrix_argv,
                matrix_baseline,
                true,
                online,
            );
            kprintln!(
                "[JSR-COMPAT-XSTATE-MATRIX] fixture=ubuntu-x86_64 executable=xstate-matrix mapped={} entry=interpreter true interpreter_syscalls={} syscall_delta={} exit_zero={} resources={} failed={}",
                result.mapped,
                result.interpreter_entered,
                result.syscalls,
                result.exited_zero,
                result.resources,
                failed()
            );
            Some(result)
        }
    };

    #[cfg(feature = "compat-xstate-matrix-verify")]
    let xstate_fallback_result = {
        let fallback_argv: [&[u8]; 1] = [b"/usr/bin/jasper-xstate-fallback"];
        let _ = run_program(
            "ubuntu-dynamic-xstate-fallback-warmup",
            XSTATE_FALLBACK,
            INTERPRETER,
            &fallback_argv,
            free_frames(),
            false,
        );
        let result = run_program(
            "ubuntu-dynamic-xstate-fallback",
            XSTATE_FALLBACK,
            INTERPRETER,
            &fallback_argv,
            free_frames(),
            true,
        );
        kprintln!(
            "[JSR-COMPAT-XSTATE-FALLBACK] fixture=ubuntu-x86_64 executable=xstate-fallback mapped={} entry=interpreter true interpreter_syscalls={} syscall_delta={} exit_zero={} resources={} failed={}",
            result.mapped,
            result.interpreter_entered,
            result.syscalls,
            result.exited_zero,
            result.resources,
            failed()
        );
        result
    };

    let frames_after = free_frames();
    let resources = true_result.resources
        && getconf_result.resources
        && printf_result.resources
        && {
            #[cfg(feature = "compat-pthread-verify")]
            {
                pthread_result.resources && pthread_result.exited_zero
            }
            #[cfg(not(feature = "compat-pthread-verify"))]
            {
                true
            }
        }
        && {
            #[cfg(feature = "compat-signal-verify")]
            {
                signal_result.resources && signal_result.exited_zero
            }
            #[cfg(not(feature = "compat-signal-verify"))]
            {
                true
            }
        }
        && {
            #[cfg(feature = "compat-signal-verify")]
            {
                sigreturn_xstate_result.resources && sigreturn_xstate_result.exited_zero
            }
            #[cfg(not(feature = "compat-signal-verify"))]
            {
                true
            }
        }
        && {
            #[cfg(feature = "compat-xstate-matrix-verify")]
            {
                xstate_matrix_result
                    .as_ref()
                    .is_none_or(|result| result.resources && result.exited_zero)
            }
            #[cfg(not(feature = "compat-xstate-matrix-verify"))]
            {
                true
            }
        }
        && {
            #[cfg(feature = "compat-xstate-matrix-verify")]
            {
                xstate_fallback_result.resources && xstate_fallback_result.exited_zero
            }
            #[cfg(not(feature = "compat-xstate-matrix-verify"))]
            {
                true
            }
        };
    check(
        true_result.exited_zero
            && getconf_result.exited_zero
            && printf_result.exited_zero
            && resources,
        "program_summary",
    );
    kprintln!(
        "[JSR-COMPAT-DYNAMIC-SUMMARY] true={} getconf={} printf={} resources={} cold_heap_delta={} free_frames_before={} free_frames_after={} heap_used_true={}/{} heap_used_getconf={}/{} heap_used_printf={}/{} failed={}",
        true_result.exited_zero,
        getconf_result.exited_zero,
        printf_result.exited_zero,
        resources,
        true_warm
            .heap_used_after
            .saturating_sub(true_warm.heap_used_before),
        frames_before,
        frames_after,
        true_result.heap_used_before,
        true_result.heap_used_after,
        getconf_result.heap_used_before,
        getconf_result.heap_used_after,
        printf_result.heap_used_before,
        printf_result.heap_used_after,
        failed()
    );
}

fn run_program(
    name: &'static str,
    executable: &[u8],
    interpreter: &[u8],
    argv: &[&[u8]],
    frames_before: usize,
    enforce_resources: bool,
) -> ProgramResult {
    run_program_with_interpreter(
        name,
        executable,
        interpreter,
        "/lib64/ld-linux-x86-64.so.2",
        argv,
        &[],
        frames_before,
        enforce_resources,
        None,
    )
}

fn run_program_on(
    name: &'static str,
    executable: &[u8],
    interpreter: &[u8],
    argv: &[&[u8]],
    frames_before: usize,
    enforce_resources: bool,
    affinity: kernel_core::smp::CpuSet,
) -> ProgramResult {
    run_program_with_interpreter(
        name,
        executable,
        interpreter,
        "/lib64/ld-linux-x86-64.so.2",
        argv,
        &[],
        frames_before,
        enforce_resources,
        Some(affinity),
    )
}

fn run_program_with_interpreter(
    name: &'static str,
    executable: &[u8],
    interpreter: &[u8],
    interpreter_path: &'static str,
    argv: &[&[u8]],
    envp: &[&[u8]],
    frames_before: usize,
    enforce_resources: bool,
    affinity: Option<kernel_core::smp::CpuSet>,
) -> ProgramResult {
    let calls_before = crate::syscall::call_count();
    let heap_before = crate::mm::heap::stats();
    let Ok(pid) = proc::create_linux(name, allowed_calls()) else {
        check(false, "create");
        return ProgramResult::FAILED;
    };
    if proc::set_application(pid, application_identity(name, executable)).is_err() {
        check(false, "application_identity");
        cleanup(pid);
        return ProgramResult::FAILED;
    }
    if argv
        .first()
        .is_none_or(|path| !proc::linux_set_exec_path(pid, path))
    {
        check(false, "exec_path");
        cleanup(pid);
        return ProgramResult::FAILED;
    }
    let executable_plan = match jasper_compat_loader::parse(executable) {
        Ok(plan) => plan,
        Err(_) => {
            check(false, "parse_executable");
            cleanup(pid);
            return ProgramResult::FAILED;
        }
    };
    let interpreter_plan = match jasper_compat_loader::parse(interpreter) {
        Ok(plan) => plan,
        Err(_) => {
            check(false, "parse_interpreter");
            cleanup(pid);
            return ProgramResult::FAILED;
        }
    };
    check(executable_plan.interpreter.as_deref() == Some(interpreter_path), "pt_interp");
    let dynamic = match plan_dynamic_program(
        &executable_plan,
        &interpreter_plan,
        EXECUTABLE_BASE,
        INTERPRETER_BASE,
        kernel_core::frame::FRAME_SIZE,
    ) {
        Ok(plan) => plan,
        Err(_) => {
            check(false, "dynamic_layout");
            cleanup(pid);
            return ProgramResult::FAILED;
        }
    };

    let mut memory = JasperLoaderMemory::new(pid);
    let executable_mapped = map_image(&mut memory, executable, &dynamic.executable).is_ok();
    let interpreter_mapped = map_image(&mut memory, interpreter, &dynamic.interpreter).is_ok();
    check(executable_mapped, "map_executable");
    check(interpreter_mapped, "map_interpreter");
    if !executable_mapped || !interpreter_mapped {
        cleanup(pid);
        return ProgramResult::FAILED;
    }

    let random = [0x5au8; 16];
    let stack = stack_input_for_program(ProgramStackInput {
        plan: &executable_plan,
        image: &dynamic.executable,
        interpreter_base: dynamic.interpreter.load_bias,
        stack_top: STACK_TOP,
        argv,
        envp,
        auxv: &[],
        random: Some(&random),
    })
    .and_then(build_initial_stack);
    check(stack.is_ok(), "initial_stack");

    let mut backend = match affinity {
        Some(online) => JasperExecutionBackend::with_stack_reserve_and_affinity(
            pid,
            name,
            STACK_RESERVE_BYTES,
            online,
        ),
        None => JasperExecutionBackend::with_stack_reserve(pid, name, STACK_RESERVE_BYTES),
    };
    let mut entered = false;
    let mut thread = false;
    let mut completed = false;
    if let Ok(stack) = stack {
        match run_process_entry(&mut backend, &dynamic.execution, stack) {
            Ok(()) => entered = true,
            Err(error) => kprintln!(
                "[JSR-COMPAT-DYNAMIC-ERROR] program={} stage=transfer error={:?}",
                name,
                error
            ),
        }
        check(entered, "transfer_interpreter");
        thread = backend.task().is_some();
        check(thread, "thread");
        let deadline = sched::timer_ticks().saturating_add(PROGRAM_DEADLINE_TICKS);
        completed = sched::run_until(deadline);
        if !completed {
            kprintln!(
                "[JSR-COMPAT-DYNAMIC-FAIL] program={} stage=deadline_exceeded deadline={}",
                name,
                deadline
            );
            check(false, "deadline");
            let _ = proc::begin_exit(pid, 124);
            let cleanup_deadline = sched::timer_ticks().saturating_add(100);
            let _ = sched::run_until(cleanup_deadline);
        }
    }

    // Drop the complete loader transaction before measuring steady-state heap usage.
    // 在测量稳态堆占用前释放整次装载事务，避免把仍在作用域的临时计划误报为泄漏。
    drop(backend);
    drop(memory);
    drop(dynamic);
    drop(interpreter_plan);
    drop(executable_plan);

    let exited_zero = completed && proc::state(pid) == Some(ProcState::Exited { code: 0 });
    let syscalls = crate::syscall::call_count().saturating_sub(calls_before);
    let interpreter_entered = entered && thread && syscalls > 0;
    check(interpreter_entered, "interpreter_syscall");
    check(exited_zero, "exit_zero");
    if let Some((pages, references, max)) = proc::frame_reference_stats(pid) {
        kprintln!(
            "[JSR-COMPAT-DYNAMIC-REFS] program={} pages={} references={} max={}",
            name,
            pages,
            references,
            max
        );
    }
    cleanup(pid);
    let frames_after = free_frames();
    let heap_after = crate::mm::heap::stats();
    let heap_used_before = heap_before.0.saturating_sub(heap_before.1);
    let heap_used_after = heap_after.0.saturating_sub(heap_after.1);
    let heap_growth = heap_after.3.saturating_sub(heap_before.3);
    let frame_deficit = frames_before.saturating_sub(frames_after);
    // The page-backed kernel heap grows monotonically. A mapping that expands by
    // exactly the missing frames keeps all capacity in the allocator and is not a
    // workload leak, provided the used heap returns to its baseline.
    let resources = heap_used_after == heap_used_before
        && (frames_after == frames_before && heap_growth == 0
            || heap_growth == frame_deficit as u64 * kernel_core::frame::FRAME_SIZE);
    if !resources {
        let (pins, orphaned) = crate::mm::pin::stats();
        kprintln!(
            "[JSR-COMPAT-DYNAMIC-RESOURCE] program={} frames_before={} frames_after={} retained={} heap_used_before={} heap_used_after={} heap_mapped_delta={} pins={} orphaned={} failed_frees={} released={}",
            name,
            frames_before,
            frames_after,
            frames_before.saturating_sub(frames_after),
            heap_used_before,
            heap_used_after,
            heap_after.3.saturating_sub(heap_before.3),
            pins,
            orphaned,
            crate::mm::memory_object::failed_page_frees(),
            crate::mm::memory_object::released_pages()
        );
    }
    if enforce_resources {
        check(resources, "resources");
    }
    ProgramResult {
        mapped: true,
        interpreter_entered,
        exited_zero,
        resources,
        syscalls,
        heap_used_before,
        heap_used_after,
    }
}

/// Runs an unmodified static Linux ELF from the selected root image.
///
/// 运行 System A/B 根卷中的未修改静态 Linux ELF；静态程序自己提供 C 运行时，
/// 不伪造解释器或动态库。
#[cfg(feature = "lifecycle-root-exec-verify")]
pub(crate) fn run_root_static_program(
    name: &'static str,
    executable: &[u8],
    argv: &[&[u8]],
    frames_before: usize,
    enforce_resources: bool,
) -> bool {
    let calls_before = crate::syscall::call_count();
    let heap_before = crate::mm::heap::stats();
    let Ok(pid) = proc::create_linux(name, allowed_calls()) else {
        return false;
    };
    let failed = || {
        cleanup(pid);
        false
    };
    if proc::set_application(pid, application_identity(name, executable)).is_err()
        || argv.first().is_none_or(|path| !proc::linux_set_exec_path(pid, path))
    {
        return failed();
    }
    let plan = match jasper_compat_loader::parse(executable) {
        Ok(plan) if plan.interpreter.is_none() => plan,
        _ => return failed(),
    };
    let load_bias = if plan.position_independent {
        EXECUTABLE_BASE
    } else {
        0
    };
    let image = match ImageLayout::new(&plan, load_bias, kernel_core::frame::FRAME_SIZE) {
        Ok(image) => image,
        Err(_) => return failed(),
    };
    let stack = match stack_input_for_program(ProgramStackInput {
        plan: &plan,
        image: &image,
        interpreter_base: 0,
        stack_top: STACK_TOP,
        argv,
        envp: &[],
        auxv: &[],
        random: Some(&[0x5au8; 16]),
    })
    .and_then(build_initial_stack)
    {
        Ok(stack) => stack,
        Err(_) => return failed(),
    };
    let mut memory = JasperLoaderMemory::new(pid);
    if map_image(&mut memory, executable, &image).is_err() {
        return failed();
    }
    let stack_pointer = match map_exec_stack(pid, &stack) {
        Ok(stack_pointer) => stack_pointer,
        Err(_) => return failed(),
    };
    let entry = image.entry;
    let started = proc::spawn_thread(pid, name, entry, stack_pointer, 0, 0).is_ok();
    if started {
        let deadline = sched::timer_ticks().saturating_add(PROGRAM_DEADLINE_TICKS);
        let completed = sched::run_until(deadline);
        if !completed {
            let _ = proc::begin_exit(pid, 124);
            let _ = sched::run_until(sched::timer_ticks().saturating_add(100));
        }
    }
    let exited_zero = started && proc::state(pid) == Some(ProcState::Exited { code: 0 });
    let syscalls = crate::syscall::call_count().saturating_sub(calls_before);
    drop(memory);
    drop(image);
    drop(stack);
    drop(plan);
    let frames_after_before_cleanup = crate::mm::frame::free_frames();
    cleanup(pid);
    let frames_after = crate::mm::frame::free_frames();
    let heap_after = crate::mm::heap::stats();
    let heap_used_before = heap_before.0.saturating_sub(heap_before.1);
    let heap_used_after = heap_after.0.saturating_sub(heap_after.1);
    let heap_growth = heap_after.3.saturating_sub(heap_before.3);
    let frame_deficit = frames_before.saturating_sub(frames_after);
    let resources = heap_used_after == heap_used_before
        && (frames_after == frames_before && heap_growth == 0
            || heap_growth == frame_deficit as u64 * kernel_core::frame::FRAME_SIZE);
    kprintln!(
        "[JSR-ANDROID-TOYBOX] program={} static=true mapped={} started={} syscalls={} exit_zero={} frames_before={} frames_after={} resources={}",
        name,
        true,
        started,
        syscalls,
        exited_zero,
        frames_before,
        frames_after,
        resources
    );
    if !resources {
        kprintln!(
            "[JSR-ANDROID-TOYBOX-RESOURCE] name={} frames_after_before_cleanup={} heap_before={} heap_after={}",
            name,
            frames_after_before_cleanup,
            heap_used_before,
            heap_used_after
        );
    }
    started && exited_zero && syscalls != 0 && (!enforce_resources || resources)
}

#[cfg(all(
    feature = "linux-abi",
    feature = "lifecycle-root-exec-verify",
    target_arch = "x86_64"
))]
fn prepare_exec_image(
    pid: ObjId,
    executable: &[u8],
    interpreter: &[u8],
    argv: &[&[u8]],
    envp: &[&[u8]],
) -> Result<(u64, u64), &'static str> {
    let executable_plan =
        jasper_compat_loader::parse(executable).map_err(|_| "parse_executable")?;
    let interpreter_plan =
        jasper_compat_loader::parse(interpreter).map_err(|_| "parse_interpreter")?;
    if executable_plan.interpreter.as_deref() != Some("/lib64/ld-linux-x86-64.so.2") {
        return Err("pt_interp");
    }
    let dynamic = plan_dynamic_program(
        &executable_plan,
        &interpreter_plan,
        EXECUTABLE_BASE,
        INTERPRETER_BASE,
        kernel_core::frame::FRAME_SIZE,
    )
    .map_err(|_| "dynamic_layout")?;
    let mut memory = JasperLoaderMemory::new(pid);
    map_image(&mut memory, executable, &dynamic.executable).map_err(|_| "map_executable")?;
    map_image(&mut memory, interpreter, &dynamic.interpreter).map_err(|_| "map_interpreter")?;
    let random = [0x5au8; 16];
    let stack = stack_input_for_program(ProgramStackInput {
        plan: &executable_plan,
        image: &dynamic.executable,
        interpreter_base: dynamic.interpreter.load_bias,
        stack_top: STACK_TOP,
        argv,
        envp,
        auxv: &[],
        random: Some(&random),
    })
    .and_then(build_initial_stack)
    .map_err(|_| "initial_stack")?;
    let stack_pointer = map_exec_stack(pid, &stack)?;
    Ok((dynamic.execution.entry(), stack_pointer))
}

#[cfg(all(
    feature = "linux-abi",
    feature = "lifecycle-root-exec-verify",
    target_arch = "x86_64"
))]
fn prepare_exec_static_image(
    pid: ObjId,
    executable: &[u8],
    argv: &[&[u8]],
    envp: &[&[u8]],
) -> Result<(u64, u64), &'static str> {
    let plan = jasper_compat_loader::parse(executable).map_err(|_| "parse_executable")?;
    if plan.interpreter.is_some() {
        return Err("static_with_interpreter");
    }
    let load_bias = if plan.position_independent {
        EXECUTABLE_BASE
    } else {
        0
    };
    let image = ImageLayout::new(&plan, load_bias, kernel_core::frame::FRAME_SIZE)
        .map_err(|_| "static_layout")?;
    let stack = stack_input_for_program(ProgramStackInput {
        plan: &plan,
        image: &image,
        interpreter_base: 0,
        stack_top: STACK_TOP,
        argv,
        envp,
        auxv: &[],
        random: Some(&[0x5au8; 16]),
    })
    .and_then(build_initial_stack)
    .map_err(|_| "initial_stack")?;
    let mut memory = JasperLoaderMemory::new(pid);
    map_image(&mut memory, executable, &image).map_err(|_| "map_executable")?;
    let stack_pointer = map_exec_stack(pid, &stack)?;
    Ok((image.entry, stack_pointer))
}

#[cfg(all(
    feature = "linux-abi",
    feature = "lifecycle-root-exec-verify",
    target_arch = "x86_64"
))]
fn map_exec_stack(
    pid: ObjId,
    stack: &jasper_compat_loader::InitialStackPlan,
) -> Result<u64, &'static str> {
    use kernel_core::frame::FRAME_SIZE;
    use kernel_core::paging::MapFlags;
    if stack.stack_pointer() == 0
        || stack.stack_top() <= stack.stack_pointer()
        || stack.stack_top() != stack.stack_pointer() + stack.bytes().len() as u64
    {
        return Err("stack");
    }
    let pointer_start = stack.stack_pointer() - stack.stack_pointer() % FRAME_SIZE;
    let start = stack
        .stack_top()
        .checked_sub(STACK_RESERVE_BYTES)
        .ok_or("stack")?
        & !(FRAME_SIZE - 1);
    if start < crate::arch::USER_WINDOW.0 || start > pointer_start {
        return Err("stack");
    }
    let end = stack
        .stack_top()
        .checked_add(FRAME_SIZE - 1)
        .ok_or("stack")?
        & !(FRAME_SIZE - 1);
    let mut mapped = alloc::vec::Vec::new();
    for address in (start..end).step_by(FRAME_SIZE as usize) {
        if proc::map_new(pid, address, MapFlags::USER.union(MapFlags::WRITE)).is_err() {
            for rollback in mapped.iter().rev().copied() {
                let _ = proc::unmap_page(pid, rollback);
            }
            return Err("stack_map");
        }
        mapped.push(address);
    }
    if proc::write(pid, stack.stack_pointer(), stack.bytes()).is_err() {
        for rollback in mapped.iter().rev().copied() {
            let _ = proc::unmap_page(pid, rollback);
        }
        return Err("stack_write");
    }
    Ok(stack.stack_pointer())
}

/// Replaces the current Linux image while preserving Process and Linux PID identity.
/// 在保留 Process 与 Linux PID 身份的前提下替换当前 Linux 映像。
#[cfg(all(
    feature = "linux-abi",
    feature = "lifecycle-root-exec-verify",
    target_arch = "x86_64"
))]
pub(crate) fn exec_dynamic_program(
    pid: ObjId,
    path: alloc::vec::Vec<u8>,
    executable: alloc::vec::Vec<u8>,
    interpreter: alloc::vec::Vec<u8>,
    argv: alloc::vec::Vec<alloc::vec::Vec<u8>>,
    envp: alloc::vec::Vec<alloc::vec::Vec<u8>>,
) -> Option<(u64, u64)> {
    let saved = match proc::begin_exec_address_space(pid) {
        Ok(saved) => saved,
        Err(error) => {
            kprintln!(
                "[JSR-LINUX-EXEC-FAIL] stage=address_space error={:?}",
                error
            );
            return None;
        }
    };
    if !proc::linux_set_exec_path(pid, &path) {
        let _ = proc::rollback_exec_address_space(pid, saved);
        return None;
    }
    let prepared = {
        let argv_refs = argv
            .iter()
            .map(|value| value.as_slice())
            .collect::<alloc::vec::Vec<_>>();
        let envp_refs = envp
            .iter()
            .map(|value| value.as_slice())
            .collect::<alloc::vec::Vec<_>>();
        prepare_exec_image(pid, &executable, &interpreter, &argv_refs, &envp_refs)
    };
    let (entry, stack) = match prepared {
        Ok(prepared) => prepared,
        Err(stage) => {
            kprintln!("[JSR-LINUX-EXEC-FAIL] stage={}", stage);
            let _ = proc::rollback_exec_address_space(pid, saved);
            return None;
        }
    };
    let Some(space) = proc::current_space_root(pid) else {
        return None;
    };
    // The replacement image is fully built at this point. Publish vfork exec
    // completion before switching CR3 so the suspended parent does not resume
    // across the child's address-space activation boundary.
    let _ = proc::vfork_commit_exec(pid);
    sched::set_current_space(Some(space));
    drop(saved);
    drop(argv);
    drop(envp);
    drop(executable);
    drop(interpreter);
    drop(path);
    let _ = crate::arch::set_user_fs_base(0);
    Some((entry, stack))
}

/// Replaces the current Linux image with one unmodified static ELF.
#[cfg(all(
    feature = "linux-abi",
    feature = "lifecycle-root-exec-verify",
    target_arch = "x86_64"
))]
pub(crate) fn exec_static_program(
    pid: ObjId,
    path: alloc::vec::Vec<u8>,
    executable: alloc::vec::Vec<u8>,
    argv: alloc::vec::Vec<alloc::vec::Vec<u8>>,
    envp: alloc::vec::Vec<alloc::vec::Vec<u8>>,
) -> Option<(u64, u64)> {
    let saved = match proc::begin_exec_address_space(pid) {
        Ok(saved) => saved,
        Err(error) => {
            kprintln!(
                "[JSR-LINUX-EXEC-FAIL] stage=static_address_space error={:?}",
                error
            );
            return None;
        }
    };
    if !proc::linux_set_exec_path(pid, &path) {
        let _ = proc::rollback_exec_address_space(pid, saved);
        return None;
    }
    let prepared = {
        let argv_refs = argv
            .iter()
            .map(|value| value.as_slice())
            .collect::<alloc::vec::Vec<_>>();
        let envp_refs = envp
            .iter()
            .map(|value| value.as_slice())
            .collect::<alloc::vec::Vec<_>>();
        prepare_exec_static_image(pid, &executable, &argv_refs, &envp_refs)
    };
    let (entry, stack) = match prepared {
        Ok(prepared) => prepared,
        Err(stage) => {
            kprintln!("[JSR-LINUX-EXEC-FAIL] stage={}", stage);
            let _ = proc::rollback_exec_address_space(pid, saved);
            return None;
        }
    };
    let Some(space) = proc::current_space_root(pid) else {
        return None;
    };
    let _ = proc::vfork_commit_exec(pid);
    sched::set_current_space(Some(space));
    drop(saved);
    drop(argv);
    drop(envp);
    drop(executable);
    drop(path);
    let _ = crate::arch::set_user_fs_base(0);
    Some((entry, stack))
}

/// Executes one bounded program image through the root-backed dynamic namespace.
/// 通过根卷动态文件命名空间执行一个有界程序镜像。
#[cfg(feature = "lifecycle-root-exec-verify")]
pub(crate) fn run_root_dynamic_program(
    name: &'static str,
    path: &'static str,
    executable: &[u8],
    interpreter: &[u8],
    interpreter_path: &'static str,
    argv: &[&[u8]],
    envp: &[&[u8]],
    frames_before: usize,
    enforce_resources: bool,
) -> bool {
    let result = run_program_with_interpreter(
        name,
        executable,
        interpreter,
        interpreter_path,
        argv,
        envp,
        frames_before,
        enforce_resources,
        None,
    );
    let verified = result.mapped
        && result.interpreter_entered
        && result.exited_zero
        && (!enforce_resources || result.resources)
        && result.syscalls != 0;
    kprintln!(
        "[JSR-LIFE-ROOT-DYNAMIC] program={} path={} interpreter={} mapped={} interpreter_syscalls={} syscalls={} exit_zero={} frames_before={} resources={} failed={}",
        name,
        path,
        interpreter_path,
        result.mapped,
        result.interpreter_entered,
        result.syscalls,
        result.exited_zero,
        frames_before,
        result.resources,
        failed()
    );
    verified
}
