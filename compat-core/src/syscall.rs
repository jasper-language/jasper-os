//! Linux x86_64 syscall identification mapped to Jasper compatibility operations.

use linux_raw_sys::general::{
    __NR_access, __NR_arch_prctl, __NR_brk, __NR_clock_gettime, __NR_clone, __NR_clone3,
    __NR_close, __NR_epoll_create1, __NR_epoll_ctl, __NR_epoll_pwait, __NR_epoll_pwait2,
    __NR_epoll_wait, __NR_execve, __NR_exit, __NR_exit_group, __NR_fcntl, __NR_fstat, __NR_futex,
    __NR_getcwd, __NR_getegid, __NR_geteuid, __NR_getgid, __NR_getgroups, __NR_getpid,
    __NR_getppid, __NR_getrandom, __NR_gettid, __NR_getuid, __NR_io_uring_enter,
    __NR_io_uring_register, __NR_io_uring_setup, __NR_kill, __NR_madvise, __NR_mmap,
    __NR_mprotect, __NR_munmap, __NR_newfstatat, __NR_openat, __NR_poll, __NR_pread64,
    __NR_prlimit64, __NR_read, __NR_readlink, __NR_rseq, __NR_rt_sigaction, __NR_rt_sigprocmask,
    __NR_rt_sigreturn, __NR_sched_yield, __NR_set_robust_list, __NR_set_tid_address,
    __NR_sigaltstack, __NR_statfs, __NR_tgkill, __NR_uname, __NR_write, __NR_writev,
};

/// Linux x86_64 futex syscall number for restart policy.
/// 用于重启策略的 Linux x86_64 futex syscall 编号。
pub const LINUX_NR_FUTEX: u64 = __NR_futex as u64;

/// Stable compatibility user identity until Jasper exposes Unix accounts.
/// Jasper 暴露 Unix 账号模型前使用的稳定兼容用户身份。
pub const LINUX_COMPAT_UID: u64 = 0;

/// Stable compatibility primary group identity.
/// 稳定的兼容主组身份。
pub const LINUX_COMPAT_GID: u64 = 0;

/// Compatibility roots are created by the kernel service and have no Linux parent.
/// 兼容根进程由内核服务创建，不存在可引用的 Linux 父进程。
pub const LINUX_COMPAT_ROOT_PPID: u64 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum LinuxSyscall {
    Read,
    Pread64,
    Write,
    WriteV,
    Close,
    OpenAt,
    Fstat,
    NewFstatAt,
    Fcntl,
    Poll,
    StatFs,
    ReadLink,
    Brk,
    Access,
    ArchPrctl,
    ClockGettime,
    Mmap,
    Munmap,
    Mprotect,
    Madvise,
    Clone,
    Clone3,
    Execve,
    Exit,
    ExitGroup,
    GetPid,
    GetPpid,
    GetTid,
    GetRandom,
    Getcwd,
    GetUid,
    GetEuid,
    GetGid,
    GetEgid,
    GetGroups,
    SetTidAddress,
    SetRobustList,
    Rseq,
    Prlimit64,
    Futex,
    RtSigAction,
    RtSigProcMask,
    RtSigReturn,
    Tgkill,
    SchedYield,
    Sigaltstack,
    Kill,
    Uname,
    EpollCreate1,
    EpollCtl,
    EpollWait,
    /// epoll wait with an atomically applied signal mask.
    /// 带原子信号掩码切换的 epoll 等待。
    EpollPWait,
    /// Nanosecond-deadline epoll wait with a signal mask.
    /// 带信号掩码和纳秒截止期的 epoll 等待。
    EpollPWait2,
    /// io_uring setup.
    /// 创建 io_uring 兼容环。
    IoUringSetup,
    /// io_uring submission and completion entry.
    /// io_uring 提交与完成入口。
    IoUringEnter,
    /// io_uring buffer/file registration.
    /// io_uring 缓冲与文件注册。
    IoUringRegister,
}

/// Explicit Linux syscall authority for one compatibility process.
///
/// 一个 Linux 兼容进程可显式发起的 syscall 集合。该集合不是 Jasper 原生
/// `SyscallSet` 的别名，也不绕过兼容层参数和 Handle/Rights 检查。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinuxSyscallSet(u64);

impl LinuxSyscallSet {
    /// No Linux syscall is authorized.
    /// 不允许任何 Linux syscall。
    pub const EMPTY: Self = Self(0);

    /// Builds an explicit set from supported Linux syscall identities.
    /// 从受支持的 Linux syscall 身份构造显式集合。
    pub const fn of(calls: &[LinuxSyscall]) -> Self {
        let mut bits = 0u64;
        let mut index = 0;
        while index < calls.len() {
            bits |= 1u64 << calls[index] as u8;
            index += 1;
        }
        Self(bits)
    }

    /// Returns whether the call is authorized.
    /// 判断该 syscall 是否获准。
    pub const fn contains(self, syscall: LinuxSyscall) -> bool {
        self.0 & (1u64 << syscall as u8) != 0
    }
}

const _: () = assert!((LinuxSyscall::ClockGettime as u8) < 64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinuxCall {
    pub syscall: LinuxSyscall,
    pub args: [u64; 6],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyscallRequest {
    pub number: u64,
    pub args: [u64; 6],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyscallDispatch {
    Mapped(LinuxCall),
    Unsupported { number: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum CompatErrno {
    Perm = linux_raw_sys::errno::EPERM,
    NoEntry = linux_raw_sys::errno::ENOENT,
    NoProcess = linux_raw_sys::errno::ESRCH,
    Interrupted = linux_raw_sys::errno::EINTR,
    BadFd = linux_raw_sys::errno::EBADF,
    TryAgain = linux_raw_sys::errno::EAGAIN,
    NoMemory = linux_raw_sys::errno::ENOMEM,
    Fault = linux_raw_sys::errno::EFAULT,
    Invalid = linux_raw_sys::errno::EINVAL,
    /// The destination buffer is too small.
    /// 目标缓冲区容量不足。
    Range = linux_raw_sys::errno::ERANGE,
    /// Resource is already owned or waited on.
    /// 资源已被占用或已有等待者。
    Busy = linux_raw_sys::errno::EBUSY,
    /// Bounded compatibility capacity is exhausted.
    /// 有界兼容容量耗尽。
    NoSpace = linux_raw_sys::errno::ENOSPC,
    /// Absolute deadline elapsed.
    /// 绝对截止期已到。
    TimedOut = linux_raw_sys::errno::ETIMEDOUT,
    /// An operation was cancelled.
    /// 操作已取消。
    Canceled = linux_raw_sys::errno::ECANCELED,
    NoSys = linux_raw_sys::errno::ENOSYS,
}

pub fn dispatch(request: SyscallRequest) -> SyscallDispatch {
    let syscall = match request.number {
        value if value == u64::from(__NR_read) => LinuxSyscall::Read,
        value if value == u64::from(__NR_pread64) => LinuxSyscall::Pread64,
        value if value == u64::from(__NR_write) => LinuxSyscall::Write,
        value if value == u64::from(__NR_writev) => LinuxSyscall::WriteV,
        value if value == u64::from(__NR_close) => LinuxSyscall::Close,
        value if value == u64::from(__NR_openat) => LinuxSyscall::OpenAt,
        value if value == u64::from(__NR_fstat) => LinuxSyscall::Fstat,
        value if value == u64::from(__NR_newfstatat) => LinuxSyscall::NewFstatAt,
        value if value == u64::from(__NR_fcntl) => LinuxSyscall::Fcntl,
        value if value == u64::from(__NR_poll) => LinuxSyscall::Poll,
        value if value == u64::from(__NR_statfs) => LinuxSyscall::StatFs,
        value if value == u64::from(__NR_readlink) => LinuxSyscall::ReadLink,
        value if value == u64::from(__NR_brk) => LinuxSyscall::Brk,
        value if value == u64::from(__NR_access) => LinuxSyscall::Access,
        value if value == u64::from(__NR_arch_prctl) => LinuxSyscall::ArchPrctl,
        value if value == u64::from(__NR_clock_gettime) => LinuxSyscall::ClockGettime,
        value if value == u64::from(__NR_mmap) => LinuxSyscall::Mmap,
        value if value == u64::from(__NR_munmap) => LinuxSyscall::Munmap,
        value if value == u64::from(__NR_mprotect) => LinuxSyscall::Mprotect,
        value if value == u64::from(__NR_madvise) => LinuxSyscall::Madvise,
        value if value == u64::from(__NR_clone) => LinuxSyscall::Clone,
        value if value == u64::from(__NR_clone3) => LinuxSyscall::Clone3,
        value if value == u64::from(__NR_execve) => LinuxSyscall::Execve,
        value if value == u64::from(__NR_exit) => LinuxSyscall::Exit,
        value if value == u64::from(__NR_exit_group) => LinuxSyscall::ExitGroup,
        value if value == u64::from(__NR_getpid) => LinuxSyscall::GetPid,
        value if value == u64::from(__NR_getppid) => LinuxSyscall::GetPpid,
        value if value == u64::from(__NR_gettid) => LinuxSyscall::GetTid,
        value if value == u64::from(__NR_getrandom) => LinuxSyscall::GetRandom,
        value if value == u64::from(__NR_getcwd) => LinuxSyscall::Getcwd,
        value if value == u64::from(__NR_getuid) => LinuxSyscall::GetUid,
        value if value == u64::from(__NR_geteuid) => LinuxSyscall::GetEuid,
        value if value == u64::from(__NR_getgid) => LinuxSyscall::GetGid,
        value if value == u64::from(__NR_getegid) => LinuxSyscall::GetEgid,
        value if value == u64::from(__NR_getgroups) => LinuxSyscall::GetGroups,
        value if value == u64::from(__NR_set_tid_address) => LinuxSyscall::SetTidAddress,
        value if value == u64::from(__NR_set_robust_list) => LinuxSyscall::SetRobustList,
        value if value == u64::from(__NR_rseq) => LinuxSyscall::Rseq,
        value if value == u64::from(__NR_prlimit64) => LinuxSyscall::Prlimit64,
        value if value == u64::from(__NR_futex) => LinuxSyscall::Futex,
        value if value == u64::from(__NR_rt_sigaction) => LinuxSyscall::RtSigAction,
        value if value == u64::from(__NR_rt_sigprocmask) => LinuxSyscall::RtSigProcMask,
        value if value == u64::from(__NR_rt_sigreturn) => LinuxSyscall::RtSigReturn,
        value if value == u64::from(__NR_tgkill) => LinuxSyscall::Tgkill,
        value if value == u64::from(__NR_sched_yield) => LinuxSyscall::SchedYield,
        value if value == u64::from(__NR_sigaltstack) => LinuxSyscall::Sigaltstack,
        value if value == u64::from(__NR_kill) => LinuxSyscall::Kill,
        value if value == u64::from(__NR_uname) => LinuxSyscall::Uname,
        value if value == u64::from(__NR_epoll_create1) => LinuxSyscall::EpollCreate1,
        value if value == u64::from(__NR_epoll_ctl) => LinuxSyscall::EpollCtl,
        value if value == u64::from(__NR_epoll_wait) => LinuxSyscall::EpollWait,
        value if value == u64::from(__NR_epoll_pwait) => LinuxSyscall::EpollPWait,
        value if value == u64::from(__NR_epoll_pwait2) => LinuxSyscall::EpollPWait2,
        value if value == u64::from(__NR_io_uring_setup) => LinuxSyscall::IoUringSetup,
        value if value == u64::from(__NR_io_uring_enter) => LinuxSyscall::IoUringEnter,
        value if value == u64::from(__NR_io_uring_register) => LinuxSyscall::IoUringRegister,
        number => return SyscallDispatch::Unsupported { number },
    };
    SyscallDispatch::Mapped(LinuxCall {
        syscall,
        args: request.args,
    })
}

pub fn compat_result(result: Result<u64, CompatErrno>) -> i64 {
    match result {
        Ok(value) if value <= i64::MAX as u64 => value as i64,
        Ok(_) => -(CompatErrno::Invalid as i32 as i64),
        Err(error) => -(error as i32 as i64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_linux_syscalls_use_target_uapi_numbers() {
        let expected = [
            (__NR_read, LinuxSyscall::Read),
            (__NR_pread64, LinuxSyscall::Pread64),
            (__NR_write, LinuxSyscall::Write),
            (__NR_writev, LinuxSyscall::WriteV),
            (__NR_close, LinuxSyscall::Close),
            (__NR_openat, LinuxSyscall::OpenAt),
            (__NR_fstat, LinuxSyscall::Fstat),
            (__NR_newfstatat, LinuxSyscall::NewFstatAt),
            (__NR_fcntl, LinuxSyscall::Fcntl),
            (__NR_poll, LinuxSyscall::Poll),
            (__NR_statfs, LinuxSyscall::StatFs),
            (__NR_readlink, LinuxSyscall::ReadLink),
            (__NR_brk, LinuxSyscall::Brk),
            (__NR_access, LinuxSyscall::Access),
            (__NR_arch_prctl, LinuxSyscall::ArchPrctl),
            (__NR_clock_gettime, LinuxSyscall::ClockGettime),
            (__NR_madvise, LinuxSyscall::Madvise),
            (__NR_set_tid_address, LinuxSyscall::SetTidAddress),
            (__NR_clone3, LinuxSyscall::Clone3),
            (__NR_set_robust_list, LinuxSyscall::SetRobustList),
            (__NR_rseq, LinuxSyscall::Rseq),
            (__NR_prlimit64, LinuxSyscall::Prlimit64),
            (__NR_getpid, LinuxSyscall::GetPid),
            (__NR_gettid, LinuxSyscall::GetTid),
            (__NR_getrandom, LinuxSyscall::GetRandom),
            (__NR_getcwd, LinuxSyscall::Getcwd),
            (__NR_getuid, LinuxSyscall::GetUid),
            (__NR_geteuid, LinuxSyscall::GetEuid),
            (__NR_getgid, LinuxSyscall::GetGid),
            (__NR_getegid, LinuxSyscall::GetEgid),
            (__NR_getgroups, LinuxSyscall::GetGroups),
            (__NR_futex, LinuxSyscall::Futex),
            (__NR_tgkill, LinuxSyscall::Tgkill),
            (__NR_rt_sigreturn, LinuxSyscall::RtSigReturn),
            (__NR_sched_yield, LinuxSyscall::SchedYield),
            (__NR_sigaltstack, LinuxSyscall::Sigaltstack),
            (__NR_kill, LinuxSyscall::Kill),
            (__NR_uname, LinuxSyscall::Uname),
            (__NR_epoll_wait, LinuxSyscall::EpollWait),
            (__NR_epoll_pwait, LinuxSyscall::EpollPWait),
            (__NR_epoll_pwait2, LinuxSyscall::EpollPWait2),
            (__NR_io_uring_setup, LinuxSyscall::IoUringSetup),
            (__NR_io_uring_enter, LinuxSyscall::IoUringEnter),
            (__NR_io_uring_register, LinuxSyscall::IoUringRegister),
        ];
        for (number, syscall) in expected {
            assert_eq!(
                dispatch(SyscallRequest {
                    number: u64::from(number),
                    args: [1, 2, 3, 4, 5, 6],
                }),
                SyscallDispatch::Mapped(LinuxCall {
                    syscall,
                    args: [1, 2, 3, 4, 5, 6],
                })
            );
        }
    }

    #[test]
    fn unsupported_is_explicit_and_errno_is_negative() {
        assert_eq!(
            dispatch(SyscallRequest {
                number: u64::MAX,
                args: [0; 6],
            }),
            SyscallDispatch::Unsupported { number: u64::MAX }
        );
        assert_eq!(compat_result(Ok(7)), 7);
        assert_eq!(compat_result(Err(CompatErrno::BadFd)), -9);
        assert_eq!(compat_result(Err(CompatErrno::Range)), -34);
        assert_eq!(compat_result(Err(CompatErrno::NoSys)), -38);
    }

    #[test]
    fn linux_syscall_authority_is_explicit_and_does_not_alias_neighbors() {
        let set = LinuxSyscallSet::of(&[
            LinuxSyscall::Write,
            LinuxSyscall::GetPid,
            LinuxSyscall::ExitGroup,
        ]);
        assert!(set.contains(LinuxSyscall::Write));
        assert!(set.contains(LinuxSyscall::GetPid));
        assert!(set.contains(LinuxSyscall::ExitGroup));
        assert!(!set.contains(LinuxSyscall::Read));
        assert!(!set.contains(LinuxSyscall::GetPpid));
        assert!(!LinuxSyscallSet::EMPTY.contains(LinuxSyscall::Write));
    }
}
