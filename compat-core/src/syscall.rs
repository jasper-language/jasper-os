//! Linux x86_64 syscall identification mapped to Jasper compatibility operations.

use linux_raw_sys::general::{
    __NR_clone, __NR_close, __NR_epoll_create1, __NR_epoll_ctl, __NR_epoll_wait, __NR_execve,
    __NR_exit, __NR_exit_group, __NR_futex, __NR_getpid, __NR_gettid, __NR_mmap, __NR_mprotect,
    __NR_munmap, __NR_openat, __NR_read, __NR_rt_sigaction, __NR_rt_sigprocmask, __NR_write,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinuxSyscall {
    Read,
    Write,
    Close,
    OpenAt,
    Mmap,
    Munmap,
    Mprotect,
    Clone,
    Execve,
    Exit,
    ExitGroup,
    GetPid,
    GetTid,
    Futex,
    RtSigAction,
    RtSigProcMask,
    EpollCreate1,
    EpollCtl,
    EpollWait,
}

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
    Interrupted = linux_raw_sys::errno::EINTR,
    BadFd = linux_raw_sys::errno::EBADF,
    TryAgain = linux_raw_sys::errno::EAGAIN,
    NoMemory = linux_raw_sys::errno::ENOMEM,
    Fault = linux_raw_sys::errno::EFAULT,
    Invalid = linux_raw_sys::errno::EINVAL,
    NoSys = linux_raw_sys::errno::ENOSYS,
}

pub fn dispatch(request: SyscallRequest) -> SyscallDispatch {
    let syscall = match request.number {
        value if value == u64::from(__NR_read) => LinuxSyscall::Read,
        value if value == u64::from(__NR_write) => LinuxSyscall::Write,
        value if value == u64::from(__NR_close) => LinuxSyscall::Close,
        value if value == u64::from(__NR_openat) => LinuxSyscall::OpenAt,
        value if value == u64::from(__NR_mmap) => LinuxSyscall::Mmap,
        value if value == u64::from(__NR_munmap) => LinuxSyscall::Munmap,
        value if value == u64::from(__NR_mprotect) => LinuxSyscall::Mprotect,
        value if value == u64::from(__NR_clone) => LinuxSyscall::Clone,
        value if value == u64::from(__NR_execve) => LinuxSyscall::Execve,
        value if value == u64::from(__NR_exit) => LinuxSyscall::Exit,
        value if value == u64::from(__NR_exit_group) => LinuxSyscall::ExitGroup,
        value if value == u64::from(__NR_getpid) => LinuxSyscall::GetPid,
        value if value == u64::from(__NR_gettid) => LinuxSyscall::GetTid,
        value if value == u64::from(__NR_futex) => LinuxSyscall::Futex,
        value if value == u64::from(__NR_rt_sigaction) => LinuxSyscall::RtSigAction,
        value if value == u64::from(__NR_rt_sigprocmask) => LinuxSyscall::RtSigProcMask,
        value if value == u64::from(__NR_epoll_create1) => LinuxSyscall::EpollCreate1,
        value if value == u64::from(__NR_epoll_ctl) => LinuxSyscall::EpollCtl,
        value if value == u64::from(__NR_epoll_wait) => LinuxSyscall::EpollWait,
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
            (__NR_write, LinuxSyscall::Write),
            (__NR_close, LinuxSyscall::Close),
            (__NR_openat, LinuxSyscall::OpenAt),
            (__NR_getpid, LinuxSyscall::GetPid),
            (__NR_futex, LinuxSyscall::Futex),
            (__NR_epoll_wait, LinuxSyscall::EpollWait),
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
        assert_eq!(compat_result(Err(CompatErrno::NoSys)), -38);
    }
}
