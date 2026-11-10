//! Linux x86_64 system-interface service for explicitly flavored processes.
//!
//! 职责：把已识别的 Linux syscall 映射到 Jasper fd、任务和进程机制；所有调用
//! 先经过兼容进程的显式 Linux 调用集合，不能借用 Jasper 原生 SyscallSet。
//! Responsibility: execute the first real Linux syscall slice outside native Core semantics.

use compat_core::syscall::{
    compat_result, dispatch, CompatErrno, LinuxCall, LinuxSyscall, SyscallDispatch, SyscallRequest,
};

use kernel_core::objtable::ObjId;
use crate::mm::user::copy_from_user;
use crate::syscall::{SyscallArgs, CONSOLE_WRITE_MAX};
use crate::{console, proc};

/// Dispatches one x86_64 Linux syscall for the current process.
///
/// 执行当前 Linux flavor 进程的一次 syscall；未映射调用返回 `ENOSYS`，未授权调用
/// 返回 `EPERM`，所有错误使用 Linux 负 errno 返回约定。
pub fn on_syscall(a: &SyscallArgs) -> i64 {
    if proc::current_exiting() {
        proc::thread_exit(0, "killed linux process");
    }
    let Some(pid) = proc::current_process() else {
        return -i64::from(CompatErrno::NoSys as i32);
    };
    let SyscallDispatch::Mapped(call) = dispatch(SyscallRequest {
        number: a.id,
        args: a.args,
    }) else {
        return -i64::from(CompatErrno::NoSys as i32);
    };
    if !proc::linux_syscall_allowed(pid, call.syscall) {
        return -i64::from(CompatErrno::Perm as i32);
    }
    execute(pid, call)
}

fn execute(pid: ObjId, call: LinuxCall) -> i64 {
    match call.syscall {
        LinuxSyscall::Write => compat_result(linux_write(pid, call.args)),
        LinuxSyscall::GetPid | LinuxSyscall::GetTid => proc::linux_pid(pid)
            .map(i64::from)
            .ok_or(CompatErrno::NoSys)
            .unwrap_or_else(|error| -i64::from(error as i32)),
        LinuxSyscall::ExitGroup => {
            let code = call.args[0] as i64;
            proc::thread_exit(code, "linux exit_group")
        }
        _ => -i64::from(CompatErrno::NoSys as i32),
    }
}

fn linux_write(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let len = usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    if !entry.rights.contains(kernel_core::object::Rights::WRITE)
        || entry.kind != compat_core::fd::CompatKind::Other
        || entry.handle != proc::LINUX_CONSOLE_HANDLE
    {
        return Err(CompatErrno::BadFd);
    }
    if len > CONSOLE_WRITE_MAX {
        return Err(CompatErrno::Invalid);
    }
    if len == 0 {
        return Ok(0);
    }
    let mut bytes = alloc::vec![0u8; len];
    copy_from_user(&mut bytes, args[1], len).map_err(|_| CompatErrno::Fault)?;
    console::write_bytes(&bytes);
    Ok(len as u64)
}
