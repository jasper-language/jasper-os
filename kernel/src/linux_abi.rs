//! Linux x86_64 system-interface service for explicitly flavored processes.
//!
//! 职责：把已识别的 Linux syscall 映射到 Jasper fd、任务、内存和受控只读文件机制；
//! 所有调用先经过兼容进程的显式 Linux 调用集合，不能借用 Jasper 原生 SyscallSet。
//! Responsibility: execute Linux syscalls through explicit compatibility authority while
//! preserving Jasper Handle/Rights, memory ownership, bounds and resource cleanup.

use compat_core::syscall::{
    compat_result, dispatch, CompatErrno, LinuxCall, LinuxSyscall, SyscallDispatch, SyscallRequest,
};

#[cfg(feature = "compat-dynamic-libc-verify")]
use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::objtable::ObjId;

use crate::mm::user::{copy_from_user, copy_to_user};
use crate::syscall::{SyscallArgs, CONSOLE_WRITE_MAX};
use crate::{console, proc};

#[cfg(feature = "compat-dynamic-libc-verify")]
static SYSCALL_TRACE_REMAINING: AtomicU32 = AtomicU32::new(96);
#[cfg(feature = "compat-dynamic-libc-verify")]
static PATH_TRACE_REMAINING: AtomicU32 = AtomicU32::new(24);

#[cfg(feature = "compat-dynamic-libc-verify")]
fn trace_request(args: &SyscallArgs) {
    let remaining = SYSCALL_TRACE_REMAINING.load(Ordering::Relaxed);
    if remaining == 0 {
        return;
    }
    let index = 96 - remaining;
    if SYSCALL_TRACE_REMAINING
        .compare_exchange(
            remaining,
            remaining - 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        )
        .is_ok()
    {
        crate::kprintln!(
            "[JSR-LINUX-SYSCALL] index={} nr={} a0={:#x} a1={:#x} a2={:#x} a3={:#x} a4={:#x} a5={:#x}",
            index,
            args.id,
            args.args[0],
            args.args[1],
            args.args[2],
            args.args[3],
            args.args[4],
            args.args[5]
        );
    }
}

#[cfg(feature = "compat-dynamic-libc-verify")]
fn trace_path(kind: &str, path: &[u8]) {
    let remaining = PATH_TRACE_REMAINING.load(Ordering::Relaxed);
    if remaining == 0
        || PATH_TRACE_REMAINING
            .compare_exchange(
                remaining,
                remaining - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .is_err()
    {
        return;
    }
    let path = path
        .iter()
        .position(|byte| *byte == 0)
        .map(|end| &path[..end])
        .unwrap_or(path);
    let mut escaped = [0u8; 256];
    let mut len = 0usize;
    for byte in path.iter().copied().take(escaped.len()) {
        let printable = byte.is_ascii_graphic() || byte == b' ';
        if len == escaped.len() {
            break;
        }
        escaped[len] = if printable { byte } else { b'?' };
        len += 1;
    }
    let text = core::str::from_utf8(&escaped[..len]).unwrap_or("<non-utf8>");
    crate::kprintln!("[JSR-LINUX-PATH] kind={} path={}", kind, text);
}

#[cfg(feature = "compat-dynamic-libc-verify")]
fn trace_path_address(pid: ObjId, kind: &str, address: u64) {
    let mut bytes = [0u8; 160];
    match proc::read(pid, address, &mut bytes) {
        Ok(()) => trace_path(kind, &bytes),
        Err(_) => crate::kprintln!(
            "[JSR-LINUX-PATH] kind={} address={:#x} readable=false",
            kind,
            address
        ),
    }
}

/// Dispatches one x86_64 Linux syscall for the current process.
///
/// 执行当前 Linux flavor 进程的一次 syscall；未映射调用返回 `ENOSYS`，未授权调用
/// 返回 `EPERM`，所有错误使用 Linux 负 errno 返回约定。
pub fn on_syscall(a: &SyscallArgs) -> i64 {
    if proc::current_exiting() {
        proc::thread_exit(0, "killed linux process");
    }
    #[cfg(feature = "compat-dynamic-libc-verify")]
    trace_request(a);
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
        LinuxSyscall::WriteV => compat_result(linux_writev(pid, call.args)),
        LinuxSyscall::Read => compat_result(linux_read(pid, call.args)),
        LinuxSyscall::Pread64 => compat_result(linux_pread64(pid, call.args)),
        LinuxSyscall::Close => compat_result(linux_close(pid, call.args[0])),
        LinuxSyscall::OpenAt => compat_result(linux_openat(pid, call.args)),
        LinuxSyscall::Fstat => compat_result(linux_fstat(pid, call.args)),
        LinuxSyscall::NewFstatAt => compat_result(linux_newfstatat(pid, call.args)),
        LinuxSyscall::Mmap => compat_result(linux_mmap(pid, call.args)),
        LinuxSyscall::Munmap => compat_result(linux_munmap(pid, call.args)),
        LinuxSyscall::Mprotect => compat_result(linux_mprotect(pid, call.args)),
        LinuxSyscall::Brk => compat_result(linux_brk(pid, call.args[0])),
        LinuxSyscall::Access => compat_result(linux_access(call.args[0])),
        LinuxSyscall::ArchPrctl => compat_result(linux_arch_prctl(call.args)),
        LinuxSyscall::ClockGettime => compat_result(linux_clock_gettime(call.args)),
        LinuxSyscall::GetPid | LinuxSyscall::GetTid => proc::linux_pid(pid)
            .map(i64::from)
            .ok_or(CompatErrno::NoSys)
            .unwrap_or_else(|error| -i64::from(error as i32)),
        LinuxSyscall::Exit | LinuxSyscall::ExitGroup => {
            let code = call.args[0] as i64;
            proc::thread_exit(code, "linux process exit")
        }
        _ => -i64::from(CompatErrno::NoSys as i32),
    }
}

fn linux_write(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let len = usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    authorize_console(pid, fd, true)?;
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

/// Writes one Linux iovec array to an authorized console descriptor.
///
/// 写入受权限保护的 Linux 控制台 fd；iovec 数量、总长度和每个用户区间都有界检查。
fn linux_writev(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const MAX_IOVECS: usize = 16;
    const IOVEC_BYTES: usize = 16;
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let count = usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    if count > MAX_IOVECS {
        return Err(CompatErrno::Invalid);
    }
    authorize_console(pid, fd, true)?;
    let mut total = 0usize;
    let mut bytes = alloc::vec::Vec::new();
    for index in 0..count {
        let vector = args[1]
            .checked_add((index * IOVEC_BYTES) as u64)
            .ok_or(CompatErrno::Fault)?;
        let mut iovec = [0u8; IOVEC_BYTES];
        copy_from_user(&mut iovec, vector, IOVEC_BYTES).map_err(|_| CompatErrno::Fault)?;
        let base = u64::from_le_bytes(iovec[0..8].try_into().unwrap());
        let len = usize::try_from(u64::from_le_bytes(iovec[8..16].try_into().unwrap()))
            .map_err(|_| CompatErrno::Invalid)?;
        total = total.checked_add(len).ok_or(CompatErrno::Invalid)?;
        if total > CONSOLE_WRITE_MAX {
            return Err(CompatErrno::Invalid);
        }
        let start = bytes.len();
        bytes.resize(start + len, 0);
        copy_from_user(&mut bytes[start..], base, len).map_err(|_| CompatErrno::Fault)?;
    }
    if !bytes.is_empty() {
        console::write_bytes(&bytes);
    }
    Ok(total as u64)
}

fn authorize_console(pid: ObjId, fd: u32, write: bool) -> Result<(), CompatErrno> {
    let entry = proc::linux_fd(pid, fd).ok_or(CompatErrno::BadFd)?;
    let rights = if write {
        kernel_core::object::Rights::WRITE
    } else {
        kernel_core::object::Rights::READ
    };
    if !entry.rights.contains(rights)
        || entry.kind != compat_core::fd::CompatKind::Other
        || entry.handle != proc::LINUX_CONSOLE_HANDLE
    {
        return Err(CompatErrno::BadFd);
    }
    Ok(())
}

/// Implements bounded Linux `read(2)` for stdin and virtual read-only files.
///
/// 标准输入当前没有数据源并返回 EOF；文件读取在全部用户页校验通过后才提交游标。
fn linux_read(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const MAX_READ: usize = 1024 * 1024;
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let len = usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    if len > MAX_READ {
        return Err(CompatErrno::Invalid);
    }
    if fd == 0 {
        authorize_console(pid, fd, false)?;
        return Ok(0);
    }
    let (handle, offset) = proc::linux_file_state(pid, fd).ok_or(CompatErrno::BadFd)?;
    let file = crate::linux_vfs::FileId::from_handle(handle).ok_or(CompatErrno::BadFd)?;
    let source = file.bytes();
    let offset = usize::try_from(offset).map_err(|_| CompatErrno::Invalid)?;
    let available = source.len().saturating_sub(offset).min(len);
    if available != 0 {
        copy_to_user(args[1], &source[offset..offset + available], available)
            .map_err(|_| CompatErrno::Fault)?;
    }
    if !proc::set_linux_file_offset(pid, fd, (offset + available) as u64) {
        return Err(CompatErrno::BadFd);
    }
    Ok(available as u64)
}

/// Implements bounded `pread64(2)` without changing the descriptor cursor.
///
/// 从显式文件偏移读取真实虚拟文件字节；非法 fd、越界长度或用户页错误均失败关闭。
fn linux_pread64(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const MAX_READ: usize = 1024 * 1024;
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let len = usize::try_from(args[2]).map_err(|_| CompatErrno::Invalid)?;
    if len > MAX_READ {
        return Err(CompatErrno::Invalid);
    }
    let (handle, _) = proc::linux_file_state(pid, fd).ok_or(CompatErrno::BadFd)?;
    let file = crate::linux_vfs::FileId::from_handle(handle).ok_or(CompatErrno::BadFd)?;
    let offset = usize::try_from(args[3]).map_err(|_| CompatErrno::Invalid)?;
    let source = file.bytes();
    let available = source.len().saturating_sub(offset).min(len);
    if available != 0 {
        copy_to_user(args[1], &source[offset..offset + available], available)
            .map_err(|_| CompatErrno::Fault)?;
    }
    Ok(available as u64)
}

/// Maps a bounded file-backed or anonymous private compatibility region.
///
/// 支持真实 libc 文件和匿名私有映射；拒绝写执行同开、越界、未对齐文件偏移、
/// 未知非私有标志和与已有映射冲突的 `MAP_FIXED`。失败会撤销本次全部页。
fn linux_mmap(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const PAGE: u64 = kernel_core::frame::FRAME_SIZE;
    const MAX_MAP_BYTES: u64 = 64 * 1024 * 1024;
    const MAP_PRIVATE: u64 = 0x02;
    const MAP_FIXED: u64 = 0x10;
    const MAP_ANONYMOUS: u64 = 0x20;
    const MAP_DENYWRITE: u64 = 0x800;
    const MAP_NORESERVE: u64 = 0x4000;
    const PROT_READ: u64 = 0x1;
    const PROT_WRITE: u64 = 0x2;
    const PROT_EXEC: u64 = 0x4;

    let bytes = args[1];
    if bytes == 0 || bytes > MAX_MAP_BYTES || args[2] & !(PROT_READ | PROT_WRITE | PROT_EXEC) != 0 {
        return Err(CompatErrno::Invalid);
    }
    if args[2] & PROT_WRITE != 0 && args[2] & PROT_EXEC != 0 {
        return Err(CompatErrno::Perm);
    }
    if args[3] & MAP_PRIVATE == 0
        || args[3] & !(MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS | MAP_DENYWRITE | MAP_NORESERVE) != 0
        || args[5] % PAGE != 0
    {
        return Err(CompatErrno::Invalid);
    }

    let anonymous = args[3] & MAP_ANONYMOUS != 0;
    let file = if anonymous {
        None
    } else {
        let fd = u32::try_from(args[4]).map_err(|_| CompatErrno::BadFd)?;
        let (handle, _) = proc::linux_file_state(pid, fd).ok_or(CompatErrno::BadFd)?;
        Some(crate::linux_vfs::FileId::from_handle(handle).ok_or(CompatErrno::BadFd)?)
    };
    let rounded = bytes.checked_add(PAGE - 1).ok_or(CompatErrno::Invalid)? & !(PAGE - 1);
    let cursor = proc::linux_mmap_cursor(pid).ok_or(CompatErrno::NoSys)?;
    let requested = if args[0] == 0 {
        cursor
    } else {
        align_down(args[0], PAGE)
    };
    if requested < crate::arch::USER_WINDOW.0
        || requested
            .checked_add(rounded)
            .is_none_or(|end| end > crate::arch::USER_WINDOW.1)
    {
        return Err(CompatErrno::NoMemory);
    }
    if args[3] & MAP_FIXED != 0 {
        // MAP_FIXED replaces prior mappings by contract. The source bytes remain available
        // in the immutable virtual file, so a later mapping failure cannot expose stale pages.
        let mut page = requested;
        while page < requested + rounded {
            let _ = proc::unmap_page(pid, page);
            page += PAGE;
        }
    }
    let mut start = requested;
    while start < crate::arch::USER_WINDOW.1.saturating_sub(rounded) {
        let mut page = start;
        let mut free = true;
        while page < start + rounded {
            if proc::page_flags(pid, page).is_some() {
                free = false;
                break;
            }
            page += PAGE;
        }
        if free {
            break;
        }
        if args[3] & MAP_FIXED != 0 {
            return Err(CompatErrno::NoMemory);
        }
        start = start.checked_add(rounded).ok_or(CompatErrno::NoMemory)?;
    }
    if start + rounded > crate::arch::USER_WINDOW.1 {
        return Err(CompatErrno::NoMemory);
    }
    let writable = args[2] & PROT_WRITE != 0;
    let executable = args[2] & PROT_EXEC != 0;
    let mut flags = kernel_core::paging::MapFlags::USER;
    if writable {
        flags = flags.union(kernel_core::paging::MapFlags::WRITE);
    }
    if executable {
        flags = flags.union(kernel_core::paging::MapFlags::EXECUTE);
    }
    let mut mapped = alloc::vec::Vec::new();
    let mut page = start;
    while page < start + rounded {
        if proc::map_new(pid, page, flags).is_err() {
            for address in mapped.iter().rev().copied() {
                let _ = proc::unmap_page(pid, address);
            }
            return Err(CompatErrno::NoMemory);
        }
        mapped.push(page);
        page += PAGE;
    }
    if let Some(file) = file {
        let source = file.bytes();
        let offset = usize::try_from(args[5]).map_err(|_| CompatErrno::Invalid)?;
        let copy_bytes = usize::try_from(bytes).map_err(|_| CompatErrno::Invalid)?;
        if offset < source.len() {
            let end = source.len().min(offset.saturating_add(copy_bytes));
            let mut copied = 0usize;
            while offset + copied < end {
                let chunk = (end - offset - copied).min(PAGE as usize);
                if proc::write(
                    pid,
                    start + copied as u64,
                    &source[offset + copied..offset + copied + chunk],
                )
                .is_err()
                {
                    for address in mapped.iter().rev().copied() {
                        let _ = proc::unmap_page(pid, address);
                    }
                    return Err(CompatErrno::Fault);
                }
                copied += chunk;
            }
        }
    }
    if !proc::set_linux_mmap_cursor(pid, start + rounded) {
        for address in mapped.iter().rev().copied() {
            let _ = proc::unmap_page(pid, address);
        }
        return Err(CompatErrno::NoSys);
    }
    Ok(start)
}

fn linux_munmap(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const PAGE: u64 = kernel_core::frame::FRAME_SIZE;
    if args[0] % PAGE != 0 || args[1] == 0 || args[1] % PAGE != 0 {
        return Err(CompatErrno::Invalid);
    }
    let end = args[0].checked_add(args[1]).ok_or(CompatErrno::Invalid)?;
    if end > crate::arch::USER_WINDOW.1 {
        return Err(CompatErrno::Invalid);
    }
    let mut page = args[0];
    while page < end {
        proc::unmap_page(pid, page).map_err(|_| CompatErrno::NoMemory)?;
        page += PAGE;
    }
    Ok(0)
}

fn linux_mprotect(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const PAGE: u64 = kernel_core::frame::FRAME_SIZE;
    const PROT_READ: u64 = 0x1;
    const PROT_WRITE: u64 = 0x2;
    const PROT_EXEC: u64 = 0x4;
    if args[0] % PAGE != 0
        || args[1] == 0
        || args[1] % PAGE != 0
        || args[2] & !(PROT_READ | PROT_WRITE | PROT_EXEC) != 0
        || (args[2] & PROT_WRITE != 0 && args[2] & PROT_EXEC != 0)
    {
        return Err(CompatErrno::Invalid);
    }
    let end = args[0].checked_add(args[1]).ok_or(CompatErrno::Invalid)?;
    if end > crate::arch::USER_WINDOW.1 {
        return Err(CompatErrno::Invalid);
    }
    proc::protect_range(
        pid,
        args[0],
        args[1] / PAGE,
        args[2] & PROT_WRITE != 0,
        args[2] & PROT_EXEC != 0,
    )
    .map_err(|_| CompatErrno::NoMemory)?;
    Ok(0)
}

/// Implements the x86_64 `arch_prctl(2)` TLS base operation.
///
/// 当前切片仅接受 `ARCH_SET_FS`，地址必须位于本架构用户私有窗口。线程级 FS_BASE 随
/// 任务上下文保存和恢复，不能把值泄漏给下一任务。
fn linux_arch_prctl(args: [u64; 6]) -> Result<u64, CompatErrno> {
    const ARCH_SET_FS: u64 = 0x1002;
    if args[0] != ARCH_SET_FS {
        return Err(CompatErrno::Invalid);
    }
    if args[1] < crate::arch::USER_WINDOW.0
        || args[1] >= crate::arch::USER_WINDOW.1
        || !crate::arch::set_user_fs_base(args[1])
    {
        return Err(CompatErrno::Invalid);
    }
    Ok(0)
}

/// Implements `clock_gettime(2)` for the Jasper monotonic clock.
///
/// 当前只声明 `CLOCK_MONOTONIC`，使用高精度内核单调时钟；没有可信墙上时钟时不对
/// `CLOCK_REALTIME` 伪造时间。时间戳以 x86_64 Linux `timespec` 写回用户空间。
fn linux_clock_gettime(args: [u64; 6]) -> Result<u64, CompatErrno> {
    const CLOCK_MONOTONIC: u64 = 1;
    if args[0] != CLOCK_MONOTONIC {
        return Err(CompatErrno::Invalid);
    }
    let now = crate::sched::now_ns();
    let mut timespec = [0u8; 16];
    timespec[0..8].copy_from_slice(&(now / 1_000_000_000).to_le_bytes());
    timespec[8..16].copy_from_slice(&(now % 1_000_000_000).to_le_bytes());
    copy_to_user(args[1], &timespec, timespec.len()).map_err(|_| CompatErrno::Fault)?;
    Ok(0)
}

/// Closes a Linux descriptor through the compatibility fd table.
///
/// 经兼容 fd 表关闭描述符；重复关闭返回 `EBADF`，不会影响其他世代。
fn linux_close(pid: ObjId, fd: u64) -> Result<u64, CompatErrno> {
    let fd = u32::try_from(fd).map_err(|_| CompatErrno::BadFd)?;
    if proc::linux_close_fd(pid, fd) {
        Ok(0)
    } else {
        Err(CompatErrno::BadFd)
    }
}

/// Opens one exact virtual read-only path through `openat(2)`.
///
/// 仅接受绝对路径与只读标志；`O_CLOEXEC` 被保留，写模式、路径穿越和未知路径失败关闭。
fn linux_openat(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const O_CLOEXEC: u64 = 0x80000;
    if !is_at_fdcwd(args[0]) {
        return Err(CompatErrno::Invalid);
    }
    #[cfg(feature = "compat-dynamic-libc-verify")]
    trace_path_address(pid, "openat-address", args[1]);
    let flags = args[2];
    if flags & 3 != 0 || flags & !O_CLOEXEC != 0 {
        return Err(CompatErrno::Perm);
    }
    let path = linux_c_string(args[1], 4096)?;
    #[cfg(feature = "compat-dynamic-libc-verify")]
    trace_path("openat", &path);
    if !path.starts_with(b"/") {
        return Err(CompatErrno::Invalid);
    }
    let file = crate::linux_vfs::lookup(&path).ok_or(CompatErrno::NoEntry)?;
    let fd = proc::linux_install_file(pid, file.handle(), flags & O_CLOEXEC != 0)
        .ok_or(CompatErrno::NoSpace)?;
    Ok(u64::from(fd))
}

/// Reads a bounded NUL-terminated Linux path from user memory.
///
/// 逐字节固定并复制，避免要求未映射的整页同时有效；缺失 NUL 或空路径失败关闭。
fn linux_c_string(address: u64, max: usize) -> Result<alloc::vec::Vec<u8>, CompatErrno> {
    let mut path = alloc::vec::Vec::new();
    for offset in 0..max {
        let current = address
            .checked_add(offset as u64)
            .ok_or(CompatErrno::Fault)?;
        let mut byte = [0u8; 1];
        copy_from_user(&mut byte, current, 1).map_err(|_| CompatErrno::Fault)?;
        if byte[0] == 0 {
            return if path.is_empty() {
                Err(CompatErrno::NoEntry)
            } else {
                Ok(path)
            };
        }
        path.push(byte[0]);
    }
    Err(CompatErrno::Invalid)
}

/// Implements `fstat(2)` for the virtual file namespace.
///
/// 填充 x86_64 Linux `struct stat`，只报告普通只读文件；控制台和其他 fd 不属于本切片。
fn linux_fstat(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
    let (handle, _) = proc::linux_file_state(pid, fd).ok_or(CompatErrno::BadFd)?;
    let file = crate::linux_vfs::FileId::from_handle(handle).ok_or(CompatErrno::BadFd)?;
    write_linux_stat(args[1], file.bytes().len() as u64, file.handle())?;
    Ok(0)
}

/// Implements `newfstatat(2)` for exact virtual paths or an open file descriptor.
///
/// 支持精确虚拟路径和 `AT_EMPTY_PATH` 下的已打开文件；其他目录 fd、路径和 flags 失败关闭。
fn linux_newfstatat(pid: ObjId, args: [u64; 6]) -> Result<u64, CompatErrno> {
    const AT_EMPTY_PATH: u64 = 0x1000;
    let file = if is_at_fdcwd(args[0]) {
        if args[3] != 0 {
            return Err(CompatErrno::Invalid);
        }
        #[cfg(feature = "compat-dynamic-libc-verify")]
        trace_path_address(pid, "newfstatat-address", args[1]);
        let path = linux_c_string(args[1], 4096)?;
        #[cfg(feature = "compat-dynamic-libc-verify")]
        trace_path("newfstatat", &path);
        crate::linux_vfs::lookup(&path).ok_or(CompatErrno::NoEntry)?
    } else if args[3] & !AT_EMPTY_PATH == 0 {
        let fd = u32::try_from(args[0]).map_err(|_| CompatErrno::BadFd)?;
        let (handle, _) = proc::linux_file_state(pid, fd).ok_or(CompatErrno::BadFd)?;
        crate::linux_vfs::FileId::from_handle(handle).ok_or(CompatErrno::BadFd)?
    } else {
        return Err(CompatErrno::Invalid);
    };
    write_linux_stat(args[2], file.bytes().len() as u64, file.handle())?;
    Ok(0)
}

/// Writes the x86_64 Linux `struct stat` fields required by the loader.
///
/// 写入 144 字节、版本稳定的 x86_64 stat；时间和设备字段只表达当前虚拟快照，
/// 不伪造宿主设备身份。
fn write_linux_stat(address: u64, size: u64, inode: u64) -> Result<(), CompatErrno> {
    const STAT_BYTES: usize = 144;
    let mut stat = [0u8; STAT_BYTES];
    stat[0..8].copy_from_slice(&1u64.to_le_bytes());
    stat[8..16].copy_from_slice(&inode.to_le_bytes());
    stat[16..24].copy_from_slice(&1u64.to_le_bytes());
    stat[24..28].copy_from_slice(&0o100444u32.to_le_bytes());
    stat[48..56].copy_from_slice(&size.to_le_bytes());
    stat[56..64].copy_from_slice(&4096i64.to_le_bytes());
    let blocks = size.div_ceil(512) as i64;
    stat[64..72].copy_from_slice(&blocks.to_le_bytes());
    copy_to_user(address, &stat, STAT_BYTES).map_err(|_| CompatErrno::Fault)
}

/// Applies Linux `brk(2)` to the process compatibility heap.
///
/// 只调整本进程兼容堆的匿名页；请求必须留在 Jasper 私有窗口和兼容堆上限内。
/// 部分映射失败会撤销本次已建立的全部页，旧 `brk` 保持不变。
fn linux_brk(pid: ObjId, requested: u64) -> Result<u64, CompatErrno> {
    const BRK_WINDOW_BYTES: u64 = 64 * 1024 * 1024;
    let current = proc::linux_brk_value(pid).ok_or(CompatErrno::NoSys)?;
    if requested == 0 {
        return Ok(current);
    }
    let floor = crate::arch::USER_WINDOW.0 + 0x1000_0000;
    let page = kernel_core::frame::FRAME_SIZE;
    if requested < floor
        || requested.checked_add(page - 1).is_none()
        || requested > floor + BRK_WINDOW_BYTES
        || requested >= crate::arch::USER_WINDOW.1
    {
        return Err(CompatErrno::NoMemory);
    }
    let old_end = align_up(current, page);
    let new_end = align_up(requested, page);
    if new_end > old_end {
        let mut mapped = alloc::vec::Vec::new();
        let mut address = old_end;
        while address < new_end {
            if proc::map_new(
                pid,
                address,
                kernel_core::paging::MapFlags::USER.union(kernel_core::paging::MapFlags::WRITE),
            )
            .is_err()
            {
                for mapped in mapped.iter().rev().copied() {
                    let _ = proc::unmap_page(pid, mapped);
                }
                return Err(CompatErrno::NoMemory);
            }
            mapped.push(address);
            address += page;
        }
    } else if new_end < old_end {
        let mut address = new_end;
        while address < old_end {
            proc::unmap_page(pid, address).map_err(|_| CompatErrno::NoMemory)?;
            address += page;
        }
    }
    if !proc::set_linux_brk(pid, requested) {
        return Err(CompatErrno::NoSys);
    }
    Ok(requested)
}

/// Implements `access(2)` over the exact verification namespace.
///
/// 已知虚拟文件返回成功，其他合法绝对路径返回 `ENOENT`；非法用户指针返回
/// `EFAULT`。不得把宿主文件系统可见性泄漏给 Linux 兼容进程。
fn linux_access(path: u64) -> Result<u64, CompatErrno> {
    let bytes = linux_c_string(path, 4096)?;
    #[cfg(feature = "compat-dynamic-libc-verify")]
    trace_path("access", &bytes);
    if crate::linux_vfs::lookup(&bytes).is_some() {
        Ok(0)
    } else {
        Err(CompatErrno::NoEntry)
    }
}

const fn align_up(value: u64, align: u64) -> u64 {
    (value + align - 1) & !(align - 1)
}

const fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}

/// Accepts both sign-extended and zero-extended encodings of `AT_FDCWD`.
///
/// x86_64 callers commonly load the 32-bit value `-100` into `edi`, which zero-extends
/// to `0x0000_0000_ffff_ff9c`; libc may also use the full 64-bit sign extension.
const fn is_at_fdcwd(value: u64) -> bool {
    value == (-100i64) as u64 || value == 0xffff_ff9c
}
