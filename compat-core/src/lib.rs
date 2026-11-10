//! Linux ABI compatibility service core.
//!
//! 职责：在系统服务/接口层把 Linux fd、进程身份和 syscall 请求映射到 Jasper
//! Handle/Rights、对象身份和原生系统接口。边界：不实现 Linux 内核 Core，不把
//! fd、errno 或 Linux syscall 语义加入 Jasper 原生 ABI。

#![cfg_attr(not(test), no_std)]

pub mod fd;
pub mod native;
pub mod process;
pub mod syscall;

pub use fd::{CompatKind, FdBatch, FdEntry, FdHandle, FdTable, FdTableError};
pub use native::{
    Epoll, EpollEvent, EpollInterest, EventSourceTable, Futex, FutexWake, MemoryMapping,
    NativeError, NativeHandle, NativeMemory, NativeWait, Uring,
};
pub use process::{LinuxPid, ProcessEntry, ProcessTable, ProcessTableError, ProcessToken};
pub use syscall::{
    compat_result, dispatch, CompatErrno, LinuxCall, LinuxSyscall, SyscallDispatch, SyscallRequest,
};
