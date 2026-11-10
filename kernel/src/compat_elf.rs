//! Jasper page-table backend for the bounded Linux ELF loader.
//!
//! 职责：把 `compat-loader` 已验证的页、重定位和权限计划落实到真实 Jasper
//! 地址空间，并通过既有线程入口完成受控 Ring 3 交接。
//! 边界：本模块不解析 ELF，不认 Linux syscall，不执行不可信宿主代码。
//! Responsibility: connect validated ELF plans to real Jasper page tables and thread entry.

use alloc::vec::Vec;

use jasper_compat_loader::{
    EntryCall, EntryFrame, ExecutionBackend, InitialStackPlan, LoaderError, LoaderMemory,
    MappingRequest, MemoryPermissions,
};
use kernel_core::frame::FRAME_SIZE;
use kernel_core::objtable::ObjId;
use kernel_core::paging::MapFlags;

use crate::proc;
use crate::task::TaskId;

#[derive(Clone)]
struct WriteSnapshot {
    address: u64,
    bytes: Vec<u8>,
}

#[derive(Clone, Copy)]
struct ProtectSnapshot {
    address: u64,
    flags: MapFlags,
}

struct Transaction {
    mapped: Vec<u64>,
    writes: Vec<WriteSnapshot>,
    protections: Vec<ProtectSnapshot>,
}

impl Transaction {
    fn new() -> Self {
        Self {
            mapped: Vec::new(),
            writes: Vec::new(),
            protections: Vec::new(),
        }
    }

    fn was_mapped(&self, address: u64) -> bool {
        self.mapped
            .iter()
            .any(|mapped| *mapped == address - address % FRAME_SIZE)
    }
}

/// A transactional `LoaderMemory` implementation over one real Jasper process.
///
/// 一个真实 Jasper 进程上的事务式 `LoaderMemory` 实现；失败回滚解除本次映射，
/// 恢复写前字节和页权限。
pub struct JasperLoaderMemory {
    process: ObjId,
    transaction: Option<Transaction>,
}

impl JasperLoaderMemory {
    /// Creates a backend for an empty or freshly created process address space.
    ///
    /// 为新建或仍为空的进程地址空间创建后端。
    pub const fn new(process: ObjId) -> Self {
        Self {
            process,
            transaction: None,
        }
    }

    /// Returns the process this backend loads into.
    ///
    /// 返回后端负责装载的进程。
    pub const fn process(&self) -> ObjId {
        self.process
    }

    fn transaction(&self) -> Result<&Transaction, LoaderError> {
        self.transaction.as_ref().ok_or(LoaderError::BadTransaction)
    }

    fn transaction_mut(&mut self) -> Result<&mut Transaction, LoaderError> {
        self.transaction.as_mut().ok_or(LoaderError::BadTransaction)
    }
}

impl LoaderMemory for JasperLoaderMemory {
    fn begin_transaction(&mut self) -> Result<(), LoaderError> {
        if self.transaction.is_some() {
            return Err(LoaderError::BadTransaction);
        }
        self.transaction = Some(Transaction::new());
        Ok(())
    }

    fn commit_transaction(&mut self) -> Result<(), LoaderError> {
        if self.transaction.take().is_none() {
            return Err(LoaderError::BadTransaction);
        }
        Ok(())
    }

    fn rollback_transaction(&mut self) -> Result<(), LoaderError> {
        let transaction = self.transaction.take().ok_or(LoaderError::BadTransaction)?;
        let mut failed = false;
        for address in transaction.mapped.iter().rev().copied() {
            failed |= proc::unmap_page(self.process, address).is_err();
        }
        for snapshot in transaction.writes.iter().rev() {
            if transaction.was_mapped(snapshot.address) {
                continue;
            }
            failed |= proc::write(self.process, snapshot.address, &snapshot.bytes).is_err();
        }
        for snapshot in transaction.protections.iter().rev().copied() {
            if transaction.was_mapped(snapshot.address) {
                continue;
            }
            failed |= proc::protect_range(
                self.process,
                snapshot.address,
                1,
                snapshot.flags.contains(MapFlags::WRITE),
                snapshot.flags.contains(MapFlags::EXECUTE),
            )
            .is_err();
        }
        if failed {
            Err(LoaderError::TransactionRollbackFailed)
        } else {
            Ok(())
        }
    }

    fn map(&mut self, source: &[u8], request: MappingRequest<'_>) -> Result<(), LoaderError> {
        if request.address % FRAME_SIZE != 0
            || request.memory_bytes == 0
            || request.memory_bytes > FRAME_SIZE
            || request.permissions.writable && request.permissions.executable
            || !request.permissions.readable
        {
            return Err(LoaderError::MemoryMap);
        }
        for range in request.file_ranges {
            let source_end = range
                .source_offset
                .checked_add(range.bytes)
                .ok_or(LoaderError::SourceOutOfBounds)?;
            let destination_end = range
                .destination_offset
                .checked_add(range.bytes)
                .ok_or(LoaderError::MemoryMap)?;
            if source_end > source.len() as u64 || destination_end > request.memory_bytes {
                return Err(LoaderError::SourceOutOfBounds);
            }
        }
        self.transaction()?;
        let flags = map_flags(request.permissions);
        proc::map_new(self.process, request.address, flags).map_err(|_| LoaderError::MemoryMap)?;
        self.transaction_mut()?.mapped.push(request.address);
        for range in request.file_ranges {
            let source_end = range.source_offset + range.bytes;
            self.write(
                request.address + range.destination_offset,
                &source[range.source_offset as usize..source_end as usize],
            )?;
        }
        Ok(())
    }

    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), LoaderError> {
        if bytes.is_empty() {
            return Ok(());
        }
        self.transaction()?;
        let mut previous = alloc::vec![0u8; bytes.len()];
        proc::read(self.process, address, &mut previous).map_err(|_| LoaderError::MemoryWrite)?;
        proc::write(self.process, address, bytes).map_err(|_| LoaderError::MemoryWrite)?;
        self.transaction_mut()?.writes.push(WriteSnapshot {
            address,
            bytes: previous,
        });
        Ok(())
    }

    fn read(&mut self, address: u64, output: &mut [u8]) -> Result<(), LoaderError> {
        proc::read(self.process, address, output).map_err(|_| LoaderError::MemoryRead)
    }

    fn protect(
        &mut self,
        address: u64,
        bytes: u64,
        permissions: MemoryPermissions,
    ) -> Result<(), LoaderError> {
        if address % FRAME_SIZE != 0
            || bytes == 0
            || !bytes.is_multiple_of(FRAME_SIZE)
            || permissions.writable && permissions.executable
            || !permissions.readable
        {
            return Err(LoaderError::MemoryProtect);
        }
        self.transaction()?;
        let pages = bytes / FRAME_SIZE;
        let mut previous = Vec::new();
        previous
            .try_reserve_exact(pages as usize)
            .map_err(|_| LoaderError::MemoryProtect)?;
        for page in 0..pages {
            let page_address = address + page * FRAME_SIZE;
            let flags =
                proc::page_flags(self.process, page_address).ok_or(LoaderError::MemoryProtect)?;
            previous.push(ProtectSnapshot {
                address: page_address,
                flags,
            });
        }
        proc::protect_range(
            self.process,
            address,
            pages,
            permissions.writable,
            permissions.executable,
        )
        .map_err(|_| LoaderError::MemoryProtect)?;
        self.transaction_mut()?.protections.extend(previous);
        Ok(())
    }
}
/// Converts neutral loader permissions to Jasper user page flags.
///
/// 将 ELF 页权限转换为 Jasper 中立映射权限；所有用户页至少可读。
pub const fn map_flags(permissions: MemoryPermissions) -> MapFlags {
    let mut flags = MapFlags::USER;
    if permissions.writable {
        flags = flags.union(MapFlags::WRITE);
    }
    if permissions.executable {
        flags = flags.union(MapFlags::EXECUTE);
    }
    flags
}

/// Controlled entry backend backed by an existing Jasper process and task runtime.
///
/// 基于现有 Jasper 进程和任务运行时的入口后端。动态解释器或静态程序通过
/// `transfer` 安装初始栈并创建主线程；目标构造器由真实运行时负责。
pub struct JasperExecutionBackend {
    process: ObjId,
    name: &'static str,
    task: Option<TaskId>,
    stack_reserve_bytes: u64,
}

impl JasperExecutionBackend {
    /// Creates an entry backend for one process.
    ///
    /// 为一个进程创建入口后端。
    pub const fn new(process: ObjId, name: &'static str) -> Self {
        Self {
            process,
            name,
            task: None,
            stack_reserve_bytes: 0,
        }
    }

    /// Creates a backend with a fixed writable stack reservation below the initial frame.
    ///
    /// 创建在初始栈帧下方预留固定可写栈区的后端。Linux 解释器和 libc 会在进入入口后
    /// 立即扩展调用栈；预留必须位于 Jasper 私有窗口内并由进程退出统一回收。
    pub const fn with_stack_reserve(
        process: ObjId,
        name: &'static str,
        stack_reserve_bytes: u64,
    ) -> Self {
        Self {
            process,
            name,
            task: None,
            stack_reserve_bytes,
        }
    }

    /// Returns the task created by a successful transfer.
    ///
    /// 返回成功交接后创建的任务。
    pub const fn task(&self) -> Option<TaskId> {
        self.task
    }

    fn load_stack(&self, stack: &InitialStackPlan) -> Result<Vec<u64>, LoaderError> {
        if stack.stack_pointer() == 0
            || stack.stack_top() <= stack.stack_pointer()
            || stack.stack_top() != stack.stack_pointer() + stack.bytes().len() as u64
        {
            return Err(LoaderError::BadStack);
        }
        if self.stack_reserve_bytes % FRAME_SIZE != 0 {
            return Err(LoaderError::BadStack);
        }
        let pointer_start = stack.stack_pointer() - stack.stack_pointer() % FRAME_SIZE;
        let start = if self.stack_reserve_bytes == 0 {
            pointer_start
        } else {
            let reserved_start = stack
                .stack_top()
                .checked_sub(self.stack_reserve_bytes)
                .ok_or(LoaderError::BadStack)?
                & !(FRAME_SIZE - 1);
            if reserved_start < crate::arch::USER_WINDOW.0 || reserved_start > pointer_start {
                return Err(LoaderError::BadStack);
            }
            reserved_start
        };
        let end = stack
            .stack_top()
            .checked_add(FRAME_SIZE - 1)
            .ok_or(LoaderError::BadStack)?
            & !(FRAME_SIZE - 1);
        let pages = (end - start) / FRAME_SIZE;
        let mut mapped = Vec::new();
        mapped
            .try_reserve_exact(pages as usize)
            .map_err(|_| LoaderError::MemoryMap)?;
        for address in (start..end).step_by(FRAME_SIZE as usize) {
            if proc::page_flags(self.process, address).is_some()
                || proc::map_new(self.process, address, MapFlags::USER.union(MapFlags::WRITE))
                    .is_err()
            {
                for rollback in mapped.iter().rev().copied() {
                    let _ = proc::unmap_page(self.process, rollback);
                }
                return Err(LoaderError::MemoryMap);
            }
            mapped.push(address);
        }
        if proc::write(self.process, stack.stack_pointer(), stack.bytes()).is_err() {
            for rollback in mapped.iter().rev().copied() {
                let _ = proc::unmap_page(self.process, rollback);
            }
            return Err(LoaderError::MemoryWrite);
        }
        Ok(mapped)
    }
}

impl ExecutionBackend for JasperExecutionBackend {
    fn call_entry(&mut self, _call: EntryCall) -> Result<(), LoaderError> {
        // The initial backend does not emulate call/return through user callbacks.
        // 初始后端不伪造用户 callback 的 call/return；该能力需真实返回路径后启用。
        Err(LoaderError::BadExecution)
    }

    fn transfer(&mut self, frame: EntryFrame) -> Result<(), LoaderError> {
        if self.task.is_some() {
            return Err(LoaderError::BadExecution);
        }
        let mapped = self.load_stack(&frame.stack)?;
        match proc::spawn_thread(
            self.process,
            self.name,
            frame.pc,
            frame.stack.stack_pointer(),
            0,
            0,
        ) {
            Ok((task, _)) => {
                self.task = Some(task);
                Ok(())
            }
            Err(_) => {
                for address in mapped.into_iter().rev() {
                    let _ = proc::unmap_page(self.process, address);
                }
                Err(LoaderError::BadExecution)
            }
        }
    }
}
