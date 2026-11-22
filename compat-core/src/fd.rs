//! Linux file descriptor table mapped to Jasper handles and rights.

use alloc::sync::Arc;
use kernel_core::object::Rights;
use kernel_core::sync::SpinLock;

const STANDARD_FD_COUNT: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompatKind {
    File,
    Directory,
    Socket,
    Pipe,
    Event,
    Timer,
    Signal,
    Pidfd,
    Inotify,
    MessageQueue,
    MountTree,
    Namespace,
    FsContext,
    Path,
    Sandbox,
    Device,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FdEntry {
    pub fd: u32,
    pub generation: u32,
    pub handle: u64,
    pub rights: Rights,
    pub kind: CompatKind,
    pub close_on_exec: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FdHandle {
    fd: u32,
    generation: u32,
}

#[derive(Clone)]
pub struct OpenFileRef(Arc<SpinLock<OpenFileState>>);

#[derive(Clone)]
pub struct FdDescription {
    pub entry: FdEntry,
    open_file: OpenFileRef,
}

impl FdDescription {
    pub fn with_handle(mut self, handle: u64) -> Self {
        self.entry.handle = handle;
        self
    }

    /// Returns the cursor shared by every descriptor and fixed-file reference.
    pub fn offset(&self) -> u64 {
        self.open_file.0.lock().offset
    }

    /// Updates the cursor shared by every descriptor and fixed-file reference.
    pub fn set_offset(&self, offset: u64) {
        self.open_file.0.lock().offset = offset;
    }

    /// Returns the Linux status flags attached to this open-file description.
    pub fn status_flags(&self) -> u32 {
        self.open_file.0.lock().status_flags
    }
}

impl FdHandle {
    pub const fn fd(self) -> u32 {
        self.fd
    }

    pub const fn generation(self) -> u32 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FdTableError {
    InvalidFd,
    InvalidHandle,
    Stale,
    NoSpace,
    Rights,
    Capacity,
    GenerationExhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Slot {
    entry: FdEntry,
    active: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FdBatch {
    handles: alloc::vec::Vec<u64>,
}

impl FdBatch {
    const fn empty() -> Self {
        Self {
            handles: alloc::vec::Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.handles.len()
    }

    pub fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }

    pub fn handles(&self) -> &[u64] {
        &self.handles
    }

}

/// Heap-backed Linux descriptor table.
///
/// Storage grows lazily to the descriptor number actually used. The runtime
/// soft/hard limits are supplied from the process resource budget and are the
/// only authority for allocation; there is no compile-time descriptor count.
///
/// 堆后备 Linux 描述符表。存储只按实际使用的描述符编号懒增长；容量唯一来源是
/// 进程资源预算产生的运行时软/硬上限，不再使用编译期固定描述符数组。
#[derive(Clone)]
pub struct FdTable {
    slots: alloc::vec::Vec<Option<Slot>>,
    generations: alloc::vec::Vec<u32>,
    /// One open-file description per fd slot. Duplicates and fork clones share
    /// the same cursor and status flags; closing one fd drops only its reference.
    open_files: alloc::vec::Vec<Option<Arc<SpinLock<OpenFileState>>>>,
    open: usize,
    soft_limit: usize,
    hard_limit: usize,
    next_free: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OpenFileState {
    offset: u64,
    status_flags: u32,
}

impl FdTable {
    pub fn new() -> Self {
        Self::with_limits(u32::MAX as usize, u32::MAX as usize)
    }

    pub fn with_limits(soft_limit: usize, hard_limit: usize) -> Self {
        let hard_limit = hard_limit.min(u32::MAX as usize);
        let soft_limit = soft_limit.min(hard_limit);
        Self {
            slots: alloc::vec::Vec::new(),
            generations: alloc::vec::Vec::new(),
            open_files: alloc::vec::Vec::new(),
            open: 0,
            soft_limit,
            hard_limit,
            next_free: 0,
        }
    }

    /// Derive a descriptor budget from a process byte budget.
    ///
    /// This estimates the table's metadata footprint. It is a policy input,
    /// not a claim that every descriptor consumes exactly this many bytes.
    /// 从进程字节预算推导 FD 上限；该估算只用于准入策略，不冒充精确内存记账。
    pub fn capacity_for_bytes(bytes: u64) -> u64 {
        let per_entry = core::mem::size_of::<Option<Slot>>()
            .saturating_add(core::mem::size_of::<u32>())
            .saturating_add(core::mem::size_of::<Option<Arc<SpinLock<OpenFileState>>>>())
            .max(1) as u64;
        (bytes / per_entry).clamp(STANDARD_FD_COUNT as u64, u64::from(u32::MAX))
    }

    pub fn soft_limit(&self) -> usize {
        self.soft_limit
    }

    pub fn hard_limit(&self) -> usize {
        self.hard_limit
    }

    pub fn allocated_capacity(&self) -> usize {
        self.slots.len()
    }

    pub fn set_limits(&mut self, soft_limit: usize, hard_limit: usize) -> bool {
        if hard_limit > u32::MAX as usize || soft_limit > hard_limit {
            return false;
        }
        self.hard_limit = hard_limit;
        self.soft_limit = soft_limit;
        true
    }

    pub const fn open_count(&self) -> usize {
        self.open
    }

    pub fn install(
        &mut self,
        handle: u64,
        rights: Rights,
        kind: CompatKind,
        close_on_exec: bool,
    ) -> Result<FdHandle, FdTableError> {
        self.install_at_or_above(0, handle, rights, kind, close_on_exec)
    }

    pub fn install_at(
        &mut self,
        fd: u32,
        handle: u64,
        rights: Rights,
        kind: CompatKind,
        close_on_exec: bool,
    ) -> Result<FdHandle, FdTableError> {
        let index = fd as usize;
        if index >= self.soft_limit {
            return Err(FdTableError::InvalidFd);
        }
        self.ensure_len(index + 1)?;
        if self.slots[index].is_some() {
            return Err(FdTableError::NoSpace);
        }
        self.install_slot(index, handle, rights, kind, close_on_exec)
    }

    pub fn duplicate(
        &mut self,
        source: FdHandle,
        min_fd: u32,
        close_on_exec: bool,
        rights: Option<Rights>,
    ) -> Result<FdHandle, FdTableError> {
        let entry = self.get(source)?;
        let rights = rights.unwrap_or(entry.rights);
        if !entry.rights.contains(rights) {
            return Err(FdTableError::Rights);
        }
        self.install_shared_at_or_above(source, min_fd, close_on_exec)
    }

    /// Duplicates the current generation of a descriptor by its numeric fd.
    ///
    /// 按当前数字描述符复制其有效世代；失效 fd 不会与复用后的新世代混淆。
    pub fn duplicate_fd(
        &mut self,
        source: u32,
        min_fd: u32,
        close_on_exec: bool,
    ) -> Result<FdHandle, FdTableError> {
        let entry = self.get_fd(source).ok_or(FdTableError::InvalidFd)?;
        self.duplicate(
            FdHandle {
                fd: source,
                generation: entry.generation,
            },
            min_fd,
            close_on_exec,
            None,
        )
    }

    /// Duplicates the current generation of `source` onto an exact descriptor.
    ///
    /// 把 `source` 当前世代精确复制到 `target`；目标已占用时原子替换。
    pub fn duplicate_fd_to(
        &mut self,
        source: u32,
        target: u32,
        close_on_exec: bool,
    ) -> Result<FdHandle, FdTableError> {
        let entry = self.get_fd(source).ok_or(FdTableError::InvalidFd)?;
        let index = target as usize;
        if index >= self.soft_limit {
            return Err(FdTableError::InvalidFd);
        }
        self.ensure_len(index + 1)?;
        let cursor = Arc::clone(
            self.open_files[source as usize]
                .as_ref()
                .ok_or(FdTableError::InvalidHandle)?,
        );
        let generation = self.generations[index]
            .checked_add(1)
            .ok_or(FdTableError::GenerationExhausted)?;
        self.generations[index] = generation;
        if !self.slots[index].is_some_and(|slot| slot.active) {
            self.open += 1;
        }
        self.open_files[index] = Some(cursor);
        self.slots[index] = Some(Slot {
            entry: FdEntry {
                fd: target,
                generation,
                handle: entry.handle,
                rights: entry.rights,
                kind: entry.kind,
                close_on_exec,
            },
            active: true,
        });
        self.advance_next_free(index);
        Ok(FdHandle {
            fd: target,
            generation,
        })
    }

    /// Returns the shared open-file cursor for the current fd generation.
    pub fn fd_offset(&self, fd: u32) -> Option<u64> {
        let entry = self.get_fd(fd)?;
        if entry.fd != fd {
            return None;
        }
        self.open_files[fd as usize]
            .as_ref()
            .map(|state| state.lock().offset)
    }

    /// Updates every fd sharing the current open-file description.
    pub fn set_fd_offset(&self, fd: u32, offset: u64) -> bool {
        let Some(entry) = self.get_fd(fd) else {
            return false;
        };
        if entry.fd != fd {
            return false;
        }
        let Some(description) = self.open_files[fd as usize].as_ref() else {
            return false;
        };
        description.lock().offset = offset;
        true
    }

    /// Returns a stable identity for the shared open-file description.
    pub fn description_identity(&self, fd: u32) -> Option<u64> {
        let entry = self.get_fd(fd)?;
        if entry.fd != fd {
            return None;
        }
        self.open_files[fd as usize]
            .as_ref()
            .map(|description| Arc::as_ptr(description) as usize as u64)
    }

    /// Counts descriptors sharing one open-file description.
    pub fn description_ref_count(&self, identity: u64) -> usize {
        self.open_files
            .iter()
            .flatten()
            .filter(|description| Arc::as_ptr(description) as usize as u64 == identity)
            .count()
    }

    /// Returns the shared Linux status flags for the current fd generation.
    pub fn fd_status_flags(&self, fd: u32) -> Option<u32> {
        let _ = self.get_fd(fd)?;
        self.open_files[fd as usize]
            .as_ref()
            .map(|state| state.lock().status_flags)
    }

    /// Captures one current descriptor and its shared open-file description
    /// for a controlled SCM_RIGHTS handoff.
    pub fn description_fd(&self, fd: u32) -> Option<FdDescription> {
        let entry = self.get_fd(fd)?;
        let open_file = self.open_files[fd as usize].as_ref()?;
        Some(FdDescription {
            entry,
            open_file: OpenFileRef(Arc::clone(open_file)),
        })
    }

    /// Installs a captured descriptor into a new fd generation while retaining
    /// the original open-file cursor and status flags.
    pub fn install_description(
        &mut self,
        description: FdDescription,
        close_on_exec: bool,
    ) -> Result<FdHandle, FdTableError> {
        self.install_description_at_or_above(description, 0, close_on_exec)
    }

    /// Sets shared Linux status flags for the current fd generation.
    pub fn set_fd_status_flags(&self, fd: u32, flags: u32) -> bool {
        if self.get_fd(fd).is_none() {
            return false;
        }
        let Some(description) = self.open_files[fd as usize].as_ref() else {
            return false;
        };
        description.lock().status_flags = flags;
        true
    }

    /// Counts live descriptors that still reference one synthetic object handle.
    pub fn handle_fd_count(&self, handle: u64) -> usize {
        self.slots
            .iter()
            .flatten()
            .filter(|slot| slot.active && slot.entry.handle == handle)
            .count()
    }

    pub fn get(&self, handle: FdHandle) -> Result<FdEntry, FdTableError> {
        let index = handle.fd as usize;
        let Some(slot) = self.slots.get(index).and_then(|slot| *slot) else {
            return Err(FdTableError::InvalidHandle);
        };
        if !slot.active || slot.entry.generation != handle.generation {
            return Err(FdTableError::Stale);
        }
        Ok(slot.entry)
    }

    pub fn get_fd(&self, fd: u32) -> Option<FdEntry> {
        let slot = self.slots.get(fd as usize)?.as_ref()?;
        slot.active.then_some(slot.entry)
    }

    pub fn set_close_on_exec(
        &mut self,
        handle: FdHandle,
        enabled: bool,
    ) -> Result<(), FdTableError> {
        let index = handle.fd as usize;
        let slot = self
            .slots
            .get_mut(index)
            .and_then(|slot| slot.as_mut())
            .ok_or(FdTableError::InvalidHandle)?;
        if !slot.active || slot.entry.generation != handle.generation {
            return Err(FdTableError::Stale);
        }
        slot.entry.close_on_exec = enabled;
        Ok(())
    }

    /// Updates close-on-exec by descriptor and current generation.
    ///
    /// 按 fd 当前世代更新 close-on-exec；陈旧或关闭的 fd 不会被误改。
    pub fn set_close_on_exec_fd(
        &mut self,
        fd: u32,
        enabled: bool,
    ) -> Result<(), FdTableError> {
        let entry = self.get_fd(fd).ok_or(FdTableError::InvalidFd)?;
        self.set_close_on_exec(
            FdHandle {
                fd,
                generation: entry.generation,
            },
            enabled,
        )
    }

    pub fn close(&mut self, handle: FdHandle) -> Result<u64, FdTableError> {
        let entry = self.get(handle)?;
        let slot = self.slots[handle.fd as usize]
            .as_mut()
            .ok_or(FdTableError::InvalidHandle)?;
        slot.active = false;
        self.open_files[handle.fd as usize] = None;
        self.open -= 1;
        self.next_free = self.next_free.min(handle.fd as usize);
        Ok(entry.handle)
    }

    pub fn close_fd(&mut self, fd: u32) -> Result<u64, FdTableError> {
        let entry = self.get_fd(fd).ok_or(FdTableError::InvalidFd)?;
        self.close(FdHandle {
            fd,
            generation: entry.generation,
        })
    }

    pub fn take_close_on_exec(&mut self) -> Result<FdBatch, FdTableError> {
        let mut batch = FdBatch::empty();
        batch
            .handles
            .try_reserve(self.open)
            .map_err(|_| FdTableError::Capacity)?;
        for index in 0..self.slots.len() {
            let close = self.slots[index]
                .as_ref()
                .is_some_and(|slot| slot.active && slot.entry.close_on_exec);
            if close {
                let handle = self.slots[index]
                    .as_ref()
                    .map(|slot| slot.entry.handle)
                    .unwrap_or(0);
                self.slots[index].as_mut().unwrap().active = false;
                self.open_files[index] = None;
                self.open -= 1;
                batch.handles.push(handle);
            }
        }
        self.next_free = 0;
        Ok(batch)
    }

    pub fn take_all(&mut self) -> Result<FdBatch, FdTableError> {
        let mut batch = FdBatch::empty();
        batch
            .handles
            .try_reserve(self.open)
            .map_err(|_| FdTableError::Capacity)?;
        for index in 0..self.slots.len() {
            let close = self.slots[index].as_ref().is_some_and(|slot| slot.active);
            if close {
                let handle = self.slots[index]
                    .as_ref()
                    .map(|slot| slot.entry.handle)
                    .unwrap_or(0);
                self.slots[index].as_mut().unwrap().active = false;
                self.open_files[index] = None;
                self.open -= 1;
                batch.handles.push(handle);
            }
        }
        self.next_free = 0;
        Ok(batch)
    }

    fn install_at_or_above(
        &mut self,
        min_fd: u32,
        handle: u64,
        rights: Rights,
        kind: CompatKind,
        close_on_exec: bool,
    ) -> Result<FdHandle, FdTableError> {
        if handle == 0 {
            return Err(FdTableError::InvalidHandle);
        }
        let start = min_fd as usize;
        if start >= self.soft_limit {
            return Err(FdTableError::NoSpace);
        }
        let index = self.find_free_at_or_above(start)?;
        self.install_slot(index, handle, rights, kind, close_on_exec)
    }

    fn install_shared_at_or_above(
        &mut self,
        source: FdHandle,
        min_fd: u32,
        close_on_exec: bool,
    ) -> Result<FdHandle, FdTableError> {
        let entry = self.get(source)?;
        let start = min_fd as usize;
        if start >= self.soft_limit {
            return Err(FdTableError::NoSpace);
        }
        let index = self.find_free_at_or_above(start)?;
        let generation = self.generations[index]
            .checked_add(1)
            .ok_or(FdTableError::GenerationExhausted)?;
        let cursor = Arc::clone(
            self.open_files[source.fd as usize]
                .as_ref()
                .ok_or(FdTableError::InvalidHandle)?,
        );
        self.generations[index] = generation;
        self.open_files[index] = Some(cursor);
        self.slots[index] = Some(Slot {
            entry: FdEntry {
                fd: index as u32,
                generation,
                handle: entry.handle,
                rights: entry.rights,
                kind: entry.kind,
                close_on_exec,
            },
            active: true,
        });
        self.open += 1;
        self.advance_next_free(index);
        Ok(FdHandle {
            fd: index as u32,
            generation,
        })
    }

    fn install_description_at_or_above(
        &mut self,
        description: FdDescription,
        min_fd: u32,
        close_on_exec: bool,
    ) -> Result<FdHandle, FdTableError> {
        let entry = description.entry;
        if entry.handle == 0 {
            return Err(FdTableError::InvalidHandle);
        }
        let start = min_fd as usize;
        if start >= self.soft_limit {
            return Err(FdTableError::NoSpace);
        }
        let index = self.find_free_at_or_above(start)?;
        let generation = self.generations[index]
            .checked_add(1)
            .ok_or(FdTableError::GenerationExhausted)?;
        self.generations[index] = generation;
        self.open_files[index] = Some(Arc::clone(&(description.open_file).0));
        self.slots[index] = Some(Slot {
            entry: FdEntry {
                fd: index as u32,
                generation,
                handle: entry.handle,
                rights: entry.rights,
                kind: entry.kind,
                close_on_exec,
            },
            active: true,
        });
        self.open += 1;
        self.advance_next_free(index);
        Ok(FdHandle {
            fd: index as u32,
            generation,
        })
    }

    fn install_slot(
        &mut self,
        index: usize,
        handle: u64,
        rights: Rights,
        kind: CompatKind,
        close_on_exec: bool,
    ) -> Result<FdHandle, FdTableError> {
        if handle == 0 {
            return Err(FdTableError::InvalidHandle);
        }
        let generation = self.generations[index]
            .checked_add(1)
            .ok_or(FdTableError::GenerationExhausted)?;
        self.generations[index] = generation;
        self.open_files[index] = Some(Arc::new(SpinLock::new(OpenFileState {
            offset: 0,
            status_flags: 0,
        })));
        self.slots[index] = Some(Slot {
            entry: FdEntry {
                fd: index as u32,
                generation,
                handle,
                rights,
                kind,
                close_on_exec,
            },
            active: true,
        });
        self.open += 1;
        self.advance_next_free(index);
        Ok(FdHandle {
            fd: index as u32,
            generation,
        })
    }

    fn ensure_len(&mut self, target: usize) -> Result<(), FdTableError> {
        if target > self.hard_limit {
            return Err(FdTableError::InvalidFd);
        }
        if target <= self.slots.len() {
            return Ok(());
        }
        let doubled = self.slots.len().saturating_mul(2).max(1);
        let new_len = target.max(doubled).min(self.hard_limit);
        let additional = new_len - self.slots.len();
        self.slots
            .try_reserve(additional)
            .map_err(|_| FdTableError::Capacity)?;
        self.generations
            .try_reserve(additional)
            .map_err(|_| FdTableError::Capacity)?;
        self.open_files
            .try_reserve(additional)
            .map_err(|_| FdTableError::Capacity)?;
        self.slots.resize(new_len, None);
        self.generations.resize(new_len, 0);
        self.open_files.resize(new_len, None);
        Ok(())
    }

    fn find_free_at_or_above(&mut self, min_fd: usize) -> Result<usize, FdTableError> {
        let mut index = min_fd.max(self.next_free);
        while index < self.soft_limit {
            self.ensure_len(index + 1)?;
            if self.slots[index].is_none_or(|slot| !slot.active) {
                return Ok(index);
            }
            index += 1;
        }
        Err(FdTableError::NoSpace)
    }

    fn advance_next_free(&mut self, installed: usize) {
        if installed != self.next_free {
            return;
        }
        while self
            .slots
            .get(self.next_free)
            .is_some_and(|slot| slot.is_some_and(|slot| slot.active))
        {
            self.next_free += 1;
        }
    }
}

impl Default for FdTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_install_duplicate_close_and_stale_generation() {
        let mut fds = FdTable::new();
        for fd in 0..3 {
            fds.install_at(
                fd,
                0x100 + u64::from(fd),
                Rights::READ.union(Rights::WRITE),
                CompatKind::File,
                false,
            )
            .unwrap();
        }
        let new = fds
            .install(0x200, Rights::READ, CompatKind::Socket, true)
            .unwrap();
        assert_eq!(new.fd(), 3);
        let copy = fds.duplicate(new, 10, false, Some(Rights::READ)).unwrap();
        assert_eq!(copy.fd(), 10);
        assert_eq!(fds.close(copy), Ok(0x200));
        let replacement = fds
            .install_at_or_above(10, 0x300, Rights::READ, CompatKind::File, false)
            .unwrap();
        assert_eq!(replacement.fd(), 10);
        assert_eq!(fds.get(copy), Err(FdTableError::Stale));
        assert_eq!(fds.get(replacement).unwrap().handle, 0x300);
        fds.set_close_on_exec_fd(replacement.fd(), true)
            .unwrap();
        assert!(fds.get_fd(replacement.fd()).unwrap().close_on_exec);
        assert_eq!(
            fds.set_close_on_exec_fd(63, true),
            Err(FdTableError::InvalidFd)
        );
    }

    #[test]
    fn cloexec_and_exit_close_only_owned_handles() {
        let mut fds = FdTable::new();
        let a = fds
            .install(1, Rights::READ, CompatKind::File, true)
            .unwrap();
        let b = fds
            .install(2, Rights::READ, CompatKind::Pipe, false)
            .unwrap();
        let closed = fds.take_close_on_exec().unwrap();
        assert_eq!(closed.handles(), &[1]);
        assert_eq!(fds.get(a), Err(FdTableError::Stale));
        assert!(fds.get(b).is_ok());
        assert_eq!(fds.take_all().unwrap().handles(), &[2]);
        assert_eq!(fds.open_count(), 0);
    }

    #[test]
    fn duplicate_cannot_escalate_rights() {
        let mut fds = FdTable::new();
        let fd = fds
            .install(1, Rights::READ, CompatKind::File, false)
            .unwrap();
        assert_eq!(
            fds.duplicate(
                fd,
                1,
                false,
                Some(Rights::READ.union(Rights::WRITE)),
            ),
            Err(FdTableError::Rights)
        );
        assert_eq!(fds.open_count(), 1);
    }

    #[test]
    fn duplicate_fd_uses_the_current_generation_and_minimum() {
        let mut fds = FdTable::new();
        let source = fds
            .install_at(
                2,
                0x55,
                Rights::READ,
                CompatKind::Directory,
                false,
            )
            .unwrap();
        let duplicate = fds.duplicate_fd(2, 4, true).unwrap();
        assert_eq!(duplicate.fd(), 4);
        assert_eq!(fds.get(duplicate).unwrap().handle, 0x55);
        assert!(fds.get(duplicate).unwrap().close_on_exec);
        assert_eq!(fds.close_fd(2), Ok(0x55));
        assert_eq!(fds.duplicate_fd(2, 0, false), Err(FdTableError::InvalidFd));
        let replacement = fds
            .install_at_or_above(2, 0x66, Rights::READ, CompatKind::File, false)
            .unwrap();
        assert_eq!(replacement.fd(), 2);
        assert_ne!(replacement.generation(), source.generation());
        assert_eq!(fds.get(duplicate).unwrap().handle, 0x55);
    }

    #[test]
    fn duplicate_to_replaces_target_and_preserves_open_count() {
        let mut fds = FdTable::with_limits(8, 8);
        fds.install_at(1, 0x11, Rights::READ, CompatKind::File, false)
            .unwrap();
        fds.install_at(5, 0x55, Rights::WRITE, CompatKind::File, true)
            .unwrap();
        let duplicate = fds.duplicate_fd_to(1, 5, false).unwrap();
        assert_eq!(duplicate.fd(), 5);
        assert_eq!(fds.open_count(), 2);
        let entry = fds.get(duplicate).unwrap();
        assert_eq!(entry.handle, 0x11);
        assert_eq!(entry.rights, Rights::READ);
        assert!(!entry.close_on_exec);
        assert_eq!(fds.duplicate_fd_to(1, 8, false), Err(FdTableError::InvalidFd));
        assert_eq!(fds.duplicate_fd_to(7, 4, false), Err(FdTableError::InvalidFd));
        assert_eq!(fds.open_count(), 2);
    }

    #[test]
    fn duplicate_and_fork_clone_share_open_file_offset() {
        let mut parent = FdTable::new();
        let source = parent
            .install(0x11, Rights::READ, CompatKind::File, false)
            .unwrap();
        let duplicate = parent.duplicate(source, 0, false, None).unwrap();
        assert!(parent.set_fd_offset(source.fd(), 17));
        assert_eq!(parent.fd_offset(duplicate.fd()), Some(17));

        let child = parent.clone();
        assert!(child.set_fd_offset(duplicate.fd(), 29));
        assert_eq!(parent.fd_offset(source.fd()), Some(29));
        assert_eq!(
            parent.close_fd(source.fd()),
            Ok(0x11),
            "closing one fd must not destroy the shared description"
        );
        assert_eq!(child.fd_offset(duplicate.fd()), Some(29));
    }

    #[test]
    fn captured_description_survives_source_close_and_preserves_cursor() {
        let mut fds = FdTable::new();
        let source = fds
            .install(
                0x88,
                Rights::READ.union(Rights::WRITE),
                CompatKind::File,
                false,
            )
            .unwrap();
        let captured = fds.description_fd(source.fd()).unwrap();
        fds.close(source).unwrap();
        assert!(fds.get_fd(source.fd()).is_none());

        captured.set_offset(37);
        assert_eq!(captured.offset(), 37);
        let reinstalled = fds.install_description(captured, false).unwrap();
        assert_eq!(fds.fd_offset(reinstalled.fd()), Some(37));
        assert_eq!(fds.get(reinstalled).unwrap().handle, 0x88);
    }

    #[test]
    fn separate_opens_of_same_handle_have_independent_descriptions() {
        let mut fds = FdTable::new();
        let first = fds
            .install(0x11, Rights::READ, CompatKind::File, false)
            .unwrap();
        let second = fds
            .install(0x11, Rights::READ, CompatKind::File, false)
            .unwrap();
        assert!(fds.set_fd_offset(first.fd(), 5));
        assert_eq!(fds.fd_offset(second.fd()), Some(0));
        assert!(fds.set_fd_offset(second.fd(), 9));
        assert_eq!(fds.fd_offset(first.fd()), Some(5));
    }

    #[test]
    fn status_flags_follow_shared_open_file_description() {
        let mut parent = FdTable::new();
        let source = parent
            .install(0x11, Rights::READ, CompatKind::Pipe, false)
            .unwrap();
        let duplicate = parent.duplicate(source, 0, false, None).unwrap();
        assert!(parent.set_fd_status_flags(source.fd(), 0x800));
        let child = parent.clone();
        assert_eq!(child.fd_status_flags(duplicate.fd()), Some(0x800));

        let independent = child
            .fd_offset(source.fd())
            .map(|_| child.get_fd(source.fd()).unwrap())
            .unwrap();
        assert_eq!(independent.handle, 0x11);
        let mut other = FdTable::new();
        let other_fd = other
            .install(0x11, Rights::READ, CompatKind::Pipe, false)
            .unwrap();
        assert_eq!(other.fd_status_flags(other_fd.fd()), Some(0));
    }

    #[test]
    fn controlled_transfer_preserves_the_open_file_description() {
        let mut source = FdTable::new();
        let fd = source
            .install(
                0x500,
                Rights::READ.union(Rights::WRITE),
                CompatKind::Pipe,
                false,
            )
            .unwrap();
        assert!(source.set_fd_offset(fd.fd(), 37));
        assert!(source.set_fd_status_flags(fd.fd(), 0x800));
        let description = source.description_fd(fd.fd()).unwrap();
        assert!(source.close(fd).is_ok());

        let mut receiver = FdTable::new();
        let second_receiver = description.clone();
        let received = receiver.install_description(description, true).unwrap();
        assert_eq!(receiver.fd_offset(received.fd()), Some(37));
        assert_eq!(receiver.fd_status_flags(received.fd()), Some(0x800));
        assert!(receiver.get(received).unwrap().close_on_exec);
        assert!(receiver.set_fd_offset(received.fd(), 91));
        let mut other_receiver = FdTable::new();
        let other = other_receiver
            .install_description(second_receiver, false)
            .unwrap();
        assert_eq!(other_receiver.fd_offset(other.fd()), Some(91));
    }

    #[test]
    fn close_reuses_the_lowest_available_descriptor() {
        let mut fds = FdTable::with_limits(8, 8);
        let first = fds
            .install_at(0, 1, Rights::READ, CompatKind::File, false)
            .unwrap();
        fds.install_at(1, 2, Rights::READ, CompatKind::File, false)
            .unwrap();
        assert_eq!(fds.close(first), Ok(1));
        assert_eq!(
            fds.install(3, Rights::READ, CompatKind::File, false)
                .unwrap()
                .fd(),
            0
        );
    }

    #[test]
    fn runtime_budget_allows_high_descriptors_without_fixed_array() {
        let mut fds = FdTable::with_limits(4096, 4096);
        let high = fds
            .install_at(2048, 0x900, Rights::READ, CompatKind::File, false)
            .unwrap();
        assert_eq!(high.fd(), 2048);
        assert!(fds.allocated_capacity() >= 2049);
        assert_eq!(fds.close(high), Ok(0x900));
        let replacement = fds
            .install_at_or_above(2048, 0x901, Rights::READ, CompatKind::File, false)
            .unwrap();
        assert_eq!(replacement.fd(), 2048);
        assert_ne!(replacement.generation(), high.generation());
    }

    #[test]
    fn descriptor_budget_rejects_above_runtime_limit_and_grows_from_metadata() {
        let mut fds = FdTable::with_limits(1024, 2048);
        assert_eq!(
            fds.install_at(1024, 1, Rights::READ, CompatKind::File, false),
            Err(FdTableError::InvalidFd)
        );
        assert!(fds.set_limits(2048, 2048));
        assert!(
            fds.install_at(1536, 1, Rights::READ, CompatKind::File, false)
                .is_ok()
        );
        assert!(FdTable::capacity_for_bytes(4096) >= 3);
        assert!(FdTable::capacity_for_bytes(u64::MAX) <= u32::MAX as u64);
    }
}
