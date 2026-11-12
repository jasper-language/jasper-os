//! Linux file descriptor table mapped to Jasper handles and rights.

use alloc::sync::Arc;
use kernel_core::object::Rights;
use kernel_core::sync::Atomic64;

pub const MAX_FDS: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompatKind {
    File,
    Directory,
    Socket,
    Pipe,
    Event,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FdBatch<const N: usize> {
    handles: [u64; N],
    len: usize,
}

impl<const N: usize> FdBatch<N> {
    const fn empty() -> Self {
        Self {
            handles: [0; N],
            len: 0,
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn handles(&self) -> &[u64] {
        &self.handles[..self.len]
    }
}

#[derive(Clone)]
pub struct FdTable<const N: usize = MAX_FDS> {
    slots: [Option<Slot>; N],
    generations: [u32; N],
    /// One open-file description per fd slot. Duplicates and fork clones share
    /// the same atomic cursor; replacing or closing an fd drops only its reference.
    open_files: [Option<Arc<Atomic64>>; N],
    open: usize,
}

impl<const N: usize> FdTable<N> {
    pub const fn new() -> Self {
        Self {
            slots: [None; N],
            generations: [0; N],
            open_files: [const { None }; N],
            open: 0,
        }
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
        if index >= N {
            return Err(FdTableError::InvalidFd);
        }
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
        if index >= N {
            return Err(FdTableError::InvalidFd);
        }
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
            .map(|offset| offset.load(core::sync::atomic::Ordering::Acquire))
    }

    /// Updates every fd sharing the current open-file description.
    pub fn set_fd_offset(&self, fd: u32, offset: u64) -> bool {
        let Some(entry) = self.get_fd(fd) else {
            return false;
        };
        if entry.fd != fd {
            return false;
        }
        let Some(cursor) = self.open_files[fd as usize].as_ref() else {
            return false;
        };
        cursor.store(offset, core::sync::atomic::Ordering::Release);
        true
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
        Ok(entry.handle)
    }

    pub fn close_fd(&mut self, fd: u32) -> Result<u64, FdTableError> {
        let entry = self.get_fd(fd).ok_or(FdTableError::InvalidFd)?;
        self.close(FdHandle {
            fd,
            generation: entry.generation,
        })
    }

    pub fn take_close_on_exec(&mut self) -> FdBatch<N> {
        let mut batch = FdBatch::empty();
        for index in 0..N {
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
                batch.handles[batch.len] = handle;
                batch.len += 1;
            }
        }
        batch
    }

    pub fn take_all(&mut self) -> FdBatch<N> {
        let mut batch = FdBatch::empty();
        for index in 0..N {
            let close = self.slots[index].as_ref().is_some_and(|slot| slot.active);
            if close {
                let handle = self.slots[index]
                    .as_ref()
                    .map(|slot| slot.entry.handle)
                    .unwrap_or(0);
                self.slots[index].as_mut().unwrap().active = false;
                self.open_files[index] = None;
                self.open -= 1;
                batch.handles[batch.len] = handle;
                batch.len += 1;
            }
        }
        batch
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
        if start >= N {
            return Err(FdTableError::NoSpace);
        }
        let index = (start..N)
            .find(|&index| self.slots[index].is_none_or(|slot| !slot.active))
            .ok_or(FdTableError::NoSpace)?;
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
        if start >= N {
            return Err(FdTableError::NoSpace);
        }
        let index = (start..N)
            .find(|&index| self.slots[index].is_none_or(|slot| !slot.active))
            .ok_or(FdTableError::NoSpace)?;
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
        self.open_files[index] = Some(Arc::new(Atomic64::new(0)));
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
        Ok(FdHandle {
            fd: index as u32,
            generation,
        })
    }
}

impl<const N: usize> Default for FdTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_install_duplicate_close_and_stale_generation() {
        let mut fds = FdTable::<16>::new();
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
        let mut fds = FdTable::<8>::new();
        let a = fds
            .install(1, Rights::READ, CompatKind::File, true)
            .unwrap();
        let b = fds
            .install(2, Rights::READ, CompatKind::Pipe, false)
            .unwrap();
        let closed = fds.take_close_on_exec();
        assert_eq!(closed.handles(), &[1]);
        assert_eq!(fds.get(a), Err(FdTableError::Stale));
        assert!(fds.get(b).is_ok());
        assert_eq!(fds.take_all().handles(), &[2]);
        assert_eq!(fds.open_count(), 0);
    }

    #[test]
    fn duplicate_cannot_escalate_rights() {
        let mut fds = FdTable::<4>::new();
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
        let mut fds = FdTable::<8>::new();
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
        let mut fds = FdTable::<8>::new();
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
        let mut parent = FdTable::<8>::new();
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
    fn separate_opens_of_same_handle_have_independent_descriptions() {
        let mut fds = FdTable::<8>::new();
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
}
