//! Linux pid/tid/tgid identities mapped to Jasper process and task objects.

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct LinuxPid(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessToken {
    pub pid: LinuxPid,
    pub generation: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessEntry {
    pub pid: LinuxPid,
    pub tid: LinuxPid,
    pub tgid: LinuxPid,
    pub object: u64,
    pub generation: u32,
    pub active: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessTableError {
    InvalidObject,
    Stale,
    NoSpace,
    NoSuchThread,
    NoSuchLeader,
    IdExhausted,
}

pub struct ProcessTable<const N: usize> {
    entries: [Option<ProcessEntry>; N],
    next_id: u32,
}

impl<const N: usize> ProcessTable<N> {
    pub const fn new() -> Self {
        Self {
            entries: [None; N],
            next_id: 1,
        }
    }

    pub fn create_process(&mut self, object: u64) -> Result<ProcessToken, ProcessTableError> {
        if object == 0 {
            return Err(ProcessTableError::InvalidObject);
        }
        let id = self.allocate_id()?;
        let entry = ProcessEntry {
            pid: id,
            tid: id,
            tgid: id,
            object,
            generation: 1,
            active: true,
        };
        self.insert(entry)?;
        Ok(ProcessToken {
            pid: id,
            generation: 1,
        })
    }

    pub fn create_thread(
        &mut self,
        tgid: LinuxPid,
        leader_generation: u32,
        object: u64,
    ) -> Result<ProcessToken, ProcessTableError> {
        if object == 0 {
            return Err(ProcessTableError::InvalidObject);
        }
        let leader = self.find_pid(tgid).ok_or(ProcessTableError::NoSuchLeader)?;
        if !leader.active || leader.generation != leader_generation || leader.pid != leader.tgid {
            return Err(ProcessTableError::Stale);
        }
        let id = self.allocate_id()?;
        let entry = ProcessEntry {
            pid: id,
            tid: id,
            tgid,
            object,
            generation: 1,
            active: true,
        };
        self.insert(entry)?;
        Ok(ProcessToken {
            pid: id,
            generation: 1,
        })
    }

    pub fn find(&self, token: ProcessToken) -> Result<ProcessEntry, ProcessTableError> {
        let entry = self
            .find_pid(token.pid)
            .ok_or(ProcessTableError::NoSuchThread)?;
        if !entry.active || entry.generation != token.generation {
            return Err(ProcessTableError::Stale);
        }
        Ok(entry)
    }

    pub fn getpid(&self, token: ProcessToken) -> Result<LinuxPid, ProcessTableError> {
        Ok(self.find(token)?.tgid)
    }

    pub fn gettid(&self, token: ProcessToken) -> Result<LinuxPid, ProcessTableError> {
        Ok(self.find(token)?.tid)
    }

    pub fn exit_thread(&mut self, token: ProcessToken) -> Result<u64, ProcessTableError> {
        let mut entry = self.find(token)?;
        if entry.pid == entry.tgid {
            return self.exit_group(token);
        }
        entry.active = false;
        let slot = self
            .slot(token.pid)
            .ok_or(ProcessTableError::NoSuchThread)?;
        self.entries[slot] = Some(entry);
        Ok(entry.object)
    }

    pub fn exit_group(&mut self, token: ProcessToken) -> Result<u64, ProcessTableError> {
        let leader = self.find(token)?;
        let tgid = leader.tgid;
        let mut leader_object = None;
        for entry in self.entries.iter_mut().flatten() {
            if entry.active && entry.tgid == tgid {
                if entry.pid == entry.tgid {
                    leader_object = Some(entry.object);
                }
                entry.active = false;
            }
        }
        leader_object.ok_or(ProcessTableError::NoSuchLeader)
    }

    pub fn active_threads(&self, tgid: LinuxPid) -> usize {
        self.entries
            .iter()
            .flatten()
            .filter(|entry| entry.active && entry.tgid == tgid)
            .count()
    }

    fn allocate_id(&mut self) -> Result<LinuxPid, ProcessTableError> {
        let id = self.next_id;
        if id == 0 || id == u32::MAX {
            return Err(ProcessTableError::IdExhausted);
        }
        self.next_id = id + 1;
        Ok(LinuxPid(id))
    }

    fn insert(&mut self, entry: ProcessEntry) -> Result<(), ProcessTableError> {
        let slot = self
            .entries
            .iter_mut()
            .find(|entry| entry.is_none_or(|entry| !entry.active))
            .ok_or(ProcessTableError::NoSpace)?;
        *slot = Some(entry);
        Ok(())
    }

    fn find_pid(&self, pid: LinuxPid) -> Option<ProcessEntry> {
        self.entries
            .iter()
            .flatten()
            .find(|entry| entry.active && entry.pid == pid)
            .copied()
    }

    fn slot(&self, pid: LinuxPid) -> Option<usize> {
        self.entries
            .iter()
            .position(|entry| entry.is_some_and(|entry| entry.pid == pid))
    }
}

impl<const N: usize> Default for ProcessTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_thread_and_group_exit_identity() {
        let mut processes = ProcessTable::<8>::new();
        let leader = processes.create_process(0x100).unwrap();
        let thread = processes
            .create_thread(leader.pid, leader.generation, 0x101)
            .unwrap();
        assert_eq!(processes.getpid(thread), Ok(leader.pid));
        assert_eq!(processes.gettid(thread), Ok(thread.pid));
        assert_ne!(leader.pid, thread.pid);
        assert_eq!(processes.active_threads(leader.pid), 2);
        assert_eq!(processes.exit_thread(thread), Ok(0x101));
        assert_eq!(processes.find(thread), Err(ProcessTableError::NoSuchThread));
        assert_eq!(processes.active_threads(leader.pid), 1);
        assert_eq!(processes.exit_group(leader), Ok(0x100));
        assert_eq!(processes.active_threads(leader.pid), 0);
    }

    #[test]
    fn stale_leader_and_stale_token_are_rejected() {
        let mut processes = ProcessTable::<4>::new();
        let leader = processes.create_process(1).unwrap();
        assert_eq!(
            processes.create_thread(leader.pid, leader.generation + 1, 2),
            Err(ProcessTableError::Stale)
        );
        assert_eq!(
            processes.find(ProcessToken {
                pid: leader.pid,
                generation: leader.generation + 1,
            }),
            Err(ProcessTableError::Stale)
        );
    }
}
