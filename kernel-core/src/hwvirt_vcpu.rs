//! Vendor-neutral HWV-1 vCPU state and second-level address-space contracts.
//!
//! This module does not enter VMX/SVM. It freezes the state machine, guest
//! physical mapping rules and invalidation semantics consumed by the VMX/SVM
//! backends in HWV-2/HWV-3.

use crate::hwvirt::Backend;

pub const MAX_GUEST_MAPPINGS: usize = 64;
pub const MAX_GPA: u64 = 1 << 48;

/// Saved architectural state. Backend-specific fields may use `extended`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VcpuState {
    pub registers: [u64; 32],
    pub rip: u64,
    pub rflags: u64,
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub xcr0: u64,
    pub extended: [u64; 32],
}

impl VcpuState {
    pub const fn initial() -> Self {
        let mut registers = [0u64; 32];
        registers[18] = 2; // Architectural RFLAGS.RES1.
        Self {
            registers,
            rip: 0,
            rflags: 2,
            cr0: 0,
            cr3: 0,
            cr4: 0,
            xcr0: 1,
            extended: [0; 32],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lifecycle {
    Offline,
    Ready,
    Running,
    Halted,
    Failed,
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateError {
    InvalidTransition,
    Closed,
    Running,
}

#[derive(Clone, Copy, Debug)]
pub struct VcpuLifecycle {
    backend: Backend,
    status: Lifecycle,
    state: VcpuState,
}

impl VcpuLifecycle {
    pub const fn new(backend: Backend) -> Self {
        Self { backend, status: Lifecycle::Offline, state: VcpuState::initial() }
    }

    pub const fn backend(&self) -> Backend {
        self.backend
    }

    pub const fn status(&self) -> Lifecycle {
        self.status
    }

    pub const fn state(&self) -> VcpuState {
        self.state
    }

    pub fn make_ready(&mut self) -> Result<(), StateError> {
        match self.status {
            Lifecycle::Offline => {
                self.status = Lifecycle::Ready;
                Ok(())
            }
            Lifecycle::Closed => Err(StateError::Closed),
            _ => Err(StateError::InvalidTransition),
        }
    }

    /// HWV-2/HWV-3 may call this immediately before a real VM Entry.
    pub fn begin_run(&mut self) -> Result<(), StateError> {
        match self.status {
            Lifecycle::Ready => {
                self.status = Lifecycle::Running;
                Ok(())
            }
            Lifecycle::Closed => Err(StateError::Closed),
            _ => Err(StateError::InvalidTransition),
        }
    }

    /// Save complete state only at a stable boundary. It is never legal while
    /// the vCPU is running on hardware.
    pub fn save(&mut self, state: VcpuState) -> Result<(), StateError> {
        match self.status {
            Lifecycle::Closed => Err(StateError::Closed),
            Lifecycle::Running => Err(StateError::Running),
            _ => {
                self.state = state;
                Ok(())
            }
        }
    }

    pub fn halt(&mut self) -> Result<(), StateError> {
        match self.status {
            Lifecycle::Running | Lifecycle::Ready => {
                self.status = Lifecycle::Halted;
                Ok(())
            }
            Lifecycle::Closed => Err(StateError::Closed),
            _ => Err(StateError::InvalidTransition),
        }
    }

    pub fn fail(&mut self) {
        if self.status != Lifecycle::Closed {
            self.status = Lifecycle::Failed;
        }
    }

    pub fn close(&mut self) {
        self.status = Lifecycle::Closed;
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GuestPermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl GuestPermissions {
    pub const READ: Self = Self { read: true, write: false, execute: false };
    pub const READ_WRITE: Self = Self { read: true, write: true, execute: false };
    pub const READ_EXECUTE: Self = Self { read: true, write: false, execute: true };
    pub const ALL: Self = Self { read: true, write: true, execute: true };
}

/// One guest-physical mapping. `memory_id` and `memory_offset` refer to a
/// pinned Memory object; this value carries no ownership itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestMapping {
    pub guest_start: u64,
    pub pages: u64,
    pub memory_id: u64,
    pub memory_offset: u64,
    pub permissions: GuestPermissions,
}

impl GuestMapping {
    pub fn guest_end(self) -> u64 {
        self.guest_start + self.pages * 4096
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapError {
    ZeroPages,
    Misaligned,
    Overflow,
    OutsideGuestWindow,
    OutsideMemory,
    Permissions,
    Overlap,
    Full,
    NotFound,
}

/// Fixed-capacity, non-overlapping GPA map. Slot identity is stable and the
/// kernel uses the same slot to hold/release its Memory internal reference.
#[derive(Clone, Copy, Debug)]
pub struct GuestMap<const N: usize> {
    entries: [Option<GuestMapping>; N],
}

impl<const N: usize> GuestMap<N> {
    pub const fn new() -> Self {
        Self { entries: [None; N] }
    }

    pub fn len(&self) -> usize {
        self.entries.iter().flatten().count()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.iter().all(Option::is_none)
    }

    pub fn get(&self, slot: usize) -> Option<GuestMapping> {
        self.entries.get(slot).copied().flatten()
    }

    pub fn iter(&self) -> impl Iterator<Item = (usize, GuestMapping)> + '_ {
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(slot, entry)| entry.map(|mapping| (slot, mapping)))
    }

    /// Validate a prospective mapping without changing the map. This lets the
    /// kernel build hardware paging structures before publishing metadata.
    pub fn validate(
        &self,
        guest_start: u64,
        pages: u64,
        memory_offset: u64,
        memory_pages: u64,
        permissions: GuestPermissions,
    ) -> Result<(), MapError> {
        if pages == 0 {
            return Err(MapError::ZeroPages);
        }
        if guest_start % 4096 != 0 || memory_offset % 4096 != 0 {
            return Err(MapError::Misaligned);
        }
        if !permissions.read {
            return Err(MapError::Permissions);
        }
        let guest_bytes = pages.checked_mul(4096).ok_or(MapError::Overflow)?;
        let guest_end = guest_start.checked_add(guest_bytes).ok_or(MapError::Overflow)?;
        if guest_end > MAX_GPA {
            return Err(MapError::OutsideGuestWindow);
        }
        if memory_offset
            .checked_add(guest_bytes)
            .filter(|&end| end <= memory_pages.saturating_mul(4096))
            .is_none()
        {
            return Err(MapError::OutsideMemory);
        }
        for (_, existing) in self.iter() {
            if guest_start < existing.guest_end() && existing.guest_start < guest_end {
                return Err(MapError::Overlap);
            }
        }
        self.entries.iter().position(Option::is_none).ok_or(MapError::Full)?;
        Ok(())
    }

    pub fn map(
        &mut self,
        guest_start: u64,
        pages: u64,
        memory_id: u64,
        memory_offset: u64,
        memory_pages: u64,
        permissions: GuestPermissions,
    ) -> Result<usize, MapError> {
        self.validate(guest_start, pages, memory_offset, memory_pages, permissions)?;
        let slot = self.entries.iter().position(Option::is_none).ok_or(MapError::Full)?;
        self.entries[slot] = Some(GuestMapping {
            guest_start,
            pages,
            memory_id,
            memory_offset,
            permissions,
        });
        Ok(slot)
    }

    pub fn unmap_exact(&mut self, guest_start: u64, pages: u64) -> Result<GuestMapping, MapError> {
        let slot = self
            .iter()
            .find_map(|(slot, mapping)| {
                (mapping.guest_start == guest_start && mapping.pages == pages).then_some(slot)
            })
            .ok_or(MapError::NotFound)?;
        Ok(self.entries[slot].take().expect("located mapping"))
    }

    pub fn lookup(&self, guest: u64) -> Option<(usize, GuestMapping)> {
        self.iter()
            .find(|(_, mapping)| guest >= mapping.guest_start && guest < mapping.guest_end())
    }

    pub fn take_all_for_memory(&mut self, memory_id: u64) -> impl Iterator<Item = GuestMapping> + '_ {
        self.entries.iter_mut().filter_map(move |entry| {
            if entry.is_some_and(|mapping| mapping.memory_id == memory_id) {
                entry.take()
            } else {
                None
            }
        })
    }

    pub fn clear(&mut self) {
        self.entries.fill(None);
    }
}

impl<const N: usize> Default for GuestMap<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_only_runs_from_ready_and_never_saves_running_state() {
        let mut cpu = VcpuLifecycle::new(Backend::Vmx);
        assert_eq!(cpu.begin_run(), Err(StateError::InvalidTransition));
        cpu.make_ready().unwrap();
        cpu.begin_run().unwrap();
        let mut state = VcpuState::initial();
        state.rip = 0x1000;
        assert_eq!(cpu.save(state), Err(StateError::Running));
        cpu.halt().unwrap();
        cpu.save(state).unwrap();
        assert_eq!(cpu.state().rip, 0x1000);
        cpu.close();
        assert_eq!(cpu.make_ready(), Err(StateError::Closed));
    }

    #[test]
    fn guest_map_rejects_overlap_alignment_and_memory_escape() {
        let mut map = GuestMap::<4>::new();
        let slot = map.map(0x1000, 2, 7, 0, 4, GuestPermissions::READ_WRITE).unwrap();
        assert_eq!(slot, 0);
        assert_eq!(map.map(0x2000, 1, 8, 0, 1, GuestPermissions::READ), Err(MapError::Overlap));
        assert_eq!(map.map(0x1001, 1, 8, 0, 1, GuestPermissions::READ), Err(MapError::Misaligned));
        assert_eq!(map.map(0x3000, 4, 8, 0, 3, GuestPermissions::READ), Err(MapError::OutsideMemory));
        assert_eq!(map.map(0x3000, 1, 8, 0, 1, GuestPermissions::default()), Err(MapError::Permissions));
        assert_eq!(map.unmap_exact(0x1000, 2).unwrap().memory_id, 7);
        assert!(map.is_empty());
    }

    #[test]
    fn memory_invalidation_removes_every_alias_only_for_the_selected_backing() {
        let mut map = GuestMap::<8>::new();
        map.map(0x1000, 1, 7, 0, 1, GuestPermissions::READ).unwrap();
        map.map(0x2000, 1, 7, 0, 1, GuestPermissions::READ).unwrap();
        map.map(0x3000, 1, 8, 0, 1, GuestPermissions::READ).unwrap();
        assert_eq!(map.take_all_for_memory(7).count(), 2);
        assert_eq!(map.len(), 1);
        assert!(map.lookup(0x3000).is_some());
    }

}
