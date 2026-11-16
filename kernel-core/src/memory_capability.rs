//! SEC-6 software memory capabilities and CHERI-ready boundary.
//!
//! This is an internal provenance table, not a replacement for page tables.
//! Every user pointer copy must resolve to an active descriptor whose range,
//! permissions, object identity and generation still match.  Hardware-tagged
//! pointers are reported as unavailable unless the platform explicitly says
//! otherwise; software checks are never presented as CHERI guarantees.

use crate::memory_object::PAGE_BYTES;

#[cfg(any(test, feature = "runtime-registries"))]
use alloc::vec::Vec;

pub const MEMORY_CAPABILITY_FORMAT_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryRights(u16);

impl MemoryRights {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const EXECUTE: Self = Self(1 << 2);
    pub const MMIO: Self = Self(1 << 3);
    pub const DMA: Self = Self(1 << 4);
    pub const GUEST: Self = Self(1 << 5);
    pub const MAP: Self = Self(1 << 6);
    pub const ALL: Self = Self(0x7f);

    pub const fn bits(self) -> u16 {
        self.0
    }

    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MemoryKind {
    Anonymous = 1,
    Image = 2,
    Stack = 3,
    Shared = 4,
    DeviceMmio = 5,
    Dma = 6,
    Guest = 7,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CapabilityState {
    Active = 1,
    Revoked = 2,
}

/// Stable identity of the backing object.  For anonymous kernel-owned pages,
/// `object_id=0` is allowed but `generation` must still advance at allocation
/// so address reuse never revives an old descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackingIdentity {
    pub object_id: u64,
    pub generation: u32,
}

impl BackingIdentity {
    pub const fn new(object_id: u64, generation: u32) -> Option<Self> {
        if generation == 0 {
            None
        } else {
            Some(Self {
                object_id,
                generation,
            })
        }
    }
}

/// One software capability.  `end` is exclusive and page aligned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryCapability {
    pub id: u64,
    pub format_version: u16,
    pub state: CapabilityState,
    pub kind: MemoryKind,
    pub rights: MemoryRights,
    pub start: u64,
    pub end: u64,
    pub backing: BackingIdentity,
    pub epoch: u32,
}

/// Runtime-admitted provenance capacity and the metadata budget it came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryCapabilityCapacityPlan {
    pub per_process: usize,
    pub metadata_budget: u64,
}

/// Derive one process's software-memory-capability capacity from runtime facts.
///
/// Provenance metadata receives one thirty-second of the admitted heap budget.
/// The budget is divided across the admitted process slots, so increasing either
/// mapping pressure or process concurrency shrinks the per-process capacity
/// instead of silently exceeding the global memory budget.
pub fn plan_memory_capability_capacity(
    memory_budget: u64,
    process_slots: usize,
) -> Option<MemoryCapabilityCapacityPlan> {
    if memory_budget == 0 || process_slots == 0 {
        return None;
    }
    let entry_bytes = core::mem::size_of::<Option<MemoryCapability>>() as u64;
    if entry_bytes == 0 {
        return None;
    }
    let metadata_budget = memory_budget / 32;
    let per_process = metadata_budget / process_slots as u64;
    let capacity = usize::try_from(per_process / entry_bytes)
        .ok()
        .filter(|&capacity| capacity != 0)?;
    Some(MemoryCapabilityCapacityPlan {
        per_process: capacity,
        metadata_budget,
    })
}

impl MemoryCapability {
    pub fn covers(self, start: u64, len: u64, required: MemoryRights) -> bool {
        self.format_version == MEMORY_CAPABILITY_FORMAT_VERSION
            && self.state == CapabilityState::Active
            && self.rights.contains(required)
            && start >= self.start
            && start
                .checked_add(len)
                .is_some_and(|end| end <= self.end)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryCapabilityError {
    InvalidRange,
    InvalidIdentity,
    NoSpace,
    Overlap,
    InvalidCapability,
    Revoked,
    RightsDenied,
    Unmapped,
    StaleIdentity,
    HardwareUnavailable,
}

impl MemoryCapabilityError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidRange => "system.memory.capability.error.invalid_range",
            Self::InvalidIdentity => "system.memory.capability.error.invalid_identity",
            Self::NoSpace => "system.memory.capability.error.capacity",
            Self::Overlap => "system.memory.capability.error.overlap",
            Self::InvalidCapability => "system.memory.capability.error.invalid",
            Self::Revoked => "system.memory.capability.error.revoked",
            Self::RightsDenied => "system.memory.capability.error.rights",
            Self::Unmapped => "system.memory.capability.error.unmapped",
            Self::StaleIdentity => "system.memory.capability.error.stale_identity",
            Self::HardwareUnavailable => "system.memory.capability.error.hardware_unavailable",
        }
    }
}

/// In-flight use token.  Revocation or a policy/identity update invalidates it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryCapabilityUse {
    pub capability: u64,
    pub epoch: u32,
    pub backing: BackingIdentity,
    pub rights: MemoryRights,
}

/// Fixed-capacity provenance table used only by bounded mechanism tests.
///
/// Production processes use [`DynamicMemoryCapabilityTable`].
#[cfg(any(test, feature = "compat-native-bounded"))]
#[derive(Clone)]
pub struct MemoryCapabilityTable<const N: usize> {
    slots: [Option<MemoryCapability>; N],
    next_id: u64,
    epoch: u32,
    revoked: u64,
}

#[cfg(any(test, feature = "compat-native-bounded"))]
impl<const N: usize> MemoryCapabilityTable<N> {
    pub const fn new() -> Self {
        assert!(N > 0, "memory capability capacity must be non-zero");
        Self {
            slots: [None; N],
            next_id: 1,
            epoch: 1,
            revoked: 0,
        }
    }

    pub fn active(&self) -> usize {
        let mut n = 0;
        let mut i = 0;
        while i < N {
            if matches!(
                self.slots[i],
                Some(cap) if cap.state == CapabilityState::Active
            ) {
                n += 1;
            }
            i += 1;
        }
        n
    }

    pub const fn revoked(&self) -> u64 {
        self.revoked
    }

    pub fn can_grant(&self, start: u64, pages: u64, kind: MemoryKind) -> bool {
        let Some(end) = canonical_end(start, pages) else {
            return false;
        };
        self.slots.iter().flatten().all(|cap| {
            cap.state == CapabilityState::Revoked
                || cap.end <= start
                || end <= cap.start
                || (cap.kind == kind
                    && cap.start == start
                    && cap.end == end
                    && cap.state == CapabilityState::Active)
        })
    }

    /// Returns the first active entry that blocks an otherwise valid grant.
    pub fn overlapping(&self, start: u64, pages: u64) -> Option<MemoryCapability> {
        let end = canonical_end(start, pages)?;
        self.slots
            .iter()
            .flatten()
            .copied()
            .find(|cap| cap.state == CapabilityState::Active && cap.start < end && start < cap.end)
    }

    /// Create or extend an adjacent capability.  Adjacent private mappings are
    /// coalesced to keep image/stack/page-by-page loaders bounded.
    pub fn grant(
        &mut self,
        start: u64,
        pages: u64,
        rights: MemoryRights,
        kind: MemoryKind,
        backing: BackingIdentity,
    ) -> Result<u64, MemoryCapabilityError> {
        let end = canonical_end(start, pages).ok_or(MemoryCapabilityError::InvalidRange)?;
        if backing.generation == 0 {
            return Err(MemoryCapabilityError::InvalidIdentity);
        }
        for slot in &mut self.slots {
            let Some(cap) = slot.as_mut() else {
                continue;
            };
            if cap.state != CapabilityState::Active {
                continue;
            }
            if cap.end <= start || end <= cap.start {
                if cap.kind == kind
                    && cap.rights == rights
                    && cap.backing == backing
                    && (cap.start == end || cap.end == start)
                {
                    cap.start = cap.start.min(start);
                    cap.end = cap.end.max(end);
                    return Ok(cap.id);
                }
                continue;
            }
            if cap.start == start && cap.end == end && cap.kind == kind {
                if cap.rights.contains(rights) {
                    return Ok(cap.id);
                }
                if cap.backing != backing {
                    return Err(MemoryCapabilityError::StaleIdentity);
                }
                let epoch = self
                    .epoch
                    .checked_add(1)
                    .ok_or(MemoryCapabilityError::NoSpace)?;
                self.epoch = epoch;
                cap.epoch = epoch;
                cap.rights = cap.rights.union(rights);
                return Ok(cap.id);
            }
            return Err(MemoryCapabilityError::Overlap);
        }
        // Revoked entries no longer grant access, so reuse them after exhausting
        // empty slots instead of permanently shrinking the mutable mapping budget.
        let index = self
            .slots
            .iter()
            .position(Option::is_none)
            .or_else(|| {
                self.slots.iter().position(|slot| {
                    matches!(
                        slot,
                        Some(cap) if cap.state == CapabilityState::Revoked
                    )
                })
            })
            .ok_or(MemoryCapabilityError::NoSpace)?;
        let epoch = self
            .epoch
            .checked_add(1)
            .ok_or(MemoryCapabilityError::NoSpace)?;
        self.epoch = epoch;
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(MemoryCapabilityError::NoSpace)?;
        self.slots[index] = Some(MemoryCapability {
            id,
            format_version: MEMORY_CAPABILITY_FORMAT_VERSION,
            state: CapabilityState::Active,
            kind,
            rights,
            start,
            end,
            backing,
            epoch,
        });
        Ok(id)
    }

    pub fn check(
        &self,
        start: u64,
        len: u64,
        required: MemoryRights,
        expected_backing: Option<BackingIdentity>,
    ) -> Result<MemoryCapabilityUse, MemoryCapabilityError> {
        if len == 0 {
            return Err(MemoryCapabilityError::InvalidRange);
        }
        let cap = self
            .slots
            .iter()
            .flatten()
            .find(|cap| cap.covers(start, len, required))
            .ok_or(MemoryCapabilityError::Unmapped)?;
        if expected_backing.is_some_and(|expected| expected != cap.backing) {
            return Err(MemoryCapabilityError::StaleIdentity);
        }
        Ok(MemoryCapabilityUse {
            capability: cap.id,
            epoch: cap.epoch,
            backing: cap.backing,
            rights: required,
        })
    }

    pub fn validate(&self, token: MemoryCapabilityUse) -> Result<(), MemoryCapabilityError> {
        let cap = self
            .slots
            .iter()
            .flatten()
            .find(|cap| cap.id == token.capability)
            .ok_or(MemoryCapabilityError::InvalidCapability)?;
        if cap.state != CapabilityState::Active {
            return Err(MemoryCapabilityError::Revoked);
        }
        if cap.backing != token.backing || !cap.rights.contains(token.rights) {
            return Err(MemoryCapabilityError::StaleIdentity);
        }
        Ok(())
    }

    /// Remove and invalidate every descriptor intersecting `[start,end)`.
    /// Caps partially outside the range are split so retained mappings keep
    /// their provenance.
    pub fn revoke_range(
        &mut self,
        start: u64,
        pages: u64,
    ) -> Result<usize, MemoryCapabilityError> {
        let Some(end) = canonical_end(start, pages) else {
            return Err(MemoryCapabilityError::InvalidRange);
        };
        let mut removed = 0usize;
        let mut extra_slots = 0usize;
        for cap in self.slots.iter().flatten() {
            if cap.state != CapabilityState::Active || cap.end <= start || end <= cap.start {
                continue;
            }
            removed += 1;
            // The intersecting slot itself can hold the retained left side.
            // Only a retained right side needs an additional slot.
            extra_slots += usize::from(end < cap.end);
        }
        if removed == 0 {
            return Ok(0);
        }
        let free = self.slots.iter().filter(|slot| slot.is_none()).count();
        if extra_slots > free {
            return Err(MemoryCapabilityError::NoSpace);
        }
        let epoch = self.epoch.wrapping_add(1).max(1);
        self.epoch = epoch;
        for index in 0..N {
            let Some(cap) = self.slots[index] else {
                continue;
            };
            if cap.state != CapabilityState::Active || cap.end <= start || end <= cap.start {
                continue;
            }
            self.slots[index] = None;
            self.revoked = self.revoked.saturating_add(1);
            if cap.start < start {
                let id = self.take_id();
                self.slots[index] = Some(MemoryCapability {
                    id,
                    end: start,
                    epoch,
                    ..cap
                });
            }
            if end < cap.end {
                if let Some(free) = self.slots.iter().position(Option::is_none) {
                    let id = self.take_id();
                    self.slots[free] = Some(MemoryCapability {
                        id,
                        start: end,
                        epoch,
                        ..cap
                    });
                }
            }
        }
        Ok(removed)
    }

    fn take_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        id
    }
}

/// Heap-backed provenance table with a runtime-admitted slot ceiling.
///
/// 堆后备来源表；槽位上限由运行时内存预算与进程容量准入。表在创建时
/// 一次性预留，后续授权、撤销与区间拆分不会再触发隐藏分配。
#[cfg(any(test, feature = "runtime-registries"))]
#[derive(Clone)]
pub struct DynamicMemoryCapabilityTable {
    slots: Vec<Option<MemoryCapability>>,
    next_id: u64,
    epoch: u32,
    revoked: u64,
}

#[cfg(any(test, feature = "runtime-registries"))]
impl DynamicMemoryCapabilityTable {
    pub fn new(capacity: usize) -> Option<Self> {
        if capacity == 0 {
            return None;
        }
        let mut slots = Vec::new();
        slots.try_reserve_exact(capacity).ok()?;
        slots.resize(capacity, None);
        Some(Self {
            slots,
            next_id: 1,
            epoch: 1,
            revoked: 0,
        })
    }

    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    pub fn active(&self) -> usize {
        self.slots
            .iter()
            .flatten()
            .filter(|cap| cap.state == CapabilityState::Active)
            .count()
    }

    pub const fn revoked(&self) -> u64 {
        self.revoked
    }

    pub fn can_grant(&self, start: u64, pages: u64, kind: MemoryKind) -> bool {
        let Some(end) = canonical_end(start, pages) else {
            return false;
        };
        self.slots.iter().flatten().all(|cap| {
            cap.state == CapabilityState::Revoked
                || cap.end <= start
                || end <= cap.start
                || (cap.kind == kind
                    && cap.start == start
                    && cap.end == end
                    && cap.state == CapabilityState::Active)
        })
    }

    pub fn overlapping(&self, start: u64, pages: u64) -> Option<MemoryCapability> {
        let end = canonical_end(start, pages)?;
        self.slots
            .iter()
            .flatten()
            .copied()
            .find(|cap| cap.state == CapabilityState::Active && cap.start < end && start < cap.end)
    }

    pub fn grant(
        &mut self,
        start: u64,
        pages: u64,
        rights: MemoryRights,
        kind: MemoryKind,
        backing: BackingIdentity,
    ) -> Result<u64, MemoryCapabilityError> {
        let end = canonical_end(start, pages).ok_or(MemoryCapabilityError::InvalidRange)?;
        if backing.generation == 0 {
            return Err(MemoryCapabilityError::InvalidIdentity);
        }
        for slot in &mut self.slots {
            let Some(cap) = slot.as_mut() else {
                continue;
            };
            if cap.state != CapabilityState::Active {
                continue;
            }
            if cap.end <= start || end <= cap.start {
                if cap.kind == kind
                    && cap.rights == rights
                    && cap.backing == backing
                    && (cap.start == end || cap.end == start)
                {
                    cap.start = cap.start.min(start);
                    cap.end = cap.end.max(end);
                    return Ok(cap.id);
                }
                continue;
            }
            if cap.start == start && cap.end == end && cap.kind == kind {
                if cap.rights.contains(rights) {
                    return Ok(cap.id);
                }
                if cap.backing != backing {
                    return Err(MemoryCapabilityError::StaleIdentity);
                }
                let epoch = self
                    .epoch
                    .checked_add(1)
                    .ok_or(MemoryCapabilityError::NoSpace)?;
                self.epoch = epoch;
                cap.epoch = epoch;
                cap.rights = cap.rights.union(rights);
                return Ok(cap.id);
            }
            return Err(MemoryCapabilityError::Overlap);
        }
        let index = self
            .slots
            .iter()
            .position(Option::is_none)
            .or_else(|| {
                self.slots.iter().position(|slot| {
                    matches!(
                        slot,
                        Some(cap) if cap.state == CapabilityState::Revoked
                    )
                })
            })
            .ok_or(MemoryCapabilityError::NoSpace)?;
        let epoch = self
            .epoch
            .checked_add(1)
            .ok_or(MemoryCapabilityError::NoSpace)?;
        self.epoch = epoch;
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(MemoryCapabilityError::NoSpace)?;
        self.slots[index] = Some(MemoryCapability {
            id,
            format_version: MEMORY_CAPABILITY_FORMAT_VERSION,
            state: CapabilityState::Active,
            kind,
            rights,
            start,
            end,
            backing,
            epoch,
        });
        Ok(id)
    }

    pub fn check(
        &self,
        start: u64,
        len: u64,
        required: MemoryRights,
        expected_backing: Option<BackingIdentity>,
    ) -> Result<MemoryCapabilityUse, MemoryCapabilityError> {
        if len == 0 {
            return Err(MemoryCapabilityError::InvalidRange);
        }
        let cap = self
            .slots
            .iter()
            .flatten()
            .find(|cap| cap.covers(start, len, required))
            .ok_or(MemoryCapabilityError::Unmapped)?;
        if expected_backing.is_some_and(|expected| expected != cap.backing) {
            return Err(MemoryCapabilityError::StaleIdentity);
        }
        Ok(MemoryCapabilityUse {
            capability: cap.id,
            epoch: cap.epoch,
            backing: cap.backing,
            rights: required,
        })
    }

    pub fn validate(&self, token: MemoryCapabilityUse) -> Result<(), MemoryCapabilityError> {
        let cap = self
            .slots
            .iter()
            .flatten()
            .find(|cap| cap.id == token.capability)
            .ok_or(MemoryCapabilityError::InvalidCapability)?;
        if cap.state != CapabilityState::Active {
            return Err(MemoryCapabilityError::Revoked);
        }
        if cap.backing != token.backing || !cap.rights.contains(token.rights) {
            return Err(MemoryCapabilityError::StaleIdentity);
        }
        Ok(())
    }

    pub fn revoke_range(
        &mut self,
        start: u64,
        pages: u64,
    ) -> Result<usize, MemoryCapabilityError> {
        let Some(end) = canonical_end(start, pages) else {
            return Err(MemoryCapabilityError::InvalidRange);
        };
        let mut removed = 0usize;
        let mut extra_slots = 0usize;
        for cap in self.slots.iter().flatten() {
            if cap.state != CapabilityState::Active || cap.end <= start || end <= cap.start {
                continue;
            }
            removed += 1;
            // The intersecting slot itself can hold the retained left side.
            // Only a retained right side needs an additional slot.
            extra_slots += usize::from(end < cap.end);
        }
        if removed == 0 {
            return Ok(0);
        }
        let free = self.slots.iter().filter(|slot| slot.is_none()).count();
        if extra_slots > free {
            return Err(MemoryCapabilityError::NoSpace);
        }
        let epoch = self.epoch.wrapping_add(1).max(1);
        self.epoch = epoch;
        for index in 0..self.slots.len() {
            let Some(cap) = self.slots[index] else {
                continue;
            };
            if cap.state != CapabilityState::Active || cap.end <= start || end <= cap.start {
                continue;
            }
            self.slots[index] = None;
            self.revoked = self.revoked.saturating_add(1);
            if cap.start < start {
                let id = self.take_id();
                self.slots[index] = Some(MemoryCapability {
                    id,
                    end: start,
                    epoch,
                    ..cap
                });
            }
            if end < cap.end {
                if let Some(free) = self.slots.iter().position(Option::is_none) {
                    let id = self.take_id();
                    self.slots[free] = Some(MemoryCapability {
                        id,
                        start: end,
                        epoch,
                        ..cap
                    });
                }
            }
        }
        Ok(removed)
    }

    fn take_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        id
    }
}

fn canonical_end(start: u64, pages: u64) -> Option<u64> {
    if pages == 0 || start % PAGE_BYTES != 0 {
        return None;
    }
    let len = pages.checked_mul(PAGE_BYTES)?;
    start.checked_add(len)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaggedPointerSupport {
    Unavailable,
    Cheri,
    Morello,
}

impl TaggedPointerSupport {
    pub const fn supports_hardware_capabilities(self) -> bool {
        !matches!(self, Self::Unavailable)
    }
}

/// Hardware capability state is discovered, never inferred from a successful
/// software bounds check.
pub const fn require_tagged_pointer_support(
    support: TaggedPointerSupport,
) -> Result<(), MemoryCapabilityError> {
    if support.supports_hardware_capabilities() {
        Ok(())
    } else {
        Err(MemoryCapabilityError::HardwareUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backing(n: u32) -> BackingIdentity {
        BackingIdentity::new(0, n).unwrap()
    }

    #[test]
    fn runtime_capacity_follows_memory_and_process_slots() {
        let small = plan_memory_capability_capacity(16 * 1024 * 1024, 64).unwrap();
        let large = plan_memory_capability_capacity(512 * 1024 * 1024, 64).unwrap();
        let concurrent = plan_memory_capability_capacity(512 * 1024 * 1024, 256).unwrap();
        assert!(large.per_process > small.per_process);
        assert!(large.per_process > concurrent.per_process);
        assert!(large.metadata_budget > small.metadata_budget);
        assert!(
            large.per_process as u64
                * 64
                * core::mem::size_of::<Option<MemoryCapability>>() as u64
                <= large.metadata_budget
        );
        assert_eq!(plan_memory_capability_capacity(0, 64), None);
        assert_eq!(plan_memory_capability_capacity(1024, 0), None);
    }

    #[test]
    fn dynamic_table_exceeds_the_previous_fixed_capacity() {
        let mut table = DynamicMemoryCapabilityTable::new(600).unwrap();
        assert_eq!(table.capacity(), 600);
        for index in 0..600u64 {
            table
                .grant(
                    (index + 1) * 2 * PAGE_BYTES,
                    1,
                    MemoryRights::READ,
                    MemoryKind::Image,
                    backing(index as u32 + 1),
                )
                .unwrap();
        }
        assert_eq!(table.active(), 600);
        assert_eq!(
            table.grant(
                1202 * PAGE_BYTES,
                1,
                MemoryRights::READ,
                MemoryKind::Image,
                backing(601),
            ),
            Err(MemoryCapabilityError::NoSpace)
        );
    }

    #[test]
    fn dynamic_split_reuses_the_replaced_slot() {
        let mut table = DynamicMemoryCapabilityTable::new(3).unwrap();
        let rights = MemoryRights::READ.union(MemoryRights::WRITE);
        table
            .grant(0x1000, 8, rights, MemoryKind::Image, backing(1))
            .unwrap();
        table
            .grant(0x9000, 1, rights, MemoryKind::Image, backing(2))
            .unwrap();
        assert_eq!(table.active(), 2);

        // Splitting the first capability in the middle reuses its slot for the
        // left half and needs the one free slot for the right half.
        assert_eq!(table.revoke_range(0x3000, 1).unwrap(), 1);
        assert_eq!(table.active(), 3);
        assert!(table
            .check(0x1000, PAGE_BYTES, MemoryRights::READ, None)
            .is_ok());
        assert!(table
            .check(0x3000, PAGE_BYTES, MemoryRights::READ, None)
            .is_err());
        assert!(table
            .check(0x1000, 2 * PAGE_BYTES, MemoryRights::READ, None)
            .is_ok());
        assert!(table
            .check(0x4000, 4 * PAGE_BYTES, MemoryRights::READ, None)
            .is_ok());
        assert!(table
            .check(0x9000, PAGE_BYTES, MemoryRights::READ, None)
            .is_ok());
    }

    #[test]
    fn bounds_rights_and_generation_are_checked() {
        let mut table = DynamicMemoryCapabilityTable::new(8).unwrap();
        table
            .grant(0x1000, 2, MemoryRights::READ, MemoryKind::Shared, backing(7))
            .unwrap();
        assert!(table
            .check(0x1000, 0x2000, MemoryRights::READ, Some(backing(7)))
            .is_ok());
        assert_eq!(
            table.check(0x0000, 0x1000, MemoryRights::READ, None),
            Err(MemoryCapabilityError::Unmapped)
        );
        assert_eq!(
            table.check(0x1000, 0x1000, MemoryRights::WRITE, None),
            Err(MemoryCapabilityError::Unmapped)
        );
        assert_eq!(
            table.check(0x1000, 0x1000, MemoryRights::READ, Some(backing(8))),
            Err(MemoryCapabilityError::StaleIdentity)
        );
    }

    #[test]
    fn overlapping_capabilities_are_refused_without_mutation() {
        let mut table = DynamicMemoryCapabilityTable::new(8).unwrap();
        table
            .grant(0x1000, 2, MemoryRights::READ, MemoryKind::Anonymous, backing(1))
            .unwrap();
        assert_eq!(
            table.grant(
                0x2000,
                2,
                MemoryRights::READ,
                MemoryKind::Stack,
                backing(2)
            ),
            Err(MemoryCapabilityError::Overlap)
        );
        assert_eq!(table.active(), 1);
    }

    #[test]
    fn revoke_invalidates_uses_and_splits_boundaries() {
        let mut table = DynamicMemoryCapabilityTable::new(8).unwrap();
        table
            .grant(0x1000, 4, MemoryRights::READ, MemoryKind::Shared, backing(3))
            .unwrap();
        let use_token = table
            .check(0x2000, 0x1000, MemoryRights::READ, None)
            .unwrap();
        assert_eq!(table.revoke_range(0x2000, 1), Ok(1));
        assert_eq!(
            table.validate(use_token),
            Err(MemoryCapabilityError::InvalidCapability)
        );
        assert!(table
            .check(0x1000, 0x1000, MemoryRights::READ, None)
            .is_ok());
        assert!(table
            .check(0x3000, 0x2000, MemoryRights::READ, None)
            .is_ok());
        assert_eq!(
            table.check(0x2000, 0x1000, MemoryRights::READ, None),
            Err(MemoryCapabilityError::Unmapped)
        );
    }

    #[test]
    fn adjacent_private_pages_coalesce() {
        let mut table = DynamicMemoryCapabilityTable::new(2).unwrap();
        let rights = MemoryRights::READ.union(MemoryRights::WRITE);
        table
            .grant(0x1000, 1, rights, MemoryKind::Image, backing(1))
            .unwrap();
        table
            .grant(0x2000, 1, rights, MemoryKind::Image, backing(1))
            .unwrap();
        assert_eq!(table.active(), 1);
        assert!(table
            .check(0x1000, 0x2000, rights, Some(backing(1)))
            .is_ok());
    }

    #[test]
    fn unavailable_hardware_is_not_reported_as_cheri() {
        assert_eq!(
            require_tagged_pointer_support(TaggedPointerSupport::Unavailable),
            Err(MemoryCapabilityError::HardwareUnavailable)
        );
        assert!(require_tagged_pointer_support(TaggedPointerSupport::Cheri).is_ok());
    }
}
