//! 堆后 CPU 身份与生命周期登记表。
//!
//! 该登记表把固件发现、平台支持、资源准入和在线状态保存为同一次事务发布的
//! 事实，逻辑 CPU ID 不要求等于稀疏硬件 ID。它是后续调度器、per-CPU 状态和
//! IRQ 路由共享 CPU 身份的唯一候选来源；不会为了适配旧 `CpuSet` 静默截断。
//!
//! Heap-stage CPU identity registry. Every allocation is completed before any
//! lifecycle fact is published, and hardware IDs stay independent of logical
//! indices. The registry has no preset processor-count ceiling.

use alloc::vec::Vec;

use crate::cpu_bitmap::CpuBitmap;
use crate::smp::{admit_cpu_inventory, CpuAdmission, CpuAdmissionError};

/// One firmware-discovered logical CPU candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuInventoryEntry {
    pub hardware_id: u32,
    pub enabled: bool,
    pub supported: bool,
}

/// Observable lifecycle state for one logical CPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuLifecycle {
    Discovered,
    Supported,
    Admitted,
    Online,
    Offline,
    Rejected,
}

/// Stable logical identity and current generation for one discovered CPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuRuntimeIdentity {
    pub logical: usize,
    pub hardware_id: u32,
    pub enabled: bool,
    pub supported: bool,
    pub generation: u64,
}

/// Why a complete CPU inventory cannot be published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuRuntimeError {
    DuplicateHardwareId { hardware_id: u32 },
    UnsupportedEnabledCpu { logical: usize, hardware_id: u32 },
    NoOnlineCandidate,
    UnknownCpu { logical: usize },
    NotAdmitted { logical: usize },
    AlreadyOnline,
    AlreadyOffline,
    BootCpu,
    LastOnlineCpu,
    Allocation,
    GenerationExhausted,
    Admission(CpuAdmissionError),
}

impl CpuRuntimeError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::DuplicateHardwareId { .. } => "system.cpu.error.duplicate_hardware_id",
            Self::UnsupportedEnabledCpu { .. } => "system.cpu.error.unsupported",
            Self::NoOnlineCandidate => "system.cpu.error.no_online_candidate",
            Self::UnknownCpu { .. } => "system.cpu.error.no_such_cpu",
            Self::NotAdmitted { .. } => "system.cpu.error.not_admitted",
            Self::AlreadyOnline => "system.cpu.error.already_online",
            Self::AlreadyOffline => "system.cpu.error.already_offline",
            Self::BootCpu => "system.cpu.error.boot_cpu",
            Self::LastOnlineCpu => "system.cpu.error.last_online_cpu",
            Self::Allocation => "system.cpu.error.registry_allocation",
            Self::GenerationExhausted => "system.cpu.error.generation",
            Self::Admission(error) => error.name(),
        }
    }
}

/// Complete heap-stage CPU lifecycle snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuRuntimeRegistry {
    identities: Vec<CpuRuntimeIdentity>,
    discovered: CpuBitmap,
    supported: CpuBitmap,
    admitted: CpuBitmap,
    online: CpuBitmap,
    rejected: CpuBitmap,
    admission: CpuAdmission,
    boot_logical: usize,
    generation: u64,
}

impl CpuRuntimeRegistry {
    /// Admit the complete enabled inventory against an explicit byte budget.
    ///
    /// Duplicate hardware IDs and enabled-but-unsupported CPUs reject the
    /// complete transaction. Disabled CPUs are retained in `discovered` and
    /// `rejected`, but never become admitted or online.
    pub fn admit_complete(
        entries: &[CpuInventoryEntry],
        per_cpu_bytes: u64,
        available_bytes: u64,
        boot_logical: usize,
    ) -> Result<Self, CpuRuntimeError> {
        reject_duplicate_hardware_ids(entries)?;

        let discovered =
            CpuBitmap::first(entries.len()).map_err(|_| CpuRuntimeError::Allocation)?;
        let mut supported = CpuBitmap::with_capacity(entries.len())
            .map_err(|_| CpuRuntimeError::Allocation)?;
        let mut admitted = CpuBitmap::with_capacity(entries.len())
            .map_err(|_| CpuRuntimeError::Allocation)?;
        let mut rejected = CpuBitmap::with_capacity(entries.len())
            .map_err(|_| CpuRuntimeError::Allocation)?;

        let mut identities = Vec::new();
        identities
            .try_reserve_exact(entries.len())
            .map_err(|_| CpuRuntimeError::Allocation)?;
        let disabled = entries.iter().filter(|entry| !entry.enabled).count();
        for (logical, entry) in entries.iter().copied().enumerate() {
            if entry.enabled && !entry.supported {
                return Err(CpuRuntimeError::UnsupportedEnabledCpu {
                    logical,
                    hardware_id: entry.hardware_id,
                });
            }
            identities.push(CpuRuntimeIdentity {
                logical,
                hardware_id: entry.hardware_id,
                enabled: entry.enabled,
                supported: entry.supported,
                generation: 0,
            });
            if entry.enabled {
                supported
                    .insert(logical)
                    .map_err(|_| CpuRuntimeError::Allocation)?;
                admitted
                    .insert(logical)
                    .map_err(|_| CpuRuntimeError::Allocation)?;
            } else {
                rejected
                    .insert(logical)
                    .map_err(|_| CpuRuntimeError::Allocation)?;
            }
        }

        let admission = admit_cpu_inventory(
            entries.len(),
            disabled,
            per_cpu_bytes,
            available_bytes,
        )
        .map_err(CpuRuntimeError::Admission)?;
        if admitted.is_empty() {
            return Err(CpuRuntimeError::NoOnlineCandidate);
        }
        if boot_logical >= identities.len() || !admitted.contains(boot_logical) {
            return Err(CpuRuntimeError::NotAdmitted {
                logical: boot_logical,
            });
        }
        let mut online = CpuBitmap::with_capacity(entries.len())
            .map_err(|_| CpuRuntimeError::Allocation)?;
        online
            .insert(boot_logical)
            .map_err(|_| CpuRuntimeError::Allocation)?;
        identities[boot_logical].generation = 1;

        Ok(Self {
            identities,
            discovered,
            supported,
            admitted,
            online,
            rejected,
            admission,
            boot_logical,
            generation: 1,
        })
    }

    pub fn identities(&self) -> &[CpuRuntimeIdentity] {
        &self.identities
    }

    pub const fn discovered(&self) -> &CpuBitmap {
        &self.discovered
    }

    pub const fn supported(&self) -> &CpuBitmap {
        &self.supported
    }

    pub const fn admitted(&self) -> &CpuBitmap {
        &self.admitted
    }

    pub const fn online(&self) -> &CpuBitmap {
        &self.online
    }

    pub const fn rejected(&self) -> &CpuBitmap {
        &self.rejected
    }

    pub const fn admission(&self) -> CpuAdmission {
        self.admission
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn identity(&self, logical: usize) -> Option<&CpuRuntimeIdentity> {
        self.identities.get(logical)
    }

    pub fn identity_for_hardware(&self, hardware_id: u32) -> Option<&CpuRuntimeIdentity> {
        self.identities
            .iter()
            .find(|identity| identity.hardware_id == hardware_id)
    }

    pub fn logical_for_hardware(&self, hardware_id: u32) -> Option<usize> {
        self.identity_for_hardware(hardware_id)
            .map(|identity| identity.logical)
    }

    pub fn state(&self, logical: usize) -> Option<CpuLifecycle> {
        if self.online.contains(logical) {
            Some(CpuLifecycle::Online)
        } else if self.rejected.contains(logical) {
            Some(CpuLifecycle::Rejected)
        } else if self.admitted.contains(logical) {
            if self
                .identities
                .get(logical)
                .is_some_and(|identity| identity.generation == 0)
            {
                Some(CpuLifecycle::Admitted)
            } else {
                Some(CpuLifecycle::Offline)
            }
        } else if self.supported.contains(logical) {
            Some(CpuLifecycle::Supported)
        } else if self.discovered.contains(logical) {
            Some(CpuLifecycle::Discovered)
        } else {
            None
        }
    }

    /// Publish an admitted CPU online. The method is in-place after all backing
    /// storage was allocated by `admit_complete`, so it does not allocate from
    /// an IRQ-held transition.
    pub fn mark_online(&mut self, logical: usize) -> Result<u64, CpuRuntimeError> {
        self.ensure_can_mark_online(logical)?;
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(CpuRuntimeError::GenerationExhausted)?;
        self.online
            .insert(logical)
            .map_err(|_| CpuRuntimeError::Allocation)?;
        self.generation = next_generation;
        self.identities[logical].generation = self.generation;
        Ok(self.generation)
    }

    /// Validate an online transition without mutating lifecycle facts.
    ///
    /// A departure coordinator runs this before quiescing hardware so an
    /// immutable failure cannot strand a CPU after interrupt teardown began.
    ///
    /// 在不改变生命周期事实的前提下校验上线迁移。离场协调器会在关闭硬件
    /// 中断与设备对象之前调用它，避免不可恢复的拒绝发生在拆除之后。
    pub fn ensure_can_mark_online(&self, logical: usize) -> Result<(), CpuRuntimeError> {
        if self.identity(logical).is_none() {
            return Err(CpuRuntimeError::UnknownCpu { logical });
        }
        if !self.admitted.contains(logical) {
            return Err(CpuRuntimeError::NotAdmitted { logical });
        }
        if self.online.contains(logical) {
            return Err(CpuRuntimeError::AlreadyOnline);
        }
        Ok(())
    }

    pub fn mark_offline(&mut self, logical: usize) -> Result<u64, CpuRuntimeError> {
        self.ensure_can_mark_offline(logical)?;
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(CpuRuntimeError::GenerationExhausted)?;
        self.online.remove(logical);
        self.generation = next_generation;
        self.identities[logical].generation = self.generation;
        Ok(self.generation)
    }

    /// Validate an offline transition without changing membership or generation.
    ///
    /// 在不修改在线集合或代际的前提下校验离线迁移。
    pub fn ensure_can_mark_offline(&self, logical: usize) -> Result<(), CpuRuntimeError> {
        if self.identity(logical).is_none() {
            return Err(CpuRuntimeError::UnknownCpu { logical });
        }
        if !self.online.contains(logical) {
            return Err(CpuRuntimeError::AlreadyOffline);
        }
        if self.online.len() == 1 {
            return Err(CpuRuntimeError::LastOnlineCpu);
        }
        if logical == self.boot_logical {
            return Err(CpuRuntimeError::BootCpu);
        }
        self.generation
            .checked_add(1)
            .ok_or(CpuRuntimeError::GenerationExhausted)?;
        Ok(())
    }
}

fn reject_duplicate_hardware_ids(entries: &[CpuInventoryEntry]) -> Result<(), CpuRuntimeError> {
    let mut hardware_ids = Vec::new();
    hardware_ids
        .try_reserve_exact(entries.len())
        .map_err(|_| CpuRuntimeError::Allocation)?;
    hardware_ids.extend(entries.iter().map(|entry| entry.hardware_id));
    hardware_ids.sort_unstable();
    if let Some(pair) = hardware_ids
        .windows(2)
        .find(|pair| pair[0] == pair[1])
    {
        return Err(CpuRuntimeError::DuplicateHardwareId {
            hardware_id: pair[0],
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(hardware_id: u32) -> CpuInventoryEntry {
        CpuInventoryEntry {
            hardware_id,
            enabled: true,
            supported: true,
        }
    }

    #[test]
    fn sparse_high_hardware_ids_keep_logical_indices() {
        let entries = [entry(0), entry(17), entry(4096), entry(u32::MAX)];
        let mut registry = CpuRuntimeRegistry::admit_complete(&entries, 8, 32, 0).unwrap();
        assert_eq!(registry.logical_for_hardware(4096), Some(2));
        assert_eq!(registry.state(2), Some(CpuLifecycle::Admitted));
        assert_eq!(registry.mark_online(2), Ok(2));
        assert_eq!(registry.state(2), Some(CpuLifecycle::Online));
        assert_eq!(registry.mark_offline(2), Ok(3));
        assert_eq!(registry.state(2), Some(CpuLifecycle::Offline));
    }

    #[test]
    fn boot_and_last_online_cpus_cannot_leave() {
        let entries = [entry(0), entry(1), entry(2)];
        let mut registry = CpuRuntimeRegistry::admit_complete(&entries, 1, 3, 0).unwrap();
        assert_eq!(
            registry.mark_offline(0),
            Err(CpuRuntimeError::LastOnlineCpu)
        );
        assert_eq!(registry.mark_online(1), Ok(2));
        let before = registry.clone();
        assert_eq!(registry.mark_offline(0), Err(CpuRuntimeError::BootCpu));
        assert_eq!(registry, before);

        assert_eq!(registry.mark_online(2), Ok(3));
        assert_eq!(registry.mark_offline(1), Ok(4));
        assert_eq!(registry.mark_offline(2), Ok(5));
        assert_eq!(
            registry.mark_offline(0),
            Err(CpuRuntimeError::LastOnlineCpu)
        );
        assert_eq!(registry.state(0), Some(CpuLifecycle::Online));
        assert_eq!(registry.generation(), 5);
        assert_eq!(registry.online().iter().collect::<Vec<_>>(), vec![0]);
        assert_eq!(
            CpuRuntimeError::BootCpu.name(),
            "system.cpu.error.boot_cpu"
        );
        assert_eq!(
            CpuRuntimeError::LastOnlineCpu.name(),
            "system.cpu.error.last_online_cpu"
        );
    }

    #[test]
    fn lifecycle_preflight_does_not_publish_partial_state() {
        let entries = [entry(0), entry(1)];
        let mut registry = CpuRuntimeRegistry::admit_complete(&entries, 1, 2, 0).unwrap();
        registry.mark_online(1).unwrap();
        let before = registry.clone();

        assert_eq!(registry.ensure_can_mark_offline(1), Ok(()));
        assert_eq!(registry, before);
        assert_eq!(
            registry.ensure_can_mark_offline(0),
            Err(CpuRuntimeError::BootCpu)
        );
        assert_eq!(registry, before);

        registry.mark_offline(1).unwrap();
        let offline = registry.clone();
        assert_eq!(registry.ensure_can_mark_online(1), Ok(()));
        assert_eq!(registry, offline);
        assert_eq!(
            registry.ensure_can_mark_online(0),
            Err(CpuRuntimeError::AlreadyOnline)
        );
        assert_eq!(registry, offline);
    }

    #[test]
    fn more_than_legacy_cpu_set_width_is_admitted() {
        let entries: Vec<_> = (0..130).map(entry).collect();
        let registry = CpuRuntimeRegistry::admit_complete(&entries, 1, 130, 0).unwrap();
        assert_eq!(registry.admitted().len(), 130);
        assert!(registry.admitted().contains(129));
        assert_eq!(registry.admission().enabled, 130);
    }

    #[test]
    fn disabled_entries_remain_distinct_from_admitted_cpus() {
        let entries = [
            entry(4),
            CpuInventoryEntry {
                hardware_id: 5,
                enabled: false,
                supported: false,
            },
            entry(6),
        ];
        let registry = CpuRuntimeRegistry::admit_complete(&entries, 1, 2, 0).unwrap();
        assert_eq!(registry.discovered().len(), 3);
        assert_eq!(registry.supported().len(), 2);
        assert_eq!(registry.admitted().len(), 2);
        assert_eq!(registry.rejected().iter().collect::<Vec<_>>(), vec![1]);
        assert_eq!(registry.state(1), Some(CpuLifecycle::Rejected));
    }

    #[test]
    fn failures_are_transactional_and_explicit() {
        let duplicate = [entry(7), entry(7)];
        assert_eq!(
            CpuRuntimeRegistry::admit_complete(&duplicate, 1, 2, 0),
            Err(CpuRuntimeError::DuplicateHardwareId { hardware_id: 7 })
        );
        let unsupported = [
            entry(8),
            CpuInventoryEntry {
                hardware_id: 9,
                enabled: true,
                supported: false,
            },
        ];
        assert_eq!(
            CpuRuntimeRegistry::admit_complete(&unsupported, 1, 2, 0),
            Err(CpuRuntimeError::UnsupportedEnabledCpu {
                logical: 1,
                hardware_id: 9
            })
        );
        assert_eq!(
            CpuRuntimeRegistry::admit_complete(&duplicate[..1], 2, 1, 0),
            Err(CpuRuntimeError::Admission(
                CpuAdmissionError::InsufficientResources {
                    required_bytes: 2,
                    available_bytes: 1
                }
            ))
        );
    }
}
