//! Physical-IOMMU policy model for DMA and interrupt remapping.
//!
//! 职责：建模域、设备独占绑定、IOVA 映射、权限、中断重映射和 reset 撤销。
//! 边界：不写 VT-d/AMD-Vi 寄存器，不发现固件表；硬件后端由 arch 层提供。
//! Responsibility: a fail-closed IOMMU domain contract, not a hardware driver.

use crate::security_domain::DomainKey;
use crate::smp::MAX_CPUS;

pub const PAGE_BYTES: u64 = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceId {
    pub segment: u16,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub generation: u32,
}

impl DeviceId {
    pub const fn sid(self) -> u32 {
        (self.bus as u32) << 8 | (self.device as u32) << 3 | self.function as u32
    }

    const fn valid(self) -> bool {
        self.segment != 0 || self.bus != 0 || self.device != 0 || self.function != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MappingRequest {
    pub device: DeviceId,
    pub iova: u64,
    pub guest_phys: u64,
    pub pages: u64,
    pub writable: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IrqRequest {
    pub device: DeviceId,
    pub source: u32,
    pub target_cpu: u8,
    pub vector: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IrqRoute {
    pub source: u32,
    pub target_cpu: u8,
    pub vector: u8,
    pub device_epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IommuError {
    InvalidDomain,
    StaleDomain,
    InvalidDevice,
    DeviceBound,
    DeviceNotBound,
    StaleDevice,
    InvalidMapping,
    Overlap,
    AccessDenied,
    NoMapping,
    Capacity,
    IrqConflict,
}

impl IommuError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidDomain => "system.iommu.error.invalid_domain",
            Self::StaleDomain => "system.iommu.error.stale_domain",
            Self::InvalidDevice => "system.iommu.error.invalid_device",
            Self::DeviceBound => "system.iommu.error.device_bound",
            Self::DeviceNotBound => "system.iommu.error.device_not_bound",
            Self::StaleDevice => "system.iommu.error.stale_device",
            Self::InvalidMapping => "system.iommu.error.invalid_mapping",
            Self::Overlap => "system.iommu.error.overlap",
            Self::AccessDenied => "system.iommu.error.access",
            Self::NoMapping => "system.iommu.error.no_mapping",
            Self::Capacity => "system.iommu.error.capacity",
            Self::IrqConflict => "system.iommu.error.irq_conflict",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DeviceBinding {
    device: DeviceId,
    epoch: u64,
    active: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Mapping {
    sid: u32,
    device_generation: u32,
    device_epoch: u64,
    iova: u64,
    guest_phys: u64,
    pages: u64,
    writable: bool,
}

impl Mapping {
    fn contains(self, iova: u64) -> bool {
        let end = self
            .iova
            .saturating_add(self.pages.saturating_mul(PAGE_BYTES));
        (self.iova..end).contains(&iova)
    }

    fn translate(self, iova: u64) -> Option<u64> {
        self.contains(iova)
            .then(|| self.guest_phys.saturating_add(iova - self.iova))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IrqBinding {
    sid: u32,
    device_generation: u32,
    route: IrqRoute,
}

pub struct IommuDomain<const DEVICES: usize, const MAPPINGS: usize, const IRQS: usize> {
    key: DomainKey,
    enabled: bool,
    devices: [Option<DeviceBinding>; DEVICES],
    mappings: [Option<Mapping>; MAPPINGS],
    irqs: [Option<IrqBinding>; IRQS],
}

impl<const DEVICES: usize, const MAPPINGS: usize, const IRQS: usize>
    IommuDomain<DEVICES, MAPPINGS, IRQS>
{
    pub fn new(key: DomainKey) -> Result<Self, IommuError> {
        if !key.is_valid() {
            return Err(IommuError::InvalidDomain);
        }
        Ok(Self {
            key,
            enabled: true,
            devices: [None; DEVICES],
            mappings: [None; MAPPINGS],
            irqs: [None; IRQS],
        })
    }

    pub const fn key(&self) -> DomainKey {
        self.key
    }

    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn bind(&mut self, key: DomainKey, device: DeviceId) -> Result<(), IommuError> {
        self.check_domain(key)?;
        if !device.valid() || device.generation == 0 {
            return Err(IommuError::InvalidDevice);
        }
        if self
            .devices
            .iter()
            .flatten()
            .any(|binding| binding.active && binding.device.sid() == device.sid())
        {
            return Err(IommuError::DeviceBound);
        }
        let slot = self
            .devices
            .iter_mut()
            .find(|binding| binding.is_none_or(|binding| !binding.active))
            .ok_or(IommuError::Capacity)?;
        *slot = Some(DeviceBinding {
            device,
            epoch: 1,
            active: true,
        });
        Ok(())
    }

    pub fn map(&mut self, key: DomainKey, request: MappingRequest) -> Result<(), IommuError> {
        self.check_domain(key)?;
        self.require_device(request.device)?;
        if !self.enabled {
            return Err(IommuError::AccessDenied);
        }
        if request.pages == 0
            || request.iova % PAGE_BYTES != 0
            || request.guest_phys % PAGE_BYTES != 0
            || request
                .pages
                .checked_mul(PAGE_BYTES)
                .and_then(|bytes| request.iova.checked_add(bytes))
                .is_none()
            || request
                .pages
                .checked_mul(PAGE_BYTES)
                .and_then(|bytes| request.guest_phys.checked_add(bytes))
                .is_none()
        {
            return Err(IommuError::InvalidMapping);
        }
        let end = request.iova + request.pages * PAGE_BYTES;
        if self.mappings.iter().flatten().any(|mapping| {
            if mapping.sid != request.device.sid() {
                return false;
            }
            let other_end = mapping.iova + mapping.pages * PAGE_BYTES;
            request.iova < other_end && mapping.iova < end
        }) {
            return Err(IommuError::Overlap);
        }
        let binding = self.binding(request.device)?;
        let slot = self
            .mappings
            .iter_mut()
            .find(|mapping| mapping.is_none())
            .ok_or(IommuError::Capacity)?;
        *slot = Some(Mapping {
            sid: request.device.sid(),
            device_generation: request.device.generation,
            device_epoch: binding.epoch,
            iova: request.iova,
            guest_phys: request.guest_phys,
            pages: request.pages,
            writable: request.writable,
        });
        Ok(())
    }

    pub fn unmap(
        &mut self,
        key: DomainKey,
        device: DeviceId,
        iova: u64,
        pages: u64,
    ) -> Result<(), IommuError> {
        self.check_domain(key)?;
        self.require_device(device)?;
        let slot = self
            .mappings
            .iter()
            .position(|mapping| {
                mapping.is_some_and(|mapping| {
                    mapping.sid == device.sid()
                        && mapping.device_generation == device.generation
                        && mapping.iova == iova
                        && mapping.pages == pages
                })
            })
            .ok_or(IommuError::NoMapping)?;
        self.mappings[slot] = None;
        Ok(())
    }

    pub fn translate(
        &self,
        key: DomainKey,
        device: DeviceId,
        iova: u64,
        access: Access,
    ) -> Result<u64, IommuError> {
        self.check_domain(key)?;
        if !self.enabled {
            return Err(IommuError::AccessDenied);
        }
        let binding = self.binding(device)?;
        let mapping = self
            .mappings
            .iter()
            .flatten()
            .find(|mapping| {
                mapping.sid == device.sid()
                    && mapping.device_generation == device.generation
                    && mapping.device_epoch == binding.epoch
                    && mapping.contains(iova)
            })
            .ok_or(IommuError::NoMapping)?;
        if access == Access::Write && !mapping.writable {
            return Err(IommuError::AccessDenied);
        }
        mapping.translate(iova).ok_or(IommuError::NoMapping)
    }

    pub fn map_irq(&mut self, key: DomainKey, request: IrqRequest) -> Result<(), IommuError> {
        self.check_domain(key)?;
        let binding = self.require_device(request.device)?;
        if usize::from(request.target_cpu) >= MAX_CPUS
            || self.irqs.iter().flatten().any(|entry| {
                entry.sid == request.device.sid() && entry.route.source == request.source
            })
        {
            return Err(IommuError::IrqConflict);
        }
        let slot = self
            .irqs
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or(IommuError::Capacity)?;
        *slot = Some(IrqBinding {
            sid: request.device.sid(),
            device_generation: request.device.generation,
            route: IrqRoute {
                source: request.source,
                target_cpu: request.target_cpu,
                vector: request.vector,
                device_epoch: binding.epoch,
            },
        });
        Ok(())
    }

    pub fn translate_irq(
        &self,
        key: DomainKey,
        device: DeviceId,
        source: u32,
    ) -> Result<IrqRoute, IommuError> {
        self.check_domain(key)?;
        let binding = self.binding(device)?;
        self.irqs
            .iter()
            .flatten()
            .find(|entry| {
                entry.sid == device.sid()
                    && entry.device_generation == device.generation
                    && entry.route.device_epoch == binding.epoch
                    && entry.route.source == source
            })
            .map(|entry| entry.route)
            .ok_or(IommuError::NoMapping)
    }

    pub fn set_enabled(&mut self, key: DomainKey, enabled: bool) -> Result<usize, IommuError> {
        self.check_domain(key)?;
        self.enabled = enabled;
        if enabled {
            return Ok(0);
        }
        let cleared = self.mappings.iter().flatten().count();
        self.mappings.fill(None);
        self.irqs.fill(None);
        Ok(cleared)
    }

    pub fn reset_device(&mut self, key: DomainKey, device: DeviceId) -> Result<usize, IommuError> {
        self.check_domain(key)?;
        let slot = self.device_slot(device)?;
        let mut cleared = 0;
        for mapping in &mut self.mappings {
            if mapping.is_some_and(|mapping| mapping.sid == device.sid()) {
                *mapping = None;
                cleared += 1;
            }
        }
        for irq in &mut self.irqs {
            if irq.is_some_and(|irq| irq.sid == device.sid()) {
                *irq = None;
                cleared += 1;
            }
        }
        let binding = self.devices[slot]
            .as_mut()
            .ok_or(IommuError::DeviceNotBound)?;
        binding.active = false;
        binding.epoch = binding.epoch.saturating_add(1);
        Ok(cleared)
    }

    pub fn reset(&mut self) -> Result<DomainKey, IommuError> {
        let generation = self
            .key
            .generation
            .checked_add(1)
            .ok_or(IommuError::Capacity)?;
        self.key.generation = generation;
        self.devices.fill(None);
        self.mappings.fill(None);
        self.irqs.fill(None);
        Ok(self.key)
    }

    pub fn active_devices(&self) -> usize {
        self.devices
            .iter()
            .flatten()
            .filter(|binding| binding.active)
            .count()
    }

    pub fn active_mappings(&self) -> usize {
        self.mappings.iter().flatten().count()
    }

    fn check_domain(&self, key: DomainKey) -> Result<(), IommuError> {
        if key == self.key {
            Ok(())
        } else if key.id == self.key.id {
            Err(IommuError::StaleDomain)
        } else {
            Err(IommuError::InvalidDomain)
        }
    }

    fn require_device(&self, device: DeviceId) -> Result<DeviceBinding, IommuError> {
        self.binding(device).map_err(|error| {
            if error == IommuError::DeviceNotBound {
                IommuError::StaleDevice
            } else {
                error
            }
        })
    }

    fn binding(&self, device: DeviceId) -> Result<DeviceBinding, IommuError> {
        self.devices
            .iter()
            .flatten()
            .find(|binding| {
                binding.active
                    && binding.device.sid() == device.sid()
                    && binding.device.generation == device.generation
            })
            .copied()
            .ok_or(IommuError::DeviceNotBound)
    }

    fn device_slot(&self, device: DeviceId) -> Result<usize, IommuError> {
        self.devices
            .iter()
            .enumerate()
            .find(|(_, binding)| {
                binding.is_some_and(|binding| {
                    binding.active
                        && binding.device.sid() == device.sid()
                        && binding.device.generation == device.generation
                })
            })
            .map(|(index, _)| index)
            .ok_or(IommuError::DeviceNotBound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain() -> IommuDomain<4, 16, 8> {
        IommuDomain::new(DomainKey {
            id: 1,
            generation: 1,
        })
        .unwrap()
    }

    fn device() -> DeviceId {
        DeviceId {
            segment: 0,
            bus: 1,
            device: 2,
            function: 0,
            generation: 1,
        }
    }

    fn mapping(iova: u64, guest_phys: u64, pages: u64, writable: bool) -> MappingRequest {
        MappingRequest {
            device: device(),
            iova,
            guest_phys,
            pages,
            writable,
        }
    }

    #[test]
    fn exclusive_binding_mapping_permissions_and_identity_translation() {
        let mut iommu = domain();
        let key = iommu.key();
        iommu.bind(key, device()).unwrap();
        assert_eq!(iommu.bind(key, device()), Err(IommuError::DeviceBound));
        iommu
            .map(key, mapping(0x1_0000, 0x20_0000, 4, false))
            .unwrap();
        assert_eq!(
            iommu.translate(key, device(), 0x1_0100, Access::Read),
            Ok(0x20_0100)
        );
        assert_eq!(
            iommu.translate(key, device(), 0x1_0100, Access::Write),
            Err(IommuError::AccessDenied)
        );
        assert_eq!(iommu.unmap(key, device(), 0x1_0000, 4), Ok(()));
        assert_eq!(
            iommu.translate(key, device(), 0x1_0100, Access::Read),
            Err(IommuError::NoMapping)
        );
    }

    #[test]
    fn overlap_alignment_and_stale_device_generation_fail_atomically() {
        let mut iommu = domain();
        let key = iommu.key();
        iommu.bind(key, device()).unwrap();
        iommu
            .map(key, mapping(0x1_0000, 0x20_0000, 2, true))
            .unwrap();
        let before = iommu.active_mappings();
        assert_eq!(
            iommu.map(key, mapping(0x1_1000, 0x30_0000, 1, true)),
            Err(IommuError::Overlap)
        );
        assert_eq!(
            iommu.map(key, mapping(0x1_0001, 0x30_0000, 1, true)),
            Err(IommuError::InvalidMapping)
        );
        let stale = DeviceId {
            generation: 2,
            ..device()
        };
        assert_eq!(
            iommu.map(
                key,
                MappingRequest {
                    device: stale,
                    ..mapping(0x2_0000, 0x40_0000, 1, true)
                }
            ),
            Err(IommuError::StaleDevice)
        );
        assert_eq!(iommu.active_mappings(), before);
    }

    #[test]
    fn interrupt_remapping_is_bound_unique_and_removed_by_device_reset() {
        let mut iommu = domain();
        let key = iommu.key();
        iommu.bind(key, device()).unwrap();
        iommu
            .map_irq(
                key,
                IrqRequest {
                    device: device(),
                    source: 10,
                    target_cpu: 1,
                    vector: 48,
                },
            )
            .unwrap();
        assert_eq!(
            iommu.map_irq(
                key,
                IrqRequest {
                    device: device(),
                    source: 10,
                    target_cpu: 2,
                    vector: 49,
                }
            ),
            Err(IommuError::IrqConflict)
        );
        assert_eq!(
            iommu.translate_irq(key, device(), 10),
            Ok(IrqRoute {
                source: 10,
                target_cpu: 1,
                vector: 48,
                device_epoch: 1,
            })
        );
        assert_eq!(iommu.reset_device(key, device()), Ok(1));
        assert_eq!(
            iommu.translate_irq(key, device(), 10),
            Err(IommuError::DeviceNotBound)
        );
    }

    #[test]
    fn disabling_or_resetting_domain_revokes_all_dma_access() {
        let mut iommu = domain();
        let key = iommu.key();
        iommu.bind(key, device()).unwrap();
        iommu
            .map(key, mapping(0x1_0000, 0x20_0000, 1, true))
            .unwrap();
        assert_eq!(iommu.set_enabled(key, false), Ok(1));
        assert_eq!(
            iommu.translate(key, device(), 0x1_0000, Access::Read),
            Err(IommuError::AccessDenied)
        );
        iommu.set_enabled(key, true).unwrap();
        assert_eq!(iommu.active_mappings(), 0);
        iommu
            .map(key, mapping(0x1_0000, 0x20_0000, 1, true))
            .unwrap();
        let next = iommu.reset().unwrap();
        assert_eq!(next.generation, key.generation + 1);
        assert_eq!(
            iommu.translate(key, device(), 0x1_0000, Access::Read),
            Err(IommuError::StaleDomain)
        );
        assert_eq!(iommu.active_devices(), 0);
        assert_eq!(iommu.active_mappings(), 0);
    }
}
