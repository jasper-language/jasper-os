//! Unified policy enforcement for HWV-5 device and VMM surfaces.
//!
//! 职责：在 PIO、网络、文件与 VMM 效果前统一检查对象世代、能力 Rights、
//! 域委托、MAC 标签和可靠审计。边界：不解析设备协议、不执行设备动作。
//! Responsibility: one fail-closed policy decision across VM device surfaces.
//! Protocol parsing and backend effects remain outside this policy point.

use crate::mac::{class_bit, MacLabel, MAC_LABEL_VERSION, OBJECT_CLASS_ALL};
use crate::security::IdentityClass;
use crate::security_domain::DomainKey;

pub const READ: u32 = 1 << 0;
pub const WRITE: u32 = 1 << 1;
pub const CONTROL: u32 = 1 << 2;
pub const RESET: u32 = 1 << 3;
pub const DMA: u32 = 1 << 4;
pub const VM_ENTER: u32 = 1 << 5;
pub const DELEGATE: u32 = 1 << 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hwv5Surface {
    Pio,
    Net,
    Fs,
    Vmm,
}

impl Hwv5Surface {
    pub const fn allowed_rights(self) -> u32 {
        match self {
            Self::Pio => READ | WRITE | CONTROL | DELEGATE,
            Self::Net => READ | WRITE | CONTROL | RESET | DMA | DELEGATE,
            Self::Fs => READ | WRITE | CONTROL | RESET | DMA | DELEGATE,
            Self::Vmm => READ | WRITE | CONTROL | RESET | DMA | VM_ENTER | DELEGATE,
        }
    }

    pub const fn identity_class(self) -> IdentityClass {
        match self {
            Self::Pio | Self::Net | Self::Fs => IdentityClass::Device,
            Self::Vmm => IdentityClass::Vcpu,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hwv5Effect {
    Observe,
    Read,
    Write,
    Control,
    Delegate,
}

impl Hwv5Effect {
    pub const fn required_right(self) -> u32 {
        match self {
            Self::Observe | Self::Read => READ,
            Self::Write => WRITE,
            Self::Control => CONTROL,
            Self::Delegate => DELEGATE,
        }
    }

    const fn requires_integrity(self) -> bool {
        matches!(self, Self::Write | Self::Control | Self::Delegate)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hwv5Deny {
    InvalidSubject,
    InvalidResource,
    StaleGeneration,
    SurfaceMismatch,
    Rights,
    DomainDelegation,
    Label,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hwv5Decision {
    Allowed,
    Denied(Hwv5Deny),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hwv5PepError {
    InvalidDomain,
    InvalidResource,
    DuplicateObject,
    Capacity,
    Rights,
    AuditFull,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hwv5Subject {
    pub domain: DomainKey,
    pub label: MacLabel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hwv5Resource {
    pub object: u64,
    pub generation: u32,
    pub owner: DomainKey,
    pub surface: Hwv5Surface,
    pub label: MacLabel,
    pub rights: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hwv5Request {
    pub object: u64,
    pub generation: u32,
    pub surface: Hwv5Surface,
    pub rights: u32,
    pub effect: Hwv5Effect,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hwv5Audit {
    pub actor: DomainKey,
    pub owner: DomainKey,
    pub object: u64,
    pub generation: u32,
    pub surface: Hwv5Surface,
    pub requested: u32,
    pub effect: Hwv5Effect,
    pub decision: Hwv5Decision,
    pub resource_epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Binding {
    resource: Hwv5Resource,
    epoch: u64,
    active: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Delegation {
    object: u64,
    generation: u32,
    target: DomainKey,
    rights: u32,
    resource_epoch: u64,
}

pub struct Hwv5Pep<const RESOURCES: usize, const DELEGATIONS: usize, const AUDIT: usize> {
    resources: [Option<Binding>; RESOURCES],
    delegations: [Option<Delegation>; DELEGATIONS],
    audit: [Option<Hwv5Audit>; AUDIT],
    audit_len: usize,
    audit_overflow: u64,
}

impl<const RESOURCES: usize, const DELEGATIONS: usize, const AUDIT: usize>
    Hwv5Pep<RESOURCES, DELEGATIONS, AUDIT>
{
    pub const fn new() -> Self {
        Self {
            resources: [None; RESOURCES],
            delegations: [None; DELEGATIONS],
            audit: [None; AUDIT],
            audit_len: 0,
            audit_overflow: 0,
        }
    }

    pub fn register(&mut self, resource: Hwv5Resource) -> Result<(), Hwv5PepError> {
        if !resource.owner.is_valid() {
            return Err(Hwv5PepError::InvalidDomain);
        }
        if resource.object == 0
            || resource.generation == 0
            || resource.rights == 0
            || resource.rights & !resource.surface.allowed_rights() != 0
            || !valid_label(resource.label, resource.surface.identity_class())
        {
            return Err(Hwv5PepError::InvalidResource);
        }
        if self
            .resources
            .iter()
            .flatten()
            .any(|binding| binding.resource.object == resource.object)
        {
            return Err(Hwv5PepError::DuplicateObject);
        }
        let slot = self
            .resources
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or(Hwv5PepError::Capacity)?;
        *slot = Some(Binding {
            resource,
            epoch: 1,
            active: true,
        });
        Ok(())
    }

    pub fn delegate(
        &mut self,
        source: DomainKey,
        target: DomainKey,
        object: u64,
        generation: u32,
        rights: u32,
    ) -> Result<(), Hwv5PepError> {
        if !source.is_valid() || !target.is_valid() || source == target {
            return Err(Hwv5PepError::InvalidDomain);
        }
        let binding = self
            .resources
            .iter()
            .flatten()
            .find(|binding| {
                binding.active
                    && binding.resource.object == object
                    && binding.resource.generation == generation
            })
            .copied()
            .ok_or(Hwv5PepError::InvalidResource)?;
        if binding.resource.owner != source
            || rights == 0
            || binding.resource.rights & rights != rights
        {
            return Err(Hwv5PepError::Rights);
        }
        if let Some(existing) = self.delegations.iter_mut().flatten().find(|delegation| {
            delegation.object == object
                && delegation.generation == generation
                && delegation.target == target
                && delegation.resource_epoch == binding.epoch
        }) {
            existing.rights = rights;
            return Ok(());
        }
        let slot = self
            .delegations
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or(Hwv5PepError::Capacity)?;
        *slot = Some(Delegation {
            object,
            generation,
            target,
            rights,
            resource_epoch: binding.epoch,
        });
        Ok(())
    }

    pub fn authorize(
        &mut self,
        subject: Hwv5Subject,
        request: Hwv5Request,
    ) -> Result<Hwv5Decision, Hwv5PepError> {
        let binding = self
            .resources
            .iter()
            .flatten()
            .find(|binding| binding.resource.object == request.object)
            .copied();
        let decision = self.evaluate(subject, request, binding);
        let (owner, epoch) = binding.map_or((DomainKey::NONE, 0), |binding| {
            (binding.resource.owner, binding.epoch)
        });
        self.record(Hwv5Audit {
            actor: subject.domain,
            owner,
            object: request.object,
            generation: request.generation,
            surface: request.surface,
            requested: request.rights,
            effect: request.effect,
            decision,
            resource_epoch: epoch,
        })?;
        Ok(decision)
    }

    pub fn revoke(&mut self, object: u64) -> Result<usize, Hwv5PepError> {
        let binding = self
            .resources
            .iter_mut()
            .flatten()
            .find(|binding| binding.active && binding.resource.object == object)
            .ok_or(Hwv5PepError::InvalidResource)?;
        binding.active = false;
        binding.epoch = binding.epoch.checked_add(1).ok_or(Hwv5PepError::Capacity)?;
        let mut removed = 0;
        for delegation in &mut self.delegations {
            if delegation.is_some_and(|delegation| delegation.object == object) {
                *delegation = None;
                removed += 1;
            }
        }
        Ok(removed)
    }

    pub fn reset_surface(&mut self, surface: Hwv5Surface) -> usize {
        let mut revoked = 0;
        for binding in self.resources.iter_mut().flatten() {
            if binding.active && binding.resource.surface == surface {
                binding.active = false;
                binding.epoch = binding.epoch.saturating_add(1);
                revoked += 1;
            }
        }
        for delegation in &mut self.delegations {
            if delegation.is_some_and(|delegation| {
                self.resources
                    .iter()
                    .flatten()
                    .find(|binding| binding.resource.object == delegation.object)
                    .is_none_or(|binding| binding.resource.surface == surface)
            }) {
                *delegation = None;
            }
        }
        revoked
    }

    pub fn active_resources(&self) -> usize {
        self.resources
            .iter()
            .flatten()
            .filter(|binding| binding.active)
            .count()
    }

    pub fn audit_events(&self) -> impl Iterator<Item = Hwv5Audit> + '_ {
        (0..self.audit_len).filter_map(move |index| self.audit[index])
    }

    pub const fn audit_overflow(&self) -> u64 {
        self.audit_overflow
    }

    fn evaluate(
        &self,
        subject: Hwv5Subject,
        request: Hwv5Request,
        binding: Option<Binding>,
    ) -> Hwv5Decision {
        use Hwv5Decision::{Allowed, Denied};
        if !subject.domain.is_valid()
            || !valid_label(subject.label, request.surface.identity_class())
        {
            return Denied(Hwv5Deny::InvalidSubject);
        }
        let Some(binding) = binding else {
            return Denied(Hwv5Deny::InvalidResource);
        };
        if !binding.active || binding.resource.generation != request.generation {
            return Denied(Hwv5Deny::StaleGeneration);
        }
        if binding.resource.surface != request.surface {
            return Denied(Hwv5Deny::SurfaceMismatch);
        }
        if request.rights == 0
            || request.rights & !binding.resource.rights != 0
            || request.rights & request.effect.required_right() == 0
        {
            return Denied(Hwv5Deny::Rights);
        }
        let available = if binding.resource.owner == subject.domain {
            binding.resource.rights
        } else {
            self.delegations
                .iter()
                .flatten()
                .filter(|delegation| {
                    delegation.object == request.object
                        && delegation.generation == request.generation
                        && delegation.target == subject.domain
                        && delegation.resource_epoch == binding.epoch
                })
                .fold(0, |rights, delegation| rights | delegation.rights)
        };
        if available & request.rights != request.rights {
            return Denied(Hwv5Deny::DomainDelegation);
        }
        let secrecy_ok = subject.label.secrecy >= binding.resource.label.secrecy;
        let integrity_ok = !request.effect.requires_integrity()
            || subject.label.integrity >= binding.resource.label.integrity;
        if !secrecy_ok || !integrity_ok {
            return Denied(Hwv5Deny::Label);
        }
        Allowed
    }

    fn record(&mut self, event: Hwv5Audit) -> Result<(), Hwv5PepError> {
        if AUDIT == 0 || self.audit_len == AUDIT {
            self.audit_overflow = self.audit_overflow.saturating_add(1);
            return Err(Hwv5PepError::AuditFull);
        }
        self.audit[self.audit_len] = Some(event);
        self.audit_len += 1;
        Ok(())
    }
}

impl<const RESOURCES: usize, const DELEGATIONS: usize, const AUDIT: usize> Default
    for Hwv5Pep<RESOURCES, DELEGATIONS, AUDIT>
{
    fn default() -> Self {
        Self::new()
    }
}

fn valid_label(label: MacLabel, class: IdentityClass) -> bool {
    label.version == MAC_LABEL_VERSION
        && crate::mac::Secrecy::from_raw(label.secrecy).is_some()
        && crate::mac::Integrity::from_raw(label.integrity).is_some()
        && label.object_classes != 0
        && label.object_classes & !OBJECT_CLASS_ALL == 0
        && label.object_classes & class_bit(class) != 0
        && label.reserved == 0
        && label.domain.0 != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mac::{Integrity, Secrecy};
    use crate::security::SecurityDomain;

    const ALL: u32 = READ | WRITE | CONTROL | RESET | DMA | VM_ENTER | DELEGATE;

    fn domain(id: u32) -> DomainKey {
        DomainKey { id, generation: 1 }
    }

    fn label(class: IdentityClass, secrecy: Secrecy, integrity: Integrity) -> MacLabel {
        MacLabel::new(SecurityDomain::USER, secrecy, integrity, class_bit(class))
    }

    fn resource(object: u64, owner: DomainKey, surface: Hwv5Surface) -> Hwv5Resource {
        Hwv5Resource {
            object,
            generation: 1,
            owner,
            surface,
            label: label(
                surface.identity_class(),
                Secrecy::Internal,
                Integrity::Managed,
            ),
            rights: ALL & surface.allowed_rights(),
        }
    }

    fn subject(domain: DomainKey, class: IdentityClass) -> Hwv5Subject {
        Hwv5Subject {
            domain,
            label: label(class, Secrecy::Internal, Integrity::Managed),
        }
    }

    #[test]
    fn every_device_and_vmm_surface_uses_the_same_gate() {
        let owner = domain(1);
        let mut pep = Hwv5Pep::<4, 4, 16>::new();
        for (object, surface) in [
            (10, Hwv5Surface::Pio),
            (11, Hwv5Surface::Net),
            (12, Hwv5Surface::Fs),
            (13, Hwv5Surface::Vmm),
        ] {
            let binding = resource(object, owner, surface);
            pep.register(binding).unwrap();
            let decision = pep.authorize(
                subject(owner, surface.identity_class()),
                Hwv5Request {
                    object,
                    generation: 1,
                    surface,
                    rights: READ,
                    effect: Hwv5Effect::Read,
                },
            );
            assert_eq!(decision, Ok(Hwv5Decision::Allowed));
        }
        assert_eq!(pep.audit_events().count(), 4);
    }

    #[test]
    fn cross_domain_requires_exact_delegation_and_revocation_invalidates_it() {
        let owner = domain(1);
        let peer = domain(2);
        let mut pep = Hwv5Pep::<2, 4, 16>::new();
        pep.register(resource(20, owner, Hwv5Surface::Net)).unwrap();
        let request = Hwv5Request {
            object: 20,
            generation: 1,
            surface: Hwv5Surface::Net,
            rights: READ | WRITE,
            effect: Hwv5Effect::Write,
        };
        assert_eq!(
            pep.authorize(subject(peer, IdentityClass::Device), request),
            Ok(Hwv5Decision::Denied(Hwv5Deny::DomainDelegation))
        );
        pep.delegate(owner, peer, 20, 1, READ).unwrap();
        assert_eq!(
            pep.authorize(subject(peer, IdentityClass::Device), request),
            Ok(Hwv5Decision::Denied(Hwv5Deny::DomainDelegation))
        );
        pep.delegate(owner, peer, 20, 1, READ | WRITE).unwrap();
        assert_eq!(
            pep.authorize(subject(peer, IdentityClass::Device), request),
            Ok(Hwv5Decision::Allowed)
        );
        assert_eq!(pep.revoke(20), Ok(1));
        assert_eq!(
            pep.authorize(subject(peer, IdentityClass::Device), request),
            Ok(Hwv5Decision::Denied(Hwv5Deny::StaleGeneration))
        );
    }

    #[test]
    fn label_surface_generation_and_rights_checks_fail_closed() {
        let owner = domain(1);
        let mut pep = Hwv5Pep::<2, 2, 16>::new();
        let mut vmm = resource(30, owner, Hwv5Surface::Vmm);
        vmm.label = label(IdentityClass::Vcpu, Secrecy::Secret, Integrity::Trusted);
        pep.register(vmm).unwrap();
        let request = Hwv5Request {
            object: 30,
            generation: 1,
            surface: Hwv5Surface::Vmm,
            rights: WRITE,
            effect: Hwv5Effect::Write,
        };
        assert_eq!(
            pep.authorize(subject(owner, IdentityClass::Vcpu), request),
            Ok(Hwv5Decision::Denied(Hwv5Deny::Label))
        );
        let trusted = Hwv5Subject {
            domain: owner,
            label: label(IdentityClass::Vcpu, Secrecy::Secret, Integrity::Trusted),
        };
        assert_eq!(
            pep.authorize(
                subject(owner, IdentityClass::Device),
                Hwv5Request {
                    surface: Hwv5Surface::Net,
                    ..request
                }
            ),
            Ok(Hwv5Decision::Denied(Hwv5Deny::SurfaceMismatch))
        );
        assert_eq!(
            pep.authorize(
                trusted,
                Hwv5Request {
                    generation: 2,
                    ..request
                }
            ),
            Ok(Hwv5Decision::Denied(Hwv5Deny::StaleGeneration))
        );
        assert_eq!(
            pep.authorize(
                trusted,
                Hwv5Request {
                    rights: DMA,
                    effect: Hwv5Effect::Read,
                    ..request
                }
            ),
            Ok(Hwv5Decision::Denied(Hwv5Deny::Rights))
        );
    }

    #[test]
    fn audit_exhaustion_and_invalid_registration_are_atomic() {
        let owner = domain(1);
        let mut pep = Hwv5Pep::<2, 2, 1>::new();
        let valid = resource(40, owner, Hwv5Surface::Pio);
        pep.register(valid).unwrap();
        let request = Hwv5Request {
            object: 40,
            generation: 1,
            surface: Hwv5Surface::Pio,
            rights: READ,
            effect: Hwv5Effect::Read,
        };
        assert_eq!(
            pep.authorize(subject(owner, IdentityClass::Device), request),
            Ok(Hwv5Decision::Allowed)
        );
        assert_eq!(
            pep.authorize(subject(owner, IdentityClass::Device), request),
            Err(Hwv5PepError::AuditFull)
        );
        assert_eq!(pep.audit_overflow(), 1);
        assert_eq!(pep.audit_events().count(), 1);

        let bad = Hwv5Resource {
            object: 41,
            generation: 1,
            owner,
            surface: Hwv5Surface::Pio,
            label: label(IdentityClass::Device, Secrecy::Internal, Integrity::Managed),
            rights: DMA,
        };
        assert_eq!(pep.register(bad), Err(Hwv5PepError::InvalidResource));
        assert_eq!(pep.active_resources(), 1);
    }

    #[test]
    fn surface_reset_revokes_only_that_device_class() {
        let owner = domain(1);
        let mut pep = Hwv5Pep::<4, 4, 16>::new();
        pep.register(resource(50, owner, Hwv5Surface::Pio)).unwrap();
        pep.register(resource(51, owner, Hwv5Surface::Net)).unwrap();
        assert_eq!(pep.reset_surface(Hwv5Surface::Pio), 1);
        assert_eq!(pep.active_resources(), 1);
        assert_eq!(
            pep.authorize(
                subject(owner, IdentityClass::Device),
                Hwv5Request {
                    object: 50,
                    generation: 1,
                    surface: Hwv5Surface::Pio,
                    rights: READ,
                    effect: Hwv5Effect::Read,
                }
            ),
            Ok(Hwv5Decision::Denied(Hwv5Deny::StaleGeneration))
        );
        assert_eq!(
            pep.authorize(
                subject(owner, IdentityClass::Device),
                Hwv5Request {
                    object: 51,
                    generation: 1,
                    surface: Hwv5Surface::Net,
                    rights: READ,
                    effect: Hwv5Effect::Read,
                }
            ),
            Ok(Hwv5Decision::Allowed)
        );
    }
}
