//! SEC-4 bounded security-domain and cross-domain gateway model.
//!
//! Domains own resources. Objects are invisible across domains unless an
//! explicit, channel-specific gateway grant exists. Every cross-domain result
//! is audited; losing audit capacity makes the operation fail closed.

/// Domain workload class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainKind {
    Application,
    Service,
    Vm,
    Device,
}

/// Domain lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainState {
    Active,
    Compromised,
    Dead,
}

/// Stable domain slot plus a restart generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DomainKey {
    pub id: u32,
    pub generation: u32,
}

impl DomainKey {
    pub const NONE: Self = Self {
        id: 0,
        generation: 0,
    };

    pub const fn is_valid(self) -> bool {
        self.id != 0 && self.generation != 0
    }
}

/// Cross-domain channels are explicit and non-interchangeable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatewayKind {
    File,
    Clipboard,
    Network,
    Ipc,
    Device,
    Service,
}

/// Gateway grant identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GatewayId(pub u32);

/// Resource identity outside the domain model. The kernel connects this to its
/// own object/handle identity; this module treats it as opaque.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DomainResource {
    pub object: u64,
    pub rights: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Allowed,
    Denied,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainError {
    InvalidDomain,
    InvalidResource,
    InvalidGateway,
    Capacity,
    NotActive,
    RightsDenied,
    AlreadyAttached,
    AuditFull,
    IdExhausted,
}

impl DomainError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidDomain => "system.domain.error.invalid",
            Self::InvalidResource => "system.domain.error.resource",
            Self::InvalidGateway => "system.domain.error.gateway",
            Self::Capacity => "system.domain.error.capacity",
            Self::NotActive => "system.domain.error.not_active",
            Self::RightsDenied => "system.domain.error.rights_denied",
            Self::AlreadyAttached => "system.domain.error.already_attached",
            Self::AuditFull => "system.domain.error.audit_full",
            Self::IdExhausted => "system.domain.error.ids_exhausted",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Domain {
    key: DomainKey,
    kind: DomainKind,
    state: DomainState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Resource {
    resource: DomainResource,
    owner: DomainKey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Gateway {
    id: GatewayId,
    object: u64,
    source: DomainKey,
    target: DomainKey,
    channel: GatewayKind,
    rights: u32,
}

/// Auditable decision for one domain boundary operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DomainAudit {
    pub actor: DomainKey,
    pub owner: DomainKey,
    pub object: u64,
    pub channel: Option<GatewayKind>,
    pub requested: u32,
    pub decision: Access,
}

/// Fixed-capacity domain table. No operation partially mutates on error.
pub struct DomainTable<
    const DOMAINS: usize,
    const RESOURCES: usize,
    const GATEWAYS: usize,
    const AUDIT: usize,
> {
    domains: [Option<Domain>; DOMAINS],
    resources: [Option<Resource>; RESOURCES],
    gateways: [Option<Gateway>; GATEWAYS],
    audit: [Option<DomainAudit>; AUDIT],
    audit_len: usize,
    audit_overflow: u64,
    next_domain: u32,
    next_gateway: u32,
}

impl<const DOMAINS: usize, const RESOURCES: usize, const GATEWAYS: usize, const AUDIT: usize>
    DomainTable<DOMAINS, RESOURCES, GATEWAYS, AUDIT>
{
    pub const fn new() -> Self {
        Self {
            domains: [None; DOMAINS],
            resources: [None; RESOURCES],
            gateways: [None; GATEWAYS],
            audit: [None; AUDIT],
            audit_len: 0,
            audit_overflow: 0,
            next_domain: 1,
            next_gateway: 1,
        }
    }

    pub fn create(&mut self, kind: DomainKind) -> Result<DomainKey, DomainError> {
        let slot = self
            .domains
            .iter()
            .position(Option::is_none)
            .ok_or(DomainError::Capacity)?;
        let id = self.next_domain;
        self.next_domain = id.checked_add(1).ok_or(DomainError::IdExhausted)?;
        let key = DomainKey { id, generation: 1 };
        self.domains[slot] = Some(Domain {
            key,
            kind,
            state: DomainState::Active,
        });
        Ok(key)
    }

    pub fn state(&self, key: DomainKey) -> Option<DomainState> {
        self.domain(key).map(|domain| domain.state)
    }

    /// Attach one opaque object to an active domain. Resources cannot be
    /// attached twice and are always owned by exactly one domain.
    pub fn attach(
        &mut self,
        owner: DomainKey,
        resource: DomainResource,
    ) -> Result<(), DomainError> {
        self.require_active(owner)?;
        if resource.object == 0 || self.resource(resource.object).is_some() {
            return Err(if resource.object == 0 {
                DomainError::InvalidResource
            } else {
                DomainError::AlreadyAttached
            });
        }
        let slot = self
            .resources
            .iter()
            .position(Option::is_none)
            .ok_or(DomainError::Capacity)?;
        self.resources[slot] = Some(Resource { resource, owner });
        Ok(())
    }

    /// Same-domain access remains subject to resource rights but never needs a
    /// gateway. Every cross-domain request is deny-by-default.
    pub fn access(
        &mut self,
        actor: DomainKey,
        object: u64,
        channel: GatewayKind,
        requested: u32,
    ) -> Result<Access, DomainError> {
        let resource = self.resource(object).ok_or(DomainError::InvalidResource)?;
        let decision = if !self.domain_active(actor) || !self.domain_active(resource.owner) {
            Access::Denied
        } else if actor == resource.owner {
            if resource.resource.rights & requested == requested {
                Access::Allowed
            } else {
                Access::Denied
            }
        } else if self.gateway(actor, resource.owner, object, channel, requested) {
            Access::Allowed
        } else {
            Access::Denied
        };
        self.record(DomainAudit {
            actor,
            owner: resource.owner,
            object,
            channel: if actor == resource.owner {
                None
            } else {
                Some(channel)
            },
            requested,
            decision,
        })?;
        Ok(decision)
    }

    /// Authorize one channel from an active source domain to the owner of an
    /// active target resource. Rights can only narrow the resource rights.
    pub fn grant(
        &mut self,
        source: DomainKey,
        object: u64,
        channel: GatewayKind,
        rights: u32,
    ) -> Result<GatewayId, DomainError> {
        self.require_active(source)?;
        let resource = self.resource(object).ok_or(DomainError::InvalidResource)?;
        self.require_active(resource.owner)?;
        if rights == 0 || resource.resource.rights & rights != rights {
            return Err(DomainError::RightsDenied);
        }
        let slot = self
            .gateways
            .iter()
            .position(Option::is_none)
            .ok_or(DomainError::Capacity)?;
        let id = GatewayId(self.next_gateway);
        self.next_gateway = self
            .next_gateway
            .checked_add(1)
            .ok_or(DomainError::IdExhausted)?;
        self.gateways[slot] = Some(Gateway {
            id,
            object,
            source,
            target: resource.owner,
            channel,
            rights,
        });
        Ok(id)
    }

    pub fn revoke_gateway(&mut self, id: GatewayId) -> Result<(), DomainError> {
        let slot = self
            .gateways
            .iter()
            .position(|gateway| gateway.is_some_and(|gateway| gateway.id == id))
            .ok_or(DomainError::InvalidGateway)?;
        self.gateways[slot] = None;
        Ok(())
    }

    /// Compromise revokes all inbound/outbound gateways and detaches every
    /// object owned by the domain. Other domains and their resources remain.
    pub fn compromise(&mut self, key: DomainKey) -> Result<usize, DomainError> {
        let slot = self.domain_slot(key).ok_or(DomainError::InvalidDomain)?;
        if self.domains[slot].is_some_and(|domain| domain.state != DomainState::Active) {
            return Err(DomainError::NotActive);
        }
        self.domains[slot].as_mut().unwrap().state = DomainState::Compromised;
        Ok(self.detach_boundary(key))
    }

    /// Crash has the same conservative boundary as compromise but records a
    /// distinct terminal state. Other domains are untouched.
    pub fn crash(&mut self, key: DomainKey) -> Result<usize, DomainError> {
        let slot = self.domain_slot(key).ok_or(DomainError::InvalidDomain)?;
        if self.domains[slot].is_some_and(|domain| domain.state != DomainState::Active) {
            return Err(DomainError::NotActive);
        }
        self.domains[slot].as_mut().unwrap().state = DomainState::Dead;
        Ok(self.detach_boundary(key))
    }

    /// Restart keeps the slot id but increments generation. Old resources and
    /// old gateway grants can never become valid for the new generation.
    pub fn restart(&mut self, key: DomainKey) -> Result<DomainKey, DomainError> {
        let slot = self.domain_slot(key).ok_or(DomainError::InvalidDomain)?;
        let domain = self.domains[slot].as_mut().unwrap();
        if domain.state == DomainState::Active {
            return Err(DomainError::NotActive);
        }
        let generation = domain
            .key
            .generation
            .checked_add(1)
            .ok_or(DomainError::IdExhausted)?;
        domain.key.generation = generation;
        domain.state = DomainState::Active;
        Ok(domain.key)
    }

    pub fn active_domains(&self) -> usize {
        self.domains
            .iter()
            .flatten()
            .filter(|domain| domain.state == DomainState::Active)
            .count()
    }

    pub fn attached_resources(&self) -> usize {
        self.resources.iter().flatten().count()
    }

    pub fn active_gateways(&self) -> usize {
        self.gateways.iter().flatten().count()
    }

    pub fn audit_overflow(&self) -> u64 {
        self.audit_overflow
    }

    pub fn audit_events(&self) -> impl Iterator<Item = DomainAudit> + '_ {
        (0..self.audit_len).filter_map(move |offset| self.audit[offset])
    }

    fn detach_boundary(&mut self, key: DomainKey) -> usize {
        let mut reclaimed = 0;
        for gateway in &mut self.gateways {
            if gateway.is_some_and(|gateway| gateway.source == key || gateway.target == key) {
                *gateway = None;
                reclaimed += 1;
            }
        }
        for resource in &mut self.resources {
            if resource.is_some_and(|resource| resource.owner == key) {
                *resource = None;
                reclaimed += 1;
            }
        }
        reclaimed
    }

    fn gateway(
        &self,
        source: DomainKey,
        target: DomainKey,
        object: u64,
        channel: GatewayKind,
        rights: u32,
    ) -> bool {
        self.gateways.iter().flatten().any(|gateway| {
            gateway.object == object
                && gateway.source == source
                && gateway.target == target
                && gateway.channel == channel
                && gateway.rights & rights == rights
        })
    }

    fn record(&mut self, event: DomainAudit) -> Result<(), DomainError> {
        if AUDIT == 0 || self.audit_len == AUDIT {
            self.audit_overflow = self.audit_overflow.saturating_add(1);
            return Err(DomainError::AuditFull);
        }
        self.audit[self.audit_len] = Some(event);
        self.audit_len += 1;
        Ok(())
    }

    fn require_active(&self, key: DomainKey) -> Result<(), DomainError> {
        match self.state(key) {
            Some(DomainState::Active) => Ok(()),
            Some(_) => Err(DomainError::NotActive),
            None => Err(DomainError::InvalidDomain),
        }
    }

    fn domain_active(&self, key: DomainKey) -> bool {
        self.state(key) == Some(DomainState::Active)
    }

    fn domain(&self, key: DomainKey) -> Option<Domain> {
        self.domains
            .iter()
            .flatten()
            .find(|domain| domain.key == key)
            .copied()
    }

    fn domain_slot(&self, key: DomainKey) -> Option<usize> {
        self.domains
            .iter()
            .position(|domain| domain.is_some_and(|domain| domain.key == key))
    }

    fn resource(&self, object: u64) -> Option<Resource> {
        self.resources
            .iter()
            .flatten()
            .find(|resource| resource.resource.object == object)
            .copied()
    }
}

impl<const DOMAINS: usize, const RESOURCES: usize, const GATEWAYS: usize, const AUDIT: usize>
    Default for DomainTable<DOMAINS, RESOURCES, GATEWAYS, AUDIT>
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const R: u32 = 1;
    const W: u32 = 2;

    fn table() -> DomainTable<8, 16, 16, 64> {
        DomainTable::new()
    }

    #[test]
    fn cross_domain_access_is_deny_by_default() {
        let mut t = table();
        let a = t.create(DomainKind::Application).unwrap();
        let b = t.create(DomainKind::Vm).unwrap();
        t.attach(
            a,
            DomainResource {
                object: 10,
                rights: R | W,
            },
        )
        .unwrap();
        assert_eq!(t.access(b, 10, GatewayKind::File, R), Ok(Access::Denied));
        assert_eq!(t.access(a, 10, GatewayKind::File, W), Ok(Access::Allowed));
    }

    #[test]
    fn each_gateway_is_explicit_and_audited() {
        let mut t = table();
        let a = t.create(DomainKind::Application).unwrap();
        let b = t.create(DomainKind::Service).unwrap();
        for (object, channel) in [
            (10, GatewayKind::File),
            (11, GatewayKind::Clipboard),
            (12, GatewayKind::Network),
            (13, GatewayKind::Ipc),
            (14, GatewayKind::Device),
            (15, GatewayKind::Service),
        ] {
            t.attach(a, DomainResource { object, rights: R }).unwrap();
            t.grant(b, object, channel, R).unwrap();
            assert_eq!(t.access(b, object, channel, R), Ok(Access::Allowed));
        }
        assert_eq!(
            t.audit_events()
                .filter(|event| event.decision == Access::Allowed)
                .count(),
            6
        );
    }

    #[test]
    fn wrong_channel_or_rights_do_not_cross() {
        let mut t = table();
        let a = t.create(DomainKind::Application).unwrap();
        let b = t.create(DomainKind::Vm).unwrap();
        t.attach(
            a,
            DomainResource {
                object: 20,
                rights: R | W,
            },
        )
        .unwrap();
        t.grant(b, 20, GatewayKind::File, R).unwrap();
        assert_eq!(
            t.access(b, 20, GatewayKind::Clipboard, R),
            Ok(Access::Denied)
        );
        assert_eq!(t.access(b, 20, GatewayKind::File, W), Ok(Access::Denied));
        assert_eq!(
            t.grant(b, 20, GatewayKind::File, W | 4),
            Err(DomainError::RightsDenied)
        );
        t.attach(
            a,
            DomainResource {
                object: 21,
                rights: R,
            },
        )
        .unwrap();
        assert_eq!(t.access(b, 21, GatewayKind::File, R), Ok(Access::Denied));
    }

    #[test]
    fn compromise_revokes_only_its_boundary() {
        let mut t = table();
        let a = t.create(DomainKind::Application).unwrap();
        let b = t.create(DomainKind::Service).unwrap();
        t.attach(
            a,
            DomainResource {
                object: 30,
                rights: R,
            },
        )
        .unwrap();
        t.attach(
            b,
            DomainResource {
                object: 31,
                rights: R,
            },
        )
        .unwrap();
        t.grant(b, 30, GatewayKind::Ipc, R).unwrap();
        assert_eq!(t.compromise(a), Ok(2));
        assert_eq!(
            t.access(b, 30, GatewayKind::Ipc, R),
            Err(DomainError::InvalidResource)
        );
        assert_eq!(t.access(b, 31, GatewayKind::Ipc, R), Ok(Access::Allowed));
        assert_eq!(t.access(a, 31, GatewayKind::Ipc, R), Ok(Access::Denied));
    }

    #[test]
    fn restart_generation_cannot_reuse_old_authority() {
        let mut t = table();
        let a = t.create(DomainKind::Application).unwrap();
        let b = t.create(DomainKind::Vm).unwrap();
        t.attach(
            a,
            DomainResource {
                object: 40,
                rights: R,
            },
        )
        .unwrap();
        let gateway = t.grant(b, 40, GatewayKind::File, R).unwrap();
        t.crash(a).unwrap();
        let restarted = t.restart(a).unwrap();
        assert_eq!(restarted.id, a.id);
        assert!(restarted.generation > a.generation);
        assert_eq!(
            t.access(b, 40, GatewayKind::File, R),
            Err(DomainError::InvalidResource)
        );
        assert_eq!(t.revoke_gateway(gateway), Err(DomainError::InvalidGateway));
        assert_eq!(t.state(b), Some(DomainState::Active));
    }

    #[test]
    fn capacity_and_audit_failures_leave_authority_unchanged() {
        let mut t: DomainTable<1, 1, 1, 1> = DomainTable::new();
        let a = t.create(DomainKind::Application).unwrap();
        let b = t.create(DomainKind::Device).unwrap_err();
        assert_eq!(b, DomainError::Capacity);
        t.attach(
            a,
            DomainResource {
                object: 50,
                rights: R,
            },
        )
        .unwrap();
        assert_eq!(
            t.attach(
                a,
                DomainResource {
                    object: 51,
                    rights: R
                }
            ),
            Err(DomainError::Capacity)
        );
        assert_eq!(t.access(a, 50, GatewayKind::File, R), Ok(Access::Allowed));
        assert_eq!(
            t.access(a, 50, GatewayKind::File, R),
            Err(DomainError::AuditFull)
        );
        assert_eq!(t.audit_overflow(), 1);
        assert_eq!(t.active_domains(), 1);
        assert_eq!(t.attached_resources(), 1);
    }
}
