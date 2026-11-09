//! Bounded capability graph for SEC-2.
//!
//! The graph is the authority-lifetime model behind handles.  It records the
//! object identity a capability names, its owner, its immutable parent edge,
//! current rights, in-flight users, revocation state and an explicit audit
//! trail.  Trees are created by delegation from an existing node; a node can
//! never name a different object or gain rights from its parent.
//!
//! The graph deliberately has no ambient allocation and no ambient authority:
//! callers must supply the exact [`ObjectIdentity`] and [`PrincipalId`].  All
//! mutating operations are serialized by the caller (the kernel object-table
//! lock in production).

use crate::{object::Rights, syscall_set::SyscallSet};
use crate::security::{BootId, IdentityClass, ObjectIdentity};

/// Opaque, monotonically allocated capability identity.  Zero is never valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CapabilityId(u64);

impl CapabilityId {
    /// The invalid/empty capability.
    pub const ZERO: Self = Self(0);

    /// Raw diagnostic encoding.  User code never receives this value as an
    /// authorization token; handles remain the only user-visible reference.
    pub const fn raw(self) -> u64 {
        self.0
    }

    pub(crate) const fn from_raw(raw: u64) -> Option<Self> {
        if raw == 0 {
            None
        } else {
            Some(Self(raw))
        }
    }

    pub const fn is_valid(self) -> bool {
        self.0 != 0
    }
}

/// Stable principal identity used by the graph.  This is intentionally
/// separate from a handle or PID: aliases may share a principal, while a
/// delegated capability may name a different principal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PrincipalId(u64);

impl PrincipalId {
    pub const fn new(raw: u64) -> Option<Self> {
        if raw == 0 {
            None
        } else {
            Some(Self(raw))
        }
    }

    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Current lifecycle state of one graph node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityState {
    Active,
    Revoked,
}

/// Per-handle graph metadata.  Handles remain the only user-visible token;
/// this record prevents a duplicate from becoming an unrelated authority root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityLink {
    pub id: CapabilityId,
    pub parent: Option<CapabilityId>,
    pub state: CapabilityState,
}

impl CapabilityLink {
    pub const fn root(id: CapabilityId) -> Self {
        Self {
            id,
            parent: None,
            state: CapabilityState::Active,
        }
    }

    pub const fn delegated(id: CapabilityId, parent: CapabilityId) -> Self {
        Self {
            id,
            parent: Some(parent),
            state: CapabilityState::Active,
        }
    }

    pub const fn is_active(self) -> bool {
        matches!(self.state, CapabilityState::Active)
    }
}

/// Graph operation failure.  No method changes the graph on error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityError {
    InvalidCapability,
    InvalidObject,
    InvalidOwner,
    RightsDenied,
    Revoked,
    CapacityExhausted,
    IdExhausted,
    DepthExhausted,
    InUse,
    HasDependents,
    ObjectMismatch,
    OwnerMismatch,
    UseInvalid,
    SyscallDenied,
    ServiceDenied,
    ProgramCapabilityDenied,
    SnapshotChanged,
}

impl CapabilityError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidCapability => "system.capability.error.invalid",
            Self::InvalidObject => "system.capability.error.invalid_object",
            Self::InvalidOwner => "system.capability.error.invalid_owner",
            Self::RightsDenied => "system.capability.error.rights_denied",
            Self::Revoked => "system.capability.error.revoked",
            Self::CapacityExhausted => "system.capability.error.capacity",
            Self::IdExhausted => "system.capability.error.ids_exhausted",
            Self::DepthExhausted => "system.capability.error.depth",
            Self::InUse => "system.capability.error.in_use",
            Self::HasDependents => "system.capability.error.has_dependents",
            Self::ObjectMismatch => "system.capability.error.object_mismatch",
            Self::OwnerMismatch => "system.capability.error.owner_mismatch",
            Self::UseInvalid => "system.capability.error.use_invalid",
            Self::SyscallDenied => "system.capability.error.syscall_denied",
            Self::ServiceDenied => "system.capability.error.service_denied",
            Self::ProgramCapabilityDenied => "system.capability.error.program_capability_denied",
            Self::SnapshotChanged => "system.capability.error.snapshot_changed",
        }
    }
}

/// One authority request expressed across every existing production gate.
///
/// This is a projection, not a new registry: handle rights remain owned by
/// `HandleTable`, syscall IDs by `SyscallSet`, service publication by
/// `ServiceGate`, and profile/program capabilities by the existing masks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorityRequest {
    pub rights: Rights,
    pub syscall: Option<u64>,
    pub service_bit: Option<u32>,
    pub program_bit: Option<u32>,
}

impl AuthorityRequest {
    pub const fn new(rights: Rights) -> Self {
        Self {
            rights,
            syscall: None,
            service_bit: None,
            program_bit: None,
        }
    }

    pub const fn with_syscall(mut self, id: u64) -> Self {
        self.syscall = Some(id);
        self
    }

    pub const fn with_service(mut self, bit: u32) -> Self {
        self.service_bit = Some(bit);
        self
    }

    pub const fn with_program_capability(mut self, bit: u32) -> Self {
        self.program_bit = Some(bit);
        self
    }
}

/// A pinned snapshot of all authority domains checked for one effect.
///
/// A changed rights set, syscall set, service publication mask or
/// profile/program capability mask invalidates an in-flight grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthoritySnapshot {
    pub rights: Rights,
    pub syscalls: SyscallSet,
    pub published_services: u32,
    pub program_capabilities: u32,
}

impl AuthoritySnapshot {
    pub const fn new(
        rights: Rights,
        syscalls: SyscallSet,
        published_services: u32,
        program_capabilities: u32,
    ) -> Self {
        Self {
            rights,
            syscalls,
            published_services,
            program_capabilities,
        }
    }

    pub fn authorize(self, request: AuthorityRequest) -> Result<(), CapabilityError> {
        if !self.rights.contains(request.rights) {
            return Err(CapabilityError::RightsDenied);
        }
        if request
            .syscall
            .is_some_and(|id| !self.syscalls.contains(id))
        {
            return Err(CapabilityError::SyscallDenied);
        }
        if request.service_bit.is_some_and(|bit| {
            bit >= 32 || self.published_services & (1u32 << bit) == 0
        }) {
            return Err(CapabilityError::ServiceDenied);
        }
        if request.program_bit.is_some_and(|bit| {
            bit >= 32 || self.program_capabilities & (1u32 << bit) == 0
        }) {
            return Err(CapabilityError::ProgramCapabilityDenied);
        }
        Ok(())
    }
}

/// In-flight grant over all authority domains. The graph token is the
/// revocable capability lease; the snapshot prevents a second domain from
/// changing between check and effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorityGrant {
    pub capability_use: CapabilityUse,
    pub snapshot: AuthoritySnapshot,
    pub request: AuthorityRequest,
}

/// A capability node.  `parent` is immutable, and because nodes only receive
/// a parent at creation (never acquire a new parent), the graph cannot form a
/// cycle.  `epoch` advances on every authority-changing operation and is
/// captured by in-flight use tokens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityNode {
    pub id: CapabilityId,
    pub parent: Option<CapabilityId>,
    pub object: ObjectIdentity,
    pub owner: PrincipalId,
    pub rights: Rights,
    pub depth: u16,
    pub epoch: u32,
    pub active_uses: u32,
    pub state: CapabilityState,
}

/// A fail-closed use token.  Callers must call [`CapabilityGraph::validate_use`]
/// immediately before committing the effect; revocation or attenuation after
/// `begin_use` invalidates the token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityUse {
    pub capability: CapabilityId,
    pub object: ObjectIdentity,
    pub owner: PrincipalId,
    pub rights: Rights,
    pub epoch: u32,
}

/// Audit event kinds.  The graph records structural events; policy/mac
/// decisions remain SEC-3 work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityEventKind {
    Root,
    Attenuate,
    Restrict,
    Transfer,
    Revoke,
    Retire,
    Denied,
}

/// A compact, bounded audit record.  `overflow` on the graph is explicit; it is
/// never treated as a successful full audit trail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityEvent {
    pub kind: CapabilityEventKind,
    pub capability: CapabilityId,
    pub parent: Option<CapabilityId>,
    pub owner: PrincipalId,
    pub object: ObjectIdentity,
    pub rights: Rights,
}

/// Dead-node notification.  A revoked node is reported once; the record is
/// retained until the caller drains it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityDeath {
    pub capability: CapabilityId,
    pub revoke_root: CapabilityId,
    pub owner: PrincipalId,
    pub object: ObjectIdentity,
}

#[derive(Clone, Copy)]
struct NodeSlot {
    node: Option<CapabilityNode>,
}

impl NodeSlot {
    const EMPTY: Self = Self { node: None };
}

#[derive(Clone, Copy)]
struct EventSlot {
    event: Option<CapabilityEvent>,
}

impl EventSlot {
    const EMPTY: Self = Self { event: None };
}

#[derive(Clone, Copy)]
struct DeathSlot {
    death: Option<CapabilityDeath>,
}

impl DeathSlot {
    const EMPTY: Self = Self { death: None };
}

/// Fixed-capacity capability graph.  `N` bounds nodes and each derived queue.
pub struct CapabilityGraph<const N: usize> {
    nodes: [NodeSlot; N],
    events: [EventSlot; N],
    deaths: [DeathSlot; N],
    next_id: u64,
    event_head: usize,
    event_len: usize,
    event_overflow: u64,
    death_head: usize,
    death_len: usize,
    death_overflow: u64,
}

impl<const N: usize> CapabilityGraph<N> {
    pub const fn new() -> Self {
        assert!(N > 0, "capability graph capacity must be non-zero");
        Self {
            nodes: [NodeSlot::EMPTY; N],
            events: [EventSlot::EMPTY; N],
            deaths: [DeathSlot::EMPTY; N],
            next_id: 1,
            event_head: 0,
            event_len: 0,
            event_overflow: 0,
            death_head: 0,
            death_len: 0,
            death_overflow: 0,
        }
    }

    /// Create a root capability for one object.  Roots are created only by the
    /// trusted grant path and cannot be forged from a user-supplied integer.
    pub fn create_root(
        &mut self,
        object: ObjectIdentity,
        owner: PrincipalId,
        rights: Rights,
    ) -> Result<CapabilityId, CapabilityError> {
        validate_object(object)?;
        self.create_node(None, object, owner, rights, 0)
    }

    /// Delegate or attenuate a capability.  The child must name the exact same
    /// object identity and may only contain a subset of the parent's rights.
    /// The owner may change (delegation), but the caller must have selected the
    /// destination explicitly.
    pub fn delegate(
        &mut self,
        parent: CapabilityId,
        object: ObjectIdentity,
        owner: PrincipalId,
        rights: Rights,
    ) -> Result<CapabilityId, CapabilityError> {
        let parent_node = *self.node(parent)?;
        if parent_node.state != CapabilityState::Active {
            self.record_denied(parent_node, None);
            return Err(CapabilityError::Revoked);
        }
        if parent_node.object != object {
            self.record_denied(parent_node, None);
            return Err(CapabilityError::ObjectMismatch);
        }
        if !parent_node.rights.contains(rights) {
            self.record_denied(parent_node, None);
            return Err(CapabilityError::RightsDenied);
        }
        let depth = parent_node
            .depth
            .checked_add(1)
            .ok_or(CapabilityError::DepthExhausted)?;
        self.create_node(Some(parent), object, owner, rights, depth)
    }

    /// Remove rights in place.  This creates no alias and increments the
    /// authority epoch, invalidating uses that began with the old rights.
    pub fn restrict(
        &mut self,
        capability: CapabilityId,
        rights: Rights,
    ) -> Result<(), CapabilityError> {
        let node = self.node_mut(capability)?;
        if node.state != CapabilityState::Active {
            return Err(CapabilityError::Revoked);
        }
        if !node.rights.contains(rights) {
            let node_copy = *node;
            self.record_denied(node_copy, None);
            return Err(CapabilityError::RightsDenied);
        }
        node.rights = rights;
        node.epoch = node.epoch.checked_add(1).ok_or(CapabilityError::IdExhausted)?;
        let copy = *node;
        self.record_event(CapabilityEvent {
            kind: CapabilityEventKind::Restrict,
            capability,
            parent: copy.parent,
            owner: copy.owner,
            object: copy.object,
            rights: copy.rights,
        });
        Ok(())
    }

    /// Transfer ownership of a capability without creating a new node.
    pub fn transfer(
        &mut self,
        capability: CapabilityId,
        from: PrincipalId,
        to: PrincipalId,
    ) -> Result<(), CapabilityError> {
        let node = self.node_mut(capability)?;
        if node.state != CapabilityState::Active {
            return Err(CapabilityError::Revoked);
        }
        if node.owner != from {
            let denied = *node;
            self.record_denied(denied, None);
            return Err(CapabilityError::OwnerMismatch);
        }
        node.owner = to;
        node.epoch = node.epoch.checked_add(1).ok_or(CapabilityError::IdExhausted)?;
        let copy = *node;
        self.record_event(CapabilityEvent {
            kind: CapabilityEventKind::Transfer,
            capability,
            parent: copy.parent,
            owner: copy.owner,
            object: copy.object,
            rights: copy.rights,
        });
        Ok(())
    }

    /// Revoke a node and every currently reachable descendant.  The operation
    /// is idempotent for already-revoked nodes.  Active uses remain counted
    /// until their owners end them, but every such use fails validation.
    pub fn revoke(&mut self, root: CapabilityId) -> Result<usize, CapabilityError> {
        let root_node = *self.node(root)?;
        if root_node.state == CapabilityState::Revoked {
            return Ok(0);
        }

        let mut affected: [CapabilityId; N] = [CapabilityId::ZERO; N];
        let mut affected_len = 0;
        for index in 0..N {
            let Some(node) = self.nodes[index].node else {
                continue;
            };
            if node.state != CapabilityState::Active {
                continue;
            }
            if node.id == root || self.is_descendant_of(node.id, root) {
                affected[affected_len] = node.id;
                affected_len += 1;
            }
        }

        for index in 0..affected_len {
            let id = affected[index];
            let node = self.node_mut(id)?;
            node.state = CapabilityState::Revoked;
            node.epoch = node
                .epoch
                .checked_add(1)
                .ok_or(CapabilityError::IdExhausted)?;
            let copy = *node;
            self.record_event(CapabilityEvent {
                kind: CapabilityEventKind::Revoke,
                capability: id,
                parent: copy.parent,
                owner: copy.owner,
                object: copy.object,
                rights: copy.rights,
            });
            self.record_death(CapabilityDeath {
                capability: id,
                revoke_root: root,
                owner: copy.owner,
                object: copy.object,
            });
        }
        Ok(affected_len)
    }

    /// Begin an in-flight authorization use.  The caller must later call
    /// [`validate_use`](Self::validate_use) before the effect and
    /// [`end_use`](Self::end_use) on every completion/abort path.
    pub fn begin_use(
        &mut self,
        capability: CapabilityId,
        owner: PrincipalId,
        required: Rights,
    ) -> Result<CapabilityUse, CapabilityError> {
        let node = self.node_mut(capability)?;
        if node.state != CapabilityState::Active {
            return Err(CapabilityError::Revoked);
        }
        if node.owner != owner {
            let denied = *node;
            self.record_denied(denied, None);
            return Err(CapabilityError::OwnerMismatch);
        }
        if !node.rights.contains(required) {
            let denied = *node;
            self.record_denied(denied, None);
            return Err(CapabilityError::RightsDenied);
        }
        node.active_uses = node
            .active_uses
            .checked_add(1)
            .ok_or(CapabilityError::CapacityExhausted)?;
        Ok(CapabilityUse {
            capability,
            object: node.object,
            owner: node.owner,
            rights: node.rights,
            epoch: node.epoch,
        })
    }

    /// Revalidate an in-flight use immediately before committing its effect.
    pub fn validate_use(&self, use_token: CapabilityUse) -> Result<(), CapabilityError> {
        let node = self.node(use_token.capability)?;
        if node.state != CapabilityState::Active
            || node.object != use_token.object
            || node.owner != use_token.owner
            || node.epoch != use_token.epoch
            || !node.rights.contains(use_token.rights)
        {
            return Err(CapabilityError::UseInvalid);
        }
        Ok(())
    }

    /// End an in-flight use.  Synchronous errors are explicit and never wrap
    /// the active-use counter.
    pub fn end_use(&mut self, use_token: CapabilityUse) -> Result<(), CapabilityError> {
        let node = self.node_mut(use_token.capability)?;
        if node.active_uses == 0 {
            return Err(CapabilityError::InUse);
        }
        node.active_uses -= 1;
        Ok(())
    }

    /// Begin one effect across handle rights, syscalls, service publication
    /// and profile/program capabilities.
    pub fn begin_authority(
        &mut self,
        capability: CapabilityId,
        owner: PrincipalId,
        request: AuthorityRequest,
        snapshot: AuthoritySnapshot,
    ) -> Result<AuthorityGrant, CapabilityError> {
        snapshot.authorize(request)?;
        let capability_use = self.begin_use(capability, owner, request.rights)?;
        if self.node(capability)?.rights != snapshot.rights {
            self.end_use(capability_use)?;
            return Err(CapabilityError::SnapshotChanged);
        }
        Ok(AuthorityGrant {
            capability_use,
            snapshot,
            request,
        })
    }

    /// Revalidate every authority domain immediately before committing an
    /// effect. Any changed snapshot or revoked graph node fails closed.
    pub fn validate_authority(
        &self,
        grant: AuthorityGrant,
        current: AuthoritySnapshot,
    ) -> Result<(), CapabilityError> {
        if current != grant.snapshot {
            return Err(CapabilityError::SnapshotChanged);
        }
        self.validate_use(grant.capability_use)?;
        current.authorize(grant.request)
    }

    pub fn end_authority(
        &mut self,
        grant: AuthorityGrant,
    ) -> Result<(), CapabilityError> {
        self.end_use(grant.capability_use)
    }

    /// Retire a node after it has no live descendants or in-flight users.  A
    /// revoked node may be retired after its uses drain; callers close the
    /// object ownership separately.
    pub fn retire(&mut self, capability: CapabilityId) -> Result<(), CapabilityError> {
        let node = *self.node(capability)?;
        if node.active_uses != 0 {
            return Err(CapabilityError::InUse);
        }
        if self.has_descendants(capability) {
            return Err(CapabilityError::HasDependents);
        }
        let event = CapabilityEvent {
            kind: CapabilityEventKind::Retire,
            capability,
            parent: node.parent,
            owner: node.owner,
            object: node.object,
            rights: node.rights,
        };
        for slot in &mut self.nodes {
            if slot.node.is_some_and(|current| current.id == capability) {
                slot.node = None;
                self.record_event(event);
                return Ok(());
            }
        }
        Err(CapabilityError::InvalidCapability)
    }

    /// Return a node for diagnostics.  This does not confer authority.
    pub fn node(&self, capability: CapabilityId) -> Result<&CapabilityNode, CapabilityError> {
        if !capability.is_valid() {
            return Err(CapabilityError::InvalidCapability);
        }
        self.nodes
            .iter()
            .filter_map(|slot| slot.node.as_ref())
            .find(|node| node.id == capability)
            .ok_or(CapabilityError::InvalidCapability)
    }

    fn node_mut(
        &mut self,
        capability: CapabilityId,
    ) -> Result<&mut CapabilityNode, CapabilityError> {
        if !capability.is_valid() {
            return Err(CapabilityError::InvalidCapability);
        }
        self.nodes
            .iter_mut()
            .filter_map(|slot| slot.node.as_mut())
            .find(|node| node.id == capability)
            .ok_or(CapabilityError::InvalidCapability)
    }

    fn create_node(
        &mut self,
        parent: Option<CapabilityId>,
        object: ObjectIdentity,
        owner: PrincipalId,
        rights: Rights,
        depth: u16,
    ) -> Result<CapabilityId, CapabilityError> {
        validate_object(object)?;
        if owner.raw() == 0 {
            return Err(CapabilityError::InvalidOwner);
        }
        let slot = self
            .nodes
            .iter()
            .position(|slot| slot.node.is_none())
            .ok_or(CapabilityError::CapacityExhausted)?;
        let id = CapabilityId(self.next_id);
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(CapabilityError::IdExhausted)?;
        let node = CapabilityNode {
            id,
            parent,
            object,
            owner,
            rights,
            depth,
            epoch: 0,
            active_uses: 0,
            state: CapabilityState::Active,
        };
        self.nodes[slot].node = Some(node);
        self.record_event(CapabilityEvent {
            kind: if parent.is_none() {
                CapabilityEventKind::Root
            } else {
                CapabilityEventKind::Attenuate
            },
            capability: id,
            parent,
            owner,
            object,
            rights,
        });
        Ok(id)
    }

    fn is_descendant_of(&self, candidate: CapabilityId, ancestor: CapabilityId) -> bool {
        let mut current = self.node(candidate).ok().and_then(|node| node.parent);
        let mut walked = 0usize;
        while let Some(id) = current {
            if id == ancestor {
                return true;
            }
            walked += 1;
            if walked > N {
                return false;
            }
            current = self.node(id).ok().and_then(|node| node.parent);
        }
        false
    }

    fn has_descendants(&self, ancestor: CapabilityId) -> bool {
        self.nodes.iter().any(|slot| {
            slot.node
                .is_some_and(|node| self.is_descendant_of(node.id, ancestor))
        })
    }

    fn record_denied(&mut self, node: CapabilityNode, requested: Option<Rights>) {
        self.record_event(CapabilityEvent {
            kind: CapabilityEventKind::Denied,
            capability: node.id,
            parent: node.parent,
            owner: node.owner,
            object: node.object,
            rights: requested.unwrap_or(Rights::NONE),
        });
    }

    fn record_event(&mut self, event: CapabilityEvent) {
        if self.event_len == N {
            self.event_overflow = self.event_overflow.saturating_add(1);
            return;
        }
        let tail = (self.event_head + self.event_len) % N;
        self.events[tail].event = Some(event);
        self.event_len += 1;
    }

    /// Pop the oldest audit event.  Overflow is observable through
    /// [`event_overflow`](Self::event_overflow).
    pub fn next_event(&mut self) -> Option<CapabilityEvent> {
        if self.event_len == 0 {
            return None;
        }
        let event = self.events[self.event_head].event.take();
        self.event_head = (self.event_head + 1) % N;
        self.event_len -= 1;
        event
    }

    pub fn event_overflow(&self) -> u64 {
        self.event_overflow
    }

    fn record_death(&mut self, death: CapabilityDeath) {
        if self.death_len == N {
            self.death_overflow = self.death_overflow.saturating_add(1);
            return;
        }
        let tail = (self.death_head + self.death_len) % N;
        self.deaths[tail].death = Some(death);
        self.death_len += 1;
    }

    /// Pop the oldest death notification.  Overflow is observable through
    /// [`death_overflow`](Self::death_overflow).
    pub fn next_death(&mut self) -> Option<CapabilityDeath> {
        if self.death_len == 0 {
            return None;
        }
        let death = self.deaths[self.death_head].death.take();
        self.death_head = (self.death_head + 1) % N;
        self.death_len -= 1;
        death
    }

    pub fn death_overflow(&self) -> u64 {
        self.death_overflow
    }

    pub fn live_nodes(&self) -> usize {
        self.nodes.iter().filter(|slot| slot.node.is_some()).count()
    }
}

impl<const N: usize> Default for CapabilityGraph<N> {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_object(object: ObjectIdentity) -> Result<(), CapabilityError> {
    if object.boot_id == BootId::ZERO
        || object.object_id == 0
        || object.class == IdentityClass::Bootstrap
    {
        Err(CapabilityError::InvalidObject)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object() -> ObjectIdentity {
        ObjectIdentity {
            boot_id: BootId::from_words([0x1111, 0x2222]),
            class: IdentityClass::Memory,
            object_id: 7,
            generation: 3,
        }
    }

    fn owner(raw: u64) -> PrincipalId {
        PrincipalId::new(raw).unwrap()
    }

    #[test]
    fn delegation_cannot_add_rights_or_change_object() {
        let mut graph = CapabilityGraph::<8>::new();
        let root = graph
            .create_root(object(), owner(1), Rights::READ.union(Rights::WRITE))
            .unwrap();
        assert_eq!(
            graph.delegate(
                root,
                ObjectIdentity {
                    generation: 4,
                    ..object()
                },
                owner(2),
                Rights::READ,
            ),
            Err(CapabilityError::ObjectMismatch)
        );
        assert_eq!(
            graph.delegate(root, object(), owner(2), Rights::CONTROL),
            Err(CapabilityError::RightsDenied)
        );
        let child = graph
            .delegate(root, object(), owner(2), Rights::READ)
            .unwrap();
        assert_eq!(graph.node(child).unwrap().parent, Some(root));
        assert_eq!(graph.node(child).unwrap().owner, owner(2));
        assert_eq!(graph.node(child).unwrap().rights, Rights::READ);
    }

    #[test]
    fn revocation_invalidates_inflight_use_and_reports_death() {
        let mut graph = CapabilityGraph::<8>::new();
        let root = graph.create_root(object(), owner(1), Rights::ALL).unwrap();
        let child = graph.delegate(root, object(), owner(1), Rights::READ).unwrap();
        let use_token = graph.begin_use(child, owner(1), Rights::READ).unwrap();
        assert!(graph.validate_use(use_token).is_ok());
        assert_eq!(graph.revoke(child).unwrap(), 1);
        assert_eq!(
            graph.validate_use(use_token),
            Err(CapabilityError::UseInvalid)
        );
        let death = graph.next_death().unwrap();
        assert_eq!(death.capability, child);
        assert_eq!(death.revoke_root, child);
        graph.end_use(use_token).unwrap();
        assert_eq!(graph.node(root).unwrap().state, CapabilityState::Active);
        assert_eq!(graph.node(child).unwrap().state, CapabilityState::Revoked);
    }

    #[test]
    fn subtree_revocation_and_transfer_are_bound_to_the_owner() {
        let mut graph = CapabilityGraph::<8>::new();
        let root = graph.create_root(object(), owner(1), Rights::ALL).unwrap();
        let child = graph.delegate(root, object(), owner(2), Rights::READ).unwrap();
        let grandchild = graph.delegate(child, object(), owner(3), Rights::READ).unwrap();
        assert_eq!(
            graph.transfer(child, owner(1), owner(3)),
            Err(CapabilityError::OwnerMismatch)
        );
        graph.transfer(child, owner(2), owner(4)).unwrap();
        assert_eq!(graph.node(child).unwrap().owner, owner(4));
        assert_eq!(graph.revoke(root).unwrap(), 3);
        assert_eq!(
            graph.node(grandchild).unwrap().state,
            CapabilityState::Revoked
        );
        assert_eq!(graph.node(child).unwrap().state, CapabilityState::Revoked);
    }

    #[test]
    fn attenuation_invalidates_old_uses_and_never_escalates() {
        let mut graph = CapabilityGraph::<4>::new();
        let root = graph.create_root(object(), owner(1), Rights::ALL).unwrap();
        let use_token = graph.begin_use(root, owner(1), Rights::READ).unwrap();
        graph.restrict(root, Rights::READ).unwrap();
        assert_eq!(
            graph.validate_use(use_token),
            Err(CapabilityError::UseInvalid)
        );
        assert_eq!(
            graph.restrict(root, Rights::WRITE),
            Err(CapabilityError::RightsDenied)
        );
        graph.end_use(use_token).unwrap();
    }

    #[test]
    fn stale_codes_capacity_and_audit_overflow_are_explicit() {
        let mut graph = CapabilityGraph::<2>::new();
        let root = graph.create_root(object(), owner(1), Rights::READ).unwrap();
        let child = graph.delegate(root, object(), owner(2), Rights::READ).unwrap();
        assert_eq!(
            graph.create_root(object(), owner(1), Rights::READ),
            Err(CapabilityError::CapacityExhausted)
        );
        assert!(graph.live_nodes() == 2);
        graph.revoke(root).unwrap();
        assert_eq!(graph.revoke(root), Ok(0));
        assert_eq!(graph.node(child).unwrap().state, CapabilityState::Revoked);
        while graph.next_event().is_some() {}
        assert!(graph.event_overflow() > 0);
        while graph.next_death().is_some() {}
        graph.delegate(root, object(), owner(2), Rights::READ).unwrap_err();
    }

    #[test]
    fn unified_authority_projection_requires_every_existing_gate() {
        let rights = Rights::READ.union(Rights::MAP);
        let syscalls = SyscallSet::from_id(41).unwrap();
        let request = AuthorityRequest::new(rights)
            .with_syscall(41)
            .with_service(3)
            .with_program_capability(2);

        AuthoritySnapshot::new(rights, syscalls, 1 << 3, 1 << 2)
            .authorize(request)
            .unwrap();
        assert_eq!(
            AuthoritySnapshot::new(rights.difference(Rights::MAP), syscalls, 1 << 3, 1 << 2)
                .authorize(request),
            Err(CapabilityError::RightsDenied)
        );
        assert_eq!(
            AuthoritySnapshot::new(rights, SyscallSet::EMPTY, 1 << 3, 1 << 2)
                .authorize(request),
            Err(CapabilityError::SyscallDenied)
        );
        assert_eq!(
            AuthoritySnapshot::new(rights, syscalls, 0, 1 << 2).authorize(request),
            Err(CapabilityError::ServiceDenied)
        );
        assert_eq!(
            AuthoritySnapshot::new(rights, syscalls, 1 << 3, 0).authorize(request),
            Err(CapabilityError::ProgramCapabilityDenied)
        );
        assert_eq!(
            AuthoritySnapshot::new(rights, syscalls, 1 << 3, 1 << 2)
                .authorize(request.with_service(32)),
            Err(CapabilityError::ServiceDenied)
        );
    }

    #[test]
    fn in_flight_authority_grant_pins_graph_and_all_other_masks() {
        let mut graph = CapabilityGraph::<4>::new();
        let capability = graph.create_root(object(), owner(1), Rights::ALL).unwrap();
        let request = AuthorityRequest::new(Rights::READ)
            .with_syscall(7)
            .with_service(1)
            .with_program_capability(2);
        let snapshot = AuthoritySnapshot::new(
            Rights::ALL,
            SyscallSet::from_id(7).unwrap(),
            1 << 1,
            1 << 2,
        );
        let grant = graph
            .begin_authority(capability, owner(1), request, snapshot)
            .unwrap();
        graph.validate_authority(grant, snapshot).unwrap();

        let changed = AuthoritySnapshot {
            published_services: 0,
            ..snapshot
        };
        assert_eq!(
            graph.validate_authority(grant, changed),
            Err(CapabilityError::SnapshotChanged)
        );
        graph.revoke(capability).unwrap();
        assert_eq!(
            graph.validate_authority(grant, snapshot),
            Err(CapabilityError::UseInvalid)
        );
        graph.end_authority(grant).unwrap();
    }

    #[test]
    fn begin_authority_rejects_handle_snapshot_mismatch_without_leaking_use() {
        let mut graph = CapabilityGraph::<2>::new();
        let capability = graph
            .create_root(object(), owner(1), Rights::READ)
            .unwrap();
        let request = AuthorityRequest::new(Rights::READ);
        let snapshot = AuthoritySnapshot::new(
            Rights::READ.union(Rights::WRITE),
            SyscallSet::EMPTY,
            0,
            0,
        );
        assert_eq!(
            graph.begin_authority(capability, owner(1), request, snapshot),
            Err(CapabilityError::SnapshotChanged)
        );
        assert_eq!(graph.node(capability).unwrap().active_uses, 0);
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    fn object() -> ObjectIdentity {
        ObjectIdentity {
            boot_id: BootId::from_words([1, 2]),
            class: IdentityClass::Memory,
            object_id: 9,
            generation: 1,
        }
    }

    #[kani::proof]
    #[kani::unwind(8)]
    fn delegation_never_escalates_or_crosses_object_generation() {
        let mut graph = CapabilityGraph::<4>::new();
        let parent_rights = Rights::from_bits_truncate(kani::any());
        let requested = Rights::from_bits_truncate(kani::any());
        let root = graph
            .create_root(object(), PrincipalId::new(1).unwrap(), parent_rights)
            .unwrap();
        let child_object = ObjectIdentity {
            generation: kani::any(),
            ..object()
        };
        let result = graph.delegate(
            root,
            child_object,
            PrincipalId::new(2).unwrap(),
            requested,
        );
        if result.is_ok() {
            assert!(parent_rights.contains(requested));
            assert_eq!(child_object, object());
        }
    }

    #[kani::proof]
    #[kani::unwind(8)]
    fn revocation_never_leaves_a_valid_use() {
        let mut graph = CapabilityGraph::<4>::new();
        let root = graph
            .create_root(object(), PrincipalId::new(1).unwrap(), Rights::ALL)
            .unwrap();
        let use_token = graph
            .begin_use(root, PrincipalId::new(1).unwrap(), Rights::READ)
            .unwrap();
        graph.revoke(root).unwrap();
        assert!(graph.validate_use(use_token).is_err());
    }
}
