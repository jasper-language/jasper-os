//! SEC-5 bounded information-flow control.
//!
//! Flow labels are independent of MAC labels and capability rights. Data and
//! control taints can only grow through copy, aggregation, encoding and
//! channel transfer. Removing a taint requires an explicitly minted
//! declassification grant with a source digest, purpose, expiry and authority.
//! Alias identities preserve the exact label and therefore cannot launder it.

use crate::mac::Secrecy;

pub const FLOW_LABEL_VERSION: u16 = 1;
pub const FLOW_POLICY_VERSION: u16 = 1;
pub const DECLASSIFY_ENDORSEMENT: u16 = 1 << 0;
pub const AUDIT_ENDORSEMENT: u16 = 1 << 1;
pub const ALL_ENDORSEMENTS: u16 = DECLASSIFY_ENDORSEMENT | AUDIT_ENDORSEMENT;
pub const PURPOSE_SYSTEM: u32 = 1 << 0;
pub const PURPOSE_DISPLAY: u32 = 1 << 1;
pub const PURPOSE_NETWORK: u32 = 1 << 2;
pub const ALL_PURPOSES: u32 = PURPOSE_SYSTEM | PURPOSE_DISPLAY | PURPOSE_NETWORK;

const DECLASS_ROOT_KEY: u64 = 0x5345_4335_4445_434c;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TaintSet(u16);

impl TaintSet {
    pub const EMPTY: Self = Self(0);
    pub const INTERNAL: Self = Self(1 << 0);
    pub const PERSONAL: Self = Self(1 << 1);
    pub const FINANCIAL: Self = Self(1 << 2);
    pub const HEALTH: Self = Self(1 << 3);
    pub const CREDENTIAL: Self = Self(1 << 4);
    pub const SECRET: Self = Self(1 << 5);
    pub const ALL: Self = Self((1 << 6) - 1);

    pub const fn bits(self) -> u16 {
        self.0
    }

    pub const fn from_bits(bits: u16) -> Option<Self> {
        if bits & !Self::ALL.0 == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    pub const fn insert(self, taint: Self) -> Self {
        Self(self.0 | taint.0)
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EndorsementSet(u16);

impl EndorsementSet {
    pub const EMPTY: Self = Self(0);
    pub const ALL: Self = Self(ALL_ENDORSEMENTS);

    pub const fn from_bits(bits: u16) -> Option<Self> {
        if bits & !ALL_ENDORSEMENTS == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    pub const fn insert(self, endorsement: u16) -> Self {
        Self(self.0 | endorsement)
    }

    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn bits(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowLabel {
    pub version: u16,
    pub data: TaintSet,
    pub control: TaintSet,
    pub endorsements: EndorsementSet,
    pub purposes: u32,
    pub expires_at: u64,
    pub generation: u32,
    pub reserved: u16,
}

impl FlowLabel {
    pub const fn public() -> Self {
        Self {
            version: FLOW_LABEL_VERSION,
            data: TaintSet::EMPTY,
            control: TaintSet::EMPTY,
            endorsements: EndorsementSet::EMPTY,
            purposes: PURPOSE_SYSTEM,
            expires_at: 0,
            generation: 1,
            reserved: 0,
        }
    }

    pub fn for_secrecy(secrecy: Secrecy) -> Self {
        let data = match secrecy {
            Secrecy::Public => TaintSet::EMPTY,
            Secrecy::Internal => TaintSet::INTERNAL,
            Secrecy::Sensitive => TaintSet::INTERNAL
                .insert(TaintSet::PERSONAL)
                .insert(TaintSet::FINANCIAL)
                .insert(TaintSet::HEALTH),
            Secrecy::Secret => TaintSet::ALL,
        };
        Self {
            data,
            purposes: ALL_PURPOSES,
            ..Self::public()
        }
    }

    pub const fn is_supported(self) -> bool {
        self.version == FLOW_LABEL_VERSION
            && self.reserved == 0
            && self.purposes != 0
            && self.purposes & !ALL_PURPOSES == 0
            && self.generation != 0
    }

    pub const fn is_expired(self, now: u64) -> bool {
        self.expires_at != 0 && now >= self.expires_at
    }

    pub fn digest(self) -> u64 {
        let mut value = 0xcbf2_9ce4_8422_2325u64;
        for word in [
            u64::from(self.version),
            u64::from(self.data.bits()),
            u64::from(self.control.bits()),
            u64::from(self.endorsements.bits()),
            u64::from(self.purposes),
            self.expires_at,
            u64::from(self.generation),
            u64::from(self.reserved),
        ] {
            value ^= word;
            value = value.wrapping_mul(0x100_0000_01b3);
        }
        value
    }

    pub fn join(self, other: Self) -> Result<Self, FlowError> {
        if !self.is_supported() || !other.is_supported() {
            return Err(FlowError::InvalidLabel);
        }
        let purposes = self.purposes & other.purposes;
        if purposes == 0 {
            return Err(FlowError::PurposeConflict);
        }
        let expires_at = match (self.expires_at, other.expires_at) {
            (0, value) | (value, 0) => value,
            (left, right) => left.min(right),
        };
        let generation = self
            .generation
            .max(other.generation)
            .checked_add(1)
            .ok_or(FlowError::Generation)?;
        Ok(Self {
            version: FLOW_LABEL_VERSION,
            data: self.data.union(other.data),
            control: self.control.union(other.control),
            endorsements: self.endorsements.intersection(other.endorsements),
            purposes,
            expires_at,
            generation,
            reserved: 0,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowPolicy {
    pub version: u16,
    pub allowed_data: TaintSet,
    pub allowed_control: TaintSet,
    pub allowed_purposes: u32,
    pub required_endorsements: EndorsementSet,
    pub reserved: u16,
}

impl FlowPolicy {
    pub const fn public() -> Self {
        Self {
            version: FLOW_POLICY_VERSION,
            allowed_data: TaintSet::EMPTY,
            allowed_control: TaintSet::EMPTY,
            allowed_purposes: PURPOSE_SYSTEM,
            required_endorsements: EndorsementSet::EMPTY,
            reserved: 0,
        }
    }

    pub fn for_clearance(clearance: Secrecy) -> Self {
        let allowed_data = FlowLabel::for_secrecy(clearance).data;
        Self {
            allowed_data,
            allowed_purposes: ALL_PURPOSES,
            ..Self::public()
        }
    }

    pub const fn is_supported(self) -> bool {
        self.version == FLOW_POLICY_VERSION
            && self.reserved == 0
            && self.allowed_purposes != 0
            && self.allowed_purposes & !ALL_PURPOSES == 0
    }

    pub fn evaluate(self, label: FlowLabel, purpose: u32, now: u64) -> Result<(), FlowError> {
        if !self.is_supported() || !label.is_supported() || purpose.count_ones() != 1 {
            return Err(FlowError::InvalidPolicy);
        }
        if self.allowed_purposes & purpose == 0 || label.purposes & purpose == 0 {
            return Err(FlowError::PurposeDenied);
        }
        if label.is_expired(now) {
            return Err(FlowError::Expired);
        }
        if !self.allowed_data.contains(label.data) {
            return Err(FlowError::DataTaint);
        }
        if !self.allowed_control.contains(label.control) {
            return Err(FlowError::ControlTaint);
        }
        if !label.endorsements.contains(self.required_endorsements) {
            return Err(FlowError::Endorsement);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowIdentity {
    pub object: u64,
    pub generation: u32,
}

impl FlowIdentity {
    pub const fn is_valid(self) -> bool {
        self.object != 0 && self.generation != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowChannel {
    Copy,
    Ipc,
    SharedMemory,
    File,
    Network,
    Clipboard,
    Display,
    VmIo,
    Aggregate,
    Declassify,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowDecision {
    Allowed,
    Denied,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowReason {
    Allowed,
    PurposeDenied,
    Expired,
    DataTaint,
    ControlTaint,
    Endorsement,
    NoLabel,
    NoPolicy,
    StaleGrant,
    InvalidGrant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowError {
    InvalidIdentity,
    InvalidLabel,
    InvalidPolicy,
    InvalidGrant,
    Capacity,
    AlreadyRegistered,
    NotFound,
    PurposeConflict,
    PurposeDenied,
    DataTaint,
    ControlTaint,
    Endorsement,
    Expired,
    Generation,
    AuditFull,
    Denied,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowAudit {
    pub sequence: u64,
    pub source: FlowIdentity,
    pub sink: FlowIdentity,
    pub channel: FlowChannel,
    pub purpose: u32,
    pub source_digest: u64,
    pub decision: FlowDecision,
    pub reason: FlowReason,
    pub declassification: Option<u64>,
    pub digest: u64,
}

#[derive(Clone, Copy)]
struct FlowNode {
    identity: FlowIdentity,
    label: FlowLabel,
    policy: Option<FlowPolicy>,
}

/// Opaque authority root. User ABI has no constructor for this type.
#[derive(Clone, Copy)]
pub struct DeclassRoot {
    key: u64,
}

impl DeclassRoot {
    pub const BOOTSTRAP: Self = Self {
        key: DECLASS_ROOT_KEY,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeclassGrant {
    id: u64,
    source_digest: u64,
    source_generation: u32,
    remove_data: TaintSet,
    remove_control: TaintSet,
    purpose: u32,
    expires_at: u64,
}

pub struct FlowEngine<const NODES: usize, const AUDIT: usize> {
    nodes: [Option<FlowNode>; NODES],
    audit: [Option<FlowAudit>; AUDIT],
    audit_len: usize,
    audit_overflow: u64,
    audit_allowed: u64,
    audit_denied: u64,
    sequence: u64,
    last_digest: u64,
    next_grant: u64,
}

impl<const NODES: usize, const AUDIT: usize> FlowEngine<NODES, AUDIT> {
    pub const fn new() -> Self {
        Self {
            nodes: [None; NODES],
            audit: [None; AUDIT],
            audit_len: 0,
            audit_overflow: 0,
            audit_allowed: 0,
            audit_denied: 0,
            sequence: 1,
            last_digest: 0,
            next_grant: 1,
        }
    }

    pub fn register(&mut self, identity: FlowIdentity, label: FlowLabel) -> Result<(), FlowError> {
        if !identity.is_valid() {
            return Err(FlowError::InvalidIdentity);
        }
        if !label.is_supported() {
            return Err(FlowError::InvalidLabel);
        }
        if self.node(identity).is_some() {
            return Err(FlowError::AlreadyRegistered);
        }
        let slot = self
            .nodes
            .iter()
            .position(Option::is_none)
            .ok_or(FlowError::Capacity)?;
        self.nodes[slot] = Some(FlowNode {
            identity,
            label,
            policy: None,
        });
        Ok(())
    }

    pub fn contains(&self, identity: FlowIdentity) -> bool {
        self.node(identity).is_some()
    }

    pub fn node_count(&self) -> usize {
        self.nodes.iter().flatten().count()
    }

    pub fn unregister(&mut self, identity: FlowIdentity) -> Option<FlowLabel> {
        let slot = self
            .nodes
            .iter()
            .position(|node| node.is_some_and(|node| node.identity == identity))?;
        self.nodes[slot].take().map(|node| node.label)
    }

    pub fn label(&self, identity: FlowIdentity) -> Option<FlowLabel> {
        self.node(identity).map(|node| node.label)
    }

    pub fn set_label(&mut self, identity: FlowIdentity, label: FlowLabel) -> Result<(), FlowError> {
        if !label.is_supported() {
            return Err(FlowError::InvalidLabel);
        }
        let slot = self
            .nodes
            .iter()
            .position(|node| node.is_some_and(|node| node.identity == identity))
            .ok_or(FlowError::NotFound)?;
        self.nodes[slot].as_mut().unwrap().label = label;
        Ok(())
    }

    pub fn audit_events(&self) -> impl Iterator<Item = FlowAudit> + '_ {
        (0..self.audit_len).filter_map(move |offset| self.audit[offset])
    }

    pub fn set_policy(
        &mut self,
        identity: FlowIdentity,
        policy: FlowPolicy,
    ) -> Result<(), FlowError> {
        if !policy.is_supported() {
            return Err(FlowError::InvalidPolicy);
        }
        let slot = self
            .nodes
            .iter()
            .position(|node| node.is_some_and(|node| node.identity == identity))
            .ok_or(FlowError::NotFound)?;
        self.nodes[slot].as_mut().unwrap().policy = Some(policy);
        Ok(())
    }

    /// Copying to another identity is an alias, not declassification.
    pub fn alias(
        &mut self,
        source: FlowIdentity,
        alias: FlowIdentity,
    ) -> Result<FlowLabel, FlowError> {
        let label = self.label(source).ok_or(FlowError::NotFound)?;
        self.reserve_audit()?;
        self.register(alias, label)?;
        self.record(
            source,
            alias,
            FlowChannel::Copy,
            label.purposes,
            label.digest(),
            FlowDecision::Allowed,
            FlowReason::Allowed,
            None,
        )?;
        Ok(label)
    }

    /// Aggregate input labels; every taint and control influence is retained.
    pub fn aggregate(
        &mut self,
        sources: &[FlowIdentity],
        destination: FlowIdentity,
    ) -> Result<FlowLabel, FlowError> {
        if sources.is_empty() || !destination.is_valid() {
            return Err(FlowError::InvalidIdentity);
        }
        let mut label = self.label(sources[0]).ok_or(FlowError::NotFound)?;
        for source in &sources[1..] {
            label = label.join(self.label(*source).ok_or(FlowError::NotFound)?)?;
        }
        self.reserve_audit()?;
        self.register(destination, label)?;
        self.record(
            sources[0],
            destination,
            FlowChannel::Aggregate,
            label.purposes,
            label.digest(),
            FlowDecision::Allowed,
            FlowReason::Allowed,
            None,
        )?;
        Ok(label)
    }

    pub fn authorize(
        &mut self,
        source: FlowIdentity,
        sink: FlowIdentity,
        channel: FlowChannel,
        purpose: u32,
        now: u64,
    ) -> Result<FlowDecision, FlowError> {
        let source_label = self.label(source).ok_or(FlowError::NotFound)?;
        let sink_node = self.node(sink).ok_or(FlowError::NotFound)?;
        let policy = sink_node.policy.ok_or(FlowError::InvalidPolicy)?;
        let (decision, reason) = match policy.evaluate(source_label, purpose, now) {
            Ok(()) => (FlowDecision::Allowed, FlowReason::Allowed),
            Err(error) => (FlowDecision::Denied, reason_for(error)),
        };
        self.record(
            source,
            sink,
            channel,
            purpose,
            source_label.digest(),
            decision,
            reason,
            None,
        )?;
        Ok(decision)
    }

    pub fn mint_declass_grant(
        &mut self,
        root: DeclassRoot,
        source: FlowIdentity,
        remove_data: TaintSet,
        remove_control: TaintSet,
        purpose: u32,
        expires_at: u64,
    ) -> Result<DeclassGrant, FlowError> {
        if root.key != DECLASS_ROOT_KEY || purpose.count_ones() != 1 || expires_at == 0 {
            return Err(FlowError::InvalidGrant);
        }
        let label = self.label(source).ok_or(FlowError::NotFound)?;
        if !label.data.contains(remove_data)
            || !label.control.contains(remove_control)
            || label.purposes & purpose == 0
        {
            return Err(FlowError::InvalidGrant);
        }
        let id = self.next_grant;
        self.next_grant = self
            .next_grant
            .checked_add(1)
            .ok_or(FlowError::Generation)?;
        Ok(DeclassGrant {
            id,
            source_digest: label.digest(),
            source_generation: label.generation,
            remove_data,
            remove_control,
            purpose,
            expires_at,
        })
    }

    pub fn declassify(
        &mut self,
        source: FlowIdentity,
        grant: DeclassGrant,
        now: u64,
    ) -> Result<FlowLabel, FlowError> {
        let slot = self
            .nodes
            .iter()
            .position(|node| node.is_some_and(|node| node.identity == source))
            .ok_or(FlowError::NotFound)?;
        let label = self.nodes[slot].as_ref().unwrap().label;
        let denial = if label.digest() != grant.source_digest
            || label.generation != grant.source_generation
        {
            Some(FlowReason::StaleGrant)
        } else if now >= grant.expires_at {
            Some(FlowReason::Expired)
        } else if grant.purpose.count_ones() != 1 || label.purposes & grant.purpose == 0 {
            Some(FlowReason::PurposeDenied)
        } else if !label.data.contains(grant.remove_data)
            || !label.control.contains(grant.remove_control)
        {
            Some(FlowReason::InvalidGrant)
        } else {
            None
        };
        if let Some(reason) = denial {
            self.record(
                source,
                source,
                FlowChannel::Declassify,
                grant.purpose,
                label.digest(),
                FlowDecision::Denied,
                reason,
                Some(grant.id),
            )?;
            return Err(FlowError::Denied);
        }
        let generation = label
            .generation
            .checked_add(1)
            .ok_or(FlowError::Generation)?;
        self.reserve_audit()?;
        let next = FlowLabel {
            data: label.data.difference(grant.remove_data),
            control: label.control.difference(grant.remove_control),
            endorsements: label.endorsements.insert(DECLASSIFY_ENDORSEMENT),
            purposes: grant.purpose,
            expires_at: grant.expires_at,
            generation,
            ..label
        };
        self.nodes[slot].as_mut().unwrap().label = next;
        self.record(
            source,
            source,
            FlowChannel::Declassify,
            grant.purpose,
            next.digest(),
            FlowDecision::Allowed,
            FlowReason::Allowed,
            Some(grant.id),
        )?;
        Ok(next)
    }

    pub fn drain_audit(&mut self) -> (u64, u64, u64, u64) {
        self.audit.fill(None);
        self.audit_len = 0;
        (
            self.audit_allowed,
            self.audit_denied,
            self.audit_overflow,
            self.last_digest,
        )
    }

    fn node(&self, identity: FlowIdentity) -> Option<FlowNode> {
        self.nodes
            .iter()
            .flatten()
            .find(|node| node.identity == identity)
            .copied()
    }

    fn record(
        &mut self,
        source: FlowIdentity,
        sink: FlowIdentity,
        channel: FlowChannel,
        purpose: u32,
        source_digest: u64,
        decision: FlowDecision,
        reason: FlowReason,
        declassification: Option<u64>,
    ) -> Result<(), FlowError> {
        self.reserve_audit()?;
        let sequence = self.sequence;
        self.sequence = sequence.checked_add(1).ok_or(FlowError::Generation)?;
        let digest = flow_digest(
            self.last_digest,
            sequence,
            source,
            sink,
            channel,
            purpose,
            source_digest,
            decision,
            declassification.unwrap_or(0),
        );
        let event = FlowAudit {
            sequence,
            source,
            sink,
            channel,
            purpose,
            source_digest,
            decision,
            reason,
            declassification,
            digest,
        };
        self.audit[self.audit_len] = Some(event);
        self.audit_len += 1;
        self.last_digest = digest;
        match decision {
            FlowDecision::Allowed => self.audit_allowed = self.audit_allowed.saturating_add(1),
            FlowDecision::Denied => self.audit_denied = self.audit_denied.saturating_add(1),
        }
        Ok(())
    }

    fn reserve_audit(&mut self) -> Result<(), FlowError> {
        if AUDIT == 0 || self.audit_len == AUDIT {
            self.audit_overflow = self.audit_overflow.saturating_add(1);
            Err(FlowError::AuditFull)
        } else {
            Ok(())
        }
    }
}

impl<const NODES: usize, const AUDIT: usize> Default for FlowEngine<NODES, AUDIT> {
    fn default() -> Self {
        Self::new()
    }
}

fn reason_for(error: FlowError) -> FlowReason {
    match error {
        FlowError::PurposeDenied => FlowReason::PurposeDenied,
        FlowError::Expired => FlowReason::Expired,
        FlowError::DataTaint => FlowReason::DataTaint,
        FlowError::ControlTaint => FlowReason::ControlTaint,
        FlowError::Endorsement => FlowReason::Endorsement,
        _ => FlowReason::NoPolicy,
    }
}

fn flow_digest(
    previous: u64,
    sequence: u64,
    source: FlowIdentity,
    sink: FlowIdentity,
    channel: FlowChannel,
    purpose: u32,
    source_digest: u64,
    decision: FlowDecision,
    declassification: u64,
) -> u64 {
    let mut value = previous ^ sequence;
    for word in [
        source.object,
        u64::from(source.generation),
        sink.object,
        u64::from(sink.generation),
        channel as u64,
        u64::from(purpose),
        source_digest,
        decision as u64,
        declassification,
    ] {
        value ^= word;
        value = value.wrapping_mul(0x100_0000_01b3);
    }
    value
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    fn id(object: u64) -> FlowIdentity {
        FlowIdentity {
            object,
            generation: 1,
        }
    }

    fn secret() -> FlowLabel {
        FlowLabel {
            data: TaintSet::SECRET,
            control: TaintSet::SECRET,
            purposes: ALL_PURPOSES,
            ..FlowLabel::public()
        }
    }

    #[test]
    fn default_deny_and_alias_copy_aggregation_cannot_remove_taint() {
        let mut engine = FlowEngine::<8, 32>::new();
        let source = id(1);
        let alias = id(2);
        let internal = id(3);
        let aggregate = id(4);
        let sink = id(5);
        engine.register(source, secret()).unwrap();
        engine
            .register(internal, FlowLabel::for_secrecy(Secrecy::Internal))
            .unwrap();
        engine.register(sink, FlowLabel::public()).unwrap();
        engine
            .set_policy(sink, FlowPolicy::for_clearance(Secrecy::Internal))
            .unwrap();
        engine.alias(source, alias).unwrap();
        assert_eq!(engine.label(alias), Some(secret()));
        assert_eq!(
            engine.authorize(alias, sink, FlowChannel::Ipc, PURPOSE_SYSTEM, 1),
            Ok(FlowDecision::Denied)
        );
        let joined = engine.aggregate(&[source, internal], aggregate).unwrap();
        assert!(joined.data.contains(TaintSet::SECRET));
        assert_eq!(
            engine.authorize(aggregate, sink, FlowChannel::Clipboard, PURPOSE_SYSTEM, 1),
            Ok(FlowDecision::Denied)
        );
        let reasons: Vec<_> = engine
            .audit_events()
            .filter(|event| event.decision == FlowDecision::Denied)
            .map(|event| event.reason)
            .collect();
        assert_eq!(reasons, [FlowReason::DataTaint, FlowReason::DataTaint]);
    }

    #[test]
    fn declassification_requires_scope_expiry_and_fresh_source_generation() {
        let mut engine = FlowEngine::<4, 32>::new();
        let source = id(10);
        let sink = id(11);
        engine.register(source, secret()).unwrap();
        engine.register(sink, FlowLabel::public()).unwrap();
        engine
            .set_policy(sink, FlowPolicy::for_clearance(Secrecy::Public))
            .unwrap();
        let grant = engine
            .mint_declass_grant(
                DeclassRoot::BOOTSTRAP,
                source,
                TaintSet::SECRET,
                TaintSet::SECRET,
                PURPOSE_DISPLAY,
                10,
            )
            .unwrap();
        let cleared = engine.declassify(source, grant, 5).unwrap();
        assert!(cleared.data.is_empty() && cleared.control.is_empty());
        assert_eq!(cleared.purposes, PURPOSE_DISPLAY);
        assert_eq!(
            engine.authorize(source, sink, FlowChannel::Display, PURPOSE_DISPLAY, 6),
            Ok(FlowDecision::Allowed)
        );
        assert_eq!(engine.declassify(source, grant, 6), Err(FlowError::Denied));
    }

    #[test]
    fn control_flow_and_expiry_are_independent_limitations() {
        let mut engine = FlowEngine::<4, 16>::new();
        let source = id(20);
        let sink = id(21);
        let label = FlowLabel {
            control: TaintSet::SECRET,
            expires_at: 4,
            ..FlowLabel::for_secrecy(Secrecy::Sensitive)
        };
        engine.register(source, label).unwrap();
        engine.register(sink, FlowLabel::public()).unwrap();
        engine
            .set_policy(sink, FlowPolicy::for_clearance(Secrecy::Sensitive))
            .unwrap();
        assert_eq!(
            engine.authorize(source, sink, FlowChannel::Network, PURPOSE_SYSTEM, 3),
            Ok(FlowDecision::Denied)
        );
        assert_eq!(
            engine.authorize(source, sink, FlowChannel::Network, PURPOSE_SYSTEM, 5),
            Ok(FlowDecision::Denied)
        );
        let reasons: Vec<_> = engine.audit_events().map(|event| event.reason).collect();
        assert_eq!(reasons, [FlowReason::ControlTaint, FlowReason::Expired]);
    }

    #[test]
    fn audit_overflow_fails_closed_without_overwriting() {
        let mut engine = FlowEngine::<2, 1>::new();
        let source = id(30);
        engine.register(source, FlowLabel::public()).unwrap();
        assert_eq!(
            engine.authorize(source, source, FlowChannel::Copy, PURPOSE_SYSTEM, 1),
            Err(FlowError::InvalidPolicy)
        );
        engine.set_policy(source, FlowPolicy::public()).unwrap();
        assert_eq!(
            engine.authorize(source, source, FlowChannel::Copy, PURPOSE_SYSTEM, 1),
            Ok(FlowDecision::Allowed)
        );
        assert_eq!(
            engine.authorize(source, source, FlowChannel::Copy, PURPOSE_SYSTEM, 1),
            Err(FlowError::AuditFull)
        );
        let (allowed, denied, overflow, _) = engine.drain_audit();
        assert_eq!((allowed, denied, overflow), (1, 0, 1));
    }
}
