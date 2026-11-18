//! Unified authorization projection over existing security facts.
//!
//! 本模块不拥有权限状态：主体身份来自 `SecurityContext`，操作能力来自
//! `SyscallSet`；策略代际由调用适配器从现有 PEP/策略源读取，撤销代际只有在
//! 完整系统级撤销源存在时才可填写。它只把这些事实组合成一次可审计、失败关闭
//! 的决策，供不同系统能力共用。
//!
//! This module does not own authority. Subject identity comes from the active
//! `SecurityContext`, operation capability from `SyscallSet`, and policy facts
//! from the existing policy source. Revocation is accepted only when a complete
//! system-wide source supplies it. The module produces one bounded,
//! fail-closed decision shared by system capabilities.

use crate::security::{MetadataState, SecurityContext};
use crate::syscall_set::SyscallSet;

pub const AUTHZ_FORMAT_VERSION: u16 = 1;
pub const KERNEL_PEP_ISSUER: u64 = 1;
pub const MAX_DELEGATION_DEPTH: u16 = 16; // JASPER-HARDCODE-REVIEW: issue=39 source=authz-delegation-depth-policy reason=bounded-policy-limit-not-platform-capability

/// Resource scope represented by the same opaque identities as native install
/// ownership. The adapter must map facts from the authoritative owner object;
/// names and paths are never scopes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessScope {
    Platform,
    Device(u64),
    User(u64),
    Group(u64),
    Tenant(u64),
    Workload(u64),
    Service(u64),
}

impl AccessScope {
    pub const fn is_valid(self) -> bool {
        match self {
            Self::Platform => true,
            Self::Device(id)
            | Self::User(id)
            | Self::Group(id)
            | Self::Tenant(id)
            | Self::Workload(id)
            | Self::Service(id) => id != 0,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Platform => "platform",
            Self::Device(_) => "device",
            Self::User(_) => "user",
            Self::Group(_) => "group",
            Self::Tenant(_) => "tenant",
            Self::Workload(_) => "workload",
            Self::Service(_) => "service",
        }
    }
}

/// Operation identity is stable within the authorization namespace. The
/// numeric value is internal metadata here; a public ABI may expose it only
/// after its own compatibility review.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    SystemUpdateStatus,
    SystemUpdateRecover,
    SystemUpdateArchive,
    SystemUpdateAudit,
    SystemInstallPublisherRotate,
    SystemInstallPublisherRecover,
}

impl Operation {
    const fn name(self) -> &'static str {
        match self {
            Self::SystemUpdateStatus => "system.update.status",
            Self::SystemUpdateRecover => "system.update.recover",
            Self::SystemUpdateArchive => "system.update.archive",
            Self::SystemUpdateAudit => "system.update.audit",
            Self::SystemInstallPublisherRotate => "system.install.publisher.rotate",
            Self::SystemInstallPublisherRecover => "system.install.publisher.recover",
        }
    }

    /// Each lifecycle operation has one security effect. A caller adapter
    /// cannot relabel a mutation as a read to obtain a weaker decision.
    ///
    /// 每个生命周期操作只有一个安全效果，适配器不能把写操作伪装成读操作。
    const fn expected_effect(self) -> Effect {
        match self {
            Self::SystemUpdateStatus | Self::SystemUpdateAudit => Effect::Read,
            Self::SystemUpdateRecover
            | Self::SystemUpdateArchive
            | Self::SystemInstallPublisherRotate
            | Self::SystemInstallPublisherRecover => Effect::Write,
        }
    }
}

/// Effect is intentionally coarse for the shared decision record. The exact
/// syscall metadata remains authoritative for finer-grained effects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    Read,
    Write,
}

impl Effect {
    const fn name(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

/// Current caller facts, all derived by kernel code rather than request input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallerFacts {
    pub context: SecurityContext,
    pub tenant: u64,
    pub scope: AccessScope,
    pub syscalls: SyscallSet,
    pub policy_epoch: u64,
    /// Current global revocation generation, or `None` when no complete
    /// system-wide revocation source is available. An object generation is not
    /// a substitute for this fact.
    pub revocation_generation: Option<u32>,
    pub now: u64,
    pub clock_trusted: bool,
}

/// One authorization request. A caller cannot provide this structure directly
/// through an ABI; the owning subsystem's adapter constructs it from trusted
/// operation metadata and resource facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub issuer: u64,
    pub operation: Operation,
    pub scope: AccessScope,
    pub required_syscall: u32,
    pub effect: Effect,
    pub not_before: u64,
    pub expires_at: Option<u64>,
    pub delegation_depth: u16,
    pub max_delegation_depth: u16,
    pub required_policy_epoch: u64,
    pub required_revocation_generation: Option<u32>,
}

/// Stable denial reasons. Unknown or incomplete facts never become allowance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    Allowed,
    InvalidIssuer,
    InvalidSubject,
    InvalidTenant,
    InactiveSubject,
    InvalidScope,
    ScopeMismatch,
    InvalidEffect,
    MissingCapability,
    PolicyStale,
    RevocationStale,
    RevocationUnavailable,
    NotYetValid,
    Expired,
    ClockUntrusted,
    DelegationTooDeep,
}

impl Reason {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::InvalidIssuer => "invalid_issuer",
            Self::InvalidSubject => "invalid_subject",
            Self::InvalidTenant => "invalid_tenant",
            Self::InactiveSubject => "inactive_subject",
            Self::InvalidScope => "invalid_scope",
            Self::ScopeMismatch => "scope_mismatch",
            Self::InvalidEffect => "invalid_effect",
            Self::MissingCapability => "missing_capability",
            Self::PolicyStale => "policy_stale",
            Self::RevocationStale => "revocation_stale",
            Self::RevocationUnavailable => "revocation_unavailable",
            Self::NotYetValid => "not_yet_valid",
            Self::Expired => "expired",
            Self::ClockUntrusted => "clock_untrusted",
            Self::DelegationTooDeep => "delegation_too_deep",
        }
    }
}

/// Complete bounded decision record. It names both the policy issuer and the
/// executor captured by `SecurityContext`; those identities are deliberately
/// separate. Consumers may serialize it into their own reliable audit stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decision {
    pub format_version: u16,
    pub issuer: u64,
    pub subject: u64,
    pub executor_object: u64,
    pub executor_generation: u32,
    pub tenant: u64,
    pub domain: u32,
    pub operation: Operation,
    pub scope: AccessScope,
    pub effect: Effect,
    pub policy_epoch: u64,
    pub revocation_generation: Option<u32>,
    pub allowed: bool,
    pub reason: Reason,
}

impl Decision {
    pub const fn admitted(self) -> bool {
        self.allowed && matches!(self.reason, Reason::Allowed)
    }
}

/// Evaluate one request against caller-supplied authoritative facts.
///
/// Checks are ordered from identity and scope to capability and finally
/// time/delegation conditions. Every failure returns a complete decision so
/// the caller can audit both successful and denied attempts.
pub fn authorize(caller: CallerFacts, request: Request) -> Decision {
    let context = caller.context;
    let mut decision = Decision {
        format_version: AUTHZ_FORMAT_VERSION,
        issuer: request.issuer,
        subject: context.object.object_id,
        executor_object: context.object.object_id,
        executor_generation: context.object.generation,
        tenant: caller.tenant,
        domain: context.mac.domain.0,
        operation: request.operation,
        scope: request.scope,
        effect: request.effect,
        policy_epoch: caller.policy_epoch,
        revocation_generation: caller.revocation_generation,
        allowed: false,
        reason: Reason::Allowed,
    };
    let reason = if request.issuer != KERNEL_PEP_ISSUER {
        Reason::InvalidIssuer
    } else if !matches!(context.state, MetadataState::Active) {
        Reason::InactiveSubject
    } else if context.require_active().is_err() {
        Reason::InvalidSubject
    } else if context.subject_identity().is_none() {
        Reason::InvalidSubject
    } else if caller.tenant == 0 {
        Reason::InvalidTenant
    } else if !caller.scope.is_valid() || !request.scope.is_valid() {
        Reason::InvalidScope
    } else if caller.scope != request.scope {
        Reason::ScopeMismatch
    } else if request.effect != request.operation.expected_effect() {
        Reason::InvalidEffect
    } else if !caller
        .syscalls
        .contains(u64::from(request.required_syscall))
    {
        Reason::MissingCapability
    } else if caller.policy_epoch < request.required_policy_epoch {
        Reason::PolicyStale
    } else if request.required_revocation_generation.is_some()
        && caller.revocation_generation != request.required_revocation_generation
    {
        if caller.revocation_generation.is_none() {
            Reason::RevocationUnavailable
        } else {
            Reason::RevocationStale
        }
    } else if request.not_before > caller.now {
        Reason::NotYetValid
    } else if request
        .expires_at
        .is_some_and(|expires| expires <= caller.now)
    {
        Reason::Expired
    } else if request.expires_at.is_some() && !caller.clock_trusted {
        Reason::ClockUntrusted
    } else if request.delegation_depth > request.max_delegation_depth
        || request.max_delegation_depth > MAX_DELEGATION_DEPTH
    {
        Reason::DelegationTooDeep
    } else {
        decision.allowed = true;
        Reason::Allowed
    };
    decision.reason = reason;
    decision
}

/// Compact stable rendering used by kernel diagnostics. It is not a substitute
/// for the subsystem's durable audit journal.
pub fn diagnostic_fields(
    decision: Decision,
) -> (
    u16,
    u64,
    u64,
    u32,
    u64,
    u32,
    &'static str,
    &'static str,
    &'static str,
    u64,
    Option<u32>,
    bool,
    &'static str,
) {
    (
        decision.format_version,
        decision.issuer,
        decision.subject,
        decision.executor_generation,
        decision.tenant,
        decision.domain,
        decision.operation.name(),
        decision.scope.name(),
        decision.effect.name(),
        decision.policy_epoch,
        decision.revocation_generation,
        decision.admitted(),
        decision.reason.name(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::objtable::ObjId;
    use crate::security::{BootId, IdentityClass};

    fn context(active: bool) -> SecurityContext {
        let id = ObjId::from_raw((1u64 << 32) | 8).unwrap();
        let mut context = SecurityContext::new(
            BootId::from_words([1, 2]),
            IdentityClass::Process,
            id,
            None,
            MetadataState::Active,
        );
        if !active {
            context.state = MetadataState::LegacyBootstrap;
        }
        context
    }

    fn caller(context: SecurityContext) -> CallerFacts {
        CallerFacts {
            context,
            tenant: 3,
            scope: AccessScope::Platform,
            syscalls: SyscallSet::of(&[111]),
            policy_epoch: 9,
            revocation_generation: Some(4),
            now: 100,
            clock_trusted: true,
        }
    }

    fn request() -> Request {
        Request {
            issuer: KERNEL_PEP_ISSUER,
            operation: Operation::SystemUpdateStatus,
            scope: AccessScope::Platform,
            required_syscall: 111,
            effect: Effect::Read,
            not_before: 1,
            expires_at: Some(200),
            delegation_depth: 0,
            max_delegation_depth: 2,
            required_policy_epoch: 9,
            required_revocation_generation: Some(4),
        }
    }

    #[test]
    fn active_caller_with_exact_facts_is_admitted_and_fully_described() {
        let decision = authorize(caller(context(true)), request());
        assert!(decision.admitted());
        assert_eq!(decision.issuer, KERNEL_PEP_ISSUER);
        assert_eq!(decision.subject, context(true).object.object_id);
        assert_eq!(decision.executor_object, context(true).object.object_id);
        assert_eq!(decision.executor_generation, 1);
        assert_eq!(decision.domain, context(true).mac.domain.0);
        assert_eq!(decision.reason, Reason::Allowed);
    }

    #[test]
    fn first_object_generation_zero_is_a_valid_active_subject() {
        let id = ObjId::from_raw(7).unwrap();
        let context = SecurityContext::new(
            BootId::from_words([1, 2]),
            IdentityClass::Process,
            id,
            None,
            MetadataState::Active,
        );
        let decision = authorize(caller(context), request());
        assert!(decision.admitted());
        assert_eq!(decision.executor_generation, 0);
    }

    #[test]
    fn non_subject_identity_cannot_request_process_operations() {
        let id = ObjId::from_raw((1u64 << 32) | 7).unwrap();
        let context = SecurityContext::new(
            BootId::from_words([1, 2]),
            IdentityClass::Device,
            id,
            None,
            MetadataState::Active,
        );
        assert_eq!(
            authorize(caller(context), request()).reason,
            Reason::InvalidSubject
        );
    }

    #[test]
    fn identity_scope_and_capability_fail_closed_without_partial_allowance() {
        let mut facts = caller(context(true));
        facts.tenant = 0;
        assert_eq!(authorize(facts, request()).reason, Reason::InvalidTenant);

        let mut facts = caller(context(true));
        facts.scope = AccessScope::Tenant(3);
        assert_eq!(authorize(facts, request()).reason, Reason::ScopeMismatch);

        let mut facts = caller(context(true));
        facts.syscalls = SyscallSet::EMPTY;
        assert_eq!(
            authorize(facts, request()).reason,
            Reason::MissingCapability
        );

        let mut facts = caller(context(true));
        facts.policy_epoch = 8;
        assert_eq!(authorize(facts, request()).reason, Reason::PolicyStale);

        let mut facts = caller(context(true));
        facts.revocation_generation = Some(3);
        assert_eq!(authorize(facts, request()).reason, Reason::RevocationStale);

        let mut facts = caller(context(true));
        facts.revocation_generation = None;
        assert_eq!(
            authorize(facts, request()).reason,
            Reason::RevocationUnavailable
        );
    }

    #[test]
    fn inactive_legacy_identity_and_untrusted_issuer_are_denied() {
        assert_eq!(
            authorize(caller(context(false)), request()).reason,
            Reason::InactiveSubject
        );
        assert_eq!(
            authorize(
                caller(context(true)),
                Request {
                    issuer: 0,
                    ..request()
                }
            )
            .reason,
            Reason::InvalidIssuer
        );
        assert_eq!(
            authorize(
                caller(context(true)),
                Request {
                    issuer: KERNEL_PEP_ISSUER + 1,
                    ..request()
                }
            )
            .reason,
            Reason::InvalidIssuer
        );
    }

    #[test]
    fn operation_effect_mismatch_is_denied() {
        assert_eq!(
            authorize(
                caller(context(true)),
                Request {
                    effect: Effect::Write,
                    ..request()
                }
            )
            .reason,
            Reason::InvalidEffect
        );
        assert_eq!(
            authorize(
                caller(context(true)),
                Request {
                    operation: Operation::SystemUpdateRecover,
                    effect: Effect::Read,
                    ..request()
                }
            )
            .reason,
            Reason::InvalidEffect
        );
    }

    #[test]
    fn time_conditions_never_allow_an_uncertain_lease() {
        assert_eq!(
            authorize(
                caller(context(true)),
                Request {
                    not_before: 101,
                    ..request()
                }
            )
            .reason,
            Reason::NotYetValid
        );
        assert_eq!(
            authorize(
                caller(context(true)),
                Request {
                    expires_at: Some(100),
                    ..request()
                }
            )
            .reason,
            Reason::Expired
        );
        let mut facts = caller(context(true));
        facts.clock_trusted = false;
        assert_eq!(authorize(facts, request()).reason, Reason::ClockUntrusted);
    }

    #[test]
    fn delegation_depth_is_bounded_before_any_effect() {
        assert_eq!(
            authorize(
                caller(context(true)),
                Request {
                    operation: Operation::SystemUpdateRecover,
                    delegation_depth: 3,
                    max_delegation_depth: 2,
                    effect: Effect::Write,
                    ..request()
                }
            )
            .reason,
            Reason::DelegationTooDeep
        );
        assert_eq!(
            authorize(
                caller(context(true)),
                Request {
                    max_delegation_depth: MAX_DELEGATION_DEPTH + 1,
                    ..request()
                }
            )
            .reason,
            Reason::DelegationTooDeep
        );
    }
}
