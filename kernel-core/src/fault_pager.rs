//! Native, capability-bound user-space pager state machine.
//!
//! This module owns no address space and performs no page-table mutation. It
//! serializes validated missing-page requests and hands the caller a unique
//! two-phase resolution permit. The caller must install the page-table entry
//! (or reject access) before completing that permit.
//!
//! 原生受权用户态 Pager 状态机。本模块不拥有地址空间、不修改页表；真实
//! 调用方获得唯一的两阶段裁决许可，安装页表结果后才能完成该许可。

use crate::memory_capability::{
    BackingIdentity, CapabilityState, MemoryCapability, MemoryKind, MemoryRights,
    MEMORY_CAPABILITY_FORMAT_VERSION,
};
use crate::memory_object::PAGE_BYTES;
use crate::task_index::Token;

/// One missing-page access class. The values are Jasper-native and intentionally
/// do not encode Linux page-fault error bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PagerAccess {
    Read,
    Write,
    Execute,
}

impl PagerAccess {
    const fn required_rights(self) -> MemoryRights {
        match self {
            Self::Read => MemoryRights::READ,
            Self::Write => MemoryRights::WRITE,
            Self::Execute => MemoryRights::EXECUTE,
        }
    }
}

/// Authority to satisfy missing pages for one native memory-object range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PagerCapability {
    backing: BackingIdentity,
    start: u64,
    end: u64,
    capability: u64,
    epoch: u32,
    rights: MemoryRights,
}

impl PagerCapability {
    /// Derive pager authority from an active memory capability covering the
    /// object range. Pager handlers need write authority to publish contents.
    ///
    /// 从覆盖目标对象范围的 active memory capability 派生 Pager 权限；处理者
    /// 必须具备写入内容的能力。
    pub fn from_capability(
        capability: MemoryCapability,
        start: u64,
        pages: u64,
    ) -> Result<Self, PagerError> {
        let rights = MemoryRights::READ.union(MemoryRights::WRITE);
        if capability.format_version != MEMORY_CAPABILITY_FORMAT_VERSION
            || capability.state != CapabilityState::Active
            || !capability.rights.contains(rights)
            || !matches!(
                capability.kind,
                MemoryKind::Anonymous | MemoryKind::Image | MemoryKind::Stack | MemoryKind::Shared
            )
            || pages == 0
            || (!start.is_multiple_of(PAGE_BYTES))
        {
            return Err(PagerError::InvalidGrant);
        }
        let bytes = pages
            .checked_mul(PAGE_BYTES)
            .ok_or(PagerError::InvalidGrant)?;
        let end = start.checked_add(bytes).ok_or(PagerError::InvalidGrant)?;
        if !capability.covers(start, bytes, rights) {
            return Err(PagerError::InvalidGrant);
        }
        Ok(Self {
            backing: capability.backing,
            start,
            end,
            capability: capability.id,
            epoch: capability.epoch,
            rights,
        })
    }

    pub const fn backing(self) -> BackingIdentity {
        self.backing
    }

    pub const fn start(self) -> u64 {
        self.start
    }

    pub const fn end(self) -> u64 {
        self.end
    }

    pub const fn capability(self) -> u64 {
        self.capability
    }

    pub const fn epoch(self) -> u32 {
        self.epoch
    }

    fn contains(self, page: u64) -> bool {
        page >= self.start
            && page
                .checked_add(PAGE_BYTES)
                .is_some_and(|end| end <= self.end)
    }

    fn matches_live(self, capability: MemoryCapability) -> bool {
        capability.format_version == MEMORY_CAPABILITY_FORMAT_VERSION
            && capability.state == CapabilityState::Active
            && capability.id == self.capability
            && capability.epoch == self.epoch
            && capability.backing == self.backing
            && capability.rights.contains(self.rights)
            && capability.covers(self.start, self.end - self.start, self.rights)
    }
}

/// A faulting task's validated right to access one page in the backing object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FaultGrant {
    backing: BackingIdentity,
    page: u64,
    rights: MemoryRights,
    capability: u64,
    epoch: u32,
}

impl FaultGrant {
    pub fn from_capability(
        capability: MemoryCapability,
        page: u64,
        access: PagerAccess,
    ) -> Result<Self, PagerError> {
        let rights = access.required_rights();
        if !page.is_multiple_of(PAGE_BYTES)
            || capability.format_version != MEMORY_CAPABILITY_FORMAT_VERSION
            || capability.state != CapabilityState::Active
            || !capability.covers(page, PAGE_BYTES, rights)
        {
            return Err(PagerError::AccessDenied);
        }
        Ok(Self {
            backing: capability.backing,
            page,
            rights,
            capability: capability.id,
            epoch: capability.epoch,
        })
    }
}

/// Stable handler identity. `Token` carries task-slot generation, so a reused
/// slot cannot inherit a dead pager handler's pending work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PagerHandler {
    task: Token,
}

impl PagerHandler {
    pub fn new(task: Token) -> Result<Self, PagerError> {
        if task.generation == 0 {
            return Err(PagerError::InvalidHandler);
        }
        Ok(Self { task })
    }

    pub const fn task(self) -> Token {
        self.task
    }
}

/// One queued missing-page request. The backing identity and page offset are
/// stable identities, not virtual addresses or compatibility fault codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FaultEvent {
    pub id: u64,
    pub backing: BackingIdentity,
    pub page: u64,
    pub access: PagerAccess,
    pub task: Token,
    pub deadline: Option<u64>,
}

/// Exclusive permission to apply one final page-table decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolutionPermit {
    id: u64,
    handler: PagerHandler,
    backing: BackingIdentity,
    page: u64,
}

impl ResolutionPermit {
    pub const fn id(self) -> u64 {
        self.id
    }

    pub const fn page(self) -> u64 {
        self.page
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PagerError {
    InvalidGrant,
    InvalidHandler,
    NoHandler,
    WrongHandler,
    WrongObject,
    AccessDenied,
    InvalidPage,
    QueueFull,
    DuplicateFault(u64),
    RecursiveFault,
    DeadlineExpired,
    NoSuchFault,
    ResolutionBusy,
    StaleResolution,
    Exhausted,
    Revoked,
}

#[derive(Clone, Copy, Debug)]
struct Resolution {
    permit: ResolutionPermit,
}

/// Bounded pager request state. `N` is a caller-selected concurrency budget;
/// there is no hidden queue capacity.
#[derive(Clone, Debug)]
pub struct FaultPager<const N: usize> {
    grant: PagerCapability,
    handler: Option<PagerHandler>,
    faults: [Option<FaultEvent>; N],
    resolving: Option<Resolution>,
    next_id: u64,
    revoked: bool,
}

impl<const N: usize> FaultPager<N> {
    pub fn new(grant: PagerCapability, handler: PagerHandler) -> Self {
        Self {
            grant,
            handler: Some(handler),
            faults: [None; N],
            resolving: None,
            next_id: 1,
            revoked: false,
        }
    }

    pub const fn grant(&self) -> PagerCapability {
        self.grant
    }

    pub const fn handler(&self) -> Option<PagerHandler> {
        self.handler
    }

    pub fn pending(&self) -> usize {
        self.faults.iter().flatten().count()
    }

    pub fn fault(&self, id: u64) -> Option<FaultEvent> {
        self.faults
            .iter()
            .flatten()
            .copied()
            .find(|fault| fault.id == id)
    }

    /// Revalidate the live capability used to create this pager before serving
    /// another request. A stale epoch or backing identity fails closed.
    pub fn reauthorize(&self, live: MemoryCapability) -> Result<(), PagerError> {
        if self.revoked || self.handler.is_none() {
            return Err(PagerError::Revoked);
        }
        if !self.grant.matches_live(live) {
            return Err(PagerError::InvalidGrant);
        }
        Ok(())
    }

    /// Enqueue one missing-page request. Duplicate pending pages return their
    /// existing event id and never allocate a second final-page decision.
    pub fn enqueue(
        &mut self,
        task: Token,
        grant: FaultGrant,
        page: u64,
        access: PagerAccess,
        now: u64,
        deadline: Option<u64>,
    ) -> Result<FaultEvent, PagerError> {
        let handler = self.handler.ok_or(PagerError::NoHandler)?;
        if self.revoked {
            return Err(PagerError::Revoked);
        }
        if task == handler.task {
            return Err(PagerError::RecursiveFault);
        }
        if grant.backing != self.grant.backing
            || page != grant.page
            || !self.grant.contains(page)
            || !grant.rights.contains(access.required_rights())
        {
            return Err(PagerError::WrongObject);
        }
        if !page.is_multiple_of(PAGE_BYTES) {
            return Err(PagerError::InvalidPage);
        }
        if deadline.is_some_and(|deadline| now >= deadline) {
            return Err(PagerError::DeadlineExpired);
        }
        if let Some(existing) = self
            .faults
            .iter()
            .flatten()
            .find(|fault| fault.backing == grant.backing && fault.page == page)
        {
            return Err(PagerError::DuplicateFault(existing.id));
        }
        let slot = self
            .faults
            .iter()
            .position(Option::is_none)
            .ok_or(PagerError::QueueFull)?;
        let id = self.next_id;
        self.next_id = self.next_id.checked_add(1).ok_or(PagerError::Exhausted)?;
        let event = FaultEvent {
            id,
            backing: grant.backing,
            page,
            access,
            task,
            deadline,
        };
        self.faults[slot] = Some(event);
        Ok(event)
    }

    /// Claim the exclusive right to perform the final page-table decision for
    /// one event. The event remains pending until completion.
    pub fn begin_resolution(
        &mut self,
        handler: PagerHandler,
        id: u64,
        now: u64,
    ) -> Result<ResolutionPermit, PagerError> {
        self.require_handler(handler)?;
        if self.resolving.is_some() {
            return Err(PagerError::ResolutionBusy);
        }
        let Some(fault) = self.fault(id) else {
            return Err(PagerError::NoSuchFault);
        };
        if fault.deadline.is_some_and(|deadline| now >= deadline) {
            self.remove(id);
            return Err(PagerError::DeadlineExpired);
        }
        let permit = ResolutionPermit {
            id,
            handler,
            backing: fault.backing,
            page: fault.page,
        };
        self.resolving = Some(Resolution { permit });
        Ok(permit)
    }

    /// Complete a permit after the caller has installed the final page-table
    /// entry or established the final deny/fault result.
    pub fn complete(
        &mut self,
        handler: PagerHandler,
        permit: ResolutionPermit,
    ) -> Result<FaultEvent, PagerError> {
        self.validate_permit(handler, permit)?;
        let fault = self.remove(permit.id).ok_or(PagerError::StaleResolution)?;
        self.resolving = None;
        Ok(fault)
    }

    /// Abort a claimed resolution without consuming the pending event. This is
    /// used when page-table installation fails and the handler may retry.
    pub fn abort_resolution(
        &mut self,
        handler: PagerHandler,
        permit: ResolutionPermit,
    ) -> Result<(), PagerError> {
        self.validate_permit(handler, permit)?;
        self.resolving = None;
        Ok(())
    }

    /// Remove one unclaimed event. A handler cannot cancel work while it owns a
    /// final page-table decision; it must complete or abort that permit first.
    pub fn cancel(&mut self, id: u64) -> bool {
        if self.resolving.is_some_and(|resolution| resolution.permit.id == id) {
            return false;
        }
        self.remove(id).is_some()
    }

    /// Expire an unclaimed event under the caller's monotonic clock.
    pub fn expire(&mut self, id: u64, now: u64) -> bool {
        if self.resolving.is_some_and(|resolution| resolution.permit.id == id) {
            return false;
        }
        let expired = self
            .fault(id)
            .is_some_and(|fault| fault.deadline.is_some_and(|deadline| now >= deadline));
        expired && self.remove(id).is_some()
    }

    /// Handler death atomically withdraws all authority and pending work. Any
    /// outstanding resolution permit becomes stale.
    pub fn handler_exit(&mut self, handler: PagerHandler) -> usize {
        if self.handler != Some(handler) {
            return 0;
        }
        let removed = self.pending();
        self.handler = None;
        self.faults.fill(None);
        self.resolving = None;
        removed
    }

    /// Bind a replacement handler only after the previous handler exited and
    /// no old page-table decisions remain.
    pub fn rebind(
        &mut self,
        handler: PagerHandler,
        live: MemoryCapability,
    ) -> Result<(), PagerError> {
        if self.revoked {
            return Err(PagerError::Revoked);
        }
        if self.handler.is_some() || self.pending() != 0 || self.resolving.is_some() {
            return Err(PagerError::WrongHandler);
        }
        if !self.grant.matches_live(live) {
            return Err(PagerError::InvalidGrant);
        }
        self.handler = Some(handler);
        Ok(())
    }

    /// Revoke the exact pager capability epoch. The caller is responsible for
    /// invalidating mappings and minimizing stale TLB entries.
    pub fn revoke(&mut self, capability: u64, epoch: u32) -> usize {
        if self.revoked
            || capability != self.grant.capability
            || epoch != self.grant.epoch
        {
            return 0;
        }
        let removed = self.pending();
        self.revoked = true;
        self.handler = None;
        self.faults.fill(None);
        self.resolving = None;
        removed
    }

    fn require_handler(&self, handler: PagerHandler) -> Result<(), PagerError> {
        if self.revoked {
            return Err(PagerError::Revoked);
        }
        if self.handler != Some(handler) {
            return Err(PagerError::WrongHandler);
        }
        Ok(())
    }

    fn validate_permit(
        &self,
        handler: PagerHandler,
        permit: ResolutionPermit,
    ) -> Result<(), PagerError> {
        self.require_handler(handler)?;
        let Some(current) = self.resolving.map(|resolution| resolution.permit) else {
            return Err(PagerError::StaleResolution);
        };
        if current != permit
            || permit.handler != handler
            || permit.backing != self.grant.backing
            || !self.grant.contains(permit.page)
        {
            return Err(PagerError::StaleResolution);
        }
        Ok(())
    }

    fn remove(&mut self, id: u64) -> Option<FaultEvent> {
        let slot = self
            .faults
            .iter()
            .position(|fault| fault.is_some_and(|fault| fault.id == id))?;
        self.faults[slot].take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_capability::{
        CapabilityState, MEMORY_CAPABILITY_FORMAT_VERSION, MemoryKind, MemoryRights,
    };

    fn backing(generation: u32) -> BackingIdentity {
        BackingIdentity::new(7, generation).unwrap()
    }

    fn capability(id: u64, epoch: u32) -> MemoryCapability {
        MemoryCapability {
            id,
            format_version: MEMORY_CAPABILITY_FORMAT_VERSION,
            state: CapabilityState::Active,
            kind: MemoryKind::Shared,
            rights: MemoryRights::READ
                .union(MemoryRights::WRITE)
                .union(MemoryRights::EXECUTE),
            start: 0x1000,
            end: 0x9000,
            backing: backing(9),
            epoch,
        }
    }

    fn pager_grant() -> PagerCapability {
        PagerCapability::from_capability(capability(1, 3), 0x1000, 8).unwrap()
    }

    fn fault_grant(page: u64, access: PagerAccess) -> FaultGrant {
        FaultGrant::from_capability(capability(2, 4), page, access).unwrap()
    }

    fn token(generation: u64) -> Token {
        Token { slot: 3, generation }
    }

    fn handler() -> PagerHandler {
        PagerHandler::new(token(10)).unwrap()
    }

    fn enqueue<const N: usize>(
        pager: &mut FaultPager<N>,
        page: u64,
    ) -> FaultEvent {
        pager
            .enqueue(
                token(1),
                fault_grant(page, PagerAccess::Read),
                page,
                PagerAccess::Read,
                0,
                None,
            )
            .unwrap()
    }

    #[test]
    fn grants_reject_wrong_rights_state_and_alignment() {
        let mut cap = capability(1, 3);
        cap.state = CapabilityState::Revoked;
        assert_eq!(
            PagerCapability::from_capability(cap, 0x1000, 8),
            Err(PagerError::InvalidGrant)
        );
        let mut cap = capability(1, 3);
        cap.kind = MemoryKind::DeviceMmio;
        assert_eq!(
            PagerCapability::from_capability(cap, 0x1000, 8),
            Err(PagerError::InvalidGrant)
        );
        assert_eq!(
            FaultGrant::from_capability(capability(2, 4), 0x1001, PagerAccess::Read),
            Err(PagerError::AccessDenied)
        );
    }

    #[test]
    fn explicit_queue_capacity_and_duplicate_pages_have_no_hidden_slots() {
        let mut pager = FaultPager::<2>::new(pager_grant(), handler());
        let first = enqueue(&mut pager, 0x2000);
        assert_eq!(
            pager.enqueue(
                token(2),
                fault_grant(0x2000, PagerAccess::Read),
                0x2000,
                PagerAccess::Read,
                0,
                None,
            ),
            Err(PagerError::DuplicateFault(first.id))
        );
        enqueue(&mut pager, 0x3000);
        assert_eq!(pager.pending(), 2);
        assert_eq!(
            pager.enqueue(
                token(3),
                fault_grant(0x4000, PagerAccess::Read),
                0x4000,
                PagerAccess::Read,
                0,
                None,
            ),
            Err(PagerError::QueueFull)
        );
    }

    #[test]
    fn handler_self_fault_and_deadline_never_allocate_work() {
        let mut pager = FaultPager::<2>::new(pager_grant(), handler());
        assert_eq!(
            pager.enqueue(
                handler().task(),
                fault_grant(0x2000, PagerAccess::Read),
                0x2000,
                PagerAccess::Read,
                0,
                None,
            ),
            Err(PagerError::RecursiveFault)
        );
        assert_eq!(
            pager.enqueue(
                token(1),
                fault_grant(0x2000, PagerAccess::Read),
                0x2000,
                PagerAccess::Read,
                9,
                Some(9),
            ),
            Err(PagerError::DeadlineExpired)
        );
        assert_eq!(pager.pending(), 0);
    }

    #[test]
    fn resolution_is_exclusive_cancellable_and_retryable() {
        let mut pager = FaultPager::<2>::new(pager_grant(), handler());
        let event = enqueue(&mut pager, 0x2000);
        let permit = pager.begin_resolution(handler(), event.id, 0).unwrap();
        assert_eq!(
            pager.begin_resolution(handler(), event.id, 0),
            Err(PagerError::ResolutionBusy)
        );
        assert!(!pager.cancel(event.id));
        pager.abort_resolution(handler(), permit).unwrap();
        assert_eq!(pager.pending(), 1);
        let permit = pager.begin_resolution(handler(), event.id, 0).unwrap();
        assert_eq!(pager.complete(handler(), permit), Ok(event));
        assert_eq!(pager.pending(), 0);
        assert_eq!(
            pager.complete(handler(), permit),
            Err(PagerError::StaleResolution)
        );
    }

    #[test]
    fn handler_death_and_capability_revocation_invalidate_every_permit() {
        let mut pager = FaultPager::<2>::new(pager_grant(), handler());
        let first = enqueue(&mut pager, 0x2000);
        let permit = pager.begin_resolution(handler(), first.id, 0).unwrap();
        enqueue(&mut pager, 0x3000);
        assert_eq!(pager.handler_exit(handler()), 2);
        assert_eq!(pager.pending(), 0);
        assert_eq!(
            pager.complete(handler(), permit),
            Err(PagerError::WrongHandler)
        );
        let replacement = PagerHandler::new(token(11)).unwrap();
        assert_eq!(
            pager.rebind(replacement, capability(1, 4)),
            Err(PagerError::InvalidGrant)
        );
        pager.rebind(replacement, capability(1, 3)).unwrap();
        let second = enqueue(&mut pager, 0x2000);
        assert_eq!(pager.revoke(1, 3), 1);
        assert_eq!(pager.pending(), 0);
        assert_eq!(
            pager.begin_resolution(replacement, second.id, 0),
            Err(PagerError::Revoked)
        );
    }

    #[test]
    fn expiry_and_live_capability_epoch_are_exact() {
        let mut pager = FaultPager::<2>::new(pager_grant(), handler());
        let event = pager
            .enqueue(
                token(1),
                fault_grant(0x2000, PagerAccess::Write),
                0x2000,
                PagerAccess::Write,
                10,
                Some(20),
            )
            .unwrap();
        assert!(!pager.expire(event.id, 19));
        assert!(pager.expire(event.id, 20));
        assert_eq!(pager.pending(), 0);

        let mut stale = capability(1, 4);
        stale.epoch = 4;
        assert_eq!(pager.reauthorize(stale), Err(PagerError::InvalidGrant));
        assert_eq!(pager.reauthorize(capability(1, 3)), Ok(()));
    }

    #[test]
    fn event_id_exhaustion_does_not_publish_partial_work() {
        let mut pager = FaultPager::<2>::new(pager_grant(), handler());
        pager.next_id = u64::MAX;
        assert_eq!(
            pager.enqueue(
                token(1),
                fault_grant(0x2000, PagerAccess::Read),
                0x2000,
                PagerAccess::Read,
                0,
                None,
            ),
            Err(PagerError::Exhausted)
        );
        assert_eq!(pager.pending(), 0);
    }
}
