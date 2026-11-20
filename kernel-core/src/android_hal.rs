//! Native HAL adapter contract over the existing Driver Host authority.
//!
//! This module validates Android service identity and lifecycle facts. HAL
//! payloads, Binder wire records and vendor ioctl commands remain outside the
//! Jasper native ABI. Device access still goes through one Driver Host pass.

use crate::authz::{AccessScope, Decision, KERNEL_PEP_ISSUER, Operation};
use crate::driver_host::{
    DriverHostBroker, Error as DriverHostError, HostToken, PassFacts, PassToken,
    RequestKind, RequestToken, Terminal,
};
use crate::event_wait::{Enroll, Key, Registration, SetError, WaitSet};
use crate::security::SubjectIdentity;
use crate::task_index::Token;

pub const ANDROID_HAL_CONTRACT_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AndroidApiLevel(pub u32);

impl AndroidApiLevel {
    pub const fn is_valid(self) -> bool {
        self.0 != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HalInterface {
    pub package: u64,
    pub interface: u64,
    pub instance: u32,
    pub version_major: u16,
    pub version_minor: u16,
}

impl HalInterface {
    pub const fn is_valid(self) -> bool {
        self.package != 0 && self.interface != 0 && self.instance != 0
    }
}

/// A bounded service generation. The Binder identity is a projection of an
/// existing security subject, not a second process/account authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HalServiceIdentity {
    pub binder_subject: SubjectIdentity,
    pub interface: HalInterface,
    pub capability_generation: u64,
}

impl HalServiceIdentity {
    pub const fn is_valid(self) -> bool {
        self.binder_subject.object.object_id != 0
            && self.binder_subject.object.generation != 0
            && self.interface.is_valid()
            && self.capability_generation != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HalServiceState {
    Starting,
    Ready,
    Crashed,
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HalError {
    UnsupportedApi,
    InvalidIdentity,
    InvalidInterface,
    AuthorizationDenied,
    AuthorizationEpoch,
    Driver(DriverHostError),
    NotReady,
    Crashed,
    StaleGeneration,
    Busy,
    Full,
    Exhausted,
    StaleWaiter,
}

impl From<DriverHostError> for HalError {
    fn from(value: DriverHostError) -> Self {
        Self::Driver(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HalDeath {
    pub service: HalServiceIdentity,
    pub generation: u64,
    pub terminal: Terminal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HalRequest {
    pub token: RequestToken,
    pub operation: RequestKind,
    pub units: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HalWait {
    Ready(HalDeath),
    Armed(Key),
    TimedOut,
}

/// One HAL service binding with a caller-selected death-notification capacity.
pub struct HalService<const WAITERS: usize> {
    identity: HalServiceIdentity,
    api: AndroidApiLevel,
    state: HalServiceState,
    pass: Option<PassToken>,
    facts: Option<PassFacts>,
    death_generation: u64,
    waiters: WaitSet<WAITERS>,
}

impl<const WAITERS: usize> HalService<WAITERS> {
    pub fn new(
        api: AndroidApiLevel,
        identity: HalServiceIdentity,
        pass: PassToken,
        facts: PassFacts,
        authorization: Decision,
    ) -> Result<Self, HalError> {
        if !api.is_valid() {
            return Err(HalError::UnsupportedApi);
        }
        if !identity.is_valid() {
            return Err(HalError::InvalidIdentity);
        }
        if !authorization.admitted()
            || authorization.issuer != KERNEL_PEP_ISSUER
            || authorization.operation != Operation::AndroidHalServiceBind
            || authorization.scope != AccessScope::Device(u64::from(facts.device().identity))
        {
            return Err(HalError::AuthorizationDenied);
        }
        if authorization.policy_epoch == 0 {
            return Err(HalError::AuthorizationEpoch);
        }
        if facts.pass_generation() != pass.generation()
            || !facts.rights().contains(crate::driver_host::Needs::DEVICE)
        {
            return Err(HalError::Driver(DriverHostError::AuthorityDenied));
        }
        Ok(Self {
            identity,
            api,
            state: HalServiceState::Starting,
            pass: Some(pass),
            facts: Some(facts),
            death_generation: 1,
            waiters: WaitSet::new(),
        })
    }

    pub const fn api(&self) -> AndroidApiLevel {
        self.api
    }

    pub const fn identity(&self) -> HalServiceIdentity {
        self.identity
    }

    pub const fn state(&self) -> HalServiceState {
        self.state
    }

    pub const fn death_generation(&self) -> u64 {
        self.death_generation
    }

    pub fn ready(&mut self) -> Result<(), HalError> {
        if self.state != HalServiceState::Starting {
            return Err(HalError::NotReady);
        }
        self.state = HalServiceState::Ready;
        Ok(())
    }

    /// Start one operation through the existing pass; no request is retained
    /// in this adapter after the broker returns its token.
    pub fn begin<
        const DEVICES: usize,
        const HOSTS: usize,
        const PASSES: usize,
        const INFLIGHT: usize,
    >(
        &self,
        broker: &mut DriverHostBroker<DEVICES, HOSTS, PASSES, INFLIGHT>,
        operation: RequestKind,
        units: u64,
    ) -> Result<HalRequest, HalError> {
        if self.state != HalServiceState::Ready {
            return Err(match self.state {
                HalServiceState::Crashed => HalError::Crashed,
                _ => HalError::NotReady,
            });
        }
        let pass = self.pass.ok_or(HalError::Crashed)?;
        let token = broker
            .begin_bounded(pass, operation, units)
            .map_err(HalError::from)?;
        Ok(HalRequest {
            token,
            operation,
            units,
        })
    }

    pub fn complete<
        const DEVICES: usize,
        const HOSTS: usize,
        const PASSES: usize,
        const INFLIGHT: usize,
    >(
        &self,
        broker: &mut DriverHostBroker<DEVICES, HOSTS, PASSES, INFLIGHT>,
        request: HalRequest,
    ) -> Result<Terminal, HalError> {
        if self.state != HalServiceState::Ready {
            return Err(HalError::NotReady);
        }
        broker.complete(request.token).map_err(HalError::from)
    }

    pub fn cancel<
        const DEVICES: usize,
        const HOSTS: usize,
        const PASSES: usize,
        const INFLIGHT: usize,
    >(
        &self,
        broker: &mut DriverHostBroker<DEVICES, HOSTS, PASSES, INFLIGHT>,
        request: HalRequest,
    ) -> Result<Terminal, HalError> {
        broker.cancel(request.token).map_err(HalError::from)
    }

    /// Register a death waiter. The caller owns the existing task registration
    /// and supplies an absolute deadline in the scheduler clock domain.
    pub fn wait_death(
        &mut self,
        registration: &mut Registration,
        task: Token,
        now: u64,
        deadline: Option<u64>,
    ) -> Result<HalWait, HalError> {
        if self.state != HalServiceState::Crashed && self.state != HalServiceState::Stopped {
            return match registration.enroll(task, false, now, deadline) {
                Enroll::Ready => Err(HalError::Busy),
                Enroll::TimedOut => Ok(HalWait::TimedOut),
                Enroll::Busy => Err(HalError::Busy),
                Enroll::Exhausted => Err(HalError::Exhausted),
                Enroll::Armed(key) => {
                    self.waiters.insert(key).map_err(|error| match error {
                        SetError::Full => HalError::Full,
                        SetError::DuplicateTask => HalError::Busy,
                    })?;
                    Ok(HalWait::Armed(key))
                }
            };
        }
        if registration.pending().is_some() {
            return Err(HalError::Busy);
        }
        Ok(HalWait::Ready(HalDeath {
            service: self.identity,
            generation: self.death_generation,
            terminal: Terminal::Revoked,
        }))
    }

    pub fn take_death(
        &mut self,
        registration: &mut Registration,
        key: Key,
    ) -> Result<HalDeath, HalError> {
        let removed = self.waiters.remove(key);
        if !removed || !registration.finish(key) {
            return Err(HalError::StaleWaiter);
        }
        if self.state != HalServiceState::Crashed && self.state != HalServiceState::Stopped {
            return Err(HalError::NotReady);
        }
        Ok(HalDeath {
            service: self.identity,
            generation: self.death_generation,
            terminal: Terminal::Cancelled,
        })
    }

    /// Mark the service dead, invalidate the old pass and notify registered
    /// waiters. Reusing the old generation requires a fresh authorization.
    pub fn crash<
        const DEVICES: usize,
        const HOSTS: usize,
        const PASSES: usize,
        const INFLIGHT: usize,
    >(
        &mut self,
        broker: &mut DriverHostBroker<DEVICES, HOSTS, PASSES, INFLIGHT>,
        host: HostToken,
        proof: crate::driver_host::QuiesceProof,
    ) -> Result<HalDeath, HalError> {
        if self.state == HalServiceState::Crashed || self.state == HalServiceState::Stopped {
            return Err(HalError::Crashed);
        }
        let generation = self
            .death_generation
            .checked_add(1)
            .ok_or(HalError::Exhausted)?;
        broker.crash(host, proof)?;
        self.state = HalServiceState::Crashed;
        self.pass = None;
        self.facts = None;
        self.death_generation = generation;
        Ok(HalDeath {
            service: self.identity,
            generation: self.death_generation,
            terminal: Terminal::Revoked,
        })
    }

    pub fn restart<
        const DEVICES: usize,
        const HOSTS: usize,
        const PASSES: usize,
        const INFLIGHT: usize,
    >(
        &mut self,
        broker: &DriverHostBroker<DEVICES, HOSTS, PASSES, INFLIGHT>,
        pass: PassToken,
        facts: PassFacts,
        authorization: Decision,
    ) -> Result<(), HalError> {
        if self.state != HalServiceState::Crashed && self.state != HalServiceState::Stopped {
            return Err(HalError::StaleGeneration);
        }
        if broker.pass_facts(pass).map_err(HalError::from)? != facts
            || !facts.rights().contains(crate::driver_host::Needs::DEVICE)
        {
            return Err(HalError::Driver(DriverHostError::AuthorityDenied));
        }
        if !authorization.admitted()
            || authorization.issuer != KERNEL_PEP_ISSUER
            || authorization.operation != Operation::AndroidHalServiceBind
            || authorization.scope != AccessScope::Device(u64::from(facts.device().identity))
            || authorization.policy_epoch == 0
        {
            return Err(HalError::AuthorizationDenied);
        }
        let generation = self
            .identity
            .capability_generation
            .checked_add(1)
            .ok_or(HalError::Exhausted)?;
        self.identity.capability_generation = generation;
        self.state = HalServiceState::Starting;
        self.pass = Some(pass);
        self.facts = Some(facts);
        Ok(())
    }

    pub fn stop(&mut self) -> Result<HalDeath, HalError> {
        if self.state == HalServiceState::Stopped {
            return Err(HalError::StaleGeneration);
        }
        let generation = self
            .death_generation
            .checked_add(1)
            .ok_or(HalError::Exhausted)?;
        self.state = HalServiceState::Stopped;
        self.pass = None;
        self.facts = None;
        self.death_generation = generation;
        self.waiters = WaitSet::new();
        Ok(HalDeath {
            service: self.identity,
            generation: self.death_generation,
            terminal: Terminal::Cancelled,
        })
    }

    pub fn drain_waiters(&mut self) -> usize {
        let mut count = 0;
        while self.waiters.pop().is_some() {
            count += 1;
        }
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::{Effect, Reason, AUTHZ_FORMAT_VERSION};
    use crate::driver_host::{DeviceIdentity, Needs, Policy};
    use crate::security::{BootId, IdentityClass, ObjectIdentity, SubjectIdentity};

    fn subject() -> SubjectIdentity {
        SubjectIdentity {
            object: ObjectIdentity {
                boot_id: BootId::from_words([1, 2]),
                class: IdentityClass::Service,
                object_id: 7,
                generation: 2,
            },
            application: None,
        }
    }

    fn interface() -> HalInterface {
        HalInterface {
            package: 11,
            interface: 22,
            instance: 1,
            version_major: 1,
            version_minor: 0,
        }
    }

    fn auth(identity: DeviceIdentity) -> Decision {
        Decision {
            format_version: AUTHZ_FORMAT_VERSION,
            issuer: KERNEL_PEP_ISSUER,
            subject: 7,
            executor_object: 7,
            executor_generation: 2,
            tenant: 0,
            domain: 0,
            operation: Operation::AndroidHalServiceBind,
            scope: AccessScope::Device(u64::from(identity.identity)),
            effect: Effect::Write,
            policy_epoch: 1,
            revocation_generation: None,
            allowed: true,
            reason: Reason::Allowed,
        }
    }

    fn broker() -> (
        DriverHostBroker<1, 1, 1, 8>,
        PassToken,
        PassFacts,
        DeviceIdentity,
        HostToken,
    ) {
        let mut broker = DriverHostBroker::new();
        let device = DeviceIdentity {
            identity: 3,
            generation: 1,
        };
        broker.discover(device).unwrap();
        let host = broker.register_host().unwrap();
        let pass = broker
            .admit(host, device, Needs::DEVICE, Policy::new(Needs::DEVICE, 0, 0, 0))
            .unwrap();
        let facts = broker.pass_facts(pass).unwrap();
        (broker, pass, facts, device, host)
    }

    #[test]
    fn binds_only_with_unified_authorization_and_existing_pass() {
        let (mut broker, pass, facts, device, _host) = broker();
        let identity = HalServiceIdentity {
            binder_subject: subject(),
            interface: interface(),
            capability_generation: 1,
        };
        let mut service = HalService::<2>::new(
            AndroidApiLevel(34),
            identity,
            pass,
            facts,
            auth(device),
        )
        .unwrap();
        assert_eq!(service.state(), HalServiceState::Starting);
        service.ready().unwrap();
        let request = service.begin(&mut broker, RequestKind::Dma, 1).unwrap_err();
        assert!(matches!(request, HalError::Driver(_)));
        assert_eq!(service.death_generation(), 1);
    }

    #[test]
    fn invalid_identity_api_and_authorization_fail_closed() {
        let (_broker, pass, facts, device, _host) = broker();
        let identity = HalServiceIdentity {
            binder_subject: subject(),
            interface: interface(),
            capability_generation: 1,
        };
        assert!(matches!(
            HalService::<1>::new(AndroidApiLevel(0), identity, pass, facts, auth(device)),
            Err(HalError::UnsupportedApi)
        ));
        let mut wrong = auth(device);
        wrong.operation = Operation::ServiceUiFramePresent;
        assert!(matches!(
            HalService::<1>::new(AndroidApiLevel(34), identity, pass, facts, wrong),
            Err(HalError::AuthorizationDenied)
        ));
    }

    #[test]
    fn death_wait_registration_is_one_shot_and_generation_scoped() {
        let (_broker, pass, facts, _, _host) = broker();
        let identity = HalServiceIdentity {
            binder_subject: subject(),
            interface: interface(),
            capability_generation: 1,
        };
        let mut service =
            HalService::<2>::new(AndroidApiLevel(34), identity, pass, facts, auth(DeviceIdentity { identity: 3, generation: 1 })).unwrap();
        let mut registration = Registration::new();
        let task = Token {
            slot: 1,
            generation: 1,
        };
        let HalWait::Armed(key) = service
            .wait_death(&mut registration, task, 0, None)
            .unwrap()
        else {
            panic!("death waiter should arm")
        };
        service.state = HalServiceState::Crashed;
        assert_eq!(service.take_death(&mut registration, key).unwrap().terminal, Terminal::Cancelled);
        assert_eq!(service.take_death(&mut registration, key), Err(HalError::StaleWaiter));
    }

    #[test]
    fn restart_boundary_rejects_old_state() {
        let (mut broker, pass, facts, device, host) = broker();
        let identity = HalServiceIdentity {
            binder_subject: subject(),
            interface: interface(),
            capability_generation: 1,
        };
        let mut service =
            HalService::<1>::new(AndroidApiLevel(34), identity, pass, facts, auth(device)).unwrap();
        service.ready().unwrap();
        assert_eq!(
            service
                .crash(&mut broker, host, crate::driver_host::QuiesceProof::CLEAN)
                .unwrap()
                .terminal,
            Terminal::Revoked
        );
        assert_eq!(service.state(), HalServiceState::Crashed);
        assert_eq!(
            service.begin(&mut broker, RequestKind::Dma, 1),
            Err(HalError::Crashed)
        );
        let recovered = broker
            .recover(host, crate::driver_host::QuiesceProof::CLEAN)
            .unwrap();
        let new_pass = broker
            .admit(
                recovered,
                device,
                Needs::DEVICE,
                Policy::new(Needs::DEVICE, 0, 0, 0),
            )
            .unwrap();
        let new_facts = broker.pass_facts(new_pass).unwrap();
        assert!(matches!(
            service.restart(&broker, pass, facts, auth(device)),
            Err(HalError::Driver(DriverHostError::StalePass))
        ));
        service
            .restart(&broker, new_pass, new_facts, auth(device))
            .unwrap();
        assert_eq!(service.identity().capability_generation, 2);
        service.ready().unwrap();
    }

    #[test]
    fn stop_without_broker_crash_still_closes_local_binding() {
        let (_broker, pass, facts, device, _host) = broker();
        let identity = HalServiceIdentity {
            binder_subject: subject(),
            interface: interface(),
            capability_generation: 1,
        };
        let mut service =
            HalService::<1>::new(AndroidApiLevel(34), identity, pass, facts, auth(device)).unwrap();
        service.ready().unwrap();
        let death = service.stop().unwrap();
        assert_eq!(death.terminal, Terminal::Cancelled);
        assert_eq!(
            service.begin(&mut DriverHostBroker::<1,1,1,1>::new(), RequestKind::Mmio, 1),
            Err(HalError::NotReady)
        );
    }
}
