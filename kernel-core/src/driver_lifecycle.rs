//! Driver and firmware package lifecycle policy for LC-4.
//!
//! This module is a fail-closed state machine for signed driver/firmware
//! packages. It reuses Driver Host and DMA quiescence facts; it does not grant
//! device authority or perform hardware access.
//!
//! 本模块定义 LC-4 的驱动/固件签名包生命周期状态机。它只消费 Driver Host
//! 与 DMA 静默事实，不建立第二套设备权限，也不执行硬件访问。

use crate::driver_host::{
    self, DeviceIdentity, DriverHostBroker, HostToken, Needs, PassToken, Policy, QuiesceProof,
};

/// Signed driver or firmware package identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Package {
    pub digest: [u8; 32],
    pub signer: [u8; 32],
    pub release: u64,
    pub security_epoch: u64,
    pub signature_valid: bool,
}

impl Package {
    /// Construct a package whose manifest signature was already verified by
    /// the lifecycle trust boundary.
    pub const fn verified(
        digest: [u8; 32],
        signer: [u8; 32],
        release: u64,
        security_epoch: u64,
    ) -> Self {
        Self {
            digest,
            signer,
            release,
            security_epoch,
            signature_valid: true,
        }
    }

    fn valid_identity(self) -> bool {
        self.signer.iter().any(|byte| *byte != 0)
            && self.release != 0
            && self.digest.iter().any(|byte| *byte != 0)
    }
}

/// Explicit lifecycle policy, not a hardware fact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LifecyclePolicy {
    pub trusted_signer: [u8; 32],
    pub release_floor: u64,
    pub security_epoch: u64,
    pub hotplug: bool,
}

/// Lifecycle state. Only `Active` may own a device lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Empty,
    Verified,
    Authorized,
    Active,
    Quarantined,
    Recovering,
    Unloaded,
}

/// Stable lifecycle failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidPackage,
    Signature,
    UntrustedSigner,
    Downgrade,
    SecurityEpoch,
    WrongState,
    HotplugDenied,
    NotQuiesced,
    RecoveryUnavailable,
    StaleGeneration,
}

/// Failure from the composed Driver Host and package lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntegrationError {
    /// Signed package policy rejected the request.
    Lifecycle(Error),
    /// Driver Host authority or generation rejected the request.
    Host(driver_host::Error),
}

/// A pass and package authorization that belong to the same live generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lease {
    pub pass: PassToken,
    pub package: Token,
}

impl Error {
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidPackage => "system.driver.error.invalid_package",
            Self::Signature => "system.driver.error.signature",
            Self::UntrustedSigner => "system.driver.error.untrusted_signer",
            Self::Downgrade => "system.firmware.error.downgrade",
            Self::SecurityEpoch => "system.firmware.error.security_epoch",
            Self::WrongState => "system.driver.error.invalid_transition",
            Self::HotplugDenied => "system.driver.error.hotplug_denied",
            Self::NotQuiesced => "system.driver.error.reset_unsafe",
            Self::RecoveryUnavailable => "system.firmware.error.recovery_unavailable",
            Self::StaleGeneration => "system.driver.error.stale_generation",
        }
    }
}

/// Generation-bound authorization result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Token {
    pub generation: u64,
}

/// One driver/firmware lifecycle controller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Controller {
    state: State,
    generation: u64,
    candidate: Option<Package>,
    active: Option<Package>,
    known_good: Option<Package>,
    recovery: Option<Package>,
    device_generation: u32,
    policy: LifecyclePolicy,
}

impl Controller {
    pub const fn new(policy: LifecyclePolicy, recovery: Option<Package>) -> Self {
        Self {
            state: State::Empty,
            generation: 1,
            candidate: None,
            active: None,
            known_good: None,
            recovery,
            device_generation: 0,
            policy,
        }
    }

    pub const fn state(self) -> State {
        self.state
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }

    pub const fn active(self) -> Option<Package> {
        self.active
    }

    /// Whether this controller currently owns the named device generation.
    pub const fn owns_device(self, device_generation: u32) -> bool {
        matches!(self.state, State::Active) && self.device_generation == device_generation
    }

    /// Whether reset may transition this controller without changing its
    /// current package authority on a precondition failure.
    pub const fn reset_eligible(self) -> bool {
        matches!(self.state, State::Active | State::Quarantined)
    }

    /// Verify and stage one package without granting device authority.
    pub fn stage(&mut self, package: Package) -> Result<(), Error> {
        if !package.valid_identity() {
            return Err(Error::InvalidPackage);
        }
        if !package.signature_valid {
            return Err(Error::Signature);
        }
        if package.signer != self.policy.trusted_signer {
            return Err(Error::UntrustedSigner);
        }
        if package.release <= self.policy.release_floor {
            return Err(Error::Downgrade);
        }
        if package.security_epoch < self.policy.security_epoch {
            return Err(Error::SecurityEpoch);
        }
        if self
            .active
            .is_some_and(|active| package.release < active.release)
        {
            return Err(Error::Downgrade);
        }
        self.candidate = Some(package);
        self.state = State::Verified;
        Ok(())
    }

    /// Bind a verified package to an already-authorized Driver Host generation.
    pub fn authorize(&mut self, device_generation: u32) -> Result<Token, Error> {
        if self.state != State::Verified || self.candidate.is_none() || device_generation == 0 {
            return Err(Error::WrongState);
        }
        self.device_generation = device_generation;
        self.state = State::Authorized;
        Ok(Token {
            generation: self.generation,
        })
    }

    /// Activate an authorized package. Old tokens become stale.
    pub fn activate(&mut self, token: Token) -> Result<(), Error> {
        self.require_token(token)?;
        if self.state != State::Authorized {
            return Err(Error::WrongState);
        }
        let package = self.candidate.ok_or(Error::WrongState)?;
        if let Some(active) = self.active {
            self.known_good = Some(active);
        } else {
            self.known_good = Some(package);
        }
        self.active = Some(package);
        self.candidate = None;
        self.state = State::Active;
        self.generation = self.generation.checked_add(1).ok_or(Error::WrongState)?;
        Ok(())
    }

    /// A hotplug removal invalidates the active lease immediately.
    pub fn detach_device(&mut self, device_generation: u32) -> Result<(), Error> {
        if !self.policy.hotplug {
            return Err(Error::HotplugDenied);
        }
        if self.state != State::Active || device_generation != self.device_generation {
            return Err(Error::StaleGeneration);
        }
        self.state = State::Quarantined;
        self.generation = self.generation.checked_add(1).ok_or(Error::WrongState)?;
        Ok(())
    }

    /// Quarantine ownership after a Driver Host crash receipt.
    ///
    /// Unlike an orderly hotplug removal, a crash is not conditional on the
    /// package policy opting into hotplug support.
    pub fn crash_device(&mut self, device_generation: u32) -> Result<(), Error> {
        if !self.owns_device(device_generation) {
            return Err(Error::StaleGeneration);
        }
        self.state = State::Quarantined;
        self.generation = self.generation.checked_add(1).ok_or(Error::WrongState)?;
        Ok(())
    }

    /// A reset may unload only after DMA and IRQ quiescence are proven.
    pub fn finish_reset(&mut self, quiesced: bool) -> Result<(), Error> {
        if !quiesced {
            self.state = State::Quarantined;
            return Err(Error::NotQuiesced);
        }
        if !matches!(self.state, State::Active | State::Quarantined) {
            return Err(Error::WrongState);
        }
        self.active = None;
        self.state = State::Unloaded;
        self.generation = self.generation.checked_add(1).ok_or(Error::WrongState)?;
        Ok(())
    }

    /// Start recovery from an explicit recovery package or the known-good image.
    pub fn begin_recovery(&mut self) -> Result<Token, Error> {
        if !matches!(self.state, State::Quarantined | State::Unloaded) {
            return Err(Error::WrongState);
        }
        let package = self
            .recovery
            .or(self.known_good)
            .ok_or(Error::RecoveryUnavailable)?;
        self.candidate = Some(package);
        self.state = State::Recovering;
        self.generation = self.generation.checked_add(1).ok_or(Error::WrongState)?;
        Ok(Token {
            generation: self.generation,
        })
    }

    /// Complete recovery only after the recovered device is quiescent again.
    pub fn complete_recovery(&mut self, token: Token, quiesced: bool) -> Result<(), Error> {
        self.require_token(token)?;
        if self.state != State::Recovering {
            return Err(Error::WrongState);
        }
        if !quiesced {
            return Err(Error::NotQuiesced);
        }
        self.active = self.candidate.take();
        self.state = State::Active;
        self.generation = self.generation.checked_add(1).ok_or(Error::WrongState)?;
        Ok(())
    }

    fn require_token(self, token: Token) -> Result<(), Error> {
        (token.generation == self.generation)
            .then_some(())
            .ok_or(Error::StaleGeneration)
    }
}

/// Stage a signed package, then admit and activate its device under the same
/// Driver Host policy.
///
/// The pass is revoked if lifecycle activation fails after Driver Host
/// admission, so no hidden device authority survives a failed operation.
pub fn admit_and_activate<
    const DEVICES: usize,
    const HOSTS: usize,
    const PASSES: usize,
    const REQUESTS: usize,
>(
    lifecycle: &mut Controller,
    broker: &mut DriverHostBroker<DEVICES, HOSTS, PASSES, REQUESTS>,
    package: Package,
    host: HostToken,
    identity: DeviceIdentity,
    requested: Needs,
    policy: Policy,
) -> Result<Lease, IntegrationError> {
    lifecycle
        .stage(package)
        .map_err(IntegrationError::Lifecycle)?;
    let pass = broker
        .admit(host, identity, requested, policy)
        .map_err(IntegrationError::Host)?;
    let package_token = match lifecycle.authorize(identity.generation) {
        Ok(token) => token,
        Err(error) => {
            let _ = broker.revoke(pass);
            return Err(IntegrationError::Lifecycle(error));
        }
    };
    if let Err(error) = lifecycle.activate(package_token) {
        let _ = broker.revoke(pass);
        return Err(IntegrationError::Lifecycle(error));
    }
    Ok(Lease {
        pass,
        package: package_token,
    })
}

/// Reset a Driver Host and unload its package only after the same quiescence
/// proof. A failed preflight changes neither authority surface.
pub fn reset_and_unload<
    const DEVICES: usize,
    const HOSTS: usize,
    const PASSES: usize,
    const REQUESTS: usize,
>(
    lifecycle: &mut Controller,
    broker: &mut DriverHostBroker<DEVICES, HOSTS, PASSES, REQUESTS>,
    host: HostToken,
    proof: QuiesceProof,
) -> Result<(driver_host::ResetReceipt, HostToken), IntegrationError> {
    if !lifecycle.reset_eligible() {
        return Err(IntegrationError::Lifecycle(Error::WrongState));
    }
    if !proof.dma_quiesced || !proof.irq_quiesced {
        return Err(IntegrationError::Lifecycle(Error::NotQuiesced));
    }
    let receipt = broker.reset(host, proof).map_err(IntegrationError::Host)?;
    lifecycle
        .finish_reset(true)
        .map_err(IntegrationError::Lifecycle)?;
    Ok((receipt, receipt.token))
}

/// Publish a Driver Host crash receipt and quarantine package ownership.
pub fn crash_and_quarantine<
    const DEVICES: usize,
    const HOSTS: usize,
    const PASSES: usize,
    const REQUESTS: usize,
>(
    lifecycle: &mut Controller,
    broker: &mut DriverHostBroker<DEVICES, HOSTS, PASSES, REQUESTS>,
    host: HostToken,
    device_generation: u32,
    proof: QuiesceProof,
) -> Result<driver_host::CrashReceipt, IntegrationError> {
    if !lifecycle.owns_device(device_generation) {
        return Err(IntegrationError::Lifecycle(Error::StaleGeneration));
    }
    let receipt = broker.crash(host, proof).map_err(IntegrationError::Host)?;
    lifecycle
        .crash_device(device_generation)
        .map_err(IntegrationError::Lifecycle)?;
    Ok(receipt)
}

/// Recover a crashed host from the explicit recovery package or known-good
/// package, with both surfaces gated by the same clean quiescence proof.
pub fn recover_and_reactivate<
    const DEVICES: usize,
    const HOSTS: usize,
    const PASSES: usize,
    const REQUESTS: usize,
>(
    lifecycle: &mut Controller,
    broker: &mut DriverHostBroker<DEVICES, HOSTS, PASSES, REQUESTS>,
    host: HostToken,
    proof: QuiesceProof,
) -> Result<HostToken, IntegrationError> {
    if !proof.dma_quiesced || !proof.irq_quiesced {
        return Err(IntegrationError::Lifecycle(Error::NotQuiesced));
    }
    let host = match broker.recover(host, proof) {
        Ok(host) => host,
        Err(error) => return Err(IntegrationError::Host(error)),
    };
    let recovery = lifecycle
        .begin_recovery()
        .map_err(IntegrationError::Lifecycle)?;
    lifecycle
        .complete_recovery(recovery, true)
        .map_err(IntegrationError::Lifecycle)?;
    Ok(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package(release: u64) -> Package {
        Package::verified([release as u8; 32], [7; 32], release, 3)
    }

    fn policy() -> LifecyclePolicy {
        LifecyclePolicy {
            trusted_signer: [7; 32],
            release_floor: 1,
            security_epoch: 3,
            hotplug: true,
        }
    }

    #[test]
    fn stage_rejects_bad_signature_downgrade_and_epoch() {
        let mut lifecycle = Controller::new(policy(), None);
        assert_eq!(
            lifecycle.stage(Package {
                signature_valid: false,
                ..package(2)
            }),
            Err(Error::Signature)
        );
        assert_eq!(
            lifecycle.stage(Package {
                signer: [8; 32],
                ..package(2)
            }),
            Err(Error::UntrustedSigner)
        );
        assert_eq!(lifecycle.stage(package(1)), Err(Error::Downgrade));
        assert_eq!(
            lifecycle.stage(Package {
                security_epoch: 2,
                ..package(2)
            }),
            Err(Error::SecurityEpoch)
        );
        assert_eq!(lifecycle.state(), State::Empty);
    }

    #[test]
    fn authorized_hotplug_reset_and_recovery_form_one_generation_chain() {
        let recovery = package(2);
        let mut lifecycle = Controller::new(policy(), Some(recovery));
        lifecycle.stage(package(4)).unwrap();
        let authorization = lifecycle.authorize(11).unwrap();
        lifecycle.activate(authorization).unwrap();
        assert_eq!(lifecycle.state(), State::Active);
        assert!(matches!(
            lifecycle.activate(authorization),
            Err(Error::StaleGeneration)
        ));
        lifecycle.detach_device(11).unwrap();
        assert_eq!(lifecycle.state(), State::Quarantined);
        let recovery_token = lifecycle.begin_recovery().unwrap();
        assert_eq!(
            lifecycle.complete_recovery(recovery_token, false),
            Err(Error::NotQuiesced)
        );
        lifecycle.complete_recovery(recovery_token, true).unwrap();
        assert_eq!(lifecycle.state(), State::Active);
        assert_eq!(lifecycle.active(), Some(recovery));
    }

    #[test]
    fn reset_failure_quarantines_and_stale_tokens_fail_closed() {
        let mut lifecycle = Controller::new(policy(), None);
        lifecycle.stage(package(2)).unwrap();
        let token = lifecycle.authorize(9).unwrap();
        lifecycle.activate(token).unwrap();
        assert_eq!(lifecycle.finish_reset(false), Err(Error::NotQuiesced));
        assert_eq!(lifecycle.state(), State::Quarantined);
        let recovery = lifecycle.begin_recovery().unwrap();
        assert!(matches!(
            lifecycle.complete_recovery(token, true),
            Err(Error::StaleGeneration)
        ));
        lifecycle.complete_recovery(recovery, true).unwrap();
    }

    #[test]
    fn host_admission_and_package_activation_share_one_generation() {
        let mut lifecycle = Controller::new(policy(), None);
        let mut broker = DriverHostBroker::<2, 2, 2, 4>::new();
        let host = broker.register_host().unwrap();
        let identity = DeviceIdentity {
            identity: 0x1044,
            generation: 11,
        };
        assert_eq!(
            admit_and_activate(
                &mut lifecycle,
                &mut broker,
                package(4),
                host,
                identity,
                Needs::DEVICE,
                Policy::new(Needs::DEVICE, 0, 0, 0),
            ),
            Err(IntegrationError::Host(
                driver_host::Error::DeviceNotDiscovered
            ))
        );
        assert_eq!(lifecycle.state(), State::Verified);
        assert_eq!(broker.stats().active_passes, 0);

        broker.discover(identity).unwrap();
        let lease = admit_and_activate(
            &mut lifecycle,
            &mut broker,
            package(4),
            host,
            identity,
            Needs::DEVICE,
            Policy::new(Needs::DEVICE, 0, 0, 0),
        )
        .unwrap();
        assert_eq!(lifecycle.state(), State::Active);
        assert!(lifecycle.owns_device(identity.generation));
        assert_eq!(broker.stats().active_passes, 1);
        assert_eq!(
            lifecycle.generation(),
            lease.package.generation.checked_add(1).unwrap()
        );
    }

    #[test]
    fn reset_and_crash_receipts_revoke_old_host_and_package_tokens() {
        let mut lifecycle = Controller::new(policy(), None);
        let mut broker = DriverHostBroker::<2, 2, 2, 4>::new();
        let host = broker.register_host().unwrap();
        let identity = DeviceIdentity {
            identity: 0x1044,
            generation: 9,
        };
        broker.discover(identity).unwrap();
        let lease = admit_and_activate(
            &mut lifecycle,
            &mut broker,
            package(4),
            host,
            identity,
            Needs::DEVICE,
            Policy::new(Needs::DEVICE, 0, 0, 0),
        )
        .unwrap();
        let request = broker.begin(lease.pass, driver_host::RequestKind::Mmio);
        assert_eq!(request, Err(driver_host::Error::AuthorityDenied));
        assert_eq!(
            reset_and_unload(
                &mut lifecycle,
                &mut broker,
                host,
                QuiesceProof {
                    dma_quiesced: true,
                    irq_quiesced: false,
                },
            ),
            Err(IntegrationError::Lifecycle(Error::NotQuiesced))
        );
        assert!(lifecycle.owns_device(identity.generation));
        assert_eq!(broker.stats().active_passes, 1);

        let crash = crash_and_quarantine(
            &mut lifecycle,
            &mut broker,
            host,
            identity.generation,
            QuiesceProof::CLEAN,
        )
        .unwrap();
        assert_eq!(crash.revoked_passes, 1);
        assert_eq!(lifecycle.state(), State::Quarantined);
        assert_eq!(
            broker.begin(lease.pass, driver_host::RequestKind::Dma),
            Err(driver_host::Error::StalePass)
        );
        assert_eq!(
            lifecycle.activate(lease.package),
            Err(Error::StaleGeneration)
        );
        let recovered =
            recover_and_reactivate(&mut lifecycle, &mut broker, host, QuiesceProof::CLEAN).unwrap();
        assert!(recovered.generation() > host.generation());
        assert_eq!(lifecycle.state(), State::Active);
    }
}
