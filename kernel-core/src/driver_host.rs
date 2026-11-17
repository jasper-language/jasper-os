//! Restricted user-space driver-host broker.
//!
//! This module models the authority and lifecycle boundary shared by a driver
//! host and the kernel. Discovery, policy admission, resource grants, work
//! requests, reset, crash revocation and quarantine are deliberately separate
//! states. A discovered device is not usable until a running host is admitted
//! against an explicit policy.
//!
//! The broker contains no hardware access. The kernel supplies discovery and
//! quiescence facts; an architecture backend must still enforce the returned
//! grants. Capacity exhaustion and stale generations fail closed.

mod journal;

pub use journal::{
    DriverHostJournal, DriverHostJournalError, DriverHostPersistentEvent,
    DriverHostPersistentEventKind,
};

/// Device discovery is permission to consider a device, never permission to use it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub identity: u32,
    pub generation: u32,
}

impl DeviceIdentity {
    pub const fn is_valid(self) -> bool {
        self.identity != 0 && self.generation != 0
    }
}

/// Minimal authority requested by a driver host.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Needs(u8);

impl Needs {
    pub const EMPTY: Self = Self(0);
    pub const DEVICE: Self = Self(1 << 0);
    pub const MMIO: Self = Self(1 << 1);
    pub const MMIO_WRITE: Self = Self(1 << 2);
    pub const DMA: Self = Self(1 << 3);
    pub const DMA_WRITE: Self = Self(1 << 4);
    pub const IRQ: Self = Self(1 << 5);

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn bits(self) -> u8 {
        self.0
    }
}

/// Explicit policy for one admitted device lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    pub allowed: Needs,
    pub max_mmio_regions: u16,
    pub max_dma_pages: u64,
    pub max_irq_routes: u16,
}

impl Policy {
    pub const fn new(
        allowed: Needs,
        max_mmio_regions: u16,
        max_dma_pages: u64,
        max_irq_routes: u16,
    ) -> Self {
        Self {
            allowed,
            max_mmio_regions,
            max_dma_pages,
            max_irq_routes,
        }
    }
}

/// A host generation token. Every reset or recovery creates a fresh generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostToken {
    slot: usize,
    generation: u64,
}

impl HostToken {
    /// Monotonic generation of this host authority.
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

/// A revocable aggregate grant for one device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PassToken {
    slot: usize,
    generation: u64,
    host_generation: u64,
}

/// One in-flight driver operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestToken {
    slot: usize,
    generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestKind {
    Mmio,
    Dma,
    Irq,
}

/// The single terminal state published for a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Terminal {
    Completed,
    Cancelled,
    Revoked,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QuiesceProof {
    pub dma_quiesced: bool,
    pub irq_quiesced: bool,
}

impl QuiesceProof {
    pub const CLEAN: Self = Self {
        dma_quiesced: true,
        irq_quiesced: true,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResetReceipt {
    pub cancelled: usize,
    pub revoked_passes: usize,
    pub token: HostToken,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrashReceipt {
    pub cancelled: usize,
    pub revoked_passes: usize,
    pub quarantined_devices: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stats {
    pub discovered: usize,
    pub bound: usize,
    pub quarantined: usize,
    pub running_hosts: usize,
    pub active_passes: usize,
    pub pending_requests: usize,
    pub completed: u64,
    pub cancelled: u64,
    pub revoked: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidDevice,
    DuplicateDevice,
    StaleHost,
    HostNotRunning,
    HostNotCrashed,
    DeviceNotDiscovered,
    DeviceUnavailable,
    DeviceBound,
    AuthorityDenied,
    Capacity,
    StalePass,
    StaleRequest,
    AlreadyTerminal,
    NotQuiesced,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DeviceState {
    Available,
    Bound {
        host_slot: usize,
        host_generation: u64,
    },
    Quarantined {
        host_slot: usize,
        host_generation: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Discovered {
    identity: DeviceIdentity,
    state: DeviceState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HostState {
    Running,
    Crashed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Host {
    generation: u64,
    state: HostState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Pass {
    generation: u64,
    host_slot: usize,
    host_generation: u64,
    device_slot: usize,
    device_generation: u32,
    rights: Needs,
    mmio_regions: u16,
    dma_pages: u64,
    irq_routes: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Request {
    generation: u64,
    pass_slot: usize,
    pass_generation: u64,
    host_slot: usize,
    host_generation: u64,
    device_slot: usize,
    mmio_regions: u16,
    dma_pages: u64,
    irq_routes: u16,
}

pub struct DriverHostBroker<
    const DEVICES: usize,
    const HOSTS: usize,
    const PASSES: usize,
    const REQUESTS: usize,
> {
    devices: [Option<Discovered>; DEVICES],
    hosts: [Option<Host>; HOSTS],
    passes: [Option<Pass>; PASSES],
    requests: [Option<Request>; REQUESTS],
    next_host_generation: u64,
    next_pass_generation: u64,
    next_request_generation: u64,
    completed: u64,
    cancelled: u64,
    revoked: u64,
}

impl<const DEVICES: usize, const HOSTS: usize, const PASSES: usize, const REQUESTS: usize>
    DriverHostBroker<DEVICES, HOSTS, PASSES, REQUESTS>
{
    pub const fn new() -> Self {
        Self {
            devices: [None; DEVICES],
            hosts: [None; HOSTS],
            passes: [None; PASSES],
            requests: [None; REQUESTS],
            next_host_generation: 1,
            next_pass_generation: 1,
            next_request_generation: 1,
            completed: 0,
            cancelled: 0,
            revoked: 0,
        }
    }

    /// Record a hardware discovery result. This does not grant access.
    pub fn discover(&mut self, identity: DeviceIdentity) -> Result<(), Error> {
        if !identity.is_valid() {
            return Err(Error::InvalidDevice);
        }
        if self.devices.iter().flatten().any(|device| {
            device.identity.identity == identity.identity
                && device.identity.generation == identity.generation
        }) {
            return Err(Error::DuplicateDevice);
        }
        let slot = self
            .devices
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or(Error::Capacity)?;
        *slot = Some(Discovered {
            identity,
            state: DeviceState::Available,
        });
        Ok(())
    }

    /// Register a new driver-host generation.
    pub fn register_host(&mut self) -> Result<HostToken, Error> {
        let slot = self
            .hosts
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let generation = self.next_host_generation;
        self.next_host_generation = generation.checked_add(1).ok_or(Error::Capacity)?;
        self.hosts[slot] = Some(Host {
            generation,
            state: HostState::Running,
        });
        Ok(HostToken { slot, generation })
    }

    /// Admit a discovered device under an explicit minimal-rights policy.
    ///
    /// All checks complete before any state changes. In particular, an
    /// unavailable device or zero-sized authority does not consume a pass slot.
    pub fn admit(
        &mut self,
        host: HostToken,
        identity: DeviceIdentity,
        requested: Needs,
        policy: Policy,
    ) -> Result<PassToken, Error> {
        self.require_running_host(host)?;
        if !requested.contains(Needs::DEVICE) {
            return Err(Error::AuthorityDenied);
        }
        if !policy.allowed.contains(requested) {
            return Err(Error::AuthorityDenied);
        }
        if (requested.contains(Needs::MMIO) && policy.max_mmio_regions == 0)
            || (requested.contains(Needs::DMA) && policy.max_dma_pages == 0)
            || (requested.contains(Needs::IRQ) && policy.max_irq_routes == 0)
            || (requested.contains(Needs::MMIO_WRITE) && !requested.contains(Needs::MMIO))
            || (requested.contains(Needs::DMA_WRITE) && !requested.contains(Needs::DMA))
        {
            return Err(Error::AuthorityDenied);
        }
        let device_slot = self.device_slot(identity)?;
        if self.devices[device_slot]
            .as_ref()
            .is_none_or(|device| device.state != DeviceState::Available)
        {
            return Err(Error::DeviceUnavailable);
        }
        if self.passes.iter().flatten().any(|pass| {
            pass.device_slot == device_slot && pass.device_generation == identity.generation
        }) {
            return Err(Error::DeviceBound);
        }
        let pass_slot = self
            .passes
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let generation = self.next_pass_generation;
        self.next_pass_generation = generation.checked_add(1).ok_or(Error::Capacity)?;
        self.passes[pass_slot] = Some(Pass {
            generation,
            host_slot: host.slot,
            host_generation: host.generation,
            device_slot,
            device_generation: identity.generation,
            rights: requested,
            mmio_regions: if requested.contains(Needs::MMIO) {
                policy.max_mmio_regions
            } else {
                0
            },
            dma_pages: if requested.contains(Needs::DMA) {
                policy.max_dma_pages
            } else {
                0
            },
            irq_routes: if requested.contains(Needs::IRQ) {
                policy.max_irq_routes
            } else {
                0
            },
        });
        self.devices[device_slot]
            .as_mut()
            .expect("checked device")
            .state = DeviceState::Bound {
            host_slot: host.slot,
            host_generation: host.generation,
        };
        Ok(PassToken {
            slot: pass_slot,
            generation,
            host_generation: host.generation,
        })
    }

    /// Start one bounded request. The grant already reserves its resource.
    pub fn begin(&mut self, pass: PassToken, kind: RequestKind) -> Result<RequestToken, Error> {
        self.begin_bounded(pass, kind, 1)
    }

    /// Reserve an explicit amount from one admitted resource grant.
    ///
    /// A pass is a capacity ceiling, not permission for an unlimited number of
    /// concurrent requests. Requests are charged until they reach exactly one
    /// terminal state, which releases the reservation.
    pub fn begin_bounded(
        &mut self,
        pass: PassToken,
        kind: RequestKind,
        amount: u64,
    ) -> Result<RequestToken, Error> {
        let admitted = self.require_pass(pass)?;
        if amount == 0 {
            return Err(Error::AuthorityDenied);
        }
        if (kind == RequestKind::Mmio && admitted.mmio_regions == 0)
            || (kind == RequestKind::Dma && admitted.dma_pages == 0)
            || (kind == RequestKind::Irq && admitted.irq_routes == 0)
        {
            return Err(Error::AuthorityDenied);
        }
        let limit = match kind {
            RequestKind::Mmio => u64::from(admitted.mmio_regions),
            RequestKind::Dma => admitted.dma_pages,
            RequestKind::Irq => u64::from(admitted.irq_routes),
        };
        let reserved = self
            .requests
            .iter()
            .flatten()
            .filter(|request| {
                request.pass_slot == pass.slot && request.pass_generation == pass.generation
            })
            .try_fold(0u64, |total, request| {
                let amount = match kind {
                    RequestKind::Mmio => u64::from(request.mmio_regions),
                    RequestKind::Dma => request.dma_pages,
                    RequestKind::Irq => u64::from(request.irq_routes),
                };
                total.checked_add(amount)
            })
            .ok_or(Error::Capacity)?;
        let requested = reserved.checked_add(amount).ok_or(Error::Capacity)?;
        if requested > limit {
            return Err(Error::Capacity);
        }
        let slot = self
            .requests
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let generation = self.next_request_generation;
        self.next_request_generation = generation.checked_add(1).ok_or(Error::Capacity)?;
        self.requests[slot] = Some(Request {
            generation,
            pass_slot: pass.slot,
            pass_generation: pass.generation,
            host_slot: admitted.host_slot,
            host_generation: admitted.host_generation,
            device_slot: admitted.device_slot,
            mmio_regions: if kind == RequestKind::Mmio {
                u16::try_from(amount).map_err(|_| Error::Capacity)?
            } else {
                0
            },
            dma_pages: if kind == RequestKind::Dma { amount } else { 0 },
            irq_routes: if kind == RequestKind::Irq {
                u16::try_from(amount).map_err(|_| Error::Capacity)?
            } else {
                0
            },
        });
        Ok(RequestToken { slot, generation })
    }

    /// Reserve one real virtqueue operation across MMIO, DMA and IRQ at once.
    ///
    /// A queue operation is one indivisible resource unit: enabling a queue may
    /// require a common/notify MMIO region, pinned descriptor/ring pages and an
    /// interrupt route. Checking or charging those classes separately could
    /// leave a partially prepared queue when the final class is exhausted.
    /// This method therefore validates every class before publishing the single
    /// terminal request. Hardware notification and used-ring completion remain
    /// external facts owned by the device backend.
    pub fn begin_queue_work(
        &mut self,
        pass: PassToken,
        mmio_regions: u16,
        dma_pages: u64,
        irq_routes: u16,
    ) -> Result<RequestToken, Error> {
        let admitted = self.require_pass(pass)?;
        let queue_rights = Needs::MMIO
            .union(Needs::MMIO_WRITE)
            .union(Needs::DMA)
            .union(Needs::DMA_WRITE)
            .union(Needs::IRQ);
        if !admitted.rights.contains(queue_rights)
            || mmio_regions == 0
            || dma_pages == 0
            || irq_routes == 0
        {
            return Err(Error::AuthorityDenied);
        }
        if mmio_regions > admitted.mmio_regions
            || dma_pages > admitted.dma_pages
            || irq_routes > admitted.irq_routes
        {
            return Err(Error::Capacity);
        }
        let reserved_mmio = self.reserved_for(pass, RequestKind::Mmio)?;
        let reserved_dma = self.reserved_for(pass, RequestKind::Dma)?;
        let reserved_irq = self.reserved_for(pass, RequestKind::Irq)?;
        if reserved_mmio
            .checked_add(u64::from(mmio_regions))
            .is_none_or(|total| total > u64::from(admitted.mmio_regions))
            || reserved_dma
                .checked_add(dma_pages)
                .is_none_or(|total| total > admitted.dma_pages)
            || reserved_irq
                .checked_add(u64::from(irq_routes))
                .is_none_or(|total| total > u64::from(admitted.irq_routes))
        {
            return Err(Error::Capacity);
        }
        let slot = self
            .requests
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let generation = self.next_request_generation;
        self.next_request_generation = generation.checked_add(1).ok_or(Error::Capacity)?;
        self.requests[slot] = Some(Request {
            generation,
            pass_slot: pass.slot,
            pass_generation: pass.generation,
            host_slot: admitted.host_slot,
            host_generation: admitted.host_generation,
            device_slot: admitted.device_slot,
            mmio_regions,
            dma_pages,
            irq_routes,
        });
        Ok(RequestToken { slot, generation })
    }

    /// Publish the one successful terminal for a request.
    pub fn complete(&mut self, request: RequestToken) -> Result<Terminal, Error> {
        self.finish_request(request, Terminal::Completed)
    }

    /// Publish the one cancellation terminal for a request.
    pub fn cancel(&mut self, request: RequestToken) -> Result<Terminal, Error> {
        self.finish_request(request, Terminal::Cancelled)
    }

    /// Revoke one admitted pass before it is published as active.
    ///
    /// This is used by the lifecycle composition when a later admission step
    /// fails. A stale token cannot revoke a newer generation.
    pub fn revoke(&mut self, pass: PassToken) -> Result<(), Error> {
        let admitted = self.require_pass(pass)?;
        if self.requests.iter().flatten().any(|request| {
            request.pass_slot == pass.slot && request.pass_generation == pass.generation
        }) {
            return Err(Error::DeviceBound);
        }
        self.passes[pass.slot] = None;
        if let Some(device) = self.devices[admitted.device_slot].as_mut() {
            if device.state
                == (DeviceState::Bound {
                    host_slot: admitted.host_slot,
                    host_generation: admitted.host_generation,
                })
            {
                device.state = DeviceState::Available;
            }
        }
        self.revoked = self.revoked.saturating_add(1);
        Ok(())
    }

    /// Revoke all host state and advance its generation after a proven reset.
    ///
    /// The quiescence checks occur before any mutation: a failed reset leaves
    /// requests, grants and the current generation untouched.
    pub fn reset(&mut self, host: HostToken, proof: QuiesceProof) -> Result<ResetReceipt, Error> {
        self.require_running_host(host)?;
        if !proof.dma_quiesced || !proof.irq_quiesced {
            return Err(Error::NotQuiesced);
        }
        let cancelled = self.cancel_requests_for_host(host.slot, host.generation);
        let (revoked_passes, _) = self.revoke_passes_for_host(host.slot, host.generation, false);
        let new_generation = host.generation.checked_add(1).ok_or(Error::Capacity)?;
        let record = self.hosts[host.slot].as_mut().expect("validated host");
        record.generation = new_generation;
        Ok(ResetReceipt {
            cancelled,
            revoked_passes,
            token: HostToken {
                slot: host.slot,
                generation: new_generation,
            },
        })
    }

    /// Crash a host. Without proven DMA and IRQ quiescence, its device remains
    /// quarantined and cannot be rebound by another host.
    pub fn crash(&mut self, host: HostToken, proof: QuiesceProof) -> Result<CrashReceipt, Error> {
        self.require_running_host(host)?;
        let cancelled = self.cancel_requests_for_host(host.slot, host.generation);
        let (revoked_passes, quarantined_devices) = self.revoke_passes_for_host(
            host.slot,
            host.generation,
            !proof.dma_quiesced || !proof.irq_quiesced,
        );
        self.hosts[host.slot]
            .as_mut()
            .expect("validated host")
            .state = HostState::Crashed;
        Ok(CrashReceipt {
            cancelled,
            revoked_passes,
            quarantined_devices,
        })
    }

    /// Recover a crashed host after a clean quiescence proof.
    ///
    /// Quarantined devices owned by this host become discoverable/available
    /// again. The returned generation invalidates every pre-crash token.
    pub fn recover(&mut self, host: HostToken, proof: QuiesceProof) -> Result<HostToken, Error> {
        let record = self.host(host)?;
        if record.state != HostState::Crashed {
            return Err(Error::HostNotCrashed);
        }
        if !proof.dma_quiesced || !proof.irq_quiesced {
            return Err(Error::NotQuiesced);
        }
        for device in self.devices.iter_mut().flatten() {
            if device.state
                == (DeviceState::Quarantined {
                    host_slot: host.slot,
                    host_generation: host.generation,
                })
            {
                device.state = DeviceState::Available;
            }
        }
        let new_generation = host.generation.checked_add(1).ok_or(Error::Capacity)?;
        let record = self.hosts[host.slot].as_mut().expect("validated host");
        record.state = HostState::Running;
        record.generation = new_generation;
        Ok(HostToken {
            slot: host.slot,
            generation: new_generation,
        })
    }

    pub fn stats(&self) -> Stats {
        Stats {
            discovered: self.devices.iter().flatten().count(),
            bound: self
                .devices
                .iter()
                .flatten()
                .filter(|device| matches!(device.state, DeviceState::Bound { .. }))
                .count(),
            quarantined: self
                .devices
                .iter()
                .flatten()
                .filter(|device| matches!(device.state, DeviceState::Quarantined { .. }))
                .count(),
            running_hosts: self
                .hosts
                .iter()
                .flatten()
                .filter(|host| host.state == HostState::Running)
                .count(),
            active_passes: self.passes.iter().flatten().count(),
            pending_requests: self.requests.iter().flatten().count(),
            completed: self.completed,
            cancelled: self.cancelled,
            revoked: self.revoked,
        }
    }

    fn host(&self, token: HostToken) -> Result<&Host, Error> {
        self.hosts
            .get(token.slot)
            .and_then(Option::as_ref)
            .filter(|host| host.generation == token.generation)
            .ok_or(Error::StaleHost)
    }

    fn require_running_host(&self, token: HostToken) -> Result<(), Error> {
        let host = self.host(token)?;
        if host.state != HostState::Running {
            return Err(Error::HostNotRunning);
        }
        Ok(())
    }

    fn device_slot(&self, identity: DeviceIdentity) -> Result<usize, Error> {
        if !identity.is_valid() {
            return Err(Error::InvalidDevice);
        }
        self.devices
            .iter()
            .position(|device| {
                device.is_some_and(|device| {
                    device.identity.identity == identity.identity
                        && device.identity.generation == identity.generation
                })
            })
            .ok_or(Error::DeviceNotDiscovered)
    }

    fn require_pass(&self, token: PassToken) -> Result<Pass, Error> {
        let pass = self
            .passes
            .get(token.slot)
            .and_then(|entry| *entry)
            .filter(|pass| {
                pass.generation == token.generation && pass.host_generation == token.host_generation
            })
            .ok_or(Error::StalePass)?;
        self.require_running_host(HostToken {
            slot: pass.host_slot,
            generation: pass.host_generation,
        })?;
        Ok(pass)
    }

    fn reserved_for(&self, pass: PassToken, kind: RequestKind) -> Result<u64, Error> {
        self.requests
            .iter()
            .flatten()
            .filter(|request| {
                request.pass_slot == pass.slot && request.pass_generation == pass.generation
            })
            .try_fold(0u64, |total, request| {
                let amount = match kind {
                    RequestKind::Mmio => u64::from(request.mmio_regions),
                    RequestKind::Dma => request.dma_pages,
                    RequestKind::Irq => u64::from(request.irq_routes),
                };
                total.checked_add(amount)
            })
            .ok_or(Error::Capacity)
    }

    fn finish_request(
        &mut self,
        token: RequestToken,
        terminal: Terminal,
    ) -> Result<Terminal, Error> {
        self.requests
            .get(token.slot)
            .and_then(|entry| *entry)
            .filter(|request| request.generation == token.generation)
            .ok_or(Error::StaleRequest)?;
        self.requests[token.slot] = None;
        match terminal {
            Terminal::Completed => self.completed = self.completed.saturating_add(1),
            Terminal::Cancelled => self.cancelled = self.cancelled.saturating_add(1),
            Terminal::Revoked => self.revoked = self.revoked.saturating_add(1),
        }
        Ok(terminal)
    }

    fn cancel_requests_for_host(&mut self, host_slot: usize, host_generation: u64) -> usize {
        let mut cancelled = 0;
        for request in self.requests.iter_mut() {
            if request.is_some_and(|request| {
                request.host_slot == host_slot && request.host_generation == host_generation
            }) {
                *request = None;
                cancelled += 1;
            }
        }
        self.revoked = self.revoked.saturating_add(cancelled as u64);
        cancelled
    }

    fn revoke_passes_for_host(
        &mut self,
        host_slot: usize,
        host_generation: u64,
        quarantine: bool,
    ) -> (usize, usize) {
        let mut revoked = 0;
        let mut quarantined = 0;
        for pass in self.passes.iter_mut() {
            let Some(admitted) = *pass else {
                continue;
            };
            if admitted.host_slot != host_slot || admitted.host_generation != host_generation {
                continue;
            }
            *pass = None;
            revoked += 1;
            let state = if quarantine {
                quarantined += 1;
                DeviceState::Quarantined {
                    host_slot,
                    host_generation,
                }
            } else {
                DeviceState::Available
            };
            if let Some(device) = self.devices[admitted.device_slot].as_mut() {
                device.state = state;
            }
        }
        // A quarantined device remains a blocker even though its pass is gone.
        if quarantine {
            for device in self.devices.iter_mut().flatten() {
                if matches!(
                    device.state,
                    DeviceState::Bound {
                        host_slot: bound_slot,
                        host_generation: bound_generation,
                    } if bound_slot == host_slot && bound_generation == host_generation
                ) {
                    device.state = DeviceState::Quarantined {
                        host_slot,
                        host_generation,
                    };
                }
            }
        }
        self.revoked = self.revoked.saturating_add(revoked as u64);
        (revoked, quarantined)
    }
}

impl<const DEVICES: usize, const HOSTS: usize, const PASSES: usize, const REQUESTS: usize> Default
    for DriverHostBroker<DEVICES, HOSTS, PASSES, REQUESTS>
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEV: DeviceIdentity = DeviceIdentity {
        identity: 0x1044,
        generation: 7,
    };

    fn broker() -> DriverHostBroker<4, 4, 4, 8> {
        DriverHostBroker::new()
    }

    fn admit(
        broker: &mut DriverHostBroker<4, 4, 4, 8>,
        host: HostToken,
        requested: Needs,
        allowed: Needs,
    ) -> PassToken {
        broker
            .admit(host, DEV, requested, Policy::new(allowed, 2, 8, 2))
            .unwrap()
    }

    #[test]
    fn discovery_and_policy_admission_are_distinct_and_atomic() {
        let mut broker = broker();
        let host = broker.register_host().unwrap();
        let all = Needs::DEVICE
            .union(Needs::MMIO)
            .union(Needs::MMIO_WRITE)
            .union(Needs::DMA)
            .union(Needs::DMA_WRITE)
            .union(Needs::IRQ);

        assert_eq!(
            broker.admit(host, DEV, Needs::DEVICE, Policy::new(all, 1, 1, 1)),
            Err(Error::DeviceNotDiscovered)
        );
        broker.discover(DEV).unwrap();
        assert_eq!(
            broker.admit(
                host,
                DEV,
                Needs::DEVICE.union(Needs::DMA),
                Policy::new(Needs::DEVICE, 1, 1, 1)
            ),
            Err(Error::AuthorityDenied)
        );
        assert_eq!(broker.stats().active_passes, 0);
        assert_eq!(broker.stats().bound, 0);

        let pass = broker
            .admit(
                host,
                DEV,
                Needs::DEVICE.union(Needs::MMIO),
                Policy::new(Needs::DEVICE.union(Needs::MMIO), 1, 1, 1),
            )
            .unwrap();
        assert_eq!(pass.generation, 1);
        assert_eq!(broker.stats().active_passes, 1);
        assert_eq!(broker.stats().bound, 1);
    }

    #[test]
    fn device_is_exclusive_and_denied_requests_change_nothing() {
        let mut broker = broker();
        let first = broker.register_host().unwrap();
        let second = broker.register_host().unwrap();
        broker.discover(DEV).unwrap();
        let allowed = Needs::DEVICE.union(Needs::MMIO).union(Needs::IRQ);
        let _pass = admit(&mut broker, first, allowed, allowed);

        assert_eq!(
            broker.admit(
                second,
                DEV,
                Needs::DEVICE,
                Policy::new(Needs::DEVICE, 1, 1, 1)
            ),
            Err(Error::DeviceUnavailable)
        );
        assert_eq!(
            broker.admit(
                first,
                DEV,
                Needs::DEVICE.union(Needs::DMA),
                Policy::new(Needs::DEVICE.union(Needs::DMA), 1, 1, 1)
            ),
            Err(Error::DeviceUnavailable)
        );
        assert_eq!(broker.stats().active_passes, 1);
    }

    #[test]
    fn requests_publish_exactly_one_terminal() {
        let mut broker = broker();
        let host = broker.register_host().unwrap();
        broker.discover(DEV).unwrap();
        let allowed = Needs::DEVICE.union(Needs::MMIO).union(Needs::IRQ);
        let pass = admit(&mut broker, host, allowed, allowed);
        let a = broker.begin(pass, RequestKind::Mmio).unwrap();
        let b = broker.begin(pass, RequestKind::Irq).unwrap();
        assert_eq!(broker.stats().pending_requests, 2);

        assert_eq!(broker.complete(a), Ok(Terminal::Completed));
        assert_eq!(broker.complete(a), Err(Error::StaleRequest));
        assert_eq!(broker.cancel(b), Ok(Terminal::Cancelled));
        assert_eq!(broker.cancel(b), Err(Error::StaleRequest));
        assert_eq!(broker.stats().pending_requests, 0);
        assert_eq!(broker.stats().completed, 1);
        assert_eq!(broker.stats().cancelled, 1);
    }

    #[test]
    fn pending_requests_reserve_grant_capacity_until_terminal() {
        let mut broker = broker();
        let host = broker.register_host().unwrap();
        broker.discover(DEV).unwrap();
        let allowed = Needs::DEVICE
            .union(Needs::MMIO)
            .union(Needs::DMA)
            .union(Needs::IRQ);
        let pass = broker
            .admit(host, DEV, allowed, Policy::new(allowed, 2, 8, 2))
            .unwrap();

        let mmio = broker.begin_bounded(pass, RequestKind::Mmio, 2).unwrap();
        assert_eq!(
            broker.begin_bounded(pass, RequestKind::Mmio, 1),
            Err(Error::Capacity)
        );
        let dma = broker.begin_bounded(pass, RequestKind::Dma, 6).unwrap();
        let irq = broker.begin_bounded(pass, RequestKind::Irq, 1).unwrap();
        assert_eq!(
            broker.begin_bounded(pass, RequestKind::Dma, 3),
            Err(Error::Capacity)
        );
        assert_eq!(broker.stats().pending_requests, 3);

        assert_eq!(broker.complete(mmio), Ok(Terminal::Completed));
        let replacement = broker.begin_bounded(pass, RequestKind::Mmio, 2).unwrap();
        assert_eq!(
            broker.begin_bounded(pass, RequestKind::Mmio, 1),
            Err(Error::Capacity)
        );

        assert_eq!(broker.cancel(dma), Ok(Terminal::Cancelled));
        assert!(broker.begin_bounded(pass, RequestKind::Dma, 8).is_ok());
        assert_eq!(
            broker.begin_bounded(pass, RequestKind::Irq, 2),
            Err(Error::Capacity)
        );

        assert_eq!(broker.complete(replacement), Ok(Terminal::Completed));
        assert_eq!(broker.cancel(irq), Ok(Terminal::Cancelled));
    }

    #[test]
    fn queue_work_reserves_mmio_dma_and_irq_atomically() {
        let mut broker = broker();
        let host = broker.register_host().unwrap();
        broker.discover(DEV).unwrap();
        let allowed = Needs::DEVICE
            .union(Needs::MMIO)
            .union(Needs::MMIO_WRITE)
            .union(Needs::DMA)
            .union(Needs::DMA_WRITE)
            .union(Needs::IRQ);
        let pass = broker
            .admit(host, DEV, allowed, Policy::new(allowed, 1, 4, 1))
            .unwrap();

        let queue = broker.begin_queue_work(pass, 1, 4, 1).unwrap();
        assert_eq!(broker.stats().pending_requests, 1);
        assert_eq!(broker.begin(pass, RequestKind::Mmio), Err(Error::Capacity));
        assert_eq!(broker.begin(pass, RequestKind::Dma), Err(Error::Capacity));
        assert_eq!(broker.begin(pass, RequestKind::Irq), Err(Error::Capacity));

        assert_eq!(broker.complete(queue), Ok(Terminal::Completed));
        assert!(broker.begin(pass, RequestKind::Mmio).is_ok());
        assert!(broker.begin(pass, RequestKind::Dma).is_ok());
        assert!(broker.begin(pass, RequestKind::Irq).is_ok());
    }

    #[test]
    fn queue_work_failure_cannot_leave_partial_resource_reservations() {
        let mut broker = broker();
        let host = broker.register_host().unwrap();
        broker.discover(DEV).unwrap();
        let without_irq = Needs::DEVICE
            .union(Needs::MMIO)
            .union(Needs::MMIO_WRITE)
            .union(Needs::DMA)
            .union(Needs::DMA_WRITE);
        let no_queue_pass = broker
            .admit(host, DEV, without_irq, Policy::new(without_irq, 1, 4, 0))
            .unwrap();
        assert_eq!(
            broker.begin_queue_work(no_queue_pass, 1, 1, 0),
            Err(Error::AuthorityDenied)
        );
        assert_eq!(broker.stats().pending_requests, 0);
        broker.revoke(no_queue_pass).unwrap();

        let allowed = without_irq.union(Needs::IRQ);
        let pass = broker
            .admit(host, DEV, allowed, Policy::new(allowed, 1, 1, 1))
            .unwrap();
        assert_eq!(broker.begin_queue_work(pass, 1, 2, 1), Err(Error::Capacity));
        assert_eq!(broker.stats().pending_requests, 0);
        assert!(broker.begin(pass, RequestKind::Mmio).is_ok());
        assert!(broker.begin(pass, RequestKind::Dma).is_ok());
        assert!(broker.begin(pass, RequestKind::Irq).is_ok());
    }

    #[test]
    fn zero_request_demand_is_rejected_without_consuming_capacity() {
        let mut broker = DriverHostBroker::<1, 1, 1, 1>::new();
        let host = broker.register_host().unwrap();
        broker.discover(DEV).unwrap();
        let allowed = Needs::DEVICE.union(Needs::MMIO);
        let pass = broker
            .admit(host, DEV, allowed, Policy::new(allowed, 1, 0, 0))
            .unwrap();

        assert_eq!(
            broker.begin_bounded(pass, RequestKind::Mmio, 0),
            Err(Error::AuthorityDenied)
        );
        assert_eq!(broker.stats().pending_requests, 0);
        assert!(broker.begin_bounded(pass, RequestKind::Mmio, 1).is_ok());
    }

    #[test]
    fn lifecycle_rollback_can_revoke_only_its_unused_pass() {
        let mut broker = broker();
        let host = broker.register_host().unwrap();
        broker.discover(DEV).unwrap();
        let pass = admit(&mut broker, host, Needs::DEVICE, Needs::DEVICE);
        broker.revoke(pass).unwrap();
        assert_eq!(broker.revoke(pass), Err(Error::StalePass));
        assert_eq!(broker.stats().active_passes, 0);
        assert_eq!(broker.stats().bound, 0);
        assert_eq!(broker.stats().revoked, 1);
        broker
            .admit(
                host,
                DEV,
                Needs::DEVICE,
                Policy::new(Needs::DEVICE, 0, 0, 0),
            )
            .unwrap();
    }

    #[test]
    fn reset_is_atomic_requires_quiescence_and_stales_all_old_tokens() {
        let mut broker = broker();
        let host = broker.register_host().unwrap();
        broker.discover(DEV).unwrap();
        let allowed = Needs::DEVICE.union(Needs::DMA).union(Needs::IRQ);
        let pass = admit(&mut broker, host, allowed, allowed);
        let request = broker.begin(pass, RequestKind::Dma).unwrap();

        assert_eq!(
            broker.reset(
                host,
                QuiesceProof {
                    dma_quiesced: false,
                    irq_quiesced: true,
                }
            ),
            Err(Error::NotQuiesced)
        );
        assert_eq!(broker.stats().pending_requests, 1);
        assert_eq!(broker.stats().active_passes, 1);

        let receipt = broker.reset(host, QuiesceProof::CLEAN).unwrap();
        assert_eq!(receipt.cancelled, 1);
        assert_eq!(receipt.revoked_passes, 1);
        assert_eq!(receipt.token.generation, host.generation + 1);
        assert_eq!(broker.begin(pass, RequestKind::Dma), Err(Error::StalePass));
        assert_eq!(broker.complete(request), Err(Error::StaleRequest));
        assert_eq!(broker.stats().pending_requests, 0);
        assert_eq!(broker.stats().active_passes, 0);
        assert_eq!(broker.stats().bound, 0);
        assert_eq!(broker.stats().revoked, 2);

        let again = broker
            .admit(
                receipt.token,
                DEV,
                Needs::DEVICE,
                Policy::new(Needs::DEVICE, 0, 0, 0),
            )
            .unwrap();
        assert_eq!(again.host_generation, receipt.token.generation);
    }

    #[test]
    fn crash_quarantines_without_quiescence_and_recovery_releases_it() {
        let mut broker = broker();
        let host = broker.register_host().unwrap();
        broker.discover(DEV).unwrap();
        let allowed = Needs::DEVICE.union(Needs::DMA).union(Needs::IRQ);
        let _pass = admit(&mut broker, host, allowed, allowed);

        let crash = broker
            .crash(
                host,
                QuiesceProof {
                    dma_quiesced: true,
                    irq_quiesced: false,
                },
            )
            .unwrap();
        assert_eq!(crash.quarantined_devices, 1);
        assert_eq!(broker.stats().quarantined, 1);
        assert_eq!(
            broker.recover(
                host,
                QuiesceProof {
                    dma_quiesced: true,
                    irq_quiesced: false,
                }
            ),
            Err(Error::NotQuiesced)
        );
        let recovered = broker.recover(host, QuiesceProof::CLEAN).unwrap();
        assert_eq!(recovered.generation, host.generation + 1);
        assert_eq!(broker.stats().quarantined, 0);
        let pass = broker
            .admit(
                recovered,
                DEV,
                Needs::DEVICE,
                Policy::new(Needs::DEVICE, 0, 0, 0),
            )
            .unwrap();
        assert_eq!(pass.host_generation, recovered.generation);
    }

    #[test]
    fn capacity_failures_do_not_partially_publish_grants() {
        let mut broker = DriverHostBroker::<2, 1, 1, 1>::new();
        broker.discover(DEV).unwrap();
        broker
            .discover(DeviceIdentity {
                identity: 0x1045,
                generation: 1,
            })
            .unwrap();
        let host = broker.register_host().unwrap();
        let allowed = Needs::DEVICE.union(Needs::MMIO);
        let pass = broker
            .admit(host, DEV, allowed, Policy::new(allowed, 1, 0, 0))
            .unwrap();
        assert_eq!(
            broker.admit(
                host,
                DeviceIdentity {
                    identity: 0x1045,
                    generation: 1
                },
                Needs::DEVICE,
                Policy::new(Needs::DEVICE, 0, 0, 0)
            ),
            Err(Error::Capacity)
        );
        let request = broker.begin(pass, RequestKind::Mmio).unwrap();
        assert!(request.generation > 0);
        assert_eq!(broker.begin(pass, RequestKind::Mmio), Err(Error::Capacity));
        assert_eq!(broker.stats().pending_requests, 1);
    }
}
