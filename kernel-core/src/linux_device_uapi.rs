//! Versioned Linux device UAPI adapter contract over one Driver Host pass.
//!
//! This module models `/dev`-style endpoint lifecycle only. It does not load
//! Linux drivers, parse vendor ioctl payloads, program MMIO or DMA hardware, or
//! create a second device/security authority. Every resource request is issued
//! through [`DriverHostBroker`] using the admitted [`PassToken`].

use crate::driver_host::{
    DeviceIdentity, DriverHostBroker, Error as DriverHostError, Needs, PassFacts, PassToken,
    RequestKind, RequestToken, Terminal,
};

pub const LINUX_DEVICE_UAPI_MAJOR: u16 = 1;
pub const LINUX_DEVICE_UAPI_MINOR: u16 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UapiVersion {
    pub major: u16,
    pub minor: u16,
}

impl UapiVersion {
    pub const CURRENT: Self = Self {
        major: LINUX_DEVICE_UAPI_MAJOR,
        minor: LINUX_DEVICE_UAPI_MINOR,
    };

    pub const fn is_compatible(self) -> bool {
        self.major == LINUX_DEVICE_UAPI_MAJOR && self.minor <= LINUX_DEVICE_UAPI_MINOR
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceNodeId(pub u32);

impl DeviceNodeId {
    pub const fn is_valid(self) -> bool {
        self.0 != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenAccess {
    ReadOnly,
    WriteOnly,
    ReadWrite,
}

impl OpenAccess {
    const fn can_read(self) -> bool {
        matches!(self, Self::ReadOnly | Self::ReadWrite)
    }

    const fn can_write(self) -> bool {
        matches!(self, Self::WriteOnly | Self::ReadWrite)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferDirection {
    ToDevice,
    FromDevice,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UapiOperation {
    Ioctl,
    Read,
    Write,
    Mmap,
    Poll,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoctlRequest {
    pub command: u32,
    pub payload_bytes: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UapiRequest {
    token: RequestToken,
    operation: UapiOperation,
    units: u64,
}

impl UapiRequest {
    pub const fn token(self) -> RequestToken {
        self.token
    }

    pub const fn operation(self) -> UapiOperation {
        self.operation
    }

    pub const fn units(self) -> u64 {
        self.units
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MappedBuffer {
    token: RequestToken,
    pages: u64,
    writable: bool,
}

impl MappedBuffer {
    pub const fn token(self) -> RequestToken {
        self.token
    }

    pub const fn pages(self) -> u64 {
        self.pages
    }

    pub const fn writable(self) -> bool {
        self.writable
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UapiError {
    UnsupportedVersion,
    InvalidNode,
    UnsupportedAccess,
    Permission,
    DeviceGone,
    Capacity,
    Busy,
    InvalidRequest,
    Closed,
    Backend,
}

fn map_broker_error(error: DriverHostError) -> UapiError {
    match error {
        DriverHostError::AuthorityDenied => UapiError::Permission,
        DriverHostError::StaleHost
        | DriverHostError::HostNotRunning
        | DriverHostError::StalePass
        | DriverHostError::DeviceUnavailable
        | DriverHostError::DeviceNotDiscovered => UapiError::DeviceGone,
        DriverHostError::Capacity => UapiError::Capacity,
        DriverHostError::StaleRequest
        | DriverHostError::AlreadyTerminal
        | DriverHostError::InvalidDevice => UapiError::InvalidRequest,
        _ => UapiError::Backend,
    }
}

/// One open Linux `/dev` endpoint backed by an existing Driver Host pass.
pub struct LinuxDeviceEndpoint<const REQUESTS: usize, const BUFFERS: usize> {
    version: UapiVersion,
    node: DeviceNodeId,
    pass: PassToken,
    facts: PassFacts,
    access: OpenAccess,
    requests: [Option<UapiRequest>; REQUESTS],
    buffers: [Option<MappedBuffer>; BUFFERS],
    closed: bool,
}

impl<const REQUESTS: usize, const BUFFERS: usize> LinuxDeviceEndpoint<REQUESTS, BUFFERS> {
    pub fn open(
        version: UapiVersion,
        node: DeviceNodeId,
        access: OpenAccess,
        pass: PassToken,
        facts: PassFacts,
    ) -> Result<Self, UapiError> {
        if !version.is_compatible() {
            return Err(UapiError::UnsupportedVersion);
        }
        if !node.is_valid() {
            return Err(UapiError::InvalidNode);
        }
        if facts.pass_generation() != pass.generation() {
            return Err(UapiError::InvalidRequest);
        }
        if !facts.rights().contains(Needs::DEVICE) {
            return Err(UapiError::Permission);
        }
        Ok(Self {
            version,
            node,
            pass,
            facts,
            access,
            requests: [None; REQUESTS],
            buffers: [None; BUFFERS],
            closed: false,
        })
    }

    pub const fn version(&self) -> UapiVersion {
        self.version
    }

    pub const fn node(&self) -> DeviceNodeId {
        self.node
    }

    pub fn device(&self) -> DeviceIdentity {
        self.facts.device()
    }

    pub fn pending_requests(&self) -> usize {
        self.requests.iter().flatten().count()
    }

    pub fn mapped_buffers(&self) -> usize {
        self.buffers.iter().flatten().count()
    }

    pub fn ioctl<
        const DEVICES: usize,
        const HOSTS: usize,
        const PASSES: usize,
        const INFLIGHT: usize,
    >(
        &mut self,
        broker: &mut DriverHostBroker<DEVICES, HOSTS, PASSES, INFLIGHT>,
        request: IoctlRequest,
    ) -> Result<UapiRequest, UapiError> {
        self.require_open()?;
        if request.command == 0 {
            return Err(UapiError::InvalidRequest);
        }
        let slot = self.free_request_slot()?;
        let token = broker
            .begin(self.pass, RequestKind::Mmio)
            .map_err(map_broker_error)?;
        Ok(self.publish_request(slot, token, UapiOperation::Ioctl, u64::from(request.payload_bytes)))
    }

    pub fn read<
        const DEVICES: usize,
        const HOSTS: usize,
        const PASSES: usize,
        const INFLIGHT: usize,
    >(
        &mut self,
        broker: &mut DriverHostBroker<DEVICES, HOSTS, PASSES, INFLIGHT>,
        pages: u64,
    ) -> Result<UapiRequest, UapiError> {
        self.begin_transfer(broker, UapiOperation::Read, TransferDirection::FromDevice, pages)
    }

    pub fn write<
        const DEVICES: usize,
        const HOSTS: usize,
        const PASSES: usize,
        const INFLIGHT: usize,
    >(
        &mut self,
        broker: &mut DriverHostBroker<DEVICES, HOSTS, PASSES, INFLIGHT>,
        pages: u64,
    ) -> Result<UapiRequest, UapiError> {
        self.begin_transfer(broker, UapiOperation::Write, TransferDirection::ToDevice, pages)
    }

    fn begin_transfer<
        const DEVICES: usize,
        const HOSTS: usize,
        const PASSES: usize,
        const INFLIGHT: usize,
    >(
        &mut self,
        broker: &mut DriverHostBroker<DEVICES, HOSTS, PASSES, INFLIGHT>,
        operation: UapiOperation,
        direction: TransferDirection,
        pages: u64,
    ) -> Result<UapiRequest, UapiError> {
        self.require_open()?;
        if pages == 0 {
            return Err(UapiError::InvalidRequest);
        }
        if (operation == UapiOperation::Read && !self.access.can_read())
            || (operation == UapiOperation::Write && !self.access.can_write())
        {
            return Err(UapiError::Permission);
        }
        if direction == TransferDirection::FromDevice
            && !self.facts.rights().contains(Needs::DMA_WRITE)
        {
            return Err(UapiError::Permission);
        }
        let slot = self.free_request_slot()?;
        let token = broker
            .begin_bounded(self.pass, RequestKind::Dma, pages)
            .map_err(map_broker_error)?;
        Ok(self.publish_request(slot, token, operation, pages))
    }

    pub fn poll<
        const DEVICES: usize,
        const HOSTS: usize,
        const PASSES: usize,
        const INFLIGHT: usize,
    >(
        &mut self,
        broker: &mut DriverHostBroker<DEVICES, HOSTS, PASSES, INFLIGHT>,
    ) -> Result<UapiRequest, UapiError> {
        self.require_open()?;
        let slot = self.free_request_slot()?;
        let token = broker
            .begin(self.pass, RequestKind::Irq)
            .map_err(map_broker_error)?;
        Ok(self.publish_request(slot, token, UapiOperation::Poll, 1))
    }

    pub fn map_buffer<
        const DEVICES: usize,
        const HOSTS: usize,
        const PASSES: usize,
        const INFLIGHT: usize,
    >(
        &mut self,
        broker: &mut DriverHostBroker<DEVICES, HOSTS, PASSES, INFLIGHT>,
        pages: u64,
        writable: bool,
    ) -> Result<MappedBuffer, UapiError> {
        self.require_open()?;
        if pages == 0 {
            return Err(UapiError::InvalidRequest);
        }
        if writable
            && (!self.access.can_write() || !self.facts.rights().contains(Needs::DMA_WRITE))
        {
            return Err(UapiError::Permission);
        }
        let slot = self
            .buffers
            .iter()
            .position(Option::is_none)
            .ok_or(UapiError::Capacity)?;
        let token = broker
            .begin_bounded(self.pass, RequestKind::Dma, pages)
            .map_err(map_broker_error)?;
        let mapped = MappedBuffer {
            token,
            pages,
            writable,
        };
        self.buffers[slot] = Some(mapped);
        Ok(mapped)
    }

    pub fn unmap<
        const DEVICES: usize,
        const HOSTS: usize,
        const PASSES: usize,
        const INFLIGHT: usize,
    >(
        &mut self,
        broker: &mut DriverHostBroker<DEVICES, HOSTS, PASSES, INFLIGHT>,
        buffer: MappedBuffer,
    ) -> Result<(), UapiError> {
        let slot = self
            .buffers
            .iter()
            .position(|entry| *entry == Some(buffer))
            .ok_or(UapiError::InvalidRequest)?;
        if let Err(error) = broker.complete(buffer.token) {
            if error != DriverHostError::AlreadyTerminal && error != DriverHostError::StalePass {
                return Err(map_broker_error(error));
            }
        }
        self.buffers[slot] = None;
        Ok(())
    }

    pub fn complete<
        const DEVICES: usize,
        const HOSTS: usize,
        const PASSES: usize,
        const INFLIGHT: usize,
    >(
        &mut self,
        broker: &mut DriverHostBroker<DEVICES, HOSTS, PASSES, INFLIGHT>,
        request: UapiRequest,
    ) -> Result<Terminal, UapiError> {
        let slot = self
            .requests
            .iter()
            .position(|entry| *entry == Some(request))
            .ok_or(UapiError::InvalidRequest)?;
        let terminal = broker.complete(request.token).map_err(map_broker_error)?;
        self.requests[slot] = None;
        Ok(terminal)
    }

    pub fn cancel<
        const DEVICES: usize,
        const HOSTS: usize,
        const PASSES: usize,
        const INFLIGHT: usize,
    >(
        &mut self,
        broker: &mut DriverHostBroker<DEVICES, HOSTS, PASSES, INFLIGHT>,
        request: UapiRequest,
    ) -> Result<Terminal, UapiError> {
        let slot = self
            .requests
            .iter()
            .position(|entry| *entry == Some(request))
            .ok_or(UapiError::InvalidRequest)?;
        let terminal = broker.cancel(request.token).map_err(map_broker_error)?;
        self.requests[slot] = None;
        Ok(terminal)
    }

    /// Close the endpoint and cancel every locally owned in-flight resource.
    ///
    /// A host crash or reset may already have revoked these tokens; that is a
    /// valid terminal for close. Local state is cleared in every case.
    pub fn close<
        const DEVICES: usize,
        const HOSTS: usize,
        const PASSES: usize,
        const INFLIGHT: usize,
    >(
        &mut self,
        broker: &mut DriverHostBroker<DEVICES, HOSTS, PASSES, INFLIGHT>,
    ) -> usize {
        if self.closed {
            return 0;
        }
        let mut released = 0;
        for request in self.requests.iter_mut().flatten() {
            if broker.cancel(request.token).is_ok() {
                released += 1;
            }
        }
        for buffer in self.buffers.iter_mut().flatten() {
            if broker.complete(buffer.token).is_ok() {
                released += 1;
            }
        }
        self.requests.fill(None);
        self.buffers.fill(None);
        self.closed = true;
        released
    }

    fn require_open(&self) -> Result<(), UapiError> {
        if self.closed {
            Err(UapiError::Closed)
        } else {
            Ok(())
        }
    }

    fn free_request_slot(&self) -> Result<usize, UapiError> {
        self.requests
            .iter()
            .position(Option::is_none)
            .ok_or(UapiError::Capacity)
    }

    fn publish_request(
        &mut self,
        slot: usize,
        token: RequestToken,
        operation: UapiOperation,
        units: u64,
    ) -> UapiRequest {
        let request = UapiRequest {
            token,
            operation,
            units,
        };
        self.requests[slot] = Some(request);
        request
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver_host::{DeviceIdentity, HostToken, Policy, QuiesceProof};

    const DEVICE: DeviceIdentity = DeviceIdentity {
        identity: 0x400,
        generation: 3,
    };
    const NODE: DeviceNodeId = DeviceNodeId(7);
    const ALL: Needs = Needs::DEVICE
        .union(Needs::MMIO)
        .union(Needs::MMIO_WRITE)
        .union(Needs::DMA)
        .union(Needs::DMA_WRITE)
        .union(Needs::IRQ);

    type Broker = DriverHostBroker<2, 2, 2, 8>;

    fn broker() -> (Broker, HostToken, PassToken, PassFacts) {
        let mut broker = Broker::new();
        broker.discover(DEVICE).unwrap();
        let host = broker.register_host().unwrap();
        let pass = broker
            .admit(host, DEVICE, ALL, Policy::new(ALL, 2, 8, 2))
            .unwrap();
        let facts = broker.pass_facts(pass).unwrap();
        (broker, host, pass, facts)
    }

    #[test]
    fn ioctl_mmap_poll_and_transfer_share_one_admitted_pass() {
        let (mut broker, _, pass, facts) = broker();
        let mut endpoint = LinuxDeviceEndpoint::<4, 2>::open(
            UapiVersion::CURRENT,
            NODE,
            OpenAccess::ReadWrite,
            pass,
            facts,
        )
        .unwrap();
        assert_eq!(endpoint.device(), DEVICE);
        let ioctl = endpoint
            .ioctl(
                &mut broker,
                IoctlRequest {
                    command: 0x802c_542a,
                    payload_bytes: 16,
                },
            )
            .unwrap();
        let read = endpoint.read(&mut broker, 2).unwrap();
        let write = endpoint.write(&mut broker, 1).unwrap();
        let poll = endpoint.poll(&mut broker).unwrap();
        let buffer = endpoint.map_buffer(&mut broker, 3, true).unwrap();
        assert_eq!(endpoint.pending_requests(), 4);
        assert_eq!(endpoint.mapped_buffers(), 1);
        assert_eq!(broker.stats().pending_requests, 5);
        assert_eq!(endpoint.complete(&mut broker, ioctl), Ok(Terminal::Completed));
        assert_eq!(endpoint.cancel(&mut broker, read), Ok(Terminal::Cancelled));
        assert_eq!(endpoint.complete(&mut broker, write), Ok(Terminal::Completed));
        assert_eq!(endpoint.cancel(&mut broker, poll), Ok(Terminal::Cancelled));
        endpoint.unmap(&mut broker, buffer).unwrap();
        assert_eq!(endpoint.pending_requests(), 0);
        assert_eq!(endpoint.mapped_buffers(), 0);
        assert_eq!(broker.stats().pending_requests, 0);
    }

    #[test]
    fn access_direction_and_capacity_fail_before_request_publication() {
        let (mut broker, _, pass, facts) = broker();
        let mut endpoint = LinuxDeviceEndpoint::<1, 1>::open(
            UapiVersion::CURRENT,
            NODE,
            OpenAccess::ReadOnly,
            pass,
            facts,
        )
        .unwrap();
        assert_eq!(endpoint.write(&mut broker, 1), Err(UapiError::Permission));
        let request = endpoint.read(&mut broker, 8).unwrap();
        assert_eq!(endpoint.read(&mut broker, 1), Err(UapiError::Capacity));
        assert_eq!(broker.stats().pending_requests, 1);
        endpoint.cancel(&mut broker, request).unwrap();
        assert_eq!(broker.stats().pending_requests, 0);
    }

    #[test]
    fn reset_revokes_open_endpoint_and_close_is_idempotent() {
        let (mut broker, host, pass, facts) = broker();
        let mut endpoint = LinuxDeviceEndpoint::<2, 1>::open(
            UapiVersion::CURRENT,
            NODE,
            OpenAccess::ReadWrite,
            pass,
            facts,
        )
        .unwrap();
        let _request = endpoint.read(&mut broker, 1).unwrap();
        let receipt = broker.reset(host, QuiesceProof::CLEAN).unwrap();
        assert_eq!(receipt.cancelled, 1);
        assert_eq!(
            endpoint.ioctl(
                &mut broker,
                IoctlRequest {
                    command: 1,
                    payload_bytes: 0,
                },
            ),
            Err(UapiError::DeviceGone)
        );
        assert_eq!(endpoint.close(&mut broker), 0);
        assert_eq!(endpoint.close(&mut broker), 0);
        assert_eq!(
            endpoint.ioctl(
                &mut broker,
                IoctlRequest {
                    command: 1,
                    payload_bytes: 0,
                },
            ),
            Err(UapiError::Closed)
        );
    }

    #[test]
    fn version_node_and_lease_binding_are_strict() {
        let (_broker, _, pass, facts) = broker();
        assert_eq!(
            LinuxDeviceEndpoint::<1, 1>::open(
                UapiVersion { major: 2, minor: 0 },
                NODE,
                OpenAccess::ReadOnly,
                pass,
                facts,
            )
            .err(),
            Some(UapiError::UnsupportedVersion)
        );
        assert_eq!(
            LinuxDeviceEndpoint::<1, 1>::open(
                UapiVersion::CURRENT,
                DeviceNodeId(0),
                OpenAccess::ReadOnly,
                pass,
                facts,
            )
            .err(),
            Some(UapiError::InvalidNode)
        );
    }

    #[test]
    fn close_cancels_all_locally_owned_requests_and_buffers() {
        let (mut broker, _, pass, facts) = broker();
        let mut endpoint = LinuxDeviceEndpoint::<2, 1>::open(
            UapiVersion::CURRENT,
            NODE,
            OpenAccess::ReadWrite,
            pass,
            facts,
        )
        .unwrap();
        endpoint.poll(&mut broker).unwrap();
        endpoint.write(&mut broker, 1).unwrap();
        endpoint.map_buffer(&mut broker, 1, true).unwrap();
        assert_eq!(endpoint.close(&mut broker), 3);
        assert_eq!(broker.stats().pending_requests, 0);
        assert_eq!(endpoint.pending_requests(), 0);
        assert_eq!(endpoint.mapped_buffers(), 0);
    }

    #[test]
    fn crash_recovery_rejects_old_pass_and_preserves_terminal_ownership() {
        let (mut broker, host, pass, facts) = broker();
        let mut old_endpoint = LinuxDeviceEndpoint::<2, 1>::open(
            UapiVersion::CURRENT,
            NODE,
            OpenAccess::ReadWrite,
            pass,
            facts,
        )
        .unwrap();
        let request = old_endpoint.poll(&mut broker).unwrap();
        let crash = broker.crash(host, QuiesceProof::CLEAN).unwrap();
        assert_eq!(crash.cancelled, 1);
        assert_eq!(crash.revoked_passes, 1);

        let recovered_host = broker.recover(host, QuiesceProof::CLEAN).unwrap();
        assert_ne!(recovered_host.generation(), host.generation());
        assert_eq!(
            old_endpoint.ioctl(
                &mut broker,
                IoctlRequest {
                    command: 1,
                    payload_bytes: 0,
                },
            ),
            Err(UapiError::DeviceGone)
        );
        assert_eq!(old_endpoint.complete(&mut broker, request), Err(UapiError::InvalidRequest));
        assert_eq!(old_endpoint.close(&mut broker), 0);

        let new_pass = broker
            .admit(recovered_host, DEVICE, ALL, Policy::new(ALL, 2, 8, 2))
            .unwrap();
        let new_facts = broker.pass_facts(new_pass).unwrap();
        let mut new_endpoint = LinuxDeviceEndpoint::<1, 1>::open(
            UapiVersion::CURRENT,
            NODE,
            OpenAccess::ReadOnly,
            new_pass,
            new_facts,
        )
        .unwrap();
        let new_request = new_endpoint.read(&mut broker, 1).unwrap();
        assert_eq!(
            new_endpoint.complete(&mut broker, new_request),
            Ok(Terminal::Completed)
        );
        new_endpoint.close(&mut broker);
        assert_eq!(broker.stats().pending_requests, 0);
    }

    #[test]
    fn cancel_and_complete_publish_one_terminal() {
        let (mut broker, _, pass, facts) = broker();
        let mut endpoint = LinuxDeviceEndpoint::<1, 1>::open(
            UapiVersion::CURRENT,
            NODE,
            OpenAccess::ReadWrite,
            pass,
            facts,
        )
        .unwrap();
        let request = endpoint.write(&mut broker, 1).unwrap();
        assert_eq!(
            endpoint.cancel(&mut broker, request),
            Ok(Terminal::Cancelled)
        );
        assert_eq!(
            endpoint.complete(&mut broker, request),
            Err(UapiError::InvalidRequest)
        );
        assert_eq!(endpoint.close(&mut broker), 0);
        assert_eq!(broker.stats().pending_requests, 0);
    }
}
