//! Bounded virtio-gpu 2D control protocol.
//!
//! 职责：解析规范布局控制命令，维护准入后的 2D 资源、backing 和 scanout 状态。
//! 边界：不进行像素复制、virgl/vulkan 渲染或真实 GPU 命令执行。
//! Responsibility: host-side control-plane resource bookkeeping.
//!
//! Resource metadata is allocated from the per-session [`GpuPolicy`] budget,
//! which is produced by the platform from display facts and available memory.

#[cfg(any(test, feature = "gpu-dynamic"))]
use alloc::vec::Vec;
use crate::service_events::{self, Source as ServiceEventSource};

pub const CONTROL_HEADER_BYTES: usize = 24;
/// Protocol-defined scanout slots in `resp_display_info`.
pub const DISPLAY_SCANOUTS: usize = 16;
pub const DISPLAY_INFO_BYTES: usize = CONTROL_HEADER_BYTES + DISPLAY_SCANOUTS * 24;
pub const CMD_GET_DISPLAY_INFO: u32 = 0x0100;
pub const CMD_RESOURCE_CREATE_2D: u32 = 0x0101;
pub const CMD_RESOURCE_UNREF: u32 = 0x0102;
pub const CMD_SET_SCANOUT: u32 = 0x0103;
pub const CMD_RESOURCE_FLUSH: u32 = 0x0104;
pub const CMD_TRANSFER_TO_HOST_2D: u32 = 0x0105;
pub const CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;
pub const CMD_RESOURCE_DETACH_BACKING: u32 = 0x0107;

pub const RESP_OK_NODATA: u32 = 0x1100;
pub const RESP_OK_DISPLAY_INFO: u32 = 0x1101;
pub const RESP_ERR_UNSPEC: u32 = 0x1200;
pub const RESP_ERR_OUT_OF_MEMORY: u32 = 0x1201;
pub const RESP_ERR_INVALID_SCANOUT: u32 = 0x1202;
pub const RESP_ERR_INVALID_RESOURCE: u32 = 0x1203;
pub const RESP_ERR_INVALID_CONTEXT: u32 = 0x1204;

pub const FORMAT_B8G8R8X8: u32 = 2;
pub const PIXEL_BYTES: u64 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GpuFrontendError {
    HeaderTooShort,
    InvalidHeader,
    InvalidPayload,
    InvalidPolicy,
    UnsupportedCommand,
    InvalidResource,
    InvalidScanout,
    BackingRequired,
    BackingOverflow,
    BudgetExceeded,
    Capacity,
    ResponseTooSmall,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GpuPolicy {
    pub display_width: u32,
    pub display_height: u32,
    pub display_enabled: bool,
    pub resource_budget: usize,
    pub backing_byte_budget: u64,
}

impl GpuPolicy {
    pub fn single_display(
        width: u32,
        height: u32,
        resource_budget: usize,
        backing_byte_budget: u64,
    ) -> Result<Self, GpuFrontendError> {
        let policy = Self {
            display_width: width,
            display_height: height,
            display_enabled: true,
            resource_budget,
            backing_byte_budget,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(self) -> Result<(), GpuFrontendError> {
        let display_valid =
            !self.display_enabled || (self.display_width != 0 && self.display_height != 0);
        let resources_valid = self.resource_budget != 0 && self.backing_byte_budget != 0;
        if !display_valid || !resources_valid {
            return Err(GpuFrontendError::InvalidPolicy);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlHeader {
    pub command: u32,
    pub flags: u32,
    pub fence: u64,
    pub context: u32,
}

impl ControlHeader {
    pub fn decode(raw: &[u8]) -> Result<Self, GpuFrontendError> {
        if raw.len() < CONTROL_HEADER_BYTES {
            return Err(GpuFrontendError::HeaderTooShort);
        }
        let header = Self {
            command: get_u32(raw, 0),
            flags: get_u32(raw, 4),
            fence: get_u64(raw, 8),
            context: get_u32(raw, 16),
        };
        if header.flags != 0 || header.context != 0 {
            return Err(GpuFrontendError::InvalidHeader);
        }
        Ok(header)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Resource {
    id: u32,
    format: u32,
    width: u32,
    height: u32,
    bytes: u64,
    backing: Option<(u64, u32)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Scanout {
    resource_id: u32,
    width: u32,
    height: u32,
}

#[cfg(any(test, feature = "gpu-dynamic"))]
pub struct VirtioGpuBackend {
    policy: GpuPolicy,
    resources: Vec<Option<Resource>>,
    resident_bytes: u64,
    scanout: Option<Scanout>,
    generation: u32,
    commands: u64,
    created: u64,
    destroyed: u64,
    rejected: u64,
    scanouts: u64,
    transfers: u64,
    flushes: u64,
    events: Option<ServiceEventSource>,
}

#[cfg(any(test, feature = "gpu-dynamic"))]
impl VirtioGpuBackend {
    pub fn new(policy: GpuPolicy) -> Result<Self, GpuFrontendError> {
        policy.validate()?;
        let mut resources = Vec::new();
        resources
            .try_reserve_exact(policy.resource_budget)
            .map_err(|_| GpuFrontendError::Capacity)?;
        resources.resize(policy.resource_budget, None);
        Ok(Self {
            policy,
            resources,
            resident_bytes: 0,
            scanout: None,
            generation: 1,
            commands: 0,
            created: 0,
            destroyed: 0,
            rejected: 0,
            scanouts: 0,
            transfers: 0,
            flushes: 0,
            events: None,
        })
    }

    pub fn new_with_events(
        policy: GpuPolicy,
        event_identity: service_events::Identity,
    ) -> Result<Self, GpuFrontendError> {
        if event_identity.kind != service_events::ServiceKind::Graphics {
            return Err(GpuFrontendError::InvalidPolicy);
        }
        let mut backend = Self::new(policy)?;
        backend.events =
            Some(ServiceEventSource::new(event_identity).map_err(|_| GpuFrontendError::InvalidPolicy)?);
        Ok(backend)
    }

    pub const fn event_source(&self) -> Option<&ServiceEventSource> {
        self.events.as_ref()
    }

    /// A fail-closed backend used when the platform has no verified display
    /// facts. It reports no scanouts and rejects every control command.
    pub fn disabled() -> Self {
        Self {
            policy: GpuPolicy {
                display_width: 0,
                display_height: 0,
                display_enabled: false,
                resource_budget: 1,
                backing_byte_budget: 1,
            },
            resources: Vec::new(),
            resident_bytes: 0,
            scanout: None,
            generation: 1,
            commands: 0,
            created: 0,
            destroyed: 0,
            rejected: 0,
            scanouts: 0,
            transfers: 0,
            flushes: 0,
            events: None,
        }
    }

    pub const fn policy(&self) -> GpuPolicy {
        self.policy
    }

    pub const fn resident_bytes(&self) -> u64 {
        self.resident_bytes
    }

    pub const fn generation(&self) -> u32 {
        self.generation
    }

    pub const fn commands(&self) -> u64 {
        self.commands
    }

    pub const fn created(&self) -> u64 {
        self.created
    }

    pub const fn destroyed(&self) -> u64 {
        self.destroyed
    }

    pub const fn rejected(&self) -> u64 {
        self.rejected
    }

    pub const fn scanouts(&self) -> u64 {
        self.scanouts
    }

    pub const fn transfers(&self) -> u64 {
        self.transfers
    }

    pub const fn flushes(&self) -> u64 {
        self.flushes
    }

    pub fn resource_count(&self) -> usize {
        self.resources.iter().flatten().count()
    }

    pub fn reset(&mut self) {
        self.generation = self.generation.saturating_add(1);
        self.resources.fill(None);
        self.resident_bytes = 0;
        self.scanout = None;
        if let Some(events) = self.events.as_mut() {
            let _ = events.restart(
                u64::from(self.generation),
                self.commands ^ self.destroyed,
            );
        }
    }

    pub fn handle_command(
        &mut self,
        request: &[u8],
        response: &mut [u8],
    ) -> Result<usize, GpuFrontendError> {
        if response.len() < CONTROL_HEADER_BYTES {
            return Err(GpuFrontendError::ResponseTooSmall);
        }
        let header = ControlHeader::decode(request)?;
        if !self.policy.display_enabled {
            self.rejected = self.rejected.saturating_add(1);
            return self.error(
                header,
                response,
                RESP_ERR_UNSPEC,
                GpuFrontendError::InvalidPolicy,
            );
        }
        let result = match header.command {
            CMD_GET_DISPLAY_INFO => self.display_info(header, request, response),
            CMD_RESOURCE_CREATE_2D => self.create_2d(header, request, response),
            CMD_RESOURCE_ATTACH_BACKING => self.attach(header, request, response),
            CMD_RESOURCE_DETACH_BACKING => self.detach(header, request, response),
            CMD_SET_SCANOUT => self.set_scanout(header, request, response),
            CMD_TRANSFER_TO_HOST_2D => self.transfer(header, request, response),
            CMD_RESOURCE_FLUSH => self.flush(header, request, response),
            CMD_RESOURCE_UNREF => self.unref(header, request, response),
            _ => {
                self.rejected = self.rejected.saturating_add(1);
                return self.error(
                    header,
                    response,
                    RESP_ERR_UNSPEC,
                    GpuFrontendError::UnsupportedCommand,
                );
            }
        };
        match result {
            Ok(length) => {
                self.commands = self.commands.saturating_add(1);
                Ok(length)
            }
            Err((code, error)) => {
                if code != RESP_ERR_UNSPEC {
                    self.rejected = self.rejected.saturating_add(1);
                }
                self.error(header, response, code, error)
            }
        }
    }

    fn display_info(
        &mut self,
        header: ControlHeader,
        request: &[u8],
        response: &mut [u8],
    ) -> Result<usize, (u32, GpuFrontendError)> {
        if request.len() != CONTROL_HEADER_BYTES || response.len() < DISPLAY_INFO_BYTES {
            return Err((RESP_ERR_UNSPEC, GpuFrontendError::InvalidPayload));
        }
        response[..DISPLAY_INFO_BYTES].fill(0);
        write_response(response, header, RESP_OK_DISPLAY_INFO);
        put_u32(response, 32, self.policy.display_width);
        put_u32(response, 36, self.policy.display_height);
        put_u32(response, 40, u32::from(self.policy.display_enabled));
        put_u32(response, 44, 0);
        Ok(DISPLAY_INFO_BYTES)
    }

    fn create_2d(
        &mut self,
        header: ControlHeader,
        request: &[u8],
        response: &mut [u8],
    ) -> Result<usize, (u32, GpuFrontendError)> {
        if request.len() != CONTROL_HEADER_BYTES + 16 {
            return Err((RESP_ERR_UNSPEC, GpuFrontendError::InvalidPayload));
        }
        let resource = Resource {
            id: get_u32(request, 24),
            format: get_u32(request, 28),
            width: get_u32(request, 32),
            height: get_u32(request, 36),
            bytes: u64::from(get_u32(request, 32))
                .checked_mul(u64::from(get_u32(request, 36)))
                .and_then(|pixels| pixels.checked_mul(PIXEL_BYTES))
                .ok_or((RESP_ERR_OUT_OF_MEMORY, GpuFrontendError::BackingOverflow))?,
            backing: None,
        };
        if resource.id == 0
            || resource.format != FORMAT_B8G8R8X8
            || resource.width == 0
            || resource.height == 0
            || self.resource(resource.id).is_some()
        {
            return Err((RESP_ERR_INVALID_RESOURCE, GpuFrontendError::InvalidResource));
        }
        if self.resource_count() >= self.policy.resource_budget
            || self
                .resident_bytes
                .checked_add(resource.bytes)
                .is_none_or(|bytes| bytes > self.policy.backing_byte_budget)
        {
            return Err((RESP_ERR_OUT_OF_MEMORY, GpuFrontendError::BudgetExceeded));
        }
        let slot = self
            .resources
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or((RESP_ERR_OUT_OF_MEMORY, GpuFrontendError::Capacity))?;
        *slot = Some(resource);
        self.resident_bytes += resource.bytes;
        self.created = self.created.saturating_add(1);
        Ok(nodata(response, header))
    }

    fn attach(
        &mut self,
        header: ControlHeader,
        request: &[u8],
        response: &mut [u8],
    ) -> Result<usize, (u32, GpuFrontendError)> {
        if request.len() < CONTROL_HEADER_BYTES + 8 {
            return Err((RESP_ERR_UNSPEC, GpuFrontendError::InvalidPayload));
        }
        let id = get_u32(request, 24);
        let entries = get_u32(request, 28);
        let entries_len = usize::try_from(entries)
            .ok()
            .and_then(|count| count.checked_mul(16))
            .and_then(|bytes| (CONTROL_HEADER_BYTES + 8).checked_add(bytes));
        if entries == 0 || entries_len != Some(request.len()) {
            return Err((RESP_ERR_UNSPEC, GpuFrontendError::InvalidPayload));
        }
        let mut address = 0u64;
        let mut length = 0u32;
        for index in 0..entries as usize {
            let entry = CONTROL_HEADER_BYTES + 8 + index * 16;
            let entry_address = get_u64(request, entry);
            let entry_length = get_u32(request, entry + 8);
            if entry_address == 0 || entry_length == 0 {
                return Err((RESP_ERR_UNSPEC, GpuFrontendError::InvalidPayload));
            }
            if index == 0 {
                address = entry_address;
            }
            length = length
                .checked_add(entry_length)
                .ok_or((RESP_ERR_UNSPEC, GpuFrontendError::BackingOverflow))?;
        }
        let slot = self.resource_slot(id)?;
        let resource = self.resources[slot]
            .as_mut()
            .ok_or((RESP_ERR_INVALID_RESOURCE, GpuFrontendError::InvalidResource))?;
        if resource.backing.is_some() {
            return Err((RESP_ERR_UNSPEC, GpuFrontendError::InvalidResource));
        }
        if u64::from(length) < resource.bytes {
            return Err((RESP_ERR_UNSPEC, GpuFrontendError::BackingOverflow));
        }
        resource.backing = Some((address, length));
        Ok(nodata(response, header))
    }

    fn detach(
        &mut self,
        header: ControlHeader,
        request: &[u8],
        response: &mut [u8],
    ) -> Result<usize, (u32, GpuFrontendError)> {
        if request.len() != CONTROL_HEADER_BYTES + 8 {
            return Err((RESP_ERR_UNSPEC, GpuFrontendError::InvalidPayload));
        }
        let id = get_u32(request, 24);
        let slot = self.resource_slot(id)?;
        self.resources[slot]
            .as_mut()
            .ok_or((RESP_ERR_INVALID_RESOURCE, GpuFrontendError::InvalidResource))?
            .backing = None;
        if self
            .scanout
            .is_some_and(|scanout| scanout.resource_id == id)
        {
            self.scanout = None;
        }
        Ok(nodata(response, header))
    }

    fn set_scanout(
        &mut self,
        header: ControlHeader,
        request: &[u8],
        response: &mut [u8],
    ) -> Result<usize, (u32, GpuFrontendError)> {
        if request.len() != CONTROL_HEADER_BYTES + 24 {
            return Err((RESP_ERR_UNSPEC, GpuFrontendError::InvalidPayload));
        }
        let scanout_id = get_u32(request, 40);
        let resource_id = get_u32(request, 44);
        if scanout_id != 0 {
            return Err((RESP_ERR_INVALID_SCANOUT, GpuFrontendError::InvalidScanout));
        }
        if resource_id == 0 {
            self.scanout = None;
            return Ok(nodata(response, header));
        }
        let resource = self
            .resource(resource_id)
            .ok_or((RESP_ERR_INVALID_RESOURCE, GpuFrontendError::InvalidResource))?;
        if resource.backing.is_none() {
            return Err((RESP_ERR_UNSPEC, GpuFrontendError::BackingRequired));
        }
        let rect = request_rect(request);
        if !rect_inside(rect, resource.width, resource.height) {
            return Err((RESP_ERR_INVALID_SCANOUT, GpuFrontendError::InvalidScanout));
        }
        self.scanout = Some(Scanout {
            resource_id,
            width: rect.2,
            height: rect.3,
        });
        self.scanouts = self.scanouts.saturating_add(1);
        Ok(nodata(response, header))
    }

    fn transfer(
        &mut self,
        header: ControlHeader,
        request: &[u8],
        response: &mut [u8],
    ) -> Result<usize, (u32, GpuFrontendError)> {
        if request.len() != CONTROL_HEADER_BYTES + 32 {
            return Err((RESP_ERR_UNSPEC, GpuFrontendError::InvalidPayload));
        }
        let resource = self
            .resource(get_u32(request, 48))
            .ok_or((RESP_ERR_INVALID_RESOURCE, GpuFrontendError::InvalidResource))?;
        let (_, backing_len) = resource
            .backing
            .ok_or((RESP_ERR_UNSPEC, GpuFrontendError::BackingRequired))?;
        let offset = get_u64(request, 40);
        let rect = request_rect(request);
        if !rect_inside(rect, resource.width, resource.height) {
            return Err((RESP_ERR_INVALID_RESOURCE, GpuFrontendError::InvalidResource));
        }
        let row_bytes = u64::from(resource.width)
            .checked_mul(PIXEL_BYTES)
            .ok_or((RESP_ERR_UNSPEC, GpuFrontendError::BackingOverflow))?;
        let last_row = u64::from(rect.1)
            .checked_add(u64::from(rect.3) - 1)
            .ok_or((RESP_ERR_UNSPEC, GpuFrontendError::BackingOverflow))?;
        let last_column = u64::from(rect.0)
            .checked_add(u64::from(rect.2) - 1)
            .ok_or((RESP_ERR_UNSPEC, GpuFrontendError::BackingOverflow))?;
        let end = last_row
            .checked_mul(row_bytes)
            .and_then(|row| row.checked_add(last_column.checked_mul(PIXEL_BYTES)?))
            .and_then(|last| last.checked_add(PIXEL_BYTES))
            .and_then(|end| offset.checked_add(end))
            .ok_or((RESP_ERR_UNSPEC, GpuFrontendError::BackingOverflow))?;
        if end > u64::from(backing_len) {
            return Err((RESP_ERR_UNSPEC, GpuFrontendError::BackingOverflow));
        }
        self.transfers = self.transfers.saturating_add(1);
        Ok(nodata(response, header))
    }

    fn flush(
        &mut self,
        header: ControlHeader,
        request: &[u8],
        response: &mut [u8],
    ) -> Result<usize, (u32, GpuFrontendError)> {
        if request.len() != CONTROL_HEADER_BYTES + 24 {
            return Err((RESP_ERR_UNSPEC, GpuFrontendError::InvalidPayload));
        }
        let resource = self
            .resource(get_u32(request, 40))
            .ok_or((RESP_ERR_INVALID_RESOURCE, GpuFrontendError::InvalidResource))?;
        if !rect_inside(request_rect(request), resource.width, resource.height) {
            return Err((RESP_ERR_INVALID_RESOURCE, GpuFrontendError::InvalidResource));
        }
        self.flushes = self.flushes.saturating_add(1);
        Ok(nodata(response, header))
    }

    fn unref(
        &mut self,
        header: ControlHeader,
        request: &[u8],
        response: &mut [u8],
    ) -> Result<usize, (u32, GpuFrontendError)> {
        if request.len() != CONTROL_HEADER_BYTES + 8 {
            return Err((RESP_ERR_UNSPEC, GpuFrontendError::InvalidPayload));
        }
        let id = get_u32(request, 24);
        let slot = self.resource_slot(id)?;
        if let Some(resource) = self.resources[slot] {
            self.resident_bytes = self.resident_bytes.saturating_sub(resource.bytes);
        }
        self.resources[slot] = None;
        self.destroyed = self.destroyed.saturating_add(1);
        if self
            .scanout
            .is_some_and(|scanout| scanout.resource_id == id)
        {
            self.scanout = None;
        }
        Ok(nodata(response, header))
    }

    fn resource(&self, id: u32) -> Option<Resource> {
        self.resources
            .iter()
            .flatten()
            .find(|resource| resource.id == id)
            .copied()
    }

    fn resource_slot(&self, id: u32) -> Result<usize, (u32, GpuFrontendError)> {
        self.resources
            .iter()
            .position(|entry| entry.is_some_and(|resource| resource.id == id))
            .ok_or((RESP_ERR_INVALID_RESOURCE, GpuFrontendError::InvalidResource))
    }

    fn error(
        &self,
        header: ControlHeader,
        response: &mut [u8],
        code: u32,
        error: GpuFrontendError,
    ) -> Result<usize, GpuFrontendError> {
        write_response(response, header, code);
        let _ = error;
        Ok(CONTROL_HEADER_BYTES)
    }
}

fn nodata(response: &mut [u8], header: ControlHeader) -> usize {
    write_response(response, header, RESP_OK_NODATA);
    CONTROL_HEADER_BYTES
}

fn write_response(response: &mut [u8], header: ControlHeader, command: u32) {
    response[..CONTROL_HEADER_BYTES].fill(0);
    put_u32(response, 0, command);
    put_u64(response, 8, header.fence);
}

fn get_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn get_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

/// `virtio_gpu_rect` occupies the first 16 payload bytes of scanout,
/// transfer and flush commands.
fn request_rect(request: &[u8]) -> (u32, u32, u32, u32) {
    (
        get_u32(request, 24),
        get_u32(request, 28),
        get_u32(request, 32),
        get_u32(request, 36),
    )
}

fn rect_inside(rect: (u32, u32, u32, u32), width: u32, height: u32) -> bool {
    let (x, y, rect_width, rect_height) = rect;
    rect_width != 0
        && rect_height != 0
        && x.checked_add(rect_width).is_some_and(|end| end <= width)
        && y.checked_add(rect_height).is_some_and(|end| end <= height)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    fn command(kind: u32, unique: u64, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; CONTROL_HEADER_BYTES + payload.len()];
        put_u32(&mut bytes, 0, kind);
        put_u64(&mut bytes, 8, unique);
        bytes[CONTROL_HEADER_BYTES..].copy_from_slice(payload);
        bytes
    }

    fn create() -> Vec<u8> {
        let mut payload = [0u8; 16];
        put_u32(&mut payload, 0, 1);
        put_u32(&mut payload, 4, FORMAT_B8G8R8X8);
        put_u32(&mut payload, 8, 64);
        put_u32(&mut payload, 12, 64);
        command(CMD_RESOURCE_CREATE_2D, 1, &payload)
    }

    fn attach() -> Vec<u8> {
        let mut payload = [0u8; 24];
        put_u32(&mut payload, 0, 1);
        put_u32(&mut payload, 4, 1);
        put_u64(&mut payload, 8, 0x20_0000);
        put_u32(&mut payload, 16, 64 * 64 * 4);
        command(CMD_RESOURCE_ATTACH_BACKING, 2, &payload)
    }

    fn assert_response(response: &[u8], expected: u32) {
        assert_eq!(get_u32(response, 0), expected);
    }

    fn gpu() -> VirtioGpuBackend {
        VirtioGpuBackend::new(GpuPolicy::single_display(1024, 768, 8, 16 * 1024 * 1024).unwrap())
            .unwrap()
    }

    #[test]
    fn create_attach_scanout_transfer_flush_and_unref_roundtrip() {
        let mut gpu = gpu();
        let mut response = [0u8; 512];
        assert_eq!(gpu.handle_command(&create(), &mut response), Ok(24));
        assert_response(&response, RESP_OK_NODATA);
        assert_eq!(gpu.resource_count(), 1);
        assert_eq!(gpu.handle_command(&attach(), &mut response), Ok(24));
        assert_response(&response, RESP_OK_NODATA);
        let mut scanout = [0u8; 24];
        put_u32(&mut scanout, 8, 64);
        put_u32(&mut scanout, 12, 64);
        put_u32(&mut scanout, 16, 0);
        put_u32(&mut scanout, 20, 1);
        assert_eq!(
            gpu.handle_command(&command(CMD_SET_SCANOUT, 3, &scanout), &mut response),
            Ok(24)
        );
        assert_response(&response, RESP_OK_NODATA);
        let mut transfer = [0u8; 32];
        put_u32(&mut transfer, 8, 64);
        put_u32(&mut transfer, 12, 64);
        put_u32(&mut transfer, 24, 1);
        assert_eq!(
            gpu.handle_command(
                &command(CMD_TRANSFER_TO_HOST_2D, 4, &transfer),
                &mut response
            ),
            Ok(24)
        );
        assert_response(&response, RESP_OK_NODATA);
        let mut unref = [0u8; 8];
        put_u32(&mut unref, 0, 1);
        assert_eq!(
            gpu.handle_command(&command(CMD_RESOURCE_UNREF, 5, &unref), &mut response),
            Ok(24)
        );
        assert_response(&response, RESP_OK_NODATA);
        assert_eq!(gpu.resource_count(), 0);
        assert_eq!(gpu.transfers(), 1);
    }

    #[test]
    fn backing_size_uses_width_times_height_pixels_and_rejects_short_range() {
        let mut gpu = gpu();
        let mut response = [0u8; 512];
        gpu.handle_command(&create(), &mut response).unwrap();

        let mut short = [0u8; 24];
        put_u32(&mut short, 0, 1);
        put_u32(&mut short, 4, 1);
        put_u64(&mut short, 8, 0x20_0000);
        put_u32(&mut short, 16, 64 * 64 * 4 - 1);
        assert_eq!(
            gpu.handle_command(
                &command(CMD_RESOURCE_ATTACH_BACKING, 3, &short),
                &mut response
            ),
            Ok(24)
        );
        assert_response(&response, RESP_ERR_UNSPEC);

        assert_eq!(gpu.handle_command(&attach(), &mut response), Ok(24));
        assert_response(&response, RESP_OK_NODATA);
    }

    #[test]
    fn attach_accepts_multiple_backing_entries_and_sums_their_lengths() {
        let mut gpu = gpu();
        let mut response = [0u8; 512];
        gpu.handle_command(&create(), &mut response).unwrap();

        let mut payload = [0u8; 40];
        put_u32(&mut payload, 0, 1);
        put_u32(&mut payload, 4, 2);
        put_u64(&mut payload, 8, 0x20_0000);
        put_u32(&mut payload, 16, 64 * 32 * 4);
        put_u64(&mut payload, 24, 0x30_0000);
        put_u32(&mut payload, 32, 64 * 32 * 4);
        assert_eq!(
            gpu.handle_command(
                &command(CMD_RESOURCE_ATTACH_BACKING, 9, &payload),
                &mut response
            ),
            Ok(24)
        );
        assert_response(&response, RESP_OK_NODATA);
    }

    #[test]
    fn malformed_duplicate_and_scanout_without_backing_fail_closed() {
        let mut gpu = gpu();
        let mut response = [0u8; 512];
        assert_eq!(gpu.handle_command(&create(), &mut response), Ok(24));
        assert_eq!(gpu.handle_command(&create(), &mut response), Ok(24));
        assert_eq!(gpu.resource_count(), 1);
        let mut scanout = [0u8; 24];
        put_u32(&mut scanout, 20, 1);
        assert_eq!(
            gpu.handle_command(&command(CMD_SET_SCANOUT, 3, &scanout), &mut response),
            Ok(24)
        );
        assert_eq!(get_u32(&response, 0), RESP_ERR_UNSPEC);
        let short = command(CMD_RESOURCE_CREATE_2D, 4, &[0; 8]);
        assert_eq!(gpu.handle_command(&short, &mut response), Ok(24));
        assert_eq!(get_u32(&response, 0), RESP_ERR_UNSPEC);
    }

    #[test]
    fn display_info_and_reset_revoke_old_resources() {
        let identity =
            service_events::Identity::new(service_events::ServiceKind::Graphics, 1, 1).unwrap();
        let mut gpu = VirtioGpuBackend::new_with_events(
            GpuPolicy::single_display(1024, 768, 8, 16 * 1024 * 1024).unwrap(),
            identity,
        )
        .unwrap();
        let observed = gpu.event_source().unwrap().identity();
        let initial = gpu.event_source().unwrap().snapshot();
        let mut subscriber =
            crate::subscription::Queue::<2>::new(initial, crate::subscription::Policy::Events);
        let mut response = [0u8; DISPLAY_INFO_BYTES];
        assert_eq!(
            gpu.handle_command(&command(CMD_GET_DISPLAY_INFO, 7, &[]), &mut response),
            Ok(DISPLAY_INFO_BYTES)
        );
        assert_eq!(get_u32(&response, 32), 1024);
        assert_eq!(get_u32(&response, 36), 768);
        assert_eq!(get_u32(&response, 40), 1);
        gpu.handle_command(&create(), &mut response).unwrap();
        gpu.reset();
        assert_eq!(gpu.generation(), 2);
        assert_eq!(gpu.resource_count(), 0);
        assert_eq!(gpu.resident_bytes(), 0);
        service_events::publish(gpu.event_source().unwrap(), observed, &mut subscriber).unwrap();
        assert_eq!(
            subscriber.take(),
            Some(crate::subscription::Delivery::Resync(
                gpu.event_source().unwrap().snapshot()
            ))
        );
        assert_ne!(
            gpu.event_source().unwrap().identity().generation,
            observed.generation
        );
    }

    #[test]
    fn display_facts_follow_policy_instead_of_fixed_mode() {
        let mut first =
            VirtioGpuBackend::new(GpuPolicy::single_display(800, 600, 2, 8 * 1024 * 1024).unwrap())
                .unwrap();
        let mut second = VirtioGpuBackend::new(
            GpuPolicy::single_display(1920, 1080, 2, 16 * 1024 * 1024).unwrap(),
        )
        .unwrap();
        let mut first_response = [0u8; DISPLAY_INFO_BYTES];
        let mut second_response = [0u8; DISPLAY_INFO_BYTES];
        first
            .handle_command(&command(CMD_GET_DISPLAY_INFO, 1, &[]), &mut first_response)
            .unwrap();
        second
            .handle_command(&command(CMD_GET_DISPLAY_INFO, 2, &[]), &mut second_response)
            .unwrap();
        assert_eq!(
            (get_u32(&first_response, 32), get_u32(&first_response, 36)),
            (800, 600)
        );
        assert_eq!(
            (get_u32(&second_response, 32), get_u32(&second_response, 36)),
            (1920, 1080)
        );
        assert_ne!(first_response[32..44], second_response[32..44]);
    }

    #[test]
    fn policy_budget_not_implementation_slots_controls_capacity() {
        let mut gpu = VirtioGpuBackend::new(
            GpuPolicy::single_display(1024, 768, 1, 16 * 1024 * 1024).unwrap(),
        )
        .unwrap();
        let mut response = [0u8; 512];
        assert_eq!(gpu.handle_command(&create(), &mut response), Ok(24));
        assert_response(&response, RESP_OK_NODATA);
        let mut second = [0u8; 16];
        put_u32(&mut second, 0, 2);
        put_u32(&mut second, 4, FORMAT_B8G8R8X8);
        put_u32(&mut second, 8, 64);
        put_u32(&mut second, 12, 64);
        assert_eq!(
            gpu.handle_command(&command(CMD_RESOURCE_CREATE_2D, 3, &second), &mut response),
            Ok(24)
        );
        assert_response(&response, RESP_ERR_OUT_OF_MEMORY);
    }

    #[test]
    fn heap_backed_resources_grow_past_previous_eight_slot_envelope() {
        let mut gpu = VirtioGpuBackend::new(
            GpuPolicy::single_display(1024, 768, 32, 512 * 1024 * 1024).unwrap(),
        )
        .unwrap();
        let mut response = [0u8; 512];
        for id in 1..=20u32 {
            let mut payload = [0u8; 16];
            put_u32(&mut payload, 0, id);
            put_u32(&mut payload, 4, FORMAT_B8G8R8X8);
            put_u32(&mut payload, 8, 64);
            put_u32(&mut payload, 12, 64);
            assert_eq!(
                gpu.handle_command(
                    &command(CMD_RESOURCE_CREATE_2D, id as u64, &payload),
                    &mut response,
                ),
                Ok(CONTROL_HEADER_BYTES)
            );
            assert_response(&response, RESP_OK_NODATA);
        }
        assert_eq!(gpu.resource_count(), 20);
    }

    #[test]
    fn missing_display_facts_fail_closed() {
        let mut gpu = VirtioGpuBackend::disabled();
        let mut response = [0u8; 512];
        assert_eq!(gpu.handle_command(&create(), &mut response), Ok(24));
        assert_response(&response, RESP_ERR_UNSPEC);
        assert_eq!(gpu.resource_count(), 0);
        assert_eq!(gpu.policy().display_enabled, false);
    }

    #[test]
    fn dimensions_are_bounded_by_bytes_and_backing_entries_are_not_capped() {
        let mut gpu = VirtioGpuBackend::new(
            GpuPolicy::single_display(1024, 768, 1, 512 * 1024 * 1024).unwrap(),
        )
        .unwrap();
        let mut response = [0u8; 512];
        let mut large = [0u8; 16];
        put_u32(&mut large, 0, 1);
        put_u32(&mut large, 4, FORMAT_B8G8R8X8);
        put_u32(&mut large, 8, 8192);
        put_u32(&mut large, 12, 8192);
        assert_eq!(
            gpu.handle_command(&command(CMD_RESOURCE_CREATE_2D, 1, &large), &mut response),
            Ok(24)
        );
        assert_response(&response, RESP_OK_NODATA);

        let entries = 17u32;
        let mut payload = [0u8; 8 + 17 * 16];
        put_u32(&mut payload, 0, 1);
        put_u32(&mut payload, 4, entries);
        let each = 16 * 1024 * 1024;
        for index in 0..entries as usize {
            let at = 8 + index * 16;
            put_u64(&mut payload, at, 0x20_0000 + (index as u64 * each as u64));
            put_u32(&mut payload, at + 8, each);
        }
        put_u32(&mut payload, 4, entries);
        let mut request = vec![0u8; CONTROL_HEADER_BYTES + payload.len()];
        put_u32(&mut request, 0, CMD_RESOURCE_ATTACH_BACKING);
        put_u64(&mut request, 8, 2);
        request[CONTROL_HEADER_BYTES..].copy_from_slice(&payload);
        assert_eq!(gpu.handle_command(&request, &mut response), Ok(24));
        assert_response(&response, RESP_OK_NODATA);
    }
}
