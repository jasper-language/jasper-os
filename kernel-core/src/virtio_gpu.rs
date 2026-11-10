//! Bounded virtio-gpu 2D control protocol.
//!
//! 职责：解析固定布局控制命令，维护有界 2D 资源、backing 和 scanout 状态。
//! 边界：不进行像素复制、virgl/vulkan 渲染或真实 GPU 命令执行。
//! Responsibility: host-side control-plane resource bookkeeping.

pub const CONTROL_HEADER_BYTES: usize = 24;
pub const DISPLAY_INFO_BYTES: usize = 24 + 16 * 24;
pub const MAX_RESOURCES: usize = 8;
pub const MAX_DIMENSION: u32 = 4096;

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
    UnsupportedCommand,
    InvalidResource,
    InvalidScanout,
    BackingRequired,
    BackingOverflow,
    Capacity,
    ResponseTooSmall,
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
    backing: Option<(u64, u32)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Scanout {
    resource_id: u32,
    width: u32,
    height: u32,
}

pub struct VirtioGpuBackend {
    resources: [Option<Resource>; MAX_RESOURCES],
    scanout: Option<Scanout>,
    generation: u32,
    commands: u64,
    rejected: u64,
    transfers: u64,
    flushes: u64,
}

impl VirtioGpuBackend {
    pub const fn new() -> Self {
        Self {
            resources: [None; MAX_RESOURCES],
            scanout: None,
            generation: 1,
            commands: 0,
            rejected: 0,
            transfers: 0,
            flushes: 0,
        }
    }

    pub const fn generation(&self) -> u32 {
        self.generation
    }

    pub const fn commands(&self) -> u64 {
        self.commands
    }

    pub const fn rejected(&self) -> u64 {
        self.rejected
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
        self.scanout = None;
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
        put_u32(response, 24, 1);
        put_u32(response, 32, 1024);
        put_u32(response, 36, 768);
        put_u32(response, 40, 1024 * 4);
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
            backing: None,
        };
        if resource.id == 0
            || resource.format != FORMAT_B8G8R8X8
            || resource.width == 0
            || resource.height == 0
            || resource.width > MAX_DIMENSION
            || resource.height > MAX_DIMENSION
            || self.resource(resource.id).is_some()
        {
            return Err((RESP_ERR_INVALID_RESOURCE, GpuFrontendError::InvalidResource));
        }
        let slot = self
            .resources
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or((RESP_ERR_OUT_OF_MEMORY, GpuFrontendError::Capacity))?;
        *slot = Some(resource);
        Ok(nodata(response, header))
    }

    fn attach(
        &mut self,
        header: ControlHeader,
        request: &[u8],
        response: &mut [u8],
    ) -> Result<usize, (u32, GpuFrontendError)> {
        if request.len() != CONTROL_HEADER_BYTES + 24 {
            return Err((RESP_ERR_UNSPEC, GpuFrontendError::InvalidPayload));
        }
        let id = get_u32(request, 24);
        let entries = get_u32(request, 28);
        let address = get_u64(request, 32);
        let length = get_u32(request, 40);
        if entries != 1 || address == 0 || length == 0 {
            return Err((RESP_ERR_UNSPEC, GpuFrontendError::InvalidPayload));
        }
        let slot = self.resource_slot(id)?;
        let resource = self.resources[slot]
            .as_mut()
            .ok_or((RESP_ERR_INVALID_RESOURCE, GpuFrontendError::InvalidResource))?;
        if resource.backing.is_some() {
            return Err((RESP_ERR_UNSPEC, GpuFrontendError::InvalidResource));
        }
        let required = u64::from(resource.width)
            .checked_mul(u64::from(resource.height))
            .and_then(|pixels| pixels.checked_mul(PIXEL_BYTES))
            .ok_or((RESP_ERR_UNSPEC, GpuFrontendError::BackingOverflow))?;
        if u64::from(length) < required {
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
        self.scanout = Some(Scanout {
            resource_id,
            width: get_u32(request, 32),
            height: get_u32(request, 36),
        });
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
        let width = u64::from(get_u32(request, 32));
        let height = u64::from(get_u32(request, 36));
        let bytes = width
            .checked_mul(height)
            .and_then(|pixels| pixels.checked_mul(PIXEL_BYTES))
            .and_then(|bytes| offset.checked_add(bytes))
            .ok_or((RESP_ERR_UNSPEC, GpuFrontendError::BackingOverflow))?;
        if bytes > u64::from(backing_len) {
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
        if self.resource(get_u32(request, 40)).is_none() {
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
        self.resources[slot] = None;
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

impl Default for VirtioGpuBackend {
    fn default() -> Self {
        Self::new()
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

    #[test]
    fn create_attach_scanout_transfer_flush_and_unref_roundtrip() {
        let mut gpu = VirtioGpuBackend::new();
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
        let mut gpu = VirtioGpuBackend::new();
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
    fn malformed_duplicate_and_scanout_without_backing_fail_closed() {
        let mut gpu = VirtioGpuBackend::new();
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
        let mut gpu = VirtioGpuBackend::new();
        let mut response = [0u8; DISPLAY_INFO_BYTES];
        assert_eq!(
            gpu.handle_command(&command(CMD_GET_DISPLAY_INFO, 7, &[]), &mut response),
            Ok(DISPLAY_INFO_BYTES)
        );
        assert_eq!(get_u32(&response, 24), 1);
        assert_eq!(get_u32(&response, 32), 1024);
        gpu.handle_command(&create(), &mut response).unwrap();
        gpu.reset();
        assert_eq!(gpu.generation(), 2);
        assert_eq!(gpu.resource_count(), 0);
    }
}
