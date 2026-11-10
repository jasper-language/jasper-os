//! Bounded virtio-fs/FUSE request backend.
//!
//! 职责：解析固定布局的 FUSE 请求，维护有界文件内容、句柄和取消表，并生成
//! 可放回 virtio 队列的响应。边界：不负责描述符遍历、中断投递或生产文件策略。
//! Responsibility: parse bounded FUSE requests and build deterministic replies.
//! Descriptor traversal, interrupt delivery and production policy remain outside.

pub const FUSE_IN_HEADER_BYTES: usize = 40;
pub const FUSE_OUT_HEADER_BYTES: usize = 16;
pub const MAX_REQUEST_BYTES: usize = 4096;
pub const MAX_RESPONSE_BYTES: usize = 4096;
pub const PENDING_CAPACITY: usize = 8;
pub const HANDLE_CAPACITY: usize = 8;
pub const FILE_CAPACITY: usize = 256;

pub const ROOT_NODE: u64 = 1;
pub const FILE_NODE: u64 = 2;
pub const FILE_NAME: &[u8] = b"hello.txt";

pub const OP_LOOKUP: u32 = 1;
pub const OP_FORGET: u32 = 2;
pub const OP_GETATTR: u32 = 3;
pub const OP_OPEN: u32 = 14;
pub const OP_READ: u32 = 15;
pub const OP_WRITE: u32 = 16;
pub const OP_RELEASE: u32 = 18;
pub const OP_FLUSH: u32 = 25;
pub const OP_INIT: u32 = 26;
pub const OP_INTERRUPT: u32 = 36;
pub const OP_DESTROY: u32 = 38;

const ENOENT: i32 = -2;
const EIO: i32 = -5;
const EACCES: i32 = -13;
const EINVAL: i32 = -22;
const ENOSYS: i32 = -38;
const ENOBUFS: i32 = -105;
const EPROTO: i32 = -71;

const ATTR_BYTES: usize = 88;
const ENTRY_OUT_BYTES: usize = 128;
const ATTR_OUT_BYTES: usize = 104;
const OPEN_OUT_BYTES: usize = 16;
const INIT_OUT_BYTES: usize = 64;
const WRITE_OUT_BYTES: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsFrontendError {
    HeaderTooShort,
    DeclaredLengthMismatch,
    RequestTooLarge,
    InvalidRequest,
    QueueFull,
    DuplicateRequest,
    BufferTooSmall,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestHeader {
    pub len: u32,
    pub opcode: u32,
    pub unique: u64,
    pub nodeid: u64,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub total_extlen: u16,
}

impl RequestHeader {
    pub fn decode(raw: &[u8]) -> Result<Self, FsFrontendError> {
        if raw.len() < FUSE_IN_HEADER_BYTES {
            return Err(FsFrontendError::HeaderTooShort);
        }
        let header = Self {
            len: get_u32(raw, 0),
            opcode: get_u32(raw, 4),
            unique: get_u64(raw, 8),
            nodeid: get_u64(raw, 16),
            uid: get_u32(raw, 24),
            gid: get_u32(raw, 28),
            pid: get_u32(raw, 32),
            total_extlen: get_u16(raw, 36),
        };
        if header.unique == 0 || header.len == 0 || header.total_extlen != 0 {
            return Err(FsFrontendError::InvalidRequest);
        }
        if header.len as usize != raw.len() {
            return Err(FsFrontendError::DeclaredLengthMismatch);
        }
        if raw.len() > MAX_REQUEST_BYTES {
            return Err(FsFrontendError::RequestTooLarge);
        }
        Ok(header)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingRequest {
    unique: u64,
    nodeid: u64,
    opcode: u32,
}

pub struct VirtioFsBackend {
    content: [u8; FILE_CAPACITY],
    content_len: usize,
    generation: u32,
    next_handle: u64,
    handles: [Option<u64>; HANDLE_CAPACITY],
    pending: [Option<PendingRequest>; PENDING_CAPACITY],
    requests: u64,
    rejected: u64,
    cancelled: u64,
    unsupported: u64,
}

impl VirtioFsBackend {
    pub fn new() -> Self {
        let mut content = [0u8; FILE_CAPACITY];
        let initial = b"Jasper virtio-fs";
        content[..initial.len()].copy_from_slice(initial);
        Self {
            content,
            content_len: initial.len(),
            generation: 1,
            next_handle: 0,
            handles: [None; HANDLE_CAPACITY],
            pending: [None; PENDING_CAPACITY],
            requests: 0,
            rejected: 0,
            cancelled: 0,
            unsupported: 0,
        }
    }

    pub const fn generation(&self) -> u32 {
        self.generation
    }

    pub const fn requests(&self) -> u64 {
        self.requests
    }

    pub const fn rejected(&self) -> u64 {
        self.rejected
    }

    pub const fn cancelled(&self) -> u64 {
        self.cancelled
    }

    pub const fn unsupported(&self) -> u64 {
        self.unsupported
    }

    pub fn content(&self) -> &[u8] {
        &self.content[..self.content_len]
    }

    pub fn pending_count(&self) -> usize {
        self.pending.iter().filter(|item| item.is_some()).count()
    }

    pub fn handle_count(&self) -> usize {
        self.handles.iter().filter(|item| item.is_some()).count()
    }

    pub fn admit(&mut self, header: RequestHeader) -> Result<(), FsFrontendError> {
        if self
            .pending
            .iter()
            .any(|item| item.is_some_and(|pending| pending.unique == header.unique))
        {
            return Err(FsFrontendError::DuplicateRequest);
        }
        let slot = self
            .pending
            .iter_mut()
            .find(|item| item.is_none())
            .ok_or(FsFrontendError::QueueFull)?;
        *slot = Some(PendingRequest {
            unique: header.unique,
            nodeid: header.nodeid,
            opcode: header.opcode,
        });
        Ok(())
    }

    pub fn cancel(&mut self, unique: u64) -> bool {
        let Some(slot) = self
            .pending
            .iter_mut()
            .find(|item| item.is_some_and(|pending| pending.unique == unique))
        else {
            return false;
        };
        *slot = None;
        self.cancelled = self.cancelled.saturating_add(1);
        true
    }

    pub fn reset(&mut self) {
        self.generation = self.generation.saturating_add(1);
        self.next_handle = 0;
        self.handles.fill(None);
        self.pending.fill(None);
    }

    pub fn handle_request(
        &mut self,
        request: &[u8],
        response: &mut [u8],
    ) -> Result<usize, FsFrontendError> {
        let header = RequestHeader::decode(request)?;
        if response.len() < FUSE_OUT_HEADER_BYTES {
            return Err(FsFrontendError::BufferTooSmall);
        }
        self.admit(header)?;
        let result = self.dispatch(header, request, response);
        self.finish(header.unique);
        match result {
            Ok(0) => Ok(0),
            Ok(length) => {
                self.requests = self.requests.saturating_add(1);
                Ok(length)
            }
            Err((code, counted)) => {
                if counted {
                    self.rejected = self.rejected.saturating_add(1);
                }
                write_out_header(response, FUSE_OUT_HEADER_BYTES as u32, code, header.unique);
                Ok(FUSE_OUT_HEADER_BYTES)
            }
        }
    }

    fn finish(&mut self, unique: u64) {
        if let Some(slot) = self
            .pending
            .iter_mut()
            .find(|item| item.is_some_and(|pending| pending.unique == unique))
        {
            *slot = None;
        }
    }

    fn dispatch(
        &mut self,
        header: RequestHeader,
        request: &[u8],
        response: &mut [u8],
    ) -> Result<usize, (i32, bool)> {
        match header.opcode {
            OP_INIT => self.init(header, request, response),
            OP_LOOKUP => self.lookup(header, request, response),
            OP_GETATTR => self.getattr(header, response),
            OP_OPEN => self.open(header, response),
            OP_READ => self.read(header, request, response),
            OP_WRITE => self.write(header, request, response),
            OP_RELEASE => self.release(header, request, response),
            OP_FLUSH => self.empty_response(header, response),
            OP_FORGET => {
                if header.nodeid != ROOT_NODE && header.nodeid != FILE_NODE {
                    return Err((ENOENT, true));
                }
                Ok(0)
            }
            OP_INTERRUPT => {
                if request.len() != FUSE_IN_HEADER_BYTES + 8 {
                    return Err((EINVAL, true));
                }
                let target = get_u64(request, FUSE_IN_HEADER_BYTES);
                if !self.cancel(target) {
                    return Err((ENOENT, false));
                }
                Ok(0)
            }
            OP_DESTROY => {
                self.reset();
                self.empty_response(header, response)
            }
            _ => {
                self.unsupported = self.unsupported.saturating_add(1);
                Err((ENOSYS, true))
            }
        }
    }

    fn init(
        &mut self,
        header: RequestHeader,
        request: &[u8],
        response: &mut [u8],
    ) -> Result<usize, (i32, bool)> {
        if header.nodeid != 0 || request.len() < FUSE_IN_HEADER_BYTES + 16 {
            return Err((EINVAL, true));
        }
        if get_u32(request, FUSE_IN_HEADER_BYTES) < 7 {
            return Err((EPROTO, true));
        }
        let len = FUSE_OUT_HEADER_BYTES + INIT_OUT_BYTES;
        if response.len() < len {
            return Err((ENOBUFS, false));
        }
        response[..len].fill(0);
        write_out_header(response, len as u32, 0, header.unique);
        put_u32(response, 16, 7);
        put_u32(response, 20, 31);
        put_u32(response, 24, 4096);
        Ok(len)
    }

    fn lookup(
        &mut self,
        header: RequestHeader,
        request: &[u8],
        response: &mut [u8],
    ) -> Result<usize, (i32, bool)> {
        if header.nodeid != ROOT_NODE {
            return Err((ENOENT, true));
        }
        let name = &request[FUSE_IN_HEADER_BYTES..];
        if name.is_empty() || name.last() != Some(&0) || name[..name.len() - 1].contains(&0) {
            return Err((EINVAL, true));
        }
        if &name[..name.len() - 1] != FILE_NAME {
            return Err((ENOENT, true));
        }
        let len = FUSE_OUT_HEADER_BYTES + ENTRY_OUT_BYTES;
        if response.len() < len {
            return Err((ENOBUFS, false));
        }
        response[..len].fill(0);
        write_out_header(response, len as u32, 0, header.unique);
        put_u64(response, 16, FILE_NODE);
        put_u64(response, 24, u64::from(self.generation));
        put_u64(response, 32, 1);
        put_u64(response, 40, 1);
        write_attr(response, 56, FILE_NODE, self.content_len, false);
        Ok(len)
    }

    fn getattr(
        &mut self,
        header: RequestHeader,
        response: &mut [u8],
    ) -> Result<usize, (i32, bool)> {
        let is_directory = match header.nodeid {
            ROOT_NODE => true,
            FILE_NODE => false,
            _ => return Err((ENOENT, true)),
        };
        let len = FUSE_OUT_HEADER_BYTES + ATTR_OUT_BYTES;
        if response.len() < len {
            return Err((ENOBUFS, false));
        }
        response[..len].fill(0);
        write_out_header(response, len as u32, 0, header.unique);
        put_u64(response, 16, 1);
        write_attr(
            response,
            32,
            header.nodeid,
            if is_directory { 0 } else { self.content_len },
            is_directory,
        );
        Ok(len)
    }

    fn open(&mut self, header: RequestHeader, response: &mut [u8]) -> Result<usize, (i32, bool)> {
        if header.nodeid != FILE_NODE {
            return Err((ENOENT, true));
        }
        let len = FUSE_OUT_HEADER_BYTES + OPEN_OUT_BYTES;
        if response.len() < len {
            return Err((ENOBUFS, false));
        }
        let handle = self.next_handle.checked_add(1).ok_or((EIO, false))?;
        if handle == 0 {
            return Err((EIO, false));
        }
        let slot = self
            .handles
            .iter_mut()
            .find(|item| item.is_none())
            .ok_or((ENOBUFS, false))?;
        *slot = Some(handle);
        self.next_handle = handle;
        response[..len].fill(0);
        write_out_header(response, len as u32, 0, header.unique);
        put_u64(response, 16, handle);
        Ok(len)
    }

    fn read(
        &mut self,
        header: RequestHeader,
        request: &[u8],
        response: &mut [u8],
    ) -> Result<usize, (i32, bool)> {
        if header.nodeid != FILE_NODE || request.len() < FUSE_IN_HEADER_BYTES + 40 {
            return Err((EINVAL, true));
        }
        let handle = get_u64(request, FUSE_IN_HEADER_BYTES);
        if !self.valid_handle(handle) {
            return Err((EACCES, true));
        }
        let offset = usize::try_from(get_u64(request, FUSE_IN_HEADER_BYTES + 8))
            .map_err(|_| (EINVAL, true))?;
        let requested = usize::try_from(get_u32(request, FUSE_IN_HEADER_BYTES + 16))
            .map_err(|_| (EINVAL, true))?;
        if offset > self.content_len {
            return Err((EINVAL, true));
        }
        let count = requested.min(self.content_len - offset);
        let len = FUSE_OUT_HEADER_BYTES + count;
        if len > MAX_RESPONSE_BYTES {
            return Err((ENOBUFS, false));
        }
        if response.len() < len {
            return Err((ENOBUFS, false));
        }
        write_out_header(response, len as u32, 0, header.unique);
        response[FUSE_OUT_HEADER_BYTES..len].copy_from_slice(&self.content[offset..offset + count]);
        Ok(len)
    }

    fn write(
        &mut self,
        header: RequestHeader,
        request: &[u8],
        response: &mut [u8],
    ) -> Result<usize, (i32, bool)> {
        if header.nodeid != FILE_NODE || request.len() < FUSE_IN_HEADER_BYTES + 40 {
            return Err((EINVAL, true));
        }
        let handle = get_u64(request, FUSE_IN_HEADER_BYTES);
        if !self.valid_handle(handle) {
            return Err((EACCES, true));
        }
        let offset = usize::try_from(get_u64(request, FUSE_IN_HEADER_BYTES + 8))
            .map_err(|_| (EINVAL, true))?;
        let size = usize::try_from(get_u32(request, FUSE_IN_HEADER_BYTES + 16))
            .map_err(|_| (EINVAL, true))?;
        let payload_offset = FUSE_IN_HEADER_BYTES + 40;
        let payload = &request[payload_offset..];
        if payload.len() != size
            || offset
                .checked_add(size)
                .is_none_or(|end| end > FILE_CAPACITY)
        {
            return Err((EINVAL, true));
        }
        let len = FUSE_OUT_HEADER_BYTES + WRITE_OUT_BYTES;
        if response.len() < len {
            return Err((ENOBUFS, false));
        }
        self.content[offset..offset + size].copy_from_slice(payload);
        self.content_len = self.content_len.max(offset + size);
        response[..len].fill(0);
        write_out_header(response, len as u32, 0, header.unique);
        put_u32(response, 16, size as u32);
        Ok(len)
    }

    fn release(
        &mut self,
        header: RequestHeader,
        request: &[u8],
        response: &mut [u8],
    ) -> Result<usize, (i32, bool)> {
        if header.nodeid != FILE_NODE || request.len() < FUSE_IN_HEADER_BYTES + 24 {
            return Err((EINVAL, true));
        }
        let handle = get_u64(request, FUSE_IN_HEADER_BYTES);
        let Some(slot) = self.handles.iter_mut().find(|item| **item == Some(handle)) else {
            return Err((EACCES, true));
        };
        *slot = None;
        self.empty_response(header, response)
    }

    fn empty_response(
        &mut self,
        header: RequestHeader,
        response: &mut [u8],
    ) -> Result<usize, (i32, bool)> {
        if response.len() < FUSE_OUT_HEADER_BYTES {
            return Err((ENOBUFS, false));
        }
        write_out_header(response, FUSE_OUT_HEADER_BYTES as u32, 0, header.unique);
        Ok(FUSE_OUT_HEADER_BYTES)
    }

    fn valid_handle(&self, handle: u64) -> bool {
        handle != 0 && self.handles.iter().any(|item| *item == Some(handle))
    }
}

impl Default for VirtioFsBackend {
    fn default() -> Self {
        Self::new()
    }
}

fn write_out_header(response: &mut [u8], length: u32, error: i32, unique: u64) {
    put_u32(response, 0, length);
    put_u32(response, 4, error as u32);
    put_u64(response, 8, unique);
}

fn write_attr(response: &mut [u8], offset: usize, node: u64, size: usize, is_directory: bool) {
    let end = offset + ATTR_BYTES;
    if end > response.len() {
        return;
    }
    response[offset..end].fill(0);
    put_u64(response, offset, node);
    put_u64(response, offset + 8, size as u64);
    put_u64(response, offset + 16, 1);
    put_u32(
        response,
        offset + 48,
        if is_directory { 0o040755 } else { 0o100644 },
    );
    put_u32(response, offset + 52, if is_directory { 2 } else { 1 });
    put_u32(response, offset + 72, 4096);
}

fn get_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn get_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("checked request length"),
    )
}

fn get_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("checked request length"),
    )
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

    fn request(opcode: u32, unique: u64, node: u64, payload: &[u8]) -> Vec<u8> {
        let mut raw = vec![0u8; FUSE_IN_HEADER_BYTES + payload.len()];
        let length = raw.len() as u32;
        put_u32(&mut raw, 0, length);
        put_u32(&mut raw, 4, opcode);
        put_u64(&mut raw, 8, unique);
        put_u64(&mut raw, 16, node);
        raw[FUSE_IN_HEADER_BYTES..].copy_from_slice(payload);
        raw
    }

    fn open_file(backend: &mut VirtioFsBackend) -> u64 {
        let request = request(OP_OPEN, 4, FILE_NODE, &[0; 8]);
        let mut response = [0u8; MAX_RESPONSE_BYTES];
        let length = backend.handle_request(&request, &mut response).unwrap();
        assert_eq!(get_u32(&response, 4), 0);
        assert_eq!(get_u32(&response, 0) as usize, length);
        get_u64(&response, 16)
    }

    #[test]
    fn init_lookup_open_read_write_and_release_roundtrip() {
        let mut backend = VirtioFsBackend::new();
        let mut response = [0u8; MAX_RESPONSE_BYTES];

        let init = request(
            OP_INIT,
            1,
            0,
            &[7, 0, 0, 0, 31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );
        assert_eq!(backend.handle_request(&init, &mut response).unwrap(), 80);
        assert_eq!(get_u32(&response, 16), 7);

        let lookup = request(OP_LOOKUP, 2, ROOT_NODE, b"hello.txt\0");
        assert_eq!(
            backend.handle_request(&lookup, &mut response).unwrap(),
            FUSE_OUT_HEADER_BYTES + ENTRY_OUT_BYTES
        );
        assert_eq!(get_u64(&response, 16), FILE_NODE);

        let handle = open_file(&mut backend);
        assert_eq!(backend.handle_count(), 1);

        let mut read_payload = [0u8; 40];
        put_u64(&mut read_payload, 0, handle);
        put_u32(&mut read_payload, 16, 16);
        let read = request(OP_READ, 5, FILE_NODE, &read_payload);
        let length = backend.handle_request(&read, &mut response).unwrap();
        assert_eq!(&response[16..length], b"Jasper virtio-fs");

        let replacement = b"bounded";
        let mut write_payload = vec![0u8; 40 + replacement.len()];
        put_u64(&mut write_payload, 0, handle);
        put_u32(&mut write_payload, 16, replacement.len() as u32);
        write_payload[40..].copy_from_slice(replacement);
        let write = request(OP_WRITE, 6, FILE_NODE, &write_payload);
        assert_eq!(
            backend.handle_request(&write, &mut response).unwrap(),
            FUSE_OUT_HEADER_BYTES + WRITE_OUT_BYTES
        );
        assert_eq!(&backend.content()[..replacement.len()], replacement);

        let mut release_payload = [0u8; 24];
        put_u64(&mut release_payload, 0, handle);
        let release = request(OP_RELEASE, 7, FILE_NODE, &release_payload);
        assert_eq!(
            backend.handle_request(&release, &mut response).unwrap(),
            FUSE_OUT_HEADER_BYTES
        );
        assert_eq!(backend.handle_count(), 0);
    }

    #[test]
    fn malformed_unknown_and_oversized_requests_fail_without_content_change() {
        let mut backend = VirtioFsBackend::new();
        let before = backend.content().to_vec();
        let mut response = [0u8; MAX_RESPONSE_BYTES];

        assert_eq!(
            RequestHeader::decode(&[0u8; FUSE_IN_HEADER_BYTES - 1]),
            Err(FsFrontendError::HeaderTooShort)
        );
        let mut bad_length = request(OP_GETATTR, 1, FILE_NODE, &[]);
        let declared = bad_length.len() as u32 + 1;
        put_u32(&mut bad_length, 0, declared);
        assert_eq!(
            backend.handle_request(&bad_length, &mut response),
            Err(FsFrontendError::DeclaredLengthMismatch)
        );

        let unsupported = request(999, 2, FILE_NODE, &[]);
        assert_eq!(
            backend.handle_request(&unsupported, &mut response).unwrap(),
            FUSE_OUT_HEADER_BYTES
        );
        assert_eq!(get_u32(&response, 4), ENOSYS as u32);
        assert_eq!(backend.rejected(), 1);
        assert_eq!(backend.unsupported(), 1);
        assert_eq!(backend.pending_count(), 0);
        assert_eq!(backend.content(), before);

        let handle = open_file(&mut backend);
        let mut write_payload = vec![0u8; 41];
        put_u64(&mut write_payload, 0, handle);
        put_u32(&mut write_payload, 16, 2);
        let invalid_write = request(OP_WRITE, 3, FILE_NODE, &write_payload);
        assert_eq!(
            backend
                .handle_request(&invalid_write, &mut response)
                .unwrap(),
            FUSE_OUT_HEADER_BYTES
        );
        assert_eq!(get_u32(&response, 4), EINVAL as u32);
        assert_eq!(backend.content(), before);
    }

    #[test]
    fn interrupt_cancels_pending_and_duplicate_is_refused() {
        let mut backend = VirtioFsBackend::new();
        let header = RequestHeader {
            len: FUSE_IN_HEADER_BYTES as u32,
            opcode: OP_GETATTR,
            unique: 42,
            nodeid: FILE_NODE,
            uid: 0,
            gid: 0,
            pid: 1,
            total_extlen: 0,
        };
        backend.admit(header).unwrap();
        assert_eq!(
            backend.admit(header),
            Err(FsFrontendError::DuplicateRequest)
        );

        let mut payload = [0u8; 8];
        put_u64(&mut payload, 0, 42);
        let interrupt = request(OP_INTERRUPT, 43, 0, &payload);
        let mut response = [0u8; MAX_RESPONSE_BYTES];
        assert_eq!(
            backend.handle_request(&interrupt, &mut response).unwrap(),
            0
        );
        assert_eq!(backend.pending_count(), 0);
        assert_eq!(backend.cancelled(), 1);
    }

    #[test]
    fn bounded_pending_table_reset_and_invalid_handle_are_atomic() {
        let mut backend = VirtioFsBackend::new();
        for unique in 1..=PENDING_CAPACITY as u64 {
            backend
                .admit(RequestHeader {
                    len: FUSE_IN_HEADER_BYTES as u32,
                    opcode: OP_GETATTR,
                    unique,
                    nodeid: FILE_NODE,
                    uid: 0,
                    gid: 0,
                    pid: 1,
                    total_extlen: 0,
                })
                .unwrap();
        }
        let full = RequestHeader {
            len: FUSE_IN_HEADER_BYTES as u32,
            opcode: OP_GETATTR,
            unique: 99,
            nodeid: FILE_NODE,
            uid: 0,
            gid: 0,
            pid: 1,
            total_extlen: 0,
        };
        assert_eq!(backend.admit(full), Err(FsFrontendError::QueueFull));
        assert!(backend.cancel(1));
        backend.admit(full).unwrap();
        for unique in 2..=PENDING_CAPACITY as u64 {
            assert!(backend.cancel(unique));
        }

        let handle = open_file(&mut backend);
        let mut read_payload = [0u8; 40];
        put_u64(&mut read_payload, 0, handle);
        let read = request(OP_READ, 100, FILE_NODE, &read_payload);
        let mut response = [0u8; MAX_RESPONSE_BYTES];
        backend.handle_request(&read, &mut response).unwrap();

        let generation = backend.generation();
        backend.reset();
        assert_eq!(backend.generation(), generation + 1);
        assert_eq!(backend.pending_count(), 0);
        assert_eq!(backend.handle_count(), 0);
        assert_eq!(
            backend.handle_request(&read, &mut response).unwrap(),
            FUSE_OUT_HEADER_BYTES
        );
        assert_eq!(get_u32(&response, 4), EACCES as u32);
    }
}
