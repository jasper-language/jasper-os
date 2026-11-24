//! Versioned `service.info` protocol over a native Channel.
//! 通过原生 Channel 承载的版本化 `service.info` 协议。
//!
//! The service owns request validation, discovery and projection. Kernel process
//! and module visibility remain facts supplied by their respective kernel
//! boundaries rather than a second registry.
//! 服务拥有请求校验、发现和投影；进程与模块可见性仍由各自内核边界提供，不建立第二注册表。

use crate::service_protocol::Header;

pub const PROTOCOL: u32 = 0x4f46_4e49; // "INFO" little-endian.
pub const VERSION: u16 = 1;
pub const SERVICE_ID: u32 = 0x494e_464f; // "OFNI" little-endian, stable protocol identity.
pub const REQUEST_BYTES: usize = 32;
pub const RESPONSE_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Operation {
    Describe = 1,
    Snapshot = 2,
}

impl Operation {
    const fn from_raw(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Describe),
            2 => Some(Self::Snapshot),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub request_id: u64,
    pub deadline_tick: u64,
    pub operation: Operation,
}

impl Request {
    pub fn encode(self) -> [u8; REQUEST_BYTES] {
        let mut out = [0u8; REQUEST_BYTES];
        out[..8].copy_from_slice(
            &Header {
                protocol: PROTOCOL,
                version: VERSION,
                bytes: REQUEST_BYTES as u16,
            }
            .encode(),
        );
        out[8] = self.operation as u8;
        put_u64(&mut out, 16, self.request_id);
        put_u64(&mut out, 24, self.deadline_tick);
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != REQUEST_BYTES
            || Header::decode(bytes[..8].try_into().ok()?)
                != Some(Header {
                    protocol: PROTOCOL,
                    version: VERSION,
                    bytes: REQUEST_BYTES as u16,
                })
            || bytes[9..16].iter().any(|byte| *byte != 0)
        {
            return None;
        }
        let request_id = get_u64(bytes, 16);
        if request_id == 0 {
            return None;
        }
        Some(Self {
            request_id,
            deadline_tick: get_u64(bytes, 24),
            operation: Operation::from_raw(bytes[8])?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Ok = 0,
    Protocol = 1,
    Unauthorized = 2,
    TimedOut = 3,
    Unsupported = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Response {
    pub request_id: u64,
    pub operation: Operation,
    pub status: Status,
    pub abi: u64,
    pub service_generation: u64,
    pub processes: u16,
    pub modules: u16,
    pub capabilities: u32,
    pub service_id: u32,
}

impl Response {
    pub fn describe(request: Request, abi: u64, service_generation: u64) -> Self {
        Self {
            request_id: request.request_id,
            operation: Operation::Describe,
            status: Status::Ok,
            abi,
            service_generation,
            processes: 0,
            modules: 0,
            capabilities: 0b11,
            service_id: SERVICE_ID,
        }
    }

    pub fn snapshot(
        request: Request,
        abi: u64,
        service_generation: u64,
        processes: u16,
        modules: u16,
    ) -> Self {
        Self {
            request_id: request.request_id,
            operation: Operation::Snapshot,
            status: Status::Ok,
            abi,
            service_generation,
            processes,
            modules,
            capabilities: 0b11,
            service_id: SERVICE_ID,
        }
    }

    pub fn error(request: Request, status: Status, service_generation: u64) -> Option<Self> {
        if status == Status::Ok {
            return None;
        }
        Some(Self {
            request_id: request.request_id,
            operation: request.operation,
            status,
            abi: 0,
            service_generation,
            processes: 0,
            modules: 0,
            capabilities: 0,
            service_id: SERVICE_ID,
        })
    }

    pub fn encode(self) -> [u8; RESPONSE_BYTES] {
        let mut out = [0u8; RESPONSE_BYTES];
        out[..8].copy_from_slice(
            &Header {
                protocol: PROTOCOL,
                version: VERSION,
                bytes: RESPONSE_BYTES as u16,
            }
            .encode(),
        );
        out[8] = self.operation as u8;
        out[9] = self.status as u8;
        put_u64(&mut out, 16, self.request_id);
        put_u64(&mut out, 24, self.abi);
        put_u64(&mut out, 32, self.service_generation);
        put_u16(&mut out, 40, self.processes);
        put_u16(&mut out, 42, self.modules);
        put_u32(&mut out, 44, self.capabilities);
        put_u32(&mut out, 48, self.service_id);
        out
    }

    pub fn decode(bytes: &[u8; RESPONSE_BYTES]) -> Option<Self> {
        if Header::decode(bytes[..8].try_into().ok()?)
            != Some(Header {
                protocol: PROTOCOL,
                version: VERSION,
                bytes: RESPONSE_BYTES as u16,
            })
            || get_u32(bytes, 48) != SERVICE_ID
            || bytes[52..].iter().any(|byte| *byte != 0)
        {
            return None;
        }
        let request_id = get_u64(bytes, 16);
        let status = match bytes[9] {
            0 => Status::Ok,
            1 => Status::Protocol,
            2 => Status::Unauthorized,
            3 => Status::TimedOut,
            4 => Status::Unsupported,
            _ => return None,
        };
        let response = Self {
            request_id,
            operation: Operation::from_raw(bytes[8])?,
            status,
            abi: get_u64(bytes, 24),
            service_generation: get_u64(bytes, 32),
            processes: get_u16(bytes, 40),
            modules: get_u16(bytes, 42),
            capabilities: get_u32(bytes, 44),
            service_id: get_u32(bytes, 48),
        };
        (request_id != 0 && (status == Status::Ok) == (response.abi != 0)).then_some(response)
    }
}

fn put_u16(out: &mut [u8], at: usize, value: u16) {
    out[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut [u8], at: usize, value: u32) {
    out[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut [u8], at: usize, value: u64) {
    out[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn get_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
}

fn get_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn get_u64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_and_responses_round_trip() {
        let request = Request {
            request_id: 7,
            deadline_tick: 9,
            operation: Operation::Snapshot,
        };
        assert_eq!(Request::decode(&request.encode()), Some(request));
        let response = Response::snapshot(request, 0x0300_1600, 3, 4, 5);
        assert_eq!(Response::decode(&response.encode()), Some(response));
    }

    #[test]
    fn service_version_and_reserved_bytes_fail_closed() {
        let request = Request {
            request_id: 7,
            deadline_tick: 9,
            operation: Operation::Describe,
        };
        let mut encoded = request.encode();
        encoded[4] = 2;
        assert_eq!(Request::decode(&encoded), None);
        encoded = request.encode();
        encoded[10] = 1;
        assert_eq!(Request::decode(&encoded), None);
        encoded = request.encode();
        encoded[16..24].fill(0);
        assert_eq!(Request::decode(&encoded), None);
    }

    #[test]
    fn successful_response_cannot_hide_failed_status() {
        let request = Request {
            request_id: 1,
            deadline_tick: 0,
            operation: Operation::Describe,
        };
        let mut response = Response::describe(request, 1, 1).encode();
        response[9] = Status::Unauthorized as u8;
        assert_eq!(Response::decode(&response), None);
    }
}
