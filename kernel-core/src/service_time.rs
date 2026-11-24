//! Versioned `service.time` protocol over a native Channel.
//! 通过原生 Channel 承载的版本化 `service.time` 协议。
//!
//! This service projects the kernel monotonic clock fact. It owns request
//! validation, idempotency and Time64/Time128 encoding; it does not own a
//! second clock, publish wall time, or replace the kernel read boundary.
//! 本服务只投影内核单调时钟事实，拥有请求校验、幂等和 Time64/Time128 编码；
//! 不建立第二时钟、不发布墙钟，也不取代内核读取边界。

use crate::service_protocol::Header;
use crate::time128::Time128;

pub const PROTOCOL: u32 = 0x454d_4954; // "TIME" little-endian.
pub const VERSION: u16 = 1;
pub const SERVICE_ID: u32 = 0x454d_4954;
pub const REQUEST_BYTES: usize = 32;
pub const RESPONSE_BYTES: usize = 80;

pub const FLAG_MONOTONIC: u32 = 1 << 0;
pub const FLAG_TIME128: u32 = 1 << 1;
pub const DESCRIBE_FLAGS: u32 = FLAG_MONOTONIC | FLAG_TIME128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Operation {
    Describe = 1,
    Sample = 2,
}

impl Operation {
    const fn from_raw(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Describe),
            2 => Some(Self::Sample),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub request_id: u64,
    pub deadline_ns: u64,
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
        put_u64(&mut out, 24, self.deadline_ns);
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
            deadline_ns: get_u64(bytes, 24),
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
    FactUnavailable = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Response {
    pub request_id: u64,
    pub operation: Operation,
    pub status: Status,
    pub abi: u64,
    pub service_generation: u64,
    pub sample_sequence: u64,
    pub monotonic_ns: u64,
    pub time128: Time128,
    pub flags: u32,
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
            sample_sequence: 0,
            monotonic_ns: 0,
            time128: Time128::ZERO,
            flags: DESCRIBE_FLAGS,
            service_id: SERVICE_ID,
        }
    }

    pub fn sample(
        request: Request,
        abi: u64,
        service_generation: u64,
        sample_sequence: u64,
        monotonic_ns: u64,
        time128: Time128,
    ) -> Self {
        Self {
            request_id: request.request_id,
            operation: Operation::Sample,
            status: Status::Ok,
            abi,
            service_generation,
            sample_sequence,
            monotonic_ns,
            time128,
            flags: FLAG_MONOTONIC | FLAG_TIME128,
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
            sample_sequence: 0,
            monotonic_ns: 0,
            time128: Time128::ZERO,
            flags: 0,
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
        put_u64(&mut out, 40, self.sample_sequence);
        put_u64(&mut out, 48, self.monotonic_ns);
        out[56..72].copy_from_slice(&self.time128.to_le_bytes());
        put_u32(&mut out, 72, self.flags);
        put_u32(&mut out, 76, self.service_id);
        out
    }

    pub fn decode(bytes: &[u8; RESPONSE_BYTES]) -> Option<Self> {
        if Header::decode(bytes[..8].try_into().ok()?)
            != Some(Header {
                protocol: PROTOCOL,
                version: VERSION,
                bytes: RESPONSE_BYTES as u16,
            })
            || get_u32(bytes, 76) != SERVICE_ID
            || bytes[10..16].iter().any(|byte| *byte != 0)
        {
            return None;
        }
        let request_id = get_u64(bytes, 16);
        let status = match bytes[9] {
            0 => Status::Ok,
            1 => Status::Protocol,
            2 => Status::Unauthorized,
            3 => Status::TimedOut,
            4 => Status::FactUnavailable,
            _ => return None,
        };
        let mut time128 = [0u8; 16];
        time128.copy_from_slice(&bytes[56..72]);
        let response = Self {
            request_id,
            operation: Operation::from_raw(bytes[8])?,
            status,
            abi: get_u64(bytes, 24),
            service_generation: get_u64(bytes, 32),
            sample_sequence: get_u64(bytes, 40),
            monotonic_ns: get_u64(bytes, 48),
            time128: Time128::from_le_bytes(time128),
            flags: get_u32(bytes, 72),
            service_id: SERVICE_ID,
        };
        let success_shape = match response.operation {
            Operation::Describe => {
                response.sample_sequence == 0
                    && response.monotonic_ns == 0
                    && response.time128 == Time128::ZERO
                    && response.flags == DESCRIBE_FLAGS
            }
            Operation::Sample => {
                response.sample_sequence != 0
                    && response.monotonic_ns != 0
                    && response.flags == (FLAG_MONOTONIC | FLAG_TIME128)
                    && response.time128.to_nanos() == i128::from(response.monotonic_ns)
            }
        };
        let error_shape = response.abi == 0
            && response.sample_sequence == 0
            && response.monotonic_ns == 0
            && response.time128 == Time128::ZERO
            && response.flags == 0;
        (request_id != 0 && ((status == Status::Ok && response.abi != 0 && success_shape)
            || (status != Status::Ok && error_shape)))
            .then_some(response)
    }
}

fn put_u32(out: &mut [u8], at: usize, value: u32) {
    out[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut [u8], at: usize, value: u64) {
    out[at..at + 8].copy_from_slice(&value.to_le_bytes());
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
            deadline_ns: 9,
            operation: Operation::Sample,
        };
        assert_eq!(Request::decode(&request.encode()), Some(request));
        let time128 = Time128::from_nanos(83).unwrap();
        let response = Response::sample(request, 0x0300_1700, 3, 1, 83, time128);
        assert_eq!(Response::decode(&response.encode()), Some(response));
    }

    #[test]
    fn describe_has_no_sample_fact() {
        let request = Request {
            request_id: 8,
            deadline_ns: 0,
            operation: Operation::Describe,
        };
        let response = Response::describe(request, 1, 2);
        assert_eq!(Response::decode(&response.encode()), Some(response));
    }

    #[test]
    fn inconsistent_time_views_and_reserved_bytes_fail_closed() {
        let request = Request {
            request_id: 7,
            deadline_ns: 9,
            operation: Operation::Sample,
        };
        let response = Response::sample(
            request,
            1,
            1,
            1,
            83,
            Time128::from_nanos(83).unwrap(),
        );
        let mut encoded = response.encode();
        encoded[56] ^= 1;
        assert_eq!(Response::decode(&encoded), None);
        encoded = response.encode();
        encoded[10] = 1;
        assert_eq!(Response::decode(&encoded), None);
    }
}
