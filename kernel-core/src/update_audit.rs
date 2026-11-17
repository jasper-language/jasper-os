//! Bounded, path-free query for the latest durable terminal-update receipt.
//!
//! The request selects only a request identity and optional archive sequence.
//! Tenant, caller and authority are supplied by the kernel. The response is a
//! fixed snapshot of the recovery-validated archive receipt and never exposes a
//! block device, partition, control root or archive path.

use crate::update_client::ClientError;
use crate::update_service::SCOPE_PLATFORM;

pub const REQUEST_MAGIC: u32 = u32::from_le_bytes(*b"JUAQ");
pub const REQUEST_VERSION: u16 = 1;
pub const REQUEST_BYTES: usize = 32;
pub const RESPONSE_MAGIC: u32 = u32::from_le_bytes(*b"JUAR");
pub const RESPONSE_VERSION: u16 = 1;
pub const RESPONSE_BYTES: usize = 160;
pub const AUDIT_JSON_BYTES: usize = 640;

/// Request for the current validated archive receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditRequest {
    pub request_id: u64,
    pub expected_archive_sequence: u64,
}

impl AuditRequest {
    pub fn encode(self) -> [u8; REQUEST_BYTES] {
        let mut out = [0u8; REQUEST_BYTES];
        put_u32(&mut out, 0, REQUEST_MAGIC);
        put_u16(&mut out, 4, REQUEST_VERSION);
        put_u64(&mut out, 8, self.request_id);
        put_u64(&mut out, 16, self.expected_archive_sequence);
        put_u32(&mut out, 24, SCOPE_PLATFORM);
        out
    }

    pub fn decode(bytes: &[u8; REQUEST_BYTES]) -> Option<Self> {
        if get_u32(bytes, 0) != REQUEST_MAGIC
            || get_u16(bytes, 4) != REQUEST_VERSION
            || get_u16(bytes, 6) != 0
            || get_u64(bytes, 8) == 0
            || get_u32(bytes, 24) != SCOPE_PLATFORM
            || get_u32(bytes, 28) != 0
        {
            return None;
        }
        Some(Self {
            request_id: get_u64(bytes, 8),
            expected_archive_sequence: get_u64(bytes, 16),
        })
    }
}

/// Kernel-authenticated principal for one archive-audit query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditPrincipal {
    pub subject: u64,
    pub tenant: u64,
    pub domain: u32,
    pub can_query_platform_update: bool,
}

/// Validated current archive receipt or an explicit empty result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditResponse {
    pub request_id: u64,
    pub tenant: u64,
    pub scope: u32,
    pub domain: u32,
    pub available: bool,
    pub archive_sequence: u64,
    pub transaction_id: u64,
    pub manifest_sha256: [u8; 32],
    pub previous_sha256: [u8; 32],
    pub terminal_stage: u8,
}

impl AuditResponse {
    pub fn empty(request_id: u64, principal: AuditPrincipal) -> Self {
        Self {
            request_id,
            tenant: principal.tenant,
            scope: SCOPE_PLATFORM,
            domain: principal.domain,
            available: false,
            archive_sequence: 0,
            transaction_id: 0,
            manifest_sha256: [0; 32],
            previous_sha256: [0; 32],
            terminal_stage: 0,
        }
    }

    pub fn encode(self) -> [u8; RESPONSE_BYTES] {
        let mut out = [0u8; RESPONSE_BYTES];
        put_u32(&mut out, 0, RESPONSE_MAGIC);
        put_u16(&mut out, 4, RESPONSE_VERSION);
        put_u64(&mut out, 8, self.request_id);
        put_u64(&mut out, 16, self.tenant);
        put_u32(&mut out, 24, self.scope);
        put_u32(&mut out, 28, self.domain);
        out[32] = u8::from(self.available);
        out[33] = self.terminal_stage;
        put_u64(&mut out, 40, self.archive_sequence);
        put_u64(&mut out, 48, self.transaction_id);
        out[56..88].copy_from_slice(&self.manifest_sha256);
        out[88..120].copy_from_slice(&self.previous_sha256);
        out
    }

    pub fn decode(bytes: &[u8; RESPONSE_BYTES]) -> Option<Self> {
        if get_u32(bytes, 0) != RESPONSE_MAGIC
            || get_u16(bytes, 4) != RESPONSE_VERSION
            || get_u16(bytes, 6) != 0
            || get_u64(bytes, 8) == 0
            || get_u64(bytes, 16) == 0
            || get_u32(bytes, 24) != SCOPE_PLATFORM
            || bytes[32] > 1
            || !matches!(bytes[33], 0 | 7 | 10)
            || bytes[34..40] != [0; 6]
            || bytes[120..].iter().any(|byte| *byte != 0)
        {
            return None;
        }
        let mut manifest_sha256 = [0; 32];
        manifest_sha256.copy_from_slice(&bytes[56..88]);
        let mut previous_sha256 = [0; 32];
        previous_sha256.copy_from_slice(&bytes[88..120]);
        let available = bytes[32] != 0;
        if available {
            if bytes[33] == 0
                || get_u64(bytes, 40) == 0
                || get_u64(bytes, 48) == 0
                || manifest_sha256 == [0; 32]
                || (get_u64(bytes, 40) > 1 && previous_sha256 == [0; 32])
            {
                return None;
            }
        } else if bytes[33] != 0 || bytes[40..120].iter().any(|byte| *byte != 0) {
            return None;
        }
        Some(Self {
            request_id: get_u64(bytes, 8),
            tenant: get_u64(bytes, 16),
            scope: get_u32(bytes, 24),
            domain: get_u32(bytes, 28),
            available,
            archive_sequence: get_u64(bytes, 40),
            transaction_id: get_u64(bytes, 48),
            manifest_sha256,
            previous_sha256,
            terminal_stage: bytes[33],
        })
    }
}

/// Mechanical transport implemented by the native syscall or an Agent bridge.
pub trait AuditTransport {
    fn audit(
        &mut self,
        request: &[u8; REQUEST_BYTES],
        output: &mut [u8; RESPONSE_BYTES],
    ) -> Result<(), i64>;
}

/// Shared audit client used by native and structured frontends.
pub struct UpdateAuditClient<T> {
    transport: T,
}

impl<T: AuditTransport> UpdateAuditClient<T> {
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    pub fn query(
        &mut self,
        request_id: u64,
        expected_archive_sequence: u64,
    ) -> Result<AuditResponse, ClientError> {
        if request_id == 0 {
            return Err(ClientError::Protocol);
        }
        let request = AuditRequest {
            request_id,
            expected_archive_sequence,
        }
        .encode();
        let mut output = [0u8; RESPONSE_BYTES];
        self.transport
            .audit(&request, &mut output)
            .map_err(ClientError::Transport)?;
        let response = AuditResponse::decode(&output).ok_or(ClientError::Protocol)?;
        if response.request_id != request_id {
            return Err(ClientError::RequestMismatch);
        }
        Ok(response)
    }
}

/// Render one already-validated audit record as `service.update.audit/1`.
pub fn encode_audit_json(response: AuditResponse, output: &mut [u8]) -> Result<usize, ClientError> {
    let mut scratch = [0u8; AUDIT_JSON_BYTES];
    let mut length = 0usize;
    let mut push = |bytes: &[u8]| -> bool {
        let Some(end) = length.checked_add(bytes.len()) else {
            return false;
        };
        if end > scratch.len() {
            return false;
        }
        scratch[length..end].copy_from_slice(bytes);
        length = end;
        true
    };
    let mut ok = push(
        b"{\"schema\":\"service.update.audit/1\",\"command\":\"system.update.audit\",\"status\":\"ok\",\"request\":",
    );
    ok &= push_u64(&mut push, response.request_id);
    ok &= push(b",\"available\":");
    ok &= push(if response.available {
        b"true"
    } else {
        b"false"
    });
    if response.available {
        ok &= push(b",\"sequence\":");
        ok &= push_u64(&mut push, response.archive_sequence);
        ok &= push(b",\"transaction\":");
        ok &= push_u64(&mut push, response.transaction_id);
        ok &= push(b",\"terminal\":\"");
        ok &= push(match response.terminal_stage {
            7 => b"complete".as_slice(),
            10 => b"rolled_back".as_slice(),
            _ => b"unknown".as_slice(),
        });
        ok &= push(b"\",\"digest\":\"");
        ok &= push_hex(&mut push, &response.manifest_sha256);
        ok &= push(b"\",\"previous\":\"");
        ok &= push_hex(&mut push, &response.previous_sha256);
        ok &= push(b"\"");
    }
    ok &= push(b",\"caller\":{\"tenant\":");
    ok &= push_u64(&mut push, response.tenant);
    ok &= push(b",\"domain\":");
    ok &= push_u64(&mut push, u64::from(response.domain));
    ok &= push(b"}}\n");
    if !ok || output.len() < length {
        return Err(ClientError::Protocol);
    }
    output[..length].copy_from_slice(&scratch[..length]);
    Ok(length)
}

fn push_u64(push: &mut impl FnMut(&[u8]) -> bool, mut value: u64) -> bool {
    let mut digits = [0u8; 20];
    let mut at = digits.len();
    loop {
        at -= 1;
        digits[at] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    push(&digits[at..])
}

fn push_hex(push: &mut impl FnMut(&[u8]) -> bool, bytes: &[u8]) -> bool {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        if !push(&[HEX[(byte >> 4) as usize], HEX[(byte & 0xf) as usize]]) {
            return false;
        }
    }
    true
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

    fn principal() -> AuditPrincipal {
        AuditPrincipal {
            subject: 7,
            tenant: 3,
            domain: 1,
            can_query_platform_update: true,
        }
    }

    #[test]
    fn request_and_available_response_round_trip_without_paths() {
        let request = AuditRequest {
            request_id: 41,
            expected_archive_sequence: 5,
        };
        assert_eq!(AuditRequest::decode(&request.encode()), Some(request));
        let response = AuditResponse {
            request_id: 41,
            tenant: 3,
            scope: SCOPE_PLATFORM,
            domain: 1,
            available: true,
            archive_sequence: 5,
            transaction_id: 9,
            manifest_sha256: [0x55; 32],
            previous_sha256: [0x44; 32],
            terminal_stage: 7,
        };
        assert_eq!(AuditResponse::decode(&response.encode()), Some(response));
    }

    #[test]
    fn empty_and_malformed_responses_fail_closed() {
        let empty = AuditResponse::empty(2, principal());
        assert_eq!(AuditResponse::decode(&empty.encode()), Some(empty));

        let mut bytes = empty.encode();
        bytes[40] = 1;
        assert_eq!(AuditResponse::decode(&bytes), None);

        let request = AuditRequest {
            request_id: 1,
            expected_archive_sequence: 0,
        };
        let mut bytes = request.encode();
        bytes[24..28].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(AuditRequest::decode(&bytes), None);
    }

    #[test]
    fn shared_client_and_json_bind_request_identity() {
        struct Fake;
        impl AuditTransport for Fake {
            fn audit(
                &mut self,
                request: &[u8; REQUEST_BYTES],
                output: &mut [u8; RESPONSE_BYTES],
            ) -> Result<(), i64> {
                let request = AuditRequest::decode(request).ok_or(1)?;
                *output = AuditResponse {
                    request_id: request.request_id,
                    tenant: 3,
                    scope: SCOPE_PLATFORM,
                    domain: 1,
                    available: true,
                    archive_sequence: 5,
                    transaction_id: 9,
                    manifest_sha256: [0x55; 32],
                    previous_sha256: [0x44; 32],
                    terminal_stage: 7,
                }
                .encode();
                Ok(())
            }
        }
        let mut client = UpdateAuditClient::new(Fake);
        let response = client.query(41, 5).unwrap();
        let mut json = [0u8; AUDIT_JSON_BYTES];
        let length = encode_audit_json(response, &mut json).unwrap();
        let text = core::str::from_utf8(&json[..length]).unwrap();
        assert!(text.contains("\"available\":true"));
        assert!(text.contains("\"sequence\":5"));
        assert!(text.contains("\"terminal\":\"complete\""));
        assert!(!text.contains("/run"));
    }
}
