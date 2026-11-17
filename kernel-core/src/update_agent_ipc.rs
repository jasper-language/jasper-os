//! Fixed, bounded wire protocol for the external structured update Agent.
//!
//! The protocol carries already-defined update-service request and response
//! records over a native IPC Channel. It does not reinterpret update state and
//! cannot supply caller identity, tenant, paths or terminal outcomes.

use crate::native_install_abi::{
    UpdateListHeader, MAX_UPDATE_LIST_BYTES, UPDATE_LIST_RECORD_BYTES,
};
use crate::update_service::{
    StatusRequest, TransactionAction, TransactionActionRequest, ACTION_REQUEST_BYTES,
    RESPONSE_BYTES, SCOPE_PLATFORM,
};

/// Request envelope magic (`JUAR` in little-endian byte order).
pub const REQUEST_MAGIC: u32 = 0x5241_554a;
/// Response envelope magic (`JUAP` in little-endian byte order).
pub const RESPONSE_MAGIC: u32 = 0x5041_554a;
/// Current Agent IPC protocol version.
pub const VERSION: u16 = 2;
/// Fixed request envelope header size.
pub const REQUEST_HEADER_BYTES: usize = 32;
/// Fixed response envelope header size.
pub const RESPONSE_HEADER_BYTES: usize = 32;
/// Largest update-service request carried by one Agent message.
pub const MAX_REQUEST_PAYLOAD: usize = ACTION_REQUEST_BYTES; // JASPER-HARDCODE-REVIEW: issue=34 source=update-agent-ipc-v1 reason=fixed-envelope-derived-from-versioned-service-record
/// Largest update-service response carried by one Agent message.
pub const MAX_RESPONSE_PAYLOAD: usize = MAX_UPDATE_LIST_BYTES; // JASPER-HARDCODE-REVIEW: issue=34 source=update-agent-ipc-v2 reason=max-bounded-list-wire-response
/// Complete fixed request message size.
pub const REQUEST_MESSAGE_BYTES: usize = REQUEST_HEADER_BYTES + MAX_REQUEST_PAYLOAD;
/// Complete fixed response message size.
pub const RESPONSE_MESSAGE_BYTES: usize = RESPONSE_HEADER_BYTES + MAX_RESPONSE_PAYLOAD;

/// One update operation admitted by the external Agent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AgentOperation {
    Status = 1,
    Recover = 2,
    Archive = 3,
    List = 4,
}

impl AgentOperation {
    fn from_raw(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Status),
            2 => Some(Self::Recover),
            3 => Some(Self::Archive),
            4 => Some(Self::List),
            _ => None,
        }
    }
}

/// One fixed-size request sent from an Agent client to the broker process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentRequest {
    pub message_id: u64,
    pub deadline_tick: u64,
    pub operation: AgentOperation,
    payload_len: u16,
    payload: [u8; MAX_REQUEST_PAYLOAD],
}

impl AgentRequest {
    /// Build a request whose envelope identity matches its embedded service request.
    pub fn new(
        message_id: u64,
        deadline_tick: u64,
        operation: AgentOperation,
        payload: &[u8],
    ) -> Option<Self> {
        if message_id == 0 || payload.is_empty() || payload.len() > MAX_REQUEST_PAYLOAD {
            return None;
        }
        let service_request_id = match operation {
            AgentOperation::Status => {
                let request = StatusRequest::decode(payload.try_into().ok()?)?;
                if request.scope != SCOPE_PLATFORM {
                    return None;
                }
                request.request_id
            }
            AgentOperation::Recover | AgentOperation::Archive => {
                let request = TransactionActionRequest::decode(payload.try_into().ok()?)?;
                let expected = match operation {
                    AgentOperation::Recover => TransactionAction::Recover,
                    AgentOperation::Archive => TransactionAction::Archive,
                    AgentOperation::Status | AgentOperation::List => unreachable!(),
                };
                if request.scope != SCOPE_PLATFORM || request.action != expected {
                    return None;
                }
                request.request_id
            }
            AgentOperation::List => {
                crate::native_install_abi::UpdateListRequest::decode(payload)?.request_id
            }
        };
        if service_request_id != message_id {
            return None;
        }
        let mut request = Self {
            message_id,
            deadline_tick,
            operation,
            payload_len: payload.len() as u16,
            payload: [0; MAX_REQUEST_PAYLOAD],
        };
        request.payload[..payload.len()].copy_from_slice(payload);
        Some(request)
    }

    /// Immutable service request payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload[..usize::from(self.payload_len)]
    }

    /// Idempotency identity excludes only the retry deadline.
    pub fn same_service_request(&self, other: &Self) -> bool {
        self.message_id == other.message_id
            && self.operation == other.operation
            && self.payload() == other.payload()
    }

    /// Encode one complete fixed-size request message.
    pub fn encode(self) -> [u8; REQUEST_MESSAGE_BYTES] {
        let mut out = [0u8; REQUEST_MESSAGE_BYTES];
        put_u32(&mut out, 0, REQUEST_MAGIC);
        put_u16(&mut out, 4, VERSION);
        out[6] = self.operation as u8;
        put_u64(&mut out, 8, self.message_id);
        put_u64(&mut out, 16, self.deadline_tick);
        put_u16(&mut out, 24, self.payload_len);
        out[REQUEST_HEADER_BYTES..REQUEST_HEADER_BYTES + usize::from(self.payload_len)]
            .copy_from_slice(self.payload());
        out
    }

    /// Decode and validate one fixed-size request.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != REQUEST_MESSAGE_BYTES
            || get_u32(bytes, 0) != REQUEST_MAGIC
            || get_u16(bytes, 4) != VERSION
            || bytes[7] != 0
            || bytes[26..REQUEST_HEADER_BYTES]
                .iter()
                .any(|byte| *byte != 0)
        {
            return None;
        }
        let operation = AgentOperation::from_raw(bytes[6])?;
        let payload_len = usize::from(get_u16(bytes, 24));
        if payload_len == 0
            || payload_len > MAX_REQUEST_PAYLOAD
            || bytes[REQUEST_HEADER_BYTES + payload_len..]
                .iter()
                .any(|byte| *byte != 0)
        {
            return None;
        }
        let request = Self::new(
            get_u64(bytes, 8),
            get_u64(bytes, 16),
            operation,
            &bytes[REQUEST_HEADER_BYTES..REQUEST_HEADER_BYTES + payload_len],
        )?;
        (request.payload_len as usize == payload_len).then_some(request)
    }

    /// Required response payload size for this operation.
    pub const fn response_bytes(self) -> usize {
        match self.operation {
            AgentOperation::Status => RESPONSE_BYTES,
            AgentOperation::Recover | AgentOperation::Archive => {
                crate::update_service::ACTION_RESPONSE_BYTES
            }
            AgentOperation::List => MAX_UPDATE_LIST_BYTES,
        }
    }
}

/// One fixed-size response returned by the Agent broker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentResponse {
    pub message_id: u64,
    pub operation: AgentOperation,
    pub code: i64,
    payload_len: u16,
    payload: [u8; MAX_RESPONSE_PAYLOAD],
}

impl AgentResponse {
    /// Successful service response.
    pub fn ok(request: &AgentRequest, payload: &[u8]) -> Option<Self> {
        if !valid_response_payload(request.operation, request.message_id, payload) {
            return None;
        }
        Self::build(request, 0, payload)
    }

    /// Transport/protocol failure identified by a positive syscall error ID.
    pub fn error(request: &AgentRequest, code: i64) -> Option<Self> {
        if code <= 0 {
            return None;
        }
        Self::build(request, -code, &[])
    }

    fn build(request: &AgentRequest, code: i64, payload: &[u8]) -> Option<Self> {
        if payload.len() > MAX_RESPONSE_PAYLOAD {
            return None;
        }
        let mut response = Self {
            message_id: request.message_id,
            operation: request.operation,
            code,
            payload_len: payload.len() as u16,
            payload: [0; MAX_RESPONSE_PAYLOAD],
        };
        response.payload[..payload.len()].copy_from_slice(payload);
        Some(response)
    }

    /// Immutable service response payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload[..usize::from(self.payload_len)]
    }

    /// Encode one complete fixed-size response message.
    pub fn encode(self) -> [u8; RESPONSE_MESSAGE_BYTES] {
        let mut out = [0u8; RESPONSE_MESSAGE_BYTES];
        put_u32(&mut out, 0, RESPONSE_MAGIC);
        put_u16(&mut out, 4, VERSION);
        out[6] = self.operation as u8;
        out[7] = 0;
        put_u64(&mut out, 8, self.message_id);
        put_u64(&mut out, 16, self.code as u64);
        put_u16(&mut out, 24, self.payload_len);
        out[RESPONSE_HEADER_BYTES..RESPONSE_HEADER_BYTES + usize::from(self.payload_len)]
            .copy_from_slice(self.payload());
        out
    }

    /// Decode and validate one fixed-size response.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != RESPONSE_MESSAGE_BYTES
            || get_u32(bytes, 0) != RESPONSE_MAGIC
            || get_u16(bytes, 4) != VERSION
            || bytes[7] != 0
            || bytes[26..RESPONSE_HEADER_BYTES]
                .iter()
                .any(|byte| *byte != 0)
        {
            return None;
        }
        let operation = AgentOperation::from_raw(bytes[6])?;
        let payload_len = usize::from(get_u16(bytes, 24));
        let code = get_u64(bytes, 16) as i64;
        if payload_len > MAX_RESPONSE_PAYLOAD
            || bytes[RESPONSE_HEADER_BYTES + payload_len..]
                .iter()
                .any(|byte| *byte != 0)
            || (code == 0) == (payload_len == 0)
        {
            return None;
        }
        if code == 0
            && !valid_response_payload(
                operation,
                get_u64(bytes, 8),
                &bytes[RESPONSE_HEADER_BYTES..RESPONSE_HEADER_BYTES + payload_len],
            )
        {
            return None;
        }
        let mut payload = [0u8; MAX_RESPONSE_PAYLOAD];
        payload[..payload_len]
            .copy_from_slice(&bytes[RESPONSE_HEADER_BYTES..RESPONSE_HEADER_BYTES + payload_len]);
        Some(Self {
            message_id: get_u64(bytes, 8),
            operation,
            code,
            payload_len: payload_len as u16,
            payload,
        })
    }
}

fn valid_response_payload(operation: AgentOperation, request_id: u64, payload: &[u8]) -> bool {
    match operation {
        AgentOperation::Status => payload.len() == RESPONSE_BYTES,
        AgentOperation::Recover | AgentOperation::Archive => {
            payload.len() == crate::update_service::ACTION_RESPONSE_BYTES
        }
        AgentOperation::List => {
            let Some(header_bytes) =
                payload.get(..crate::native_install_abi::UPDATE_LIST_HEADER_BYTES)
            else {
                return false;
            };
            let Some(header) = UpdateListHeader::decode(header_bytes) else {
                return false;
            };
            let Some(expected) = (header.record_count as usize)
                .checked_mul(UPDATE_LIST_RECORD_BYTES)
                .and_then(|records| {
                    crate::native_install_abi::UPDATE_LIST_HEADER_BYTES.checked_add(records)
                })
            else {
                return false;
            };
            header.request_id == request_id
                && expected == payload.len()
                && payload.len() <= MAX_RESPONSE_PAYLOAD
        }
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
    use crate::update_service::{TransactionAction, ACTION_REQUEST_BYTES, REQUEST_BYTES};

    fn status_request() -> [u8; REQUEST_BYTES] {
        StatusRequest {
            request_id: 7,
            expected_generation: 0,
            scope: SCOPE_PLATFORM,
        }
        .encode()
    }

    fn action_request() -> [u8; ACTION_REQUEST_BYTES] {
        TransactionActionRequest {
            request_id: 8,
            expected_generation: 3,
            transaction_id: 4,
            manifest_sha256: [5; 32],
            action: TransactionAction::Archive,
            scope: SCOPE_PLATFORM,
        }
        .encode()
    }

    #[test]
    fn request_identity_operation_and_payload_round_trip() {
        let status = AgentRequest::new(7, 11, AgentOperation::Status, &status_request()).unwrap();
        assert_eq!(AgentRequest::decode(&status.encode()), Some(status));
        let archive = AgentRequest::new(8, 12, AgentOperation::Archive, &action_request()).unwrap();
        assert_eq!(AgentRequest::decode(&archive.encode()), Some(archive));
        let list = crate::native_install_abi::UpdateListRequest { request_id: 9 }
            .encode()
            .unwrap();
        let list = AgentRequest::new(9, 13, AgentOperation::List, &list).unwrap();
        assert_eq!(AgentRequest::decode(&list.encode()), Some(list));
    }

    #[test]
    fn list_response_accepts_only_a_complete_header_and_record_set() {
        let request_bytes = crate::native_install_abi::UpdateListRequest { request_id: 9 }
            .encode()
            .unwrap();
        let request = AgentRequest::new(9, 0, AgentOperation::List, &request_bytes).unwrap();
        let mut response = [0u8; crate::native_install_abi::UPDATE_LIST_HEADER_BYTES];
        assert!(UpdateListHeader {
            request_id: 9,
            record_count: 0,
        }
        .encode((&mut response).try_into().unwrap()));
        assert!(AgentResponse::ok(&request, &response).is_some());
        assert!(AgentResponse::ok(&request, &response[..response.len() - 1]).is_none());
        assert!(AgentResponse::ok(&request, &[response.as_slice(), &[1]].concat()).is_none());
    }

    #[test]
    fn mismatched_operation_or_envelope_identity_fails_closed() {
        assert_eq!(
            AgentRequest::new(8, 0, AgentOperation::Recover, &action_request()),
            None
        );
        assert_eq!(
            AgentRequest::new(9, 0, AgentOperation::Status, &status_request()),
            None
        );
        let request = AgentRequest::new(7, 0, AgentOperation::Status, &status_request()).unwrap();
        let mut bytes = request.encode();
        bytes[6] = AgentOperation::Recover as u8;
        assert_eq!(AgentRequest::decode(&bytes), None);
    }

    #[test]
    fn idempotency_ignores_only_the_retry_deadline() {
        let first = AgentRequest::new(7, 11, AgentOperation::Status, &status_request()).unwrap();
        let retry = AgentRequest::new(7, 12, AgentOperation::Status, &status_request()).unwrap();
        assert!(first.same_service_request(&retry));

        let changed = StatusRequest {
            request_id: 7,
            expected_generation: 1,
            scope: SCOPE_PLATFORM,
        }
        .encode();
        let conflict = AgentRequest::new(7, 11, AgentOperation::Status, &changed).unwrap();
        assert!(!first.same_service_request(&conflict));
    }

    #[test]
    fn response_requires_matching_code_and_payload_shape() {
        let request = AgentRequest::new(7, 0, AgentOperation::Status, &status_request()).unwrap();
        let success = AgentResponse::ok(&request, &[9; RESPONSE_BYTES]).unwrap();
        assert_eq!(AgentResponse::decode(&success.encode()), Some(success));
        assert_eq!(AgentResponse::error(&request, 4170).unwrap().code, -4170);
        assert_eq!(AgentResponse::error(&request, 0), None);
        assert_eq!(AgentResponse::ok(&request, &[0; 1]), None);
    }

    #[test]
    fn every_envelope_byte_tamper_is_rejected_or_changes_the_value() {
        let request = AgentRequest::new(7, 0, AgentOperation::Status, &status_request()).unwrap();
        let encoded = request.encode();
        for index in 0..REQUEST_MESSAGE_BYTES {
            let mut changed = encoded;
            changed[index] ^= 1;
            assert_ne!(AgentRequest::decode(&changed), Some(request));
        }

        let response = AgentResponse::ok(
            &AgentRequest::new(7, 0, AgentOperation::Status, &status_request()).unwrap(),
            &[9; RESPONSE_BYTES],
        )
        .unwrap();
        let encoded = response.encode();
        for index in 0..RESPONSE_MESSAGE_BYTES {
            let mut changed = encoded;
            changed[index] ^= 1;
            assert_ne!(AgentResponse::decode(&changed), Some(response));
        }
    }
}
