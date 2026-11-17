//! Bounded structured-Agent frontend for native update services.
//!
//! The frontend owns no update state and performs no transport work itself. It
//! delegates request construction and response validation to [`UpdateClient`],
//! then renders the already-authenticated result into a fixed JSON envelope.
//! Native CLI JSON mode consumes this same frontend so automation and the
//! interactive CLI cannot drift into separate protocols.

use crate::update_client::{ClientError, UpdateClient, UpdateTransport};
use crate::update_service::{StatusResponse, TransactionActionStatus};
use crate::update_status::NO_SLOT;

/// Maximum bytes in one structured status response.
pub const STATUS_JSON_BYTES: usize = 1280;
/// Maximum bytes in one structured recovery response.
pub const ACTION_JSON_BYTES: usize = 512;

/// Failure while completing one structured frontend request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentError {
    /// The shared update client rejected the exchange.
    Client(ClientError),
    /// The caller-provided output cannot hold the complete envelope.
    BufferTooSmall,
}

impl From<ClientError> for AgentError {
    fn from(error: ClientError) -> Self {
        Self::Client(error)
    }
}

/// Structured frontend over a mechanical native or Agent update transport.
pub struct UpdateAgent<T> {
    client: UpdateClient<T>,
}

impl<T: UpdateTransport> UpdateAgent<T> {
    /// Wrap one transport without introducing a second protocol implementation.
    pub const fn new(transport: T) -> Self {
        Self {
            client: UpdateClient::new(transport),
        }
    }

    /// Query status and render `service.update.status/1`.
    pub fn status_json(
        &mut self,
        request_id: u64,
        expected_generation: u64,
        output: &mut [u8],
    ) -> Result<usize, AgentError> {
        let response = self.client.status(request_id, expected_generation)?;
        encode_status_json(&response, output)
    }

    /// Recover one transaction and render `service.update.action/1`.
    pub fn recover_json(
        &mut self,
        status_request_id: u64,
        action_request_id: u64,
        output: &mut [u8],
    ) -> Result<usize, AgentError> {
        let response = self.client.recover(status_request_id, action_request_id)?;
        encode_action_json(&response, output)
    }
}

/// Render an already-validated status response.
///
/// Rendering occurs in a private fixed buffer first. A short caller buffer
/// therefore fails without publishing a partial JSON document.
pub fn encode_status_json(
    response: &StatusResponse,
    output: &mut [u8],
) -> Result<usize, AgentError> {
    let mut scratch = [0u8; STATUS_JSON_BYTES];
    let mut writer = JsonWriter::new(&mut scratch);
    let status = response.status;
    let mut ok = writer.push(
        b"{\"schema\":\"service.update.status/1\",\"command\":\"system.update.status\",\"status\":\"ok\",\"generation\":",
    );
    ok &= writer.push_u64(status.service_generation);
    ok &= writer.push(b",\"transaction\":");
    ok &= writer.push_u64(status.transaction_id);
    ok &= writer.push(b",\"active\":{\"slot\":\"");
    ok &= writer.push(slot_name(status.active_slot));
    ok &= writer.push(b"\",\"state\":\"");
    ok &= writer.push(state_name(status.active_state));
    ok &= writer.push(b"\",\"release\":");
    ok &= writer.push_u64(status.active_release);
    ok &= writer.push(b",\"attempts\":");
    ok &= writer.push_u64(u64::from(status.active_attempts));
    ok &= writer.push(b",\"digest\":\"");
    ok &= writer.push_hex(&status.active_digest);
    ok &= writer.push(b"\"},\"candidate\":");
    if status.candidate_slot == NO_SLOT {
        ok &= writer.push(b"null");
    } else {
        ok &= writer.push(b"{\"slot\":\"");
        ok &= writer.push(slot_name(status.candidate_slot));
        ok &= writer.push(b"\",\"state\":\"");
        ok &= writer.push(state_name(status.candidate_state));
        ok &= writer.push(b"\",\"release\":");
        ok &= writer.push_u64(status.candidate_release);
        ok &= writer.push(b",\"attempts\":");
        ok &= writer.push_u64(u64::from(status.candidate_attempts));
        ok &= writer.push(b",\"digest\":\"");
        ok &= writer.push_hex(&status.candidate_digest);
        ok &= writer.push(b"\"}");
    }
    ok &= writer.push(b",\"rollback_floor\":");
    ok &= writer.push_u64(status.rollback_floor);
    ok &= writer.push(b",\"security_epoch\":");
    ok &= writer.push_u64(status.security_epoch);
    ok &= writer.push(b",\"data_schema\":{\"min\":");
    ok &= writer.push_u64(u64::from(status.data_schema_min));
    ok &= writer.push(b",\"max\":");
    ok &= writer.push_u64(u64::from(status.data_schema_max));
    ok &= writer.push(b"},\"caller\":{\"subject\":");
    ok &= writer.push_u64(status.caller_subject);
    ok &= writer.push(b",\"domain\":");
    ok &= writer.push_u64(u64::from(status.caller_domain));
    ok &= writer.push(b",\"tenant\":");
    ok &= writer.push_u64(response.authorization.tenant);
    ok &= writer.push(b"},\"request\":");
    ok &= writer.push_u64(response.authorization.request_id);
    ok &= writer.push(b"}\n");
    if !ok {
        return Err(AgentError::BufferTooSmall);
    }
    let length = writer.len;
    drop(writer);
    copy_complete(&scratch[..length], output)
}

/// Render an already-validated recovery response.
pub fn encode_action_json(
    response: &TransactionActionStatus,
    output: &mut [u8],
) -> Result<usize, AgentError> {
    let mut scratch = [0u8; ACTION_JSON_BYTES];
    let mut writer = JsonWriter::new(&mut scratch);
    let mut ok = writer.push(
        b"{\"schema\":\"service.update.action/1\",\"command\":\"system.update.recover\",\"status\":\"ok\",\"action\":\"recover\",\"generation\":",
    );
    ok &= writer.push_u64(response.generation);
    ok &= writer.push(b",\"transaction\":");
    ok &= writer.push_u64(response.transaction_id);
    ok &= writer.push(b",\"digest\":\"");
    ok &= writer.push_hex(&response.manifest_sha256);
    ok &= writer.push(b"\",\"recovery_required\":");
    ok &= writer.push(if response.recovery_required {
        b"true"
    } else {
        b"false"
    });
    ok &= writer.push(b",\"archived\":");
    ok &= writer.push(if response.archived { b"true" } else { b"false" });
    ok &= writer.push(b",\"caller\":{\"tenant\":");
    ok &= writer.push_u64(response.tenant);
    ok &= writer.push(b",\"domain\":");
    ok &= writer.push_u64(u64::from(response.domain));
    ok &= writer.push(b"},\"request\":");
    ok &= writer.push_u64(response.request_id);
    ok &= writer.push(b"}\n");
    if !ok {
        return Err(AgentError::BufferTooSmall);
    }
    let length = writer.len;
    drop(writer);
    copy_complete(&scratch[..length], output)
}

fn copy_complete(encoded: &[u8], output: &mut [u8]) -> Result<usize, AgentError> {
    if output.len() < encoded.len() {
        return Err(AgentError::BufferTooSmall);
    }
    output[..encoded.len()].copy_from_slice(encoded);
    Ok(encoded.len())
}

fn slot_name(slot: u8) -> &'static [u8] {
    match slot {
        0 => b"A",
        1 => b"B",
        _ => b"none",
    }
}

fn state_name(state: u8) -> &'static [u8] {
    match state {
        0 => b"empty",
        1 => b"candidate",
        2 => b"confirmed",
        3 => b"failed",
        _ => b"unknown",
    }
}

struct JsonWriter<'a> {
    bytes: &'a mut [u8],
    len: usize,
}

impl<'a> JsonWriter<'a> {
    fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, len: 0 }
    }

    fn push(&mut self, text: &[u8]) -> bool {
        let Some(end) = self.len.checked_add(text.len()) else {
            return false;
        };
        if end > self.bytes.len() {
            return false;
        }
        self.bytes[self.len..end].copy_from_slice(text);
        self.len = end;
        true
    }

    fn push_u64(&mut self, mut value: u64) -> bool {
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
        self.push(&digits[at..])
    }

    fn push_hex(&mut self, bytes: &[u8]) -> bool {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in bytes {
            if !self.push(&[HEX[(byte >> 4) as usize], HEX[(byte & 0xf) as usize]]) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::update_service::{
        Authorization, StatusRequest, ACTION_RESPONSE_BYTES, RESPONSE_BYTES, SCOPE_PLATFORM,
    };
    use crate::update_status::UpdateStatus;

    struct Fake {
        response: StatusResponse,
        last_request: u64,
    }

    impl UpdateTransport for Fake {
        fn status(&mut self, request: &[u8], output: &mut [u8; RESPONSE_BYTES]) -> Result<(), i64> {
            let request = StatusRequest::decode(request.try_into().map_err(|_| 1)?).ok_or(1)?;
            self.last_request = request.request_id;
            let mut response = self.response;
            response.authorization.request_id = request.request_id;
            *output = response.encode();
            Ok(())
        }

        fn recover(
            &mut self,
            _request: &[u8],
            _output: &mut [u8; ACTION_RESPONSE_BYTES],
        ) -> Result<(), i64> {
            Err(2)
        }
    }

    fn response() -> StatusResponse {
        StatusResponse {
            authorization: Authorization {
                request_id: 1,
                tenant: 3,
                domain: 1,
                scope: SCOPE_PLATFORM,
            },
            status: UpdateStatus {
                service_generation: 7,
                transaction_id: 9,
                rollback_floor: 2,
                security_epoch: 3,
                active_slot: 0,
                candidate_slot: NO_SLOT,
                active_state: 2,
                candidate_state: 0,
                active_attempts: 0,
                candidate_attempts: 0,
                active_release: 4,
                candidate_release: 0,
                data_schema_min: 1,
                data_schema_max: 1,
                caller_subject: 11,
                caller_domain: 1,
                active_digest: [0x55; 32],
                candidate_digest: [0; 32],
            },
        }
    }

    #[test]
    fn structured_frontend_uses_shared_client_and_stable_envelope() {
        let fake = Fake {
            response: response(),
            last_request: 0,
        };
        let mut agent = UpdateAgent::new(fake);
        let mut output = [0u8; STATUS_JSON_BYTES];
        let length = agent.status_json(41, 0, &mut output).unwrap();
        let text = core::str::from_utf8(&output[..length]).unwrap();
        assert!(text.starts_with(
            "{\"schema\":\"service.update.status/1\",\"command\":\"system.update.status\",\"status\":\"ok\""
        ));
        assert!(text.contains("\"generation\":7"));
        assert!(text.contains("\"candidate\":null"));
        assert!(text.contains("\"tenant\":3"));
        assert!(text.contains("\"request\":41"));
        assert!(text.ends_with("}\n"));
    }

    #[test]
    fn malformed_identity_uses_the_shared_client_failure_taxonomy() {
        let mut current = response();
        current.authorization.domain = 2;
        let fake = Fake {
            response: current,
            last_request: 0,
        };
        let mut agent = UpdateAgent::new(fake);
        let mut output = [0u8; STATUS_JSON_BYTES];
        assert_eq!(
            agent.status_json(42, 0, &mut output),
            Err(AgentError::Client(ClientError::IdentityMismatch))
        );
    }

    #[test]
    fn short_output_never_publishes_partial_json() {
        let response = response();
        let mut output = [0xa5u8; 32];
        assert_eq!(
            encode_status_json(&response, &mut output),
            Err(AgentError::BufferTooSmall)
        );
        assert_eq!(output, [0xa5; 32]);
    }

    #[test]
    fn structured_recovery_envelope_is_fixed_and_path_free() {
        let response = TransactionActionStatus {
            request_id: 51,
            tenant: 3,
            scope: SCOPE_PLATFORM,
            domain: 1,
            generation: 8,
            transaction_id: 9,
            manifest_sha256: [0x66; 32],
            recovery_required: false,
            archived: false,
        };
        let mut output = [0u8; ACTION_JSON_BYTES];
        let length = encode_action_json(&response, &mut output).unwrap();
        let text = core::str::from_utf8(&output[..length]).unwrap();
        assert!(text.starts_with(
            "{\"schema\":\"service.update.action/1\",\"command\":\"system.update.recover\""
        ));
        assert!(text.contains("\"recovery_required\":false"));
        assert!(text.contains("\"request\":51"));
        assert!(!text.as_bytes().windows(4).any(|window| window == b"/run"));
    }
}
