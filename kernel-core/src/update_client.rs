//! Shared native update-client contract used by CLI and structured frontends.
//!
//! The transport owns the syscall mechanism only. Request construction, response
//! identity checks and status-to-action binding remain in this module so every
//! frontend consumes exactly the same business protocol.

use crate::update_service::{
    StatusRequest, StatusResponse, TransactionAction, TransactionActionRequest,
    TransactionActionStatus, ACTION_RESPONSE_BYTES, RESPONSE_BYTES, SCOPE_PLATFORM,
};
use crate::update_status::NO_SLOT;

/// Failure common to every update-client frontend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientError {
    /// The kernel or host transport rejected the call.
    Transport(i64),
    /// A successful call returned an invalid or wrong-sized response.
    Protocol,
    /// The response was not bound to the request identifier.
    RequestMismatch,
    /// Authenticated caller facts changed within one status/action exchange.
    IdentityMismatch,
    /// The action response did not match the status transaction or digest.
    BindingMismatch,
}

/// Mechanical transport implemented by a native syscall client or Agent bridge.
pub trait UpdateTransport {
    /// Invoke the versioned status query with encoded request bytes.
    fn status(&mut self, request: &[u8], output: &mut [u8; RESPONSE_BYTES]) -> Result<(), i64>;

    /// Invoke the path-free recovery action with encoded request bytes.
    fn recover(
        &mut self,
        request: &[u8],
        output: &mut [u8; ACTION_RESPONSE_BYTES],
    ) -> Result<(), i64>;

    /// Invoke the path-free terminal archive action with encoded request bytes.
    fn archive(
        &mut self,
        request: &[u8],
        output: &mut [u8; ACTION_RESPONSE_BYTES],
    ) -> Result<(), i64>;
}

/// One native update frontend over a shared transport.
pub struct UpdateClient<T> {
    transport: T,
}

impl<T: UpdateTransport> UpdateClient<T> {
    /// Wrap one transport.
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Return the underlying transport after all calls complete.
    pub fn into_inner(self) -> T {
        self.transport
    }

    /// Query authenticated platform status.
    pub fn status(
        &mut self,
        request_id: u64,
        expected_generation: u64,
    ) -> Result<StatusResponse, ClientError> {
        if request_id == 0 {
            return Err(ClientError::Protocol);
        }
        let request = StatusRequest {
            request_id,
            expected_generation,
            scope: SCOPE_PLATFORM,
        }
        .encode();
        let mut output = [0u8; RESPONSE_BYTES];
        self.transport
            .status(&request, &mut output)
            .map_err(ClientError::Transport)?;
        let response = StatusResponse::decode(&output).ok_or(ClientError::Protocol)?;
        if response.authorization.request_id != request_id {
            return Err(ClientError::RequestMismatch);
        }
        if response.authorization.domain != response.status.caller_domain {
            return Err(ClientError::IdentityMismatch);
        }
        Ok(response)
    }

    /// Query status, derive its stable transaction binding and recover it.
    pub fn recover(
        &mut self,
        status_request_id: u64,
        action_request_id: u64,
    ) -> Result<TransactionActionStatus, ClientError> {
        if status_request_id == 0
            || action_request_id == 0
            || status_request_id == action_request_id
        {
            return Err(ClientError::Protocol);
        }
        let status = self.status(status_request_id, 0)?;
        let manifest_sha256 = if status.status.candidate_slot != NO_SLOT {
            status.status.candidate_digest
        } else {
            status.status.active_digest
        };
        let request = TransactionActionRequest {
            request_id: action_request_id,
            expected_generation: status.status.service_generation,
            transaction_id: status.status.transaction_id,
            manifest_sha256,
            action: TransactionAction::Recover,
            scope: SCOPE_PLATFORM,
        }
        .encode();
        let mut output = [0u8; ACTION_RESPONSE_BYTES];
        self.transport
            .recover(&request, &mut output)
            .map_err(ClientError::Transport)?;
        let response = TransactionActionStatus::decode(&output).ok_or(ClientError::Protocol)?;
        if response.request_id != action_request_id {
            return Err(ClientError::RequestMismatch);
        }
        if response.tenant != status.authorization.tenant
            || response.domain != status.authorization.domain
            || response.scope != status.authorization.scope
        {
            return Err(ClientError::IdentityMismatch);
        }
        if response.transaction_id != status.status.transaction_id
            || response.manifest_sha256 != manifest_sha256
            || response.generation != status.status.service_generation
        {
            return Err(ClientError::BindingMismatch);
        }
        Ok(response)
    }

    /// Query authoritative terminal state and archive its exact transaction.
    pub fn archive(
        &mut self,
        status_request_id: u64,
        action_request_id: u64,
    ) -> Result<TransactionActionStatus, ClientError> {
        if status_request_id == 0
            || action_request_id == 0
            || status_request_id == action_request_id
        {
            return Err(ClientError::Protocol);
        }
        let status = self.status(status_request_id, 0)?;
        if !matches!(status.status.terminal_stage, 7 | 10)
            || status.status.candidate_digest == [0; 32]
        {
            return Err(ClientError::Protocol);
        }
        let request = TransactionActionRequest {
            request_id: action_request_id,
            expected_generation: status.status.service_generation,
            transaction_id: status.status.transaction_id,
            manifest_sha256: status.status.candidate_digest,
            action: TransactionAction::Archive,
            scope: SCOPE_PLATFORM,
        }
        .encode();
        let mut output = [0u8; ACTION_RESPONSE_BYTES];
        self.transport
            .archive(&request, &mut output)
            .map_err(ClientError::Transport)?;
        let response = TransactionActionStatus::decode(&output).ok_or(ClientError::Protocol)?;
        if response.request_id != action_request_id {
            return Err(ClientError::RequestMismatch);
        }
        if response.tenant != status.authorization.tenant
            || response.domain != status.authorization.domain
            || response.scope != status.authorization.scope
        {
            return Err(ClientError::IdentityMismatch);
        }
        if response.transaction_id != status.status.transaction_id
            || response.manifest_sha256 != status.status.candidate_digest
            || response.generation != status.status.service_generation
            || !response.archived
        {
            return Err(ClientError::BindingMismatch);
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::update_service::Authorization;
    use crate::update_status::UpdateStatus;

    struct Fake {
        status: StatusResponse,
        action: TransactionActionStatus,
        status_calls: u32,
        recover_calls: u32,
        fail_status: Option<i64>,
        corrupt_action: bool,
        action_tenant: Option<u64>,
        action_domain: Option<u32>,
        status_domain: Option<u32>,
        last_status_request: u64,
        last_action_request: u64,
    }

    impl UpdateTransport for Fake {
        fn status(&mut self, request: &[u8], output: &mut [u8; RESPONSE_BYTES]) -> Result<(), i64> {
            self.status_calls += 1;
            if let Some(code) = self.fail_status {
                return Err(code);
            }
            let Some(decoded) = StatusRequest::decode(request.try_into().unwrap()) else {
                return Err(1);
            };
            self.last_status_request = decoded.request_id;
            let mut response = self.status;
            response.authorization.request_id = decoded.request_id;
            if let Some(domain) = self.status_domain {
                response.authorization.domain = domain;
            }
            *output = response.encode();
            Ok(())
        }

        fn recover(
            &mut self,
            request: &[u8],
            output: &mut [u8; ACTION_RESPONSE_BYTES],
        ) -> Result<(), i64> {
            self.recover_calls += 1;
            let Some(decoded) = TransactionActionRequest::decode(request.try_into().unwrap())
            else {
                return Err(1);
            };
            self.last_action_request = decoded.request_id;
            let mut response = self.action;
            response.request_id = decoded.request_id;
            response.transaction_id = decoded.transaction_id;
            response.manifest_sha256 = decoded.manifest_sha256;
            response.generation = decoded.expected_generation;
            if let Some(tenant) = self.action_tenant {
                response.tenant = tenant;
            }
            if let Some(domain) = self.action_domain {
                response.domain = domain;
            }
            if self.corrupt_action {
                response.generation = response.generation.saturating_add(1);
            }
            *output = response.encode();
            Ok(())
        }

        fn archive(
            &mut self,
            request: &[u8],
            output: &mut [u8; ACTION_RESPONSE_BYTES],
        ) -> Result<(), i64> {
            self.recover(request, output)
        }
    }

    fn status(request_tenant: u64) -> StatusResponse {
        StatusResponse {
            authorization: Authorization {
                request_id: 1,
                tenant: request_tenant,
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
                terminal_stage: 0,
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

    fn action() -> TransactionActionStatus {
        TransactionActionStatus {
            request_id: 1,
            tenant: 3,
            scope: SCOPE_PLATFORM,
            domain: 1,
            generation: 7,
            transaction_id: 9,
            manifest_sha256: [0x55; 32],
            recovery_required: false,
            archived: false,
        }
    }

    #[test]
    fn cli_and_agent_business_contract_reuses_one_binding_implementation() {
        let fake = Fake {
            status: status(3),
            action: action(),
            status_calls: 0,
            recover_calls: 0,
            fail_status: None,
            corrupt_action: false,
            action_tenant: None,
            action_domain: None,
            status_domain: None,
            last_status_request: 0,
            last_action_request: 0,
        };
        let mut client = UpdateClient::new(fake);
        let queried = client.status(21, 7).unwrap();
        assert_eq!(queried.authorization.request_id, 21);
        let recovered = client.recover(22, 23).unwrap();
        assert_eq!(recovered.transaction_id, 9);
        assert_eq!(recovered.manifest_sha256, [0x55; 32]);
        assert_eq!(recovered.request_id, 23);
        let fake = client.into_inner();
        assert_eq!(fake.status_calls, 2);
        assert_eq!(fake.recover_calls, 1);
        assert_eq!(fake.last_status_request, 22);
        assert_eq!(fake.last_action_request, 23);
    }

    #[test]
    fn transport_protocol_and_binding_failures_are_distinct() {
        let base = Fake {
            status: status(3),
            action: action(),
            status_calls: 0,
            recover_calls: 0,
            fail_status: Some(4170),
            corrupt_action: false,
            action_tenant: None,
            action_domain: None,
            status_domain: None,
            last_status_request: 0,
            last_action_request: 0,
        };
        assert_eq!(
            UpdateClient::new(base).status(1, 0),
            Err(ClientError::Transport(4170))
        );

        let mut fake = Fake {
            status: status(3),
            action: action(),
            status_calls: 0,
            recover_calls: 0,
            fail_status: None,
            corrupt_action: true,
            action_tenant: None,
            action_domain: None,
            status_domain: None,
            last_status_request: 0,
            last_action_request: 0,
        };
        fake.action.transaction_id = 9;
        let mut client = UpdateClient::new(fake);
        assert_eq!(client.recover(1, 2), Err(ClientError::BindingMismatch));
    }

    #[test]
    fn candidate_digest_is_the_recovery_binding_when_present() {
        let mut current = status(3);
        current.status.candidate_slot = 1;
        current.status.candidate_state = 1;
        current.status.candidate_release = 5;
        current.status.candidate_digest = [0x77; 32];
        let fake = Fake {
            status: current,
            action: action(),
            status_calls: 0,
            recover_calls: 0,
            fail_status: None,
            corrupt_action: false,
            action_tenant: None,
            action_domain: None,
            status_domain: None,
            last_status_request: 0,
            last_action_request: 0,
        };
        let recovered = UpdateClient::new(fake).recover(33, 34).unwrap();
        assert_eq!(recovered.manifest_sha256, [0x77; 32]);
        assert_eq!(recovered.transaction_id, 9);
        assert_eq!(recovered.generation, 7);
        assert_eq!(recovered.request_id, 34);
    }

    #[test]
    fn zero_request_ids_and_cross_envelope_identity_changes_fail_closed() {
        let fake = Fake {
            status: status(3),
            action: action(),
            status_calls: 0,
            recover_calls: 0,
            fail_status: None,
            corrupt_action: false,
            action_tenant: None,
            action_domain: None,
            status_domain: None,
            last_status_request: 0,
            last_action_request: 0,
        };
        assert_eq!(
            UpdateClient::new(fake).status(0, 0),
            Err(ClientError::Protocol)
        );

        let fake = Fake {
            status: status(3),
            action: action(),
            status_calls: 0,
            recover_calls: 0,
            fail_status: None,
            corrupt_action: false,
            action_tenant: Some(4),
            action_domain: None,
            status_domain: None,
            last_status_request: 0,
            last_action_request: 0,
        };
        assert_eq!(
            UpdateClient::new(fake).recover(41, 42),
            Err(ClientError::IdentityMismatch)
        );

        let fake = Fake {
            status: status(3),
            action: action(),
            status_calls: 0,
            recover_calls: 0,
            fail_status: None,
            corrupt_action: false,
            action_tenant: None,
            action_domain: Some(2),
            status_domain: None,
            last_status_request: 0,
            last_action_request: 0,
        };
        assert_eq!(
            UpdateClient::new(fake).recover(43, 44),
            Err(ClientError::IdentityMismatch)
        );

        let fake = Fake {
            status: status(3),
            action: action(),
            status_calls: 0,
            recover_calls: 0,
            fail_status: None,
            corrupt_action: false,
            action_tenant: None,
            action_domain: None,
            status_domain: Some(2),
            last_status_request: 0,
            last_action_request: 0,
        };
        assert_eq!(
            UpdateClient::new(fake).status(45, 0),
            Err(ClientError::IdentityMismatch)
        );
    }

    #[test]
    fn archive_requires_authoritative_terminal_state_and_matching_receipt() {
        let mut terminal = status(3);
        terminal.status.terminal_stage = 7;
        terminal.status.candidate_digest = [0x55; 32];
        let fake = Fake {
            status: terminal,
            action: TransactionActionStatus {
                archived: true,
                ..action()
            },
            status_calls: 0,
            recover_calls: 0,
            fail_status: None,
            corrupt_action: false,
            action_tenant: None,
            action_domain: None,
            status_domain: None,
            last_status_request: 0,
            last_action_request: 0,
        };
        let archived = UpdateClient::new(fake).archive(61, 62).unwrap();
        assert!(archived.archived);
        assert_eq!(archived.manifest_sha256, [0x55; 32]);
        assert_eq!(archived.request_id, 62);

        let fake = Fake {
            status: status(3),
            action: TransactionActionStatus {
                archived: true,
                ..action()
            },
            status_calls: 0,
            recover_calls: 0,
            fail_status: None,
            corrupt_action: false,
            action_tenant: None,
            action_domain: None,
            status_domain: None,
            last_status_request: 0,
            last_action_request: 0,
        };
        assert_eq!(
            UpdateClient::new(fake).archive(63, 64),
            Err(ClientError::Protocol)
        );
    }
}
