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
        Ok(response)
    }

    /// Query status, derive its stable transaction binding and recover it.
    pub fn recover(&mut self, request_id: u64) -> Result<TransactionActionStatus, ClientError> {
        let status = self.status(request_id, 0)?;
        let manifest_sha256 = if status.status.candidate_slot != NO_SLOT {
            status.status.candidate_digest
        } else {
            status.status.active_digest
        };
        let request = TransactionActionRequest {
            request_id,
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
        let response =
            TransactionActionStatus::decode(&output).ok_or(ClientError::Protocol)?;
        if response.request_id != request_id {
            return Err(ClientError::RequestMismatch);
        }
        if response.transaction_id != status.status.transaction_id
            || response.manifest_sha256 != manifest_sha256
            || response.generation != status.status.service_generation
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
    }

    impl UpdateTransport for Fake {
        fn status(
            &mut self,
            request: &[u8],
            output: &mut [u8; RESPONSE_BYTES],
        ) -> Result<(), i64> {
            self.status_calls += 1;
            if let Some(code) = self.fail_status {
                return Err(code);
            }
            let Some(decoded) = StatusRequest::decode(request.try_into().unwrap()) else {
                return Err(1);
            };
            let mut response = self.status;
            response.authorization.request_id = decoded.request_id;
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
            let mut response = self.action;
            response.request_id = decoded.request_id;
            if self.corrupt_action {
                response.generation = response.generation.saturating_add(1);
            }
            *output = response.encode();
            Ok(())
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
        };
        let mut client = UpdateClient::new(fake);
        let queried = client.status(21, 7).unwrap();
        assert_eq!(queried.authorization.request_id, 21);
        let recovered = client.recover(22).unwrap();
        assert_eq!(recovered.transaction_id, 9);
        assert_eq!(recovered.manifest_sha256, [0x55; 32]);
        let fake = client.into_inner();
        assert_eq!(fake.status_calls, 2);
        assert_eq!(fake.recover_calls, 1);
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
        };
        fake.action.transaction_id = 9;
        let mut client = UpdateClient::new(fake);
        assert_eq!(client.recover(1), Err(ClientError::BindingMismatch));
    }
}
