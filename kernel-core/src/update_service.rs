//! Versioned status-service contract for native update commands.
//!
//! JUCS resolves the user-facing command. This module is the next layer: a
//! bounded request/response contract that carries request identity, caller
//! tenant, explicit platform scope and an optional expected generation.
//! Neither internal storage paths nor caller-selected tenants are accepted.

use crate::update_status::{UpdateStatus, BYTES as STATUS_BYTES};

pub const REQUEST_MAGIC: u32 = 0x5153_554a; // "JUSQ" little-endian.
pub const REQUEST_VERSION: u16 = 1;
pub const REQUEST_BYTES: usize = 32;
pub const RESPONSE_MAGIC: u32 = 0x5253_554a; // "JUSR" little-endian.
pub const RESPONSE_VERSION: u16 = 1;
pub const RESPONSE_BYTES: usize = 192;
pub const SCOPE_PLATFORM: u32 = 1;
pub const ACTION_REQUEST_MAGIC: u32 = 0x4153_554a; // "JUSA" little-endian.
pub const ACTION_REQUEST_VERSION: u16 = 1;
pub const ACTION_REQUEST_BYTES: usize = 80;
pub const ACTION_RESPONSE_MAGIC: u32 = 0x4253_554a; // "JUSB" little-endian.
pub const ACTION_RESPONSE_VERSION: u16 = 1;
pub const ACTION_RESPONSE_BYTES: usize = 112;

/// One status-service request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatusRequest {
    /// Caller-generated non-zero idempotency and audit identifier.
    pub request_id: u64,
    /// Zero asks for the current generation; non-zero must match it.
    pub expected_generation: u64,
    /// The only currently admitted visibility scope is the platform A/B state.
    pub scope: u32,
}

impl StatusRequest {
    pub fn encode(self) -> [u8; REQUEST_BYTES] {
        let mut out = [0u8; REQUEST_BYTES];
        put_u32(&mut out, 0, REQUEST_MAGIC);
        put_u16(&mut out, 4, REQUEST_VERSION);
        put_u16(&mut out, 6, 0);
        put_u64(&mut out, 8, self.request_id);
        put_u64(&mut out, 16, self.expected_generation);
        put_u32(&mut out, 24, self.scope);
        out
    }

    pub fn decode(bytes: &[u8; REQUEST_BYTES]) -> Option<Self> {
        if get_u32(bytes, 0) != REQUEST_MAGIC
            || get_u16(bytes, 4) != REQUEST_VERSION
            || get_u16(bytes, 6) != 0
            || get_u64(bytes, 8) == 0
            || get_u32(bytes, 28) != 0
        {
            return None;
        }
        Some(Self {
            request_id: get_u64(bytes, 8),
            expected_generation: get_u64(bytes, 16),
            scope: get_u32(bytes, 24),
        })
    }
}

/// Kernel-authenticated caller facts. None of these fields come from the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Principal {
    pub subject: u64,
    pub tenant: u64,
    pub domain: u32,
    pub can_query_platform_update: bool,
}

/// Facts admitted after request and principal checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Authorization {
    pub request_id: u64,
    pub tenant: u64,
    pub domain: u32,
    pub scope: u32,
}

/// Path-free transactional update maintenance action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionAction {
    Recover,
    Archive,
}

impl TransactionAction {
    const fn raw(self) -> u32 {
        match self {
            Self::Recover => 1,
            Self::Archive => 2,
        }
    }

    const fn from_raw(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::Recover),
            2 => Some(Self::Archive),
            _ => None,
        }
    }
}

/// Stable transaction identity supplied by the caller after trusted discovery.
///
/// Internal control, staging and archive paths are intentionally absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionActionRequest {
    pub request_id: u64,
    pub expected_generation: u64,
    pub transaction_id: u64,
    pub manifest_sha256: [u8; 32],
    pub action: TransactionAction,
    pub scope: u32,
}

impl TransactionActionRequest {
    pub fn encode(self) -> [u8; ACTION_REQUEST_BYTES] {
        let mut out = [0u8; ACTION_REQUEST_BYTES];
        put_u32(&mut out, 0, ACTION_REQUEST_MAGIC);
        put_u16(&mut out, 4, ACTION_REQUEST_VERSION);
        put_u16(&mut out, 6, 0);
        put_u64(&mut out, 8, self.request_id);
        put_u64(&mut out, 16, self.expected_generation);
        put_u64(&mut out, 24, self.transaction_id);
        out[32..64].copy_from_slice(&self.manifest_sha256);
        put_u32(&mut out, 64, self.action.raw());
        put_u32(&mut out, 68, self.scope);
        out
    }

    pub fn decode(bytes: &[u8; ACTION_REQUEST_BYTES]) -> Option<Self> {
        if get_u32(bytes, 0) != ACTION_REQUEST_MAGIC
            || get_u16(bytes, 4) != ACTION_REQUEST_VERSION
            || get_u16(bytes, 6) != 0
            || get_u64(bytes, 8) == 0
            || get_u64(bytes, 24) == 0
            || bytes[32..64].iter().all(|byte| *byte == 0)
            || get_u32(bytes, 72) != 0
            || get_u32(bytes, 76) != 0
        {
            return None;
        }
        let mut manifest_sha256 = [0u8; 32];
        manifest_sha256.copy_from_slice(&bytes[32..64]);
        Some(Self {
            request_id: get_u64(bytes, 8),
            expected_generation: get_u64(bytes, 16),
            transaction_id: get_u64(bytes, 24),
            manifest_sha256,
            action: TransactionAction::from_raw(get_u32(bytes, 64))?,
            scope: get_u32(bytes, 68),
        })
    }
}

/// Kernel/service-authenticated authority for one maintenance action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActionPrincipal {
    pub subject: u64,
    pub tenant: u64,
    pub domain: u32,
    pub can_recover_platform_update: bool,
    pub can_archive_platform_update: bool,
}

/// Public, path-free outcome of one accepted maintenance action.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TransactionActionStatus {
    pub request_id: u64,
    pub tenant: u64,
    pub scope: u32,
    pub domain: u32,
    pub generation: u64,
    pub transaction_id: u64,
    pub manifest_sha256: [u8; 32],
    pub recovery_required: bool,
    pub archived: bool,
}

impl TransactionActionStatus {
    pub fn encode(self) -> [u8; ACTION_RESPONSE_BYTES] {
        let mut out = [0u8; ACTION_RESPONSE_BYTES];
        put_u32(&mut out, 0, ACTION_RESPONSE_MAGIC);
        put_u16(&mut out, 4, ACTION_RESPONSE_VERSION);
        put_u16(&mut out, 6, 0);
        put_u64(&mut out, 8, self.request_id);
        put_u64(&mut out, 16, self.tenant);
        put_u32(&mut out, 24, self.scope);
        put_u32(&mut out, 28, self.domain);
        put_u64(&mut out, 32, self.generation);
        put_u64(&mut out, 40, self.transaction_id);
        out[48..80].copy_from_slice(&self.manifest_sha256);
        out[80] = u8::from(self.recovery_required);
        out[81] = u8::from(self.archived);
        out
    }

    pub fn decode(bytes: &[u8; ACTION_RESPONSE_BYTES]) -> Option<Self> {
        if get_u32(bytes, 0) != ACTION_RESPONSE_MAGIC
            || get_u16(bytes, 4) != ACTION_RESPONSE_VERSION
            || get_u16(bytes, 6) != 0
            || get_u64(bytes, 8) == 0
            || get_u64(bytes, 16) == 0
            || get_u32(bytes, 24) != SCOPE_PLATFORM
            || get_u64(bytes, 32) == 0
            || get_u64(bytes, 40) == 0
            || bytes[48..80].iter().all(|byte| *byte == 0)
            || bytes[80] > 1
            || bytes[81] > 1
            || bytes[82..].iter().any(|byte| *byte != 0)
        {
            return None;
        }
        let mut manifest_sha256 = [0u8; 32];
        manifest_sha256.copy_from_slice(&bytes[48..80]);
        Some(Self {
            request_id: get_u64(bytes, 8),
            tenant: get_u64(bytes, 16),
            scope: get_u32(bytes, 24),
            domain: get_u32(bytes, 28),
            generation: get_u64(bytes, 32),
            transaction_id: get_u64(bytes, 40),
            manifest_sha256,
            recovery_required: bytes[80] != 0,
            archived: bytes[81] != 0,
        })
    }
}

/// Stable service-level failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceError {
    InvalidRequest,
    Unauthorized,
    TenantScope,
    StaleGeneration { expected: u64, current: u64 },
    TransactionMismatch,
}

impl ServiceError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidRequest => "system.update.error.protocol",
            Self::Unauthorized => "system.update.error.unauthorized",
            Self::TenantScope => "system.update.error.tenant_scope",
            Self::StaleGeneration { .. } => "system.update.error.stale_generation",
            Self::TransactionMismatch => "system.update.error.transaction_mismatch",
        }
    }
}

/// Authorize a status request against kernel-derived caller and generation facts.
///
/// A request can select only the platform scope. It cannot name a tenant or an
/// internal object; the returned tenant is always the authenticated principal's
/// tenant. Unknown scopes fail closed rather than widening visibility.
pub fn authorize(
    request: StatusRequest,
    principal: Principal,
    current_generation: u64,
) -> Result<Authorization, ServiceError> {
    if request.request_id == 0 || request.scope != SCOPE_PLATFORM {
        return Err(if request.scope == SCOPE_PLATFORM {
            ServiceError::InvalidRequest
        } else {
            ServiceError::TenantScope
        });
    }
    if principal.subject == 0 || principal.tenant == 0 || !principal.can_query_platform_update {
        return Err(ServiceError::Unauthorized);
    }
    if request.expected_generation != 0 && request.expected_generation != current_generation {
        return Err(ServiceError::StaleGeneration {
            expected: request.expected_generation,
            current: current_generation,
        });
    }
    Ok(Authorization {
        request_id: request.request_id,
        tenant: principal.tenant,
        domain: principal.domain,
        scope: request.scope,
    })
}

/// Authorize one recovery/archive action against an authoritative transaction.
pub fn authorize_transaction_action(
    request: TransactionActionRequest,
    principal: ActionPrincipal,
    current_generation: u64,
    current_transaction: u64,
    current_manifest_sha256: [u8; 32],
) -> Result<Authorization, ServiceError> {
    if request.request_id == 0 || request.transaction_id == 0 {
        return Err(ServiceError::InvalidRequest);
    }
    if request.scope != SCOPE_PLATFORM {
        return Err(ServiceError::TenantScope);
    }
    let authorized = principal.subject != 0
        && principal.tenant != 0
        && match request.action {
            TransactionAction::Recover => principal.can_recover_platform_update,
            TransactionAction::Archive => principal.can_archive_platform_update,
        };
    if !authorized {
        return Err(ServiceError::Unauthorized);
    }
    if request.expected_generation != 0 && request.expected_generation != current_generation {
        return Err(ServiceError::StaleGeneration {
            expected: request.expected_generation,
            current: current_generation,
        });
    }
    if request.transaction_id != current_transaction
        || request.manifest_sha256 != current_manifest_sha256
    {
        return Err(ServiceError::TransactionMismatch);
    }
    Ok(Authorization {
        request_id: request.request_id,
        tenant: principal.tenant,
        domain: principal.domain,
        scope: request.scope,
    })
}

/// Versioned response envelope. The inner status record remains independently decodable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatusResponse {
    pub authorization: Authorization,
    pub status: UpdateStatus,
}

impl StatusResponse {
    pub fn encode(self) -> [u8; RESPONSE_BYTES] {
        let mut out = [0u8; RESPONSE_BYTES];
        put_u32(&mut out, 0, RESPONSE_MAGIC);
        put_u16(&mut out, 4, RESPONSE_VERSION);
        put_u16(&mut out, 6, 0);
        put_u64(&mut out, 8, self.authorization.request_id);
        put_u64(&mut out, 16, self.authorization.tenant);
        put_u32(&mut out, 24, self.authorization.scope);
        put_u32(&mut out, 28, self.authorization.domain);
        out[32..32 + STATUS_BYTES].copy_from_slice(&self.status.encode());
        out
    }

    pub fn decode(bytes: &[u8; RESPONSE_BYTES]) -> Option<Self> {
        if get_u32(bytes, 0) != RESPONSE_MAGIC
            || get_u16(bytes, 4) != RESPONSE_VERSION
            || get_u16(bytes, 6) != 0
            || get_u64(bytes, 8) == 0
            || get_u64(bytes, 16) == 0
            || get_u32(bytes, 24) != SCOPE_PLATFORM
        {
            return None;
        }
        let mut status_bytes = [0u8; STATUS_BYTES];
        status_bytes.copy_from_slice(&bytes[32..32 + STATUS_BYTES]);
        Some(Self {
            authorization: Authorization {
                request_id: get_u64(bytes, 8),
                tenant: get_u64(bytes, 16),
                scope: get_u32(bytes, 24),
                domain: get_u32(bytes, 28),
            },
            status: UpdateStatus::decode(&status_bytes)?,
        })
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
    use crate::update_status::NO_SLOT;

    fn request() -> StatusRequest {
        StatusRequest {
            request_id: 7,
            expected_generation: 0,
            scope: SCOPE_PLATFORM,
        }
    }

    fn principal() -> Principal {
        Principal {
            subject: 11,
            tenant: 3,
            domain: 1,
            can_query_platform_update: true,
        }
    }

    fn status() -> UpdateStatus {
        UpdateStatus {
            service_generation: 5,
            transaction_id: 4,
            rollback_floor: 2,
            security_epoch: 1,
            active_slot: 0,
            candidate_slot: NO_SLOT,
            active_state: 2,
            candidate_state: 0,
            active_attempts: 0,
            candidate_attempts: 0,
            terminal_stage: 0,
            active_release: 2,
            candidate_release: 0,
            data_schema_min: 1,
            data_schema_max: 1,
            caller_subject: 11,
            caller_domain: 1,
            active_digest: [0x44; 32],
            candidate_digest: [0; 32],
        }
    }

    #[test]
    fn request_and_response_round_trip_without_paths() {
        let request = request();
        assert_eq!(StatusRequest::decode(&request.encode()), Some(request));
        let admitted = authorize(request, principal(), 5).unwrap();
        let response = StatusResponse {
            authorization: admitted,
            status: status(),
        };
        assert_eq!(StatusResponse::decode(&response.encode()), Some(response));
    }

    #[test]
    fn missing_identity_tenant_injection_and_unknown_scope_fail_closed() {
        assert_eq!(
            authorize(
                request(),
                Principal {
                    subject: 0,
                    ..principal()
                },
                5
            ),
            Err(ServiceError::Unauthorized)
        );
        assert_eq!(
            authorize(
                StatusRequest {
                    scope: 9,
                    ..request()
                },
                principal(),
                5
            ),
            Err(ServiceError::TenantScope)
        );
        assert_eq!(
            authorize(
                StatusRequest {
                    expected_generation: 4,
                    ..request()
                },
                principal(),
                5
            ),
            Err(ServiceError::StaleGeneration {
                expected: 4,
                current: 5,
            })
        );
    }

    #[test]
    fn zero_request_id_and_tampered_response_are_rejected() {
        let mut bytes = request().encode();
        bytes[8..16].fill(0);
        assert_eq!(StatusRequest::decode(&bytes), None);

        let response = StatusResponse {
            authorization: authorize(request(), principal(), 5).unwrap(),
            status: status(),
        };
        let mut bytes = response.encode();
        bytes[24..28].copy_from_slice(&9u32.to_le_bytes());
        assert_eq!(StatusResponse::decode(&bytes), None);
    }

    fn action_request(action: TransactionAction) -> TransactionActionRequest {
        TransactionActionRequest {
            request_id: 17,
            expected_generation: 5,
            transaction_id: 4,
            manifest_sha256: [0x55; 32],
            action,
            scope: SCOPE_PLATFORM,
        }
    }

    fn action_principal() -> ActionPrincipal {
        ActionPrincipal {
            subject: 11,
            tenant: 3,
            domain: 1,
            can_recover_platform_update: true,
            can_archive_platform_update: true,
        }
    }

    #[test]
    fn recovery_and_archive_requests_are_path_free_and_round_trip() {
        for action in [TransactionAction::Recover, TransactionAction::Archive] {
            let request = action_request(action);
            let bytes = request.encode();
            assert_eq!(TransactionActionRequest::decode(&bytes), Some(request));
            assert!(!bytes.windows(4).any(|window| window == b"/run"));
            assert_eq!(
                authorize_transaction_action(request, action_principal(), 5, 4, [0x55; 32])
                    .unwrap(),
                Authorization {
                    request_id: 17,
                    tenant: 3,
                    domain: 1,
                    scope: SCOPE_PLATFORM,
                }
            );
        }
    }

    #[test]
    fn action_authority_scope_generation_and_transaction_binding_fail_closed() {
        let recover = action_request(TransactionAction::Recover);
        assert_eq!(
            authorize_transaction_action(
                recover,
                ActionPrincipal {
                    can_recover_platform_update: false,
                    ..action_principal()
                },
                5,
                4,
                [0x55; 32]
            ),
            Err(ServiceError::Unauthorized)
        );
        assert_eq!(
            authorize_transaction_action(
                TransactionActionRequest {
                    scope: 9,
                    ..recover
                },
                action_principal(),
                5,
                4,
                [0x55; 32]
            ),
            Err(ServiceError::TenantScope)
        );
        assert_eq!(
            authorize_transaction_action(
                TransactionActionRequest {
                    expected_generation: 3,
                    ..recover
                },
                action_principal(),
                5,
                4,
                [0x55; 32]
            ),
            Err(ServiceError::StaleGeneration {
                expected: 3,
                current: 5,
            })
        );
        assert_eq!(
            authorize_transaction_action(
                TransactionActionRequest {
                    transaction_id: 3,
                    ..recover
                },
                action_principal(),
                5,
                4,
                [0x55; 32]
            ),
            Err(ServiceError::TransactionMismatch)
        );
        assert_eq!(
            authorize_transaction_action(recover, action_principal(), 5, 4, [0x56; 32]),
            Err(ServiceError::TransactionMismatch)
        );
    }

    #[test]
    fn action_response_preserves_identity_and_rejects_tampering() {
        let status = TransactionActionStatus {
            request_id: 17,
            tenant: 3,
            scope: SCOPE_PLATFORM,
            domain: 1,
            generation: 6,
            transaction_id: 4,
            manifest_sha256: [0x55; 32],
            recovery_required: false,
            archived: true,
        };
        let bytes = status.encode();
        assert_eq!(TransactionActionStatus::decode(&bytes), Some(status));
        let mut tampered = bytes;
        tampered[24..28].copy_from_slice(&9u32.to_le_bytes());
        assert_eq!(TransactionActionStatus::decode(&tampered), None);
        let mut reserved = bytes;
        reserved[82] = 1;
        assert_eq!(TransactionActionStatus::decode(&reserved), None);
    }
}
