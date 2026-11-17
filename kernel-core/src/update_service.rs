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

/// Stable service-level failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceError {
    InvalidRequest,
    Unauthorized,
    TenantScope,
    StaleGeneration { expected: u64, current: u64 },
}

impl ServiceError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidRequest => "system.update.error.protocol",
            Self::Unauthorized => "system.update.error.unauthorized",
            Self::TenantScope => "system.update.error.tenant_scope",
            Self::StaleGeneration { .. } => "system.update.error.stale_generation",
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
            expected: current_generation,
            current: request.expected_generation,
        });
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
                expected: 5,
                current: 4,
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
}
