//! Read-only service facade for the native `system update status` command.
//!
//! The JUCS command identity is resolved in userspace and reaches this module
//! through `system.update.control.get`. The service authenticates the caller,
//! reads the same dual-copy A/B control records used by lifecycle health and
//! returns a fixed, path-free record. No logical or physical path participates
//! in authorization.

use kernel_core::objtable::ObjId;
use kernel_core::update_service::{
    authorize, Principal, StatusRequest, StatusResponse, REQUEST_BYTES, RESPONSE_BYTES,
    SCOPE_PLATFORM,
};
use kernel_core::update_status::{UpdateStatus, BYTES, NO_SLOT};
use kernel_core::usi_request::Begin;

use crate::mm::user::{copy_from_user, copy_to_user};
use crate::syscall::table::{
    SYSTEM_ERROR_INVALID_ARGUMENT, SYSTEM_ERROR_RIGHTS_DENIED,
    SYSTEM_UPDATE_ERROR_BUFFER_TOO_SMALL, SYSTEM_UPDATE_ERROR_PROTOCOL,
    SYSTEM_UPDATE_ERROR_REQUEST_ID, SYSTEM_UPDATE_ERROR_STALE_GENERATION,
    SYSTEM_UPDATE_ERROR_TENANT_SCOPE, SYSTEM_UPDATE_ERROR_UNAUTHORIZED,
    SYSTEM_UPDATE_ERROR_UNAVAILABLE,
};
use crate::syscall::{err, user_ptr_err};

const STATUS_SERVICE_ID: u16 = 0x1101;

/// Query the authoritative update control state for one authenticated process.
pub fn query(pid: ObjId, output_ptr: u64, capacity: u64) -> i64 {
    let frames_before = crate::mm::frame::free_frames();
    if pid.raw() == 0 {
        return err(SYSTEM_ERROR_INVALID_ARGUMENT);
    }
    let context = match crate::security::require_active(pid) {
        Ok(context) => context,
        Err(_) => return err(SYSTEM_ERROR_RIGHTS_DENIED),
    };
    let Ok(capacity) = usize::try_from(capacity) else {
        return err(SYSTEM_ERROR_INVALID_ARGUMENT);
    };
    if capacity < BYTES {
        return err(SYSTEM_UPDATE_ERROR_BUFFER_TOO_SMALL);
    }
    let current = match crate::lifecycle_health::read_control_block() {
        Ok(current) => current,
        Err(error) => {
            crate::kprintln!(
                "[JSR-UPDATE-STATUS] caller={} domain={} result=unavailable reason={}",
                pid.raw(),
                context.mac.domain.0,
                error.name()
            );
            return err(SYSTEM_UPDATE_ERROR_UNAVAILABLE);
        }
    };
    let active_slot = current.active_slot();
    let active = current.slot(active_slot);
    let candidate = current.candidate();
    let (candidate_slot, candidate_state, candidate_attempts, candidate_release, candidate_digest) =
        candidate
            .map(|(slot, record)| {
                (
                    slot as u8,
                    record.state() as u8,
                    record.attempts(),
                    record.release(),
                    record.digest(),
                )
            })
            .unwrap_or((NO_SLOT, 0, 0, 0, [0; 32]));
    let schema = active.data_schema_range();
    let record = UpdateStatus {
        service_generation: current.generation(),
        transaction_id: current.transaction_id(),
        rollback_floor: current.rollback_floor(),
        security_epoch: current.security_epoch(),
        active_slot: active_slot as u8,
        candidate_slot,
        active_state: active.state() as u8,
        candidate_state,
        active_attempts: active.attempts(),
        candidate_attempts,
        active_release: active.release(),
        candidate_release,
        data_schema_min: schema.0,
        data_schema_max: schema.1,
        caller_subject: pid.raw(),
        caller_domain: context.mac.domain.0,
        active_digest: active.digest(),
        candidate_digest,
    };
    let bytes = record.encode();
    if UpdateStatus::decode(&bytes) != Some(record) {
        return err(SYSTEM_UPDATE_ERROR_PROTOCOL);
    }
    if let Err(error) = copy_to_user(output_ptr, &bytes, capacity) {
        return user_ptr_err(error);
    }
    let frames_after = crate::mm::frame::free_frames();
    crate::kprintln!(
        "[JSR-UPDATE-STATUS] caller={} domain={} generation={} transaction={} active={} candidate={} bytes={} frames_before={} frames_after={} result=ok",
        pid.raw(),
        context.mac.domain.0,
        record.service_generation,
        record.transaction_id,
        record.active_slot,
        record.candidate_slot,
        BYTES,
        frames_before,
        frames_after
    );
    BYTES as i64
}

/// Versioned status query used by the native JUCS client.
///
/// The request cannot select a tenant or supply a path. The kernel derives the
/// authenticated subject/tenant, enforces platform scope and optional expected
/// generation, then returns the same status record inside a request-bound
/// response envelope.
pub fn query_v1(
    pid: ObjId,
    request_ptr: u64,
    output_ptr: u64,
    capacity: u64,
) -> i64 {
    if pid.raw() == 0 {
        return err(SYSTEM_ERROR_INVALID_ARGUMENT);
    }
    let context = match crate::security::require_active(pid) {
        Ok(context) => context,
        Err(_) => return err(SYSTEM_UPDATE_ERROR_UNAUTHORIZED),
    };
    let Ok(capacity) = usize::try_from(capacity) else {
        return err(SYSTEM_ERROR_INVALID_ARGUMENT);
    };
    if capacity < RESPONSE_BYTES {
        return err(SYSTEM_UPDATE_ERROR_BUFFER_TOO_SMALL);
    }
    let mut raw_request = [0u8; REQUEST_BYTES];
    if let Err(error) = copy_from_user(&mut raw_request, request_ptr, REQUEST_BYTES) {
        return user_ptr_err(error);
    }
    let Some(request) = StatusRequest::decode(&raw_request) else {
        return err(SYSTEM_UPDATE_ERROR_PROTOCOL);
    };
    let current = match crate::lifecycle_health::read_control_block() {
        Ok(current) => current,
        Err(error) => {
            crate::kprintln!(
                "[JSR-UPDATE-STATUS-V1] caller={} tenant={} request={} result=unavailable reason={}",
                pid.raw(),
                principal_tenant(pid),
                request.request_id,
                error.name()
            );
            return err(SYSTEM_UPDATE_ERROR_UNAVAILABLE);
        }
    };
    let tenant = principal_tenant(pid);
    let principal = Principal {
        subject: pid.raw(),
        tenant,
        domain: context.mac.domain.0,
        can_query_platform_update: true,
    };
    let authorization = match authorize(request, principal, current.generation()) {
        Ok(authorization) => authorization,
        Err(error) => {
            let code = match error {
                kernel_core::update_service::ServiceError::InvalidRequest => {
                    SYSTEM_UPDATE_ERROR_PROTOCOL
                }
                kernel_core::update_service::ServiceError::Unauthorized => {
                    SYSTEM_UPDATE_ERROR_UNAUTHORIZED
                }
                kernel_core::update_service::ServiceError::TenantScope => {
                    SYSTEM_UPDATE_ERROR_TENANT_SCOPE
                }
                kernel_core::update_service::ServiceError::StaleGeneration { .. } => {
                    SYSTEM_UPDATE_ERROR_STALE_GENERATION
                }
            };
            crate::kprintln!(
                "[JSR-UPDATE-STATUS-V1] caller={} tenant={} request={} expected={} current={} result=reject code={}",
                pid.raw(),
                tenant,
                request.request_id,
                request.expected_generation,
                current.generation(),
                error.name()
            );
            return err(code);
        }
    };
    let slot = match crate::proc::begin_usi_request(pid, request.request_id, STATUS_SERVICE_ID) {
        Ok(Begin::New(slot)) => Some(slot),
        Ok(Begin::Retry) => None,
        Ok(Begin::Busy | Begin::Conflict | Begin::Exhausted) | Err(_) => {
            return err(SYSTEM_UPDATE_ERROR_REQUEST_ID);
        }
    };
    let status = status_from_control(pid, context, current);
    let response = StatusResponse {
        authorization,
        status,
    };
    let bytes = response.encode();
    if StatusResponse::decode(&bytes) != Some(response) {
        if let Some(slot) = slot {
            crate::proc::abort_usi_request(pid, slot, request.request_id, STATUS_SERVICE_ID);
        }
        return err(SYSTEM_UPDATE_ERROR_PROTOCOL);
    }
    if let Err(error) = copy_to_user(output_ptr, &bytes, capacity) {
        if let Some(slot) = slot {
            crate::proc::abort_usi_request(pid, slot, request.request_id, STATUS_SERVICE_ID);
        }
        return user_ptr_err(error);
    }
    if let Some(slot) = slot {
        crate::proc::complete_usi_request(pid, slot, request.request_id, STATUS_SERVICE_ID);
    }
    crate::kprintln!(
        "[JSR-UPDATE-STATUS-V1] caller={} tenant={} domain={} request={} generation={} scope={} bytes={} result=ok",
        pid.raw(),
        authorization.tenant,
        authorization.domain,
        authorization.request_id,
        response.status.service_generation,
        SCOPE_PLATFORM,
        RESPONSE_BYTES
    );
    RESPONSE_BYTES as i64
}

fn principal_tenant(pid: ObjId) -> u64 {
    if let Some(application) = crate::security::process_application(pid) {
        if application.stable_id != 0 {
            return application.stable_id;
        }
    }
    crate::proc::workload_domain(pid)
        .map(|domain| u64::from(domain.id) + 1)
        .unwrap_or(1)
}

fn status_from_control(
    pid: ObjId,
    context: kernel_core::security::SecurityContext,
    current: jasper_lifecycle_boot::ControlBlock,
) -> UpdateStatus {
    let active_slot = current.active_slot();
    let active = current.slot(active_slot);
    let candidate = current.candidate();
    let (candidate_slot, candidate_state, candidate_attempts, candidate_release, candidate_digest) =
        candidate
            .map(|(slot, record)| {
                (
                    slot as u8,
                    record.state() as u8,
                    record.attempts(),
                    record.release(),
                    record.digest(),
                )
            })
            .unwrap_or((NO_SLOT, 0, 0, 0, [0; 32]));
    let schema = active.data_schema_range();
    UpdateStatus {
        service_generation: current.generation(),
        transaction_id: current.transaction_id(),
        rollback_floor: current.rollback_floor(),
        security_epoch: current.security_epoch(),
        active_slot: active_slot as u8,
        candidate_slot,
        active_state: active.state() as u8,
        candidate_state,
        active_attempts: active.attempts(),
        candidate_attempts,
        active_release: active.release(),
        candidate_release,
        data_schema_min: schema.0,
        data_schema_max: schema.1,
        caller_subject: pid.raw(),
        caller_domain: context.mac.domain.0,
        active_digest: active.digest(),
        candidate_digest,
    }
}
