//! Read-only service facade for the native `system update status` command.
//!
//! The JUCS command identity is resolved in userspace and reaches this module
//! through `system.update.control.get`. The service authenticates the caller,
//! reads the same dual-copy A/B control records used by lifecycle health and
//! returns a fixed, path-free record. No logical or physical path participates
//! in authorization.

use jasper_lifecycle_model::update::UpdateStage;
use kernel_core::authz::{
    self, AccessScope, CallerFacts, Effect, Operation, Request as AuthzRequest, KERNEL_PEP_ISSUER,
};
use kernel_core::objtable::ObjId;
use kernel_core::update_audit::{
    AuditPrincipal, AuditRequest, AuditResponse, REQUEST_BYTES as AUDIT_REQUEST_BYTES,
    RESPONSE_BYTES as AUDIT_RESPONSE_BYTES,
};
use kernel_core::update_service::{
    authorize, authorize_transaction_action, ActionPrincipal, Principal, StatusRequest,
    StatusResponse, TransactionAction, TransactionActionRequest, TransactionActionStatus,
    ACTION_REQUEST_BYTES, ACTION_RESPONSE_BYTES, REQUEST_BYTES, RESPONSE_BYTES, SCOPE_PLATFORM,
};
use kernel_core::update_status::{UpdateStatus, BYTES, NO_SLOT};
use kernel_core::usi_request::Begin;

use crate::mm::user::{copy_from_user, copy_to_user};
use crate::syscall::table::{
    SYSTEM_ERROR_INVALID_ARGUMENT, SYSTEM_ERROR_RIGHTS_DENIED, SYSTEM_UPDATE_ACTION_ARCHIVE,
    SYSTEM_UPDATE_ACTION_RECOVER, SYSTEM_UPDATE_AUDIT_QUERY, SYSTEM_UPDATE_CONTROL_GET,
    SYSTEM_UPDATE_ERROR_BUFFER_TOO_SMALL, SYSTEM_UPDATE_ERROR_PROTOCOL,
    SYSTEM_UPDATE_ERROR_REQUEST_ID, SYSTEM_UPDATE_ERROR_STALE_GENERATION,
    SYSTEM_UPDATE_ERROR_TENANT_SCOPE, SYSTEM_UPDATE_ERROR_TRANSACTION_MISMATCH,
    SYSTEM_UPDATE_ERROR_UNAUTHORIZED, SYSTEM_UPDATE_ERROR_UNAVAILABLE, SYSTEM_UPDATE_STATUS_QUERY,
};
use crate::syscall::{err, user_ptr_err};

const STATUS_SERVICE_ID: u16 = 0x1101;
const RECOVERY_SERVICE_ID: u16 = 0x1102;
const ARCHIVE_SERVICE_ID: u16 = 0x1103;
const AUDIT_SERVICE_ID: u16 = 0x1104;

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
    if require_update_authority(
        pid,
        context,
        Operation::SystemUpdateStatus,
        SYSTEM_UPDATE_CONTROL_GET,
        Effect::Read,
    )
    .is_err()
    {
        return err(SYSTEM_UPDATE_ERROR_UNAUTHORIZED);
    }
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
    let record = status_from_control(pid, context, current);
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
pub fn query_v1(pid: ObjId, request_ptr: u64, output_ptr: u64, capacity: u64) -> i64 {
    if pid.raw() == 0 {
        return err(SYSTEM_ERROR_INVALID_ARGUMENT);
    }
    let context = match crate::security::require_active(pid) {
        Ok(context) => context,
        Err(_) => return err(SYSTEM_UPDATE_ERROR_UNAUTHORIZED),
    };
    if require_update_authority(
        pid,
        context,
        Operation::SystemUpdateStatus,
        SYSTEM_UPDATE_STATUS_QUERY,
        Effect::Read,
    )
    .is_err()
    {
        return err(SYSTEM_UPDATE_ERROR_UNAUTHORIZED);
    }
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
                kernel_core::update_service::ServiceError::TransactionMismatch => {
                    SYSTEM_UPDATE_ERROR_PROTOCOL
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

/// Execute the path-free platform recovery action.
///
/// Authorization is bound to the caller's update-recovery syscall capability,
/// authenticated principal, current generation, transaction and manifest
/// digest. The mechanism repairs both durable control copies but accepts no
/// caller-provided path or device selector.
pub fn recover_v1(pid: ObjId, request_ptr: u64, output_ptr: u64, capacity: u64) -> i64 {
    if pid.raw() == 0 {
        return err(SYSTEM_ERROR_INVALID_ARGUMENT);
    }
    let context = match crate::security::require_active(pid) {
        Ok(context) => context,
        Err(_) => return err(SYSTEM_UPDATE_ERROR_UNAUTHORIZED),
    };
    if require_update_authority(
        pid,
        context,
        Operation::SystemUpdateRecover,
        SYSTEM_UPDATE_ACTION_RECOVER,
        Effect::Write,
    )
    .is_err()
    {
        return err(SYSTEM_UPDATE_ERROR_UNAUTHORIZED);
    }
    let Ok(capacity) = usize::try_from(capacity) else {
        return err(SYSTEM_ERROR_INVALID_ARGUMENT);
    };
    if capacity < ACTION_RESPONSE_BYTES {
        return err(SYSTEM_UPDATE_ERROR_BUFFER_TOO_SMALL);
    }
    let mut raw_request = [0u8; ACTION_REQUEST_BYTES];
    if let Err(error) = copy_from_user(&mut raw_request, request_ptr, ACTION_REQUEST_BYTES) {
        return user_ptr_err(error);
    }
    let Some(request) = TransactionActionRequest::decode(&raw_request) else {
        return err(SYSTEM_UPDATE_ERROR_PROTOCOL);
    };
    if request.action != TransactionAction::Recover {
        return err(SYSTEM_UPDATE_ERROR_PROTOCOL);
    }
    let current = match crate::lifecycle_health::read_control_block() {
        Ok(current) => current,
        Err(error) => {
            crate::kprintln!(
                "[JSR-UPDATE-ACTION] caller={} request={} result=unavailable reason={}",
                pid.raw(),
                request.request_id,
                error.name()
            );
            return err(SYSTEM_UPDATE_ERROR_UNAVAILABLE);
        }
    };
    let tenant = principal_tenant(pid);
    let digest = transaction_digest(current);
    let authorization = match authorize_transaction_action(
        request,
        ActionPrincipal {
            subject: pid.raw(),
            tenant,
            domain: context.mac.domain.0,
            can_recover_platform_update: true,
            can_archive_platform_update: false,
        },
        current.generation(),
        current.transaction_id(),
        digest,
    ) {
        Ok(authorization) => authorization,
        Err(error) => {
            crate::kprintln!(
                "[JSR-UPDATE-ACTION] caller={} tenant={} request={} transaction={} generation={} result=reject code={}",
                pid.raw(),
                tenant,
                request.request_id,
                request.transaction_id,
                request.expected_generation,
                error.name()
            );
            return err(action_error(error));
        }
    };
    let slot = match crate::proc::begin_usi_request(pid, request.request_id, RECOVERY_SERVICE_ID) {
        Ok(Begin::New(slot)) => Some(slot),
        Ok(Begin::Retry) => None,
        Ok(Begin::Busy | Begin::Conflict | Begin::Exhausted) | Err(_) => {
            return err(SYSTEM_UPDATE_ERROR_REQUEST_ID);
        }
    };
    let repaired = match crate::lifecycle_health::recover_control_block(true) {
        Ok(repaired) => repaired,
        Err(_) => {
            if let Some(slot) = slot {
                crate::proc::abort_usi_request(pid, slot, request.request_id, RECOVERY_SERVICE_ID);
            }
            return err(SYSTEM_UPDATE_ERROR_UNAVAILABLE);
        }
    };
    if repaired.generation() != current.generation()
        || repaired.transaction_id() != current.transaction_id()
        || transaction_digest(repaired) != digest
    {
        if let Some(slot) = slot {
            crate::proc::abort_usi_request(pid, slot, request.request_id, RECOVERY_SERVICE_ID);
        }
        return err(SYSTEM_UPDATE_ERROR_STALE_GENERATION);
    }
    let response = TransactionActionStatus {
        request_id: authorization.request_id,
        tenant: authorization.tenant,
        scope: authorization.scope,
        domain: authorization.domain,
        generation: repaired.generation(),
        transaction_id: repaired.transaction_id(),
        manifest_sha256: digest,
        recovery_required: false,
        archived: false,
    };
    let bytes = response.encode();
    if TransactionActionStatus::decode(&bytes) != Some(response) {
        if let Some(slot) = slot {
            crate::proc::abort_usi_request(pid, slot, request.request_id, RECOVERY_SERVICE_ID);
        }
        return err(SYSTEM_UPDATE_ERROR_PROTOCOL);
    }
    if let Err(error) = copy_to_user(output_ptr, &bytes, capacity) {
        if let Some(slot) = slot {
            crate::proc::abort_usi_request(pid, slot, request.request_id, RECOVERY_SERVICE_ID);
        }
        return user_ptr_err(error);
    }
    if let Some(slot) = slot {
        crate::proc::complete_usi_request(pid, slot, request.request_id, RECOVERY_SERVICE_ID);
    }
    crate::kprintln!(
        "[JSR-UPDATE-ACTION] caller={} tenant={} domain={} request={} generation={} transaction={} action=recover result=ok",
        pid.raw(),
        authorization.tenant,
        authorization.domain,
        authorization.request_id,
        response.generation,
        response.transaction_id
    );
    ACTION_RESPONSE_BYTES as i64
}

/// Persist one archive receipt for the authoritative terminal transaction.
///
/// The caller selects only an action and a request identity. The kernel derives
/// the terminal outcome, transaction, manifest digest, generation and fixed
/// archive destination from the authenticated control record.
pub fn archive_v1(pid: ObjId, request_ptr: u64, output_ptr: u64, capacity: u64) -> i64 {
    if pid.raw() == 0 {
        return err(SYSTEM_ERROR_INVALID_ARGUMENT);
    }
    let context = match crate::security::require_active(pid) {
        Ok(context) => context,
        Err(_) => return err(SYSTEM_UPDATE_ERROR_UNAUTHORIZED),
    };
    if require_update_authority(
        pid,
        context,
        Operation::SystemUpdateArchive,
        SYSTEM_UPDATE_ACTION_ARCHIVE,
        Effect::Write,
    )
    .is_err()
    {
        return err(SYSTEM_UPDATE_ERROR_UNAUTHORIZED);
    }
    let Ok(capacity) = usize::try_from(capacity) else {
        return err(SYSTEM_ERROR_INVALID_ARGUMENT);
    };
    if capacity < ACTION_RESPONSE_BYTES {
        return err(SYSTEM_UPDATE_ERROR_BUFFER_TOO_SMALL);
    }
    let mut raw_request = [0u8; ACTION_REQUEST_BYTES];
    if let Err(error) = copy_from_user(&mut raw_request, request_ptr, ACTION_REQUEST_BYTES) {
        return user_ptr_err(error);
    }
    let Some(request) = TransactionActionRequest::decode(&raw_request) else {
        return err(SYSTEM_UPDATE_ERROR_PROTOCOL);
    };
    if request.action != TransactionAction::Archive {
        return err(SYSTEM_UPDATE_ERROR_PROTOCOL);
    }
    let current = match crate::lifecycle_health::read_control_block() {
        Ok(current) => current,
        Err(_) => return err(SYSTEM_UPDATE_ERROR_UNAVAILABLE),
    };
    let terminal_stage = match current.terminal() {
        jasper_lifecycle_boot::TransactionTerminal::Complete => UpdateStage::Complete,
        jasper_lifecycle_boot::TransactionTerminal::RolledBack => UpdateStage::RolledBack,
        jasper_lifecycle_boot::TransactionTerminal::None => {
            return err(SYSTEM_UPDATE_ERROR_PROTOCOL)
        }
    };
    let Some(digest) = current.transaction_digest() else {
        return err(SYSTEM_UPDATE_ERROR_PROTOCOL);
    };
    let tenant = principal_tenant(pid);
    let authorization = match authorize_transaction_action(
        request,
        ActionPrincipal {
            subject: pid.raw(),
            tenant,
            domain: context.mac.domain.0,
            can_recover_platform_update: false,
            can_archive_platform_update: true,
        },
        current.generation(),
        current.transaction_id(),
        digest,
    ) {
        Ok(authorization) => authorization,
        Err(error) => {
            crate::kprintln!(
                "[JSR-UPDATE-ARCHIVE] caller={} tenant={} request={} transaction={} generation={} result=reject code={}",
                pid.raw(),
                tenant,
                request.request_id,
                request.transaction_id,
                request.expected_generation,
                error.name()
            );
            return err(action_error(error));
        }
    };
    let slot = match crate::proc::begin_usi_request(pid, request.request_id, ARCHIVE_SERVICE_ID) {
        Ok(Begin::New(slot)) => Some(slot),
        Ok(Begin::Retry) => None,
        Ok(Begin::Busy | Begin::Conflict | Begin::Exhausted) | Err(_) => {
            return err(SYSTEM_UPDATE_ERROR_REQUEST_ID);
        }
    };
    let receipt = match crate::lifecycle_health::commit_archive_receipt(
        current.transaction_id(),
        digest,
        terminal_stage,
    ) {
        Ok(receipt) => receipt,
        Err(error) => {
            if let Some(slot) = slot {
                crate::proc::abort_usi_request(pid, slot, request.request_id, ARCHIVE_SERVICE_ID);
            }
            crate::kprintln!(
                "[JSR-UPDATE-ARCHIVE] caller={} request={} result=unavailable reason={:?}",
                pid.raw(),
                request.request_id,
                error
            );
            return err(SYSTEM_UPDATE_ERROR_UNAVAILABLE);
        }
    };
    if receipt.transaction_id() != current.transaction_id()
        || receipt.manifest_sha256() != digest
        || receipt.terminal_stage() != terminal_stage
    {
        if let Some(slot) = slot {
            crate::proc::abort_usi_request(pid, slot, request.request_id, ARCHIVE_SERVICE_ID);
        }
        return err(SYSTEM_UPDATE_ERROR_PROTOCOL);
    }
    let response = TransactionActionStatus {
        request_id: authorization.request_id,
        tenant: authorization.tenant,
        scope: authorization.scope,
        domain: authorization.domain,
        generation: current.generation(),
        transaction_id: current.transaction_id(),
        manifest_sha256: digest,
        recovery_required: false,
        archived: true,
    };
    let bytes = response.encode();
    if TransactionActionStatus::decode(&bytes) != Some(response) {
        if let Some(slot) = slot {
            crate::proc::abort_usi_request(pid, slot, request.request_id, ARCHIVE_SERVICE_ID);
        }
        return err(SYSTEM_UPDATE_ERROR_PROTOCOL);
    }
    if let Err(error) = copy_to_user(output_ptr, &bytes, capacity) {
        if let Some(slot) = slot {
            crate::proc::abort_usi_request(pid, slot, request.request_id, ARCHIVE_SERVICE_ID);
        }
        return user_ptr_err(error);
    }
    if let Some(slot) = slot {
        crate::proc::complete_usi_request(pid, slot, request.request_id, ARCHIVE_SERVICE_ID);
    }
    crate::kprintln!(
        "[JSR-UPDATE-ARCHIVE] caller={} tenant={} domain={} request={} generation={} transaction={} terminal={:?} result=ok",
        pid.raw(),
        authorization.tenant,
        authorization.domain,
        authorization.request_id,
        current.generation(),
        current.transaction_id(),
        terminal_stage
    );
    ACTION_RESPONSE_BYTES as i64
}

/// Query the current recovery-validated terminal archive receipt.
///
/// The request carries no path or caller-selected identity. A missing receipt
/// is represented explicitly; malformed or conflicting receipt copies are not
/// treated as “no history”.
pub fn audit_v1(pid: ObjId, request_ptr: u64, output_ptr: u64, capacity: u64) -> i64 {
    if pid.raw() == 0 {
        return err(SYSTEM_ERROR_INVALID_ARGUMENT);
    }
    let context = match crate::security::require_active(pid) {
        Ok(context) => context,
        Err(_) => return err(SYSTEM_UPDATE_ERROR_UNAUTHORIZED),
    };
    if require_update_authority(
        pid,
        context,
        Operation::SystemUpdateAudit,
        SYSTEM_UPDATE_AUDIT_QUERY,
        Effect::Read,
    )
    .is_err()
    {
        return err(SYSTEM_UPDATE_ERROR_UNAUTHORIZED);
    }
    let Ok(capacity) = usize::try_from(capacity) else {
        return err(SYSTEM_ERROR_INVALID_ARGUMENT);
    };
    if capacity < AUDIT_RESPONSE_BYTES {
        return err(SYSTEM_UPDATE_ERROR_BUFFER_TOO_SMALL);
    }
    let mut raw_request = [0u8; AUDIT_REQUEST_BYTES];
    if let Err(error) = copy_from_user(&mut raw_request, request_ptr, AUDIT_REQUEST_BYTES) {
        return user_ptr_err(error);
    }
    let Some(request) = AuditRequest::decode(&raw_request) else {
        return err(SYSTEM_UPDATE_ERROR_PROTOCOL);
    };
    let tenant = principal_tenant(pid);
    let principal = AuditPrincipal {
        subject: pid.raw(),
        tenant,
        domain: context.mac.domain.0,
        can_query_platform_update: true,
    };
    if principal.subject == 0 || principal.tenant == 0 {
        return err(SYSTEM_UPDATE_ERROR_UNAUTHORIZED);
    }
    let receipt = match crate::lifecycle_health::read_archive_receipt() {
        Ok(receipt) => receipt,
        Err(_) => return err(SYSTEM_UPDATE_ERROR_UNAVAILABLE),
    };
    if request.expected_archive_sequence != 0
        && receipt
            .is_none_or(|receipt| receipt.archive_sequence() != request.expected_archive_sequence)
    {
        return err(SYSTEM_UPDATE_ERROR_STALE_GENERATION);
    }
    let slot = match crate::proc::begin_usi_request(pid, request.request_id, AUDIT_SERVICE_ID) {
        Ok(Begin::New(slot)) => Some(slot),
        Ok(Begin::Retry) => None,
        Ok(Begin::Busy | Begin::Conflict | Begin::Exhausted) | Err(_) => {
            return err(SYSTEM_UPDATE_ERROR_REQUEST_ID);
        }
    };
    let response = match receipt {
        Some(receipt) => AuditResponse {
            request_id: request.request_id,
            tenant: principal.tenant,
            scope: SCOPE_PLATFORM,
            domain: principal.domain,
            available: true,
            archive_sequence: receipt.archive_sequence(),
            transaction_id: receipt.transaction_id(),
            manifest_sha256: receipt.manifest_sha256(),
            previous_sha256: receipt.previous_sha256(),
            terminal_stage: receipt.terminal_stage() as u8,
        },
        None => AuditResponse::empty(request.request_id, principal),
    };
    let bytes = response.encode();
    if AuditResponse::decode(&bytes) != Some(response) {
        if let Some(slot) = slot {
            crate::proc::abort_usi_request(pid, slot, request.request_id, AUDIT_SERVICE_ID);
        }
        return err(SYSTEM_UPDATE_ERROR_PROTOCOL);
    }
    if let Err(error) = copy_to_user(output_ptr, &bytes, capacity) {
        if let Some(slot) = slot {
            crate::proc::abort_usi_request(pid, slot, request.request_id, AUDIT_SERVICE_ID);
        }
        return user_ptr_err(error);
    }
    if let Some(slot) = slot {
        crate::proc::complete_usi_request(pid, slot, request.request_id, AUDIT_SERVICE_ID);
    }
    crate::kprintln!(
        "[JSR-UPDATE-AUDIT] caller={} tenant={} domain={} request={} available={} sequence={} transaction={} result=ok",
        pid.raw(),
        response.tenant,
        response.domain,
        response.request_id,
        response.available,
        response.archive_sequence,
        response.transaction_id
    );
    AUDIT_RESPONSE_BYTES as i64
}

fn transaction_digest(current: jasper_lifecycle_boot::ControlBlock) -> [u8; 32] {
    current
        .transaction_digest()
        .unwrap_or_else(|| current.slot(current.active_slot()).digest())
}

/// Project the caller's existing identity, tenant, domain and SyscallSet
/// authority into the shared authorization decision record.
///
/// This adapter does not create a second permission table. The active process
/// context and its admitted SyscallSet remain authoritative; policy facts are
/// captured at the same decision point. A complete system-wide revocation
/// source is not integrated yet, so the decision records that fact explicitly
/// instead of aliasing an object generation. A denied or incomplete snapshot
/// never reaches the lifecycle store.
fn require_update_authority(
    pid: ObjId,
    context: kernel_core::security::SecurityContext,
    operation: Operation,
    required_syscall: u32,
    effect: Effect,
) -> Result<authz::Decision, ()> {
    let syscalls =
        crate::kobj::with(|table| crate::proc::syscalls_in(table, pid)).map_err(|_| ())?;
    let policy_epoch = crate::security::policy_epoch();
    let decision = authz::authorize(
        CallerFacts {
            context,
            tenant: principal_tenant(pid),
            scope: AccessScope::Platform,
            syscalls,
            policy_epoch,
            // No complete system-wide revocation source is integrated yet.
            // Keep that fact explicit instead of aliasing an object generation.
            revocation_generation: None,
            // The P0 profile has no trusted wall clock. No expiring update
            // lease is accepted until that fact exists.
            now: 0,
            clock_trusted: false,
        },
        AuthzRequest {
            issuer: KERNEL_PEP_ISSUER,
            operation,
            scope: AccessScope::Platform,
            required_syscall,
            effect,
            not_before: 0,
            expires_at: None,
            delegation_depth: 0,
            max_delegation_depth: authz::MAX_DELEGATION_DEPTH,
            required_policy_epoch: policy_epoch,
            required_revocation_generation: None,
        },
    );
    let (
        version,
        issuer,
        subject,
        executor_generation,
        tenant,
        domain,
        operation_name,
        scope,
        effect_name,
        policy,
        revocation,
        allowed,
        reason,
    ) = authz::diagnostic_fields(decision);
    crate::kprintln!(
        "[JSR-AUTHZ] version={} issuer={} subject={} executor_generation={} tenant={} domain={} operation={} scope={} effect={} policy={} revocation={:?} decision={} reason={}",
        version,
        issuer,
        subject,
        executor_generation,
        tenant,
        domain,
        operation_name,
        scope,
        effect_name,
        policy,
        revocation,
        allowed,
        reason
    );
    if decision.admitted() {
        Ok(decision)
    } else {
        Err(())
    }
}

fn action_error(error: kernel_core::update_service::ServiceError) -> u32 {
    match error {
        kernel_core::update_service::ServiceError::InvalidRequest => SYSTEM_UPDATE_ERROR_PROTOCOL,
        kernel_core::update_service::ServiceError::TransactionMismatch => {
            SYSTEM_UPDATE_ERROR_TRANSACTION_MISMATCH
        }
        kernel_core::update_service::ServiceError::Unauthorized => SYSTEM_UPDATE_ERROR_UNAUTHORIZED,
        kernel_core::update_service::ServiceError::TenantScope => SYSTEM_UPDATE_ERROR_TENANT_SCOPE,
        kernel_core::update_service::ServiceError::StaleGeneration { .. } => {
            SYSTEM_UPDATE_ERROR_STALE_GENERATION
        }
    }
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
    let terminal_stage = current.terminal() as u8;
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
    let transaction_digest = if terminal_stage == 0 {
        candidate_digest
    } else {
        current.transaction_digest().unwrap_or([0; 32])
    };
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
        terminal_stage,
        active_release: active.release(),
        candidate_release,
        data_schema_min: schema.0,
        data_schema_max: schema.1,
        caller_subject: pid.raw(),
        caller_domain: context.mac.domain.0,
        active_digest: active.digest(),
        candidate_digest: transaction_digest,
    }
}
