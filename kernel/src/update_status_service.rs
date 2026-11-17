//! Read-only service facade for the native `system update status` command.
//!
//! The JUCS command identity is resolved in userspace and reaches this module
//! through `system.update.control.get`. The service authenticates the caller,
//! reads the same dual-copy A/B control records used by lifecycle health and
//! returns a fixed, path-free record. No logical or physical path participates
//! in authorization.

use kernel_core::objtable::ObjId;
use kernel_core::update_status::{UpdateStatus, BYTES, NO_SLOT};

use crate::mm::user::copy_to_user;
use crate::syscall::table::{
    SYSTEM_ERROR_INVALID_ARGUMENT, SYSTEM_ERROR_RIGHTS_DENIED,
    SYSTEM_UPDATE_ERROR_BUFFER_TOO_SMALL, SYSTEM_UPDATE_ERROR_PROTOCOL,
    SYSTEM_UPDATE_ERROR_UNAVAILABLE,
};
use crate::syscall::{err, user_ptr_err};

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
