//! Live LC-1 diagnostic service behind `system.diagnostic.query`.
//!
//! This module owns a bounded in-kernel diagnostic store and serializes the
//! existing versioned request / response contract into user memory. The
//! caller is an ordinary user process; no path or component name participates
//! in authorization.

use alloc::vec;

use jasper_lifecycle_model::diagnostic_usi::{
    ContractService, EVENT_BYTES, MAX_PAGE_EVENTS, REQUEST_BYTES, RESPONSE_HEADER_BYTES,
};
use jasper_lifecycle_model::diagnostics::{
    ClockQuality, DiagnosticAccess, DiagnosticAuthority, DiagnosticIo, DiagnosticIoError,
    DiagnosticService, EventInput, EventKind, PayloadKind, PrivacyClass, RecoveryAction,
    Severity,
};
use spin::Mutex;

use crate::mm::user::{copy_from_user, copy_to_user};
use crate::syscall::table::{
    SYSTEM_ERROR_INVALID_ARGUMENT, SYSTEM_ERROR_UNSUPPORTED,
    SYSTEM_USI_ERROR_BUFFER_TOO_SMALL, SYSTEM_USI_ERROR_SCHEMA,
};
use crate::syscall::{err, user_ptr_err};

// JASPER-HARDCODE-REVIEW: issue=21 source=diagnostic-usi-v1-contract reason=response-size-is-derived-from-fixed-wire-record-width-and-max-page
const MAX_RESPONSE_BYTES: usize = RESPONSE_HEADER_BYTES + MAX_PAGE_EVENTS * EVENT_BYTES; // JASPER-HARDCODE-REVIEW: issue=21 source=diagnostic-usi-v1-contract reason=response-size-derived-from-versioned-record-width

struct RamDisk {
    bytes: alloc::vec::Vec<u8>,
}

impl RamDisk {
    fn new(capacity: usize) -> Self {
        Self {
            bytes: vec![0; capacity],
        }
    }
}

impl DiagnosticIo for RamDisk {
    fn capacity(&self) -> usize {
        self.bytes.len()
    }

    fn read(&mut self, offset: usize, out: &mut [u8]) -> Result<(), DiagnosticIoError> {
        let end = offset
            .checked_add(out.len())
            .ok_or(DiagnosticIoError::Read)?;
        out.copy_from_slice(
            self.bytes
                .get(offset..end)
                .ok_or(DiagnosticIoError::Read)?,
        );
        Ok(())
    }

    fn write(&mut self, offset: usize, input: &[u8]) -> Result<(), DiagnosticIoError> {
        let end = offset
            .checked_add(input.len())
            .ok_or(DiagnosticIoError::Write)?;
        self.bytes
            .get_mut(offset..end)
            .ok_or(DiagnosticIoError::Write)?
            .copy_from_slice(input);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), DiagnosticIoError> {
        Ok(())
    }
}

struct KernelAuthority;

impl DiagnosticAuthority for KernelAuthority {
    fn access(&self, subject: u64) -> Option<DiagnosticAccess> {
        (subject != 0).then_some(DiagnosticAccess {
            can_collect: true,
            can_query: true,
            privacy_ceiling: PrivacyClass::Internal,
            max_page: MAX_PAGE_EVENTS,
        })
    }
}

type Service = ContractService<RamDisk, KernelAuthority>;

static SERVICE: Mutex<Option<Service>> = Mutex::new(None);

fn boot_event() -> EventInput<'static> {
    EventInput {
        kind: EventKind::UpdateBoot,
        severity: Severity::Info,
        privacy: PrivacyClass::Internal,
        clock_quality: ClockQuality::Unknown,
        observed_at: 0,
        causes: &[],
        component: "system.diagnostic",
        component_version: 1,
        transaction_id: 1,
        boot_id: 1,
        platform_profile: [0x33; 32],
        resource_pressure: [0; 4],
        recovery: RecoveryAction::None,
        payload_kind: PayloadKind::None,
        payload_reference: &[],
        payload_digest: [0; 32],
        redacted: true,
        correlation: None,
    }
}

fn initialize(service: &mut Option<Service>) -> bool {
    if service.is_some() {
        return true;
    }
    let Ok(capacity) = usize::try_from(crate::mm::heap::limit() / 1024) else {
        return false;
    };
    if capacity == 0 {
        return false;
    }
    let Ok(mut diagnostics) = DiagnosticService::format(RamDisk::new(capacity), KernelAuthority)
    else {
        return false;
    };
    if diagnostics.collect(1, boot_event()).is_err() {
        return false;
    }
    *service = Some(ContractService::new(diagnostics));
    true
}

/// Query or status operation. `subject` is the authenticated numeric process
/// identity; the syscall dispatcher has already checked the operation grant.
pub fn query(subject: u64, request_ptr: u64, output_ptr: u64, capacity: u64) -> i64 {
    if subject == 0 {
        return err(SYSTEM_ERROR_INVALID_ARGUMENT);
    }
    let Ok(capacity) = usize::try_from(capacity) else {
        return err(SYSTEM_ERROR_INVALID_ARGUMENT);
    };
    if capacity < MAX_RESPONSE_BYTES {
        return err(SYSTEM_USI_ERROR_BUFFER_TOO_SMALL);
    }
    let mut request = [0u8; REQUEST_BYTES];
    if let Err(error) = copy_from_user(&mut request, request_ptr, REQUEST_BYTES) {
        return user_ptr_err(error);
    }
    let now_ns = crate::hrtime::now().unwrap_or(0);
    let mut output = [0u8; MAX_RESPONSE_BYTES];
    let len = {
        let mut service = SERVICE.lock();
        if !initialize(&mut service) {
            return err(SYSTEM_ERROR_UNSUPPORTED);
        }
        match service
            .as_ref()
            .and_then(|service| {
                service
                    .handle_encoded::<MAX_PAGE_EVENTS>(
                        subject,
                        &request,
                        now_ns,
                        false,
                        &mut output,
                    )
                    .ok()
            }) {
            Some(len) => len,
            None => return err(SYSTEM_USI_ERROR_SCHEMA),
        }
    };
    if let Err(error) = copy_to_user(output_ptr, &output[..len], capacity) {
        return user_ptr_err(error);
    }
    len as i64
}
