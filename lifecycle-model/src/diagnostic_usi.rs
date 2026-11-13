//! Candidate versioned contract between an authenticated USI adapter and the
//! LC-1 diagnostic service.
//!
//! This module deliberately does not register a `system.*` operation. The
//! adapter supplies the authenticated subject out of band, while the request
//! carries only bounded query policy and an expected authority generation.

use crate::diagnostics::{
    encode_event, DiagnosticAuthority, DiagnosticIo, DiagnosticQueryRequest, DiagnosticService,
    DiagnosticServiceError, EventKind, PrivacyClass, Severity, PERSISTED_EVENT_BYTES,
};

/// Candidate diagnostic wire-contract magic (`JLD1` little-endian).
pub const MAGIC: u32 = u32::from_le_bytes(*b"JLD1");
/// Candidate diagnostic wire-contract version.
pub const VERSION: u16 = 1;
/// Fixed request size.
pub const REQUEST_BYTES: usize = 64;
/// Fixed response-header size.
pub const RESPONSE_HEADER_BYTES: usize = 80;
/// One event record reuses the existing durable diagnostic schema.
pub const EVENT_BYTES: usize = PERSISTED_EVENT_BYTES;
/// Maximum events in one response.
pub const MAX_PAGE_EVENTS: usize = 8;
/// Event-kind wire value meaning no filter.
pub const ANY_EVENT_KIND: u8 = 0xff;

const REQUEST_FLAG_CANCELABLE: u8 = 1;

/// Wire operations in the candidate contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Operation {
    /// Query one bounded page.
    Query = 1,
    /// Query payload-free collector status.
    Status = 2,
}

/// Semantic response status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum ResponseStatus {
    /// Request completed.
    Ok = 0,
    /// Subject was absent, revoked or lacked query authority.
    Unauthorized = 1,
    /// Absolute deadline elapsed before dispatch.
    TimedOut = 2,
    /// A cancelable request was cancelled before dispatch.
    Cancelled = 3,
    /// Expected policy generation is stale or does not match.
    StaleGeneration = 4,
    /// Durable diagnostic storage could not serve the request.
    Unavailable = 5,
}

/// Strict request parser/encoder failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContractError {
    /// Magic, version, operation, enum, reserved byte or field range is invalid.
    Malformed,
    /// The output buffer cannot hold the complete response.
    BufferTooSmall,
}

/// Candidate bounded diagnostic request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryRequest {
    /// Request identity used by the USI idempotency ledger.
    pub request_id: u64,
    /// Policy generation observed by the client; zero requests the current one.
    pub expected_generation: u64,
    /// Absolute monotonic deadline; zero means no timeout.
    pub deadline_ns: u64,
    /// Stable event-ID resume cursor.
    pub after_id: u64,
    /// Operation.
    pub operation: Operation,
    /// Optional event-kind filter.
    pub kind: Option<EventKind>,
    /// Minimum event severity.
    pub minimum_severity: Severity,
    /// Caller-requested privacy ceiling.
    pub privacy_ceiling: PrivacyClass,
    /// Requested page size, already bounded by `MAX_PAGE_EVENTS`.
    pub limit: u16,
    /// Whether cancellation may be observed before dispatch.
    pub cancelable: bool,
}

impl QueryRequest {
    /// Encodes one strict 64-byte request.
    pub fn encode(self) -> Result<[u8; REQUEST_BYTES], ContractError> {
        if self.request_id == 0
            || self.limit > MAX_PAGE_EVENTS as u16
            || (self.operation == Operation::Query && self.limit == 0)
            || (self.operation == Operation::Status
                && (self.limit != 0
                    || self.after_id != 0
                    || self.kind.is_some()
                    || self.minimum_severity != Severity::Info))
        {
            return Err(ContractError::Malformed);
        }
        let mut out = [0u8; REQUEST_BYTES];
        put_u32(&mut out, 0, MAGIC);
        put_u16(&mut out, 4, VERSION);
        put_u16(&mut out, 6, self.operation as u16);
        put_u64(&mut out, 8, self.request_id);
        put_u64(&mut out, 16, self.expected_generation);
        put_u64(&mut out, 24, self.deadline_ns);
        put_u64(&mut out, 32, self.after_id);
        out[40] = self.kind.map_or(ANY_EVENT_KIND, event_kind_raw);
        out[41] = self.minimum_severity as u8;
        out[42] = self.privacy_ceiling as u8;
        out[43] = u8::from(self.cancelable);
        put_u16(&mut out, 44, self.limit);
        Ok(out)
    }

    /// Decodes one strict 64-byte request.
    pub fn decode(bytes: &[u8; REQUEST_BYTES]) -> Result<Self, ContractError> {
        if get_u32(bytes, 0) != MAGIC
            || get_u16(bytes, 4) != VERSION
            || bytes[46..].iter().any(|byte| *byte != 0)
        {
            return Err(ContractError::Malformed);
        }
        let operation = match get_u16(bytes, 6) {
            1 => Operation::Query,
            2 => Operation::Status,
            _ => return Err(ContractError::Malformed),
        };
        let kind = match bytes[40] {
            ANY_EVENT_KIND => None,
            value => Some(get_event_kind(value).ok_or(ContractError::Malformed)?),
        };
        let minimum_severity = get_severity(bytes[41]).ok_or(ContractError::Malformed)?;
        let privacy_ceiling = get_privacy(bytes[42]).ok_or(ContractError::Malformed)?;
        if bytes[43] & !REQUEST_FLAG_CANCELABLE != 0 {
            return Err(ContractError::Malformed);
        }
        let request = Self {
            request_id: get_u64(bytes, 8),
            expected_generation: get_u64(bytes, 16),
            deadline_ns: get_u64(bytes, 24),
            after_id: get_u64(bytes, 32),
            operation,
            kind,
            minimum_severity,
            privacy_ceiling,
            limit: get_u16(bytes, 44),
            cancelable: bytes[43] & REQUEST_FLAG_CANCELABLE != 0,
        };
        // Reuse encoder validation so decode has exactly the same field rules.
        let _ = request.encode()?;
        Ok(request)
    }
}

/// Candidate response header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResponseHeader {
    /// Request identity.
    pub request_id: u64,
    /// Operation answered.
    pub operation: Operation,
    /// Semantic result.
    pub status: ResponseStatus,
    /// Current policy generation.
    pub generation: u64,
    /// Stable cursor for the next page.
    pub next_cursor: u64,
    /// Number of event records following the header.
    pub records: u16,
    /// Collector sequence.
    pub sequence: u64,
    /// Accepted-event count.
    pub accepted: u64,
    /// Capacity-dropped count.
    pub capacity_dropped: u64,
}

impl ResponseHeader {
    fn encode(self) -> [u8; RESPONSE_HEADER_BYTES] {
        let mut out = [0u8; RESPONSE_HEADER_BYTES];
        put_u32(&mut out, 0, MAGIC);
        put_u16(&mut out, 4, VERSION);
        put_u16(&mut out, 6, self.operation as u16);
        put_u64(&mut out, 8, self.request_id);
        put_u64(&mut out, 16, self.generation);
        put_u64(&mut out, 24, self.next_cursor);
        put_u16(&mut out, 32, self.records);
        put_u16(&mut out, 34, self.status as u16);
        put_u64(&mut out, 40, self.accepted);
        put_u64(&mut out, 48, self.capacity_dropped);
        put_u64(&mut out, 56, self.sequence);
        out
    }

    /// Decodes and strictly validates one fixed-width response header.
    pub fn decode(bytes: &[u8; RESPONSE_HEADER_BYTES]) -> Result<Self, ContractError> {
        if get_u32(bytes, 0) != MAGIC
            || get_u16(bytes, 4) != VERSION
            || bytes[36..40].iter().any(|byte| *byte != 0)
            || bytes[64..80].iter().any(|byte| *byte != 0)
        {
            return Err(ContractError::Malformed);
        }
        let operation = match get_u16(bytes, 6) {
            1 => Operation::Query,
            2 => Operation::Status,
            _ => return Err(ContractError::Malformed),
        };
        let status = match get_u16(bytes, 34) {
            0 => ResponseStatus::Ok,
            1 => ResponseStatus::Unauthorized,
            2 => ResponseStatus::TimedOut,
            3 => ResponseStatus::Cancelled,
            4 => ResponseStatus::StaleGeneration,
            5 => ResponseStatus::Unavailable,
            _ => return Err(ContractError::Malformed),
        };
        let records = get_u16(bytes, 32);
        if records > MAX_PAGE_EVENTS as u16 {
            return Err(ContractError::Malformed);
        }
        Ok(Self {
            request_id: get_u64(bytes, 8),
            operation,
            status,
            generation: get_u64(bytes, 16),
            next_cursor: get_u64(bytes, 24),
            records,
            accepted: get_u64(bytes, 40),
            capacity_dropped: get_u64(bytes, 48),
            sequence: get_u64(bytes, 56),
        })
    }
}

/// Authority-gated adapter that serializes LC-1 results into the candidate
/// USI contract. Authentication remains an out-of-band adapter responsibility.
pub struct ContractService<D: DiagnosticIo, A: DiagnosticAuthority> {
    service: DiagnosticService<D, A>,
}

impl<D: DiagnosticIo, A: DiagnosticAuthority> ContractService<D, A> {
    /// Wraps an existing diagnostic service.
    pub const fn new(service: DiagnosticService<D, A>) -> Self {
        Self { service }
    }

    /// Handles one already-decoded request.
    ///
    /// `cancelled` is observed at the dispatch boundary. Query execution is
    /// bounded and synchronous, so it does not claim asynchronous cancellation.
    pub fn handle<const N: usize>(
        &self,
        subject: u64,
        request: QueryRequest,
        now_ns: u64,
        cancelled: bool,
        out: &mut [u8],
    ) -> Result<usize, ContractError> {
        if N == 0 || N > MAX_PAGE_EVENTS || out.len() < RESPONSE_HEADER_BYTES {
            return Err(ContractError::BufferTooSmall);
        }
        let Some(generation) = self.service.authority_generation(subject) else {
            return self.write_error(request, ResponseStatus::Unauthorized, 0, out);
        };
        if request.expected_generation != 0 && request.expected_generation != generation {
            return self.write_error(request, ResponseStatus::StaleGeneration, generation, out);
        }
        if request.deadline_ns != 0 && now_ns >= request.deadline_ns {
            return self.write_error(request, ResponseStatus::TimedOut, generation, out);
        }
        if request.cancelable && cancelled {
            return self.write_error(request, ResponseStatus::Cancelled, generation, out);
        }
        if request.operation == Operation::Status {
            let status = match self.service.status(subject) {
                Ok(status) => status,
                Err(DiagnosticServiceError::Unauthorized) => {
                    return self.write_error(
                        request,
                        ResponseStatus::Unauthorized,
                        generation,
                        out,
                    );
                }
                Err(DiagnosticServiceError::Collect(_)) => {
                    return self.write_error(request, ResponseStatus::Unavailable, generation, out);
                }
            };
            return self.write_success(request, generation, request.after_id, status, &[], out);
        }

        let query = DiagnosticQueryRequest {
            kind: request.kind,
            minimum_severity: request.minimum_severity,
            privacy_ceiling: request.privacy_ceiling,
            after_id: request.after_id,
            limit: usize::from(request.limit),
        };
        let (page, cursor, status) = match self.service.query_page::<N>(subject, query) {
            Ok(result) => result,
            Err(DiagnosticServiceError::Unauthorized) => {
                return self.write_error(request, ResponseStatus::Unauthorized, generation, out);
            }
            Err(DiagnosticServiceError::Collect(_)) => {
                return self.write_error(request, ResponseStatus::Unavailable, generation, out);
            }
        };
        let mut events = [[0u8; EVENT_BYTES]; MAX_PAGE_EVENTS];
        for (index, target) in events.iter_mut().take(page.len()).enumerate() {
            let event = page.get(index).ok_or(ContractError::Malformed)?;
            encode_event(event, target);
        }
        self.write_success(
            request,
            generation,
            cursor,
            status,
            &events[..page.len()],
            out,
        )
    }

    /// Decodes and handles one fixed-width request.
    pub fn handle_encoded<const N: usize>(
        &self,
        subject: u64,
        bytes: &[u8; REQUEST_BYTES],
        now_ns: u64,
        cancelled: bool,
        out: &mut [u8],
    ) -> Result<usize, ContractError> {
        self.handle::<N>(
            subject,
            QueryRequest::decode(bytes)?,
            now_ns,
            cancelled,
            out,
        )
    }

    fn write_error(
        &self,
        request: QueryRequest,
        status: ResponseStatus,
        generation: u64,
        out: &mut [u8],
    ) -> Result<usize, ContractError> {
        out[..RESPONSE_HEADER_BYTES].copy_from_slice(
            &ResponseHeader {
                request_id: request.request_id,
                operation: request.operation,
                status,
                generation,
                next_cursor: request.after_id,
                records: 0,
                sequence: 0,
                accepted: 0,
                capacity_dropped: 0,
            }
            .encode(),
        );
        Ok(RESPONSE_HEADER_BYTES)
    }

    fn write_success(
        &self,
        request: QueryRequest,
        generation: u64,
        cursor: u64,
        status: crate::diagnostics::CollectorStatus,
        events: &[[u8; EVENT_BYTES]],
        out: &mut [u8],
    ) -> Result<usize, ContractError> {
        let total = RESPONSE_HEADER_BYTES
            .checked_add(
                events
                    .len()
                    .checked_mul(EVENT_BYTES)
                    .ok_or(ContractError::Malformed)?,
            )
            .ok_or(ContractError::Malformed)?;
        if out.len() < total {
            return Err(ContractError::BufferTooSmall);
        }
        out[..RESPONSE_HEADER_BYTES].copy_from_slice(
            &ResponseHeader {
                request_id: request.request_id,
                operation: request.operation,
                status: ResponseStatus::Ok,
                generation,
                next_cursor: cursor,
                records: events.len() as u16,
                sequence: status.sequence,
                accepted: status.stats.accepted,
                capacity_dropped: status.stats.capacity_dropped,
            }
            .encode(),
        );
        for (index, event) in events.iter().enumerate() {
            let start = RESPONSE_HEADER_BYTES + index * EVENT_BYTES;
            out[start..start + EVENT_BYTES].copy_from_slice(event);
        }
        Ok(total)
    }
}

fn event_kind_raw(kind: EventKind) -> u8 {
    kind as u8
}

fn get_event_kind(value: u8) -> Option<EventKind> {
    match value {
        0 => Some(EventKind::KernelException),
        1 => Some(EventKind::ServiceCrash),
        2 => Some(EventKind::ApplicationCrash),
        3 => Some(EventKind::DriverHardware),
        4 => Some(EventKind::StorageCorruption),
        5 => Some(EventKind::Network),
        6 => Some(EventKind::UpdateBoot),
        7 => Some(EventKind::PerformanceRegression),
        _ => None,
    }
}

fn get_severity(value: u8) -> Option<Severity> {
    match value {
        0 => Some(Severity::Info),
        1 => Some(Severity::Warning),
        2 => Some(Severity::Error),
        3 => Some(Severity::Critical),
        _ => None,
    }
}

fn get_privacy(value: u8) -> Option<PrivacyClass> {
    match value {
        0 => Some(PrivacyClass::Public),
        1 => Some(PrivacyClass::Internal),
        2 => Some(PrivacyClass::Sensitive),
        3 => Some(PrivacyClass::Secret),
        _ => None,
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
    use crate::diagnostics::{
        decode_event, ClockQuality, DiagnosticAccess, DiagnosticIoError, DiagnosticService,
        EventInput, PayloadKind, RecoveryAction,
    };
    use core::cell::Cell;

    const DISK_BYTES: usize = 16 * 1024;

    struct MemoryDisk {
        bytes: [u8; DISK_BYTES],
    }

    impl MemoryDisk {
        const fn new() -> Self {
            Self {
                bytes: [0; DISK_BYTES],
            }
        }
    }

    impl DiagnosticIo for MemoryDisk {
        fn capacity(&self) -> usize {
            self.bytes.len()
        }

        fn read(&mut self, offset: usize, out: &mut [u8]) -> Result<(), DiagnosticIoError> {
            let end = offset
                .checked_add(out.len())
                .ok_or(DiagnosticIoError::Read)?;
            out.copy_from_slice(self.bytes.get(offset..end).ok_or(DiagnosticIoError::Read)?);
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

    struct Authority {
        generation: Cell<u64>,
    }

    impl DiagnosticAuthority for Authority {
        fn access(&self, subject: u64) -> Option<DiagnosticAccess> {
            (subject == 7).then_some(DiagnosticAccess {
                can_collect: true,
                can_query: true,
                privacy_ceiling: PrivacyClass::Internal,
                max_page: 2,
            })
        }

        fn generation(&self, subject: u64) -> Option<u64> {
            self.access(subject).map(|_| self.generation.get())
        }
    }

    fn request() -> QueryRequest {
        QueryRequest {
            request_id: 19,
            expected_generation: 0,
            deadline_ns: 0,
            after_id: 0,
            operation: Operation::Query,
            kind: None,
            minimum_severity: Severity::Info,
            privacy_ceiling: PrivacyClass::Internal,
            limit: 8,
            cancelable: true,
        }
    }

    fn input(
        privacy: PrivacyClass,
        severity: Severity,
        component: &'static str,
    ) -> EventInput<'static> {
        EventInput {
            kind: EventKind::KernelException,
            severity,
            privacy,
            clock_quality: ClockQuality::Trusted,
            observed_at: 10,
            causes: &[],
            component,
            component_version: 1,
            transaction_id: 0,
            boot_id: 1,
            platform_profile: [7; 32],
            resource_pressure: [1, 2, 3, 4],
            recovery: RecoveryAction::None,
            payload_kind: PayloadKind::None,
            payload_reference: &[],
            payload_digest: [0; 32],
            redacted: false,
        }
    }

    #[test]
    fn request_roundtrip_is_exact_and_reserved_bytes_fail_closed() {
        let encoded = request().encode().unwrap();
        assert_eq!(QueryRequest::decode(&encoded), Ok(request()));
        for at in [46, 47, 63] {
            let mut bad = encoded;
            bad[at] = 1;
            assert_eq!(QueryRequest::decode(&bad), Err(ContractError::Malformed));
        }
        let mut bad = encoded;
        bad[41] = 9;
        assert_eq!(QueryRequest::decode(&bad), Err(ContractError::Malformed));
        let mut bad = encoded;
        bad[43] = 0x80;
        assert_eq!(QueryRequest::decode(&bad), Err(ContractError::Malformed));
    }

    #[test]
    fn query_is_authority_capped_private_and_cursor_stable() {
        let mut service = DiagnosticService::format(
            MemoryDisk::new(),
            Authority {
                generation: Cell::new(3),
            },
        )
        .unwrap();
        service
            .collect(7, input(PrivacyClass::Public, Severity::Info, "kernel"))
            .unwrap();
        service
            .collect(
                7,
                input(PrivacyClass::Internal, Severity::Warning, "system.service"),
            )
            .unwrap();
        service
            .collect(
                7,
                input(PrivacyClass::Secret, Severity::Critical, "secret.source"),
            )
            .unwrap();
        let contract = ContractService::new(service);
        let mut out = [0u8; RESPONSE_HEADER_BYTES + 2 * EVENT_BYTES];
        let len = contract
            .handle::<4>(7, request(), 20, false, &mut out)
            .unwrap();
        assert_eq!(len, out.len());
        let header =
            ResponseHeader::decode(out[..RESPONSE_HEADER_BYTES].try_into().unwrap()).unwrap();
        assert_eq!(header.status, ResponseStatus::Ok);
        assert_eq!(header.generation, 3);
        assert_eq!(header.records, 2);
        assert_eq!(header.next_cursor, 2);
        let first: &[u8; EVENT_BYTES] = out
            [RESPONSE_HEADER_BYTES..RESPONSE_HEADER_BYTES + EVENT_BYTES]
            .try_into()
            .unwrap();
        assert_eq!(decode_event(first).unwrap().privacy(), PrivacyClass::Public);
    }

    #[test]
    fn unauthorized_stale_timeout_and_cancel_are_explicit() {
        let mut service = DiagnosticService::format(
            MemoryDisk::new(),
            Authority {
                generation: Cell::new(4),
            },
        )
        .unwrap();
        service
            .collect(7, input(PrivacyClass::Public, Severity::Info, "kernel"))
            .unwrap();
        let contract = ContractService::new(service);
        let mut out = [0u8; RESPONSE_HEADER_BYTES];

        assert_eq!(
            contract.handle::<2>(8, request(), 1, false, &mut out),
            Ok(RESPONSE_HEADER_BYTES)
        );
        assert_eq!(
            ResponseHeader::decode(&out).unwrap().status,
            ResponseStatus::Unauthorized
        );

        let mut stale = request();
        stale.expected_generation = 3;
        assert_eq!(contract.handle::<2>(7, stale, 1, false, &mut out), Ok(80));
        assert_eq!(
            ResponseHeader::decode(&out).unwrap().status,
            ResponseStatus::StaleGeneration
        );

        let mut expired = request();
        expired.deadline_ns = 20;
        assert_eq!(
            contract.handle::<2>(7, expired, 20, false, &mut out),
            Ok(80)
        );
        assert_eq!(
            ResponseHeader::decode(&out).unwrap().status,
            ResponseStatus::TimedOut
        );

        assert_eq!(
            contract.handle::<2>(7, request(), 1, true, &mut out),
            Ok(80)
        );
        assert_eq!(
            ResponseHeader::decode(&out).unwrap().status,
            ResponseStatus::Cancelled
        );
    }

    #[test]
    fn status_has_no_events_and_response_reserved_bytes_are_strict() {
        let mut service = DiagnosticService::format(
            MemoryDisk::new(),
            Authority {
                generation: Cell::new(1),
            },
        )
        .unwrap();
        service
            .collect(7, input(PrivacyClass::Public, Severity::Info, "kernel"))
            .unwrap();
        let contract = ContractService::new(service);
        let mut status = request();
        status.operation = Operation::Status;
        status.limit = 0;
        let mut out = [0u8; RESPONSE_HEADER_BYTES];
        assert_eq!(contract.handle::<2>(7, status, 1, false, &mut out), Ok(80));
        let header = ResponseHeader::decode(&out).unwrap();
        assert_eq!(header.records, 0);
        assert_eq!(header.status, ResponseStatus::Ok);
        let mut corrupt = out;
        corrupt[36] = 1;
        assert_eq!(
            ResponseHeader::decode(&corrupt),
            Err(ContractError::Malformed)
        );
    }
}
