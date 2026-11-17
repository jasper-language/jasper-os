//! Shared bounded client and structured frontend for tenant update list results.
//!
//! The transport supplies bytes only. Request identity, response shape, record
//! decoding and JSON rendering remain in this module so native and Agent
//! frontends consume one contract.

use crate::native_install::{OwnerScope, PackageSource};
use crate::native_install_abi::{
    UpdateListHeader, UpdateListRecord, UpdateListRequest, MAX_UPDATE_LIST_BYTES,
    MAX_VISIBLE_UPDATES, UPDATE_LIST_HEADER_BYTES, UPDATE_LIST_RECORD_BYTES,
    UPDATE_LIST_REQUEST_BYTES,
};
use crate::update_client::ClientError;

/// Maximum JSON bytes for one bounded visible-update collection.
pub const LIST_JSON_BYTES: usize = 12288; // JASPER-HARDCODE-REVIEW: issue=34 source=update-list-ui-v1 reason=fixed-json-bound-for-32-wire-records

/// Mechanical transport for the versioned update-list syscall.
pub trait UpdateListTransport {
    /// Invoke the list syscall and return its encoded byte count.
    fn list(
        &mut self,
        request: &[u8; UPDATE_LIST_REQUEST_BYTES],
        output: &mut [u8; MAX_UPDATE_LIST_BYTES],
    ) -> Result<usize, i64>;
}

/// Validated visible-update collection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpdateListResponse {
    request_id: u64,
    count: usize,
    records: [Option<UpdateListRecord>; MAX_VISIBLE_UPDATES],
}

impl UpdateListResponse {
    /// Request identity echoed by the service.
    pub const fn request_id(self) -> u64 {
        self.request_id
    }

    /// Number of visible records.
    pub const fn len(self) -> usize {
        self.count
    }

    /// One record in stable service order.
    pub fn record(self, index: usize) -> Option<UpdateListRecord> {
        (index < self.count).then(|| self.records[index]).flatten()
    }
}

/// One shared update-list client over a native or Agent transport.
pub struct UpdateListClient<T> {
    transport: T,
}

impl<T: UpdateListTransport> UpdateListClient<T> {
    /// Wrap one mechanical transport.
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Return the transport after all calls complete.
    pub fn into_inner(self) -> T {
        self.transport
    }

    /// Query the authenticated caller's bounded visible-update collection.
    pub fn list(&mut self, request_id: u64) -> Result<UpdateListResponse, ClientError> {
        let request = UpdateListRequest { request_id }
            .encode()
            .ok_or(ClientError::Protocol)?;
        let mut output = [0u8; MAX_UPDATE_LIST_BYTES];
        let length = self
            .transport
            .list(&request, &mut output)
            .map_err(ClientError::Transport)?;
        decode_list(&output, length, request_id)
    }
}

/// Structured frontend over the shared update-list client.
pub struct UpdateListAgent<T> {
    client: UpdateListClient<T>,
}

impl<T: UpdateListTransport> UpdateListAgent<T> {
    /// Wrap one mechanical transport.
    pub const fn new(transport: T) -> Self {
        Self {
            client: UpdateListClient::new(transport),
        }
    }

    /// Query and render `service.update.list/1`.
    pub fn list_json(
        &mut self,
        request_id: u64,
        output: &mut [u8],
    ) -> Result<usize, AgentListError> {
        let response = self.client.list(request_id)?;
        encode_list_json(&response, output)
    }
}

/// Structured list rendering failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentListError {
    /// Shared client validation failed.
    Client(ClientError),
    /// Output cannot hold the complete JSON document.
    BufferTooSmall,
}

impl From<ClientError> for AgentListError {
    fn from(error: ClientError) -> Self {
        Self::Client(error)
    }
}

/// Render the stable structured list envelope without partial output.
pub fn encode_list_json(
    response: &UpdateListResponse,
    output: &mut [u8],
) -> Result<usize, AgentListError> {
    let mut scratch = [0u8; LIST_JSON_BYTES];
    let mut writer = JsonWriter::new(&mut scratch);
    let mut ok = writer.push(
        b"{\"schema\":\"service.update.list/1\",\"command\":\"system.update.list\",\"status\":\"ok\",\"request\":",
    );
    ok &= writer.push_u64(response.request_id);
    ok &= writer.push(b",\"records\":[");
    for index in 0..response.count {
        if index != 0 {
            ok &= writer.push(b",");
        }
        let record = response.records[index].expect("validated list record");
        ok &= writer.push(b"{\"installation\":");
        ok &= writer.push_u64(record.installation.to_raw());
        ok &= writer.push(b",\"package\":");
        ok &= writer.push_u64(record.package.to_raw());
        ok &= writer.push(b",\"app_id\":");
        ok &= writer.push_u64(record.app_id);
        ok &= writer.push(b",\"publisher\":");
        ok &= writer.push_u64(record.publisher);
        ok &= writer.push(b",\"version\":");
        ok &= writer.push_u64(u64::from(record.version));
        ok &= writer.push(b",\"content\":\"");
        ok &= writer.push_hex(&record.content);
        ok &= writer.push(b"\",\"scope\":");
        ok &= push_scope(&mut writer, record.scope);
        ok &= writer.push(b",\"source\":\"");
        ok &= writer.push(source_name(record.source));
        ok &= writer.push(b"\",\"enabled\":");
        ok &= writer.push(if record.enabled { b"true" } else { b"false" });
        ok &= writer.push(b"}");
    }
    ok &= writer.push(b"]}\n");
    if !ok {
        return Err(AgentListError::BufferTooSmall);
    }
    let length = writer.len;
    drop(writer);
    if output.len() < length {
        return Err(AgentListError::BufferTooSmall);
    }
    output[..length].copy_from_slice(&scratch[..length]);
    Ok(length)
}

fn decode_list(
    bytes: &[u8; MAX_UPDATE_LIST_BYTES],
    length: usize,
    request_id: u64,
) -> Result<UpdateListResponse, ClientError> {
    if length < UPDATE_LIST_HEADER_BYTES || length > MAX_UPDATE_LIST_BYTES {
        return Err(ClientError::Protocol);
    }
    let header = UpdateListHeader::decode(&bytes[..UPDATE_LIST_HEADER_BYTES])
        .ok_or(ClientError::Protocol)?;
    if header.request_id != request_id {
        return Err(ClientError::RequestMismatch);
    }
    let count = header.record_count as usize;
    let expected = UPDATE_LIST_HEADER_BYTES
        .checked_add(
            count
                .checked_mul(UPDATE_LIST_RECORD_BYTES)
                .ok_or(ClientError::Protocol)?,
        )
        .ok_or(ClientError::Protocol)?;
    if length != expected || bytes[length..].iter().any(|byte| *byte != 0) {
        return Err(ClientError::Protocol);
    }
    let mut records = [None; MAX_VISIBLE_UPDATES];
    for index in 0..count {
        let at = UPDATE_LIST_HEADER_BYTES + index * UPDATE_LIST_RECORD_BYTES;
        records[index] = Some(
            UpdateListRecord::decode(&bytes[at..at + UPDATE_LIST_RECORD_BYTES])
                .ok_or(ClientError::Protocol)?,
        );
    }
    Ok(UpdateListResponse {
        request_id,
        count,
        records,
    })
}

fn push_scope(writer: &mut JsonWriter<'_>, scope: OwnerScope) -> bool {
    let (kind, id) = match scope {
        OwnerScope::System => (b"system".as_slice(), 0),
        OwnerScope::Device(id) => (b"device".as_slice(), id),
        OwnerScope::User(id) => (b"user".as_slice(), id),
        OwnerScope::Group(id) => (b"group".as_slice(), id),
        OwnerScope::Tenant(id) => (b"tenant".as_slice(), id),
        OwnerScope::Workload(id) => (b"workload".as_slice(), id),
    };
    writer.push(b"{\"kind\":\"")
        && writer.push(kind)
        && writer.push(b"\",\"id\":")
        && writer.push_u64(id)
        && writer.push(b"}")
}

fn source_name(source: PackageSource) -> &'static [u8] {
    match source {
        PackageSource::SystemBuiltin => b"system_builtin",
        PackageSource::Store => b"store",
        PackageSource::UserImport => b"user_import",
        PackageSource::Enterprise => b"enterprise",
        PackageSource::Developer => b"developer",
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
    use crate::native_install::{InstallationKey, PackageKey};

    fn record() -> UpdateListRecord {
        UpdateListRecord {
            installation: InstallationKey::from_raw((2u64 << 16) | 1).unwrap(),
            package: PackageKey::from_raw((1u64 << 16) | 1).unwrap(),
            app_id: 0x41,
            publisher: 7,
            version: 3,
            content: [0x5a; 32],
            scope: OwnerScope::Tenant(8),
            source: PackageSource::Enterprise,
            enabled: true,
        }
    }

    struct Fake {
        bytes: [u8; MAX_UPDATE_LIST_BYTES],
        length: usize,
    }

    impl UpdateListTransport for Fake {
        fn list(
            &mut self,
            _request: &[u8; UPDATE_LIST_REQUEST_BYTES],
            output: &mut [u8; MAX_UPDATE_LIST_BYTES],
        ) -> Result<usize, i64> {
            *output = self.bytes;
            Ok(self.length)
        }
    }

    fn encoded() -> ([u8; MAX_UPDATE_LIST_BYTES], usize) {
        let mut bytes = [0u8; MAX_UPDATE_LIST_BYTES];
        let mut header = [0u8; UPDATE_LIST_HEADER_BYTES];
        assert!(UpdateListHeader {
            request_id: 9,
            record_count: 1,
        }
        .encode(&mut header));
        bytes[..UPDATE_LIST_HEADER_BYTES].copy_from_slice(&header);
        let record = record().encode();
        bytes[UPDATE_LIST_HEADER_BYTES..UPDATE_LIST_HEADER_BYTES + UPDATE_LIST_RECORD_BYTES]
            .copy_from_slice(&record);
        (bytes, UPDATE_LIST_HEADER_BYTES + UPDATE_LIST_RECORD_BYTES)
    }

    #[test]
    fn client_and_agent_validate_and_render_the_same_records() {
        let (bytes, length) = encoded();
        let mut agent = UpdateListAgent::new(Fake { bytes, length });
        let mut output = [0u8; LIST_JSON_BYTES];
        let length = agent.list_json(9, &mut output).unwrap();
        let text = core::str::from_utf8(&output[..length]).unwrap();
        assert!(text.starts_with(
            "{\"schema\":\"service.update.list/1\",\"command\":\"system.update.list\",\"status\":\"ok\""
        ));
        assert!(text.contains("\"scope\":{\"kind\":\"tenant\",\"id\":8}"));
        assert!(text.contains("\"source\":\"enterprise\""));
        assert!(text.contains("\"enabled\":true"));
        assert!(text.ends_with("]}\n"));
    }

    #[test]
    fn request_mismatch_trailing_bytes_and_short_output_fail_closed() {
        let (bytes, length) = encoded();
        let fake = Fake { bytes, length };
        assert_eq!(
            UpdateListClient::new(fake).list(10),
            Err(ClientError::RequestMismatch)
        );

        let (mut bytes, length) = encoded();
        bytes[length] = 1;
        assert_eq!(
            UpdateListClient::new(Fake { bytes, length }).list(9),
            Err(ClientError::Protocol)
        );

        let (bytes, length) = encoded();
        let response = UpdateListClient::new(Fake { bytes, length })
            .list(9)
            .unwrap();
        let mut short = [0xa5u8; 32];
        assert_eq!(
            encode_list_json(&response, &mut short),
            Err(AgentListError::BufferTooSmall)
        );
        assert_eq!(short, [0xa5; 32]);
    }
}
