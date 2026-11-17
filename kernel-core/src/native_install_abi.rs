//! Versioned user ABI records for native package installation.
//!
//! Records contain package and policy inputs only. Security domains, runtime
//! principals and ownership subjects are derived by the kernel from the
//! authenticated caller; logical paths and AppIDs never authorize an action.

use crate::native_install::{
    GrantRights, InstallationKey, InstallationSnapshot, OwnerScope, PackageKey, PackageSource,
    PackageSpec, Subject, CONTENT_BYTES,
};

pub const MAGIC: u32 = u32::from_le_bytes(*b"JSI1");
pub const VERSION: u16 = 1;
pub const PACKAGE_PUT_BYTES: usize = 80;
pub const REGISTER_BYTES: usize = 64;
pub const GRANT_BYTES: usize = 64;
pub const INFO_BYTES: usize = 64;
pub const UPDATE_LIST_MAGIC: u32 = u32::from_le_bytes(*b"JSIU");
pub const UPDATE_LIST_VERSION: u16 = 1;
pub const UPDATE_LIST_REQUEST_BYTES: usize = 32;
pub const UPDATE_LIST_HEADER_BYTES: usize = 32;
pub const UPDATE_LIST_RECORD_BYTES: usize = 96;
pub const MAX_VISIBLE_UPDATES: usize = 32; // JASPER-HARDCODE-REVIEW: issue=33 source=storage-ABI-v1 reason=bounded-native-install-snapshot-capacity
pub const MAX_UPDATE_LIST_BYTES: usize = // JASPER-HARDCODE-REVIEW: issue=33 source=storage-ABI-v1 reason=bounded-native-install-snapshot-wire-size
    UPDATE_LIST_HEADER_BYTES + MAX_VISIBLE_UPDATES * UPDATE_LIST_RECORD_BYTES;

/// Request for the authenticated caller's update-visible installation set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpdateListRequest {
    pub request_id: u64,
}

impl UpdateListRequest {
    pub fn encode(self) -> Option<[u8; UPDATE_LIST_REQUEST_BYTES]> {
        if self.request_id == 0 {
            return None;
        }
        let mut out = [0u8; UPDATE_LIST_REQUEST_BYTES];
        out[0..4].copy_from_slice(&UPDATE_LIST_MAGIC.to_le_bytes());
        out[4..6].copy_from_slice(&UPDATE_LIST_VERSION.to_le_bytes());
        out[8..16].copy_from_slice(&self.request_id.to_le_bytes());
        Some(out)
    }

    pub fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() != UPDATE_LIST_REQUEST_BYTES
            || read_u32(raw, 0)? != UPDATE_LIST_MAGIC
            || read_u16(raw, 4)? != UPDATE_LIST_VERSION
            || read_u16(raw, 6)? != 0
            || read_u64(raw, 8)? == 0
            || raw[16..32].iter().any(|byte| *byte != 0)
        {
            return None;
        }
        Some(Self {
            request_id: read_u64(raw, 8)?,
        })
    }
}

/// Fixed response header preceding zero or more update records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpdateListHeader {
    pub request_id: u64,
    pub record_count: u32,
}

impl UpdateListHeader {
    pub fn encode(self, out: &mut [u8; UPDATE_LIST_HEADER_BYTES]) -> bool {
        if self.request_id == 0 || self.record_count as usize > MAX_VISIBLE_UPDATES {
            return false;
        }
        out[0..4].copy_from_slice(&UPDATE_LIST_MAGIC.to_le_bytes());
        out[4..6].copy_from_slice(&UPDATE_LIST_VERSION.to_le_bytes());
        out[8..16].copy_from_slice(&self.request_id.to_le_bytes());
        out[16..20].copy_from_slice(&self.record_count.to_le_bytes());
        out[20..24].copy_from_slice(&(UPDATE_LIST_RECORD_BYTES as u32).to_le_bytes());
        true
    }

    pub fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() < UPDATE_LIST_HEADER_BYTES
            || read_u32(raw, 0)? != UPDATE_LIST_MAGIC
            || read_u16(raw, 4)? != UPDATE_LIST_VERSION
            || read_u16(raw, 6)? != 0
            || read_u64(raw, 8)? == 0
            || read_u32(raw, 16)? as usize > MAX_VISIBLE_UPDATES
            || read_u32(raw, 20)? as usize != UPDATE_LIST_RECORD_BYTES
            || raw[24..32].iter().any(|byte| *byte != 0)
        {
            return None;
        }
        Some(Self {
            request_id: read_u64(raw, 8)?,
            record_count: read_u32(raw, 16)?,
        })
    }
}

/// One immutable installation/package fact visible to an update principal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpdateListRecord {
    pub installation: InstallationKey,
    pub package: PackageKey,
    pub app_id: u64,
    pub publisher: u64,
    pub version: u32,
    pub content: [u8; CONTENT_BYTES],
    pub scope: OwnerScope,
    pub source: PackageSource,
    pub enabled: bool,
}

impl UpdateListRecord {
    pub const fn from_parts(
        installation: InstallationKey,
        package: crate::native_install::PackageSnapshot,
        scope: OwnerScope,
        source: PackageSource,
        enabled: bool,
    ) -> Self {
        Self {
            installation,
            package: package.key,
            app_id: package.spec.app_id,
            publisher: package.spec.publisher,
            version: package.spec.version,
            content: package.spec.content,
            scope,
            source,
            enabled,
        }
    }

    pub fn encode(self) -> [u8; UPDATE_LIST_RECORD_BYTES] {
        let mut out = [0u8; UPDATE_LIST_RECORD_BYTES];
        out[0..8].copy_from_slice(&self.installation.to_raw().to_le_bytes());
        out[8..16].copy_from_slice(&self.package.to_raw().to_le_bytes());
        out[16..24].copy_from_slice(&self.app_id.to_le_bytes());
        out[24..32].copy_from_slice(&self.publisher.to_le_bytes());
        out[32..36].copy_from_slice(&self.version.to_le_bytes());
        out[36..36 + CONTENT_BYTES].copy_from_slice(&self.content);
        encode_scope(&mut out, 68, self.scope);
        out[84] = package_source_tag(self.source);
        out[85] = u8::from(self.enabled);
        out
    }

    pub fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() != UPDATE_LIST_RECORD_BYTES {
            return None;
        }
        let mut content = [0u8; CONTENT_BYTES];
        content.copy_from_slice(raw.get(36..36 + CONTENT_BYTES)?);
        let record = Self {
            installation: InstallationKey::from_raw(read_u64(raw, 0)?)?,
            package: PackageKey::from_raw(read_u64(raw, 8)?)?,
            app_id: read_u64(raw, 16)?,
            publisher: read_u64(raw, 24)?,
            version: read_u32(raw, 32)?,
            content,
            scope: decode_scope(raw, 68)?,
            source: package_source_from_tag(raw[84])?,
            enabled: match raw[85] {
                0 => false,
                1 => true,
                _ => return None,
            },
        };
        if record.app_id == 0
            || record.publisher == 0
            || record.version == 0
            || raw[86..].iter().any(|byte| *byte != 0)
        {
            return None;
        }
        Some(record)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackagePutArgs {
    pub spec: PackageSpec,
    pub bytes_ptr: u64,
    pub bytes_len: u32,
}

impl PackagePutArgs {
    pub fn encode(self) -> Option<[u8; PACKAGE_PUT_BYTES]> {
        if self.bytes_len == 0 {
            return None;
        }
        let mut out = [0u8; PACKAGE_PUT_BYTES];
        out[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        out[4..6].copy_from_slice(&VERSION.to_le_bytes());
        out[8..16].copy_from_slice(&self.spec.app_id.to_le_bytes());
        out[16..24].copy_from_slice(&self.spec.publisher.to_le_bytes());
        out[24..28].copy_from_slice(&self.spec.version.to_le_bytes());
        out[28..32].copy_from_slice(&self.bytes_len.to_le_bytes());
        out[32..32 + CONTENT_BYTES].copy_from_slice(&self.spec.content);
        out[64..72].copy_from_slice(&self.bytes_ptr.to_le_bytes());
        Some(out)
    }

    pub fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() != PACKAGE_PUT_BYTES
            || read_u32(raw, 0)? != MAGIC
            || read_u16(raw, 4)? != VERSION
            || read_u16(raw, 6)? != 0
            || raw[72..80].iter().any(|byte| *byte != 0)
        {
            return None;
        }
        let mut content = [0u8; CONTENT_BYTES];
        content.copy_from_slice(raw.get(32..32 + CONTENT_BYTES)?);
        let bytes_len = read_u32(raw, 28)?;
        if bytes_len == 0 {
            return None;
        }
        Some(Self {
            spec: PackageSpec {
                app_id: read_u64(raw, 8)?,
                publisher: read_u64(raw, 16)?,
                version: read_u32(raw, 24)?,
                content,
            },
            bytes_len,
            bytes_ptr: read_u64(raw, 64)?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisterArgs {
    pub package: PackageKey,
    pub scope: OwnerScope,
    pub source: PackageSource,
    pub update_authority: Subject,
}

impl RegisterArgs {
    pub fn encode(self) -> [u8; REGISTER_BYTES] {
        let mut out = [0u8; REGISTER_BYTES];
        out[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        out[4..6].copy_from_slice(&VERSION.to_le_bytes());
        out[8..16].copy_from_slice(&self.package.to_raw().to_le_bytes());
        encode_scope(&mut out, 16, self.scope);
        out[32] = package_source_tag(self.source);
        encode_subject(&mut out, 40, self.update_authority);
        out
    }

    pub fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() != REGISTER_BYTES
            || read_u32(raw, 0)? != MAGIC
            || read_u16(raw, 4)? != VERSION
            || read_u16(raw, 6)? != 0
            || raw[33..40].iter().any(|byte| *byte != 0)
            || raw[56..64].iter().any(|byte| *byte != 0)
        {
            return None;
        }
        Some(Self {
            package: PackageKey::from_raw(read_u64(raw, 8)?)?,
            scope: decode_scope(raw, 16)?,
            source: package_source_from_tag(raw[32])?,
            update_authority: decode_subject(raw, 40)?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantArgs {
    pub installation: InstallationKey,
    pub subject: Subject,
    pub rights: GrantRights,
    pub expires_at: Option<u64>,
}

impl GrantArgs {
    pub fn encode(self) -> [u8; GRANT_BYTES] {
        let mut out = [0u8; GRANT_BYTES];
        out[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        out[4..6].copy_from_slice(&VERSION.to_le_bytes());
        out[8..16].copy_from_slice(&self.installation.to_raw().to_le_bytes());
        encode_subject(&mut out, 16, self.subject);
        out[32..36].copy_from_slice(&self.rights.0.to_le_bytes());
        out[36] = u8::from(self.expires_at.is_some());
        if let Some(expires) = self.expires_at {
            out[40..48].copy_from_slice(&expires.to_le_bytes());
        }
        out
    }

    pub fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() != GRANT_BYTES
            || read_u32(raw, 0)? != MAGIC
            || read_u16(raw, 4)? != VERSION
            || read_u16(raw, 6)? != 0
            || raw[37..40].iter().any(|byte| *byte != 0)
            || raw[48..64].iter().any(|byte| *byte != 0)
        {
            return None;
        }
        let expires_at = match raw[36] {
            0 if raw[40..48].iter().all(|byte| *byte == 0) => None,
            0 => return None,
            1 => Some(read_u64(raw, 40)?),
            _ => return None,
        };
        Some(Self {
            installation: InstallationKey::from_raw(read_u64(raw, 8)?)?,
            subject: decode_subject(raw, 16)?,
            rights: GrantRights(read_u32(raw, 32)?),
            expires_at,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstallationInfo {
    pub key: InstallationKey,
    pub package: PackageKey,
    pub scope: OwnerScope,
    pub source: PackageSource,
    pub update_authority: Subject,
    pub enabled: bool,
}

impl InstallationInfo {
    pub const fn from_snapshot(snapshot: InstallationSnapshot) -> Self {
        Self {
            key: snapshot.key,
            package: snapshot.package,
            scope: snapshot.scope,
            source: snapshot.source,
            update_authority: snapshot.update_authority.subject,
            enabled: snapshot.enabled,
        }
    }

    pub fn encode(self) -> [u8; INFO_BYTES] {
        let mut out = [0u8; INFO_BYTES];
        out[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        out[4..6].copy_from_slice(&VERSION.to_le_bytes());
        out[8..16].copy_from_slice(&self.key.to_raw().to_le_bytes());
        out[16..24].copy_from_slice(&self.package.to_raw().to_le_bytes());
        encode_scope(&mut out, 24, self.scope);
        out[40] = package_source_tag(self.source);
        out[41] = u8::from(self.enabled);
        encode_subject(&mut out, 48, self.update_authority);
        out
    }
}

fn encode_scope(raw: &mut [u8], at: usize, scope: OwnerScope) {
    let (tag, id) = match scope {
        OwnerScope::System => (0, 0),
        OwnerScope::Device(id) => (1, id),
        OwnerScope::User(id) => (2, id),
        OwnerScope::Group(id) => (3, id),
        OwnerScope::Tenant(id) => (4, id),
        OwnerScope::Workload(id) => (5, id),
    };
    raw[at] = tag;
    raw[at + 8..at + 16].copy_from_slice(&id.to_le_bytes());
}

fn decode_scope(raw: &[u8], at: usize) -> Option<OwnerScope> {
    if raw[at + 1..at + 8].iter().any(|byte| *byte != 0) {
        return None;
    }
    let id = read_u64(raw, at + 8)?;
    match (raw[at], id) {
        (0, 0) => Some(OwnerScope::System),
        (1, id) if id != 0 => Some(OwnerScope::Device(id)),
        (2, id) if id != 0 => Some(OwnerScope::User(id)),
        (3, id) if id != 0 => Some(OwnerScope::Group(id)),
        (4, id) if id != 0 => Some(OwnerScope::Tenant(id)),
        (5, id) if id != 0 => Some(OwnerScope::Workload(id)),
        _ => None,
    }
}

fn encode_subject(raw: &mut [u8], at: usize, subject: Subject) {
    let (tag, id) = match subject {
        Subject::System => (0, 0),
        Subject::Device(id) => (1, id),
        Subject::User(id) => (2, id),
        Subject::Group(id) => (3, id),
        Subject::Tenant(id) => (4, id),
        Subject::Workload(id) => (5, id),
        Subject::Service(id) => (6, id),
    };
    raw[at] = tag;
    raw[at + 8..at + 16].copy_from_slice(&id.to_le_bytes());
}

fn decode_subject(raw: &[u8], at: usize) -> Option<Subject> {
    if raw[at + 1..at + 8].iter().any(|byte| *byte != 0) {
        return None;
    }
    let id = read_u64(raw, at + 8)?;
    match (raw[at], id) {
        (0, 0) => Some(Subject::System),
        (1, id) if id != 0 => Some(Subject::Device(id)),
        (2, id) if id != 0 => Some(Subject::User(id)),
        (3, id) if id != 0 => Some(Subject::Group(id)),
        (4, id) if id != 0 => Some(Subject::Tenant(id)),
        (5, id) if id != 0 => Some(Subject::Workload(id)),
        (6, id) if id != 0 => Some(Subject::Service(id)),
        _ => None,
    }
}

const fn package_source_tag(source: PackageSource) -> u8 {
    match source {
        PackageSource::SystemBuiltin => 0,
        PackageSource::Store => 1,
        PackageSource::UserImport => 2,
        PackageSource::Enterprise => 3,
        PackageSource::Developer => 4,
    }
}

const fn package_source_from_tag(tag: u8) -> Option<PackageSource> {
    match tag {
        0 => Some(PackageSource::SystemBuiltin),
        1 => Some(PackageSource::Store),
        2 => Some(PackageSource::UserImport),
        3 => Some(PackageSource::Enterprise),
        4 => Some(PackageSource::Developer),
        _ => None,
    }
}

fn read_u16(raw: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(raw.get(at..at + 2)?.try_into().ok()?))
}

fn read_u32(raw: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(raw.get(at..at + 4)?.try_into().ok()?))
}

fn read_u64(raw: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(raw.get(at..at + 8)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package() -> PackagePutArgs {
        PackagePutArgs {
            spec: PackageSpec {
                app_id: 0x41,
                publisher: 7,
                content: [0x5a; CONTENT_BYTES],
                version: 3,
            },
            bytes_ptr: 0x1000,
            bytes_len: 12,
        }
    }

    #[test]
    fn records_roundtrip_and_reject_reserved_or_leaked_fields() {
        let package = package();
        let encoded = package.encode().unwrap();
        assert_eq!(PackagePutArgs::decode(&encoded), Some(package));
        let mut leaked = encoded;
        leaked[72] = 1;
        assert_eq!(PackagePutArgs::decode(&leaked), None);

        let register = RegisterArgs {
            package: PackageKey::from_raw((1u64 << 16) | 1).unwrap(),
            scope: OwnerScope::Workload(7),
            source: PackageSource::Store,
            update_authority: Subject::Workload(7),
        };
        let encoded = register.encode();
        assert_eq!(RegisterArgs::decode(&encoded), Some(register));

        let grant = GrantArgs {
            installation: InstallationKey::from_raw((2u64 << 16) | 1).unwrap(),
            subject: Subject::Workload(7),
            rights: GrantRights::DISCOVER.union(GrantRights::START),
            expires_at: Some(55),
        };
        let encoded = grant.encode();
        assert_eq!(GrantArgs::decode(&encoded), Some(grant));
    }

    #[test]
    fn info_contains_only_non_secret_installation_facts() {
        let key = InstallationKey::from_raw((2u64 << 16) | 1).unwrap();
        let package = PackageKey::from_raw((1u64 << 16) | 1).unwrap();
        let info = InstallationInfo {
            key,
            package,
            scope: OwnerScope::Workload(7),
            source: PackageSource::Store,
            update_authority: Subject::Workload(7),
            enabled: true,
        }
        .encode();
        assert_eq!(&info[0..4], b"JSI1");
        assert_eq!(read_u64(&info, 8), Some(key.to_raw()));
        assert_eq!(read_u64(&info, 16), Some(package.to_raw()));
        assert_eq!(decode_scope(&info, 24), Some(OwnerScope::Workload(7)));
        assert_eq!(decode_subject(&info, 48), Some(Subject::Workload(7)));
    }

    #[test]
    fn update_list_wire_binds_request_and_rejects_identity_or_reserved_fields() {
        let request = UpdateListRequest { request_id: 9 };
        let encoded = request.encode().unwrap();
        assert_eq!(UpdateListRequest::decode(&encoded), Some(request));
        let mut spoofed = encoded;
        spoofed[16] = 1;
        assert_eq!(UpdateListRequest::decode(&spoofed), None);

        let mut header = [0u8; UPDATE_LIST_HEADER_BYTES];
        assert!(UpdateListHeader {
            request_id: 9,
            record_count: 1,
        }
        .encode(&mut header));
        assert_eq!(
            UpdateListHeader::decode(&header),
            Some(UpdateListHeader {
                request_id: 9,
                record_count: 1,
            })
        );

        let record = UpdateListRecord {
            installation: InstallationKey::from_raw((2u64 << 16) | 1).unwrap(),
            package: PackageKey::from_raw((1u64 << 16) | 1).unwrap(),
            app_id: 0x41,
            publisher: 7,
            version: 3,
            content: [0x5a; CONTENT_BYTES],
            scope: OwnerScope::Tenant(8),
            source: PackageSource::Enterprise,
            enabled: true,
        };
        let encoded = record.encode();
        assert_eq!(UpdateListRecord::decode(&encoded), Some(record));
        let mut leaked = encoded;
        leaked[86] = 1;
        assert_eq!(UpdateListRecord::decode(&leaked), None);
    }
}
