//! Versioned user ABI for bounded Sandbox launch plans.
//!
//! Records contain stable keys and explicit policy inputs only. They never
//! contain a security domain or logical path; the kernel supplies the caller's
//! domain and revalidates every referenced authority before admission.

use crate::sandbox::SandboxKey;
use crate::sandbox_image::{ImageKey, VolumeKey};
use crate::sandbox_launch::{
    CapabilitySet, DataScopeGrant, DeviceGrant, LaunchPlanKey, LaunchPlanSnapshot, LaunchResources,
    NetworkPolicyRef,
};
use crate::security_domain::DomainKey;
use crate::workload::{IoRateLimits, ResourceLimits, WorkloadKey};

pub const MAGIC: u32 = u32::from_le_bytes(*b"JSL1");
pub const VERSION: u16 = 1;
pub const CREATE_BYTES: usize = 1184;
pub const INFO_BYTES: usize = 144;
pub const MAX_DEVICE_GRANTS: usize = 16;
pub const MAX_DATA_SCOPES: usize = 16;

const HEADER_BYTES: usize = 160;
const GRANT_BYTES: usize = 32;
const DEVICES_OFFSET: usize = HEADER_BYTES;
const DATA_OFFSET: usize = DEVICES_OFFSET + MAX_DEVICE_GRANTS * GRANT_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaunchCreateArgs {
    pub sandbox: SandboxKey,
    /// Optional caller hint. Zero asks the kernel to derive the Sandbox root.
    pub root: Option<WorkloadKey>,
    pub image: ImageKey,
    pub volume: Option<VolumeKey>,
    pub root_capabilities: CapabilitySet,
    pub capabilities: CapabilitySet,
    pub resources: LaunchResources,
    pub network_policy: Option<NetworkPolicyRef>,
    pub device_count: u16,
    pub data_count: u16,
    pub devices: [DeviceGrant; MAX_DEVICE_GRANTS],
    pub data: [DataScopeGrant; MAX_DATA_SCOPES],
}

impl LaunchCreateArgs {
    pub fn encode(self) -> Option<[u8; CREATE_BYTES]> {
        if self.device_count as usize > MAX_DEVICE_GRANTS
            || self.data_count as usize > MAX_DATA_SCOPES
        {
            return None;
        }
        let mut out = [0u8; CREATE_BYTES];
        out[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        out[4..6].copy_from_slice(&VERSION.to_le_bytes());
        out[8..16].copy_from_slice(&self.sandbox.to_raw().to_le_bytes());
        out[16..24].copy_from_slice(&self.root.map_or(0, WorkloadKey::to_raw).to_le_bytes());
        out[24..32].copy_from_slice(&self.image.to_raw().to_le_bytes());
        out[32..40].copy_from_slice(&self.volume.map_or(0, VolumeKey::to_raw).to_le_bytes());
        out[40..48].copy_from_slice(&self.root_capabilities.raw().to_le_bytes());
        out[48..56].copy_from_slice(&self.capabilities.raw().to_le_bytes());
        if let Some(policy) = self.network_policy {
            out[56..64].copy_from_slice(&policy.policy.to_le_bytes());
            out[64..68].copy_from_slice(&policy.generation.to_le_bytes());
        }
        out[68..70].copy_from_slice(&self.device_count.to_le_bytes());
        out[70..72].copy_from_slice(&self.data_count.to_le_bytes());
        out[72..76].copy_from_slice(&self.resources.limits.cpu_permille.to_le_bytes());
        out[76..80].copy_from_slice(&self.resources.limits.threads.to_le_bytes());
        out[80..88].copy_from_slice(&self.resources.limits.memory_bytes.to_le_bytes());
        out[88..92].copy_from_slice(&self.resources.limits.ring_entries.to_le_bytes());
        out[96..104].copy_from_slice(&self.resources.limits.io_bytes.to_le_bytes());
        out[104..112].copy_from_slice(&self.resources.limits.io_ops.to_le_bytes());
        if let Some(rate) = self.resources.io_rate {
            out[112..120].copy_from_slice(&rate.bytes_per_window.to_le_bytes());
            out[120..128].copy_from_slice(&rate.ops_per_window.to_le_bytes());
            out[128..136].copy_from_slice(&rate.window_ns.to_le_bytes());
        }
        for (index, grant) in self.used_devices().iter().copied().enumerate() {
            encode_device(&mut out, DEVICES_OFFSET + index * GRANT_BYTES, grant);
        }
        for (index, grant) in self.used_data().iter().copied().enumerate() {
            encode_data(&mut out, DATA_OFFSET + index * GRANT_BYTES, grant);
        }
        Some(out)
    }

    pub fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() != CREATE_BYTES
            || read_u32(raw, 0)? != MAGIC
            || read_u16(raw, 4)? != VERSION
            || raw[6..8].iter().any(|byte| *byte != 0)
            || raw[92..96].iter().any(|byte| *byte != 0)
            || raw[136..160].iter().any(|byte| *byte != 0)
        {
            return None;
        }
        let device_count = read_u16(raw, 68)?;
        let data_count = read_u16(raw, 70)?;
        if device_count as usize > MAX_DEVICE_GRANTS || data_count as usize > MAX_DATA_SCOPES {
            return None;
        }
        let volume_raw = read_u64(raw, 32)?;
        let volume = if volume_raw == 0 {
            None
        } else {
            Some(VolumeKey::from_raw(volume_raw)?)
        };
        let policy_raw = read_u64(raw, 56)?;
        let policy_generation = read_u32(raw, 64)?;
        let network_policy = match (policy_raw, policy_generation) {
            (0, 0) => None,
            (policy, generation) if policy != 0 && generation != 0 => {
                Some(NetworkPolicyRef { policy, generation })
            }
            _ => return None,
        };
        let io_rate = match (
            read_u64(raw, 112)?,
            read_u64(raw, 120)?,
            read_u64(raw, 128)?,
        ) {
            (0, 0, 0) => None,
            (bytes, ops, window) => Some(IoRateLimits {
                bytes_per_window: bytes,
                ops_per_window: ops,
                window_ns: window,
            }),
        };
        let mut devices = [EMPTY_DEVICE; MAX_DEVICE_GRANTS];
        for (index, slot) in devices[..device_count as usize].iter_mut().enumerate() {
            *slot = decode_device(raw, DEVICES_OFFSET + index * GRANT_BYTES)?;
        }
        let used_device_bytes = DEVICES_OFFSET + device_count as usize * GRANT_BYTES;
        if raw[used_device_bytes..DATA_OFFSET]
            .iter()
            .any(|byte| *byte != 0)
        {
            return None;
        }
        let mut data = [EMPTY_DATA; MAX_DATA_SCOPES];
        for (index, slot) in data[..data_count as usize].iter_mut().enumerate() {
            *slot = decode_data(raw, DATA_OFFSET + index * GRANT_BYTES)?;
        }
        let used_data_bytes = DATA_OFFSET + data_count as usize * GRANT_BYTES;
        if raw[used_data_bytes..].iter().any(|byte| *byte != 0) {
            return None;
        }
        Some(Self {
            sandbox: SandboxKey::from_raw(read_u64(raw, 8)?)?,
            root: match read_u64(raw, 16)? {
                0 => None,
                raw => Some(WorkloadKey::from_raw(raw)?),
            },
            image: ImageKey::from_raw(read_u64(raw, 24)?)?,
            volume,
            root_capabilities: CapabilitySet::new(read_u64(raw, 40)?)?,
            capabilities: CapabilitySet::new(read_u64(raw, 48)?)?,
            resources: LaunchResources {
                limits: ResourceLimits {
                    cpu_permille: read_u32(raw, 72)?,
                    memory_bytes: read_u64(raw, 80)?,
                    threads: read_u32(raw, 76)?,
                    ring_entries: read_u32(raw, 88)?,
                    io_bytes: read_u64(raw, 96)?,
                    io_ops: read_u64(raw, 104)?,
                },
                io_rate,
            },
            network_policy,
            device_count,
            data_count,
            devices,
            data,
        })
    }

    pub fn used_devices(&self) -> &[DeviceGrant] {
        &self.devices[..self.device_count as usize]
    }

    pub fn used_data(&self) -> &[DataScopeGrant] {
        &self.data[..self.data_count as usize]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaunchPlanInfo {
    pub key: LaunchPlanKey,
    pub sandbox: SandboxKey,
    pub root: WorkloadKey,
    pub image: ImageKey,
    pub volume: Option<VolumeKey>,
    pub root_capabilities: CapabilitySet,
    pub capabilities: CapabilitySet,
    pub resources: LaunchResources,
    pub network_policy: Option<NetworkPolicyRef>,
    pub devices: u16,
    pub data_scopes: u16,
    pub data_writable_mask: u16,
}

impl LaunchPlanInfo {
    pub const fn from_snapshot(snapshot: LaunchPlanSnapshot) -> Self {
        Self {
            key: snapshot.key,
            sandbox: snapshot.sandbox,
            root: snapshot.root,
            image: snapshot.image,
            volume: snapshot.volume,
            root_capabilities: snapshot.root_capabilities,
            capabilities: snapshot.capabilities,
            resources: snapshot.resources,
            network_policy: snapshot.network_policy,
            devices: snapshot.devices,
            data_scopes: snapshot.data_scopes,
            data_writable_mask: snapshot.data_writable_mask,
        }
    }

    pub fn encode(self) -> [u8; INFO_BYTES] {
        let mut out = [0u8; INFO_BYTES];
        out[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        out[4..6].copy_from_slice(&VERSION.to_le_bytes());
        out[8..16].copy_from_slice(&self.key.to_raw().to_le_bytes());
        out[16..24].copy_from_slice(&self.sandbox.to_raw().to_le_bytes());
        out[24..32].copy_from_slice(&self.root.to_raw().to_le_bytes());
        out[32..40].copy_from_slice(&self.image.to_raw().to_le_bytes());
        out[40..48].copy_from_slice(&self.volume.map_or(0, VolumeKey::to_raw).to_le_bytes());
        out[48..56].copy_from_slice(&self.root_capabilities.raw().to_le_bytes());
        out[56..64].copy_from_slice(&self.capabilities.raw().to_le_bytes());
        if let Some(policy) = self.network_policy {
            out[64..72].copy_from_slice(&policy.policy.to_le_bytes());
            out[72..76].copy_from_slice(&policy.generation.to_le_bytes());
        }
        out[80..84].copy_from_slice(&self.resources.limits.cpu_permille.to_le_bytes());
        out[84..88].copy_from_slice(&self.resources.limits.threads.to_le_bytes());
        out[88..96].copy_from_slice(&self.resources.limits.memory_bytes.to_le_bytes());
        out[96..100].copy_from_slice(&self.resources.limits.ring_entries.to_le_bytes());
        out[100..102].copy_from_slice(&self.devices.to_le_bytes());
        out[102..104].copy_from_slice(&self.data_scopes.to_le_bytes());
        out[104..112].copy_from_slice(&self.resources.limits.io_bytes.to_le_bytes());
        out[112..120].copy_from_slice(&self.resources.limits.io_ops.to_le_bytes());
        if let Some(rate) = self.resources.io_rate {
            out[120..128].copy_from_slice(&rate.bytes_per_window.to_le_bytes());
            out[128..136].copy_from_slice(&rate.ops_per_window.to_le_bytes());
            out[136..144].copy_from_slice(&rate.window_ns.to_le_bytes());
        } else {
            out[120..144].fill(0);
        }
        out
    }
}

const EMPTY_DEVICE: DeviceGrant = DeviceGrant {
    object: 0,
    generation: 0,
    rights: 0,
    owner: DomainKey::NONE,
    grantee: DomainKey::NONE,
};

const EMPTY_DATA: DataScopeGrant = DataScopeGrant {
    object: 0,
    generation: 0,
    owner: DomainKey::NONE,
    grantee: DomainKey::NONE,
    writable: false,
};

fn decode_device(raw: &[u8], at: usize) -> Option<DeviceGrant> {
    Some(DeviceGrant {
        object: read_u64(raw, at)?,
        owner: decode_domain(raw, at + 8)?,
        grantee: decode_domain(raw, at + 16)?,
        generation: read_u32(raw, at + 24)?,
        rights: read_u32(raw, at + 28)?,
    })
}

fn decode_data(raw: &[u8], at: usize) -> Option<DataScopeGrant> {
    let writable = read_u32(raw, at + 28)?;
    if writable > 1 {
        return None;
    }
    Some(DataScopeGrant {
        object: read_u64(raw, at)?,
        owner: decode_domain(raw, at + 8)?,
        grantee: decode_domain(raw, at + 16)?,
        generation: read_u32(raw, at + 24)?,
        writable: writable == 1,
    })
}

fn decode_domain(raw: &[u8], at: usize) -> Option<DomainKey> {
    Some(DomainKey {
        id: read_u32(raw, at)?,
        generation: read_u32(raw, at + 4)?,
    })
}

fn encode_device(raw: &mut [u8], at: usize, grant: DeviceGrant) {
    raw[at..at + 8].copy_from_slice(&grant.object.to_le_bytes());
    encode_domain(raw, at + 8, grant.owner);
    encode_domain(raw, at + 16, grant.grantee);
    raw[at + 24..at + 28].copy_from_slice(&grant.generation.to_le_bytes());
    raw[at + 28..at + 32].copy_from_slice(&grant.rights.to_le_bytes());
}

fn encode_data(raw: &mut [u8], at: usize, grant: DataScopeGrant) {
    raw[at..at + 8].copy_from_slice(&grant.object.to_le_bytes());
    encode_domain(raw, at + 8, grant.owner);
    encode_domain(raw, at + 16, grant.grantee);
    raw[at + 24..at + 28].copy_from_slice(&grant.generation.to_le_bytes());
    raw[at + 28..at + 32].copy_from_slice(&u32::from(grant.writable).to_le_bytes());
}

fn encode_domain(raw: &mut [u8], at: usize, domain: DomainKey) {
    raw[at..at + 4].copy_from_slice(&domain.id.to_le_bytes());
    raw[at + 4..at + 8].copy_from_slice(&domain.generation.to_le_bytes());
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

    fn args() -> LaunchCreateArgs {
        LaunchCreateArgs {
            sandbox: SandboxKey::from_raw((1u64 << 16) | 2).unwrap(),
            root: Some(WorkloadKey::from_raw((3u64 << 16) | 4).unwrap()),
            image: ImageKey::from_raw((5u64 << 16) | 6).unwrap(),
            volume: Some(VolumeKey::from_raw((7u64 << 16) | 8).unwrap()),
            root_capabilities: CapabilitySet::ALL,
            capabilities: CapabilitySet::EXECUTE.union(CapabilitySet::DATA_WRITE),
            resources: LaunchResources {
                limits: ResourceLimits {
                    cpu_permille: 250,
                    memory_bytes: 16 * 1024,
                    threads: 4,
                    ring_entries: 8,
                    io_bytes: 32 * 1024,
                    io_ops: 16,
                },
                io_rate: Some(IoRateLimits {
                    bytes_per_window: 4096,
                    ops_per_window: 8,
                    window_ns: 1_000_000,
                }),
            },
            network_policy: None,
            device_count: 1,
            data_count: 1,
            devices: [DeviceGrant {
                object: 9,
                generation: 2,
                rights: 3,
                owner: DomainKey {
                    id: 44,
                    generation: 2,
                },
                grantee: DomainKey {
                    id: 44,
                    generation: 2,
                },
            }; MAX_DEVICE_GRANTS],
            data: [DataScopeGrant {
                object: 10,
                generation: 3,
                owner: DomainKey {
                    id: 44,
                    generation: 2,
                },
                grantee: DomainKey {
                    id: 44,
                    generation: 2,
                },
                writable: true,
            }; MAX_DATA_SCOPES],
        }
    }

    #[test]
    fn create_record_roundtrips_with_reserved_bytes_zero() {
        let args = args();
        let encoded = args.encode().unwrap();
        let decoded = LaunchCreateArgs::decode(&encoded).unwrap();
        assert_eq!(decoded.sandbox, args.sandbox);
        assert_eq!(decoded.root, args.root);
        assert_eq!(decoded.image, args.image);
        assert_eq!(decoded.volume, args.volume);
        assert_eq!(decoded.capabilities, args.capabilities);
        assert_eq!(decoded.resources, args.resources);
        assert_eq!(decoded.device_count, args.device_count);
        assert_eq!(decoded.data_count, args.data_count);
        assert_eq!(decoded.used_devices(), args.used_devices());
        assert_eq!(decoded.used_data(), args.used_data());
        assert_eq!(encoded.len(), CREATE_BYTES);
        for at in [6, 7, 94, 95, 150] {
            let mut bad = encoded;
            bad[at] = 1;
            assert_eq!(LaunchCreateArgs::decode(&bad), None);
        }
    }

    #[test]
    fn info_contains_only_identity_resources_and_policy_facts() {
        let args = args();
        let key = LaunchPlanKey::from_raw((11u64 << 16) | 12).unwrap();
        let encoded = LaunchPlanInfo {
            key,
            sandbox: args.sandbox,
            root: args.root.unwrap(),
            image: args.image,
            volume: args.volume,
            root_capabilities: args.root_capabilities,
            capabilities: args.capabilities,
            resources: args.resources,
            network_policy: None,
            devices: args.device_count,
            data_scopes: args.data_count,
            data_writable_mask: 1,
        }
        .encode();
        assert_eq!(&encoded[0..4], b"JSL1");
        assert_eq!(read_u16(&encoded, 4), Some(VERSION));
        assert_eq!(read_u64(&encoded, 8), Some(key.to_raw()));
        assert_eq!(read_u64(&encoded, 40), Some(args.volume.unwrap().to_raw()));
        assert_eq!(read_u16(&encoded, 100), Some(1));
        assert_eq!(&encoded[76..80], &[0; 4]);
    }
}
