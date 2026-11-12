//! Versioned native Workload user-ABI descriptors.
//!
//! 原生 Workload 用户 ABI 的版本化定长描述符。DomainKey 不来自用户输入；
//! 内核从调用者身份取得权威域并插入由内核管理的 Workload 对象。

use crate::workload::{
    ResourceLimits, ResourceUsage, WorkloadKey, WorkloadSnapshot, WorkloadState,
};

pub const MAGIC: u32 = u32::from_le_bytes(*b"JWL1");
pub const VERSION: u16 = 1;
pub const CREATE_BYTES: usize = 40;
pub const INFO_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateArgs {
    pub parent: Option<WorkloadKey>,
    pub limits: ResourceLimits,
}

impl CreateArgs {
    pub fn encode(self) -> [u8; CREATE_BYTES] {
        let mut out = [0u8; CREATE_BYTES];
        out[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        out[4..6].copy_from_slice(&VERSION.to_le_bytes());
        out[8..16].copy_from_slice(&self.parent.map_or(0, WorkloadKey::to_raw).to_le_bytes());
        out[16..20].copy_from_slice(&self.limits.cpu_permille.to_le_bytes());
        out[20..24].copy_from_slice(&self.limits.threads.to_le_bytes());
        out[24..32].copy_from_slice(&self.limits.memory_bytes.to_le_bytes());
        out[32..36].copy_from_slice(&self.limits.ring_entries.to_le_bytes());
        out
    }

    pub fn decode(raw: &[u8; CREATE_BYTES]) -> Option<Self> {
        if read_u32(raw, 0)? != MAGIC
            || read_u16(raw, 4)? != VERSION
            || read_u16(raw, 6)? != 0
            || read_u32(raw, 36)? != 0
        {
            return None;
        }
        let parent_raw = read_u64(raw, 8)?;
        let parent = if parent_raw == 0 {
            None
        } else {
            Some(WorkloadKey::from_raw(parent_raw)?)
        };
        Some(Self {
            parent,
            limits: ResourceLimits {
                cpu_permille: read_u32(raw, 16)?,
                threads: read_u32(raw, 20)?,
                memory_bytes: read_u64(raw, 24)?,
                ring_entries: read_u32(raw, 32)?,
            },
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkloadInfo {
    pub key: WorkloadKey,
    pub parent: Option<WorkloadKey>,
    pub state: WorkloadState,
    pub limits: ResourceLimits,
    pub usage: ResourceUsage,
    pub children: u16,
}

impl WorkloadInfo {
    pub const fn from_snapshot(snapshot: WorkloadSnapshot) -> Self {
        Self {
            key: snapshot.key,
            parent: snapshot.parent,
            state: snapshot.state,
            limits: snapshot.limits,
            usage: snapshot.usage,
            children: snapshot.children,
        }
    }

    pub fn encode(self) -> [u8; INFO_BYTES] {
        let mut out = [0u8; INFO_BYTES];
        out[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        out[4..6].copy_from_slice(&VERSION.to_le_bytes());
        out[6] = encode_state(self.state);
        out[8..16].copy_from_slice(&self.key.to_raw().to_le_bytes());
        out[16..24].copy_from_slice(&self.parent.map_or(0, WorkloadKey::to_raw).to_le_bytes());
        out[24..28].copy_from_slice(&self.limits.cpu_permille.to_le_bytes());
        out[28..32].copy_from_slice(&self.limits.threads.to_le_bytes());
        out[32..40].copy_from_slice(&self.limits.memory_bytes.to_le_bytes());
        out[40..44].copy_from_slice(&self.limits.ring_entries.to_le_bytes());
        out[44..48].copy_from_slice(&(self.children as u32).to_le_bytes());
        out[48..56].copy_from_slice(&self.usage.memory_bytes.to_le_bytes());
        out[56..60].copy_from_slice(&self.usage.threads.to_le_bytes());
        out[60..64].copy_from_slice(&self.usage.ring_entries.to_le_bytes());
        out
    }
}

const fn encode_state(state: WorkloadState) -> u8 {
    match state {
        WorkloadState::Created => 1,
        WorkloadState::Ready => 2,
        WorkloadState::Running => 3,
        WorkloadState::Stopping => 4,
        WorkloadState::Stopped => 5,
        WorkloadState::Failed => 6,
    }
}

fn read_u16(raw: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        raw.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32(raw: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        raw.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u64(raw: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        raw.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security_domain::DomainKey;
    use crate::workload::{WorkloadState, WorkloadTable};

    const LIMITS: ResourceLimits = ResourceLimits {
        cpu_permille: 250,
        memory_bytes: 16 * 1024,
        threads: 4,
        ring_entries: 8,
    };

    #[test]
    fn create_descriptor_round_trip_is_strict() {
        let mut table = WorkloadTable::<2>::new();
        let parent = table
            .create(
                DomainKey {
                    id: 9,
                    generation: 2,
                },
                LIMITS,
            )
            .unwrap();
        let args = CreateArgs {
            parent: Some(parent),
            limits: LIMITS,
        };
        let encoded = args.encode();
        assert_eq!(CreateArgs::decode(&encoded), Some(args));

        for offset in [0usize, 4, 6, 36] {
            let mut invalid = encoded;
            invalid[offset] ^= 0x80;
            assert_eq!(CreateArgs::decode(&invalid), None);
        }
    }

    #[test]
    fn query_record_is_stable_and_contains_no_domain() {
        let mut table = WorkloadTable::<1>::new();
        let key = table
            .create(
                DomainKey {
                    id: 9,
                    generation: 2,
                },
                LIMITS,
            )
            .unwrap();
        table.transition(key, WorkloadState::Ready).unwrap();
        let info = WorkloadInfo::from_snapshot(table.snapshot(key).unwrap());
        let encoded = info.encode();
        assert_eq!(read_u32(&encoded, 0), Some(MAGIC));
        assert_eq!(read_u16(&encoded, 4), Some(VERSION));
        assert_eq!(read_u64(&encoded, 8), Some(key.to_raw()));
        assert_eq!(read_u32(&encoded, 24), Some(LIMITS.cpu_permille));
        assert_eq!(encoded[6], 2);
    }
}
