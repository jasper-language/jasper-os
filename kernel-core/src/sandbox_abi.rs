//! Versioned native Sandbox user-ABI records.
//!
//! Sandbox creation consumes the existing Workload create descriptor. The
//! Sandbox query record intentionally exposes only its stable identity and the
//! root Workload's current state; limits, usage, domain and children remain
//! Workload facts.
//!
//! 原生 Sandbox 用户 ABI。创建复用 Workload 描述符；查询记录只暴露稳定的
//! Sandbox 标识与 root Workload 的实时状态，限额、使用量、安全域和子级
//! 仍由 Workload 唯一拥有。

use crate::sandbox::{SandboxKey, SandboxSnapshot};
use crate::workload::WorkloadState;

pub const MAGIC: u32 = u32::from_le_bytes(*b"JSB1");
pub const VERSION: u16 = 1;
pub const INFO_BYTES: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SandboxInfo {
    pub key: SandboxKey,
    pub state: WorkloadState,
}

impl SandboxInfo {
    pub const fn from_snapshot(snapshot: SandboxSnapshot) -> Self {
        Self {
            key: snapshot.key,
            state: snapshot.state,
        }
    }

    pub fn encode(self) -> [u8; INFO_BYTES] {
        let mut out = [0u8; INFO_BYTES];
        out[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        out[4..6].copy_from_slice(&VERSION.to_le_bytes());
        out[6] = encode_state(self.state);
        out[8..16].copy_from_slice(&self.key.to_raw().to_le_bytes());
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::SandboxTable;
    use crate::security_domain::DomainKey;
    use crate::workload::{ResourceLimits, WorkloadTable};

    const LIMITS: ResourceLimits = ResourceLimits {
        cpu_permille: 250,
        memory_bytes: 16 * 1024,
        threads: 4,
        ring_entries: 8,
        io_bytes: 64 * 1024,
        io_ops: 32,
    };

    #[test]
    fn sandbox_info_contains_only_identity_and_live_state() {
        let mut workloads = WorkloadTable::<2>::new();
        let mut sandboxes = SandboxTable::<1>::new();
        let domain = DomainKey {
            id: 41,
            generation: 3,
        };
        let key = sandboxes.create(&mut workloads, domain, LIMITS).unwrap();
        sandboxes.mark_ready(&mut workloads, key).unwrap();
        sandboxes.start(&mut workloads, key).unwrap();

        let snapshot = sandboxes.snapshot(&workloads, key).unwrap();
        let encoded = SandboxInfo::from_snapshot(snapshot).encode();
        assert_eq!(&encoded[0..4], b"JSB1");
        assert_eq!(u16::from_le_bytes([encoded[4], encoded[5]]), VERSION);
        assert_eq!(encoded[6], 3);
        assert_eq!(encoded[7], 0);
        assert_eq!(
            SandboxKey::from_raw(u64::from_le_bytes(
                encoded[8..16].try_into().expect("fixed key field")
            )),
            Some(key)
        );
        assert_eq!(encoded.len(), INFO_BYTES);
    }
}
