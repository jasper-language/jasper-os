//! Native sandbox identity over one root Workload.
//!
//! A sandbox owns exactly one root Workload. Its lifecycle, security domain,
//! limits, usage and children remain Workload facts; this module stores only
//! the stable sandbox generation and the root binding.
//!
//! 原生 Sandbox 只拥有一个 root Workload；生命周期、安全域、限额、使用量和
//! 子级仍是 Workload 的唯一事实。本模块只保存稳定的 Sandbox 世代和 root 绑定。

use crate::security_domain::DomainKey;
use crate::workload::{
    ResourceLimits, WorkloadError, WorkloadKey, WorkloadSnapshot, WorkloadState, WorkloadTable,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SandboxKey {
    slot: u16,
    generation: u32,
}

impl SandboxKey {
    pub const fn slot(self) -> u16 {
        self.slot
    }

    pub const fn generation(self) -> u32 {
        self.generation
    }

    /// Pack the stable sandbox generation and slot into a non-zero ABI scalar.
    ///
    /// 将稳定的 Sandbox 世代和槽位打包为非零 ABI 标量。
    pub const fn to_raw(self) -> u64 {
        ((self.generation as u64) << 16) | self.slot as u64
    }

    /// Decode a candidate identifier. The sandbox table remains authoritative.
    ///
    /// 解码候选标识；是否存活与当前世代仍以 Sandbox 表为准。
    pub const fn from_raw(raw: u64) -> Option<Self> {
        if raw == 0 || raw >> 48 != 0 || (raw >> 16) as u32 == 0 {
            return None;
        }
        Some(Self {
            slot: raw as u16,
            generation: (raw >> 16) as u32,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SandboxError {
    InvalidKey,
    InvalidRoot,
    RootAlreadyBound,
    Capacity,
    IdExhausted,
    Workload(WorkloadError),
}

impl SandboxError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidKey => "system.sandbox.error.stale",
            Self::InvalidRoot => "system.sandbox.error.root",
            Self::RootAlreadyBound => "system.sandbox.error.already_bound",
            Self::Capacity => "system.sandbox.error.capacity",
            Self::IdExhausted => "system.sandbox.error.ids_exhausted",
            Self::Workload(error) => error.name(),
        }
    }
}

impl From<WorkloadError> for SandboxError {
    fn from(error: WorkloadError) -> Self {
        Self::Workload(error)
    }
}

/// Stable identity and current lifecycle, copied from the root Workload only
/// for a bounded query result.
///
/// 仅界定的查询结果会复制 root Workload 的当前生命周期事实。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SandboxSnapshot {
    pub key: SandboxKey,
    pub root: WorkloadKey,
    pub domain: DomainKey,
    pub state: WorkloadState,
}

#[derive(Clone, Copy)]
struct Record {
    key: SandboxKey,
    root: WorkloadKey,
}

/// Fixed-capacity sandbox identity table.
///
/// A sandbox is created in `Created` and follows the root Workload's
/// `Created -> Ready -> Running -> Stopping -> Stopped/Failed` states. There
/// is no second state field. A terminal root cannot transition again, and
/// `Stopped` is admitted by Workload only after usage and children reach zero.
///
/// 固定容量的 Sandbox 身份表。Sandbox 不复制状态字段，而是完全委托 root
/// Workload；`Stopping` 时新资源和新子级均被 Workload 拒绝。
pub struct SandboxTable<const N: usize> {
    slots: [Option<Record>; N],
    generations: [u32; N],
}

impl<const N: usize> SandboxTable<N> {
    pub const fn new() -> Self {
        Self {
            slots: [None; N],
            generations: [0; N],
        }
    }

    /// Atomically create a root Workload and its stable sandbox identity.
    ///
    /// 原子创建 root Workload 与稳定 Sandbox 身份；容量不足时不会留下
    /// 未登记或无主 Workload。
    pub fn create<const W: usize>(
        &mut self,
        workloads: &mut WorkloadTable<W>,
        domain: DomainKey,
        limits: ResourceLimits,
    ) -> Result<SandboxKey, SandboxError> {
        let (slot, generation) = self.vacant()?;
        let root = workloads.create(domain, limits)?;
        let key = SandboxKey {
            slot: slot as u16,
            generation,
        };
        self.generations[slot] = generation;
        self.slots[slot] = Some(Record { key, root });
        Ok(key)
    }

    /// Bind an existing `Created` root Workload to a new stable identity.
    ///
    /// 将一个现有的 `Created` root Workload 绑定到新 Sandbox 身份。非根
    /// Workload、已终止 Workload 或已被 Sandbox 拥有的 root 均拒绝。
    pub fn adopt<const W: usize>(
        &mut self,
        workloads: &WorkloadTable<W>,
        root: WorkloadKey,
    ) -> Result<SandboxKey, SandboxError> {
        let snapshot = workloads.snapshot(root)?;
        if snapshot.parent.is_some() || snapshot.state != WorkloadState::Created {
            return Err(SandboxError::InvalidRoot);
        }
        if self.root_is_bound(root) {
            return Err(SandboxError::RootAlreadyBound);
        }
        let (slot, generation) = self.vacant()?;
        let key = SandboxKey {
            slot: slot as u16,
            generation,
        };
        self.generations[slot] = generation;
        self.slots[slot] = Some(Record { key, root });
        Ok(key)
    }

    /// Query identity and lifecycle without duplicating resource facts.
    pub fn snapshot<const W: usize>(
        &self,
        workloads: &WorkloadTable<W>,
        key: SandboxKey,
    ) -> Result<SandboxSnapshot, SandboxError> {
        let record = self.record(key)?;
        let workload = workloads.snapshot(record.root)?;
        Ok(SandboxSnapshot {
            key,
            root: record.root,
            domain: workload.domain,
            state: workload.state,
        })
    }

    /// Return the complete authoritative root Workload record.
    pub fn root_snapshot<const W: usize>(
        &self,
        workloads: &WorkloadTable<W>,
        key: SandboxKey,
    ) -> Result<WorkloadSnapshot, SandboxError> {
        let record = self.record(key)?;
        Ok(workloads.snapshot(record.root)?)
    }

    /// Advance `Created -> Ready`.
    pub fn mark_ready<const W: usize>(
        &self,
        workloads: &mut WorkloadTable<W>,
        key: SandboxKey,
    ) -> Result<(), SandboxError> {
        self.transition(workloads, key, WorkloadState::Ready)
    }

    /// Advance `Ready -> Running`.
    pub fn start<const W: usize>(
        &self,
        workloads: &mut WorkloadTable<W>,
        key: SandboxKey,
    ) -> Result<(), SandboxError> {
        self.transition(workloads, key, WorkloadState::Running)
    }

    /// Begin shutdown. Once this succeeds, Workload admission rejects new
    /// resources, child Workloads and newly started members.
    ///
    /// 开始关闭；成功后 Workload 准入门面拒绝新资源、新子级和新成员启动。
    pub fn request_stop<const W: usize>(
        &self,
        workloads: &mut WorkloadTable<W>,
        key: SandboxKey,
    ) -> Result<(), SandboxError> {
        self.transition(workloads, key, WorkloadState::Stopping)
    }

    /// Complete shutdown only after Workload usage and children are zero.
    ///
    /// 仅当 Workload 使用量与子级均归零后才完成关闭。
    pub fn complete_stop<const W: usize>(
        &self,
        workloads: &mut WorkloadTable<W>,
        key: SandboxKey,
    ) -> Result<(), SandboxError> {
        self.transition(workloads, key, WorkloadState::Stopped)
    }

    /// Enter the single failure terminal from any non-terminal state.
    ///
    /// 从任意非终态进入唯一失败终态。
    pub fn fail<const W: usize>(
        &self,
        workloads: &mut WorkloadTable<W>,
        key: SandboxKey,
    ) -> Result<(), SandboxError> {
        self.transition(workloads, key, WorkloadState::Failed)
    }

    /// Admit a child only while the sandbox root is `Running`.
    ///
    /// 仅当 Sandbox root 处于 `Running` 时准入子 Workload；`Stopping` 后
    /// 不再允许新启动。
    pub fn launch_child<const W: usize>(
        &self,
        workloads: &mut WorkloadTable<W>,
        key: SandboxKey,
        limits: ResourceLimits,
    ) -> Result<WorkloadKey, SandboxError> {
        let record = self.record(key)?;
        let state = workloads.snapshot(record.root)?.state;
        if state != WorkloadState::Running {
            return Err(WorkloadError::InvalidState.into());
        }
        Ok(workloads.create_child(record.root, limits)?)
    }

    /// Remove a terminal, fully drained sandbox after destroying its root.
    ///
    /// Workload 必须已处于终态且资源与子级归零；成功后 Sandbox 槽位可复用，
    /// 但旧身份因世代递增而永久失效。
    pub fn destroy<const W: usize>(
        &mut self,
        workloads: &mut WorkloadTable<W>,
        key: SandboxKey,
    ) -> Result<(), SandboxError> {
        let slot = key.slot as usize;
        let record = self.record(key)?;
        workloads.destroy(record.root)?;
        self.slots[slot] = None;
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn transition<const W: usize>(
        &self,
        workloads: &mut WorkloadTable<W>,
        key: SandboxKey,
        next: WorkloadState,
    ) -> Result<(), SandboxError> {
        let record = self.record(key)?;
        Ok(workloads.transition(record.root, next)?)
    }

    fn record(&self, key: SandboxKey) -> Result<Record, SandboxError> {
        self.slots
            .get(key.slot as usize)
            .and_then(|slot| *slot)
            .filter(|record| record.key == key)
            .ok_or(SandboxError::InvalidKey)
    }

    fn root_is_bound(&self, root: WorkloadKey) -> bool {
        self.slots
            .iter()
            .flatten()
            .any(|record| record.root == root)
    }

    fn vacant(&self) -> Result<(usize, u32), SandboxError> {
        let slot = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(SandboxError::Capacity)?;
        let generation = self.generations[slot]
            .checked_add(1)
            .ok_or(SandboxError::IdExhausted)?;
        Ok((slot, generation))
    }
}

impl<const N: usize> Default for SandboxTable<N> {
    fn default() -> Self {
        Self::new()
    }
}
