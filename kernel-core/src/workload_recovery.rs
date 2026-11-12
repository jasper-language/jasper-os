//! Bounded OOM selection, member-exit and crash-recovery contracts.
//!
//! This module contains policy and preflight logic only. It never executes a
//! Process kill, writes to a device, or invents a terminal Workload state.
//! Callers must submit OOM victims to the normal member-exit path and release
//! resources before `finish_stop` can publish `Stopped`.
//!
//! 有界 OOM 选择、成员退出与崩溃恢复契约。本模块只做策略和预检，不执行
//! Process 终止、不写设备、不伪造终态。调用者必须通过正常成员退出路径处理
//! OOM victim，并在资源归还后才能由 `finish_stop` 发布 `Stopped`。

use crate::security_domain::DomainKey;
use crate::workload::{ResourceUsage, WorkloadKey, WorkloadMembers, WorkloadState, WorkloadTable};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryError {
    InvalidRoot,
    InvalidCandidate,
    CrossDomain,
    DuplicateCandidate,
    InvalidState,
    InsufficientReclaim,
    Capacity,
    InvalidMember,
    MembersRemain,
    ResourcesRemain,
    ChildrenRemain,
}

impl RecoveryError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidRoot => "system.workload.recovery.error.root",
            Self::InvalidCandidate => "system.workload.recovery.error.candidate",
            Self::CrossDomain => "system.workload.recovery.error.domain",
            Self::DuplicateCandidate => "system.workload.recovery.error.duplicate",
            Self::InvalidState => "system.workload.recovery.error.state",
            Self::InsufficientReclaim => "system.workload.recovery.error.insufficient",
            Self::Capacity => "system.workload.recovery.error.capacity",
            Self::InvalidMember => "system.workload.recovery.error.member",
            Self::MembersRemain => "system.workload.recovery.error.members_remain",
            Self::ResourcesRemain => "system.workload.recovery.error.resources_remain",
            Self::ChildrenRemain => "system.workload.recovery.error.children_remain",
        }
    }
}

/// Caller-provided victim facts. Resource usage and tree membership are
/// revalidated against the Workload table before any victim is selected.
///
/// 调用者提供的 victim 事实；选择前会从 Workload 表重新校验资源用量和树归属。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OomCandidate {
    pub workload: WorkloadKey,
    /// Larger means more expendable. Critical candidates are never selected.
    pub oom_score: u8,
    pub reclaimable_bytes: u64,
    pub critical: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OomVictim {
    pub workload: WorkloadKey,
    pub oom_score: u8,
    pub reclaimable_bytes: u64,
    pub depth: u16,
}

/// Failure-atomic bounded OOM plan.
///
/// 失败原子的有界 OOM 计划。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OomPlan<const N: usize> {
    victims: [Option<OomVictim>; N],
    len: usize,
    reclaimable_bytes: u64,
}

impl<const N: usize> OomPlan<N> {
    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub const fn reclaimable_bytes(&self) -> u64 {
        self.reclaimable_bytes
    }

    pub fn victim(&self, index: usize) -> Option<OomVictim> {
        self.victims.get(index).copied().flatten()
    }
}

/// Select an ordered, bounded OOM plan inside one Workload tree.
///
/// Validation is completed before the plan is returned. Cross-domain, root,
/// duplicate, non-Running, over-claimed and critical candidates cannot produce
/// a partial plan. Ordering is deterministic: score, reclaim, depth, key.
///
/// 在一个 Workload 树内选择有序、有界 OOM 计划。返回前完成全部校验；
/// 跨域、root、重复、非 Running、超额声明和 critical candidate 都不会产生
/// 部分计划。排序依次为 score、可回收量、深度和 key。
pub fn plan_oom<const W: usize, const N: usize>(
    table: &WorkloadTable<W>,
    root: WorkloadKey,
    required_bytes: u64,
    candidates: &[OomCandidate],
) -> Result<OomPlan<N>, RecoveryError> {
    let root_snapshot = table
        .snapshot(root)
        .map_err(|_| RecoveryError::InvalidRoot)?;
    if root_snapshot.state != WorkloadState::Running {
        return Err(RecoveryError::InvalidRoot);
    }
    if required_bytes == 0 {
        return Ok(OomPlan {
            victims: [None; N],
            len: 0,
            reclaimable_bytes: 0,
        });
    }

    let mut available = 0u64;
    for (index, candidate) in candidates.iter().enumerate() {
        if candidates[..index]
            .iter()
            .any(|previous| previous.workload == candidate.workload)
        {
            return Err(RecoveryError::DuplicateCandidate);
        }
        let snapshot = table
            .snapshot(candidate.workload)
            .map_err(|_| RecoveryError::InvalidCandidate)?;
        if candidate.workload == root {
            return Err(RecoveryError::InvalidCandidate);
        }
        if snapshot.domain != root_snapshot.domain {
            return Err(RecoveryError::CrossDomain);
        }
        if !descends_from(table, root, candidate.workload)? {
            return Err(RecoveryError::InvalidCandidate);
        }
        if snapshot.state != WorkloadState::Running
            || candidate.reclaimable_bytes > snapshot.usage.memory_bytes
        {
            return Err(RecoveryError::InvalidCandidate);
        }
        if !candidate.critical {
            available = available
                .checked_add(candidate.reclaimable_bytes)
                .ok_or(RecoveryError::InsufficientReclaim)?;
        }
    }
    if available < required_bytes {
        return Err(RecoveryError::InsufficientReclaim);
    }

    let mut plan = OomPlan {
        victims: [None; N],
        len: 0,
        reclaimable_bytes: 0,
    };
    while plan.reclaimable_bytes < required_bytes {
        let next = select_next_oom(table, root, candidates, &plan)?;
        if plan.len == N {
            return Err(RecoveryError::Capacity);
        }
        plan.victims[plan.len] = Some(next);
        plan.len += 1;
        plan.reclaimable_bytes = plan
            .reclaimable_bytes
            .checked_add(next.reclaimable_bytes)
            .ok_or(RecoveryError::InsufficientReclaim)?;
    }
    Ok(plan)
}

fn select_next_oom<const W: usize, const N: usize>(
    table: &WorkloadTable<W>,
    root: WorkloadKey,
    candidates: &[OomCandidate],
    plan: &OomPlan<N>,
) -> Result<OomVictim, RecoveryError> {
    let mut best: Option<OomVictim> = None;
    for candidate in candidates {
        if candidate.critical
            || candidate.reclaimable_bytes == 0
            || (0..plan.len)
                .filter_map(|index| plan.victim(index))
                .any(|victim| victim.workload == candidate.workload)
        {
            continue;
        }
        let snapshot = table
            .snapshot(candidate.workload)
            .map_err(|_| RecoveryError::InvalidCandidate)?;
        if snapshot.state != WorkloadState::Running
            || candidate.reclaimable_bytes > snapshot.usage.memory_bytes
            || !descends_from(table, root, candidate.workload)?
        {
            return Err(RecoveryError::InvalidCandidate);
        }
        let victim = OomVictim {
            workload: candidate.workload,
            oom_score: candidate.oom_score,
            reclaimable_bytes: candidate.reclaimable_bytes,
            depth: tree_depth(table, candidate.workload)?,
        };
        if best.is_none_or(|current| oom_precedes(victim, current)) {
            best = Some(victim);
        }
    }
    best.ok_or(RecoveryError::InsufficientReclaim)
}

fn oom_precedes(left: OomVictim, right: OomVictim) -> bool {
    left.oom_score > right.oom_score
        || (left.oom_score == right.oom_score
            && (left.reclaimable_bytes > right.reclaimable_bytes
                || (left.reclaimable_bytes == right.reclaimable_bytes
                    && (left.depth > right.depth
                        || (left.depth == right.depth
                            && left.workload.to_raw() < right.workload.to_raw())))))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExitProgress {
    pub remaining_members: usize,
    pub resources_drained: bool,
    pub children_drained: bool,
    pub terminal: bool,
}

/// Detach one exited member and report, but do not publish, completion.
///
/// 解除一个已退出成员的绑定并报告完成条件；不会在此处发布终态。
pub fn note_member_exit<const W: usize, const M: usize>(
    table: &WorkloadTable<W>,
    members: &mut WorkloadMembers<M>,
    workload: WorkloadKey,
    member: u64,
) -> Result<ExitProgress, RecoveryError> {
    let attached = members.get(member).ok_or(RecoveryError::InvalidMember)?;
    if attached.workload != workload {
        return Err(RecoveryError::InvalidMember);
    }
    members
        .detach(workload, member)
        .map_err(|_| RecoveryError::InvalidMember)?;
    exit_progress(table, members, workload)
}

/// Publish `Stopped` only after members, resources and child Workloads are gone.
///
/// 只在成员、资源和子 Workload 全部归零后发布 `Stopped`。
pub fn finish_stop<const W: usize, const M: usize>(
    table: &mut WorkloadTable<W>,
    members: &WorkloadMembers<M>,
    workload: WorkloadKey,
) -> Result<ExitProgress, RecoveryError> {
    let progress = exit_progress(table, members, workload)?;
    let snapshot = table
        .snapshot(workload)
        .map_err(|_| RecoveryError::InvalidRoot)?;
    match snapshot.state {
        WorkloadState::Stopped => return Ok(progress),
        WorkloadState::Stopping => {}
        _ => return Err(RecoveryError::InvalidState),
    }
    if progress.remaining_members != 0 {
        return Err(RecoveryError::MembersRemain);
    }
    if !progress.resources_drained {
        return Err(RecoveryError::ResourcesRemain);
    }
    if !progress.children_drained {
        return Err(RecoveryError::ChildrenRemain);
    }
    table
        .transition(workload, WorkloadState::Stopped)
        .map_err(|_| RecoveryError::InvalidState)?;
    Ok(ExitProgress {
        terminal: true,
        ..progress
    })
}

fn exit_progress<const W: usize, const M: usize>(
    table: &WorkloadTable<W>,
    members: &WorkloadMembers<M>,
    workload: WorkloadKey,
) -> Result<ExitProgress, RecoveryError> {
    let snapshot = table
        .snapshot(workload)
        .map_err(|_| RecoveryError::InvalidRoot)?;
    Ok(ExitProgress {
        remaining_members: members.count_for(workload),
        resources_drained: snapshot.usage == ResourceUsage::default(),
        children_drained: snapshot.children == 0,
        terminal: snapshot.state.terminal(),
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrashTarget {
    pub workload: WorkloadKey,
    pub member_count: usize,
}

/// Bounded crash plan. Descendants are ordered deepest-first and root is last.
///
/// 有界崩溃计划；后代按深度倒序，root 最后。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrashPlan<const N: usize> {
    targets: [Option<CrashTarget>; N],
    len: usize,
}

impl<const N: usize> CrashPlan<N> {
    pub const fn len(&self) -> usize {
        self.len
    }

    pub fn target(&self, index: usize) -> Option<CrashTarget> {
        self.targets.get(index).copied().flatten()
    }
}

/// Preflight a root crash across an explicit bounded set of descendant keys.
///
/// 在一组显式、有界的后代 key 上预检 root 崩溃；任何跨树、跨域或终态目标
/// 都使整份计划失败。
pub fn plan_root_crash<const W: usize, const M: usize, const N: usize>(
    table: &WorkloadTable<W>,
    members: &WorkloadMembers<M>,
    root: WorkloadKey,
    descendants: &[WorkloadKey],
) -> Result<CrashPlan<N>, RecoveryError> {
    if descendants.len() >= N {
        return Err(RecoveryError::Capacity);
    }
    let root_snapshot = table
        .snapshot(root)
        .map_err(|_| RecoveryError::InvalidRoot)?;
    if root_snapshot.state.terminal() {
        return Err(RecoveryError::InvalidRoot);
    }
    for (index, candidate) in descendants.iter().enumerate() {
        if descendants[..index].contains(candidate) || *candidate == root {
            return Err(RecoveryError::DuplicateCandidate);
        }
        let snapshot = table
            .snapshot(*candidate)
            .map_err(|_| RecoveryError::InvalidCandidate)?;
        if snapshot.domain != root_snapshot.domain {
            return Err(RecoveryError::CrossDomain);
        }
        if !descends_from(table, root, *candidate)? || snapshot.state.terminal() {
            return Err(RecoveryError::InvalidCandidate);
        }
    }
    let mut plan = CrashPlan {
        targets: [None; N],
        len: 0,
    };
    while plan.len < descendants.len() {
        let next = descendants
            .iter()
            .filter(|candidate| {
                !(0..plan.len)
                    .filter_map(|index| plan.target(index))
                    .any(|target| target.workload == **candidate)
            })
            .max_by_key(|candidate| {
                (
                    tree_depth(table, **candidate).unwrap_or(0),
                    core::cmp::Reverse((*candidate).to_raw()),
                )
            })
            .copied()
            .ok_or(RecoveryError::InvalidCandidate)?;
        let depth = tree_depth(table, next)?;
        debug_assert!(depth != 0);
        plan.targets[plan.len] = Some(CrashTarget {
            workload: next,
            member_count: members.count_for(next),
        });
        plan.len += 1;
    }
    plan.targets[plan.len] = Some(CrashTarget {
        workload: root,
        member_count: members.count_for(root),
    });
    plan.len += 1;
    Ok(plan)
}

/// Apply a preflighted crash plan after revalidating every target.
///
/// 重新校验所有目标后应用已预检的崩溃计划；不会发布 `Stopped`。
pub fn apply_root_crash<const W: usize, const N: usize>(
    table: &mut WorkloadTable<W>,
    plan: &CrashPlan<N>,
) -> Result<(), RecoveryError> {
    for index in 0..plan.len {
        let target = plan.target(index).ok_or(RecoveryError::InvalidCandidate)?;
        let snapshot = table
            .snapshot(target.workload)
            .map_err(|_| RecoveryError::InvalidCandidate)?;
        if snapshot.state.terminal() {
            return Err(RecoveryError::InvalidState);
        }
    }
    for index in 0..plan.len {
        let target = plan.target(index).ok_or(RecoveryError::InvalidCandidate)?;
        table
            .transition(target.workload, WorkloadState::Failed)
            .map_err(|_| RecoveryError::InvalidState)?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoverySnapshot {
    pub failed_root: WorkloadKey,
    pub replacement: Option<WorkloadKey>,
    pub domain: DomainKey,
    pub remaining_members: usize,
    pub resources_drained: bool,
    pub children_drained: bool,
    pub replacement_running: bool,
    pub publishable: bool,
}

/// Revalidate crash restart without copying Workload state.
///
/// 不复制 Workload 状态地重新校验崩溃重启；replacement 必须同域、Running
/// 且使用新 key，旧 root 必须 Failed 且成员、资源和子级全部排空。
pub fn recovery_snapshot<const W: usize, const M: usize>(
    table: &WorkloadTable<W>,
    members: &WorkloadMembers<M>,
    failed_root: WorkloadKey,
    replacement: Option<WorkloadKey>,
) -> Result<RecoverySnapshot, RecoveryError> {
    let old = table
        .snapshot(failed_root)
        .map_err(|_| RecoveryError::InvalidRoot)?;
    if old.state != WorkloadState::Failed {
        return Err(RecoveryError::InvalidState);
    }
    let remaining_members = members.count_for(failed_root);
    let resources_drained = old.usage == ResourceUsage::default();
    let children_drained = old.children == 0;
    let replacement_running = match replacement {
        Some(key) if key != failed_root => {
            let new = table
                .snapshot(key)
                .map_err(|_| RecoveryError::InvalidCandidate)?;
            if new.domain != old.domain {
                return Err(RecoveryError::CrossDomain);
            }
            new.state == WorkloadState::Running
        }
        Some(_) => return Err(RecoveryError::InvalidCandidate),
        None => false,
    };
    Ok(RecoverySnapshot {
        failed_root,
        replacement,
        domain: old.domain,
        remaining_members,
        resources_drained,
        children_drained,
        replacement_running,
        publishable: replacement_running
            && remaining_members == 0
            && resources_drained
            && children_drained,
    })
}

fn descends_from<const W: usize>(
    table: &WorkloadTable<W>,
    root: WorkloadKey,
    candidate: WorkloadKey,
) -> Result<bool, RecoveryError> {
    if candidate == root {
        return Ok(false);
    }
    let mut current = table
        .snapshot(candidate)
        .map_err(|_| RecoveryError::InvalidCandidate)?
        .parent;
    for _ in 0..W {
        match current {
            Some(key) if key == root => return Ok(true),
            Some(key) => {
                current = table
                    .snapshot(key)
                    .map_err(|_| RecoveryError::InvalidCandidate)?
                    .parent
            }
            None => return Ok(false),
        }
    }
    Err(RecoveryError::InvalidCandidate)
}

fn tree_depth<const W: usize>(
    table: &WorkloadTable<W>,
    workload: WorkloadKey,
) -> Result<u16, RecoveryError> {
    let mut current = Some(workload);
    let mut depth = 0u16;
    for _ in 0..W {
        let Some(key) = current else {
            return Ok(depth);
        };
        depth = depth.checked_add(1).ok_or(RecoveryError::Capacity)?;
        current = table
            .snapshot(key)
            .map_err(|_| RecoveryError::InvalidCandidate)?
            .parent;
    }
    Err(RecoveryError::InvalidCandidate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workload::ResourceLimits;

    const DOMAIN: DomainKey = DomainKey {
        id: 3,
        generation: 4,
    };
    const LIMITS: ResourceLimits = ResourceLimits {
        cpu_permille: 1000,
        memory_bytes: 16 * 1024,
        threads: 8,
        ring_entries: 16,
        io_bytes: 64 * 1024,
        io_ops: 64,
    };

    fn running(table: &mut WorkloadTable<8>, domain: DomainKey) -> WorkloadKey {
        let key = table.create(domain, LIMITS).unwrap();
        table.transition(key, WorkloadState::Ready).unwrap();
        table.transition(key, WorkloadState::Running).unwrap();
        key
    }

    #[test]
    fn oom_plan_rejects_cross_domain_root_and_critical_candidates() {
        let mut table = WorkloadTable::<8>::new();
        let root = running(&mut table, DOMAIN);
        let victim = table.create_child(root, LIMITS).unwrap();
        table.transition(victim, WorkloadState::Ready).unwrap();
        table.transition(victim, WorkloadState::Running).unwrap();
        table
            .charge(
                victim,
                ResourceUsage {
                    memory_bytes: 4096,
                    threads: 1,
                    ring_entries: 0,
                },
            )
            .unwrap();
        let foreign = running(
            &mut table,
            DomainKey {
                id: 9,
                generation: 4,
            },
        );

        assert_eq!(
            plan_oom::<8, 4>(
                &table,
                root,
                1,
                &[OomCandidate {
                    workload: foreign,
                    oom_score: 255,
                    reclaimable_bytes: 4096,
                    critical: false,
                }]
            )
            .unwrap_err(),
            RecoveryError::CrossDomain
        );
        assert_eq!(
            plan_oom::<8, 4>(
                &table,
                root,
                1,
                &[OomCandidate {
                    workload: root,
                    oom_score: 255,
                    reclaimable_bytes: 4096,
                    critical: false,
                }]
            )
            .unwrap_err(),
            RecoveryError::InvalidCandidate
        );
        assert_eq!(
            plan_oom::<8, 4>(
                &table,
                root,
                1,
                &[OomCandidate {
                    workload: victim,
                    oom_score: 255,
                    reclaimable_bytes: 4096,
                    critical: true,
                }]
            )
            .unwrap_err(),
            RecoveryError::InsufficientReclaim
        );
    }

    #[test]
    fn oom_output_is_deterministic_depth_first_and_failure_atomic() {
        let mut table = WorkloadTable::<8>::new();
        let root = running(&mut table, DOMAIN);
        let child = table
            .create_child(
                root,
                ResourceLimits {
                    cpu_permille: 400,
                    ..LIMITS
                },
            )
            .unwrap();
        table.transition(child, WorkloadState::Ready).unwrap();
        table.transition(child, WorkloadState::Running).unwrap();
        let grandchild = table
            .create_child(
                child,
                ResourceLimits {
                    cpu_permille: 400,
                    ..LIMITS
                },
            )
            .unwrap();
        table.transition(grandchild, WorkloadState::Ready).unwrap();
        table
            .transition(grandchild, WorkloadState::Running)
            .unwrap();
        let sibling = table
            .create_child(
                root,
                ResourceLimits {
                    cpu_permille: 400,
                    ..LIMITS
                },
            )
            .unwrap();
        table.transition(sibling, WorkloadState::Ready).unwrap();
        table.transition(sibling, WorkloadState::Running).unwrap();
        for key in [child, grandchild, sibling] {
            table
                .charge(
                    key,
                    ResourceUsage {
                        memory_bytes: 2048,
                        threads: 1,
                        ring_entries: 0,
                    },
                )
                .unwrap();
        }
        let candidates = [
            OomCandidate {
                workload: sibling,
                oom_score: 50,
                reclaimable_bytes: 2048,
                critical: false,
            },
            OomCandidate {
                workload: child,
                oom_score: 50,
                reclaimable_bytes: 2048,
                critical: false,
            },
            OomCandidate {
                workload: grandchild,
                oom_score: 50,
                reclaimable_bytes: 2048,
                critical: false,
            },
        ];
        let plan = plan_oom::<8, 3>(&table, root, 3000, &candidates).unwrap();
        assert_eq!(plan.len(), 2);
        assert_eq!(plan.reclaimable_bytes(), 4096);
        assert_eq!(
            plan.victim(0).unwrap().workload.to_raw(),
            grandchild.to_raw()
        );
        assert_eq!(plan.victim(1).unwrap().workload.to_raw(), child.to_raw());

        assert_eq!(
            plan_oom::<8, 1>(&table, root, 3000, &candidates).unwrap_err(),
            RecoveryError::Capacity
        );
        assert_eq!(
            table.snapshot(grandchild).unwrap().state,
            WorkloadState::Running
        );
    }

    #[test]
    fn member_exit_never_skips_resource_or_child_drain() {
        let mut table = WorkloadTable::<8>::new();
        let root = running(&mut table, DOMAIN);
        let usage = ResourceUsage {
            memory_bytes: 4096,
            threads: 1,
            ring_entries: 0,
        };
        table.charge(root, usage).unwrap();
        table.transition(root, WorkloadState::Stopping).unwrap();
        let mut members = WorkloadMembers::<4>::new();
        assert_eq!(
            members.attach(&table, root, 41),
            Err(crate::workload::MembershipError::NotRunning)
        );

        let mut member_table = WorkloadTable::<8>::new();
        let member_root = running(&mut member_table, DOMAIN);
        let mut members = WorkloadMembers::<4>::new();
        members.attach(&member_table, member_root, 41).unwrap();
        members.attach(&member_table, member_root, 42).unwrap();
        member_table
            .charge(
                member_root,
                ResourceUsage {
                    memory_bytes: 4096,
                    threads: 1,
                    ring_entries: 0,
                },
            )
            .unwrap();
        member_table
            .transition(member_root, WorkloadState::Stopping)
            .unwrap();
        let progress = note_member_exit(&member_table, &mut members, member_root, 41).unwrap();
        assert_eq!(progress.remaining_members, 1);
        assert_eq!(
            finish_stop(&mut member_table, &members, member_root),
            Err(RecoveryError::MembersRemain)
        );
        let progress = note_member_exit(&member_table, &mut members, member_root, 42).unwrap();
        assert_eq!(progress.remaining_members, 0);
        assert!(!progress.resources_drained);
        assert_eq!(
            finish_stop(&mut member_table, &members, member_root),
            Err(RecoveryError::ResourcesRemain)
        );
        member_table
            .release(
                member_root,
                ResourceUsage {
                    memory_bytes: 4096,
                    threads: 1,
                    ring_entries: 0,
                },
            )
            .unwrap();
        assert!(
            finish_stop(&mut member_table, &members, member_root)
                .unwrap()
                .terminal
        );
        assert_eq!(
            member_table.snapshot(member_root).unwrap().state,
            WorkloadState::Stopped
        );
    }

    #[test]
    fn crash_plan_is_tree_local_ordered_and_keeps_resources_for_cleanup() {
        let mut table = WorkloadTable::<8>::new();
        let root = running(&mut table, DOMAIN);
        let child = table.create_child(root, LIMITS).unwrap();
        table.transition(child, WorkloadState::Ready).unwrap();
        table.transition(child, WorkloadState::Running).unwrap();
        let grandchild = table.create_child(child, LIMITS).unwrap();
        table.transition(grandchild, WorkloadState::Ready).unwrap();
        table
            .transition(grandchild, WorkloadState::Running)
            .unwrap();
        let mut members = WorkloadMembers::<4>::new();
        members.attach(&table, grandchild, 77).unwrap();
        table
            .charge(
                grandchild,
                ResourceUsage {
                    memory_bytes: 4096,
                    threads: 1,
                    ring_entries: 0,
                },
            )
            .unwrap();

        let plan =
            plan_root_crash::<8, 4, 4>(&table, &members, root, &[child, grandchild]).unwrap();
        assert_eq!(plan.len(), 3);
        assert_eq!(
            plan.target(0).unwrap().workload.to_raw(),
            grandchild.to_raw()
        );
        assert_eq!(plan.target(1).unwrap().workload.to_raw(), child.to_raw());
        assert_eq!(plan.target(2).unwrap().workload.to_raw(), root.to_raw());
        apply_root_crash(&mut table, &plan).unwrap();
        assert_eq!(table.snapshot(root).unwrap().state, WorkloadState::Failed);
        assert_ne!(
            table.snapshot(grandchild).unwrap().usage,
            ResourceUsage::default()
        );
        assert_eq!(members.count_for(grandchild), 1);
    }

    #[test]
    fn recovery_requires_same_domain_new_key_and_full_old_drain() {
        let mut table = WorkloadTable::<8>::new();
        let root = running(&mut table, DOMAIN);
        let mut members = WorkloadMembers::<4>::new();
        members.attach(&table, root, 9).unwrap();
        table
            .charge(
                root,
                ResourceUsage {
                    memory_bytes: 4096,
                    threads: 1,
                    ring_entries: 0,
                },
            )
            .unwrap();
        table.transition(root, WorkloadState::Failed).unwrap();
        let replacement = running(&mut table, DOMAIN);
        let snapshot = recovery_snapshot(&table, &members, root, Some(replacement)).unwrap();
        assert!(!snapshot.publishable);
        assert_eq!(snapshot.remaining_members, 1);

        let foreign = running(
            &mut table,
            DomainKey {
                id: 8,
                generation: 4,
            },
        );
        assert_eq!(
            recovery_snapshot(&table, &members, root, Some(foreign)).unwrap_err(),
            RecoveryError::CrossDomain
        );
        assert_eq!(
            recovery_snapshot(&table, &members, root, Some(root)).unwrap_err(),
            RecoveryError::InvalidCandidate
        );
    }
}
