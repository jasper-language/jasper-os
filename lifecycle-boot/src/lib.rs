//! 双槽启动控制的持久格式、启动选择与断电恢复。
//! Persistent format, boot selection, and power-loss recovery for dual-slot boot control.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// 一份启动控制记录的固定线上长度（字节）。
/// Fixed on-wire size of one boot-control record in bytes.
pub const CONTROL_RECORD_BYTES: usize = 180;

/// P0 GPT 的固定磁盘 GUID 原始字节。
/// Raw P0 GPT disk-GUID bytes.
pub const P0_DISK_GUID: [u8; 16] = [
    0x70, 0x73, 0x61, 0x4a, 0x72, 0x65, 0x53, 0x4f, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
/// P0 Control A 的固定绝对 LBA。
/// Fixed absolute LBA of P0 Control A.
pub const P0_CONTROL_A_LBA: u64 = 34_605_056;
/// P0 Control A 的分区类型 GUID 原始字节。
/// Raw partition-type GUID bytes for P0 Control A.
pub const P0_CONTROL_A_TYPE_GUID: [u8; 16] = [
    0x70, 0x73, 0x61, 0x4a, 0x72, 0x65, 0x53, 0x4f, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
];
/// P0 Control A 的唯一分区 GUID 原始字节。
/// Raw unique partition GUID bytes for P0 Control A.
pub const P0_CONTROL_A_PARTITION_GUID: [u8; 16] = [
    0x70, 0x73, 0x61, 0x4a, 0x72, 0x65, 0x53, 0x4f, 0xa0, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
];
/// P0 Control B 的固定绝对 LBA。
/// Fixed absolute LBA of P0 Control B.
pub const P0_CONTROL_B_LBA: u64 = 34_736_128;
/// P0 Control B 的分区类型 GUID 原始字节。
/// Raw partition-type GUID bytes for P0 Control B.
pub const P0_CONTROL_B_TYPE_GUID: [u8; 16] = [
    0x70, 0x73, 0x61, 0x4a, 0x72, 0x65, 0x53, 0x4f, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
];
/// P0 Control B 的唯一分区 GUID 原始字节。
/// Raw unique partition GUID bytes for P0 Control B.
pub const P0_CONTROL_B_PARTITION_GUID: [u8; 16] = [
    0x70, 0x73, 0x61, 0x4a, 0x72, 0x65, 0x53, 0x4f, 0xa0, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
];
/// P0 System A 的固定绝对 LBA。
/// Fixed absolute LBA of P0 System A.
pub const P0_SYSTEM_A_LBA: u64 = 1_050_624;
/// P0 System B 的固定绝对 LBA。
/// Fixed absolute LBA of P0 System B.
pub const P0_SYSTEM_B_LBA: u64 = 17_827_840;
/// P0 System A/B 的固定分区字节数。
/// Fixed partition size in bytes for P0 System A/B.
pub const P0_SYSTEM_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// 双槽 A/B 的稳定编号。Stable identifiers for the two boot slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Slot {
    /// A 槽。Slot A.
    A = 0,
    /// B 槽。Slot B.
    B = 1,
}

impl Slot {
    const fn index(self) -> usize {
        self as usize
    }
}

/// 启动槽状态。Boot-slot state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SlotState {
    /// 尚无映像。No image is present.
    Empty = 0,
    /// 已暂存，等待完整验证和预检查。Staged, awaiting full verification and preflight.
    Candidate = 1,
    /// 已通过健康确认。Confirmed healthy.
    Confirmed = 2,
    /// 启动预算耗尽或健康明确失败。The boot budget was exhausted or health explicitly failed.
    Failed = 3,
}

/// 一个启动槽的持久事实。
/// Persistent facts for one boot slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotRecord {
    state: SlotState,
    generation: u64,
    release: u64,
    digest: [u8; 32],
    attempts: u8,
    data_schema_min: u32,
    data_schema_max: u32,
}

impl SlotRecord {
    const EMPTY: Self = Self {
        state: SlotState::Empty,
        generation: 0,
        release: 0,
        digest: [0; 32],
        attempts: 0,
        data_schema_min: 0,
        data_schema_max: 0,
    };

    /// 槽状态。Slot state.
    pub const fn state(self) -> SlotState {
        self.state
    }

    /// 槽记录的单调世代。Monotonic generation of this slot record.
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// 发布序号，用作系统槽反回滚依据。Release sequence used for system anti-rollback decisions.
    pub const fn release(self) -> u64 {
        self.release
    }

    /// 已认证工件摘要。Digest of the verified artifact.
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }

    /// 已使用的连续启动尝试。Consecutive boot attempts consumed.
    pub const fn attempts(self) -> u8 {
        self.attempts
    }

    /// 该槽能够读取的数据 Schema 范围。Data-schema range readable by this slot.
    pub const fn data_schema_range(self) -> (u32, u32) {
        (self.data_schema_min, self.data_schema_max)
    }
}

/// 候选槽允许连续尝试的最大次数。Maximum consecutive attempts for a candidate slot.
pub const MAX_BOOT_ATTEMPTS: u8 = 3;

/// 启动选择原因。Why a slot was selected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootReason {
    /// 候选首次进入健康判定。The candidate entered health evaluation.
    CandidateTrial,
    /// 最近一次健康确认的版本。The latest health-confirmed release.
    ConfirmedRelease,
}

/// 一次必须在跳转前持久化的启动选择。
/// A boot decision whose attempt record must be durable before transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootDecision {
    /// 要启动的槽。Slot to boot.
    pub slot: Slot,
    /// 本次选择后的累计尝试次数。Attempt count after this decision.
    pub attempt: u8,
    /// 选择原因。Selection reason.
    pub reason: BootReason,
}

/// 一次系统槽候选的完整持久身份。
/// Complete persistent identity for one system-slot candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Candidate {
    /// 发布序号。Release sequence.
    pub release: u64,
    /// 已认证映像摘要。Digest of the verified image.
    pub digest: [u8; 32],
    /// 更新事务标识。Update-transaction identifier.
    pub transaction_id: u64,
    /// 不可下降的安全纪元。Security epoch that cannot decrease.
    pub security_epoch: u64,
    /// 可读数据 Schema 下限。Minimum readable data schema.
    pub data_schema_min: u32,
    /// 可读数据 Schema 上限。Maximum readable data schema.
    pub data_schema_max: u32,
}

/// 启动控制拒绝或恢复原因。
/// Boot-control rejection or recovery reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootControlError {
    /// 槽号不能承载候选。The slot cannot hold a candidate.
    InvalidCandidateSlot,
    /// 发布序号必须严格高于反回滚下限。The release must be strictly above the rollback floor.
    RollbackRejected,
    /// 已有候选，必须先完成或失败。A candidate already exists.
    CandidatePending,
    /// 目标槽保存的是当前唯一已知良好版本。The target is the only known-good slot.
    WouldDiscardKnownGood,
    /// 事件不适用于该槽当前状态。The event is invalid for the slot's current state.
    InvalidSlotState(SlotState),
    /// 没有可安全启动的槽，必须进入救援环境。No safe boot slot remains; recovery is required.
    NoSafeSlot,
    /// 记录的魔数、版本、长度或校验失败。The record magic, version, length, or checksum failed.
    CorruptRecord,
    /// 记录不符合结构不变量。The record violates structural invariants.
    InvalidRecord,
    /// 世代或计数值溢出。A generation or counter overflowed.
    Overflow,
    /// 两代记录声称相同世代但内容不同。Two records claim the same generation with different contents.
    EqualGenerationMismatch,
    /// 候选槽不能读取升级前的数据 Schema，无法保留安全回滚边界。
    /// The candidate cannot read the pre-upgrade data schema, so safe rollback is not possible.
    IncompatibleDataSchema,
    /// 健康证据不属于当前候选或活动槽。Health evidence does not belong to the active slot or current candidate.
    UnexpectedHealthEvidence,
    /// 候选尚未持久消耗试启动预算，不能提交健康结果。
    /// The candidate has not durably consumed a trial attempt, so health cannot be reported.
    TrialNotPrepared,
}

const MAGIC: [u8; 8] = *b"JLC0CTL1";
const FORMAT_VERSION: u16 = 1;
const HEADER_BYTES: usize = 56;
const SLOT_BYTES: usize = 60;
const CRC_OFFSET: usize = CONTROL_RECORD_BYTES - 4;

/// 权威启动控制事实。
/// Authoritative boot-control facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlBlock {
    generation: u64,
    transaction_id: u64,
    rollback_floor: u64,
    security_epoch: u64,
    data_schema_min: u32,
    data_schema_max: u32,
    active_slot: Slot,
    slots: [SlotRecord; 2],
}

impl ControlBlock {
    /// 以唯一的健康槽创建首个控制记录。
    /// Creates the first control record with one healthy slot.
    pub fn initialize(
        slot: Slot,
        release: u64,
        digest: [u8; 32],
        transaction_id: u64,
        security_epoch: u64,
        data_schema_min: u32,
        data_schema_max: u32,
    ) -> Result<Self, BootControlError> {
        if release == 0
            || digest == [0; 32]
            || transaction_id == 0
            || data_schema_min > data_schema_max
        {
            return Err(BootControlError::InvalidRecord);
        }
        let mut record = SlotRecord::EMPTY;
        record.state = SlotState::Confirmed;
        record.generation = 1;
        record.release = release;
        record.digest = digest;
        record.data_schema_min = data_schema_min;
        record.data_schema_max = data_schema_max;
        let mut slots = [SlotRecord::EMPTY; 2];
        slots[slot.index()] = record;
        Ok(Self {
            generation: 1,
            transaction_id,
            rollback_floor: release,
            security_epoch,
            data_schema_min,
            data_schema_max,
            active_slot: slot,
            slots,
        })
    }

    /// 控制记录世代。Control-record generation.
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// 系统更新的反回滚下限。Anti-rollback floor for system updates.
    pub const fn rollback_floor(self) -> u64 {
        self.rollback_floor
    }

    /// 最近一次启动事务标识。Identifier of the current lifecycle transaction.
    pub const fn transaction_id(self) -> u64 {
        self.transaction_id
    }

    /// 防回滚安全纪元；不得下降。Anti-rollback security epoch; it must never decrease.
    pub const fn security_epoch(self) -> u64 {
        self.security_epoch
    }

    /// 当前活动槽。Current active slot.
    pub const fn active_slot(self) -> Slot {
        self.active_slot
    }

    /// 数据 Schema 可读范围。Readable data-schema range.
    pub const fn data_schema_range(self) -> (u32, u32) {
        (self.data_schema_min, self.data_schema_max)
    }

    /// 读取指定槽。Reads one slot.
    pub const fn slot(self, slot: Slot) -> SlotRecord {
        self.slots[slot.index()]
    }

    /// 当前优先的已知良好槽。Current preferred known-good slot.
    pub fn preferred_confirmed(self) -> Option<(Slot, SlotRecord)> {
        self.confirmed()
            .into_iter()
            .flatten()
            .max_by_key(|(_, record)| record.release)
    }

    /// 将经过完整验证的新版本放入非当前槽并记为候选。
    /// Places a fully verified release in the non-current slot and marks it as a candidate.
    pub fn stage_candidate(
        &mut self,
        slot: Slot,
        candidate: Candidate,
    ) -> Result<(), BootControlError> {
        if candidate.release == 0
            || candidate.digest == [0; 32]
            || candidate.transaction_id == 0
            || candidate.data_schema_min > candidate.data_schema_max
        {
            return Err(BootControlError::InvalidRecord);
        }
        if candidate.release <= self.rollback_floor {
            return Err(BootControlError::RollbackRejected);
        }
        if self
            .slots
            .iter()
            .any(|record| record.state == SlotState::Candidate)
        {
            return Err(BootControlError::CandidatePending);
        }
        let Some((preferred_slot, preferred)) = self.preferred_confirmed() else {
            return Err(BootControlError::NoSafeSlot);
        };
        if slot == preferred_slot {
            return Err(BootControlError::WouldDiscardKnownGood);
        }
        if candidate.release <= preferred.release {
            return Err(BootControlError::RollbackRejected);
        }
        if candidate.transaction_id <= self.transaction_id
            || candidate.security_epoch < self.security_epoch
        {
            return Err(BootControlError::RollbackRejected);
        }
        if candidate.data_schema_min > self.data_schema_min
            || candidate.data_schema_max < self.data_schema_max
        {
            return Err(BootControlError::IncompatibleDataSchema);
        }
        let mut next = *self;
        let record = &mut next.slots[slot.index()];
        record.state = SlotState::Candidate;
        record.generation = record
            .generation
            .checked_add(1)
            .ok_or(BootControlError::Overflow)?;
        record.release = candidate.release;
        record.digest = candidate.digest;
        record.attempts = 0;
        record.data_schema_min = candidate.data_schema_min;
        record.data_schema_max = candidate.data_schema_max;
        next.transaction_id = candidate.transaction_id;
        next.security_epoch = candidate.security_epoch;
        next.bump_generation()?;
        *self = next;
        Ok(())
    }

    /// 记录启动候选前必须提交的选择；候选预算耗尽时自动回退。
    /// Records a decision that must be committed before boot; an exhausted candidate falls back.
    pub fn prepare_boot(&mut self) -> Result<BootDecision, BootControlError> {
        let mut next = *self;
        if let Some((slot, record)) = next.candidate() {
            if record.attempts < MAX_BOOT_ATTEMPTS {
                let attempt = record.attempts + 1;
                next.slots[slot.index()].attempts = attempt;
                next.bump_slot_and_control(slot)?;
                *self = next;
                return Ok(BootDecision {
                    slot,
                    attempt,
                    reason: BootReason::CandidateTrial,
                });
            }
            next.slots[slot.index()].state = SlotState::Failed;
            next.slots[slot.index()].attempts = 0;
            next.bump_slot_generation(slot)?;
        }

        let mut choice = None;
        for candidate in next.confirmed().into_iter().flatten() {
            if candidate.1.attempts >= MAX_BOOT_ATTEMPTS {
                continue;
            }
            if choice
                .as_ref()
                .map(|(_, record): &(Slot, SlotRecord)| candidate.1.release > record.release)
                .unwrap_or(true)
            {
                choice = Some(candidate);
            }
        }
        let (slot, record) = choice.ok_or(BootControlError::NoSafeSlot)?;
        let attempt = record.attempts + 1;
        next.slots[slot.index()].attempts = attempt;
        next.bump_slot_and_control(slot)?;
        *self = next;
        Ok(BootDecision {
            slot,
            attempt,
            reason: BootReason::ConfirmedRelease,
        })
    }

    /// 记录最小健康集合结果；候选通过后成为新的已知良好版本。
    /// Records the minimum-health result; a passing candidate becomes the new known-good release.
    pub fn report_health(&mut self, slot: Slot, healthy: bool) -> Result<(), BootControlError> {
        let state = self.slots[slot.index()].state;
        match state {
            SlotState::Candidate if self.slots[slot.index()].attempts == 0 => {
                return Err(BootControlError::TrialNotPrepared)
            }
            SlotState::Candidate => {}
            SlotState::Confirmed if self.candidate().is_some() || slot != self.active_slot => {
                return Err(BootControlError::UnexpectedHealthEvidence)
            }
            SlotState::Confirmed => {}
            _ => return Err(BootControlError::InvalidSlotState(state)),
        }
        if !healthy && state == SlotState::Confirmed && self.confirmed_count() == 1 {
            return Err(BootControlError::NoSafeSlot);
        }
        let mut next = *self;
        if healthy {
            let release = next.slots[slot.index()].release;
            if state == SlotState::Candidate {
                next.slots[slot.index()].state = SlotState::Confirmed;
                next.active_slot = slot;
                next.rollback_floor = next.rollback_floor.max(release);
            }
            next.slots[slot.index()].attempts = 0;
        } else {
            next.slots[slot.index()].state = SlotState::Failed;
            next.slots[slot.index()].attempts = 0;
            if state == SlotState::Confirmed {
                let fallback = next
                    .confirmed()
                    .into_iter()
                    .flatten()
                    .max_by_key(|(_, record)| record.release)
                    .ok_or(BootControlError::NoSafeSlot)?;
                next.active_slot = fallback.0;
            }
        }
        next.bump_slot_and_control(slot)?;
        *self = next;
        Ok(())
    }

    /// 当前唯一候选。The current sole candidate, if any.
    pub fn candidate(self) -> Option<(Slot, SlotRecord)> {
        self.find(SlotState::Candidate)
    }

    /// 编码固定的 180 字节控制记录。
    /// Encodes the fixed 180-byte control record.
    pub fn encode(self) -> [u8; CONTROL_RECORD_BYTES] {
        let mut out = [0u8; CONTROL_RECORD_BYTES];
        out[0..8].copy_from_slice(&MAGIC);
        out[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        out[10..12].copy_from_slice(&(CONTROL_RECORD_BYTES as u16).to_le_bytes());
        out[12..20].copy_from_slice(&self.generation.to_le_bytes());
        out[20..28].copy_from_slice(&self.transaction_id.to_le_bytes());
        out[28..36].copy_from_slice(&self.rollback_floor.to_le_bytes());
        out[36..44].copy_from_slice(&self.security_epoch.to_le_bytes());
        out[44..48].copy_from_slice(&self.data_schema_min.to_le_bytes());
        out[48..52].copy_from_slice(&self.data_schema_max.to_le_bytes());
        out[52] = self.active_slot as u8;
        for (index, record) in self.slots.iter().copied().enumerate() {
            let at = HEADER_BYTES + index * SLOT_BYTES;
            out[at] = record.state as u8;
            out[at + 1] = record.attempts;
            out[at + 4..at + 12].copy_from_slice(&record.generation.to_le_bytes());
            out[at + 12..at + 20].copy_from_slice(&record.release.to_le_bytes());
            out[at + 20..at + 52].copy_from_slice(&record.digest);
            out[at + 52..at + 56].copy_from_slice(&record.data_schema_min.to_le_bytes());
            out[at + 56..at + 60].copy_from_slice(&record.data_schema_max.to_le_bytes());
        }
        let crc = crc32fast::hash(&out[..CRC_OFFSET]);
        out[CRC_OFFSET..].copy_from_slice(&crc.to_le_bytes());
        out
    }

    /// 解码并验证固定控制记录；任何未知或矛盾事实都失败关闭。
    /// Decodes and validates a fixed control record; unknown or contradictory facts fail closed.
    pub fn decode(bytes: &[u8]) -> Result<Self, BootControlError> {
        if bytes.len() != CONTROL_RECORD_BYTES {
            return Err(BootControlError::CorruptRecord);
        }
        if bytes[0..8] != MAGIC
            || u16::from_le_bytes([bytes[8], bytes[9]]) != FORMAT_VERSION
            || u16::from_le_bytes([bytes[10], bytes[11]]) as usize != CONTROL_RECORD_BYTES
            || u32::from_le_bytes([
                bytes[CRC_OFFSET],
                bytes[CRC_OFFSET + 1],
                bytes[CRC_OFFSET + 2],
                bytes[CRC_OFFSET + 3],
            ]) != crc32fast::hash(&bytes[..CRC_OFFSET])
        {
            return Err(BootControlError::CorruptRecord);
        }
        let generation = read_u64(&bytes[12..20]);
        let transaction_id = read_u64(&bytes[20..28]);
        let rollback_floor = read_u64(&bytes[28..36]);
        let security_epoch = read_u64(&bytes[36..44]);
        let data_schema_min = read_u32(&bytes[44..48]);
        let data_schema_max = read_u32(&bytes[48..52]);
        let active_slot = match bytes[52] {
            0 => Slot::A,
            1 => Slot::B,
            _ => return Err(BootControlError::InvalidRecord),
        };
        if generation == 0
            || transaction_id == 0
            || data_schema_min > data_schema_max
            || bytes[53..56] != [0, 0, 0]
        {
            return Err(BootControlError::InvalidRecord);
        }
        let mut slots = [SlotRecord::EMPTY; 2];
        for (index, record) in slots.iter_mut().enumerate() {
            let at = HEADER_BYTES + index * SLOT_BYTES;
            let state = match bytes[at] {
                0 => SlotState::Empty,
                1 => SlotState::Candidate,
                2 => SlotState::Confirmed,
                3 => SlotState::Failed,
                _ => return Err(BootControlError::InvalidRecord),
            };
            if bytes[at + 2] != 0 || bytes[at + 3] != 0 {
                return Err(BootControlError::InvalidRecord);
            }
            *record = SlotRecord {
                state,
                attempts: bytes[at + 1],
                generation: read_u64(&bytes[at + 4..at + 12]),
                release: read_u64(&bytes[at + 12..at + 20]),
                digest: bytes[at + 20..at + 52]
                    .try_into()
                    .map_err(|_| BootControlError::InvalidRecord)?,
                data_schema_min: read_u32(&bytes[at + 52..at + 56]),
                data_schema_max: read_u32(&bytes[at + 56..at + 60]),
            };
            if record.attempts > MAX_BOOT_ATTEMPTS {
                return Err(BootControlError::InvalidRecord);
            }
            if state == SlotState::Empty {
                if *record != SlotRecord::EMPTY {
                    return Err(BootControlError::InvalidRecord);
                }
            } else if record.generation == 0
                || record.release == 0
                || record.digest == [0; 32]
                || record.data_schema_min > record.data_schema_max
            {
                return Err(BootControlError::InvalidRecord);
            }
        }
        let block = Self {
            generation,
            rollback_floor,
            transaction_id,
            security_epoch,
            data_schema_min,
            data_schema_max,
            active_slot,
            slots,
        };
        let candidates = block
            .slots
            .iter()
            .filter(|record| record.state == SlotState::Candidate)
            .count();
        let confirmed = block
            .slots
            .iter()
            .filter(|record| record.state == SlotState::Confirmed)
            .count();
        if candidates > 1 || confirmed == 0 {
            return Err(BootControlError::InvalidRecord);
        }
        if block.slots[active_slot.index()].state != SlotState::Confirmed {
            return Err(BootControlError::InvalidRecord);
        }
        if block.slots.iter().any(|record| {
            matches!(record.state, SlotState::Candidate | SlotState::Confirmed)
                && (record.data_schema_min > data_schema_min
                    || record.data_schema_max < data_schema_max)
        }) {
            return Err(BootControlError::InvalidRecord);
        }
        if let Some((_, candidate)) = block.candidate() {
            if candidate.release <= rollback_floor {
                return Err(BootControlError::InvalidRecord);
            }
        }
        Ok(block)
    }

    fn bump_generation(&mut self) -> Result<(), BootControlError> {
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(BootControlError::Overflow)?;
        Ok(())
    }

    fn bump_slot_and_control(&mut self, slot: Slot) -> Result<(), BootControlError> {
        self.bump_slot_generation(slot)?;
        self.bump_generation()
    }

    fn bump_slot_generation(&mut self, slot: Slot) -> Result<(), BootControlError> {
        let record = &mut self.slots[slot.index()];
        record.generation = record
            .generation
            .checked_add(1)
            .ok_or(BootControlError::Overflow)?;
        Ok(())
    }

    fn find(self, state: SlotState) -> Option<(Slot, SlotRecord)> {
        if self.slots[0].state == state {
            Some((Slot::A, self.slots[0]))
        } else if self.slots[1].state == state {
            Some((Slot::B, self.slots[1]))
        } else {
            None
        }
    }

    fn confirmed(self) -> [Option<(Slot, SlotRecord)>; 2] {
        [
            (self.slots[0].state == SlotState::Confirmed).then_some((Slot::A, self.slots[0])),
            (self.slots[1].state == SlotState::Confirmed).then_some((Slot::B, self.slots[1])),
        ]
    }

    fn confirmed_count(self) -> usize {
        self.slots
            .iter()
            .filter(|record| record.state == SlotState::Confirmed)
            .count()
    }
}

/// 恢复两份启动控制副本：忽略无效副本，选择最高有效世代。
/// Recovers the two control copies: ignores invalid copies and selects the highest valid generation.
pub fn recover(
    first: Option<&[u8]>,
    second: Option<&[u8]>,
) -> Result<ControlBlock, BootControlError> {
    let first = first.map(ControlBlock::decode).transpose().ok().flatten();
    let second = second.map(ControlBlock::decode).transpose().ok().flatten();
    match (first, second) {
        (Some(first), Some(second)) if first.generation == second.generation && first != second => {
            Err(BootControlError::EqualGenerationMismatch)
        }
        (Some(first), Some(second)) => Ok(if first.generation >= second.generation {
            first
        } else {
            second
        }),
        (Some(block), None) | (None, Some(block)) => Ok(block),
        (None, None) => Err(BootControlError::CorruptRecord),
    }
}

/// 控制记录存储后端；提交顺序固定为“写非活动副本，再 flush”。
/// Control-record storage backend; commit order is always "write inactive copy, then flush".
pub trait ControlIo {
    /// 写入指定副本的完整固定长度记录。Writes the complete fixed-length record to one copy.
    fn write_copy(
        &mut self,
        copy: usize,
        bytes: &[u8; CONTROL_RECORD_BYTES],
    ) -> Result<(), ControlIoError>;
    /// 使此前写入获得持久性。Makes previous writes durable.
    fn flush(&mut self) -> Result<(), ControlIoError>;
    /// 在 flush 后读回指定副本，供完整性验证。Reads a copy after flush for integrity verification.
    fn read_copy(
        &mut self,
        copy: usize,
        out: &mut [u8; CONTROL_RECORD_BYTES],
    ) -> Result<(), ControlIoError>;
}

/// 存储后端报告的写入或同步失败。
/// A write or synchronization failure reported by the storage backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlIoError {
    /// 后端操作失败。The backend operation failed.
    Failed,
}

/// 提交阶段错误。Commit-stage failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitError {
    /// 新记录不是本地权威状态的直接后继。The next record is not the immediate successor of local authority.
    Generation,
    /// 写入失败。The write failed.
    Write,
    /// flush 失败，调用者必须停止正常启动。Flush failed and the caller must stop normal boot.
    Flush,
    /// 读回内容与写入内容不一致。Readback differs from the written bytes.
    Readback,
}

/// 把下一世代写入未选中的副本；成功后只更新本地镜像，不宣称设备已持久。
/// Writes the next generation to the inactive copy; success updates only the local mirror, not a durability claim.
pub fn commit<IO: ControlIo>(
    io: &mut IO,
    local: &mut ControlBlock,
    next: ControlBlock,
) -> Result<(), CommitError> {
    if next.generation
        != local
            .generation
            .checked_add(1)
            .ok_or(CommitError::Generation)?
    {
        return Err(CommitError::Generation);
    }
    let bytes = next.encode();
    let copy = (next.generation & 1) as usize;
    io.write_copy(copy, &bytes)
        .map_err(|_| CommitError::Write)?;
    io.flush().map_err(|_| CommitError::Flush)?;
    let mut readback = [0u8; CONTROL_RECORD_BYTES];
    io.read_copy(copy, &mut readback)
        .map_err(|_| CommitError::Readback)?;
    if readback != bytes {
        return Err(CommitError::Readback);
    }
    *local = next;
    Ok(())
}

fn read_u64(bytes: &[u8]) -> u64 {
    let mut out = [0u8; 8];
    out.copy_from_slice(bytes);
    u64::from_le_bytes(out)
}

fn read_u32(bytes: &[u8]) -> u32 {
    let mut out = [0u8; 4];
    out.copy_from_slice(bytes);
    u32::from_le_bytes(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn p0_control_lbas_are_fixed_before_shared_data() {
        const MIB_SECTORS: u64 = 2048;
        const ESP_SECTORS: u64 = 512 * MIB_SECTORS;
        const SYSTEM_SECTORS: u64 = 8 * 1024 * MIB_SECTORS;
        const CONTROL_SECTORS: u64 = 64 * MIB_SECTORS;
        let system_a = MIB_SECTORS + ESP_SECTORS;
        let system_b = system_a + SYSTEM_SECTORS;
        assert_eq!(P0_SYSTEM_A_LBA, system_a);
        assert_eq!(P0_SYSTEM_B_LBA, system_b);
        assert_eq!(P0_SYSTEM_BYTES, SYSTEM_SECTORS * 512);
        let control_a = MIB_SECTORS + ESP_SECTORS + 2 * SYSTEM_SECTORS;
        assert_eq!(P0_CONTROL_A_LBA, control_a);
        assert_eq!(P0_CONTROL_B_LBA, control_a + CONTROL_SECTORS);
    }

    #[test]
    fn p0_guid_constants_match_gpt_on_disk_byte_order() {
        assert_eq!(
            P0_CONTROL_A_TYPE_GUID,
            [
                0x70, 0x73, 0x61, 0x4a, 0x72, 0x65, 0x53, 0x4f, 0x80, 0x01, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x03,
            ]
        );
        assert_eq!(
            P0_CONTROL_A_PARTITION_GUID,
            [
                0x70, 0x73, 0x61, 0x4a, 0x72, 0x65, 0x53, 0x4f, 0xa0, 0x04, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x04,
            ]
        );
        assert_eq!(
            P0_CONTROL_B_TYPE_GUID,
            [
                0x70, 0x73, 0x61, 0x4a, 0x72, 0x65, 0x53, 0x4f, 0x80, 0x01, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x04,
            ]
        );
        assert_eq!(
            P0_CONTROL_B_PARTITION_GUID,
            [
                0x70, 0x73, 0x61, 0x4a, 0x72, 0x65, 0x53, 0x4f, 0xa0, 0x05, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x05,
            ]
        );
    }

    fn initial() -> ControlBlock {
        ControlBlock::initialize(Slot::A, 1, digest(1), 1, 0, 1, 1).unwrap()
    }

    fn stage(block: &mut ControlBlock) {
        block
            .stage_candidate(
                Slot::B,
                Candidate {
                    release: 2,
                    digest: digest(2),
                    transaction_id: 2,
                    security_epoch: 2,
                    data_schema_min: 1,
                    data_schema_max: 2,
                },
            )
            .unwrap();
    }

    #[test]
    fn record_round_trip_and_every_byte_mutation_fails_or_changes_state() {
        let mut block = initial();
        stage(&mut block);
        let encoded = block.encode();
        assert_eq!(ControlBlock::decode(&encoded), Ok(block));
        for index in 0..CONTROL_RECORD_BYTES {
            let mut corrupt = encoded;
            corrupt[index] ^= 0x80;
            assert!(
                ControlBlock::decode(&corrupt) != Ok(block),
                "mutation at {index}"
            );
        }
    }

    #[test]
    fn boot_attempt_is_counted_before_transfer_and_exhaustion_rolls_back() {
        let mut block = initial();
        stage(&mut block);
        let generation_before_trials = block.generation();
        for attempt in 1..=MAX_BOOT_ATTEMPTS {
            let decision = block.prepare_boot().unwrap();
            assert_eq!(decision.slot, Slot::B);
            assert_eq!(decision.attempt, attempt);
        }
        let fallback = block.prepare_boot().unwrap();
        assert_eq!(fallback.slot, Slot::A);
        assert_eq!(fallback.reason, BootReason::ConfirmedRelease);
        assert_eq!(block.slot(Slot::B).state(), SlotState::Failed);
        assert_eq!(
            block.generation(),
            generation_before_trials + u64::from(MAX_BOOT_ATTEMPTS) + 1
        );
        assert_eq!(block.slot(Slot::B).generation(), 5);
        assert_eq!(block.slot(Slot::A).generation(), 2);
    }

    #[test]
    fn healthy_candidate_advances_floor_but_old_slot_remains_bootable() {
        let mut block = initial();
        stage(&mut block);
        block.prepare_boot().unwrap();
        block.report_health(Slot::B, true).unwrap();
        assert_eq!(block.rollback_floor(), 2);
        assert_eq!(block.active_slot(), Slot::B);
        assert_eq!(block.security_epoch(), 2);
        assert_eq!(block.data_schema_range(), (1, 1));
        assert_eq!(block.slot(Slot::A).data_schema_range(), (1, 1));
        assert_eq!(block.slot(Slot::B).data_schema_range(), (1, 2));
        assert_eq!(block.slot(Slot::B).state(), SlotState::Confirmed);
        assert_eq!(ControlBlock::decode(&block.encode()), Ok(block));
        assert_eq!(
            block.stage_candidate(
                Slot::A,
                Candidate {
                    release: 1,
                    digest: digest(1),
                    transaction_id: 3,
                    security_epoch: 2,
                    data_schema_min: 1,
                    data_schema_max: 2,
                }
            ),
            Err(BootControlError::RollbackRejected)
        );
    }

    #[test]
    fn replayed_transaction_or_decreased_security_epoch_is_rejected() {
        let mut block = initial();
        let replay = Candidate {
            release: 2,
            digest: digest(2),
            transaction_id: 1,
            security_epoch: 2,
            data_schema_min: 1,
            data_schema_max: 2,
        };
        assert_eq!(
            block.stage_candidate(Slot::B, replay),
            Err(BootControlError::RollbackRejected)
        );
        stage(&mut block);
        block.prepare_boot().unwrap();
        block.report_health(Slot::B, true).unwrap();
        let lower_epoch = Candidate {
            release: 3,
            digest: digest(3),
            transaction_id: 3,
            security_epoch: 1,
            data_schema_min: 2,
            data_schema_max: 3,
        };
        assert_eq!(
            block.stage_candidate(Slot::A, lower_epoch),
            Err(BootControlError::RollbackRejected)
        );
    }

    #[test]
    fn candidate_must_preserve_the_current_data_schema_for_rollback() {
        let mut block = initial();
        let incompatible = Candidate {
            release: 2,
            digest: digest(2),
            transaction_id: 2,
            security_epoch: 2,
            data_schema_min: 2,
            data_schema_max: 3,
        };
        assert_eq!(
            block.stage_candidate(Slot::B, incompatible),
            Err(BootControlError::IncompatibleDataSchema)
        );
        assert_eq!(block.data_schema_range(), (1, 1));
        assert_eq!(block.slot(Slot::B).state(), SlotState::Empty);

        block
            .stage_candidate(
                Slot::B,
                Candidate {
                    release: 2,
                    digest: digest(2),
                    transaction_id: 2,
                    security_epoch: 2,
                    data_schema_min: 1,
                    data_schema_max: 3,
                },
            )
            .unwrap();
        block.prepare_boot().unwrap();
        block.report_health(Slot::B, true).unwrap();
        assert_eq!(block.slot(Slot::A).data_schema_range(), (1, 1));
        assert_eq!(block.slot(Slot::B).data_schema_range(), (1, 3));
        assert_eq!(block.data_schema_range(), (1, 1));
    }

    #[test]
    fn health_requires_a_prepared_trial_and_rejects_foreign_evidence() {
        let mut block = initial();
        stage(&mut block);
        assert_eq!(
            block.report_health(Slot::B, true),
            Err(BootControlError::TrialNotPrepared)
        );
        assert_eq!(
            block.report_health(Slot::A, true),
            Err(BootControlError::UnexpectedHealthEvidence)
        );
        block.prepare_boot().unwrap();
        block.report_health(Slot::B, true).unwrap();
        assert_eq!(
            block.report_health(Slot::A, false),
            Err(BootControlError::UnexpectedHealthEvidence)
        );
        assert_eq!(block.active_slot(), Slot::B);
    }

    #[test]
    fn generation_exhaustion_never_leaves_partial_state() {
        let mut stage_block = initial();
        stage_block.generation = u64::MAX;
        let before_stage = stage_block;
        assert_eq!(
            stage_block.stage_candidate(
                Slot::B,
                Candidate {
                    release: 2,
                    digest: digest(2),
                    transaction_id: 2,
                    security_epoch: 2,
                    data_schema_min: 1,
                    data_schema_max: 1,
                }
            ),
            Err(BootControlError::Overflow)
        );
        assert_eq!(stage_block, before_stage);

        let mut prepare_block = initial();
        stage(&mut prepare_block);
        prepare_block.generation = u64::MAX;
        let before_prepare = prepare_block;
        assert_eq!(
            prepare_block.prepare_boot(),
            Err(BootControlError::Overflow)
        );
        assert_eq!(prepare_block, before_prepare);

        let mut health_block = initial();
        stage(&mut health_block);
        health_block.prepare_boot().unwrap();
        health_block.generation = u64::MAX;
        let before_health = health_block;
        assert_eq!(
            health_block.report_health(Slot::B, true),
            Err(BootControlError::Overflow)
        );
        assert_eq!(health_block, before_health);
    }

    #[test]
    fn sole_confirmed_slot_cannot_be_declared_unhealthy() {
        let mut block = initial();
        let before = block;
        assert_eq!(
            block.report_health(Slot::A, false),
            Err(BootControlError::NoSafeSlot)
        );
        assert_eq!(block, before);
    }

    #[test]
    fn failed_new_release_falls_back_to_the_old_confirmed_slot() {
        let mut block = initial();
        stage(&mut block);
        block.prepare_boot().unwrap();
        block.report_health(Slot::B, true).unwrap();
        block.prepare_boot().unwrap();
        block.report_health(Slot::B, false).unwrap();
        assert_eq!(block.active_slot(), Slot::A);
        assert_eq!(block.slot(Slot::A).state(), SlotState::Confirmed);
        assert_eq!(block.slot(Slot::B).state(), SlotState::Failed);
        assert_eq!(block.rollback_floor(), 2);
        assert_eq!(ControlBlock::decode(&block.encode()), Ok(block));
    }

    #[test]
    fn torn_new_copy_recovers_last_complete_record() {
        let old = initial();
        let mut next = old;
        stage(&mut next);
        let old_bytes = old.encode();
        let mut torn = next.encode();
        torn[80] ^= 1;
        assert_eq!(recover(Some(&old_bytes), Some(&torn)), Ok(old));
    }

    #[test]
    fn highest_valid_generation_wins() {
        let old = initial();
        let mut next = old;
        stage(&mut next);
        assert_eq!(recover(Some(&old.encode()), Some(&next.encode())), Ok(next));
    }

    #[test]
    fn equal_generation_with_different_content_is_rejected() {
        let block = initial();
        let mut other = block;
        other.slots[0].digest = digest(9);
        assert_eq!(
            recover(Some(&block.encode()), Some(&other.encode())),
            Err(BootControlError::EqualGenerationMismatch)
        );
    }

    #[test]
    fn commit_failure_does_not_replace_local_authority() {
        struct Writer {
            fail_write: bool,
            fail_flush: bool,
            fail_read: bool,
            corrupt_read: bool,
        }
        impl ControlIo for Writer {
            fn write_copy(
                &mut self,
                _copy: usize,
                _bytes: &[u8; CONTROL_RECORD_BYTES],
            ) -> Result<(), ControlIoError> {
                if self.fail_write {
                    Err(ControlIoError::Failed)
                } else {
                    Ok(())
                }
            }
            fn flush(&mut self) -> Result<(), ControlIoError> {
                if self.fail_flush {
                    Err(ControlIoError::Failed)
                } else {
                    Ok(())
                }
            }
            fn read_copy(
                &mut self,
                _copy: usize,
                out: &mut [u8; CONTROL_RECORD_BYTES],
            ) -> Result<(), ControlIoError> {
                if self.fail_read {
                    return Err(ControlIoError::Failed);
                }
                if self.corrupt_read {
                    out[0] ^= 1;
                }
                Ok(())
            }
        }

        let old = initial();
        let mut next = old;
        stage(&mut next);
        let mut local = old;
        assert_eq!(
            commit(
                &mut Writer {
                    fail_write: true,
                    fail_flush: false,
                    fail_read: false,
                    corrupt_read: false,
                },
                &mut local,
                next
            ),
            Err(CommitError::Write)
        );
        assert_eq!(local, old);
        assert_eq!(
            commit(
                &mut Writer {
                    fail_write: false,
                    fail_flush: true,
                    fail_read: false,
                    corrupt_read: false,
                },
                &mut local,
                next
            ),
            Err(CommitError::Flush)
        );
        assert_eq!(local, old);
        assert_eq!(
            commit(
                &mut Writer {
                    fail_write: false,
                    fail_flush: false,
                    fail_read: false,
                    corrupt_read: true,
                },
                &mut local,
                next
            ),
            Err(CommitError::Readback)
        );
        assert_eq!(local, old);
    }

    #[test]
    fn successful_commit_is_flushed_read_back_and_then_published() {
        struct Store {
            bytes: [u8; CONTROL_RECORD_BYTES],
        }
        impl ControlIo for Store {
            fn write_copy(
                &mut self,
                _copy: usize,
                bytes: &[u8; CONTROL_RECORD_BYTES],
            ) -> Result<(), ControlIoError> {
                self.bytes = *bytes;
                Ok(())
            }
            fn flush(&mut self) -> Result<(), ControlIoError> {
                Ok(())
            }
            fn read_copy(
                &mut self,
                _copy: usize,
                out: &mut [u8; CONTROL_RECORD_BYTES],
            ) -> Result<(), ControlIoError> {
                *out = self.bytes;
                Ok(())
            }
        }

        let old = initial();
        let mut next = old;
        stage(&mut next);
        let mut local = old;
        let mut store = Store {
            bytes: old.encode(),
        };
        assert_eq!(commit(&mut store, &mut local, next), Ok(()));
        assert_eq!(local, next);
        assert_eq!(store.bytes, next.encode());
    }

    #[test]
    fn commits_alternate_physical_copies_and_keep_the_prior_generation() {
        struct Store {
            copies: [[u8; CONTROL_RECORD_BYTES]; 2],
            last_written: Option<usize>,
        }
        impl ControlIo for Store {
            fn write_copy(
                &mut self,
                copy: usize,
                bytes: &[u8; CONTROL_RECORD_BYTES],
            ) -> Result<(), ControlIoError> {
                self.copies[copy] = *bytes;
                self.last_written = Some(copy);
                Ok(())
            }
            fn flush(&mut self) -> Result<(), ControlIoError> {
                Ok(())
            }
            fn read_copy(
                &mut self,
                copy: usize,
                out: &mut [u8; CONTROL_RECORD_BYTES],
            ) -> Result<(), ControlIoError> {
                *out = self.copies[copy];
                Ok(())
            }
        }

        let old = initial();
        let mut next = old;
        stage(&mut next);
        let mut local = old;
        let mut store = Store {
            copies: [old.encode(); 2],
            last_written: None,
        };
        commit(&mut store, &mut local, next).unwrap();
        assert_eq!(store.last_written, Some(0));
        assert_eq!(store.copies[1], old.encode());
        assert_eq!(
            recover(Some(&store.copies[0]), Some(&store.copies[1])),
            Ok(next)
        );

        let prior_generation = store.copies[0];
        let mut newer = local;
        newer.prepare_boot().unwrap();
        commit(&mut store, &mut local, newer).unwrap();
        assert_eq!(store.last_written, Some(1));
        assert_eq!(store.copies[0], prior_generation);
        assert_eq!(
            recover(Some(&store.copies[0]), Some(&store.copies[1])),
            Ok(newer)
        );
    }
}
