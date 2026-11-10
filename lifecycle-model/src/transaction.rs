//! LC-2 更新交易记录的固定持久格式与双副本恢复。
//! Fixed persistent format and dual-copy recovery for LC-2 update transactions.
//!
//! 记录绑定完整清单 SHA-256，并保存状态机阶段与单调世代。它不写启动槽，也不把
//! `Prepared`、`Committed` 或 `Trial` 当作成功。
//! A record binds the complete manifest SHA-256 and stores the state-machine phase and
//! monotonic generation. It does not write a boot slot or treat `Prepared`, `Committed`
//! or `Trial` as success.

use crate::update::{RestoreError, TransitionError, UpdateEvent, UpdateMachine, UpdateStage};
use crate::TRANSACTION_RECORD_BYTES;

const MAGIC: [u8; 8] = *b"JLC2TXN1";
const FORMAT_VERSION: u16 = 1;
const CRC_OFFSET: usize = TRANSACTION_RECORD_BYTES - 4;
const DIGEST_OFFSET: usize = 28;
const RESERVED_OFFSET: usize = 21;
const RESERVED_BYTES: usize = 7;

/// 一条更新交易记录。
/// One update-transaction record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionRecord {
    machine: UpdateMachine,
    manifest_sha256: [u8; 32],
}

/// 交易记录验证或转换错误。
/// Transaction-record validation or transition error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionError {
    /// 魔数、版本、长度、保留位或 CRC 非法。Magic, version, length, reserved bits or CRC are invalid.
    CorruptRecord,
    /// 清单摘要不能为零。The manifest digest must be non-zero.
    InvalidDigest,
    /// 阶段与世代组合不可能出现。The stage/generation pair is impossible.
    InvalidState,
    /// 两副本声称相同世代但内容不同。Two copies claim the same generation with different contents.
    EqualGenerationMismatch,
    /// 状态机拒绝事件。The state machine rejected the event.
    Transition(TransitionError),
}

impl From<RestoreError> for TransactionError {
    fn from(_: RestoreError) -> Self {
        Self::InvalidState
    }
}

impl TransactionRecord {
    /// 创建已通过发现、验证和准备三个阶段的新记录。
    /// Creates a new record after discovery, verification and preparation.
    pub fn prepared(manifest_sha256: [u8; 32]) -> Result<Self, TransactionError> {
        if manifest_sha256 == [0; 32] {
            return Err(TransactionError::InvalidDigest);
        }
        let mut machine = UpdateMachine::idle();
        for event in [
            UpdateEvent::Discover,
            UpdateEvent::Verify,
            UpdateEvent::Prepare,
        ] {
            machine.apply(event).map_err(TransactionError::Transition)?;
        }
        Ok(Self {
            machine,
            manifest_sha256,
        })
    }

    /// 交易绑定的清单摘要。Manifest digest bound to this transaction.
    pub const fn manifest_sha256(self) -> [u8; 32] {
        self.manifest_sha256
    }

    /// 当前阶段。Current stage.
    pub const fn stage(self) -> UpdateStage {
        self.machine.stage()
    }

    /// 当前记录世代。Current record generation.
    pub const fn generation(self) -> u64 {
        self.machine.generation()
    }

    /// 应用状态机事件；失败不改变记录。
    /// Applies a state-machine event; failure leaves the record unchanged.
    pub fn apply(&mut self, event: UpdateEvent) -> Result<UpdateStage, TransactionError> {
        let mut next = *self;
        let stage = next
            .machine
            .apply(event)
            .map_err(TransactionError::Transition)?;
        *self = next;
        Ok(stage)
    }

    /// 编码固定 64 字节交易记录。
    /// Encodes the fixed 64-byte transaction record.
    pub fn encode(self) -> [u8; TRANSACTION_RECORD_BYTES] {
        let mut out = [0u8; TRANSACTION_RECORD_BYTES];
        out[..8].copy_from_slice(&MAGIC);
        out[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        out[10..12].copy_from_slice(&(TRANSACTION_RECORD_BYTES as u16).to_le_bytes());
        out[12..20].copy_from_slice(&self.generation().to_le_bytes());
        out[20] = self.stage() as u8;
        out[DIGEST_OFFSET..DIGEST_OFFSET + 32].copy_from_slice(&self.manifest_sha256);
        let crc = crc32fast::hash(&out[..CRC_OFFSET]);
        out[CRC_OFFSET..].copy_from_slice(&crc.to_le_bytes());
        out
    }

    /// 解码并验证交易记录；未知或矛盾事实失败关闭。
    /// Decodes and validates a transaction record; unknown or contradictory facts fail closed.
    pub fn decode(bytes: &[u8]) -> Result<Self, TransactionError> {
        if bytes.len() != TRANSACTION_RECORD_BYTES
            || bytes[..8] != MAGIC
            || u16::from_le_bytes([bytes[8], bytes[9]]) != FORMAT_VERSION
            || u16::from_le_bytes([bytes[10], bytes[11]]) as usize != TRANSACTION_RECORD_BYTES
            || bytes[RESERVED_OFFSET..RESERVED_OFFSET + RESERVED_BYTES] != [0; RESERVED_BYTES]
            || read_u32(&bytes[CRC_OFFSET..]) != crc32fast::hash(&bytes[..CRC_OFFSET])
        {
            return Err(TransactionError::CorruptRecord);
        }
        let generation = read_u64(&bytes[12..20]);
        let stage = match bytes[20] {
            0 => UpdateStage::Idle,
            1 => UpdateStage::Discovered,
            2 => UpdateStage::Verified,
            3 => UpdateStage::Prepared,
            4 => UpdateStage::Committed,
            5 => UpdateStage::Trial,
            6 => UpdateStage::Confirmed,
            7 => UpdateStage::Complete,
            8 => UpdateStage::Aborted,
            9 => UpdateStage::Rollback,
            10 => UpdateStage::RolledBack,
            _ => return Err(TransactionError::CorruptRecord),
        };
        let manifest_sha256: [u8; 32] = bytes[DIGEST_OFFSET..DIGEST_OFFSET + 32]
            .try_into()
            .map_err(|_| TransactionError::CorruptRecord)?;
        if manifest_sha256 == [0; 32] {
            return Err(TransactionError::InvalidDigest);
        }
        let machine = UpdateMachine::restore(stage, generation)?;
        Ok(Self {
            machine,
            manifest_sha256,
        })
    }
}

/// 从两份交易副本恢复最高有效世代。
/// Recovers the highest valid generation from two transaction copies.
pub fn recover(
    first: Option<&[u8]>,
    second: Option<&[u8]>,
) -> Result<TransactionRecord, TransactionError> {
    let first = first
        .map(TransactionRecord::decode)
        .transpose()
        .ok()
        .flatten();
    let second = second
        .map(TransactionRecord::decode)
        .transpose()
        .ok()
        .flatten();
    match (first, second) {
        (Some(first), Some(second))
            if first.generation() == second.generation() && first != second =>
        {
            Err(TransactionError::EqualGenerationMismatch)
        }
        (Some(first), Some(second)) => Ok(if first.generation() >= second.generation() {
            first
        } else {
            second
        }),
        (Some(record), None) | (None, Some(record)) => Ok(record),
        (None, None) => Err(TransactionError::CorruptRecord),
    }
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().expect("fixed transaction field"))
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().expect("fixed transaction CRC"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn prepared_record_round_trips_and_every_byte_mutation_fails_or_changes_state() {
        let record = TransactionRecord::prepared(digest(7)).unwrap();
        assert_eq!(record.stage(), UpdateStage::Prepared);
        assert_eq!(record.generation(), 3);
        let encoded = record.encode();
        assert_eq!(TransactionRecord::decode(&encoded), Ok(record));
        for index in 0..TRANSACTION_RECORD_BYTES {
            let mut changed = encoded;
            changed[index] ^= 1;
            match TransactionRecord::decode(&changed) {
                Err(_) => {}
                Ok(decoded) => {
                    assert_ne!(decoded, record, "mutation {index} was accepted unchanged")
                }
            }
        }
    }

    #[test]
    fn transaction_events_are_atomic_and_bound_to_the_manifest() {
        let mut record = TransactionRecord::prepared(digest(8)).unwrap();
        let before = record;
        assert_eq!(
            record.apply(UpdateEvent::BeginTrial),
            Err(TransactionError::Transition(
                TransitionError::InvalidPhase {
                    current: UpdateStage::Prepared,
                    event: UpdateEvent::BeginTrial,
                }
            ))
        );
        assert_eq!(record, before);
        record.apply(UpdateEvent::Commit).unwrap();
        assert_eq!(record.stage(), UpdateStage::Committed);
        assert_eq!(record.manifest_sha256(), digest(8));
    }

    #[test]
    fn recovery_selects_highest_generation_and_rejects_equal_conflicts() {
        let first = TransactionRecord::prepared(digest(1)).unwrap();
        let mut second = first;
        second.apply(UpdateEvent::Commit).unwrap();
        let first_bytes = first.encode();
        let second_bytes = second.encode();
        assert_eq!(recover(Some(&first_bytes), Some(&second_bytes)), Ok(second));
        assert_eq!(recover(Some(&first_bytes), None), Ok(first));

        let conflict = TransactionRecord::prepared(digest(2)).unwrap();
        assert_eq!(
            recover(Some(&first_bytes), Some(&conflict.encode())),
            Err(TransactionError::EqualGenerationMismatch)
        );
    }

    #[test]
    fn zero_digest_and_impossible_state_fail_closed() {
        assert_eq!(
            TransactionRecord::prepared([0; 32]),
            Err(TransactionError::InvalidDigest)
        );
        let mut bytes = TransactionRecord::prepared(digest(3)).unwrap().encode();
        bytes[12..20].copy_from_slice(&0u64.to_le_bytes());
        bytes[20] = UpdateStage::Prepared as u8;
        let crc = crc32fast::hash(&bytes[..CRC_OFFSET]);
        bytes[CRC_OFFSET..].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(
            TransactionRecord::decode(&bytes),
            Err(TransactionError::InvalidState)
        );
    }
}
