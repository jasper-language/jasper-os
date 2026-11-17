//! LC-2 终态更新归档收据的固定持久格式与双副本提交协议。
//! Fixed persistent format and dual-copy commit protocol for LC-2 terminal archives.
//!
//! 收据只记录已经通过交易状态机验证的终态事实，不接受调用者路径，也不把目录存在
//! 等同于归档成功。存储后端只需实现两个固定副本、flush 和读回；同一协议可供宿主
//! 文件后端与后续内核块设备后端复用。
//! The receipt records only a terminal fact already validated by the transaction state
//! machine. It accepts no caller path and never treats a directory as archive success.

use sha2::{Digest, Sha256};

use crate::update::UpdateStage;

/// 一份归档收据的固定线上长度。
/// Fixed on-wire length of one archive receipt.
pub const ARCHIVE_RECEIPT_BYTES: usize = 128;

const MAGIC: [u8; 8] = *b"JLC2ARC1";
const FORMAT_VERSION: u16 = 1;
const CRC_OFFSET: usize = 100;
const RESERVED_HEADER_OFFSET: usize = 12;
const RESERVED_HEADER_BYTES: usize = 4;
const RESERVED_STAGE_OFFSET: usize = 97;
const RESERVED_STAGE_BYTES: usize = 3;
const RESERVED_TAIL_OFFSET: usize = 104;

/// 一份终态更新归档收据。
/// One terminal update-archive receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArchiveReceipt {
    archive_sequence: u64,
    transaction_id: u64,
    manifest_sha256: [u8; 32],
    previous_sha256: [u8; 32],
    terminal_stage: UpdateStage,
}

/// 归档收据验证、提交或恢复错误。
/// Archive-receipt validation, commit or recovery error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchiveError {
    /// 魔数、版本、长度、保留位或 CRC 非法。
    /// Magic, version, length, reserved bits or CRC are invalid.
    CorruptRecord,
    /// 交易、归档 sequence 或清单摘要不能为零。
    /// Transaction, archive sequence or manifest digest is zero.
    InvalidIdentity,
    /// 只有 Complete 或 RolledBack 可以归档。
    /// Only Complete or RolledBack transactions can be archived.
    NonTerminal,
    /// 新收据不是当前收据的直接后继。
    /// The next receipt is not the exact successor of the current receipt.
    Sequence,
    /// 前序归档摘要不匹配。
    /// The previous archive digest does not match.
    PreviousDigest,
    /// 两份同代收据内容冲突。
    /// Two receipts at the same sequence disagree.
    EqualSequenceMismatch,
    /// 底层写入失败。
    /// The storage backend rejected a write.
    Write,
    /// 持久化刷新失败。
    /// The storage backend failed to flush.
    Flush,
    /// 写入后读回不一致。
    /// Readback differs from the committed bytes.
    Readback,
}

/// 双副本归档收据存储后端。
/// Storage backend for the two archive-receipt copies.
pub trait ArchiveIo {
    /// 写入指定副本的完整固定长度收据。
    /// Writes one complete fixed-length receipt copy.
    fn write_copy(
        &mut self,
        copy: usize,
        bytes: &[u8; ARCHIVE_RECEIPT_BYTES],
    ) -> Result<(), ArchiveError>;

    /// 使此前写入获得持久性。
    /// Makes previous writes durable.
    fn flush(&mut self) -> Result<(), ArchiveError>;

    /// 读取指定副本用于校验。
    /// Reads one copy for validation.
    fn read_copy(
        &mut self,
        copy: usize,
        out: &mut [u8; ARCHIVE_RECEIPT_BYTES],
    ) -> Result<(), ArchiveError>;
}

impl ArchiveReceipt {
    /// 创建一份已绑定终态交易的新收据。
    /// Creates a receipt bound to one terminal transaction.
    pub fn new(
        archive_sequence: u64,
        transaction_id: u64,
        manifest_sha256: [u8; 32],
        previous_sha256: [u8; 32],
        terminal_stage: UpdateStage,
    ) -> Result<Self, ArchiveError> {
        if archive_sequence == 0 || transaction_id == 0 || manifest_sha256 == [0; 32] {
            return Err(ArchiveError::InvalidIdentity);
        }
        if !is_terminal(terminal_stage) {
            return Err(ArchiveError::NonTerminal);
        }
        if archive_sequence == 1 && previous_sha256 != [0; 32] {
            return Err(ArchiveError::PreviousDigest);
        }
        if archive_sequence > 1 && previous_sha256 == [0; 32] {
            return Err(ArchiveError::PreviousDigest);
        }
        Ok(Self {
            archive_sequence,
            transaction_id,
            manifest_sha256,
            previous_sha256,
            terminal_stage,
        })
    }

    /// 单调归档序号。
    /// Monotonic archive sequence.
    pub const fn archive_sequence(self) -> u64 {
        self.archive_sequence
    }

    /// 绑定的启动控制交易标识。
    /// Bound boot-control transaction identifier.
    pub const fn transaction_id(self) -> u64 {
        self.transaction_id
    }

    /// 绑定的完整清单摘要。
    /// Bound complete-manifest digest.
    pub const fn manifest_sha256(self) -> [u8; 32] {
        self.manifest_sha256
    }

    /// 前一份收据的完整编码摘要。
    /// Full encoded digest of the previous receipt.
    pub const fn previous_sha256(self) -> [u8; 32] {
        self.previous_sha256
    }

    /// 已验证的交易终态。
    /// Validated terminal transaction stage.
    pub const fn terminal_stage(self) -> UpdateStage {
        self.terminal_stage
    }

    /// 编码固定 128 字节归档收据。
    /// Encodes the fixed 128-byte archive receipt.
    pub fn encode(self) -> [u8; ARCHIVE_RECEIPT_BYTES] {
        let mut out = [0u8; ARCHIVE_RECEIPT_BYTES];
        out[..8].copy_from_slice(&MAGIC);
        out[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        out[10..12].copy_from_slice(&(ARCHIVE_RECEIPT_BYTES as u16).to_le_bytes());
        out[16..24].copy_from_slice(&self.archive_sequence.to_le_bytes());
        out[24..32].copy_from_slice(&self.transaction_id.to_le_bytes());
        out[32..64].copy_from_slice(&self.manifest_sha256);
        out[64..96].copy_from_slice(&self.previous_sha256);
        out[96] = self.terminal_stage as u8;
        let crc = crc32fast::hash(&out[..CRC_OFFSET]);
        out[CRC_OFFSET..CRC_OFFSET + 4].copy_from_slice(&crc.to_le_bytes());
        out
    }

    /// 解码并验证固定归档收据；未知、不终止或矛盾事实失败关闭。
    /// Decodes and validates a fixed receipt; unknown, non-terminal or contradictory facts fail closed.
    pub fn decode(bytes: &[u8; ARCHIVE_RECEIPT_BYTES]) -> Result<Self, ArchiveError> {
        if bytes[..8] != MAGIC
            || read_u16(&bytes[8..10]) != FORMAT_VERSION
            || usize::from(read_u16(&bytes[10..12])) != ARCHIVE_RECEIPT_BYTES
            || bytes[RESERVED_HEADER_OFFSET..RESERVED_HEADER_OFFSET + RESERVED_HEADER_BYTES]
                != [0; RESERVED_HEADER_BYTES]
            || bytes[RESERVED_STAGE_OFFSET..RESERVED_STAGE_OFFSET + RESERVED_STAGE_BYTES]
                != [0; RESERVED_STAGE_BYTES]
            || read_u32(&bytes[CRC_OFFSET..CRC_OFFSET + 4]) != crc32fast::hash(&bytes[..CRC_OFFSET])
            || bytes[RESERVED_TAIL_OFFSET..].iter().any(|byte| *byte != 0)
        {
            return Err(ArchiveError::CorruptRecord);
        }
        let terminal_stage = match bytes[96] {
            7 => UpdateStage::Complete,
            10 => UpdateStage::RolledBack,
            _ => return Err(ArchiveError::CorruptRecord),
        };
        let mut manifest_sha256 = [0u8; 32];
        manifest_sha256.copy_from_slice(&bytes[32..64]);
        let mut previous_sha256 = [0u8; 32];
        previous_sha256.copy_from_slice(&bytes[64..96]);
        Self::new(
            read_u64(&bytes[16..24]),
            read_u64(&bytes[24..32]),
            manifest_sha256,
            previous_sha256,
            terminal_stage,
        )
    }

    /// 当前收据完整编码的 SHA-256 前序摘要。
    /// SHA-256 chain digest of this receipt's complete encoding.
    pub fn chain_sha256(self) -> [u8; 32] {
        Sha256::digest(self.encode()).into()
    }
}

/// 从两份收据恢复最高有效归档世代。
/// Recovers the highest valid archive generation from two receipt copies.
pub fn recover(
    first: Option<&[u8; ARCHIVE_RECEIPT_BYTES]>,
    second: Option<&[u8; ARCHIVE_RECEIPT_BYTES]>,
) -> Result<ArchiveReceipt, ArchiveError> {
    let first = first.and_then(|bytes| ArchiveReceipt::decode(bytes).ok());
    let second = second.and_then(|bytes| ArchiveReceipt::decode(bytes).ok());
    match (first, second) {
        (Some(first), Some(second))
            if first.archive_sequence == second.archive_sequence && first != second =>
        {
            Err(ArchiveError::EqualSequenceMismatch)
        }
        (Some(first), Some(second)) => {
            let (older, newer) = if first.archive_sequence < second.archive_sequence {
                (first, second)
            } else {
                (second, first)
            };
            if newer.archive_sequence != older.archive_sequence + 1
                || newer.previous_sha256 != older.chain_sha256()
            {
                return Err(ArchiveError::PreviousDigest);
            }
            Ok(newer)
        }
        (Some(receipt), None) | (None, Some(receipt)) => Ok(receipt),
        (None, None) => Err(ArchiveError::CorruptRecord),
    }
}

/// 提交下一份归档收据，并在 flush 后验证实际写入副本。
/// Commits the next archive receipt and verifies the written copy after flush.
///
/// 写入顺序固定为 `write_copy -> flush -> read_copy`。任何失败都不会返回成功，
/// 调用者不得在此之前清理 staging。
/// The order is fixed as `write_copy -> flush -> read_copy`; callers must not clean
/// staging unless this function succeeds.
pub fn commit<IO: ArchiveIo>(
    io: &mut IO,
    current: Option<ArchiveReceipt>,
    next: ArchiveReceipt,
) -> Result<ArchiveReceipt, ArchiveError> {
    match current {
        Some(current) => {
            if next.archive_sequence
                != current
                    .archive_sequence
                    .checked_add(1)
                    .ok_or(ArchiveError::Sequence)?
            {
                return Err(ArchiveError::Sequence);
            }
            if next.previous_sha256 != current.chain_sha256() {
                return Err(ArchiveError::PreviousDigest);
            }
        }
        None => {
            if next.archive_sequence != 1 || next.previous_sha256 != [0; 32] {
                return Err(ArchiveError::Sequence);
            }
        }
    }
    let copy = ((next.archive_sequence - 1) & 1) as usize;
    let bytes = next.encode();
    io.write_copy(copy, &bytes)?;
    io.flush()?;
    let mut readback = [0u8; ARCHIVE_RECEIPT_BYTES];
    io.read_copy(copy, &mut readback)?;
    if readback != bytes {
        return Err(ArchiveError::Readback);
    }
    Ok(next)
}

/// 修复单个损坏或过期副本到最高有效收据；同代冲突不执行写。
/// Repairs one damaged or stale copy to the highest valid receipt; equal conflicts perform no write.
pub fn repair<IO: ArchiveIo>(
    io: &mut IO,
    first: &[u8; ARCHIVE_RECEIPT_BYTES],
    second: &[u8; ARCHIVE_RECEIPT_BYTES],
) -> Result<ArchiveReceipt, ArchiveError> {
    let current = recover(Some(first), Some(second))?;
    let first_current = ArchiveReceipt::decode(first).ok() == Some(current);
    let second_current = ArchiveReceipt::decode(second).ok() == Some(current);
    if first_current && second_current {
        return Ok(current);
    }
    let bytes = current.encode();
    if !first_current {
        io.write_copy(0, &bytes)?;
    }
    if !second_current {
        io.write_copy(1, &bytes)?;
    }
    io.flush()?;
    let mut readback = [0u8; ARCHIVE_RECEIPT_BYTES];
    io.read_copy(0, &mut readback)?;
    if readback != bytes {
        return Err(ArchiveError::Readback);
    }
    io.read_copy(1, &mut readback)?;
    if readback != bytes {
        return Err(ArchiveError::Readback);
    }
    Ok(current)
}

fn is_terminal(stage: UpdateStage) -> bool {
    matches!(stage, UpdateStage::Complete | UpdateStage::RolledBack)
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes(bytes.try_into().expect("fixed archive u16"))
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().expect("fixed archive u32"))
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().expect("fixed archive u64"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt(sequence: u64, transaction: u64, stage: UpdateStage) -> ArchiveReceipt {
        let previous = if sequence == 1 {
            [0; 32]
        } else {
            receipt(sequence - 1, transaction - 1, stage).chain_sha256()
        };
        ArchiveReceipt::new(sequence, transaction, [sequence as u8; 32], previous, stage).unwrap()
    }

    #[derive(Clone)]
    struct MemoryIo {
        copies: [[u8; ARCHIVE_RECEIPT_BYTES]; 2],
        writes: usize,
        flushes: usize,
        fail_write: bool,
        fail_flush: bool,
        corrupt_readback: bool,
    }

    impl MemoryIo {
        fn new(first: [u8; ARCHIVE_RECEIPT_BYTES], second: [u8; ARCHIVE_RECEIPT_BYTES]) -> Self {
            Self {
                copies: [first, second],
                writes: 0,
                flushes: 0,
                fail_write: false,
                fail_flush: false,
                corrupt_readback: false,
            }
        }
    }

    impl ArchiveIo for MemoryIo {
        fn write_copy(
            &mut self,
            copy: usize,
            bytes: &[u8; ARCHIVE_RECEIPT_BYTES],
        ) -> Result<(), ArchiveError> {
            if self.fail_write {
                return Err(ArchiveError::Write);
            }
            let target = self.copies.get_mut(copy).ok_or(ArchiveError::Write)?;
            *target = *bytes;
            self.writes += 1;
            Ok(())
        }

        fn flush(&mut self) -> Result<(), ArchiveError> {
            if self.fail_flush {
                return Err(ArchiveError::Flush);
            }
            self.flushes += 1;
            Ok(())
        }

        fn read_copy(
            &mut self,
            copy: usize,
            out: &mut [u8; ARCHIVE_RECEIPT_BYTES],
        ) -> Result<(), ArchiveError> {
            let source = self.copies.get(copy).ok_or(ArchiveError::Readback)?;
            out.copy_from_slice(source);
            if self.corrupt_readback {
                out[0] ^= 1;
            }
            Ok(())
        }
    }

    #[test]
    fn fixed_receipt_round_trips_and_every_byte_mutation_is_detected() {
        let value = receipt(1, 7, UpdateStage::Complete);
        let encoded = value.encode();
        assert_eq!(ArchiveReceipt::decode(&encoded), Ok(value));
        for index in 0..ARCHIVE_RECEIPT_BYTES {
            let mut changed = encoded;
            changed[index] ^= 1;
            let decoded = ArchiveReceipt::decode(&changed);
            assert_ne!(decoded, Ok(value), "mutation at {index} was accepted");
        }
    }

    #[test]
    fn only_terminal_nonzero_identity_and_valid_first_receipt_are_admitted() {
        assert_eq!(
            ArchiveReceipt::new(1, 1, [1; 32], [0; 32], UpdateStage::Trial),
            Err(ArchiveError::NonTerminal)
        );
        assert_eq!(
            ArchiveReceipt::new(0, 1, [1; 32], [0; 32], UpdateStage::Complete),
            Err(ArchiveError::InvalidIdentity)
        );
        assert_eq!(
            ArchiveReceipt::new(2, 1, [1; 32], [0; 32], UpdateStage::Complete),
            Err(ArchiveError::PreviousDigest)
        );
        assert!(ArchiveReceipt::new(2, 1, [1; 32], [3; 32], UpdateStage::RolledBack).is_ok());
    }

    #[test]
    fn recovery_selects_highest_generation_and_rejects_equal_conflicts() {
        let first = receipt(1, 7, UpdateStage::Complete);
        let second =
            ArchiveReceipt::new(2, 8, [2; 32], first.chain_sha256(), UpdateStage::RolledBack)
                .unwrap();
        assert_eq!(
            recover(Some(&first.encode()), Some(&second.encode())),
            Ok(second)
        );
        assert_eq!(recover(Some(&first.encode()), None), Ok(first));
        let conflict =
            ArchiveReceipt::new(2, 9, [9; 32], first.chain_sha256(), UpdateStage::Complete)
                .unwrap();
        assert_eq!(
            recover(Some(&second.encode()), Some(&conflict.encode())),
            Err(ArchiveError::EqualSequenceMismatch)
        );
        let disconnected =
            ArchiveReceipt::new(3, 9, [9; 32], [7; 32], UpdateStage::Complete).unwrap();
        assert_eq!(
            recover(Some(&second.encode()), Some(&disconnected.encode())),
            Err(ArchiveError::PreviousDigest)
        );
    }

    #[test]
    fn commit_requires_exact_sequence_and_previous_chain_digest() {
        let first = receipt(1, 7, UpdateStage::Complete);
        let second =
            ArchiveReceipt::new(2, 8, [2; 32], first.chain_sha256(), UpdateStage::Complete)
                .unwrap();
        let mut io = MemoryIo::new([0; ARCHIVE_RECEIPT_BYTES], [0; ARCHIVE_RECEIPT_BYTES]);
        assert_eq!(
            commit(&mut io, Some(first), first),
            Err(ArchiveError::Sequence)
        );
        assert_eq!(commit(&mut io, Some(first), second), Ok(second));
        assert_eq!(io.writes, 1);
        assert_eq!(io.flushes, 1);
    }

    #[test]
    fn write_flush_and_readback_failures_do_not_report_success() {
        let first = receipt(1, 7, UpdateStage::Complete);
        let second =
            ArchiveReceipt::new(2, 8, [2; 32], first.chain_sha256(), UpdateStage::Complete)
                .unwrap();
        let mut io = MemoryIo::new(first.encode(), [0; ARCHIVE_RECEIPT_BYTES]);
        io.fail_write = true;
        assert_eq!(
            commit(&mut io, Some(first), second),
            Err(ArchiveError::Write)
        );
        io.fail_write = false;
        io.fail_flush = true;
        assert_eq!(
            commit(&mut io, Some(first), second),
            Err(ArchiveError::Flush)
        );
        io.fail_flush = false;
        io.corrupt_readback = true;
        assert_eq!(
            commit(&mut io, Some(first), second),
            Err(ArchiveError::Readback)
        );
    }

    #[test]
    fn repair_restores_one_torn_copy_but_equal_conflict_writes_nothing() {
        let first = receipt(1, 7, UpdateStage::Complete);
        let second =
            ArchiveReceipt::new(2, 8, [2; 32], first.chain_sha256(), UpdateStage::Complete)
                .unwrap();
        let mut io = MemoryIo::new(first.encode(), second.encode());
        assert_eq!(
            repair(&mut io, &first.encode(), &second.encode()),
            Ok(second)
        );
        assert_eq!(io.writes, 1);
        assert_eq!(io.copies[0], second.encode());

        let conflict =
            ArchiveReceipt::new(2, 9, [9; 32], first.chain_sha256(), UpdateStage::Complete)
                .unwrap();
        let mut io = MemoryIo::new(second.encode(), conflict.encode());
        assert_eq!(
            repair(&mut io, &second.encode(), &conflict.encode()),
            Err(ArchiveError::EqualSequenceMismatch)
        );
        assert_eq!(io.writes, 0);
    }
}
