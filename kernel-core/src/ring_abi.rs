//! 异步环的用户态二进制布局（`system.async.ring.*` 的参数与记录格式）。
//! User-visible binary layout of the asynchronous ring: submission entries, completion entries, enter arguments.
//!
//! # 职责
//! 定义用户程序与内核之间交换的三种固定大小记录，并提供**按字节**编码 / 解码：
//! * [`Sqe`]（32 字节）：一条提交——操作编号、用户标签、两个参数
//! * [`Cqe`]（32 字节）：一条完成——请求 ID、用户标签、操作编号、结果（≥0 为操作结果，<0 为 `-(错误 ID)`）
//! * [`EnterArgs`]（56 字节）：一次 `system.async.ring.enter` 的输入与输出
//!
//! # 为什么按字节编解码
//! 内核从不把用户内存直接当作 Rust 结构体引用：先经用户指针安全层复制到内核缓冲区，再用这里的
//! `decode` 逐字段读取（小端序；所有支持的指令集均为小端）。用户程序可以直接使用 `#[repr(C)]` 结构体，
//! 其内存布局与编码完全一致（由下方的编译期断言锁定）。
//!
//! # 边界
//! 只是格式，不含任何语义检查；语义（哪些操作可经 ring 提交、权限、配额）由内核在提交时检查。

/// 一条提交记录的字节数。
pub const SQE_SIZE: usize = 32;
/// 一条完成记录的字节数。
pub const CQE_SIZE: usize = 32;
/// `enter` 参数块的字节数。
pub const ENTER_ARGS_SIZE: usize = 56;

/// 提交记录（Submission Queue Entry）。
/// Submission entry.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Sqe {
    /// 操作编号（系统接口登记表中的操作 ID）。
    pub op: u32,
    /// 保留标志，必须为 0。
    pub flags: u32,
    /// 用户标签：内核原样带回，从不参与匹配；重复标签合法。
    pub user_tag: u64,
    /// 参数 0（含义由操作定义）。
    pub arg0: u64,
    /// 参数 1（含义由操作定义）。
    pub arg1: u64,
}

/// 完成记录（Completion Queue Entry）。
/// Completion entry.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Cqe {
    /// 内核分配的请求 ID（同一 Ring 内单调递增、永不复用）。
    pub request_id: u64,
    /// 提交时的用户标签。
    pub user_tag: u64,
    /// 操作编号。
    pub op: u32,
    /// 保留，恒为 0。
    pub reserved: u32,
    /// 结果：≥0 为操作结果；<0 为 `-(错误 ID)`，例如被取消时为 `-(system.async.error.cancelled)`。
    pub result: i64,
}

/// `system.async.ring.enter` 的参数块：前半是输入，后半由内核写回。
/// Arguments of `enter`; the kernel writes back the output fields.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EnterArgs {
    /// 输入：提交记录数组的用户地址。
    pub sq_ptr: u64,
    /// 输入：完成记录缓冲区的用户地址。
    pub cq_ptr: u64,
    /// 输入：请求 ID 输出数组的用户地址（每条被接受的提交按顺序写回一个 `u64` 请求 ID，供取消使用；0 = 不需要）。
    pub id_ptr: u64,
    /// 输入：要提交的记录数（≤ 单次批量上限）。
    pub sq_count: u32,
    /// 输入：最多收取的完成记录数（0 = 只提交不收取）。
    pub cq_max: u32,
    /// 输入：至少等到这么多条完成可收取才返回（无法再满足时提前返回）。
    pub wait_min: u32,
    /// 保留，必须为 0。
    pub reserved: u32,
    /// 输出：被接受的提交数（按顺序；遇到第一条被拒的提交即停止）。
    pub submitted: u32,
    /// 输出：本次收取的完成记录数。
    pub reaped: u32,
    /// 输出：第一条被拒提交的错误（`-(错误 ID)`），全部接受时为 0。
    pub first_error: i64,
}

const _: () = assert!(core::mem::size_of::<Sqe>() == SQE_SIZE);
const _: () = assert!(core::mem::size_of::<Cqe>() == CQE_SIZE);
const _: () = assert!(core::mem::size_of::<EnterArgs>() == ENTER_ARGS_SIZE);

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn u64_at(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(a)
}

impl Sqe {
    /// 从 32 字节解码。
    pub fn decode(b: &[u8; SQE_SIZE]) -> Self {
        Sqe { op: u32_at(b, 0), flags: u32_at(b, 4), user_tag: u64_at(b, 8), arg0: u64_at(b, 16), arg1: u64_at(b, 24) }
    }

    /// 编码为 32 字节。
    pub fn encode(&self) -> [u8; SQE_SIZE] {
        let mut b = [0u8; SQE_SIZE];
        b[0..4].copy_from_slice(&self.op.to_le_bytes());
        b[4..8].copy_from_slice(&self.flags.to_le_bytes());
        b[8..16].copy_from_slice(&self.user_tag.to_le_bytes());
        b[16..24].copy_from_slice(&self.arg0.to_le_bytes());
        b[24..32].copy_from_slice(&self.arg1.to_le_bytes());
        b
    }
}

impl Cqe {
    /// 从 32 字节解码。
    pub fn decode(b: &[u8; CQE_SIZE]) -> Self {
        Cqe {
            request_id: u64_at(b, 0),
            user_tag: u64_at(b, 8),
            op: u32_at(b, 16),
            reserved: u32_at(b, 20),
            result: u64_at(b, 24) as i64,
        }
    }

    /// 编码为 32 字节。
    pub fn encode(&self) -> [u8; CQE_SIZE] {
        let mut b = [0u8; CQE_SIZE];
        b[0..8].copy_from_slice(&self.request_id.to_le_bytes());
        b[8..16].copy_from_slice(&self.user_tag.to_le_bytes());
        b[16..20].copy_from_slice(&self.op.to_le_bytes());
        b[20..24].copy_from_slice(&self.reserved.to_le_bytes());
        b[24..32].copy_from_slice(&self.result.to_le_bytes());
        b
    }
}

impl EnterArgs {
    /// 从 56 字节解码。
    pub fn decode(b: &[u8; ENTER_ARGS_SIZE]) -> Self {
        EnterArgs {
            sq_ptr: u64_at(b, 0),
            cq_ptr: u64_at(b, 8),
            id_ptr: u64_at(b, 16),
            sq_count: u32_at(b, 24),
            cq_max: u32_at(b, 28),
            wait_min: u32_at(b, 32),
            reserved: u32_at(b, 36),
            submitted: u32_at(b, 40),
            reaped: u32_at(b, 44),
            first_error: u64_at(b, 48) as i64,
        }
    }

    /// 编码为 56 字节。
    pub fn encode(&self) -> [u8; ENTER_ARGS_SIZE] {
        let mut b = [0u8; ENTER_ARGS_SIZE];
        b[0..8].copy_from_slice(&self.sq_ptr.to_le_bytes());
        b[8..16].copy_from_slice(&self.cq_ptr.to_le_bytes());
        b[16..24].copy_from_slice(&self.id_ptr.to_le_bytes());
        b[24..28].copy_from_slice(&self.sq_count.to_le_bytes());
        b[28..32].copy_from_slice(&self.cq_max.to_le_bytes());
        b[32..36].copy_from_slice(&self.wait_min.to_le_bytes());
        b[36..40].copy_from_slice(&self.reserved.to_le_bytes());
        b[40..44].copy_from_slice(&self.submitted.to_le_bytes());
        b[44..48].copy_from_slice(&self.reaped.to_le_bytes());
        b[48..56].copy_from_slice(&self.first_error.to_le_bytes());
        b
    }

    /// 输出字段（`submitted`、`reaped`、`first_error`）在参数块中的字节偏移与长度。
    pub const OUTPUT_RANGE: (usize, usize) = (40, 16);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_roundtrip_and_match_repr_c_layout() {
        let s = Sqe { op: 3, flags: 0, user_tag: 7, arg0: u64::MAX, arg1: 1 };
        assert_eq!(Sqe::decode(&s.encode()), s);
        let c = Cqe { request_id: 9, user_tag: 7, op: 12, reserved: 0, result: -4105 };
        assert_eq!(Cqe::decode(&c.encode()), c);
        let e = EnterArgs { sq_ptr: 1, cq_ptr: 2, id_ptr: 8, sq_count: 3, cq_max: 4, wait_min: 5, reserved: 0, submitted: 6, reaped: 7, first_error: -4109 };
        assert_eq!(EnterArgs::decode(&e.encode()), e);
        // 编码与 #[repr(C)] 的内存表示逐字节一致（小端目标）
        // SAFETY：Sqe 为 repr(C)、无填充（32 字节由 5 个字段恰好填满），按字节读取合法。
        let raw = unsafe { core::slice::from_raw_parts(&s as *const Sqe as *const u8, SQE_SIZE) };
        assert_eq!(raw, &s.encode()[..]);
        let raw = unsafe { core::slice::from_raw_parts(&e as *const EnterArgs as *const u8, ENTER_ARGS_SIZE) };
        assert_eq!(raw, &e.encode()[..]);
        let (off, len) = EnterArgs::OUTPUT_RANGE;
        assert_eq!(&e.encode()[off..off + len], &raw[off..off + len]);
    }
}
