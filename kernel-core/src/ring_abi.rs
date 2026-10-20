//! 异步环的用户态二进制布局（`system.async.ring.*` 的参数与记录格式）。
//! User-visible binary layout of the asynchronous ring: submission entries, completion entries, enter arguments.
//!
//! # 职责
//! 定义用户程序与内核之间交换的三种固定大小记录，并提供**按字节**编码 / 解码：
//! * [`Sqe`]（32 字节）：一条提交——操作编号、用户标签、两个参数
//! * [`Cqe`]（32 字节）：一条完成——请求 ID、用户标签、操作编号、结果（≥0 为操作结果，<0 为 `-(错误 ID)`）
//! * [`EnterArgs`]（56 字节）：一次 `system.async.ring.enter` 的输入与输出
//! * [`MsgDesc`]（40 字节）：`system.channel.send` / `system.channel.recv` 的消息描述（消息体缓冲区、句柄数组、输出字段）
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
/// 消息描述的字节数。
pub const MSG_DESC_SIZE: usize = 40;

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

/// 消息描述：send 时描述要发送的消息体与要转移的句柄；recv 时描述接收缓冲区，并由内核写回输出字段。
/// Message descriptor used by `system.channel.send` / `system.channel.recv`.
///
/// * send：`data_ptr`/`data_len` 是消息体；`handles_ptr` 指向 `handles_cap` 个 `u64` 句柄值（全部随消息移动）
/// * recv：`data_ptr`/`data_len` 是接收缓冲区容量；`handles_ptr`/`handles_cap` 是接收句柄值的数组容量；
///   完成时内核写回 `out_data_len`（实际字节数；缓冲区不足时为**所需**字节数）、`out_handles`（收到的句柄数）、
///   `out_sender`（发送方进程标识低 32 位）与 `out_sender_app`（发送方的应用身份）
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MsgDesc {
    /// 消息体（send）或接收缓冲区（recv）的用户地址。
    pub data_ptr: u64,
    /// 句柄值数组的用户地址（元素为 `u64`）。
    pub handles_ptr: u64,
    /// 消息体长度（send）或接收缓冲区容量（recv）。
    pub data_len: u32,
    /// 句柄数（send）或句柄数组容量（recv）。
    pub handles_cap: u32,
    /// 输出（recv）：消息体字节数；缓冲区不足时为所需字节数。
    pub out_data_len: u32,
    /// 输出（recv）：收到的句柄数。
    pub out_handles: u32,
    /// 输出（recv）：发送方的进程标识低 32 位（由内核盖章，用户态只读）。
    ///
    /// 为什么由内核写：身份必须是"事实"而不是"声明"；用户态无法影响这个字段，
    /// 因此接收方可以据此判断消息来源，而发送方无法伪造。
    /// English: sender identity stamped by the kernel; read-only for user space.
    pub out_sender: u32,
    /// 输出（recv）：发送方的应用身份（`u32`；0 = 发送方未绑定身份）。
    ///
    /// 内核在**发送时**取发送方进程的应用身份并随消息保存，接收时写入这里；发送方之后退出、被回收
    /// 或尝试改写身份都不影响这条消息上的章。用户态写入的值一律被内核覆盖，因此这个字段是
    /// "事实"而不是"声明"：接收方可以据此拒绝匿名来源，发送方无法伪造。
    /// English: application identity stamped by the kernel at send time; user writes are overwritten.
    pub out_sender_app: u32,
}

impl MsgDesc {
    /// 从 40 字节解码。
    pub fn decode(b: &[u8; MSG_DESC_SIZE]) -> Self {
        MsgDesc {
            data_ptr: u64_at(b, 0),
            handles_ptr: u64_at(b, 8),
            data_len: u32_at(b, 16),
            handles_cap: u32_at(b, 20),
            out_data_len: u32_at(b, 24),
            out_handles: u32_at(b, 28),
            out_sender: u32_at(b, 32),
            out_sender_app: u32_at(b, 36),
        }
    }

    /// 编码为 40 字节。
    pub fn encode(&self) -> [u8; MSG_DESC_SIZE] {
        let mut b = [0u8; MSG_DESC_SIZE];
        b[0..8].copy_from_slice(&self.data_ptr.to_le_bytes());
        b[8..16].copy_from_slice(&self.handles_ptr.to_le_bytes());
        b[16..20].copy_from_slice(&self.data_len.to_le_bytes());
        b[20..24].copy_from_slice(&self.handles_cap.to_le_bytes());
        b[24..28].copy_from_slice(&self.out_data_len.to_le_bytes());
        b[28..32].copy_from_slice(&self.out_handles.to_le_bytes());
        b[32..36].copy_from_slice(&self.out_sender.to_le_bytes());
        b[36..40].copy_from_slice(&self.out_sender_app.to_le_bytes());
        b
    }

    /// 输出字段（`out_data_len`、`out_handles`、`out_sender`、`out_sender_app`）在描述中的字节偏移与长度。
    pub const OUTPUT_RANGE: (usize, usize) = (24, 16);
}

const _: () = assert!(core::mem::size_of::<Sqe>() == SQE_SIZE);
const _: () = assert!(core::mem::size_of::<MsgDesc>() == MSG_DESC_SIZE);
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
        let m = MsgDesc { data_ptr: 1, handles_ptr: 2, data_len: 3, handles_cap: 4, out_data_len: 5, out_handles: 6, out_sender: 7, out_sender_app: 0x5157 };
        assert_eq!(MsgDesc::decode(&m.encode()), m);
        assert_eq!(m.out_sender_app, 0x5157);
        // SAFETY：MsgDesc 为 repr(C)、无填充。
        let raw_m = unsafe { core::slice::from_raw_parts(&m as *const MsgDesc as *const u8, MSG_DESC_SIZE) };
        assert_eq!(raw_m, &m.encode()[..]);
        let (off, len) = EnterArgs::OUTPUT_RANGE;
        assert_eq!(&e.encode()[off..off + len], &raw[off..off + len]);
        // 输出区间必须覆盖 out_sender（偏移 32）与 out_sender_app（偏移 36），且总长仍为 40
        let (off, len) = MsgDesc::OUTPUT_RANGE;
        assert_eq!((off, len), (24, 16));
        assert_eq!(&m.encode()[off..off + len], &[5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0, 0x57, 0x51, 0, 0]);
    }

    #[test]
    fn msg_desc_sender_app_roundtrip_and_output_range() {
        let m = MsgDesc {
            data_ptr: 0x1122_3344_5566_7788,
            handles_ptr: 0x99aa_bbcc_ddee_ff00,
            data_len: 17,
            handles_cap: 3,
            out_data_len: 29,
            out_handles: 2,
            out_sender: 0x0102_0304,
            out_sender_app: 0x5157,
        };
        let b = m.encode();
        assert_eq!(MsgDesc::decode(&b), m);
        assert_eq!(MSG_DESC_SIZE, 40);
        // 输出区间覆盖两个身份字段：out_sender 在 32..36，out_sender_app 在 36..40。
        let (off, len) = MsgDesc::OUTPUT_RANGE;
        assert_eq!((off, len), (24, 16));
        assert_eq!(&b[off..off + 8], &[29, 0, 0, 0, 2, 0, 0, 0]);
        assert_eq!(&b[off + 8..off + 12], &0x0102_0304u32.to_le_bytes());
        assert_eq!(&b[off + 12..off + 16], &0x5157u32.to_le_bytes());
    }
}
