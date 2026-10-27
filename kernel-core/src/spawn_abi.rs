//! `system.process.spawn` 的参数块格式与纯规则检查（内核与用户运行时共用，宿主可测）。
//! Parameter block of `system.process.spawn` and its pure admission rules.
//!
//! # 职责
//! * [`SpawnDesc`]（88 字节，小端，v2）：子进程映像、256 位系统调用集合、入口参数、CPU 上限，
//!   以及内核写回的两个句柄。v2 显式携带 magic / version / size，旧格式或伪造头部被拒绝，
//!   不再按字段偏移猜测。
//! * [`check`]：不依赖内核状态的全部前置规则——头部、映像大小、调用集合**只能是调用者集合的子集**
//!   （不能借 spawn 提权）、只能包含已登记的操作、CPU 上限范围、保留字段为 0
//!
//! # 边界
//! 只有格式与无状态规则；子进程数配额、帧配额、ELF 是否可装载由内核在持锁时检查。
//! 为什么单独成文件：用户程序按同一份布局构造参数块，规则可在宿主上穷举测试。
//!
//! # 与旧格式的关系
//! 当前所有 ABI 允许破坏性调整（issue #1）：这里不保留 `u64` 权限字段或 56 字节旧布局，
//! 因此不存在「旧调用者绕过新权限模型」的影子通道。旧布局的 magic 校验会直接拒绝。

use crate::syscall_set::SyscallSet;

/// 参数块字节数（`repr(C)` 布局，见下方字段偏移注释）。
pub const SPAWN_DESC_SIZE: usize = 88;
/// 参数块 magic：ASCII `JSP2`（小端写入）。
pub const SPAWN_DESC_MAGIC: u32 = 0x4A53_5032;
/// 参数块格式版本。
pub const SPAWN_DESC_VERSION: u16 = 2;
/// 子进程映像（ELF）的字节数上限：内核要把它复制进内核缓冲区，必须有界。
/// Upper bound on the child image size.
pub const MAX_IMAGE_BYTES: u64 = 2 * 1024 * 1024;
/// 每个进程同时持有（以进程句柄计）的、由它创建的子进程数上限（防止无界地创建进程）。
/// Upper bound on children a process holds at once.
pub const MAX_CHILDREN: usize = 8;
/// CPU 上限的取值上界（千分比；1000 = 不限）。
pub const CPU_UNLIMITED: u32 = 1000;
/// CPU 上限的取值下界（千分比）：太小的上限会让子进程几乎无法前进，按参数非法拒绝。
pub const MIN_CPU_LIMIT: u32 = 10;

/// `system.process.spawn` 的参数块（v2）。
/// Spawn parameter block (v2).
///
/// 字段偏移（小端）：
/// * 0..4 magic、4..6 version、6..8 size
/// * 8..16 image_ptr、16..24 image_len、24..56 calls（4 个小端 u64）
/// * 56..64 arg、64..68 cpu_limit_permille、68..72 flags
/// * 72..80 out_process、80..88 out_channel
///
/// 调用者填写前 8 个字段；成功时内核写回 `out_process`（父进程中指向子进程的句柄，权限 WAIT）与
/// `out_channel`（父进程中引导通道的端点）。子进程的主线程以（子进程中引导通道另一端的句柄, `arg`）进入。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpawnDesc {
    /// 格式标识（[`SPAWN_DESC_MAGIC`]）。
    pub magic: u32,
    /// 格式版本（[`SPAWN_DESC_VERSION`]）。
    pub version: u16,
    /// 参数块字节数（[`SPAWN_DESC_SIZE`]）。
    pub size: u16,
    /// ELF 映像在调用者内存中的地址。
    pub image_ptr: u64,
    /// ELF 映像字节数。
    pub image_len: u64,
    /// 授予子进程的系统调用集合（256 位；只剩调用者自己的子集）。
    pub calls: SyscallSet,
    /// 子进程主线程的第二个入口参数（原样传递）。
    pub arg: u64,
    /// CPU 上限（千分比，`CPU_UNLIMITED` = 不限）。
    pub cpu_limit_permille: u32,
    /// 保留，必须为 0。
    pub flags: u32,
    /// 输出：父进程中的子进程句柄。
    pub out_process: u64,
    /// 输出：父进程中的引导通道端点句柄。
    pub out_channel: u64,
}

impl Default for SpawnDesc {
    /// 合法的 v2 头部 + 空权限集合 + 未设置映像/参数。
    /// A well-formed v2 header with an empty capability set.
    fn default() -> Self {
        SpawnDesc {
            magic: SPAWN_DESC_MAGIC,
            version: SPAWN_DESC_VERSION,
            size: SPAWN_DESC_SIZE as u16,
            image_ptr: 0,
            image_len: 0,
            calls: SyscallSet::EMPTY,
            arg: 0,
            cpu_limit_permille: 0,
            flags: 0,
            out_process: 0,
            out_channel: 0,
        }
    }
}

/// 参数块被拒的原因（每一项都对应一个稳定的错误码，由内核映射）。
/// Why a spawn request was rejected before any state was touched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnReject {
    /// 头部不合法：magic / version / size 不匹配（旧格式、伪造或截断的调用者）。
    Format,
    /// 映像为空或超过 [`MAX_IMAGE_BYTES`]。
    ImageSize,
    /// 请求的调用不在调用者自己的集合中（试图提权）。
    Escalation,
    /// 请求了未登记的操作 ID。
    UnknownCall,
    /// CPU 上限不在 `[MIN_CPU_LIMIT, CPU_UNLIMITED]` 内。
    CpuLimit,
    /// 保留字段非 0。
    Reserved,
}

fn u64_at(b: &[u8; SPAWN_DESC_SIZE], o: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(v)
}

fn u32_at(b: &[u8; SPAWN_DESC_SIZE], o: usize) -> u32 {
    let mut v = [0u8; 4];
    v.copy_from_slice(&b[o..o + 4]);
    u32::from_le_bytes(v)
}

fn u16_at(b: &[u8; SPAWN_DESC_SIZE], o: usize) -> u16 {
    let mut v = [0u8; 2];
    v.copy_from_slice(&b[o..o + 2]);
    u16::from_le_bytes(v)
}

impl SpawnDesc {
    /// 从 88 字节解码并校验头部；头部不合法时返回 [`SpawnReject::Format`]。
    /// Decodes from bytes and validates the v2 header.
    pub fn decode(b: &[u8; SPAWN_DESC_SIZE]) -> Result<Self, SpawnReject> {
        let magic = u32_at(b, 0);
        let version = u16_at(b, 4);
        let size = u16_at(b, 6);
        if magic != SPAWN_DESC_MAGIC || version != SPAWN_DESC_VERSION || size as usize != SPAWN_DESC_SIZE {
            return Err(SpawnReject::Format);
        }
        let mut call_bytes = [0u8; crate::syscall_set::BYTES];
        call_bytes.copy_from_slice(&b[24..56]);
        Ok(SpawnDesc {
            magic,
            version,
            size,
            image_ptr: u64_at(b, 8),
            image_len: u64_at(b, 16),
            calls: SyscallSet::decode(&call_bytes),
            arg: u64_at(b, 56),
            cpu_limit_permille: u32_at(b, 64),
            flags: u32_at(b, 68),
            out_process: u64_at(b, 72),
            out_channel: u64_at(b, 80),
        })
    }

    /// 编码为 88 字节（头部由字段写入；构造器把合法值放进字段）。
    /// Encodes to bytes.
    pub fn encode(&self) -> [u8; SPAWN_DESC_SIZE] {
        let mut b = [0u8; SPAWN_DESC_SIZE];
        b[0..4].copy_from_slice(&self.magic.to_le_bytes());
        b[4..6].copy_from_slice(&self.version.to_le_bytes());
        b[6..8].copy_from_slice(&self.size.to_le_bytes());
        b[8..16].copy_from_slice(&self.image_ptr.to_le_bytes());
        b[16..24].copy_from_slice(&self.image_len.to_le_bytes());
        let mut call_bytes = [0u8; crate::syscall_set::BYTES];
        self.calls.encode(&mut call_bytes);
        b[24..56].copy_from_slice(&call_bytes);
        b[56..64].copy_from_slice(&self.arg.to_le_bytes());
        b[64..68].copy_from_slice(&self.cpu_limit_permille.to_le_bytes());
        b[68..72].copy_from_slice(&self.flags.to_le_bytes());
        b[72..80].copy_from_slice(&self.out_process.to_le_bytes());
        b[80..88].copy_from_slice(&self.out_channel.to_le_bytes());
        b
    }

    /// 只修改输出字段后的编码（内核写回用：其余字段保持调用者给的值）。
    /// Encoding with the output fields set.
    pub fn with_outputs(mut self, process: u64, channel: u64) -> [u8; SPAWN_DESC_SIZE] {
        self.out_process = process;
        self.out_channel = channel;
        self.encode()
    }
}

const _: () = assert!(core::mem::size_of::<SpawnDesc>() == SPAWN_DESC_SIZE);
const _: () = assert!(SPAWN_DESC_SIZE <= u16::MAX as usize);
// 序列化偏移与 `repr(C)` 布局必须一致：任何字段顺序变化都在编译期失败。
const _: () = {
    use core::mem::offset_of;
    assert!(offset_of!(SpawnDesc, magic) == 0);
    assert!(offset_of!(SpawnDesc, version) == 4);
    assert!(offset_of!(SpawnDesc, size) == 6);
    assert!(offset_of!(SpawnDesc, image_ptr) == 8);
    assert!(offset_of!(SpawnDesc, image_len) == 16);
    assert!(offset_of!(SpawnDesc, calls) == 24);
    assert!(offset_of!(SpawnDesc, arg) == 56);
    assert!(offset_of!(SpawnDesc, cpu_limit_permille) == 64);
    assert!(offset_of!(SpawnDesc, flags) == 68);
    assert!(offset_of!(SpawnDesc, out_process) == 72);
    assert!(offset_of!(SpawnDesc, out_channel) == 80);
};

/// 无状态规则检查：`caller` 是调用者自己的调用集合，`known` 是全部已登记操作的集合。
/// 通过时不保证一定能创建成功（配额与装载由内核继续检查），但被拒的请求一定不改动任何状态。
/// Stateless admission rules for a spawn request.
pub fn check(d: &SpawnDesc, caller: SyscallSet, known: SyscallSet) -> Result<(), SpawnReject> {
    if d.magic != SPAWN_DESC_MAGIC || d.version != SPAWN_DESC_VERSION || d.size as usize != SPAWN_DESC_SIZE {
        return Err(SpawnReject::Format);
    }
    if d.flags != 0 {
        return Err(SpawnReject::Reserved);
    }
    if d.image_len == 0 || d.image_len > MAX_IMAGE_BYTES {
        return Err(SpawnReject::ImageSize);
    }
    if !d.calls.is_subset_of(known) {
        return Err(SpawnReject::UnknownCall);
    }
    if !d.calls.is_subset_of(caller) {
        return Err(SpawnReject::Escalation);
    }
    if d.cpu_limit_permille < MIN_CPU_LIMIT || d.cpu_limit_permille > CPU_UNLIMITED {
        return Err(SpawnReject::CpuLimit);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_desc() -> SpawnDesc {
        SpawnDesc {
            image_ptr: 0x1000,
            image_len: 4096,
            calls: SyscallSet::of(&[0, 1, 3]),
            arg: 7,
            cpu_limit_permille: CPU_UNLIMITED,
            ..Default::default()
        }
    }

    #[test]
    fn spawn_desc_roundtrip_and_outputs() {
        let d = SpawnDesc { out_process: 3, out_channel: 9, flags: 0, ..ok_desc() };
        assert_eq!(SpawnDesc::decode(&d.encode()), Ok(d));
        let w = SpawnDesc::decode(&ok_desc().with_outputs(0x11, 0x22)).expect("内核写回的头部必须保持合法");
        assert_eq!((w.out_process, w.out_channel, w.image_len, w.arg), (0x11, 0x22, 4096, 7));
    }

    #[test]
    fn spawn_desc_rejects_foreign_or_truncated_header() {
        let mut raw = ok_desc().encode();
        raw[0] ^= 0xFF;
        assert_eq!(SpawnDesc::decode(&raw), Err(SpawnReject::Format));
        let mut raw = ok_desc().encode();
        raw[4..6].copy_from_slice(&1u16.to_le_bytes());
        assert_eq!(SpawnDesc::decode(&raw), Err(SpawnReject::Format));
        let mut raw = ok_desc().encode();
        raw[6..8].copy_from_slice(&56u16.to_le_bytes());
        assert_eq!(SpawnDesc::decode(&raw), Err(SpawnReject::Format));
        // 旧 56 字节布局的零字节缓冲区：头部不合法，必须在任何副作用前拒绝。
        assert_eq!(SpawnDesc::decode(&[0u8; SPAWN_DESC_SIZE]), Err(SpawnReject::Format));
    }

    #[test]
    fn spawn_check_accepts_subset() {
        let caller = SyscallSet::of(&[0, 1, 2, 3, 63, 64, 127]);
        let known = caller;
        assert_eq!(check(&ok_desc(), caller, known), Ok(()));
        assert_eq!(check(&SpawnDesc { calls: SyscallSet::EMPTY, ..ok_desc() }, SyscallSet::EMPTY, known), Ok(()));
        assert_eq!(check(&SpawnDesc { calls: SyscallSet::of(&[63, 64, 127]), ..ok_desc() }, caller, known), Ok(()));
        assert_eq!(check(&SpawnDesc { cpu_limit_permille: MIN_CPU_LIMIT, ..ok_desc() }, caller, known), Ok(()));
        assert_eq!(check(&SpawnDesc { image_len: MAX_IMAGE_BYTES, ..ok_desc() }, caller, known), Ok(()));
    }

    #[test]
    fn spawn_check_rejects_each_rule() {
        let known = SyscallSet::of(&[0, 1, 2, 3, 63, 64, 127]);
        // 提权：请求了调用者没有的调用（高编号位也必须被看见）。
        assert_eq!(check(&ok_desc(), SyscallSet::of(&[0, 1]), known), Err(SpawnReject::Escalation));
        assert_eq!(
            check(&SpawnDesc { calls: SyscallSet::of(&[64]), ..ok_desc() }, SyscallSet::of(&[63]), known),
            Err(SpawnReject::Escalation)
        );
        // 未登记的操作即使调用者「有」也拒绝（集合里出现未知位）。
        assert_eq!(check(&SpawnDesc { calls: SyscallSet::of(&[200]), ..ok_desc() }, SyscallSet::FULL, known), Err(SpawnReject::UnknownCall));
        assert_eq!(check(&SpawnDesc { image_len: 0, ..ok_desc() }, known, known), Err(SpawnReject::ImageSize));
        assert_eq!(check(&SpawnDesc { image_len: MAX_IMAGE_BYTES + 1, ..ok_desc() }, known, known), Err(SpawnReject::ImageSize));
        assert_eq!(check(&SpawnDesc { cpu_limit_permille: MIN_CPU_LIMIT - 1, ..ok_desc() }, known, known), Err(SpawnReject::CpuLimit));
        assert_eq!(check(&SpawnDesc { cpu_limit_permille: CPU_UNLIMITED + 1, ..ok_desc() }, known, known), Err(SpawnReject::CpuLimit));
        assert_eq!(check(&SpawnDesc { flags: 1, ..ok_desc() }, known, known), Err(SpawnReject::Reserved));
        assert_eq!(check(&SpawnDesc { magic: 0, ..ok_desc() }, known, known), Err(SpawnReject::Format));
    }

    #[test]
    fn spawn_check_subset_exhaustive_small() {
        // 4 位集合上穷举：通过 ⇔ 请求 ⊆ 调用者
        let known = SyscallSet::of(&[0, 1, 2, 3]);
        for caller in 0u64..16 {
            for calls in 0u64..16 {
                let caller_set = SyscallSet::from_words([caller, 0, 0, 0]);
                let calls_set = SyscallSet::from_words([calls, 0, 0, 0]);
                let r = check(&SpawnDesc { calls: calls_set, ..ok_desc() }, caller_set, known);
                assert_eq!(r.is_ok(), calls & !caller == 0, "caller={:04b} calls={:04b}", caller, calls);
            }
        }
    }

    #[test]
    fn spawn_check_high_ids_63_64_127_and_255() {
        // issue #1 验收：ID 63/64/127 以及更高有效编号必须能被授权，且不能互相串位。
        let known = SyscallSet::of(&[63, 64, 127, 255]);
        for id in [63u32, 64, 127, 255] {
            let one = SyscallSet::from_id(id).expect("容量内的 ID 必须可表示");
            assert_eq!(check(&SpawnDesc { calls: one, ..ok_desc() }, known, known), Ok(()), "id={id}");
            // 调用者只有相邻位时仍然拒绝，证明没有按字粗粒度授权。
            let neighbour = if id == 255 { 127 } else { id + 1 };
            let caller = SyscallSet::from_id(neighbour).expect("容量内的 ID 必须可表示");
            assert_eq!(
                check(&SpawnDesc { calls: one, ..ok_desc() }, caller, known),
                Err(SpawnReject::Escalation),
                "id={id} neighbour={neighbour}"
            );
        }
        // 越界 ID 无法进入参数块：构造阶段就失败，不会被解码成 0 或别的位。
        assert_eq!(SyscallSet::try_of(&[256]), None);
    }
}
