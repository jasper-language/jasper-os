//! `system.process.spawn` 的参数块格式与纯规则检查（内核与用户运行时共用，宿主可测）。
//! Parameter block of `system.process.spawn` and its pure admission rules.
//!
//! # 职责
//! * [`SpawnDesc`]（48 字节，小端）：子进程映像、授予的系统调用集合、入口参数、CPU 上限，以及内核写回的两个句柄
//! * [`check`]：不依赖内核状态的全部前置规则——映像大小、调用集合**只能是调用者集合的子集**（不能借 spawn 提权）、
//!   只能包含已登记的操作、CPU 上限范围、保留字段为 0
//!
//! # 边界
//! 只有格式与无状态规则；子进程数配额、帧配额、ELF 是否可装载由内核在持锁时检查。
//! 为什么单独成文件：用户程序按同一份布局构造参数块，规则可在宿主上穷举测试。

/// 参数块字节数。
pub const SPAWN_DESC_SIZE: usize = 48;
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

/// `system.process.spawn` 的参数块。
/// Spawn parameter block.
///
/// 调用者填写前 6 个字段；成功时内核写回 `out_process`（父进程中指向子进程的句柄，权限 WAIT）与
/// `out_channel`（父进程中引导通道的端点）。子进程的主线程以（子进程中引导通道另一端的句柄, `arg`）进入。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SpawnDesc {
    /// ELF 映像在调用者内存中的地址。
    pub image_ptr: u64,
    /// ELF 映像字节数。
    pub image_len: u64,
    /// 授予子进程的系统调用集合（位 i = 操作 ID i）。
    pub calls: u64,
    /// 子进程主线程的第二个入口参数（原样传递）。
    pub arg: u64,
    /// CPU 上限（千分比，`CPU_UNLIMITED` = 不限）。
    pub cpu_limit_permille: u32,
    /// 保留，必须为 0。
    pub flags: u32,
    /// 输出：父进程中的子进程句柄。
    pub out_process: u32,
    /// 输出：父进程中的引导通道端点句柄。
    pub out_channel: u32,
}

/// 参数块被拒的原因（每一项都对应一个稳定的错误码，由内核映射）。
/// Why a spawn request was rejected before any state was touched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnReject {
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

impl SpawnDesc {
    /// 从 48 字节解码。
    /// Decodes from bytes.
    pub fn decode(b: &[u8; SPAWN_DESC_SIZE]) -> Self {
        SpawnDesc {
            image_ptr: u64_at(b, 0),
            image_len: u64_at(b, 8),
            calls: u64_at(b, 16),
            arg: u64_at(b, 24),
            cpu_limit_permille: u32_at(b, 32),
            flags: u32_at(b, 36),
            out_process: u32_at(b, 40),
            out_channel: u32_at(b, 44),
        }
    }

    /// 编码为 48 字节。
    /// Encodes to bytes.
    pub fn encode(&self) -> [u8; SPAWN_DESC_SIZE] {
        let mut b = [0u8; SPAWN_DESC_SIZE];
        b[0..8].copy_from_slice(&self.image_ptr.to_le_bytes());
        b[8..16].copy_from_slice(&self.image_len.to_le_bytes());
        b[16..24].copy_from_slice(&self.calls.to_le_bytes());
        b[24..32].copy_from_slice(&self.arg.to_le_bytes());
        b[32..36].copy_from_slice(&self.cpu_limit_permille.to_le_bytes());
        b[36..40].copy_from_slice(&self.flags.to_le_bytes());
        b[40..44].copy_from_slice(&self.out_process.to_le_bytes());
        b[44..48].copy_from_slice(&self.out_channel.to_le_bytes());
        b
    }

    /// 只修改输出字段后的编码（内核写回用：其余字段保持调用者给的值）。
    /// Encoding with the output fields set.
    pub fn with_outputs(mut self, process: u32, channel: u32) -> [u8; SPAWN_DESC_SIZE] {
        self.out_process = process;
        self.out_channel = channel;
        self.encode()
    }
}

const _: () = assert!(core::mem::size_of::<SpawnDesc>() == SPAWN_DESC_SIZE);

/// 无状态规则检查：`caller` 是调用者自己的调用集合，`known` 是全部已登记操作的集合。
/// 通过时不保证一定能创建成功（配额与装载由内核继续检查），但被拒的请求一定不改动任何状态。
/// Stateless admission rules for a spawn request.
pub fn check(d: &SpawnDesc, caller: u64, known: u64) -> Result<(), SpawnReject> {
    if d.flags != 0 {
        return Err(SpawnReject::Reserved);
    }
    if d.image_len == 0 || d.image_len > MAX_IMAGE_BYTES {
        return Err(SpawnReject::ImageSize);
    }
    if d.calls & !known != 0 {
        return Err(SpawnReject::UnknownCall);
    }
    if d.calls & !caller != 0 {
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
        SpawnDesc { image_ptr: 0x1000, image_len: 4096, calls: 0b1011, arg: 7, cpu_limit_permille: CPU_UNLIMITED, ..Default::default() }
    }

    #[test]
    fn spawn_desc_roundtrip_and_outputs() {
        let d = SpawnDesc { out_process: 3, out_channel: 9, flags: 0, ..ok_desc() };
        assert_eq!(SpawnDesc::decode(&d.encode()), d);
        let w = SpawnDesc::decode(&ok_desc().with_outputs(0x11, 0x22));
        assert_eq!((w.out_process, w.out_channel, w.image_len, w.arg), (0x11, 0x22, 4096, 7));
    }

    #[test]
    fn spawn_check_accepts_subset() {
        assert_eq!(check(&ok_desc(), 0b1111, 0xff), Ok(()));
        assert_eq!(check(&SpawnDesc { calls: 0, ..ok_desc() }, 0, 0xff), Ok(()));
        assert_eq!(check(&SpawnDesc { cpu_limit_permille: MIN_CPU_LIMIT, ..ok_desc() }, 0b1111, 0xff), Ok(()));
        assert_eq!(check(&SpawnDesc { image_len: MAX_IMAGE_BYTES, ..ok_desc() }, 0b1111, 0xff), Ok(()));
    }

    #[test]
    fn spawn_check_rejects_each_rule() {
        // 提权：请求了调用者没有的调用
        assert_eq!(check(&ok_desc(), 0b0011, 0xff), Err(SpawnReject::Escalation));
        // 未登记的操作即使调用者「有」也拒绝（集合里出现未知位）
        assert_eq!(check(&SpawnDesc { calls: 1 << 40, ..ok_desc() }, u64::MAX, 0xff), Err(SpawnReject::UnknownCall));
        assert_eq!(check(&SpawnDesc { image_len: 0, ..ok_desc() }, 0b1111, 0xff), Err(SpawnReject::ImageSize));
        assert_eq!(check(&SpawnDesc { image_len: MAX_IMAGE_BYTES + 1, ..ok_desc() }, 0b1111, 0xff), Err(SpawnReject::ImageSize));
        assert_eq!(check(&SpawnDesc { cpu_limit_permille: MIN_CPU_LIMIT - 1, ..ok_desc() }, 0b1111, 0xff), Err(SpawnReject::CpuLimit));
        assert_eq!(check(&SpawnDesc { cpu_limit_permille: CPU_UNLIMITED + 1, ..ok_desc() }, 0b1111, 0xff), Err(SpawnReject::CpuLimit));
        assert_eq!(check(&SpawnDesc { flags: 1, ..ok_desc() }, 0b1111, 0xff), Err(SpawnReject::Reserved));
    }

    #[test]
    fn spawn_check_subset_exhaustive_small() {
        // 4 位集合上穷举：通过 ⇔ 请求 ⊆ 调用者
        for caller in 0u64..16 {
            for calls in 0u64..16 {
                let r = check(&SpawnDesc { calls, ..ok_desc() }, caller, 0xf);
                assert_eq!(r.is_ok(), calls & !caller == 0, "caller={:04b} calls={:04b}", caller, calls);
            }
        }
    }
}
