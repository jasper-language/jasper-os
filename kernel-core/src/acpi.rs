//! ACPI 表的只读解析（处理器枚举所需的子集）：RSDP → RSDT/XSDT → MADT。
//! Read-only ACPI parsing for processor enumeration: RSDP → RSDT/XSDT → MADT.
//!
//! # 职责与边界
//! * 只解析，不分配：物理内存经调用者注入的 [`PhysRead`] 读取（内核经全物理内存映射实现，宿主测试用内存数组）。
//! * 固件表是**不可信输入**：校验签名与校验和，长度设上限，条目长度为 0 或越界即报错，绝不越界或死循环。
//! * 只覆盖处理器枚举：本地中断控制器条目（含 x2 扩展形式）与本地中断控制器地址覆盖条目；
//!   不解析 AML、不处理其他表。
//!
//! # 为什么放在 kernel-core
//! 表格式与指令集无关（x86_64 与部分 AArch64 服务器都用 ACPI），放在这里可以在宿主上用构造的表测试。

use crate::smp::Topology;

/// 物理内存读取能力（由调用者注入）。
/// Physical memory reader supplied by the caller.
pub trait PhysRead {
    /// 从物理地址 `phys` 读取 `buf.len()` 字节；地址不可访问时返回 `false`。
    /// Read `buf.len()` bytes at `phys`; `false` if not accessible.
    fn read(&self, phys: u64, buf: &mut [u8]) -> bool;
}

/// 单张表长度上限（防御损坏或恶意的长度字段）。
pub const MAX_TABLE_LEN: u32 = 1 << 20;
/// 系统描述表头长度。
const SDT_HEADER_LEN: u32 = 36;
/// MADT 中本地中断控制器地址与标志之后、条目开始处的偏移。
const MADT_ENTRIES_OFFSET: u32 = 44;

/// ACPI 解析错误。
/// ACPI parse error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcpiError {
    /// 读取失败（地址不可访问）。
    Unreadable,
    /// 签名不符。
    BadSignature,
    /// 校验和不为零。
    BadChecksum,
    /// 长度字段非法（过短、过长或条目越界）。
    BadLength,
    /// 根表中没有 MADT。
    NoMadt,
}

impl AcpiError {
    /// 规范名。
    /// Canonical name.
    pub const fn name(self) -> &'static str {
        match self {
            AcpiError::Unreadable => "system.firmware.error.unreadable",
            AcpiError::BadSignature => "system.firmware.error.bad_signature",
            AcpiError::BadChecksum => "system.firmware.error.bad_checksum",
            AcpiError::BadLength => "system.firmware.error.bad_length",
            AcpiError::NoMadt => "system.firmware.error.no_madt",
        }
    }
}

/// MADT 中与处理器启动相关的信息。
/// Processor information from the MADT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Madt {
    /// 本地中断控制器寄存器的物理地址（已应用覆盖条目）。
    pub local_controller: u64,
    /// 已启用处理器的硬件标识（引导处理器排在下标 0）。
    pub topology: Topology,
}

fn read_u8(m: &dyn PhysRead, at: u64) -> Result<u8, AcpiError> {
    let mut b = [0u8; 1];
    m.read(at, &mut b).then_some(b[0]).ok_or(AcpiError::Unreadable)
}

fn read_u32(m: &dyn PhysRead, at: u64) -> Result<u32, AcpiError> {
    let mut b = [0u8; 4];
    m.read(at, &mut b).then(|| u32::from_le_bytes(b)).ok_or(AcpiError::Unreadable)
}

fn read_u64(m: &dyn PhysRead, at: u64) -> Result<u64, AcpiError> {
    let mut b = [0u8; 8];
    m.read(at, &mut b).then(|| u64::from_le_bytes(b)).ok_or(AcpiError::Unreadable)
}

/// `[at, at + len)` 的字节和（模 256）是否为零。
fn checksum_ok(m: &dyn PhysRead, at: u64, len: u32) -> Result<bool, AcpiError> {
    let mut sum = 0u8;
    let mut buf = [0u8; 64];
    let mut done = 0u32;
    while done < len {
        let n = (len - done).min(buf.len() as u32) as usize;
        let addr = at.checked_add(done as u64).ok_or(AcpiError::BadLength)?;
        if !m.read(addr, &mut buf[..n]) {
            return Err(AcpiError::Unreadable);
        }
        sum = buf[..n].iter().fold(sum, |s, &b| s.wrapping_add(b));
        done += n as u32;
    }
    Ok(sum == 0)
}

/// 读取并校验 RSDP，返回 (根表地址, 根表条目宽度：XSDT 为 8、RSDT 为 4)。
fn root_table(m: &dyn PhysRead, rsdp: u64) -> Result<(u64, u64), AcpiError> {
    let mut sig = [0u8; 8];
    if !m.read(rsdp, &mut sig) {
        return Err(AcpiError::Unreadable);
    }
    if &sig != b"RSD PTR " {
        return Err(AcpiError::BadSignature);
    }
    if !checksum_ok(m, rsdp, 20)? {
        return Err(AcpiError::BadChecksum);
    }
    let revision = read_u8(m, rsdp + 15)?;
    if revision >= 2 {
        let len = read_u32(m, rsdp + 20)?;
        if !(36..=4096).contains(&len) {
            return Err(AcpiError::BadLength);
        }
        if !checksum_ok(m, rsdp, len)? {
            return Err(AcpiError::BadChecksum);
        }
        let xsdt = read_u64(m, rsdp + 24)?;
        if xsdt != 0 {
            return Ok((xsdt, 8));
        }
    }
    Ok((read_u32(m, rsdp + 16)? as u64, 4))
}

/// 校验位于 `at` 的系统描述表（签名、长度、校验和），返回其长度。
fn table(m: &dyn PhysRead, at: u64, signature: &[u8; 4]) -> Result<u32, AcpiError> {
    let mut sig = [0u8; 4];
    if !m.read(at, &mut sig) {
        return Err(AcpiError::Unreadable);
    }
    if &sig != signature {
        return Err(AcpiError::BadSignature);
    }
    let len = read_u32(m, at + 4)?;
    if !(SDT_HEADER_LEN..=MAX_TABLE_LEN).contains(&len) {
        return Err(AcpiError::BadLength);
    }
    if !checksum_ok(m, at, len)? {
        return Err(AcpiError::BadChecksum);
    }
    Ok(len)
}

/// 在根表中找 MADT（签名 `APIC`）的地址；签名不符的条目跳过，校验失败的 MADT 报错。
fn find_madt(m: &dyn PhysRead, root: u64, width: u64) -> Result<u64, AcpiError> {
    let sig: &[u8; 4] = if width == 8 { b"XSDT" } else { b"RSDT" };
    let len = table(m, root, sig)? as u64;
    let entries = (len - SDT_HEADER_LEN as u64) / width;
    for i in 0..entries {
        let at = root + SDT_HEADER_LEN as u64 + i * width;
        let addr = if width == 8 { read_u64(m, at)? } else { read_u32(m, at)? as u64 };
        let mut s = [0u8; 4];
        if addr != 0 && m.read(addr, &mut s) && &s == b"APIC" {
            return Ok(addr);
        }
    }
    Err(AcpiError::NoMadt)
}

/// 从 RSDP 出发解析 MADT。`boot_hw_id` 是引导处理器的硬件标识（排在拓扑下标 0）。
/// Parse the MADT starting from the RSDP at `rsdp`.
pub fn parse_madt(m: &dyn PhysRead, rsdp: u64, boot_hw_id: u32) -> Result<Madt, AcpiError> {
    let (root, width) = root_table(m, rsdp)?;
    let madt = find_madt(m, root, width)?;
    let len = table(m, madt, b"APIC")?;
    if len < MADT_ENTRIES_OFFSET {
        return Err(AcpiError::BadLength);
    }
    let mut local_controller = read_u32(m, madt + 36)? as u64;
    let mut topology = Topology::boot_only(boot_hw_id);
    let mut off = MADT_ENTRIES_OFFSET;
    while off < len {
        if len - off < 2 {
            return Err(AcpiError::BadLength);
        }
        let at = madt + off as u64;
        let kind = read_u8(m, at)?;
        let elen = read_u8(m, at + 1)? as u32;
        if elen < 2 || elen > len - off {
            return Err(AcpiError::BadLength);
        }
        match (kind, elen) {
            // 本地中断控制器：处理器 UID(1) 硬件标识(1) 标志(4)
            (0, 8..) => {
                let id = read_u8(m, at + 3)? as u32;
                add_cpu(&mut topology, id, read_u32(m, at + 4)?);
            }
            // 本地中断控制器地址覆盖：保留(2) 地址(8)
            (5, 12..) => local_controller = read_u64(m, at + 4)?,
            // x2 扩展本地中断控制器：保留(2) 硬件标识(4) 标志(4) UID(4)
            (9, 16..) => {
                let id = read_u32(m, at + 4)?;
                add_cpu(&mut topology, id, read_u32(m, at + 8)?);
            }
            (0 | 5 | 9, _) => return Err(AcpiError::BadLength),
            _ => {}
        }
        off += elen;
    }
    Ok(Madt { local_controller, topology })
}

/// 标志位 0 = 已启用；未启用的（含仅「可上线」的热插拔位）只计数。
fn add_cpu(t: &mut Topology, id: u32, flags: u32) {
    if flags & 1 != 0 {
        t.push(id);
    } else {
        t.disabled += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 宿主上的「物理内存」：从 0 开始的字节数组。
    struct Mem(Vec<u8>);

    impl PhysRead for Mem {
        fn read(&self, phys: u64, buf: &mut [u8]) -> bool {
            let s = phys as usize;
            match self.0.get(s..s + buf.len()) {
                Some(src) => {
                    buf.copy_from_slice(src);
                    true
                }
                None => false,
            }
        }
    }

    fn fix_checksum(bytes: &mut [u8], at: usize) {
        bytes[at] = 0;
        let sum = bytes.iter().fold(0u8, |s, &b| s.wrapping_add(b));
        bytes[at] = 0u8.wrapping_sub(sum);
    }

    fn sdt(sig: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut t = vec![0u8; 36];
        t[..4].copy_from_slice(sig);
        t.extend_from_slice(body);
        let len = t.len() as u32;
        t[4..8].copy_from_slice(&len.to_le_bytes());
        t[8] = 1;
        fix_checksum(&mut t, 9);
        t
    }

    fn madt_body(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&0xFEE0_0000u32.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes());
        for e in entries {
            b.extend_from_slice(e);
        }
        b
    }

    fn lapic(id: u8, flags: u32) -> Vec<u8> {
        let mut e = vec![0, 8, id, id];
        e.extend_from_slice(&flags.to_le_bytes());
        e
    }

    fn x2apic(id: u32, flags: u32) -> Vec<u8> {
        let mut e = vec![9, 16, 0, 0];
        e.extend_from_slice(&id.to_le_bytes());
        e.extend_from_slice(&flags.to_le_bytes());
        e.extend_from_slice(&id.to_le_bytes());
        e
    }

    /// 布局：RSDP @0x100，根表 @0x200，另一张无关表 @0x400，MADT @0x800。
    fn image(revision: u8, entries: &[Vec<u8>]) -> Mem {
        let mut mem = vec![0u8; 0x2000];
        let other = sdt(b"FACP", &[0u8; 8]);
        mem[0x400..0x400 + other.len()].copy_from_slice(&other);
        let madt = sdt(b"APIC", &madt_body(entries));
        mem[0x800..0x800 + madt.len()].copy_from_slice(&madt);
        let root = if revision >= 2 {
            let mut body = Vec::new();
            body.extend_from_slice(&0x400u64.to_le_bytes());
            body.extend_from_slice(&0x800u64.to_le_bytes());
            sdt(b"XSDT", &body)
        } else {
            let mut body = Vec::new();
            body.extend_from_slice(&0x400u32.to_le_bytes());
            body.extend_from_slice(&0x800u32.to_le_bytes());
            sdt(b"RSDT", &body)
        };
        mem[0x200..0x200 + root.len()].copy_from_slice(&root);
        let mut rsdp = vec![0u8; 36];
        rsdp[..8].copy_from_slice(b"RSD PTR ");
        rsdp[15] = revision;
        if revision >= 2 {
            rsdp[20..24].copy_from_slice(&36u32.to_le_bytes());
            rsdp[24..32].copy_from_slice(&0x200u64.to_le_bytes());
        } else {
            rsdp[16..20].copy_from_slice(&0x200u32.to_le_bytes());
        }
        let mut head = rsdp[..20].to_vec();
        fix_checksum(&mut head, 8);
        rsdp[..20].copy_from_slice(&head);
        if revision >= 2 {
            fix_checksum(&mut rsdp, 32);
        }
        mem[0x100..0x100 + 36].copy_from_slice(&rsdp);
        Mem(mem)
    }

    #[test]
    fn v1_rsdt_lists_enabled_cpus_boot_first() {
        let m = image(0, &[lapic(0, 1), lapic(1, 1), lapic(2, 0), lapic(3, 1)]);
        let madt = parse_madt(&m, 0x100, 0).unwrap();
        assert_eq!(madt.local_controller, 0xFEE0_0000);
        assert_eq!(madt.topology.ids(), &[0, 1, 3]);
        assert_eq!(madt.topology.disabled, 1);
    }

    #[test]
    fn v2_xsdt_with_x2_entries_and_override_and_nonzero_boot() {
        let mut ov = vec![5, 12, 0, 0];
        ov.extend_from_slice(&0xFED0_0000u64.to_le_bytes());
        let m = image(2, &[lapic(0, 1), x2apic(300, 1), ov, lapic(5, 1), vec![1, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]]);
        let madt = parse_madt(&m, 0x100, 5).unwrap();
        assert_eq!(madt.local_controller, 0xFED0_0000);
        assert_eq!(madt.topology.ids(), &[5, 0, 300]);
    }

    #[test]
    fn rejects_bad_signature_and_checksum() {
        let m = image(0, &[lapic(0, 1)]);
        assert_eq!(parse_madt(&m, 0x104, 0), Err(AcpiError::BadSignature));
        let mut bad = image(0, &[lapic(0, 1)]);
        bad.0[0x100 + 16] ^= 0x01; // RSDP 内容变了、校验和未更新
        assert_eq!(parse_madt(&bad, 0x100, 0), Err(AcpiError::BadChecksum));
        let mut bad_madt = image(2, &[lapic(0, 1), lapic(1, 1)]);
        bad_madt.0[0x800 + 44 + 3] = 9; // 改条目不改校验和
        assert_eq!(parse_madt(&bad_madt, 0x100, 0), Err(AcpiError::BadChecksum));
        assert_eq!(parse_madt(&m, 0x1_0000, 0), Err(AcpiError::Unreadable));
    }

    #[test]
    fn rejects_zero_length_entry_and_overrun() {
        let m = image(0, &[lapic(0, 1), vec![0, 0, 0, 0]]);
        assert_eq!(parse_madt(&m, 0x100, 0), Err(AcpiError::BadLength));
        let m = image(0, &[lapic(0, 1), vec![0, 40, 1, 1]]);
        assert_eq!(parse_madt(&m, 0x100, 0), Err(AcpiError::BadLength));
        let m = image(0, &[vec![0, 4, 1, 1]]); // 长度对该类型过短
        assert_eq!(parse_madt(&m, 0x100, 0), Err(AcpiError::BadLength));
    }

    #[test]
    fn missing_madt_reported() {
        let mut m = image(2, &[lapic(0, 1)]);
        m.0[0x800] = b'X'; // MADT 签名被破坏 ⇒ 根表里找不到
        assert_eq!(parse_madt(&m, 0x100, 0), Err(AcpiError::NoMadt));
        assert_eq!(AcpiError::NoMadt.name(), "system.firmware.error.no_madt");
    }

    #[test]
    fn too_many_cpus_counted_not_lost() {
        let entries: Vec<Vec<u8>> = (0..40u8).map(|i| lapic(i, 1)).collect();
        let m = image(0, &entries);
        let madt = parse_madt(&m, 0x100, 0).unwrap();
        assert_eq!(madt.topology.count(), crate::smp::MAX_CPUS);
        assert_eq!(madt.topology.dropped, 40 - crate::smp::MAX_CPUS);
    }
}
