//! ACPI 表的只读解析（处理器、平台与设备发现所需的子集）：
//! RSDP → RSDT/XSDT → MADT / FACP / SRAT / SLIT / MCFG / DMAR / WDAT。
//! Read-only ACPI parsing for processor, platform and device discovery.
//!
//! # 职责与边界
//! * 只读解析；物理内存经调用者注入的 [`PhysRead`] 读取（内核经全物理内存映射实现，
//!   宿主测试用内存数组）。完整发现清单按实际条目分配，分配失败明确拒绝。
//! * 固件表是**不可信输入**：校验签名与校验和，长度设上限，条目长度为 0 或越界即报错，绝不越界或死循环。
//! * 处理器、NUMA、固件标识、中断路由和 DMA 重映射；不解析 AML、不写 IOMMU 寄存器。
//!
//! # 为什么放在 kernel-core
//! 表格式与指令集无关（x86_64 与部分 AArch64 服务器都用 ACPI），放在这里可以在宿主上用构造的表测试。

use alloc::vec::Vec;

use crate::pci::Ecam;
use crate::smp::Topology;

/// 物理内存读取能力（由调用者注入）。
/// Physical memory reader supplied by the caller.
pub trait PhysRead {
    /// 从物理地址 `phys` 读取 `buf.len()` 字节；地址不可访问时返回 `false`。
    /// Read `buf.len()` bytes at `phys`; `false` if not accessible.
    fn read(&self, phys: u64, buf: &mut [u8]) -> bool;
}

/// 单张表长度上限（防御损坏或恶意的长度字段）。
pub const MAX_TABLE_LEN: u32 = 1 << 20; // JASPER-HARDCODE-REVIEW: issue=35 source=acpi-table-parser-policy reason=bounded-firmware-table-allocation
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
    /// 根表中没有 FACP（不符合 ACPI 固定平台描述要求）。
    NoFacp,
    /// 根表中没有 SRAT（平台未声明 NUMA affinity）。
    NoSrat,
    /// 根表中没有 MCFG（平台不提供 ECAM）。
    NoMcfg,
    /// 根表中没有 DMAR（平台不暴露 Intel DMA remapping）。
    NoDmar,
    /// 根表中没有 WDAT（平台未声明 ACPI 硬件看门狗）。
    NoWdat,
    /// 无法为完整发现结果分配审计内存。
    Capacity,
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
            AcpiError::NoFacp => "system.firmware.error.no_facp",
            AcpiError::NoSrat => "system.firmware.error.no_srat",
            AcpiError::NoMcfg => "system.firmware.error.no_mcfg",
            AcpiError::NoDmar => "system.firmware.error.no_dmar",
            AcpiError::NoWdat => "system.firmware.error.no_wdat",
            AcpiError::Capacity => "system.firmware.error.capacity",
        }
    }
}

/// Maximum bounded WDAT instruction records retained by the kernel.
pub const MAX_WDAT_INSTRUCTIONS: usize = 64;

/// ACPI Generic Address Structure used by a WDAT action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WdatRegister {
    /// ACPI address-space identifier.
    pub address_space: u8,
    /// Register address in that address space.
    pub address: u64,
    /// Register width in bits.
    pub bit_width: u8,
    /// First significant bit in the register.
    pub bit_offset: u8,
    /// ACPI access width: 1 byte, 2 word, 3 dword.
    pub access_width: u8,
}

/// One bounded ACPI WDAT action instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WdatInstruction {
    pub action: u8,
    pub instruction: u8,
    pub register: WdatRegister,
    pub value: u32,
    pub mask: u32,
}

/// Parsed ACPI Watchdog Action Table.
#[derive(Debug, Clone, Copy)]
pub struct Wdat {
    pub timer_period_ms: u32,
    pub min_count: u32,
    pub max_count: u32,
    pub flags: u8,
    instructions: [Option<WdatInstruction>; MAX_WDAT_INSTRUCTIONS],
    count: usize,
}

impl Wdat {
    /// Parsed actions in firmware table order.
    pub fn instructions(&self) -> impl Iterator<Item = &WdatInstruction> {
        self.instructions[..self.count].iter().filter_map(Option::as_ref)
    }
}

/// 一个 I/O 中断控制器。
/// One I/O interrupt controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IoController {
    /// 硬件标识。
    pub id: u8,
    /// 寄存器物理地址。
    pub address: u64,
    /// 第一条输入线对应的全局中断号。
    pub gsi_base: u32,
}

/// ISA 中断的路由：全局中断号与电气特性。
/// Route of an ISA interrupt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IsaRoute {
    /// 全局中断号。
    pub gsi: u32,
    /// 低电平有效（否则高电平有效）。
    pub active_low: bool,
    /// 电平触发（否则边沿触发）。
    pub level: bool,
}

/// MADT 中与处理器启动、中断路由相关的信息。
/// Processor and interrupt-routing information from the MADT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Madt {
    /// 本地中断控制器寄存器的物理地址（已应用覆盖条目）。
    pub local_controller: u64,
    /// 已启用处理器的硬件标识（引导处理器排在下标 0）。
    pub topology: Topology,
    /// Raw and reconciled firmware processor record counts.
    pub cpu_inventory: CpuInventory,
    io: Vec<IoController>,
    /// (ISA 中断号, 路由)。
    overrides: Vec<(u8, IsaRoute)>,
}

/// Firmware CPU records before and after duplicate reconciliation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CpuInventory {
    /// Local APIC records (MADT type 0).
    pub local_apic_records: usize,
    /// x2APIC records (MADT type 9).
    pub x2apic_records: usize,
    /// Records whose firmware enabled bit is set.
    pub enabled_records: usize,
    /// Records whose firmware enabled bit is clear.
    pub disabled_records: usize,
    /// Repeated hardware IDs across local/x2APIC records.
    pub duplicate_records: usize,
    /// Duplicate records that disagreed on the enabled bit.
    pub conflicting_duplicates: usize,
    /// Distinct hardware IDs enabled by firmware.
    pub unique_enabled: usize,
    /// Distinct hardware IDs reported only as disabled.
    pub unique_disabled: usize,
}

impl CpuInventory {
    pub const fn raw_records(self) -> usize {
        self.local_apic_records.saturating_add(self.x2apic_records)
    }
}

impl Madt {
    /// 已记录的 I/O 中断控制器。
    /// Recorded I/O interrupt controllers.
    pub fn io_controllers(&self) -> &[IoController] {
        &self.io
    }

    /// 负责全局中断号 `gsi` 的 I/O 中断控制器及其输入线号（取 `gsi_base` 不超过 `gsi` 的最大者；
    /// 每个控制器的输入线数要读寄存器才知道，由调用者校验）。
    /// Controller responsible for `gsi`, with the pin number on it.
    pub fn controller_for(&self, gsi: u32) -> Option<(IoController, u32)> {
        self.io_controllers()
            .iter()
            .filter(|c| c.gsi_base <= gsi)
            .max_by_key(|c| c.gsi_base)
            .map(|c| (*c, gsi - c.gsi_base))
    }

    /// ISA 中断 `irq` 的路由：有覆盖条目时按条目，否则恒等映射、高电平有效、边沿触发。
    /// Route of ISA interrupt `irq`.
    pub fn isa_route(&self, irq: u8) -> IsaRoute {
        self.overrides
            .iter()
            .find(|(src, _)| *src == irq)
            .map(|(_, r)| *r)
            .unwrap_or(IsaRoute { // JASPER-HARDCODE-REVIEW: issue=35 source=ACPI-MADT-v1 reason=ISA-identity-route-default-required-by-MADT-binding
                gsi: irq as u32,
                active_low: false,
                level: false,
            })
    }
}

/// 覆盖条目的标志：极性（位 0–1）与触发方式（位 2–3）；00 = 遵从总线规定（ISA：高电平有效、边沿触发）。
fn isa_route_from(gsi: u32, flags: u16) -> IsaRoute {
    IsaRoute {
        gsi,
        active_low: flags & 0b11 == 0b11,
        level: (flags >> 2) & 0b11 == 0b11,
    }
}

fn read_u8(m: &dyn PhysRead, at: u64) -> Result<u8, AcpiError> {
    let mut b = [0u8; 1];
    m.read(at, &mut b)
        .then_some(b[0])
        .ok_or(AcpiError::Unreadable)
}

fn read_u32(m: &dyn PhysRead, at: u64) -> Result<u32, AcpiError> {
    let mut b = [0u8; 4];
    m.read(at, &mut b)
        .then(|| u32::from_le_bytes(b))
        .ok_or(AcpiError::Unreadable)
}

fn read_u16(m: &dyn PhysRead, at: u64) -> Result<u16, AcpiError> {
    let mut b = [0u8; 2];
    m.read(at, &mut b)
        .then(|| u16::from_le_bytes(b))
        .ok_or(AcpiError::Unreadable)
}

fn read_u64(m: &dyn PhysRead, at: u64) -> Result<u64, AcpiError> {
    let mut b = [0u8; 8];
    m.read(at, &mut b)
        .then(|| u64::from_le_bytes(b))
        .ok_or(AcpiError::Unreadable)
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

/// 在根表中找签名为 `want` 的表的地址；签名不符的条目跳过，找不到返回 `Ok(None)`。
fn find_table(
    m: &dyn PhysRead,
    root: u64,
    width: u64,
    want: &[u8; 4],
) -> Result<Option<u64>, AcpiError> {
    let sig: &[u8; 4] = if width == 8 { b"XSDT" } else { b"RSDT" };
    let len = table(m, root, sig)? as u64;
    let entries = (len - SDT_HEADER_LEN as u64) / width;
    for i in 0..entries {
        let at = root + SDT_HEADER_LEN as u64 + i * width;
        let addr = if width == 8 {
            read_u64(m, at)?
        } else {
            read_u32(m, at)? as u64
        };
        let mut s = [0u8; 4];
        if addr != 0 && m.read(addr, &mut s) && &s == want {
            return Ok(Some(addr));
        }
    }
    Ok(None)
}

/// Read-only platform identity facts from the ACPI fixed platform table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareInfo {
    pub acpi_oem_id: Vec<u8>,
    pub acpi_oem_table_id: Vec<u8>,
    pub acpi_oem_revision: u32,
    pub creator_id: Vec<u8>,
    pub creator_revision: u32,
}

impl FirmwareInfo {
    pub fn acpi_oem_id_text(&self) -> Vec<u8> {
        trimmed(&self.acpi_oem_id)
    }

    pub fn acpi_oem_table_id_text(&self) -> Vec<u8> {
        trimmed(&self.acpi_oem_table_id)
    }

    pub fn creator_id_text(&self) -> Vec<u8> {
        trimmed(&self.creator_id)
    }
}

fn trimmed(bytes: &[u8]) -> Vec<u8> {
    let start = bytes
        .iter()
        .position(|byte| *byte != 0 && !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| *byte != 0 && !byte.is_ascii_whitespace())
        .map_or(start, |index| index + 1);
    bytes[start..end].to_vec()
}

fn read_vec(m: &dyn PhysRead, at: u64, len: usize) -> Result<Vec<u8>, AcpiError> {
    let mut out = Vec::new();
    out.try_reserve_exact(len).map_err(|_| AcpiError::Capacity)?;
    out.resize(len, 0);
    if !m.read(at, &mut out) {
        return Err(AcpiError::Unreadable);
    }
    Ok(out)
}

/// Parse the ACPI FACP/FADT platform identity fields.
pub fn parse_firmware_info(m: &dyn PhysRead, rsdp: u64) -> Result<FirmwareInfo, AcpiError> {
    let (root, width) = root_table(m, rsdp)?;
    let at = find_table(m, root, width, b"FACP")?.ok_or(AcpiError::NoFacp)?;
    let len = table(m, at, b"FACP")?;
    if len < SDT_HEADER_LEN {
        return Err(AcpiError::BadLength);
    }
    Ok(FirmwareInfo {
        acpi_oem_id: read_vec(m, at + 10, 6)?,
        acpi_oem_table_id: read_vec(m, at + 16, 8)?,
        acpi_oem_revision: read_u32(m, at + 24)?,
        creator_id: read_vec(m, at + 28, 4)?,
        creator_revision: read_u32(m, at + 32)?,
    })
}

/// One SRAT processor-affinity record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NumaCpuAffinity {
    pub hardware_id: u32,
    pub proximity_domain: u32,
    pub enabled: bool,
}

/// One SRAT memory-affinity record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NumaMemoryAffinity {
    pub proximity_domain: u32,
    pub base: u64,
    pub length: u64,
    pub enabled: bool,
    pub hot_pluggable: bool,
    pub non_volatile: bool,
}

/// Firmware NUMA affinity plus optional SLIT distance matrix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NumaTopology {
    cpus: Vec<NumaCpuAffinity>,
    memory: Vec<NumaMemoryAffinity>,
    localities: Option<usize>,
    distances: Vec<u8>,
    /// SRAT records whose type is recognized but whose length is unsafe.
    pub malformed_records: usize,
}

impl NumaTopology {
    pub fn cpus(&self) -> &[NumaCpuAffinity] {
        &self.cpus
    }

    pub fn memory(&self) -> &[NumaMemoryAffinity] {
        &self.memory
    }

    pub fn localities(&self) -> Option<usize> {
        self.localities
    }

    pub fn distance(&self, from: usize, to: usize) -> Option<u8> {
        let count = self.localities?;
        if from >= count || to >= count {
            return None;
        }
        self.distances.get(from * count + to).copied()
    }

    pub fn domain_count(&self) -> usize {
        let max = self
            .cpus
            .iter()
            .map(|cpu| cpu.proximity_domain)
            .chain(self.memory.iter().map(|memory| memory.proximity_domain))
            .max()
            .map_or(0, |domain| domain as usize + 1);
        max.max(self.localities.unwrap_or(0))
    }
}

/// Parse SRAT affinity records and, when present, the SLIT distance matrix.
///
/// SRAT and SLIT are firmware declarations. Callers must still report which
/// CPUs and memory ranges the kernel admitted and used.
pub fn parse_numa(m: &dyn PhysRead, rsdp: u64) -> Result<NumaTopology, AcpiError> {
    const SRAT_ENTRIES_OFFSET: u32 = 48;
    let (root, width) = root_table(m, rsdp)?;
    let at = find_table(m, root, width, b"SRAT")?.ok_or(AcpiError::NoSrat)?;
    let len = table(m, at, b"SRAT")?;
    if len < SRAT_ENTRIES_OFFSET {
        return Err(AcpiError::BadLength);
    }
    let mut cpus = Vec::new();
    let mut memory = Vec::new();
    let mut malformed_records = 0;
    let mut off = SRAT_ENTRIES_OFFSET;
    while off < len {
        if len - off < 2 {
            return Err(AcpiError::BadLength);
        }
        let entry = at + off as u64;
        let kind = read_u8(m, entry)?;
        let entry_len = read_u8(m, entry + 1)? as u32;
        if entry_len < 2 || entry_len > len - off {
            return Err(AcpiError::BadLength);
        }
        match (kind, entry_len) {
            (0, 16..) => {
                let flags = read_u32(m, entry + 4)?;
                cpus.try_reserve(1).map_err(|_| AcpiError::Capacity)?;
                cpus.push(NumaCpuAffinity {
                    hardware_id: read_u8(m, entry + 3)? as u32,
                    proximity_domain: u32::from(read_u8(m, entry + 2)?)
                        | (u32::from(read_u8(m, entry + 9)?) << 8)
                        | (u32::from(read_u8(m, entry + 10)?) << 16)
                        | (u32::from(read_u8(m, entry + 11)?) << 24),
                    enabled: flags & 1 != 0,
                });
            }
            (2, 24..) => {
                cpus.try_reserve(1).map_err(|_| AcpiError::Capacity)?;
                cpus.push(NumaCpuAffinity {
                    hardware_id: read_u32(m, entry + 8)?,
                    proximity_domain: read_u32(m, entry + 4)?,
                    enabled: read_u32(m, entry + 12)? & 1 != 0,
                });
            }
            (1, 40..) => {
                let flags = read_u32(m, entry + 28)?;
                memory.try_reserve(1).map_err(|_| AcpiError::Capacity)?;
                memory.push(NumaMemoryAffinity {
                    proximity_domain: read_u32(m, entry + 2)?,
                    base: read_u64(m, entry + 8)?,
                    length: read_u64(m, entry + 16)?,
                    enabled: flags & 1 != 0,
                    hot_pluggable: flags & 2 != 0,
                    non_volatile: flags & 4 != 0,
                });
            }
            (1 | 2, _) => return Err(AcpiError::BadLength),
            (0, _) => malformed_records += 1,
            _ => {}
        }
        off += entry_len;
    }

    let mut localities = None;
    let mut distances = Vec::new();
    if let Some(slit) = find_table(m, root, width, b"SLIT")? {
        let slit_len = table(m, slit, b"SLIT")?;
        if slit_len < 44 {
            return Err(AcpiError::BadLength);
        }
        let count = read_u64(m, slit + 36)?;
        let count = usize::try_from(count).map_err(|_| AcpiError::BadLength)?;
        let bytes = count
            .checked_mul(count)
            .ok_or(AcpiError::BadLength)?;
        if 44u32
            .checked_add(u32::try_from(bytes).map_err(|_| AcpiError::BadLength)?)
            .is_none_or(|end| end > slit_len)
        {
            return Err(AcpiError::BadLength);
        }
        distances = read_vec(m, slit + 44, bytes)?;
        localities = Some(count);
    }
    Ok(NumaTopology {
        cpus,
        memory,
        localities,
        distances,
        malformed_records,
    })
}

/// 从 RSDP 出发解析 MADT。`boot_hw_id` 是引导处理器的硬件标识（排在拓扑下标 0）。
/// Parse the MADT starting from the RSDP at `rsdp`.
pub fn parse_madt(m: &dyn PhysRead, rsdp: u64, boot_hw_id: u32) -> Result<Madt, AcpiError> {
    let (root, width) = root_table(m, rsdp)?;
    let madt = find_table(m, root, width, b"APIC")?.ok_or(AcpiError::NoMadt)?;
    let len = table(m, madt, b"APIC")?;
    if len < MADT_ENTRIES_OFFSET {
        return Err(AcpiError::BadLength);
    }
    let mut local_controller = read_u32(m, madt + 36)? as u64;
    let mut cpu_records: Vec<(u32, bool)> = Vec::new();
    let mut cpu_inventory = CpuInventory::default();
    let mut io = Vec::new();
    let mut overrides = Vec::new();
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
                cpu_inventory.local_apic_records += 1;
                reconcile_cpu_record(
                    &mut cpu_records,
                    &mut cpu_inventory,
                    id,
                    read_u32(m, at + 4)? & 1 != 0,
                )?;
            }
            // I/O 中断控制器：标识(1) 保留(1) 地址(4) 全局中断号起点(4)
            (1, 12..) => {
                let c = IoController {
                    id: read_u8(m, at + 2)?,
                    address: read_u32(m, at + 4)? as u64,
                    gsi_base: read_u32(m, at + 8)?,
                };
                io.try_reserve(1).map_err(|_| AcpiError::Capacity)?;
                io.push(c);
            }
            // ISA 中断源覆盖：总线(1) 源(1) 全局中断号(4) 标志(2)
            (2, 10..) => {
                let mut f = [0u8; 2];
                if !m.read(at + 8, &mut f) {
                    return Err(AcpiError::Unreadable);
                }
                let route = isa_route_from(read_u32(m, at + 4)?, u16::from_le_bytes(f));
                let src = read_u8(m, at + 3)?;
                overrides.try_reserve(1).map_err(|_| AcpiError::Capacity)?;
                overrides.push((src, route));
            }
            // 本地中断控制器地址覆盖：保留(2) 地址(8)
            (5, 12..) => local_controller = read_u64(m, at + 4)?,
            // x2 扩展本地中断控制器：保留(2) 硬件标识(4) 标志(4) UID(4)
            (9, 16..) => {
                let id = read_u32(m, at + 4)?;
                cpu_inventory.x2apic_records += 1;
                reconcile_cpu_record(
                    &mut cpu_records,
                    &mut cpu_inventory,
                    id,
                    read_u32(m, at + 8)? & 1 != 0,
                )?;
            }
            (0 | 1 | 2 | 5 | 9, _) => return Err(AcpiError::BadLength),
            _ => {}
        }
        off += elen;
    }
    let mut topology = Topology::boot_only(boot_hw_id);
    for &(id, enabled) in &cpu_records {
        if enabled {
            topology.push(id);
        }
    }
    for &(id, enabled) in &cpu_records {
        if !enabled && !cpu_records.iter().any(|&(other, on)| other == id && on) {
            topology.push_disabled(id);
        }
    }
    cpu_inventory.unique_enabled = cpu_records.iter().filter(|(_, enabled)| *enabled).count();
    cpu_inventory.unique_disabled = cpu_records.iter().filter(|(_, enabled)| !*enabled).count();
    Ok(Madt {
        local_controller,
        topology,
        cpu_inventory,
        io,
        overrides,
    })
}

/// MCFG 中保留字段之后、窗口条目开始处的偏移。
const MCFG_ENTRIES_OFFSET: u32 = 44;
/// MCFG 每个窗口条目的长度。
const MCFG_ENTRY_LEN: u32 = 16;

/// MCFG 解析结果：平台声明的 ECAM 窗口。
/// ECAM windows declared by the MCFG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mcfg {
    windows: Vec<Ecam>,
    /// 总线范围颠倒而未记录的条目数。
    pub dropped: usize,
}

impl Mcfg {
    /// 已记录的窗口（按表中顺序）。
    /// Recorded windows in table order.
    pub fn windows(&self) -> &[Ecam] {
        &self.windows
    }
}

/// 从 RSDP 出发解析 MCFG；根表中没有 MCFG 返回 [`AcpiError::NoMcfg`]。
/// Parse the MCFG starting from the RSDP at `rsdp`.
pub fn parse_mcfg(m: &dyn PhysRead, rsdp: u64) -> Result<Mcfg, AcpiError> {
    let (root, width) = root_table(m, rsdp)?;
    let at = find_table(m, root, width, b"MCFG")?.ok_or(AcpiError::NoMcfg)?;
    let len = table(m, at, b"MCFG")?;
    if len < MCFG_ENTRIES_OFFSET || (len - MCFG_ENTRIES_OFFSET) % MCFG_ENTRY_LEN != 0 {
        return Err(AcpiError::BadLength);
    }
    let mut out = Mcfg {
        windows: Vec::new(),
        dropped: 0,
    };
    let mut off = MCFG_ENTRIES_OFFSET;
    while off < len {
        let e = at + off as u64;
        let mut tail = [0u8; 4];
        if !m.read(e + 8, &mut tail) {
            return Err(AcpiError::Unreadable);
        }
        let window = Ecam {
            base: read_u64(m, e)?,
            segment: u16::from_le_bytes([tail[0], tail[1]]),
            bus_start: tail[2],
            bus_end: tail[3],
        };
        if window.is_empty() {
            out.dropped += 1;
        } else {
            out.windows
                .try_reserve(1)
                .map_err(|_| AcpiError::Capacity)?;
            out.windows.push(window);
        }
        off += MCFG_ENTRY_LEN;
    }
    Ok(out)
}

/// Parse the ACPI WDAT hardware-watchdog table.
///
/// The standard SDT header is 36 bytes. WDAT's own fixed header is 32 bytes, so
/// `header_length` is relative to the end of the standard header. Every action
/// record is copied into a fixed bound before the kernel touches a register.
pub fn parse_wdat(m: &dyn PhysRead, rsdp: u64) -> Result<Wdat, AcpiError> {
    const WDAT_HEADER_LEN: u32 = 32;
    const WDAT_ENTRY_LEN: u32 = 24;

    let (root, width) = root_table(m, rsdp)?;
    let at = find_table(m, root, width, b"WDAT")?.ok_or(AcpiError::NoWdat)?;
    let len = table(m, at, b"WDAT")?;
    let data_offset = read_u32(m, at + 36)?;
    if data_offset < WDAT_HEADER_LEN
        || data_offset > len.saturating_sub(SDT_HEADER_LEN)
    {
        return Err(AcpiError::BadLength);
    }
    let timer_period_ms = read_u32(m, at + 48)?;
    let max_count = read_u32(m, at + 52)?;
    let min_count = read_u32(m, at + 56)?;
    let flags = read_u8(m, at + 60)?;
    let entries = read_u32(m, at + 64)?;
    if timer_period_ms == 0 || min_count > max_count {
        return Err(AcpiError::BadLength);
    }
    if entries as usize > MAX_WDAT_INSTRUCTIONS {
        return Err(AcpiError::Capacity);
    }
    let entries_start = SDT_HEADER_LEN + data_offset;
    let entries_bytes = entries.checked_mul(WDAT_ENTRY_LEN).ok_or(AcpiError::BadLength)?;
    if entries_start.checked_add(entries_bytes).is_none_or(|end| end > len) {
        return Err(AcpiError::BadLength);
    }

    let mut out = Wdat {
        timer_period_ms,
        min_count,
        max_count,
        flags,
        instructions: [None; MAX_WDAT_INSTRUCTIONS],
        count: entries as usize,
    };
    for index in 0..out.count {
        let e = at + u64::from(entries_start + index as u32 * WDAT_ENTRY_LEN);
        let register = WdatRegister {
            address_space: read_u8(m, e + 4)?,
            bit_width: read_u8(m, e + 5)?,
            bit_offset: read_u8(m, e + 6)?,
            access_width: read_u8(m, e + 7)?,
            address: read_u64(m, e + 8)?,
        };
        out.instructions[index] = Some(WdatInstruction {
            action: read_u8(m, e)?,
            instruction: read_u8(m, e + 1)?,
            register,
            value: read_u32(m, e + 16)?,
            mask: read_u32(m, e + 20)?,
        });
    }
    Ok(out)
}

/// DMAR device scope 类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarScopeKind {
    PciEndpoint,
    PciBridge,
    IoApic,
    Hpet,
    AcpiNamespace,
    Reserved(u8),
}

/// 一条 DMAR device scope。`path` 是桥下逐级 `(device, function)`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmarScope {
    pub kind: DmarScopeKind,
    pub enumeration_id: u8,
    pub start_bus: u8,
    path: Vec<(u8, u8)>,
}

impl DmarScope {
    pub fn path(&self) -> &[(u8, u8)] {
        &self.path
    }
}

/// 一个 DMAR hardware unit（DRHD）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmarUnit {
    pub segment: u16,
    pub register_base: u64,
    /// Register set size in 4 KiB pages, as encoded by DMAR.
    pub register_pages: u8,
    pub include_all: bool,
    scopes: Vec<DmarScope>,
}

impl DmarUnit {
    pub fn scopes(&self) -> &[DmarScope] {
        &self.scopes
    }

    /// Whether this DRHD owns a PCI requester. `include_all` is an explicit
    /// firmware statement; for scoped units only PCI endpoint/bridge paths
    /// count. IOAPIC/HPET scopes do not authorize DMA.
    pub fn covers(&self, segment: u16, bus: u8, device: u8, function: u8) -> bool {
        if self.segment != segment {
            return false;
        }
        if self.include_all {
            return true;
        }
        self.scopes().iter().any(|scope| {
            if !matches!(
                scope.kind,
                DmarScopeKind::PciEndpoint | DmarScopeKind::PciBridge
            ) {
                return false;
            }
            if scope.path.is_empty() {
                return false;
            }
            let last = scope.path[scope.path.len() - 1];
            // A multi-hop bridge path cannot be resolved from the final bus
            // number and endpoint alone: intermediate secondary/subordinate
            // buses are not encoded in the path. Treating the last path entry
            // as a direct match would assign a device to the wrong IOMMU unit.
            // Multi-hop scopes therefore remain fail-closed until PCI bridge
            // topology is supplied to this pure parser.
            scope.path.len() == 1 && scope.start_bus == bus && last == (device, function)
        })
    }
}

/// Result of selecting the unique hardware unit that owns one PCI requester.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarUnitSelection {
    /// No DRHD scope owns the requester.
    Missing,
    /// More than one DRHD claims the requester.
    Ambiguous,
}

impl DmarUnitSelection {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Missing => "system.iommu.error.device_unit",
            Self::Ambiguous => "system.iommu.error.ambiguous_scope",
        }
    }
}

/// DMAR 解析结果。`intr_remap` 是固件声明，不是本内核已验证的 IR 状态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dmar {
    pub host_address_width: u8,
    pub intr_remap: bool,
    pub x2apic_opt_out: bool,
    pub x2apic_mode: bool,
    units: Vec<DmarUnit>,
    /// Entries rejected by an explicit semantic rule and not used for routing.
    pub dropped: usize,
}

impl Dmar {
    pub fn units(&self) -> &[DmarUnit] {
        &self.units
    }

    /// Select a unit only when exactly one DRHD owns the requester.
    ///
    /// Overlapping DRHD scopes are firmware ambiguity, not a reason to use the
    /// first table entry. The returned index follows [`Self::units`] order.
    pub fn unit_index_for_unique(
        &self,
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
    ) -> Result<usize, DmarUnitSelection> {
        let mut selected = None;
        for (index, unit) in self.units().iter().enumerate() {
            if unit.covers(segment, bus, device, function) {
                if selected.is_some() {
                    return Err(DmarUnitSelection::Ambiguous);
                }
                selected = Some(index);
            }
        }
        selected.ok_or(DmarUnitSelection::Missing)
    }

    pub fn unit_for_unique(
        &self,
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
    ) -> Result<&DmarUnit, DmarUnitSelection> {
        self.unit_index_for_unique(segment, bus, device, function)
            .map(|index| &self.units[index])
    }
}

const DMAR_ENTRIES_OFFSET: u32 = 48;
const DMAR_DRHD_MIN_LEN: u16 = 16;
const DMAR_SCOPE_MIN_LEN: u16 = 6;

/// 从 RSDP 出发解析 `DMAR`。所有子结构和 device scope 都做边界、
/// 对齐与长度校验；截断的 unit/scope 计入 `dropped`，固件结构损坏失败关闭。
pub fn parse_dmar(m: &dyn PhysRead, rsdp: u64) -> Result<Dmar, AcpiError> {
    let (root, width) = root_table(m, rsdp)?;
    let at = find_table(m, root, width, b"DMAR")?.ok_or(AcpiError::NoDmar)?;
    let len = table(m, at, b"DMAR")?;
    if len < DMAR_ENTRIES_OFFSET {
        return Err(AcpiError::BadLength);
    }
    let host_address_width = read_u8(m, at + 36)?;
    let flags = read_u8(m, at + 37)?;
    if !(1..=64).contains(&host_address_width) {
        return Err(AcpiError::BadLength);
    }
    let mut out = Dmar {
        host_address_width,
        intr_remap: flags & 1 != 0,
        x2apic_opt_out: flags & 2 != 0,
        x2apic_mode: flags & 4 != 0,
        units: Vec::new(),
        dropped: 0,
    };
    let mut off = DMAR_ENTRIES_OFFSET;
    while off < len {
        if len - off < 4 {
            return Err(AcpiError::BadLength);
        }
        let h = at + off as u64;
        let kind = read_u16(m, h)?;
        let elen = read_u16(m, h + 2)?;
        if elen < 4 || u32::from(elen) > len - off {
            return Err(AcpiError::BadLength);
        }
        if kind == 0 {
            if elen < DMAR_DRHD_MIN_LEN {
                return Err(AcpiError::BadLength);
            }
            let mut unit = DmarUnit {
                segment: read_u16(m, h + 6)?,
                register_base: read_u64(m, h + 8)?,
                register_pages: read_u8(m, h + 5)?.max(1),
                include_all: read_u8(m, h + 4)? & 1 != 0,
                scopes: Vec::new(),
            };
            // A zero size field is the architecturally defined minimum
            // 4 KiB register block and is what QEMU's Q35 DMAR emits.
            if unit.register_base == 0 || unit.register_base & 0xfff != 0 {
                return Err(AcpiError::BadLength);
            }
            let mut scope_off = DMAR_DRHD_MIN_LEN;
            while scope_off < elen {
                if elen - scope_off < DMAR_SCOPE_MIN_LEN {
                    return Err(AcpiError::BadLength);
                }
                let s = h + u64::from(scope_off);
                let entry_type = read_u8(m, s)?;
                let slen = read_u16(m, s + 1)?;
                if slen < DMAR_SCOPE_MIN_LEN
                    || slen > elen - scope_off
                    || (slen - DMAR_SCOPE_MIN_LEN) % 2 != 0
                {
                    return Err(AcpiError::BadLength);
                }
                let level_count = ((slen - DMAR_SCOPE_MIN_LEN) / 2) as usize;
                let mut scope = DmarScope {
                    kind: match entry_type {
                        1 => DmarScopeKind::PciEndpoint,
                        2 => DmarScopeKind::PciBridge,
                        3 => DmarScopeKind::IoApic,
                        4 => DmarScopeKind::Hpet,
                        5 => DmarScopeKind::AcpiNamespace,
                        other => DmarScopeKind::Reserved(other),
                    },
                    enumeration_id: read_u8(m, s + 4)?,
                    start_bus: read_u8(m, s + 5)?,
                    path: Vec::new(),
                };
                scope
                    .path
                    .try_reserve(level_count)
                    .map_err(|_| AcpiError::Capacity)?;
                for level in 0..level_count {
                    let p = s + DMAR_SCOPE_MIN_LEN as u64 + level as u64 * 2;
                    scope.path.push((read_u8(m, p)?, read_u8(m, p + 1)?));
                }
                unit.scopes
                    .try_reserve(1)
                    .map_err(|_| AcpiError::Capacity)?;
                unit.scopes.push(scope);
                scope_off += slen;
            }
            out.units
                .try_reserve(1)
                .map_err(|_| AcpiError::Capacity)?;
            out.units.push(unit);
        }
        off += u32::from(elen);
    }
    Ok(out)
}

/// Reconcile duplicate Local APIC/x2APIC records by hardware ID.
///
/// Firmware can publish both legacy and extended records during the x2APIC
/// transition. A disabled compatibility record for a CPU that is enabled by
/// another record is a duplicate fact, not an absent CPU.
fn reconcile_cpu_record(
    records: &mut Vec<(u32, bool)>,
    inventory: &mut CpuInventory,
    id: u32,
    enabled: bool,
) -> Result<(), AcpiError> {
    if enabled {
        inventory.enabled_records += 1;
    } else {
        inventory.disabled_records += 1;
    }
    match records.iter_mut().find(|(existing, _)| *existing == id) {
        Some((_, prior)) => {
            inventory.duplicate_records += 1;
            if *prior != enabled {
                inventory.conflicting_duplicates += 1;
            }
            // An enabled record wins over a disabled compatibility record.
            *prior |= enabled;
        }
        None => {
            records.try_reserve(1).map_err(|_| AcpiError::Capacity)?;
            records.push((id, enabled));
        }
    }
    Ok(())
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
        assert_eq!(madt.topology.iter().collect::<Vec<_>>(), vec![0, 1, 3]);
        assert_eq!(madt.topology.disabled, 1);
        assert_eq!(madt.topology.disabled_ids(), &[2]);
    }

    #[test]
    fn v2_xsdt_with_x2_entries_and_override_and_nonzero_boot() {
        let mut ov = vec![5, 12, 0, 0];
        ov.extend_from_slice(&0xFED0_0000u64.to_le_bytes());
        let m = image(
            2,
            &[
                lapic(0, 1),
                x2apic(300, 1),
                ov,
                lapic(5, 1),
                vec![1, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ],
        );
        let madt = parse_madt(&m, 0x100, 5).unwrap();
        assert_eq!(madt.local_controller, 0xFED0_0000);
        assert_eq!(madt.topology.iter().collect::<Vec<_>>(), vec![5, 0, 300]);
    }

    #[test]
    fn duplicate_legacy_and_x2apic_records_are_not_disabled_cpus() {
        let m = image(
            2,
            &[
                lapic(0, 1),
                lapic(1, 1),
                lapic(2, 0),
                x2apic(1, 0),
                x2apic(2, 0),
                x2apic(3, 1),
            ],
        );
        let madt = parse_madt(&m, 0x100, 0).unwrap();
        assert_eq!(madt.topology.iter().collect::<Vec<_>>(), vec![0, 1, 3]);
        assert_eq!(madt.topology.disabled_ids(), &[2]);
        assert_eq!(madt.cpu_inventory.local_apic_records, 3);
        assert_eq!(madt.cpu_inventory.x2apic_records, 3);
        assert_eq!(madt.cpu_inventory.raw_records(), 6);
        assert_eq!(madt.cpu_inventory.enabled_records, 3);
        assert_eq!(madt.cpu_inventory.disabled_records, 3);
        assert_eq!(madt.cpu_inventory.duplicate_records, 2);
        assert_eq!(madt.cpu_inventory.conflicting_duplicates, 1);
        assert_eq!(madt.cpu_inventory.unique_enabled, 3);
        assert_eq!(madt.cpu_inventory.unique_disabled, 1);
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

    fn ioapic(id: u8, addr: u32, gsi_base: u32) -> Vec<u8> {
        let mut e = vec![1, 12, id, 0];
        e.extend_from_slice(&addr.to_le_bytes());
        e.extend_from_slice(&gsi_base.to_le_bytes());
        e
    }

    fn iso(src: u8, gsi: u32, flags: u16) -> Vec<u8> {
        let mut e = vec![2, 10, 0, src];
        e.extend_from_slice(&gsi.to_le_bytes());
        e.extend_from_slice(&flags.to_le_bytes());
        e
    }

    #[test]
    fn io_controllers_and_isa_overrides() {
        let m = image(
            2,
            &[
                lapic(0, 1),
                ioapic(1, 0xFEC0_0000, 0),
                ioapic(2, 0xFEC1_0000, 24),
                iso(0, 2, 0),
                iso(9, 9, 0b1111),
            ],
        );
        let madt = parse_madt(&m, 0x100, 0).unwrap();
        assert_eq!(madt.io_controllers().len(), 2);
        assert_eq!(
            madt.isa_route(0),
            IsaRoute {
                gsi: 2,
                active_low: false,
                level: false
            }
        );
        assert_eq!(
            madt.isa_route(9),
            IsaRoute {
                gsi: 9,
                active_low: true,
                level: true
            }
        );
        // 没有覆盖条目：恒等映射、ISA 默认电气特性
        assert_eq!(
            madt.isa_route(4),
            IsaRoute {
                gsi: 4,
                active_low: false,
                level: false
            }
        );
        let (c, pin) = madt.controller_for(8).unwrap();
        assert_eq!((c.address, pin), (0xFEC0_0000, 8));
        let (c, pin) = madt.controller_for(30).unwrap();
        assert_eq!((c.id, pin), (2, 6));
    }

    #[test]
    fn routing_entries_short_rejected_and_absent_controller_reported() {
        let m = image(0, &[lapic(0, 1), vec![1, 8, 0, 0, 0, 0, 0, 0]]);
        assert_eq!(parse_madt(&m, 0x100, 0), Err(AcpiError::BadLength));
        let m = image(0, &[lapic(0, 1), vec![2, 6, 0, 0, 0, 0]]);
        assert_eq!(parse_madt(&m, 0x100, 0), Err(AcpiError::BadLength));
        let madt = parse_madt(&image(0, &[lapic(0, 1)]), 0x100, 0).unwrap();
        assert!(madt.io_controllers().is_empty());
        assert_eq!(madt.controller_for(4), None);
        let many: Vec<Vec<u8>> = (0..6u8)
            .map(|i| ioapic(i, 0xFEC0_0000 + i as u32 * 0x1000, i as u32 * 24))
            .collect();
        let madt = parse_madt(&image(0, &many), 0x100, 0).unwrap();
        assert_eq!(madt.io_controllers().len(), 6);
    }

    #[test]
    fn all_isa_overrides_are_retained_without_a_fixed_inventory_limit() {
        let mut entries = vec![lapic(0, 1)];
        entries.extend((0..20u8).map(|source| iso(source, 32 + u32::from(source), 0)));
        let madt = parse_madt(&image(0, &entries), 0x100, 0).unwrap();
        assert_eq!(madt.overrides.len(), 20);
        assert_eq!(madt.isa_route(19).gsi, 51);
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
        assert_eq!(madt.topology.count(), 40);
        assert_eq!(madt.topology.dropped, 0);
        assert_eq!(madt.topology.hw_id(39), Some(39));
    }
    /// 在 `image` 的基础上把 MCFG 放在 @0x1000，并把它加进根表（XSDT 第三项）。
    fn image_with_mcfg(entries: &[(u64, u16, u8, u8)]) -> Mem {
        let mut m = image(2, &[lapic(0, 1)]);
        let mut body = vec![0u8; 8];
        for &(base, seg, start, end) in entries {
            body.extend_from_slice(&base.to_le_bytes());
            body.extend_from_slice(&seg.to_le_bytes());
            body.push(start);
            body.push(end);
            body.extend_from_slice(&[0u8; 4]);
        }
        let mcfg = sdt(b"MCFG", &body);
        m.0[0x1000..0x1000 + mcfg.len()].copy_from_slice(&mcfg);
        let mut root_body = Vec::new();
        for a in [0x400u64, 0x800, 0x1000] {
            root_body.extend_from_slice(&a.to_le_bytes());
        }
        let root = sdt(b"XSDT", &root_body);
        m.0[0x200..0x200 + root.len()].copy_from_slice(&root);
        m
    }

    fn image_with_platform_and_numa() -> Mem {
        let mut m = image(2, &[lapic(0, 1)]);
        let mut facp = sdt(b"FACP", &[0u8; 8]);
        facp[10..16].copy_from_slice(b"JASPER");
        facp[16..24].copy_from_slice(b"AMD TEST");
        facp[24..28].copy_from_slice(&7u32.to_le_bytes());
        facp[28..32].copy_from_slice(b"JSR ");
        facp[32..36].copy_from_slice(&9u32.to_le_bytes());
        fix_checksum(&mut facp, 9);
        m.0[0x400..0x400 + facp.len()].copy_from_slice(&facp);

        let mut srat_body = vec![0u8; 12];
        let mut cpu0 = vec![0, 16, 0, 0];
        cpu0.extend_from_slice(&1u32.to_le_bytes());
        cpu0.push(0);
        cpu0.extend_from_slice(&[0, 0, 0]);
        cpu0.extend_from_slice(&0u32.to_le_bytes());
        srat_body.extend_from_slice(&cpu0);

        let mut cpu1 = vec![2, 24, 0, 0];
        cpu1.extend_from_slice(&1u32.to_le_bytes());
        cpu1.extend_from_slice(&1u32.to_le_bytes());
        cpu1.extend_from_slice(&1u32.to_le_bytes());
        cpu1.extend_from_slice(&0u32.to_le_bytes());
        cpu1.extend_from_slice(&0u32.to_le_bytes());
        srat_body.extend_from_slice(&cpu1);

        let mut cpu2 = vec![2, 24, 0, 0];
        cpu2.extend_from_slice(&1u32.to_le_bytes());
        cpu2.extend_from_slice(&2u32.to_le_bytes());
        cpu2.extend_from_slice(&0u32.to_le_bytes());
        cpu2.extend_from_slice(&0u32.to_le_bytes());
        cpu2.extend_from_slice(&0u32.to_le_bytes());
        srat_body.extend_from_slice(&cpu2);

        let mut memory = vec![1, 40];
        memory.extend_from_slice(&1u32.to_le_bytes());
        memory.extend_from_slice(&[0, 0]);
        memory.extend_from_slice(&0x4_0000_0000u64.to_le_bytes());
        memory.extend_from_slice(&0x8000_0000u64.to_le_bytes());
        memory.extend_from_slice(&0u32.to_le_bytes());
        memory.extend_from_slice(&5u32.to_le_bytes());
        memory.extend_from_slice(&0u64.to_le_bytes());
        srat_body.extend_from_slice(&memory);

        let srat = sdt(b"SRAT", &srat_body);
        m.0[0x1000..0x1000 + srat.len()].copy_from_slice(&srat);

        let mut slit_body = 2u64.to_le_bytes().to_vec();
        slit_body.extend_from_slice(&[10, 20, 20, 10]);
        let slit = sdt(b"SLIT", &slit_body);
        m.0[0x1800..0x1800 + slit.len()].copy_from_slice(&slit);

        let mut root_body = Vec::new();
        for address in [0x400u64, 0x800, 0x1000, 0x1800] {
            root_body.extend_from_slice(&address.to_le_bytes());
        }
        let root = sdt(b"XSDT", &root_body);
        m.0[0x200..0x200 + root.len()].copy_from_slice(&root);
        m
    }

    #[test]
    fn facp_srat_and_slit_report_real_platform_facts() {
        let m = image_with_platform_and_numa();
        let firmware = parse_firmware_info(&m, 0x100).unwrap();
        assert_eq!(firmware.acpi_oem_id_text(), b"JASPER");
        assert_eq!(firmware.acpi_oem_table_id_text(), b"AMD TEST");
        assert_eq!(firmware.acpi_oem_revision, 7);
        assert_eq!(firmware.creator_id_text(), b"JSR");
        assert_eq!(firmware.creator_revision, 9);

        let numa = parse_numa(&m, 0x100).unwrap();
        assert_eq!(numa.domain_count(), 2);
        assert_eq!(numa.cpus().len(), 3);
        assert_eq!(
            numa.cpus()[0],
            NumaCpuAffinity {
                hardware_id: 0,
                proximity_domain: 0,
                enabled: true
            }
        );
        assert_eq!(numa.cpus()[2].enabled, false);
        assert_eq!(numa.memory().len(), 1);
        assert_eq!(numa.memory()[0].base, 0x4_0000_0000);
        assert!(numa.memory()[0].non_volatile);
        assert_eq!(numa.localities(), Some(2));
        assert_eq!(numa.distance(0, 0), Some(10));
        assert_eq!(numa.distance(0, 1), Some(20));
        assert_eq!(numa.distance(1, 0), Some(20));
        assert_eq!(numa.distance(2, 0), None);
    }

    #[test]
    fn mcfg_windows_parsed() {
        let m = image_with_mcfg(&[(0xB000_0000, 0, 0, 0xFF), (0xE000_0000, 1, 0x10, 0x1F)]);
        let mcfg = parse_mcfg(&m, 0x100).unwrap();
        assert_eq!(
            mcfg.windows(),
            &[
                Ecam {
                    base: 0xB000_0000,
                    segment: 0,
                    bus_start: 0,
                    bus_end: 0xFF
                },
                Ecam {
                    base: 0xE000_0000,
                    segment: 1,
                    bus_start: 0x10,
                    bus_end: 0x1F
                },
            ]
        );
        assert_eq!(mcfg.dropped, 0);
        assert!(
            parse_madt(&m, 0x100, 0).is_ok(),
            "加入 MCFG 后 MADT 仍可找到"
        );
    }

    #[test]
    fn mcfg_invalid_is_rejected_without_capping_valid_windows() {
        let mut e: Vec<(u64, u16, u8, u8)> = vec![(0xC000_0000, 0, 9, 3)];
        e.extend((0..5u16).map(|i| (0xD000_0000 + ((i as u64) << 28), i, 0, 0)));
        let mcfg = parse_mcfg(&image_with_mcfg(&e), 0x100).unwrap();
        assert_eq!(mcfg.windows().len(), 5);
        assert_eq!(mcfg.windows()[0].segment, 0);
        assert_eq!(mcfg.dropped, 1, "仅有总线范围颠倒的条目被拒绝");
    }

    #[test]
    fn mcfg_missing_or_malformed_rejected() {
        assert_eq!(
            parse_mcfg(&image(2, &[lapic(0, 1)]), 0x100),
            Err(AcpiError::NoMcfg)
        );
        assert_eq!(AcpiError::NoMcfg.name(), "system.firmware.error.no_mcfg");
        let mut ragged = image_with_mcfg(&[(0xB000_0000, 0, 0, 0xFF)]);
        // 长度改成不是整条目，再修正校验和：长度检查必须拒绝。
        ragged.0[0x1000 + 4..0x1000 + 8].copy_from_slice(&(36u32 + 8 + 12).to_le_bytes());
        let mut t = ragged.0[0x1000..0x1000 + 56].to_vec();
        fix_checksum(&mut t, 9);
        ragged.0[0x1000..0x1000 + 56].copy_from_slice(&t);
        assert_eq!(parse_mcfg(&ragged, 0x100), Err(AcpiError::BadLength));
        let mut bad = image_with_mcfg(&[(0xB000_0000, 0, 0, 0xFF)]);
        bad.0[0x1000 + 44] ^= 0x10; // 改条目不改校验和
        assert_eq!(parse_mcfg(&bad, 0x100), Err(AcpiError::BadChecksum));
    }

    fn image_with_dmar(drhd: Vec<u8>) -> Mem {
        let mut m = image(2, &[lapic(0, 1)]);
        let mut body = vec![0u8; 12];
        body[0] = 48;
        body[1] = 0b111;
        body.extend_from_slice(&drhd);
        let dmar = sdt(b"DMAR", &body);
        m.0[0x1000..0x1000 + dmar.len()].copy_from_slice(&dmar);
        let mut root_body = Vec::new();
        for a in [0x400u64, 0x800, 0x1000] {
            root_body.extend_from_slice(&a.to_le_bytes());
        }
        let root = sdt(b"XSDT", &root_body);
        m.0[0x200..0x200 + root.len()].copy_from_slice(&root);
        m
    }

    fn drhd_with_scopes(include_all: bool, paths: &[Vec<(u8, u8)>]) -> Vec<u8> {
        let mut unit = vec![0u8; 16];
        unit[4] = u8::from(include_all);
        unit[5] = 0; // minimum 4 KiB block
        unit[8..16].copy_from_slice(&0xFED9_0000u64.to_le_bytes());
        for (index, path) in paths.iter().enumerate() {
            let length = (6 + path.len() * 2) as u16;
            unit.push(1);
            unit.extend_from_slice(&length.to_le_bytes());
            unit.extend_from_slice(&[0, index as u8, 0]);
            for &(device, function) in path {
                unit.push(device);
                unit.push(function);
            }
        }
        let total = unit.len() as u16;
        unit[..2].copy_from_slice(&0u16.to_le_bytes());
        unit[2..4].copy_from_slice(&total.to_le_bytes());
        unit
    }

    fn drhd_with_scope(include_all: bool, path: &[(u8, u8)]) -> Vec<u8> {
        drhd_with_scopes(include_all, &[path.to_vec()])
    }

    #[test]
    fn dmar_hardware_units_and_scopes_parsed() {
        let m = image_with_dmar(drhd_with_scope(false, &[(2, 0)]));
        let dmar = parse_dmar(&m, 0x100).unwrap();
        assert_eq!(dmar.host_address_width, 48);
        assert!(dmar.intr_remap && dmar.x2apic_opt_out && dmar.x2apic_mode);
        assert_eq!(dmar.units().len(), 1);
        let unit = &dmar.units()[0];
        assert_eq!(unit.register_base, 0xFED9_0000);
        assert_eq!(unit.register_pages, 1);
        assert_eq!(unit.scopes().len(), 1);
        assert_eq!(unit.scopes()[0].kind, DmarScopeKind::PciEndpoint);
        assert_eq!(unit.scopes()[0].path(), &[(2, 0)]);
        assert!(unit.covers(0, 0, 2, 0));
        assert!(!unit.covers(0, 0, 3, 0));
        assert_eq!(
            dmar.unit_for_unique(0, 0, 2, 0)
                .map(|unit| unit.register_base),
            Ok(0xFED9_0000)
        );
        assert_eq!(
            dmar.unit_for_unique(0, 0, 3, 0),
            Err(DmarUnitSelection::Missing)
        );
    }

    #[test]
    fn dmar_inventory_follows_firmware_lengths_without_fixed_capacities() {
        let mut entries = Vec::new();
        for index in 0..10u8 {
            let mut unit = drhd_with_scope(false, &[(index, 0)]);
            unit[8..16].copy_from_slice(&(0xFED9_0000u64 + index as u64 * 0x1000).to_le_bytes());
            entries.extend(unit);
        }
        let parsed = parse_dmar(&image_with_dmar(entries), 0x100).unwrap();
        assert_eq!(parsed.units().len(), 10);
        assert_eq!(parsed.dropped, 0);

        let paths: Vec<_> = (0..40u8).map(|index| vec![(index, 0)]).collect();
        let parsed =
            parse_dmar(&image_with_dmar(drhd_with_scopes(false, &paths)), 0x100).unwrap();
        assert_eq!(parsed.units().len(), 1);
        assert_eq!(parsed.units()[0].scopes().len(), 40);
        assert_eq!(parsed.dropped, 0);

        let deep_path: Vec<_> = (0..12u8).map(|device| (device, 0)).collect();
        let parsed = parse_dmar(
            &image_with_dmar(drhd_with_scopes(false, &[deep_path.clone()])),
            0x100,
        )
        .unwrap();
        assert_eq!(parsed.units()[0].scopes()[0].path(), deep_path);
    }

    #[test]
    fn dmar_include_all_and_negative_scope_types() {
        let dmar = parse_dmar(&image_with_dmar(drhd_with_scope(true, &[])), 0x100).unwrap();
        assert!(dmar.units()[0].covers(0, 0xff, 0x1f, 7));
        let mut ioapic = drhd_with_scope(false, &[]);
        ioapic[16] = 3;
        let dmar = parse_dmar(&image_with_dmar(ioapic), 0x100).unwrap();
        assert!(!dmar.units()[0].covers(0, 0, 0, 0));
    }

    #[test]
    fn dmar_selects_exactly_one_hardware_unit_or_fails_closed() {
        let first = drhd_with_scope(false, &[(2, 0)]);
        let mut second = drhd_with_scope(false, &[(3, 0)]);
        second[8..16].copy_from_slice(&0xFED9_1000u64.to_le_bytes());
        let mut entries = first;
        entries.extend(second);
        let dmar = parse_dmar(&image_with_dmar(entries), 0x100).unwrap();
        assert_eq!(dmar.units().len(), 2);
        assert_eq!(dmar.unit_index_for_unique(0, 0, 2, 0), Ok(0));
        assert_eq!(dmar.unit_index_for_unique(0, 0, 3, 0), Ok(1));
        assert_eq!(
            dmar.unit_index_for_unique(0, 0, 4, 0),
            Err(DmarUnitSelection::Missing)
        );

        let first = drhd_with_scope(false, &[(2, 0)]);
        let mut second = drhd_with_scope(false, &[(2, 0)]);
        second[8..16].copy_from_slice(&0xFED9_1000u64.to_le_bytes());
        let mut overlap = first;
        overlap.extend(second);
        let dmar = parse_dmar(&image_with_dmar(overlap), 0x100).unwrap();
        assert_eq!(
            dmar.unit_index_for_unique(0, 0, 2, 0),
            Err(DmarUnitSelection::Ambiguous)
        );
        assert_eq!(DmarUnitSelection::Ambiguous.name(), "system.iommu.error.ambiguous_scope");
    }

    #[test]
    fn dmar_multihop_scope_is_not_matched_without_bridge_topology() {
        let dmar =
            parse_dmar(&image_with_dmar(drhd_with_scope(false, &[(1, 0), (2, 0)])), 0x100)
                .unwrap();
        assert!(!dmar.units()[0].covers(0, 0, 2, 0));
        assert!(!dmar.units()[0].covers(0, 5, 2, 0));
        assert_eq!(
            dmar.unit_index_for_unique(0, 0, 2, 0),
            Err(DmarUnitSelection::Missing)
        );
    }

    #[test]
    fn dmar_missing_and_malformed_scopes_fail_closed() {
        assert_eq!(
            parse_dmar(&image(2, &[lapic(0, 1)]), 0x100),
            Err(AcpiError::NoDmar)
        );
        assert_eq!(AcpiError::NoDmar.name(), "system.firmware.error.no_dmar");

        let mut malformed = image_with_dmar(drhd_with_scope(false, &[(2, 0)]));
        // Make the scope length larger than its containing DRHD, then update
        // the DMAR checksum so the parser reaches structural validation.
        malformed.0[0x1000 + 48 + 16 + 1] = 32;
        let dmar_len =
            u32::from_le_bytes(malformed.0[0x1000 + 4..0x1000 + 8].try_into().unwrap()) as usize;
        let mut table = malformed.0[0x1000..0x1000 + dmar_len].to_vec();
        fix_checksum(&mut table, 9);
        malformed.0[0x1000..0x1000 + dmar_len].copy_from_slice(&table);
        assert_eq!(parse_dmar(&malformed, 0x100), Err(AcpiError::BadLength));
    }

    #[test]
    fn wdat_parses_bounded_actions_and_rejects_missing_table() {
        let mut body = vec![0u8; 32];
        body[0..4].copy_from_slice(&32u32.to_le_bytes());
        body[12..16].copy_from_slice(&10u32.to_le_bytes());
        body[16..20].copy_from_slice(&100u32.to_le_bytes());
        body[20..24].copy_from_slice(&1u32.to_le_bytes());
        body[24] = 1;
        body[28..32].copy_from_slice(&1u32.to_le_bytes());
        let mut action = vec![0u8; 24];
        action[0] = 6;
        action[1] = 2;
        action[4] = 1;
        action[5] = 32;
        action[6] = 0;
        action[7] = 3;
        action[8..16].copy_from_slice(&0x1234u64.to_le_bytes());
        action[20..24].copy_from_slice(&0xffffu32.to_le_bytes());
        body.extend(action);

        let mut mem = image(2, &[lapic(0, 1)]);
        let wdat = sdt(b"WDAT", &body);
        mem.0[0x1000..0x1000 + wdat.len()].copy_from_slice(&wdat);
        let root = sdt(b"XSDT", &0x1000u64.to_le_bytes());
        mem.0[0x200..0x200 + root.len()].copy_from_slice(&root);

        let parsed = parse_wdat(&mem, 0x100).unwrap();
        assert_eq!(parsed.timer_period_ms, 10);
        assert_eq!((parsed.min_count, parsed.max_count), (1, 100));
        let actions: Vec<_> = parsed.instructions().copied().collect();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].action, 6);
        assert_eq!(actions[0].register.address_space, 1);
        assert_eq!(actions[0].register.address, 0x1234);
        assert_eq!(actions[0].mask, 0xffff);
        assert!(matches!(
            parse_wdat(&image(2, &[lapic(0, 1)]), 0x100),
            Err(AcpiError::NoWdat)
        ));
    }
}
