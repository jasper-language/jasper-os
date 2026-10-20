//! 启动期容量：对象表、任务表、实时表的容量在启动时决定，而不是写死在编译期。
//! Boot-time capacities: object, task and real-time table sizes are decided at boot.
//!
//! # 职责
//! * [`BootCapacity`]：三张表的容量；默认值来自生效配置档；
//! * 启动容量记录（[`RECORD_LEN`] 字节）：内核镜像里留一份可被宿主工具改写的记录，
//!   [`encode`] 生成、[`parse`] 解析——同一份镜像不必重新编译就能以不同容量启动；
//! * [`resolve`]：把「默认值 + 记录里的覆盖值」合成最终容量，并在**启动期**拒绝越界或放不进内存的配置，
//!   拒绝时给出结构化原因（哪一项、取值、允许范围、为什么）；
//! * [`InstallError`]：表安装启动期存储时的拒绝原因（对象表与实时表共用）。
//!
//! # 为什么用镜像内的记录而不是启动命令行
//! 四个指令集的引导方式不同：x86_64 的引导器不传命令行，AArch64 / RISC-V 才有设备树 `bootargs`。
//! 镜像内的定长记录对四个指令集是同一种机制，也不需要在内核里写命令行解析器。
//!
//! # 边界
//! 只做格式与判定，不分配内存、不碰任何表（安装由内核完成）。

use crate::config::bounds;

/// 启动容量记录的字节数。
pub const RECORD_LEN: usize = 32;

/// 记录格式版本。
pub const RECORD_VERSION: u32 = 1;

/// 记录开头的标记。宿主工具在镜像里按它定位记录，要求**恰好出现一次**。
pub const RECORD_MAGIC: [u8; 8] = *b"JSRBCAP\x01";

/// 按位取反后的标记：内核解析时与它比较，避免标记的第二份拷贝出现在内核只读数据里，
/// 让宿主工具误判记录位置。
const MAGIC_INVERTED: [u8; 8] = invert(RECORD_MAGIC);

const fn invert(m: [u8; 8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    let mut i = 0;
    while i < 8 {
        out[i] = !m[i];
        i += 1;
    }
    out
}

/// 三张表的容量。
/// Capacities of the three boot-sized tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootCapacity {
    /// 内核对象表的槽位数。
    pub objects: usize,
    /// 调度器任务槽位数（含引导线程）。
    pub tasks: usize,
    /// 实时任务在册表的容量。
    pub rt: usize,
}

/// 记录里的覆盖值（`None` = 沿用配置档默认值）。
/// Overrides carried by the record (`None` keeps the profile default).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Overrides {
    /// 对象表容量。
    pub objects: Option<u32>,
    /// 任务槽位数。
    pub tasks: Option<u32>,
    /// 实时表容量。
    pub rt: Option<u32>,
}

impl Overrides {
    /// 是否有任何一项被覆盖。
    pub const fn any(&self) -> bool {
        self.objects.is_some() || self.tasks.is_some() || self.rt.is_some()
    }
}

/// 记录损坏的原因（记录损坏 ⇒ 拒绝启动：带着来路不明的容量跑起来，后面全是猜的）。
/// Why a capacity record is malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordError {
    /// 标记不对。
    BadMagic,
    /// 版本不认识。
    BadVersion(u32),
    /// 保留字段不为 0。
    BadReserved,
}

impl RecordError {
    /// 稳定文本名。
    pub const fn as_str(&self) -> &'static str {
        match self {
            RecordError::BadMagic => "bad_magic",
            RecordError::BadVersion(_) => "bad_version",
            RecordError::BadReserved => "bad_reserved",
        }
    }
}

/// 生成一份记录（值为 0 的字段表示「不覆盖」）。`const`：内核用它初始化镜像里的默认记录。
/// Encode a record; zero means "no override".
pub const fn encode(ov: Overrides) -> [u8; RECORD_LEN] {
    let mut out = [0u8; RECORD_LEN];
    let mut i = 0;
    while i < 8 {
        out[i] = RECORD_MAGIC[i];
        i += 1;
    }
    put(&mut out, 8, RECORD_VERSION);
    put(&mut out, 16, unwrap_or_zero(ov.objects));
    put(&mut out, 20, unwrap_or_zero(ov.tasks));
    put(&mut out, 24, unwrap_or_zero(ov.rt));
    out
}

const fn unwrap_or_zero(v: Option<u32>) -> u32 {
    match v {
        Some(x) => x,
        None => 0,
    }
}

const fn put(out: &mut [u8; RECORD_LEN], at: usize, v: u32) {
    let b = v.to_le_bytes();
    out[at] = b[0];
    out[at + 1] = b[1];
    out[at + 2] = b[2];
    out[at + 3] = b[3];
}

fn get(r: &[u8; RECORD_LEN], at: usize) -> u32 {
    u32::from_le_bytes([r[at], r[at + 1], r[at + 2], r[at + 3]])
}

fn nonzero(v: u32) -> Option<u32> {
    if v == 0 {
        None
    } else {
        Some(v)
    }
}

/// 解析记录。保留字段（12..16 与 28..32）必须为 0。
/// Parse a record; reserved words must be zero.
pub fn parse(r: &[u8; RECORD_LEN]) -> Result<Overrides, RecordError> {
    for (b, inv) in r[..8].iter().zip(MAGIC_INVERTED.iter()) {
        if !*b != *inv {
            return Err(RecordError::BadMagic);
        }
    }
    let version = get(r, 8);
    if version != RECORD_VERSION {
        return Err(RecordError::BadVersion(version));
    }
    if get(r, 12) != 0 || get(r, 28) != 0 {
        return Err(RecordError::BadReserved);
    }
    Ok(Overrides { objects: nonzero(get(r, 16)), tasks: nonzero(get(r, 20)), rt: nonzero(get(r, 24)) })
}

/// 每项容量的内存成本（字节）与可用于这些表的预算。由内核按实际类型大小给出。
/// Per-entry memory cost and the mem_limit available to the boot-sized tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryCost {
    /// 每个对象槽位（槽位 + 清理队列项）。
    pub per_object: usize,
    /// 每个任务槽位（任务记录 + 内核栈 + 调度暂存）。
    pub per_task: usize,
    /// 每个实时表项。
    pub per_rt: usize,
    /// 三张表合计不得超过的字节数（内核按堆上限留出余量后给出）。
    pub mem_limit: usize,
}

/// 拒绝的原因类别。
/// Why a capacity was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapReason {
    /// 超出允许范围（范围之外的值没有被验证过）。
    OutOfRange,
    /// 与另一项不一致（例如实时表比任务表还大）。
    Inconsistent,
    /// 三张表合计放不进内存预算。
    ExceedsMemory,
}

impl CapReason {
    /// 稳定文本名。
    pub const fn as_str(self) -> &'static str {
        match self {
            CapReason::OutOfRange => "out_of_range",
            CapReason::Inconsistent => "inconsistent",
            CapReason::ExceedsMemory => "exceeds_memory",
        }
    }
}

/// 一条结构化拒绝：哪一项、取值、允许范围、原因。
/// One structured refusal: field, value, allowed range and reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapError {
    /// 字段名（`objects` / `tasks` / `rt` / `total`）。
    pub field: &'static str,
    /// 请求的取值（`total` 时为合计字节数）。
    pub value: u64,
    /// 允许的最小值。
    pub min: u64,
    /// 允许的最大值。
    pub max: u64,
    /// 原因。
    pub reason: CapReason,
}

/// 容量来源。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// 全部取配置档默认值。
    Default,
    /// 至少一项来自镜像里的启动容量记录。
    Override,
}

impl Source {
    /// 稳定文本名。
    pub const fn as_str(self) -> &'static str {
        match self {
            Source::Default => "default",
            Source::Override => "override",
        }
    }
}

fn check(field: &'static str, value: usize, min: usize, max: usize) -> Result<(), CapError> {
    if value < min || value > max {
        return Err(CapError { field, value: value as u64, min: min as u64, max: max as u64, reason: CapReason::OutOfRange });
    }
    Ok(())
}

/// 合成最终容量：默认值叠加覆盖值，再逐项检查范围、一致性与内存预算。
/// 通过返回（容量, 来源）；任何一项不通过都返回第一条拒绝原因，调用者据此拒绝启动。
/// Combine defaults and overrides, then validate range, consistency and memory mem_limit.
pub fn resolve(defaults: BootCapacity, ov: Overrides, cost: MemoryCost) -> Result<(BootCapacity, Source), CapError> {
    let pick = |o: Option<u32>, d: usize| o.map_or(d, |v| v as usize);
    let cap = BootCapacity {
        objects: pick(ov.objects, defaults.objects),
        tasks: pick(ov.tasks, defaults.tasks),
        rt: pick(ov.rt, defaults.rt),
    };
    check("objects", cap.objects, bounds::MIN_OBJECTS, bounds::MAX_OBJECTS)?;
    check("tasks", cap.tasks, bounds::MIN_TASKS, bounds::MAX_TASKS)?;
    check("rt", cap.rt, bounds::MIN_RT, bounds::MAX_RT)?;
    if cap.rt >= cap.tasks {
        // 每个实时任务都要占一个任务槽位，另外至少留一个给引导线程。
        return Err(CapError {
            field: "rt",
            value: cap.rt as u64,
            min: bounds::MIN_RT as u64,
            max: (cap.tasks - 1) as u64,
            reason: CapReason::Inconsistent,
        });
    }
    let total = (cap.objects as u64) * cost.per_object as u64
        + (cap.tasks as u64) * cost.per_task as u64
        + (cap.rt as u64) * cost.per_rt as u64;
    if total > cost.mem_limit as u64 {
        return Err(CapError { field: "total", value: total, min: 0, max: cost.mem_limit as u64, reason: CapReason::ExceedsMemory });
    }
    let source = if ov.any() { Source::Override } else { Source::Default };
    Ok((cap, source))
}

/// 表安装启动期存储时的拒绝原因（被拒时表保持原样）。
/// Why installing boot-time storage into a table was refused (the table is left unchanged).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallError {
    /// 表已经装过存储（容量只能在启动期决定一次）。
    AlreadyInstalled,
    /// 容量为 0。
    Empty,
    /// 两个配套切片长度不同（例如对象表的清理队列必须与槽位同容量，才能保证永不溢出）。
    LengthMismatch,
    /// 容量超出标识的下标位宽。
    TooLarge,
    /// 存储里有非空项（必须全部为空）。
    NotVacant,
}

impl InstallError {
    /// 稳定文本名。
    pub const fn as_str(self) -> &'static str {
        match self {
            InstallError::AlreadyInstalled => "already_installed",
            InstallError::Empty => "empty",
            InstallError::LengthMismatch => "length_mismatch",
            InstallError::TooLarge => "too_large",
            InstallError::NotVacant => "not_vacant",
        }
    }
}

#[cfg(test)]
mod tests;
