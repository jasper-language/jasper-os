//! LC-1 本地诊断事件的稳定、无分配模型。
//! Stable allocation-free model for LC-1 local diagnostic events.
//!
//! 本模块只冻结事件 Schema、容量淘汰、隐私分类和导出授权，不实现文件、网络、
//! 进程隔离或 `system.*` 接口。正式采集器仍由 LC-1 系统服务实现。
//! This module freezes only the event schema, capacity eviction, privacy classes, and export
//! authorization. The production collector remains an LC-1 system service.

/// 当前诊断事件 Schema 版本。
/// Current diagnostic-event schema version.
pub const SCHEMA_VERSION: u16 = 1;
/// 单个事件保存的直接原因链上限。
/// Maximum direct cause chain stored in one event.
pub const MAX_CAUSES: usize = 8;
/// 组件稳定标识的最大字节数。
/// Maximum byte length of a stable component identifier.
pub const MAX_COMPONENT_ID: usize = 32;
/// 本地有效载荷引用或脱敏摘要的最大字节数。
/// Maximum byte length of a local payload reference or redacted excerpt.
pub const MAX_PAYLOAD_REFERENCE: usize = 64;

/// LC-1 必须区分的故障类别。
/// Failure categories that LC-1 must distinguish.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EventKind {
    /// 内核异常。Kernel exception.
    KernelException = 0,
    /// 系统服务崩溃。System-service crash.
    ServiceCrash = 1,
    /// 应用崩溃。Application crash.
    ApplicationCrash = 2,
    /// 驱动或硬件故障。Driver or hardware failure.
    DriverHardware = 3,
    /// 文件或存储损坏。File or storage corruption.
    StorageCorruption = 4,
    /// 网络故障。Network failure.
    Network = 5,
    /// 更新或启动失败。Update or boot failure.
    UpdateBoot = 6,
    /// 性能回退。Performance regression.
    PerformanceRegression = 7,
}

impl EventKind {
    /// 全部冻结类别。All frozen categories.
    pub const ALL: [Self; 8] = [
        Self::KernelException,
        Self::ServiceCrash,
        Self::ApplicationCrash,
        Self::DriverHardware,
        Self::StorageCorruption,
        Self::Network,
        Self::UpdateBoot,
        Self::PerformanceRegression,
    ];
}

/// 诊断严重度；数值越大越应保留。
/// Diagnostic severity; larger values should be retained first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Severity {
    /// 信息。Information.
    Info = 0,
    /// 告警。Warning.
    Warning = 1,
    /// 错误。Error.
    Error = 2,
    /// 关键。Critical.
    Critical = 3,
}

/// 隐私分类。
/// Privacy classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum PrivacyClass {
    /// 可公开。Public.
    Public = 0,
    /// 内部。Internal.
    Internal = 1,
    /// 敏感。Sensitive.
    Sensitive = 2,
    /// 秘密，默认禁止远程导出。Secret, forbidden from default remote export.
    Secret = 3,
}

/// 事件时钟质量。
/// Event clock quality.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ClockQuality {
    /// 已同步可信。Synchronized and trusted.
    Trusted = 0,
    /// 未同步但可用于顺序。Unsynchronized but usable for ordering.
    Untrusted = 1,
    /// 不可用。Unavailable.
    Unknown = 2,
}

/// 恢复动作分类。
/// Recovery-action classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RecoveryAction {
    /// 无恢复动作。No recovery action.
    None = 0,
    /// 重试。Retry.
    Retry = 1,
    /// 降级运行。Run degraded.
    Degraded = 2,
    /// 回滚。Rollback.
    RolledBack = 3,
    /// 进入救援。Enter recovery.
    EnteredRecovery = 4,
    /// 隔离组件。Component isolated.
    Isolated = 5,
}

/// 事件载荷的处理方式。
/// How an event payload is represented.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PayloadKind {
    /// 没有载荷。No payload.
    None = 0,
    /// 只有摘要。Digest only.
    DigestOnly = 1,
    /// 仅本地对象引用。Local object reference only.
    LocalReference = 2,
    /// 已脱敏短文本。Redacted short text.
    RedactedText = 3,
}

/// 诊断事件输入。
/// Diagnostic event input.
#[derive(Clone, Copy, Debug)]
pub struct EventInput<'a> {
    /// 故障类别。Failure category.
    pub kind: EventKind,
    /// 严重度。Severity.
    pub severity: Severity,
    /// 隐私分类。Privacy class.
    pub privacy: PrivacyClass,
    /// 时钟质量。Clock quality.
    pub clock_quality: ClockQuality,
    /// 原始单调计数，不伪造成墙钟时间。Raw monotonic count, never a fabricated wall time.
    pub observed_at: u64,
    /// 直接原因事件 ID。Direct cause event IDs.
    pub causes: &'a [u32],
    /// 稳定组件标识。Stable component identifier.
    pub component: &'a str,
    /// 组件版本。Component version.
    pub component_version: u32,
    /// 生命周期事务 ID；非生命周期事件可为 0。Lifecycle transaction ID; zero when not applicable.
    pub transaction_id: u64,
    /// 启动 ID；不适用时可为 0。Boot ID; zero when not applicable.
    pub boot_id: u64,
    /// 平台 Profile 的认证摘要。Authenticated platform-profile digest.
    pub platform_profile: [u8; 32],
    /// 资源压力摘要：CPU‰、内存‰、存储‰、网络‰。Resource pressure in per-mille.
    pub resource_pressure: [u16; 4],
    /// 恢复动作。Recovery action.
    pub recovery: RecoveryAction,
    /// 载荷处理方式。Payload representation.
    pub payload_kind: PayloadKind,
    /// 本地引用或脱敏文本。Local reference or redacted excerpt.
    pub payload_reference: &'a [u8],
    /// 原始载荷摘要；不适用时为零。Original payload digest; zero when not applicable.
    pub payload_digest: [u8; 32],
    /// 载荷是否经过脱敏。Whether any retained payload was redacted.
    pub redacted: bool,
}

/// 事件 Schema 校验失败原因。
/// Event-schema validation failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchemaError {
    /// 组件标识为空、过长或含非法字符。Component identifier is empty, oversized, or invalid.
    Component,
    /// 原因链过长。Cause chain is too long.
    Causes,
    /// 本地引用或脱敏文本过长。Payload reference is oversized.
    PayloadTooLong,
    /// 载荷形态与其摘要/引用不一致。Payload shape disagrees with its digest/reference.
    PayloadShape,
    /// 敏感或秘密载荷违反隐私策略。Sensitive or secret payload violates privacy policy.
    Privacy,
    /// 保留载荷没有经过脱敏。Retained payload was not marked redacted.
    RedactionRequired,
}

/// 固定容量、可复制的诊断事件。
/// Fixed-capacity, copyable diagnostic event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiagnosticEvent {
    id: u64,
    schema_version: u16,
    kind: EventKind,
    severity: Severity,
    privacy: PrivacyClass,
    clock_quality: ClockQuality,
    observed_at: u64,
    causes: [u32; MAX_CAUSES],
    cause_count: u8,
    component: [u8; MAX_COMPONENT_ID],
    component_len: u8,
    component_version: u32,
    transaction_id: u64,
    boot_id: u64,
    platform_profile: [u8; 32],
    resource_pressure: [u16; 4],
    recovery: RecoveryAction,
    payload_kind: PayloadKind,
    payload_reference: [u8; MAX_PAYLOAD_REFERENCE],
    payload_len: u8,
    payload_digest: [u8; 32],
    redacted: bool,
}

impl DiagnosticEvent {
    /// 校验并构造事件；ID 由有界事件环分配。
    /// Validates and constructs an event; the bounded ring assigns the ID.
    pub fn new(input: EventInput<'_>) -> Result<Self, SchemaError> {
        if input.component.is_empty()
            || input.component.len() > MAX_COMPONENT_ID
            || !input
                .component
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(SchemaError::Component);
        }
        if input.causes.len() > MAX_CAUSES {
            return Err(SchemaError::Causes);
        }
        if input.payload_reference.len() > MAX_PAYLOAD_REFERENCE {
            return Err(SchemaError::PayloadTooLong);
        }
        let digest_present = input.payload_digest != [0; 32];
        match input.payload_kind {
            PayloadKind::None if input.payload_reference.is_empty() && !digest_present => {}
            PayloadKind::DigestOnly if input.payload_reference.is_empty() && digest_present => {}
            PayloadKind::LocalReference
                if !input.payload_reference.is_empty() && digest_present => {}
            PayloadKind::RedactedText if !input.payload_reference.is_empty() => {}
            _ => return Err(SchemaError::PayloadShape),
        }
        if input.privacy >= PrivacyClass::Sensitive
            && !matches!(
                input.payload_kind,
                PayloadKind::None | PayloadKind::DigestOnly | PayloadKind::LocalReference
            )
        {
            return Err(SchemaError::Privacy);
        }
        if input.privacy == PrivacyClass::Secret
            && input.payload_kind == PayloadKind::LocalReference
        {
            return Err(SchemaError::Privacy);
        }
        if matches!(
            input.payload_kind,
            PayloadKind::LocalReference | PayloadKind::RedactedText
        ) && !input.redacted
        {
            return Err(SchemaError::RedactionRequired);
        }

        let mut causes = [0; MAX_CAUSES];
        causes[..input.causes.len()].copy_from_slice(input.causes);
        let mut component = [0; MAX_COMPONENT_ID];
        component[..input.component.len()].copy_from_slice(input.component.as_bytes());
        let mut payload_reference = [0; MAX_PAYLOAD_REFERENCE];
        payload_reference[..input.payload_reference.len()].copy_from_slice(input.payload_reference);
        Ok(Self {
            id: 0,
            schema_version: SCHEMA_VERSION,
            kind: input.kind,
            severity: input.severity,
            privacy: input.privacy,
            clock_quality: input.clock_quality,
            observed_at: input.observed_at,
            causes,
            cause_count: input.causes.len() as u8,
            component,
            component_len: input.component.len() as u8,
            component_version: input.component_version,
            transaction_id: input.transaction_id,
            boot_id: input.boot_id,
            platform_profile: input.platform_profile,
            resource_pressure: input.resource_pressure,
            recovery: input.recovery,
            payload_kind: input.payload_kind,
            payload_reference,
            payload_len: input.payload_reference.len() as u8,
            payload_digest: input.payload_digest,
            redacted: input.redacted,
        })
    }

    /// 分配后的事件 ID。Assigned event ID.
    pub const fn id(self) -> u64 {
        self.id
    }
    /// Schema 版本。Schema version.
    pub const fn schema_version(self) -> u16 {
        self.schema_version
    }
    /// 故障类别。Failure category.
    pub const fn kind(self) -> EventKind {
        self.kind
    }
    /// 严重度。Severity.
    pub const fn severity(self) -> Severity {
        self.severity
    }
    /// 隐私分类。Privacy class.
    pub const fn privacy(self) -> PrivacyClass {
        self.privacy
    }
    /// 时钟质量。Clock quality.
    pub const fn clock_quality(self) -> ClockQuality {
        self.clock_quality
    }
    /// 原始单调观测值。Raw monotonic observation.
    pub const fn observed_at(self) -> u64 {
        self.observed_at
    }
    /// 直接原因。Direct causes.
    pub fn causes(&self) -> &[u32] {
        &self.causes[..usize::from(self.cause_count)]
    }
    /// 稳定组件标识。Stable component identifier.
    pub fn component(&self) -> &str {
        core::str::from_utf8(&self.component[..usize::from(self.component_len)])
            .expect("validated ASCII component")
    }
    /// 组件版本。Component version.
    pub const fn component_version(self) -> u32 {
        self.component_version
    }
    /// 生命周期事务 ID。Lifecycle transaction ID.
    pub const fn transaction_id(self) -> u64 {
        self.transaction_id
    }
    /// 启动 ID。Boot ID.
    pub const fn boot_id(self) -> u64 {
        self.boot_id
    }
    /// 平台 Profile 摘要。Platform-profile digest.
    pub const fn platform_profile(self) -> [u8; 32] {
        self.platform_profile
    }
    /// 资源压力。Resource pressure.
    pub const fn resource_pressure(self) -> [u16; 4] {
        self.resource_pressure
    }
    /// 恢复动作。Recovery action.
    pub const fn recovery(self) -> RecoveryAction {
        self.recovery
    }
    /// 载荷表示方式。Payload representation.
    pub const fn payload_kind(self) -> PayloadKind {
        self.payload_kind
    }
    /// 本地引用或脱敏文本。Local reference or redacted text.
    pub fn payload_reference(&self) -> &[u8] {
        &self.payload_reference[..usize::from(self.payload_len)]
    }
    /// 原始载荷摘要。Original payload digest.
    pub const fn payload_digest(self) -> [u8; 32] {
        self.payload_digest
    }
    /// 保留载荷是否已经脱敏。Whether retained payload was redacted.
    pub const fn redacted(self) -> bool {
        self.redacted
    }
}

/// 有界事件环统计。
/// Bounded event-ring statistics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RingStats {
    /// 当前事件数。Current event count.
    pub len: usize,
    /// 成功进入事件环的事件数。Events accepted into the ring.
    pub accepted: u64,
    /// 为容量淘汰的事件数。Events evicted or rejected for capacity.
    pub capacity_dropped: u64,
}

/// 记录结果。
/// Record outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordOutcome {
    /// 写入空闲槽。Stored in a free slot.
    Stored(u64),
    /// 替换较低优先级事件。Replaced a lower-priority event.
    Replaced {
        /// 新事件 ID。New event ID.
        stored: u64,
        /// 被移除事件 ID。Removed event ID.
        dropped: u64,
    },
    /// 新事件因优先级不足被丢弃。The incoming event was dropped for insufficient priority.
    Dropped(u64),
}

/// 有界记录错误。
/// Bounded-record error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordError {
    /// 容量为零。The ring has zero capacity.
    ZeroCapacity,
    /// 事件 ID 空间耗尽。The event-ID space is exhausted.
    IdsExhausted,
}

/// 有界诊断查询；隐私上限之外的事件不会返回。
/// Bounded diagnostic query; events above the privacy ceiling are never returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiagnosticQuery {
    /// 可选类别过滤。Optional category filter.
    pub kind: Option<EventKind>,
    /// 最低严重度。Minimum severity.
    pub minimum_severity: Severity,
    /// 允许返回的最高隐私级别。Highest privacy class allowed in results.
    pub privacy_ceiling: PrivacyClass,
    /// 仅返回大于该 ID 的事件。Return only events with a greater ID.
    pub after_id: u64,
    /// 本次最多返回的事件数。Maximum events returned by this query session.
    pub remaining: usize,
}

impl DiagnosticQuery {
    /// 创建从头开始的有界查询。Creates a bounded query from the beginning.
    pub const fn new(
        kind: Option<EventKind>,
        minimum_severity: Severity,
        privacy_ceiling: PrivacyClass,
        limit: usize,
    ) -> Self {
        Self {
            kind,
            minimum_severity,
            privacy_ceiling,
            after_id: 0,
            remaining: limit,
        }
    }
}

/// 固定容量诊断事件环；满时优先淘汰最低严重度，同级保留先到事件。
/// Fixed-capacity diagnostic ring; evicts the lowest severity first and keeps earlier equal-severity events.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiagnosticRing<const N: usize> {
    events: [Option<DiagnosticEvent>; N],
    next_id: u64,
    accepted: u64,
    capacity_dropped: u64,
}

impl<const N: usize> DiagnosticRing<N> {
    /// 创建空事件环。Creates an empty event ring.
    pub const fn new() -> Self {
        Self {
            events: [None; N],
            next_id: 1,
            accepted: 0,
            capacity_dropped: 0,
        }
    }

    /// 记录已验证事件。Records a validated event.
    pub fn record(&mut self, mut event: DiagnosticEvent) -> Result<RecordOutcome, RecordError> {
        if N == 0 {
            return Err(RecordError::ZeroCapacity);
        }
        if self.next_id == 0 {
            return Err(RecordError::IdsExhausted);
        }
        let id = self.next_id;
        self.next_id = self.next_id.checked_add(1).unwrap_or(0);
        event.id = id;
        if let Some(slot) = self.events.iter().position(Option::is_none) {
            self.events[slot] = Some(event);
            self.accepted = self.accepted.saturating_add(1);
            return Ok(RecordOutcome::Stored(id));
        }
        let mut victim = 0;
        for index in 1..N {
            let severity = self.events[index]
                .expect("full ring has no empty slot")
                .severity;
            if severity
                < self.events[victim]
                    .expect("full ring has no empty slot")
                    .severity
            {
                victim = index;
            }
        }
        let old = self.events[victim].expect("full ring has no empty slot").id;
        if event.severity > self.events[victim].expect("full ring").severity {
            self.events[victim] = Some(event);
            self.accepted = self.accepted.saturating_add(1);
            self.capacity_dropped = self.capacity_dropped.saturating_add(1);
            Ok(RecordOutcome::Replaced {
                stored: id,
                dropped: old,
            })
        } else {
            self.capacity_dropped = self.capacity_dropped.saturating_add(1);
            Ok(RecordOutcome::Dropped(id))
        }
    }

    /// 当前事件数。Current event count.
    pub fn len(&self) -> usize {
        self.events.iter().flatten().count()
    }

    /// 是否为空。Whether the ring is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 按事件 ID 查找。Finds an event by ID.
    pub fn get(&self, id: u64) -> Option<&DiagnosticEvent> {
        self.events.iter().flatten().find(|event| event.id == id)
    }

    /// 返回下一匹配事件并推进查询游标。
    /// Returns the next matching event and advances the query cursor.
    pub fn query_next(&self, query: &mut DiagnosticQuery) -> Option<&DiagnosticEvent> {
        if query.remaining == 0 {
            return None;
        }
        let next = self
            .events
            .iter()
            .flatten()
            .filter(|event| event.id > query.after_id)
            .filter(|event| query.kind.is_none_or(|kind| event.kind == kind))
            .filter(|event| event.severity >= query.minimum_severity)
            .filter(|event| event.privacy <= query.privacy_ceiling)
            .min_by_key(|event| event.id)?;
        query.after_id = next.id;
        query.remaining -= 1;
        Some(next)
    }

    /// 快照统计。Snapshot statistics.
    pub fn stats(&self) -> RingStats {
        RingStats {
            len: self.len(),
            accepted: self.accepted,
            capacity_dropped: self.capacity_dropped,
        }
    }
}

impl<const N: usize> Default for DiagnosticRing<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// 持久化诊断副本固定保存的事件数。
/// Number of events retained by the persistent diagnostic copy.
pub const PERSISTED_EVENTS: usize = 16;
/// 一条持久化诊断事件的固定长度。
/// Fixed encoded length of one persisted diagnostic event.
pub const PERSISTED_EVENT_BYTES: usize = 256;
/// 每份诊断快照的固定长度。
/// Fixed size of one diagnostic snapshot copy.
pub const DIAGNOSTIC_COPY_BYTES: usize =
    DIAGNOSTIC_HEADER_BYTES + PERSISTED_EVENTS * PERSISTED_EVENT_BYTES;
/// 两份诊断副本之间的固定存储跨度。
/// Fixed storage stride between the two diagnostic copies.
pub const DIAGNOSTIC_COPY_STRIDE: usize = 8192;

const DIAGNOSTIC_HEADER_BYTES: usize = 64;
const DIAGNOSTIC_MAGIC: [u8; 8] = *b"JLC1DIAG";
const DIAGNOSTIC_VERSION: u16 = 1;

/// 诊断持久化宿主错误。
/// Host failure while reading, writing, or flushing diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagnosticIoError {
    /// 底层读取失败。The backing read failed.
    Read,
    /// 底层写入失败。The backing write failed.
    Write,
    /// flush 失败。The backing flush failed.
    Flush,
}

/// 双副本诊断存储的最小后端契约。
/// Minimal byte-addressed backend for two diagnostic snapshot copies.
pub trait DiagnosticIo {
    /// 后端容量。Backend capacity in bytes.
    fn capacity(&self) -> usize;
    /// 从固定字节偏移读取完整缓冲。Reads one complete buffer at a byte offset.
    fn read(&mut self, offset: usize, out: &mut [u8]) -> Result<(), DiagnosticIoError>;
    /// 向固定字节偏移写入完整缓冲。Writes one complete buffer at a byte offset.
    fn write(&mut self, offset: usize, input: &[u8]) -> Result<(), DiagnosticIoError>;
    /// 使此前写入持久化。Makes previous writes durable.
    fn flush(&mut self) -> Result<(), DiagnosticIoError>;
}

/// 持久化诊断记录错误。
/// Persistent diagnostic-store failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagnosticStoreError {
    /// 存储容量不足。The backing store is too small.
    Capacity,
    /// 两份副本均不可用。Neither snapshot copy is valid.
    Corrupt,
    /// 副本世代或内容存在歧义。The copy generations or contents are ambiguous.
    ConflictingCopies,
    /// 底层 I/O 或 flush 失败。The backing I/O or flush failed.
    Io(DiagnosticIoError),
    /// 快照序列耗尽。The snapshot sequence is exhausted.
    SequenceExhausted,
    /// 事件环拒绝记录。The in-memory ring rejected the event.
    Record(RecordError),
}

/// 双副本、有界且可恢复的诊断事件存储。
///
/// 每次提交只覆盖非活动副本；写入和 flush 后必须读回一致，才发布新的
/// 内存快照。已落盘副本仍可作为损坏提交的回退点。
/// Two-copy, bounded, recoverable diagnostic-event store. A commit overwrites
/// the inactive copy and publishes it locally only after flush and readback.
pub struct PersistentDiagnosticStore<D: DiagnosticIo> {
    device: D,
    ring: DiagnosticRing<PERSISTED_EVENTS>,
    sequence: u64,
}

impl<D: DiagnosticIo> PersistentDiagnosticStore<D> {
    /// 格式化后端为两个空诊断副本。
    /// Formats the backing store with two empty diagnostic copies.
    pub fn format(mut device: D) -> Result<Self, DiagnosticStoreError> {
        if device.capacity() < DIAGNOSTIC_COPY_STRIDE * 2 {
            return Err(DiagnosticStoreError::Capacity);
        }
        let invalid = [0u8; DIAGNOSTIC_HEADER_BYTES];
        device
            .write(0, &invalid)
            .map_err(DiagnosticStoreError::Io)?;
        device
            .write(DIAGNOSTIC_COPY_STRIDE, &invalid)
            .map_err(DiagnosticStoreError::Io)?;
        device.flush().map_err(DiagnosticStoreError::Io)?;
        let mut store = Self {
            device,
            ring: DiagnosticRing::new(),
            sequence: 0,
        };
        store.commit(DiagnosticRing::new())?;
        Ok(store)
    }

    /// 从两份副本恢复最高有效世代。
    /// Recovers the highest valid generation from two copies.
    pub fn open(mut device: D) -> Result<Self, DiagnosticStoreError> {
        if device.capacity() < DIAGNOSTIC_COPY_STRIDE * 2 {
            return Err(DiagnosticStoreError::Capacity);
        }
        let first = read_snapshot(&mut device, 0)?;
        let second = read_snapshot(&mut device, DIAGNOSTIC_COPY_STRIDE)?;
        let (sequence, ring) = match (first, second) {
            (Some((first_sequence, first_ring)), Some((second_sequence, second_ring)))
                if first_sequence == second_sequence && first_ring != second_ring =>
            {
                return Err(DiagnosticStoreError::ConflictingCopies);
            }
            (Some((first_sequence, first_ring)), Some((second_sequence, second_ring))) => {
                if first_sequence >= second_sequence {
                    (first_sequence, first_ring)
                } else {
                    (second_sequence, second_ring)
                }
            }
            (Some(snapshot), None) | (None, Some(snapshot)) => snapshot,
            (None, None) => return Err(DiagnosticStoreError::Corrupt),
        };
        Ok(Self {
            device,
            ring,
            sequence,
        })
    }

    /// 记录事件并持久化完整有界快照。
    /// Records one event and persists the complete bounded snapshot.
    pub fn record(
        &mut self,
        event: DiagnosticEvent,
    ) -> Result<(RecordOutcome, RingStats), DiagnosticStoreError> {
        let mut next = self.ring.clone();
        let outcome = next.record(event).map_err(DiagnosticStoreError::Record)?;
        self.commit(next)?;
        Ok((outcome, self.ring.stats()))
    }

    /// 当前已发布事件环。Current published event ring.
    pub const fn ring(&self) -> &DiagnosticRing<PERSISTED_EVENTS> {
        &self.ring
    }

    /// 当前快照序列。Current snapshot sequence.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// 取回底层设备。Returns the backing device.
    pub fn into_device(self) -> D {
        self.device
    }

    fn commit(
        &mut self,
        ring: DiagnosticRing<PERSISTED_EVENTS>,
    ) -> Result<(), DiagnosticStoreError> {
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(DiagnosticStoreError::SequenceExhausted)?;
        let bytes = encode_snapshot(sequence, &ring);
        let slot = (sequence as usize) & 1;
        let offset = slot * DIAGNOSTIC_COPY_STRIDE;
        self.device
            .write(offset, &bytes)
            .map_err(DiagnosticStoreError::Io)?;
        self.device.flush().map_err(DiagnosticStoreError::Io)?;
        let mut readback = [0u8; DIAGNOSTIC_COPY_BYTES];
        self.device
            .read(offset, &mut readback)
            .map_err(DiagnosticStoreError::Io)?;
        if readback != bytes {
            return Err(DiagnosticStoreError::Corrupt);
        }
        self.ring = ring;
        self.sequence = sequence;
        Ok(())
    }
}

/// Collector failure before an event reaches the persistent ring.
/// 事件进入持久环之前的采集失败。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CollectError {
    /// The event schema rejected the input.
    /// 事件 Schema 拒绝了输入。
    Schema(SchemaError),
    /// The persistent snapshot commit failed.
    /// 持久快照提交失败。
    Store(DiagnosticStoreError),
}

/// One durable collection result.
/// 一次持久采集的结果。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CollectReport {
    /// Event-ring admission outcome.
    /// 事件环的准入结果。
    pub outcome: RecordOutcome,
    /// Current ring statistics after the commit.
    /// 提交后的当前事件环统计。
    pub stats: RingStats,
    /// Published persistent snapshot sequence.
    /// 已发布的持久快照序列。
    pub sequence: u64,
}

/// Collector status without exposing retained payloads.
/// 不暴露保留载荷的采集器状态。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CollectorStatus {
    /// Current bounded-ring statistics.
    /// 当前有界环统计。
    pub stats: RingStats,
    /// Current durable snapshot sequence.
    /// 当前持久快照序列。
    pub sequence: u64,
}

/// One bounded, privacy-filtered query page.
/// 一个有界且经过隐私过滤的查询页。
#[derive(Clone, Copy)]
pub struct DiagnosticPage<const N: usize> {
    events: [Option<DiagnosticEvent>; N],
    len: usize,
}

impl<const N: usize> DiagnosticPage<N> {
    /// Creates an empty page.
    /// 创建空查询页。
    pub const fn new() -> Self {
        Self {
            events: [None; N],
            len: 0,
        }
    }

    /// Number of events copied into this page.
    /// 本页复制的事件数。
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the page is empty.
    /// 查询页是否为空。
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns one event by page position.
    /// 按页内位置返回事件。
    pub fn get(&self, index: usize) -> Option<&DiagnosticEvent> {
        self.events.get(index)?.as_ref()
    }
}

impl<const N: usize> Default for DiagnosticPage<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Minimal local diagnostic collector over the persistent two-copy store.
///
/// This is a service-layer building block, not a new ABI. Ingested inputs are
/// schema-validated before a durable commit; queries always pass through the
/// existing privacy ceiling and stable-ID cursor instead of exposing raw ring
/// entries by ID.
///
/// 持久双副本存储上的最小本地诊断采集器。本类型是服务层构件，不是新 ABI；
/// 输入先做 Schema 校验再持久提交；查询必须经过既有隐私上限和稳定 ID 游标，
/// 不提供绕过策略的按 ID 原始读取。
pub struct DiagnosticCollector<D: DiagnosticIo> {
    store: PersistentDiagnosticStore<D>,
}

impl<D: DiagnosticIo> DiagnosticCollector<D> {
    /// Creates and formats a new collector store.
    /// 创建并格式化新的采集存储。
    pub fn format(device: D) -> Result<Self, DiagnosticStoreError> {
        Ok(Self {
            store: PersistentDiagnosticStore::format(device)?,
        })
    }

    /// Reopens the highest valid durable snapshot.
    /// 重开最高有效持久快照。
    pub fn open(device: D) -> Result<Self, DiagnosticStoreError> {
        Ok(Self {
            store: PersistentDiagnosticStore::open(device)?,
        })
    }

    /// Validates, admits and durably commits one event.
    ///
    /// A schema or commit failure leaves the previously published in-memory
    /// ring and durable snapshot unchanged.
    /// 校验、准入并持久提交一个事件；Schema 或提交失败不改变此前已发布的
    /// 内存环与持久快照。
    pub fn collect(&mut self, input: EventInput<'_>) -> Result<CollectReport, CollectError> {
        let event = DiagnosticEvent::new(input).map_err(CollectError::Schema)?;
        let (outcome, stats) = self.store.record(event).map_err(CollectError::Store)?;
        Ok(CollectReport {
            outcome,
            stats,
            sequence: self.store.sequence(),
        })
    }

    /// Returns bounded collector status without payloads.
    /// 返回不含载荷的有界采集器状态。
    pub fn status(&self) -> CollectorStatus {
        CollectorStatus {
            stats: self.store.ring().stats(),
            sequence: self.store.sequence(),
        }
    }

    /// Returns the next privacy-filtered event and advances the query cursor.
    /// 返回下一条经过隐私过滤的事件并推进查询游标。
    pub fn query_next(&self, query: &mut DiagnosticQuery) -> Option<DiagnosticEvent> {
        self.store.ring().query_next(query).copied()
    }

    /// Returns one bounded query page.
    ///
    /// The query limit and page capacity are both enforced; the smaller bound
    /// wins. No secret or above-ceiling event is copied.
    /// 同时执行查询上限与页面容量限制，取较小值；不会复制秘密事件或高于
    /// 隐私上限的事件。
    pub fn query_page<const N: usize>(&self, query: &mut DiagnosticQuery) -> DiagnosticPage<N> {
        let mut page = DiagnosticPage::<N>::new();
        while page.len < N {
            let Some(event) = self.store.ring().query_next(query) else {
                break;
            };
            page.events[page.len] = Some(*event);
            page.len += 1;
        }
        page
    }

    /// Returns the backing device for controlled shutdown/reopen.
    /// 取回底层设备以进行受控关闭或重开。
    pub fn into_device(self) -> D {
        self.store.into_device()
    }
}

/// One subject's effective diagnostic-service rights.
///
/// This is service policy input, not an ABI record and not an authorization
/// derived from a component name or path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiagnosticAccess {
    /// Whether the subject may submit validated events for durable collection.
    pub can_collect: bool,
    /// Whether the subject may page through retained event summaries.
    pub can_query: bool,
    /// Highest event privacy class this subject may observe.
    pub privacy_ceiling: PrivacyClass,
    /// Hard per-query page bound imposed by policy.
    pub max_page: usize,
}

/// Trusted authority used by the diagnostic service at each operation.
///
/// Implementations must derive access from the existing identity/SEC/PEP
/// model. Component IDs, device paths and event contents are never authority.
pub trait DiagnosticAuthority {
    /// Returns current effective access for one authenticated subject.
    fn access(&self, subject: u64) -> Option<DiagnosticAccess>;
}

/// Service-boundary failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagnosticServiceError {
    /// The subject is absent, revoked or lacks the requested operation.
    Unauthorized,
    /// Event validation or durable collection failed.
    Collect(CollectError),
}

impl From<CollectError> for DiagnosticServiceError {
    fn from(error: CollectError) -> Self {
        Self::Collect(error)
    }
}

/// One authenticated query request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiagnosticQueryRequest {
    /// Optional event-kind filter.
    pub kind: Option<EventKind>,
    /// Minimum severity.
    pub minimum_severity: Severity,
    /// Caller-requested privacy ceiling; the authority may lower it.
    pub privacy_ceiling: PrivacyClass,
    /// Stable event-ID cursor from the previous page.
    pub after_id: u64,
    /// Caller-requested page size; page capacity and authority may lower it.
    pub limit: usize,
}

/// Authority-gated diagnostic service boundary.
///
/// The future USI adapter can call this type without adding a new syscall or
/// pre-approving a `system.*` identifier. Every query re-evaluates the authority
/// and never exposes an event above its effective privacy ceiling.
pub struct DiagnosticService<D: DiagnosticIo, A: DiagnosticAuthority> {
    collector: DiagnosticCollector<D>,
    authority: A,
}

impl<D: DiagnosticIo, A: DiagnosticAuthority> DiagnosticService<D, A> {
    /// Formats a new service backing store.
    pub fn format(device: D, authority: A) -> Result<Self, DiagnosticServiceError> {
        Ok(Self {
            collector: DiagnosticCollector::format(device)
                .map_err(|error| DiagnosticServiceError::Collect(CollectError::Store(error)))?,
            authority,
        })
    }

    /// Reopens the highest valid durable snapshot.
    pub fn open(device: D, authority: A) -> Result<Self, DiagnosticServiceError> {
        Ok(Self {
            collector: DiagnosticCollector::open(device)
                .map_err(|error| DiagnosticServiceError::Collect(CollectError::Store(error)))?,
            authority,
        })
    }

    /// Validates, authorizes and durably collects one event.
    pub fn collect(
        &mut self,
        subject: u64,
        input: EventInput<'_>,
    ) -> Result<CollectReport, DiagnosticServiceError> {
        let access = self
            .authority
            .access(subject)
            .ok_or(DiagnosticServiceError::Unauthorized)?;
        if !access.can_collect {
            return Err(DiagnosticServiceError::Unauthorized);
        }
        self.collector.collect(input).map_err(Into::into)
    }

    /// Returns one authority-capped query page and its stable resume cursor.
    ///
    /// The effective limit is the minimum of page capacity `N`, the caller's
    /// request and the authority's `max_page`. A zero-size authority page is
    /// denied rather than silently returning an empty success.
    pub fn query_page<const N: usize>(
        &self,
        subject: u64,
        request: DiagnosticQueryRequest,
    ) -> Result<(DiagnosticPage<N>, u64, CollectorStatus), DiagnosticServiceError> {
        let access = self
            .authority
            .access(subject)
            .ok_or(DiagnosticServiceError::Unauthorized)?;
        if !access.can_query || access.max_page == 0 || request.limit == 0 || N == 0 {
            return Err(DiagnosticServiceError::Unauthorized);
        }
        let limit = request.limit.min(access.max_page).min(N);
        let privacy_ceiling = core::cmp::min(request.privacy_ceiling, access.privacy_ceiling);
        let mut query = DiagnosticQuery::new(
            request.kind,
            request.minimum_severity,
            privacy_ceiling,
            limit,
        );
        query.after_id = request.after_id;
        let page = self.collector.query_page::<N>(&mut query);
        Ok((page, query.after_id, self.collector.status()))
    }

    /// Returns payload-free collector status to a collector or query principal.
    pub fn status(&self, subject: u64) -> Result<CollectorStatus, DiagnosticServiceError> {
        let access = self
            .authority
            .access(subject)
            .ok_or(DiagnosticServiceError::Unauthorized)?;
        if !access.can_collect && !access.can_query {
            return Err(DiagnosticServiceError::Unauthorized);
        }
        Ok(self.collector.status())
    }

    /// Returns the backing device for controlled shutdown or reopen.
    pub fn into_device(self) -> D {
        self.collector.into_device()
    }
}

impl<const N: usize> DiagnosticRing<N> {
    fn restore(
        events: [Option<DiagnosticEvent>; N],
        next_id: u64,
        accepted: u64,
        capacity_dropped: u64,
    ) -> Option<Self> {
        if next_id == 0 || accepted < events.iter().flatten().count() as u64 {
            return None;
        }
        for (index, event) in events.iter().flatten().enumerate() {
            if event.id == 0
                || event.id >= next_id
                || events
                    .iter()
                    .flatten()
                    .take(index)
                    .any(|prior| prior.id == event.id)
            {
                return None;
            }
        }
        Some(Self {
            events,
            next_id,
            accepted,
            capacity_dropped,
        })
    }
}

type Snapshot = (u64, DiagnosticRing<PERSISTED_EVENTS>);

fn read_snapshot<D: DiagnosticIo>(
    device: &mut D,
    offset: usize,
) -> Result<Option<Snapshot>, DiagnosticStoreError> {
    let mut bytes = [0u8; DIAGNOSTIC_COPY_BYTES];
    device
        .read(offset, &mut bytes)
        .map_err(DiagnosticStoreError::Io)?;
    Ok(decode_snapshot(&bytes))
}

/// 远程导出的用途。Remote-export purpose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportPurpose {
    /// 用户主动支持。User-requested support.
    UserSupport = 0,
    /// 安全事件响应。Security response.
    SecurityResponse = 1,
    /// 组织内维护。Organization maintenance.
    OrganizationMaintenance = 2,
}

/// 显式本地授权；本身不产生网络行为。
/// Explicit local authorization; it performs no network action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RemoteGrant {
    /// 导出用途。Export purpose.
    pub purpose: ExportPurpose,
    /// 单调时钟到期点。Monotonic expiry.
    pub expires_at: u64,
    /// 是否由本地用户/组织明确授权。Whether a local user or organization authorized it.
    pub locally_authorized: bool,
    /// 是否允许敏感元数据。Whether sensitive metadata is allowed.
    pub allow_sensitive: bool,
}

/// 导出判定。
/// Export decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportDecision {
    /// 仅允许脱敏信封，不包含原始载荷。Only a redacted envelope may leave the device.
    RedactedEnvelope,
    /// 没有有效授权。No valid grant.
    LocalOnlyNoGrant,
    /// 授权无效或过期。The grant is invalid or expired.
    LocalOnlyInvalidGrant,
    /// 敏感数据未被该用途授权。Sensitive data is not authorized for this purpose.
    LocalOnlySensitive,
    /// 秘密数据禁止远程导出。Secret data is forbidden from remote export.
    LocalOnlySecret,
}

/// 判定一个事件是否可导出；默认拒绝，秘密数据永不远程导出。
/// Decides whether one event may be exported; default deny and never export secret data.
pub fn export_decision(
    event: &DiagnosticEvent,
    grant: Option<RemoteGrant>,
    now: u64,
) -> ExportDecision {
    if event.privacy == PrivacyClass::Secret {
        return ExportDecision::LocalOnlySecret;
    }
    let Some(grant) = grant else {
        return ExportDecision::LocalOnlyNoGrant;
    };
    if !grant.locally_authorized || now >= grant.expires_at {
        return ExportDecision::LocalOnlyInvalidGrant;
    }
    if event.privacy == PrivacyClass::Sensitive
        && !(grant.allow_sensitive && grant.purpose == ExportPurpose::SecurityResponse)
    {
        return ExportDecision::LocalOnlySensitive;
    }
    ExportDecision::RedactedEnvelope
}

fn encode_snapshot(
    sequence: u64,
    ring: &DiagnosticRing<PERSISTED_EVENTS>,
) -> [u8; DIAGNOSTIC_COPY_BYTES] {
    let mut bytes = [0u8; DIAGNOSTIC_COPY_BYTES];
    bytes[..8].copy_from_slice(&DIAGNOSTIC_MAGIC);
    bytes[8..10].copy_from_slice(&DIAGNOSTIC_VERSION.to_le_bytes());
    bytes[10..12].copy_from_slice(&(DIAGNOSTIC_HEADER_BYTES as u16).to_le_bytes());
    bytes[12..14].copy_from_slice(&(PERSISTED_EVENTS as u16).to_le_bytes());
    let event_count = ring.events.iter().flatten().count();
    bytes[14..16].copy_from_slice(&(event_count as u16).to_le_bytes());
    bytes[16..24].copy_from_slice(&sequence.to_le_bytes());
    bytes[24..32].copy_from_slice(&ring.next_id.to_le_bytes());
    let stats = ring.stats();
    bytes[32..40].copy_from_slice(&stats.accepted.to_le_bytes());
    bytes[40..48].copy_from_slice(&stats.capacity_dropped.to_le_bytes());
    for (slot, event) in ring.events.iter().flatten().enumerate() {
        let start = DIAGNOSTIC_HEADER_BYTES + slot * PERSISTED_EVENT_BYTES;
        encode_event(
            event,
            (&mut bytes[start..start + PERSISTED_EVENT_BYTES])
                .try_into()
                .expect("fixed diagnostic-event slot"),
        );
    }
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&bytes[..60]);
    hasher.update(&bytes[DIAGNOSTIC_HEADER_BYTES..]);
    bytes[60..64].copy_from_slice(&hasher.finalize().to_le_bytes());
    bytes
}

fn decode_snapshot(bytes: &[u8; DIAGNOSTIC_COPY_BYTES]) -> Option<Snapshot> {
    if bytes[..8] != DIAGNOSTIC_MAGIC
        || diag_read_u16(bytes, 8)? != DIAGNOSTIC_VERSION
        || diag_read_u16(bytes, 10)? as usize != DIAGNOSTIC_HEADER_BYTES
        || diag_read_u16(bytes, 12)? as usize != PERSISTED_EVENTS
        || bytes[48..60].iter().any(|byte| *byte != 0)
    {
        return None;
    }
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&bytes[..60]);
    hasher.update(&bytes[DIAGNOSTIC_HEADER_BYTES..]);
    if diag_read_u32(bytes, 60)? != hasher.finalize() {
        return None;
    }
    let event_count = diag_read_u16(bytes, 14)? as usize;
    if event_count > PERSISTED_EVENTS {
        return None;
    }
    let mut events = [None; PERSISTED_EVENTS];
    for (slot, event_slot) in events[..event_count].iter_mut().enumerate() {
        let start = DIAGNOSTIC_HEADER_BYTES + slot * PERSISTED_EVENT_BYTES;
        let event_bytes: &[u8; PERSISTED_EVENT_BYTES] = bytes[start..start + PERSISTED_EVENT_BYTES]
            .try_into()
            .ok()?;
        *event_slot = Some(decode_event(event_bytes)?);
    }
    for slot in event_count..PERSISTED_EVENTS {
        let start = DIAGNOSTIC_HEADER_BYTES + slot * PERSISTED_EVENT_BYTES;
        if bytes[start..start + PERSISTED_EVENT_BYTES]
            .iter()
            .any(|byte| *byte != 0)
        {
            return None;
        }
    }
    let sequence = diag_read_u64(bytes, 16)?;
    let next_id = diag_read_u64(bytes, 24)?;
    let accepted = diag_read_u64(bytes, 32)?;
    let capacity_dropped = diag_read_u64(bytes, 40)?;
    Some((
        sequence,
        DiagnosticRing::restore(events, next_id, accepted, capacity_dropped)?,
    ))
}

fn encode_event(event: &DiagnosticEvent, out: &mut [u8; PERSISTED_EVENT_BYTES]) {
    out[..4].copy_from_slice(b"DGE1");
    out[4..6].copy_from_slice(&event.schema_version.to_le_bytes());
    out[8..16].copy_from_slice(&event.id.to_le_bytes());
    out[16] = event.kind as u8;
    out[17] = event.severity as u8;
    out[18] = event.privacy as u8;
    out[19] = event.clock_quality as u8;
    out[20..28].copy_from_slice(&event.observed_at.to_le_bytes());
    out[28] = event.cause_count;
    out[29] = event.component_len;
    out[30] = event.payload_len;
    out[31] = u8::from(event.redacted);
    for (index, cause) in event.causes.iter().enumerate() {
        let start = 32 + index * 4;
        out[start..start + 4].copy_from_slice(&cause.to_le_bytes());
    }
    out[64..96].copy_from_slice(&event.component);
    out[96..100].copy_from_slice(&event.component_version.to_le_bytes());
    out[100..108].copy_from_slice(&event.transaction_id.to_le_bytes());
    out[108..116].copy_from_slice(&event.boot_id.to_le_bytes());
    out[116..148].copy_from_slice(&event.platform_profile);
    for (index, pressure) in event.resource_pressure.iter().enumerate() {
        let start = 148 + index * 2;
        out[start..start + 2].copy_from_slice(&pressure.to_le_bytes());
    }
    out[156] = event.recovery as u8;
    out[157] = event.payload_kind as u8;
    out[160..224].copy_from_slice(&event.payload_reference);
    out[224..256].copy_from_slice(&event.payload_digest);
}

fn decode_event(bytes: &[u8; PERSISTED_EVENT_BYTES]) -> Option<DiagnosticEvent> {
    if bytes[..4] != *b"DGE1"
        || diag_read_u16(bytes, 4)? != SCHEMA_VERSION
        || bytes[6..8].iter().any(|byte| *byte != 0)
        || bytes[158..160].iter().any(|byte| *byte != 0)
    {
        return None;
    }
    let id = diag_read_u64(bytes, 8)?;
    let cause_count = bytes[28] as usize;
    let component_len = bytes[29] as usize;
    let payload_len = bytes[30] as usize;
    if id == 0
        || cause_count > MAX_CAUSES
        || component_len == 0
        || component_len > MAX_COMPONENT_ID
        || payload_len > MAX_PAYLOAD_REFERENCE
        || bytes[31] > 1
    {
        return None;
    }
    if bytes[32 + cause_count * 4..64]
        .iter()
        .any(|byte| *byte != 0)
        || bytes[64 + component_len..96].iter().any(|byte| *byte != 0)
        || bytes[160 + payload_len..224].iter().any(|byte| *byte != 0)
    {
        return None;
    }
    let mut causes = [0u32; MAX_CAUSES];
    for (index, cause) in causes[..cause_count].iter_mut().enumerate() {
        *cause = diag_read_u32(bytes, 32 + index * 4)?;
    }
    let component = core::str::from_utf8(&bytes[64..64 + component_len]).ok()?;
    let mut platform_profile = [0u8; 32];
    platform_profile.copy_from_slice(&bytes[116..148]);
    let mut pressure = [0u16; 4];
    for (index, value) in pressure.iter_mut().enumerate() {
        *value = diag_read_u16(bytes, 148 + index * 2)?;
    }
    let mut payload_digest = [0u8; 32];
    payload_digest.copy_from_slice(&bytes[224..256]);
    let mut event = DiagnosticEvent::new(EventInput {
        kind: decode_kind(bytes[16])?,
        severity: decode_severity(bytes[17])?,
        privacy: decode_privacy(bytes[18])?,
        clock_quality: decode_clock(bytes[19])?,
        observed_at: diag_read_u64(bytes, 20)?,
        causes: &causes[..cause_count],
        component,
        component_version: diag_read_u32(bytes, 96)?,
        transaction_id: diag_read_u64(bytes, 100)?,
        boot_id: diag_read_u64(bytes, 108)?,
        platform_profile,
        resource_pressure: pressure,
        recovery: decode_recovery(bytes[156])?,
        payload_kind: decode_payload(bytes[157])?,
        payload_reference: &bytes[160..160 + payload_len],
        payload_digest,
        redacted: bytes[31] != 0,
    })
    .ok()?;
    event.id = id;
    Some(event)
}

fn decode_kind(value: u8) -> Option<EventKind> {
    Some(match value {
        0 => EventKind::KernelException,
        1 => EventKind::ServiceCrash,
        2 => EventKind::ApplicationCrash,
        3 => EventKind::DriverHardware,
        4 => EventKind::StorageCorruption,
        5 => EventKind::Network,
        6 => EventKind::UpdateBoot,
        7 => EventKind::PerformanceRegression,
        _ => return None,
    })
}

fn decode_severity(value: u8) -> Option<Severity> {
    Some(match value {
        0 => Severity::Info,
        1 => Severity::Warning,
        2 => Severity::Error,
        3 => Severity::Critical,
        _ => return None,
    })
}

fn decode_privacy(value: u8) -> Option<PrivacyClass> {
    Some(match value {
        0 => PrivacyClass::Public,
        1 => PrivacyClass::Internal,
        2 => PrivacyClass::Sensitive,
        3 => PrivacyClass::Secret,
        _ => return None,
    })
}

fn decode_clock(value: u8) -> Option<ClockQuality> {
    Some(match value {
        0 => ClockQuality::Trusted,
        1 => ClockQuality::Untrusted,
        2 => ClockQuality::Unknown,
        _ => return None,
    })
}

fn decode_recovery(value: u8) -> Option<RecoveryAction> {
    Some(match value {
        0 => RecoveryAction::None,
        1 => RecoveryAction::Retry,
        2 => RecoveryAction::Degraded,
        3 => RecoveryAction::RolledBack,
        4 => RecoveryAction::EnteredRecovery,
        5 => RecoveryAction::Isolated,
        _ => return None,
    })
}

fn decode_payload(value: u8) -> Option<PayloadKind> {
    Some(match value {
        0 => PayloadKind::None,
        1 => PayloadKind::DigestOnly,
        2 => PayloadKind::LocalReference,
        3 => PayloadKind::RedactedText,
        _ => return None,
    })
}

fn diag_read_u16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn diag_read_u32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn diag_read_u64(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(kind: EventKind, severity: Severity) -> EventInput<'static> {
        EventInput {
            kind,
            severity,
            privacy: PrivacyClass::Internal,
            clock_quality: ClockQuality::Trusted,
            observed_at: 42,
            causes: &[],
            component: "system.storage",
            component_version: 7,
            transaction_id: 11,
            boot_id: 12,
            platform_profile: [0x11; 32],
            resource_pressure: [10, 20, 30, 40],
            recovery: RecoveryAction::Degraded,
            payload_kind: PayloadKind::None,
            payload_reference: &[],
            payload_digest: [0; 32],
            redacted: false,
        }
    }

    #[test]
    fn all_required_event_kinds_are_stable_and_round_trip_fields() {
        let mut ring = DiagnosticRing::<8>::new();
        for (index, kind) in EventKind::ALL.into_iter().enumerate() {
            assert_eq!(kind as u8, index as u8);
            let event = DiagnosticEvent::new(base(kind, Severity::Warning)).unwrap();
            assert_eq!(
                ring.record(event),
                Ok(RecordOutcome::Stored(index as u64 + 1))
            );
            let stored = ring.get(index as u64 + 1).unwrap();
            assert_eq!(stored.schema_version(), SCHEMA_VERSION);
            assert_eq!(stored.kind(), kind);
            assert_eq!(stored.component(), "system.storage");
            assert_eq!(stored.platform_profile(), [0x11; 32]);
        }
        assert_eq!(
            ring.stats(),
            RingStats {
                len: 8,
                accepted: 8,
                capacity_dropped: 0
            }
        );
    }

    #[test]
    fn full_ring_preserves_critical_and_drops_low_severity() {
        let mut ring = DiagnosticRing::<2>::new();
        ring.record(DiagnosticEvent::new(base(EventKind::Network, Severity::Info)).unwrap())
            .unwrap();
        ring.record(
            DiagnosticEvent::new(base(EventKind::StorageCorruption, Severity::Error)).unwrap(),
        )
        .unwrap();
        let critical =
            DiagnosticEvent::new(base(EventKind::KernelException, Severity::Critical)).unwrap();
        assert_eq!(
            ring.record(critical),
            Ok(RecordOutcome::Replaced {
                stored: 3,
                dropped: 1
            })
        );
        assert!(ring.get(1).is_none());
        assert_eq!(ring.get(2).unwrap().severity(), Severity::Error);
        assert_eq!(ring.get(3).unwrap().severity(), Severity::Critical);
        assert_eq!(ring.stats().capacity_dropped, 1);
    }

    #[test]
    fn equal_or_lower_severity_cannot_evict_existing_event() {
        let mut ring = DiagnosticRing::<1>::new();
        ring.record(
            DiagnosticEvent::new(base(EventKind::ServiceCrash, Severity::Critical)).unwrap(),
        )
        .unwrap();
        let same =
            DiagnosticEvent::new(base(EventKind::ApplicationCrash, Severity::Critical)).unwrap();
        assert_eq!(ring.record(same), Ok(RecordOutcome::Dropped(2)));
        assert_eq!(ring.get(1).unwrap().kind(), EventKind::ServiceCrash);
        assert_eq!(ring.stats().capacity_dropped, 1);
    }

    #[test]
    fn sensitive_and_secret_payloads_fail_closed() {
        let mut input = base(EventKind::ServiceCrash, Severity::Error);
        input.privacy = PrivacyClass::Sensitive;
        input.payload_kind = PayloadKind::RedactedText;
        input.payload_reference = b"redacted";
        input.redacted = true;
        assert_eq!(DiagnosticEvent::new(input), Err(SchemaError::Privacy));

        input.privacy = PrivacyClass::Secret;
        input.payload_kind = PayloadKind::LocalReference;
        input.payload_digest = [7; 32];
        assert_eq!(DiagnosticEvent::new(input), Err(SchemaError::Privacy));
    }

    #[test]
    fn retained_payload_must_be_marked_redacted() {
        let mut input = base(EventKind::Network, Severity::Warning);
        input.payload_kind = PayloadKind::RedactedText;
        input.payload_reference = b"sanitized";
        assert_eq!(
            DiagnosticEvent::new(input),
            Err(SchemaError::RedactionRequired)
        );
    }

    #[test]
    fn clock_quality_is_explicit_and_does_not_fabricate_time() {
        let mut input = base(EventKind::UpdateBoot, Severity::Warning);
        input.clock_quality = ClockQuality::Untrusted;
        let event = DiagnosticEvent::new(input).unwrap();
        assert_eq!(event.clock_quality(), ClockQuality::Untrusted);
        assert_eq!(event.observed_at(), 42);
    }

    #[test]
    fn remote_export_defaults_off_and_secret_never_exports() {
        let normal = DiagnosticEvent::new(base(EventKind::Network, Severity::Warning)).unwrap();
        assert_eq!(
            export_decision(&normal, None, 1),
            ExportDecision::LocalOnlyNoGrant
        );
        assert_eq!(
            export_decision(
                &normal,
                Some(RemoteGrant {
                    purpose: ExportPurpose::UserSupport,
                    expires_at: 10,
                    locally_authorized: true,
                    allow_sensitive: false,
                }),
                9,
            ),
            ExportDecision::RedactedEnvelope
        );

        let mut secret = base(EventKind::ServiceCrash, Severity::Critical);
        secret.privacy = PrivacyClass::Secret;
        let secret = DiagnosticEvent::new(secret).unwrap();
        assert_eq!(
            export_decision(
                &secret,
                Some(RemoteGrant {
                    purpose: ExportPurpose::SecurityResponse,
                    expires_at: 10,
                    locally_authorized: true,
                    allow_sensitive: true,
                }),
                9,
            ),
            ExportDecision::LocalOnlySecret
        );
    }

    #[test]
    fn sensitive_export_requires_security_purpose_and_live_local_grant() {
        let mut input = base(EventKind::ApplicationCrash, Severity::Error);
        input.privacy = PrivacyClass::Sensitive;
        let event = DiagnosticEvent::new(input).unwrap();
        let grant = RemoteGrant {
            purpose: ExportPurpose::UserSupport,
            expires_at: 10,
            locally_authorized: true,
            allow_sensitive: true,
        };
        assert_eq!(
            export_decision(&event, Some(grant), 9),
            ExportDecision::LocalOnlySensitive
        );
        assert_eq!(
            export_decision(
                &event,
                Some(RemoteGrant {
                    purpose: ExportPurpose::SecurityResponse,
                    ..grant
                }),
                9,
            ),
            ExportDecision::RedactedEnvelope
        );
        assert_eq!(
            export_decision(
                &event,
                Some(RemoteGrant {
                    purpose: ExportPurpose::SecurityResponse,
                    ..grant
                }),
                10,
            ),
            ExportDecision::LocalOnlyInvalidGrant
        );
    }

    #[test]
    fn invalid_component_and_oversized_cause_chain_are_rejected() {
        let mut input = base(EventKind::DriverHardware, Severity::Error);
        input.component = "bad component";
        assert_eq!(DiagnosticEvent::new(input), Err(SchemaError::Component));

        let causes = [1u32, 2, 3, 4, 5, 6, 7, 8, 9];
        input = base(EventKind::DriverHardware, Severity::Error);
        input.causes = &causes;
        assert_eq!(DiagnosticEvent::new(input), Err(SchemaError::Causes));
    }

    #[test]
    fn bounded_query_filters_and_pages_without_exposing_secret_events() {
        let mut ring = DiagnosticRing::<4>::new();
        let mut info = base(EventKind::Network, Severity::Info);
        info.privacy = PrivacyClass::Internal;
        ring.record(DiagnosticEvent::new(info).unwrap()).unwrap();
        ring.record(
            DiagnosticEvent::new(base(EventKind::StorageCorruption, Severity::Error)).unwrap(),
        )
        .unwrap();
        let mut sensitive = base(EventKind::ServiceCrash, Severity::Warning);
        sensitive.privacy = PrivacyClass::Sensitive;
        ring.record(DiagnosticEvent::new(sensitive).unwrap())
            .unwrap();
        let mut secret = base(EventKind::KernelException, Severity::Critical);
        secret.privacy = PrivacyClass::Secret;
        ring.record(DiagnosticEvent::new(secret).unwrap()).unwrap();

        let mut query = DiagnosticQuery::new(None, Severity::Error, PrivacyClass::Internal, 1);
        assert_eq!(ring.query_next(&mut query).unwrap().id(), 2);
        assert_eq!(ring.query_next(&mut query), None);
        query.remaining = 4;
        assert_eq!(ring.query_next(&mut query), None);

        let mut category = DiagnosticQuery::new(
            Some(EventKind::ServiceCrash),
            Severity::Info,
            PrivacyClass::Sensitive,
            4,
        );
        assert_eq!(ring.query_next(&mut category).unwrap().id(), 3);
        assert_eq!(ring.query_next(&mut category), None);
    }

    struct MemoryDisk {
        bytes: [u8; DIAGNOSTIC_COPY_STRIDE * 2],
        writes: usize,
        fail_write_at: Option<usize>,
        fail_flush: bool,
    }

    impl MemoryDisk {
        fn new() -> Self {
            Self {
                bytes: [0; DIAGNOSTIC_COPY_STRIDE * 2],
                writes: 0,
                fail_write_at: None,
                fail_flush: false,
            }
        }
    }

    impl DiagnosticIo for MemoryDisk {
        fn capacity(&self) -> usize {
            self.bytes.len()
        }

        fn read(&mut self, offset: usize, out: &mut [u8]) -> Result<(), DiagnosticIoError> {
            let end = offset
                .checked_add(out.len())
                .ok_or(DiagnosticIoError::Read)?;
            let source = self.bytes.get(offset..end).ok_or(DiagnosticIoError::Read)?;
            out.copy_from_slice(source);
            Ok(())
        }

        fn write(&mut self, offset: usize, input: &[u8]) -> Result<(), DiagnosticIoError> {
            let write = self.writes;
            self.writes = self.writes.saturating_add(1);
            if self.fail_write_at == Some(write) {
                return Err(DiagnosticIoError::Write);
            }
            let end = offset
                .checked_add(input.len())
                .ok_or(DiagnosticIoError::Write)?;
            let target = self
                .bytes
                .get_mut(offset..end)
                .ok_or(DiagnosticIoError::Write)?;
            target.copy_from_slice(input);
            Ok(())
        }

        fn flush(&mut self) -> Result<(), DiagnosticIoError> {
            if self.fail_flush {
                Err(DiagnosticIoError::Flush)
            } else {
                Ok(())
            }
        }
    }

    struct TestAuthority;

    impl DiagnosticAuthority for TestAuthority {
        fn access(&self, subject: u64) -> Option<DiagnosticAccess> {
            match subject {
                1 => Some(DiagnosticAccess {
                    can_collect: false,
                    can_query: true,
                    privacy_ceiling: PrivacyClass::Internal,
                    max_page: 2,
                }),
                2 => Some(DiagnosticAccess {
                    can_collect: true,
                    can_query: true,
                    privacy_ceiling: PrivacyClass::Secret,
                    max_page: 16,
                }),
                _ => None,
            }
        }
    }

    #[test]
    fn persistent_diagnostics_survive_reopen_with_ring_statistics() {
        let disk = MemoryDisk::new();
        let mut store = PersistentDiagnosticStore::format(disk).unwrap();
        let event = DiagnosticEvent::new(base(EventKind::ServiceCrash, Severity::Error)).unwrap();
        let (outcome, stats) = store.record(event).unwrap();
        assert_eq!(outcome, RecordOutcome::Stored(1));
        assert_eq!(stats.len, 1);

        let reopened = PersistentDiagnosticStore::open(store.into_device()).unwrap();
        assert_eq!(reopened.sequence(), 2);
        assert_eq!(reopened.ring().stats(), stats);
        let restored = reopened.ring().get(1).unwrap();
        assert_eq!(restored.kind(), EventKind::ServiceCrash);
        assert_eq!(restored.component(), "system.storage");
        assert_eq!(restored.resource_pressure(), [10, 20, 30, 40]);
    }

    #[test]
    fn failed_inactive_copy_commit_keeps_previous_snapshot() {
        let disk = MemoryDisk::new();
        let mut store = PersistentDiagnosticStore::format(disk).unwrap();
        store
            .record(DiagnosticEvent::new(base(EventKind::Network, Severity::Warning)).unwrap())
            .unwrap();
        store.device.fail_write_at = Some(store.device.writes);
        assert!(matches!(
            store.record(
                DiagnosticEvent::new(base(EventKind::StorageCorruption, Severity::Critical))
                    .unwrap()
            ),
            Err(DiagnosticStoreError::Io(DiagnosticIoError::Write))
        ));
        assert_eq!(store.ring().len(), 1);

        store.device.fail_write_at = None;
        let reopened = PersistentDiagnosticStore::open(store.into_device()).unwrap();
        assert_eq!(reopened.sequence(), 2);
        assert_eq!(reopened.ring().len(), 1);
        assert_eq!(reopened.ring().get(1).unwrap().kind(), EventKind::Network);
    }

    #[test]
    fn corrupt_latest_copy_falls_back_to_previous_generation() {
        let disk = MemoryDisk::new();
        let mut store = PersistentDiagnosticStore::format(disk).unwrap();
        store
            .record(DiagnosticEvent::new(base(EventKind::Network, Severity::Warning)).unwrap())
            .unwrap();
        store
            .record(
                DiagnosticEvent::new(base(EventKind::StorageCorruption, Severity::Critical))
                    .unwrap(),
            )
            .unwrap();
        let newest_offset = DIAGNOSTIC_COPY_STRIDE;
        let mut disk = store.into_device();
        disk.bytes[newest_offset + 60] ^= 0xff;
        let reopened = PersistentDiagnosticStore::open(disk).unwrap();
        assert_eq!(reopened.sequence(), 2);
        assert_eq!(reopened.ring().len(), 1);
        assert_eq!(reopened.ring().get(1).unwrap().kind(), EventKind::Network);
    }

    #[test]
    fn collector_persists_all_event_classes_and_pages_by_stable_id() {
        let mut collector = DiagnosticCollector::format(MemoryDisk::new()).unwrap();
        for (index, kind) in EventKind::ALL.into_iter().enumerate() {
            let mut input = base(kind, Severity::Warning);
            input.observed_at = 100 + index as u64;
            let report = collector.collect(input).unwrap();
            assert_eq!(report.outcome, RecordOutcome::Stored(index as u64 + 1));
            assert_eq!(report.sequence, index as u64 + 2);
        }
        assert_eq!(
            collector.status(),
            CollectorStatus {
                stats: RingStats {
                    len: EventKind::ALL.len(),
                    accepted: EventKind::ALL.len() as u64,
                    capacity_dropped: 0,
                },
                sequence: EventKind::ALL.len() as u64 + 1,
            }
        );

        let mut query = DiagnosticQuery::new(
            None,
            Severity::Info,
            PrivacyClass::Internal,
            EventKind::ALL.len(),
        );
        let first = collector.query_page::<3>(&mut query);
        let second = collector.query_page::<3>(&mut query);
        let third = collector.query_page::<3>(&mut query);
        assert_eq!((first.len(), second.len(), third.len()), (3, 3, 2));
        let mut ids = [0u64; 8];
        for (slot, event) in first
            .events
            .iter()
            .chain(second.events.iter())
            .chain(third.events.iter())
            .flatten()
            .enumerate()
        {
            ids[slot] = event.id();
        }
        assert_eq!(ids, [1, 2, 3, 4, 5, 6, 7, 8]);

        let reopened = DiagnosticCollector::open(collector.into_device()).unwrap();
        assert_eq!(
            reopened.status(),
            CollectorStatus {
                stats: RingStats {
                    len: EventKind::ALL.len(),
                    accepted: EventKind::ALL.len() as u64,
                    capacity_dropped: 0,
                },
                sequence: EventKind::ALL.len() as u64 + 1,
            }
        );
    }

    #[test]
    fn collector_commit_failure_keeps_published_state_and_reopen_snapshot() {
        let mut collector = DiagnosticCollector::format(MemoryDisk::new()).unwrap();
        collector
            .collect(base(EventKind::Network, Severity::Warning))
            .unwrap();
        let before = collector.status();
        collector.store.device.fail_write_at = Some(collector.store.device.writes);
        assert_eq!(
            collector.collect(base(EventKind::StorageCorruption, Severity::Critical)),
            Err(CollectError::Store(DiagnosticStoreError::Io(
                DiagnosticIoError::Write
            )))
        );
        assert_eq!(collector.status(), before);

        collector.store.device.fail_write_at = None;
        let reopened = DiagnosticCollector::open(collector.into_device()).unwrap();
        assert_eq!(reopened.status(), before);
        let mut query = DiagnosticQuery::new(None, Severity::Info, PrivacyClass::Internal, 16);
        let page = reopened.query_page::<16>(&mut query);
        assert_eq!(page.len(), 1);
        assert_eq!(page.get(0).unwrap().kind(), EventKind::Network);
    }

    #[test]
    fn collector_query_never_exposes_above_ceiling_events() {
        let mut collector = DiagnosticCollector::format(MemoryDisk::new()).unwrap();
        collector
            .collect(base(EventKind::Network, Severity::Warning))
            .unwrap();
        let mut sensitive = base(EventKind::ServiceCrash, Severity::Error);
        sensitive.privacy = PrivacyClass::Sensitive;
        collector.collect(sensitive).unwrap();
        let mut secret = base(EventKind::KernelException, Severity::Critical);
        secret.privacy = PrivacyClass::Secret;
        collector.collect(secret).unwrap();

        let mut query = DiagnosticQuery::new(None, Severity::Info, PrivacyClass::Internal, 16);
        let page = collector.query_page::<16>(&mut query);
        assert_eq!(page.len(), 1);
        assert_eq!(page.get(0).unwrap().kind(), EventKind::Network);
    }

    #[test]
    fn diagnostic_service_rechecks_authority_and_caps_privacy_and_pages() {
        let mut service = DiagnosticService::format(MemoryDisk::new(), TestAuthority).unwrap();
        service
            .collect(2, base(EventKind::Network, Severity::Warning))
            .unwrap();
        let mut sensitive = base(EventKind::ServiceCrash, Severity::Error);
        sensitive.privacy = PrivacyClass::Sensitive;
        service.collect(2, sensitive).unwrap();
        let mut secret = base(EventKind::KernelException, Severity::Critical);
        secret.privacy = PrivacyClass::Secret;
        service.collect(2, secret).unwrap();

        let request = DiagnosticQueryRequest {
            kind: None,
            minimum_severity: Severity::Info,
            privacy_ceiling: PrivacyClass::Secret,
            after_id: 0,
            limit: 16,
        };
        let (page, cursor, status) = service.query_page::<4>(1, request).unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page.get(0).unwrap().kind(), EventKind::Network);
        assert_eq!(cursor, 1);
        assert_eq!(status.stats.len, 3);
        let (next, next_cursor, _) = service
            .query_page::<4>(
                1,
                DiagnosticQueryRequest {
                    after_id: cursor,
                    ..request
                },
            )
            .unwrap();
        assert!(next.is_empty());
        assert_eq!(next_cursor, cursor);

        let (first, cursor, _) = service.query_page::<2>(2, request).unwrap();
        assert_eq!((first.len(), cursor), (2, 2));
        let (second, cursor, _) = service
            .query_page::<2>(
                2,
                DiagnosticQueryRequest {
                    after_id: cursor,
                    ..request
                },
            )
            .unwrap();
        assert_eq!((second.len(), cursor), (1, 3));
        assert_eq!(
            service.collect(1, base(EventKind::ApplicationCrash, Severity::Error)),
            Err(DiagnosticServiceError::Unauthorized)
        );
        assert!(matches!(
            service.query_page::<4>(99, request),
            Err(DiagnosticServiceError::Unauthorized)
        ));
    }

    #[test]
    fn diagnostic_service_reopens_with_same_authority_policy() {
        let mut service = DiagnosticService::format(MemoryDisk::new(), TestAuthority).unwrap();
        service
            .collect(2, base(EventKind::UpdateBoot, Severity::Error))
            .unwrap();
        let disk = service.into_device();
        let reopened = DiagnosticService::open(disk, TestAuthority).unwrap();
        let (page, cursor, status) = reopened
            .query_page::<4>(
                1,
                DiagnosticQueryRequest {
                    kind: Some(EventKind::UpdateBoot),
                    minimum_severity: Severity::Info,
                    privacy_ceiling: PrivacyClass::Internal,
                    after_id: 0,
                    limit: 4,
                },
            )
            .unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page.get(0).unwrap().kind(), EventKind::UpdateBoot);
        assert_eq!(cursor, 1);
        assert_eq!(status.stats.len, 1);
    }
}
