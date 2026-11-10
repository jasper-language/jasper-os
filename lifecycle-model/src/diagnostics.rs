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

/// 固定容量诊断事件环；满时优先淘汰最低严重度，同级保留先到事件。
/// Fixed-capacity diagnostic ring; evicts the lowest severity first and keeps earlier equal-severity events.
#[derive(Clone, Debug)]
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
}
