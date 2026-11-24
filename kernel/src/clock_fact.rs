//! Live kernel clock fact with coherent Time64 and Time128 views.
//! 实时内核时钟事实及其一致的 Time64/Time128 视图。

use kernel_core::clock_contract::{
    ClockIdentity, ClockQuality, ClockSnapshotCell, Epoch, Measurement,
    MonotonicSnapshot, SourceClass, TimeScale, TrustState,
};

const CLOCK_DOMAIN: u64 = 1;
static SNAPSHOT: ClockSnapshotCell = ClockSnapshotCell::new();

/// Read the existing monotonic scheduler clock once and publish both widths.
/// 从现有单调调度时钟读取一次，并发布两个位宽。
pub fn snapshot() -> Option<MonotonicSnapshot> {
    let nanos = crate::sched::now_ns();
    let boot_generation = crate::early::boot_id().max(1);
    let resolution_ns = crate::early::tsc_frequency_hz()
        .map(|frequency| (1_000_000_000u64 / frequency.max(1)).max(1));
    let identity = ClockIdentity {
        scale: TimeScale::Monotonic,
        epoch: Epoch::Boot(boot_generation),
        boot_generation,
        domain_id: CLOCK_DOMAIN,
        publication_sequence: 0,
        quality: ClockQuality {
            source: SourceClass::ArchitectureTimer,
            source_id: CLOCK_DOMAIN,
            trust: TrustState::Untrusted,
            synchronized: false,
            resolution: resolution_ns
                .map(Measurement::Nanoseconds)
                .unwrap_or(Measurement::Unknown),
            uncertainty: Measurement::Unknown,
            sample_age: Measurement::Nanoseconds(0),
            drift_ppb: None,
        },
    };
    let value = MonotonicSnapshot::from_nanos(nanos, identity).ok()?;
    SNAPSHOT.publish_monotonic(value).ok()?;
    SNAPSHOT.read_monotonic().ok()
}

/// Default Time64 monotonic value. The Time128 view is published from the
/// same read rather than sampled independently.
/// 默认 Time64 单调值；Time128 视图来自同一次读取。
pub fn now_ns() -> u64 {
    snapshot().map_or_else(crate::sched::now_ns, |value| value.time64_ns)
}

/// Emit one hardware-discovered, explicitly untrusted clock snapshot.
/// 输出一次硬件发现、明确不可信的时钟快照。
pub fn report() {
    if let Some(value) = snapshot() {
        crate::kprintln!(
            "[JSR-CLOCK-FACT] scale=monotonic epoch=boot:{} generation={} domain={} source=architecture-timer trust=untrusted synchronized=false time64_ns={} time128_sec={} time128_fraction={} resolution_ns={:?} uncertainty=unknown",
            value.identity.boot_generation,
            value.identity.boot_generation,
            value.identity.domain_id,
            value.time64_ns,
            value.time128.seconds,
            value.time128.fraction,
            value.identity.quality.resolution
        );
    }
}
