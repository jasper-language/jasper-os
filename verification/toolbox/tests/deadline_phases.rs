//! issue #2：期限唤醒六个时间点的顺序、时钟域和累计区间性质。
//! Proptest checks the five endpoints after the deadline against an independent
//! cumulative reference; Miri runs one fixed timeline.
use kernel_core::raw_timing::{ClockDomain, DeadlineTimeline, Endpoint};
use proptest::prelude::*;

fn point(cpu: usize, counter: u64, clock: ClockDomain) -> Endpoint {
    Endpoint { cpu, counter, clock }
}

fn timeline(base: u64, gaps: [u64; 4], cpu: usize) -> DeadlineTimeline {
    let a = base + gaps[0];
    let b = a + gaps[1];
    let c = b + gaps[2];
    let d = c + gaps[3];
    DeadlineTimeline::new(
        point(cpu, base, ClockDomain::SharedNs),
        point(cpu, a, ClockDomain::SharedNs),
        point(cpu, b, ClockDomain::SharedNs),
        point(cpu, c, ClockDomain::SharedNs),
        point(cpu, d, ClockDomain::SharedNs),
    )
    .expect("nondecreasing shared timeline")
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, failure_persistence: None, ..ProptestConfig::default() })]

    #[test]
    fn cumulative_samples_match_endpoint_reference(
        base in 0u64..10_000,
        gaps in prop::array::uniform4(1u64..10_000),
        cpu in 0usize..8,
        resume_gap in 0u64..10_000,
    ) {
        let t = timeline(base, gaps, cpu);
        let samples = t.samples_to_published(3, 7, 11);
        let cumulative = [
            gaps[0],
            gaps[0] + gaps[1],
            gaps[0] + gaps[1] + gaps[2],
            gaps[0] + gaps[1] + gaps[2] + gaps[3],
        ];
        prop_assert_eq!(samples.map(|s| s.path), [5, 6, 7, 8]);
        prop_assert_eq!(
            samples.map(|s| s.shared_ns_delta().unwrap()),
            cumulative
        );
        let publish = base + cumulative[3];
        let resume = t
            .sample_to_resume(3, 7, 11, point(cpu, publish + resume_gap, ClockDomain::SharedNs))
            .unwrap();
        prop_assert_eq!(resume.path, 9);
        prop_assert_eq!(resume.shared_ns_delta(), Some(cumulative[3] + resume_gap));
    }

    #[test]
    fn order_and_clock_violations_are_rejected(
        base in 1u64..10_000,
        gaps in prop::array::uniform4(1u64..10_000),
    ) {
        let t = timeline(base, gaps, 2);
        let open = DeadlineTimeline::new(
            t.deadline,
            t.interrupt_entry,
            t.lock_acquired,
            t.wake_start,
            point(2, t.wake_start.counter - 1, ClockDomain::SharedNs),
        );
        prop_assert!(open.is_none());
        let raw = DeadlineTimeline::new(
            t.deadline,
            point(2, t.interrupt_entry.counter, ClockDomain::Raw),
            t.lock_acquired,
            t.wake_start,
            t.queue_published,
        );
        prop_assert!(raw.is_none());
        prop_assert!(t.sample_to_resume(
            3,
            7,
            11,
            point(2, t.queue_published.counter.saturating_sub(1), ClockDomain::SharedNs),
        ).is_none());
    }
}

#[test]
fn fixed_timeline_under_miri() {
    let t = timeline(100, [20, 20, 30, 20], 1);
    let samples = t.samples_to_published(4, 8, 12);
    assert_eq!(samples.map(|s| s.shared_ns_delta().unwrap()), [20, 40, 70, 90]);
    assert_eq!(
        t.sample_to_resume(
            4,
            8,
            12,
            point(1, 220, ClockDomain::SharedNs),
        )
        .unwrap()
        .shared_ns_delta(),
        Some(120)
    );
}
