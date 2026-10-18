//! QoS 策略的确定性模拟测试：在宿主上逐 tick 模拟「吃满 CPU 的任务 + 周期性交互任务」，
//! 验证唤醒延迟、各档份额、防饿死、档内公平与用量衰减。
//! Deterministic tick-level simulation tests for the QoS policy.
//!
//! 模拟器与内核机制的顺序一致：每个 tick 先给刚运行完这个 tick 的任务记账，再唤醒到期的睡眠任务
//! （唤醒可能立即抢占），最后检查时间片 / 更高档 / 欠账抢占；需要时重新选择。

use super::*;

/// 模拟任务的行为。
#[derive(Clone, Copy)]
enum Kind {
    /// 永远可运行（吃满 CPU）。
    Hog,
    /// 每 `period` 个 tick 醒来一次，运行 `burst` 个 tick 后睡到下一个周期点。
    Periodic { period: u64, burst: u32 },
}

struct SimTask {
    e: SchedEntity,
    kind: Kind,
    runnable: bool,
    woken_at: Option<u64>,
    burst_left: u32,
    next_wake: u64,
    lat: LatencyHistogram,
}

struct Sim {
    policy: QosPolicy,
    tasks: Vec<SimTask>,
    current: Option<usize>,
    used: u32,
    quantum: u32,
    now: u64,
    idle_with_work: u64,
}

impl Sim {
    fn new() -> Self {
        Sim {
            policy: QosPolicy::new(QosParams::DEFAULT),
            tasks: Vec::new(),
            current: None,
            used: 0,
            quantum: 0,
            now: 0,
            idle_with_work: 0,
        }
    }

    fn add(&mut self, qos: Qos, kind: Kind) -> usize {
        let (runnable, next_wake, burst_left) = match kind {
            Kind::Hog => (true, 0, 0),
            Kind::Periodic { period, burst } => (false, period, burst),
        };
        self.tasks.push(SimTask {
            e: SchedEntity::new(qos),
            kind,
            runnable,
            woken_at: None,
            burst_left,
            next_wake,
            lat: LatencyHistogram::new(),
        });
        self.tasks.len() - 1
    }

    fn waiting(&self) -> ClassMask {
        let mut m = ClassMask::EMPTY;
        for (i, t) in self.tasks.iter().enumerate() {
            if t.runnable && Some(i) != self.current {
                m.insert(t.e.qos);
            }
        }
        m
    }

    fn pick(&mut self) {
        let tasks = &self.tasks;
        let mut it = tasks.iter().enumerate().filter(|(_, t)| t.runnable).map(|(i, t)| (i, &t.e));
        let choice = self.policy.choose(&mut it);
        match choice {
            Some(c) => {
                let t = &mut self.tasks[c.slot];
                self.policy.dispatched(&mut t.e);
                if let Some(w) = t.woken_at.take() {
                    t.lat.record(self.now - w);
                }
                self.current = Some(c.slot);
                self.used = 0;
                self.quantum = c.quantum;
            }
            None => self.current = None,
        }
    }

    /// 推进一个 tick。
    fn step(&mut self) {
        self.now += 1;
        let waiting = self.waiting();
        let cur = self.current;
        self.policy.on_tick(cur.map(|i| &mut self.tasks[i].e), waiting);
        self.used += 1;
        let mut resched = false;
        // 当前任务这个 tick 的工作做完了吗？
        if let Some(i) = cur {
            let now = self.now;
            let t = &mut self.tasks[i];
            if let Kind::Periodic { period, .. } = t.kind {
                t.burst_left -= 1;
                if t.burst_left == 0 {
                    t.runnable = false;
                    t.next_wake = (now / period + 1) * period;
                    self.current = None;
                    resched = true;
                }
            }
        }
        // 唤醒到期的睡眠任务。
        let cur_qos = self.current.map(|i| self.tasks[i].e.qos);
        for t in self.tasks.iter_mut() {
            if let Kind::Periodic { burst, .. } = t.kind {
                if !t.runnable && t.next_wake <= self.now {
                    t.runnable = true;
                    t.woken_at = Some(self.now);
                    t.burst_left = burst;
                    self.policy.woken(&mut t.e);
                    if self.policy.wake_preempts(t.e.qos, cur_qos) {
                        resched = true;
                    }
                }
            }
        }
        if !resched {
            let cur = self.current.map(|i| &self.tasks[i].e);
            if self.policy.should_preempt(cur, self.used, self.quantum, self.waiting()).is_some() {
                resched = true;
            }
        }
        if resched || self.current.is_none() {
            self.pick();
        }
        if self.current.is_none() && self.tasks.iter().any(|t| t.runnable) {
            self.idle_with_work += 1;
        }
    }

    fn run(&mut self, ticks: u64) {
        if self.current.is_none() {
            self.pick();
        }
        for _ in 0..ticks {
            self.step();
        }
    }

    fn cpu(&self, i: usize) -> u64 {
        self.tasks[i].e.cpu_ticks
    }
}

#[test]
fn interactive_wake_latency_is_zero_under_background_hogs() {
    let mut s = Sim::new();
    let hogs: Vec<usize> = (0..4).map(|_| s.add(Qos::Background, Kind::Hog)).collect();
    let ui = s.add(Qos::UserInitiated, Kind::Periodic { period: 5, burst: 1 });
    s.run(4000);
    let lat = s.tasks[ui].lat;
    assert!(lat.count() >= 790, "交互任务唤醒次数 {}", lat.count());
    assert_eq!(lat.max(), 0, "高档任务被唤醒时应立即抢占后台任务");
    let cpu: Vec<u64> = hogs.iter().map(|&h| s.cpu(h)).collect();
    let (min, max) = (*cpu.iter().min().unwrap(), *cpu.iter().max().unwrap());
    assert!(min > 0 && min * 2 >= max, "后台任务之间应轮流：{:?}", cpu);
    assert_eq!(s.idle_with_work, 0);
}

#[test]
fn same_class_wake_latency_bounded_by_quantum() {
    let mut s = Sim::new();
    for _ in 0..4 {
        s.add(Qos::UserInitiated, Kind::Hog);
    }
    let p = s.add(Qos::UserInitiated, Kind::Periodic { period: 7, burst: 1 });
    s.run(4000);
    let lat = s.tasks[p].lat;
    // 同档不抢占，但档内唤醒优先 ⇒ 当前时间片一结束就轮到它，而不是排在所有吃满任务之后。
    assert!(lat.max() <= QosParams::DEFAULT.quantum[1] as u64, "max={}", lat.max());
}

#[test]
fn every_class_keeps_its_minimum_share() {
    let mut s = Sim::new();
    let ids: Vec<usize> = Qos::ALL.iter().map(|&q| s.add(q, Kind::Hog)).collect();
    let total = 20_000u64;
    s.run(total);
    let share: Vec<u64> = ids.iter().map(|&i| s.cpu(i) * 1000 / total).collect();
    assert!(share[0] >= 750, "交互档份额 {:?}", share);
    assert!(share[1] >= 80, "用户发起档份额 {:?}", share);
    assert!(share[2] >= 40, "工具档份额 {:?}", share);
    assert!(share[3] >= 15, "后台档份额 {:?}", share);
    assert_eq!(ids.iter().map(|&i| s.cpu(i)).sum::<u64>(), total, "有可运行任务时不得空转");
}

#[test]
fn background_is_throttled_to_its_share_under_contention() {
    let mut s = Sim::new();
    let fg = s.add(Qos::UserInitiated, Kind::Hog);
    let bg = s.add(Qos::Background, Kind::Hog);
    let total = 10_000u64;
    s.run(total);
    let bg_share = s.cpu(bg) * 1000 / total;
    assert!((15..=30).contains(&bg_share), "后台份额 {}‰", bg_share);
    assert_eq!(s.cpu(fg) + s.cpu(bg), total);
}

#[test]
fn background_alone_uses_the_whole_cpu() {
    let mut s = Sim::new();
    let a = s.add(Qos::Background, Kind::Hog);
    let b = s.add(Qos::Background, Kind::Hog);
    s.run(1000);
    assert_eq!(s.cpu(a) + s.cpu(b), 1000, "没有更高档工作时后台不受限");
    assert!(s.cpu(a).abs_diff(s.cpu(b)) <= 4);
}

#[test]
fn equal_hogs_share_fairly() {
    let mut s = Sim::new();
    let ids: Vec<usize> = (0..3).map(|_| s.add(Qos::Utility, Kind::Hog)).collect();
    s.run(9000);
    for &i in &ids {
        assert!(s.cpu(i).abs_diff(3000) <= 30, "cpu={}", s.cpu(i));
    }
}

#[test]
fn pressure_release_recovers_immediately() {
    // 压力期间与撤销之后，交互任务的延迟都为 0；撤销后它独占需要的全部 CPU。
    let mut s = Sim::new();
    let hogs: Vec<usize> = (0..6).map(|_| s.add(Qos::Utility, Kind::Hog)).collect();
    let ui = s.add(Qos::Interactive, Kind::Periodic { period: 3, burst: 2 });
    s.run(3000);
    assert_eq!(s.tasks[ui].lat.max(), 0);
    for &h in &hogs {
        s.tasks[h].runnable = false;
    }
    let before = s.cpu(ui);
    s.run(300);
    assert_eq!(s.tasks[ui].lat.max(), 0);
    assert_eq!(s.cpu(ui) - before, 200, "撤销压力后交互任务每周期都拿到完整的 2 个 tick");
}

#[test]
fn usage_decays_by_half_each_period() {
    let mut p = QosPolicy::new(QosParams::DEFAULT);
    let mut e = SchedEntity::new(Qos::UserInitiated);
    for _ in 0..8 {
        p.on_tick(Some(&mut e), ClassMask::EMPTY);
    }
    // 第 8 个 tick 进入纪元 1：前 7 个 tick 的用量在记第 8 个之前已减半。
    assert_eq!(p.effective_usage(&e), 7 * 1024 / 2 + 1024);
    let base = p.effective_usage(&e);
    for _ in 0..8 {
        p.on_tick(None, ClassMask::EMPTY);
    }
    assert_eq!(p.effective_usage(&e), base / 2);
    for _ in 0..8 * 40 {
        p.on_tick(None, ClassMask::EMPTY);
    }
    assert_eq!(p.effective_usage(&e), 0, "很久以前的用量完全衰减");
}

#[test]
fn rescued_dispatch_gets_exactly_one_tick() {
    let mut p = QosPolicy::new(QosParams::DEFAULT);
    let hi = SchedEntity::new(Qos::Interactive);
    let lo = SchedEntity::new(Qos::Background);
    // 后台档等满 50 个 tick（20‰ × 50 = 1000）后应被补给一次。
    let mut waiting = ClassMask::EMPTY;
    waiting.insert(Qos::Background);
    let mut hi_run = hi;
    for _ in 0..50 {
        p.on_tick(Some(&mut hi_run), waiting);
    }
    assert_eq!(p.owed(Qos::Background), 1000);
    let cands = [(1usize, hi_run), (2usize, lo)];
    let mut it = cands.iter().map(|(i, e)| (*i, e));
    let c = p.choose(&mut it).unwrap();
    assert_eq!(c, Choice { slot: 2, quantum: 1, rescued: true });
    assert_eq!(p.should_preempt(Some(&hi_run), 0, 2, waiting), Some(Preempt::Owed));
}

#[test]
fn wake_preemption_rules() {
    let p = QosPolicy::new(QosParams::DEFAULT);
    assert!(p.wake_preempts(Qos::Background, None), "任何任务都抢占空闲");
    assert!(!p.wake_preempts(Qos::Background, Some(Qos::Background)));
    assert!(!p.wake_preempts(Qos::Background, Some(Qos::Utility)));
    assert!(p.wake_preempts(Qos::Interactive, Some(Qos::UserInitiated)));
    assert!(p.wake_preempts(Qos::Utility, Some(Qos::Background)));
    assert!(!p.wake_preempts(Qos::UserInitiated, Some(Qos::UserInitiated)), "同档不抢占");
}

#[test]
fn qos_change_rules() {
    use Qos::*;
    assert!(qos_change_allowed(UserInitiated, Background, None), "降低总是允许");
    assert!(qos_change_allowed(Utility, Utility, None), "不变总是允许");
    assert!(!qos_change_allowed(Background, UserInitiated, None), "没有能力不能自升");
    assert!(qos_change_allowed(Background, UserInitiated, Some(UserInitiated)));
    assert!(!qos_change_allowed(Background, Interactive, Some(UserInitiated)), "不能超过上限");
    assert_eq!(Qos::from_raw(4), None);
    assert_eq!(Qos::from_raw(u64::MAX), None);
    assert_eq!(Qos::from_raw(3), Some(Background));
}

#[test]
fn latency_histogram_percentiles() {
    let mut h = LatencyHistogram::new();
    assert_eq!(h.percentile(990), 0);
    for _ in 0..99 {
        h.record(0);
    }
    h.record(3);
    assert_eq!(h.percentile(990), 0);
    assert_eq!(h.percentile(1000), 3);
    h.record(100);
    assert_eq!(h.max(), 100);
    assert_eq!(h.percentile(1000), 100, "最后一桶报告实际最大值");
}

/// 确定性 PRNG（xorshift64*），测试自带、不引入外部依赖。
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

#[test]
fn random_mixes_never_starve_a_class() {
    for seed in 1..=24u64 {
        let mut r = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let mut s = Sim::new();
        for _ in 0..(2 + r.below(6)) {
            let q = Qos::ALL[r.below(4) as usize];
            let kind = if r.below(2) == 0 {
                Kind::Hog
            } else {
                Kind::Periodic { period: 2 + r.below(20), burst: 1 + r.below(3) as u32 }
            };
            s.add(q, kind);
        }
        // 每档「持续可运行」期间相邻两次运行的最大间隔。
        let mut gap = [0u64; QOS_CLASSES];
        let mut worst = [0u64; QOS_CLASSES];
        s.pick();
        for _ in 0..6000 {
            s.step();
            let ran = s.current.map(|i| s.tasks[i].e.qos);
            for q in Qos::ALL {
                let runnable = s.tasks.iter().any(|t| t.runnable && t.e.qos == q);
                if !runnable || ran == Some(q) {
                    gap[q.index()] = 0;
                } else {
                    gap[q.index()] += 1;
                    worst[q.index()] = worst[q.index()].max(gap[q.index()]);
                }
            }
        }
        assert_eq!(s.idle_with_work, 0, "seed {}: 有可运行任务时空转", seed);
        // 有份额的档：最长等待 ≈ 1000/份额 个 tick，外加其它欠账档各补一个 tick 与时间片余量。
        for q in [Qos::UserInitiated, Qos::Utility, Qos::Background] {
            let share = QosParams::DEFAULT.min_share_permille[q.index()] as u64;
            let bound = TICK_UNITS as u64 / share + 8;
            assert!(worst[q.index()] <= bound, "seed {}: {} 最长等待 {} > {}", seed, q.name(), worst[q.index()], bound);
        }
    }
}
