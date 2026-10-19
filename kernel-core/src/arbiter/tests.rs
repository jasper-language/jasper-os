//! 仲裁器的宿主测试：预留上限、饥饿补偿、兜底与确定性。
//! Host tests for the arbiter.

use super::*;

#[test]
fn realtime_runs_first_within_reserve() {
    let mut a = Arbiter::new(ArbiterParams::DEFAULT);
    let w = Window::default();
    let demand = Demand { realtime: true, interactive: true, batch: true };
    assert_eq!(a.pick(demand, &w), Some(Class::RealTime));
}

#[test]
fn realtime_is_capped_by_its_reserve() {
    let mut a = Arbiter::new(ArbiterParams { rt_reserve_permille: 300, ..ArbiterParams::DEFAULT });
    // 窗口 100 tick、实时已用 40 ⇒ 400‰，超过 300‰ 预留。
    let w = Window { ticks: 100, realtime: 40, interactive: 50, batch: 10 };
    let demand = Demand { realtime: true, interactive: true, batch: false };
    assert_eq!(a.pick(demand, &w), Some(Class::Interactive), "实时超预留后必须让给交互");
}

#[test]
fn realtime_still_runs_when_nothing_else_is_runnable() {
    let mut a = Arbiter::new(ArbiterParams { rt_reserve_permille: 100, ..ArbiterParams::DEFAULT });
    let w = Window { ticks: 100, realtime: 50, interactive: 10, batch: 40 };
    let demand = Demand { realtime: true, interactive: false, batch: false };
    assert_eq!(a.pick(demand, &w), Some(Class::RealTime), "唯一可运行时不得让处理器空转");
}

#[test]
fn batch_starvation_forces_a_turn() {
    let mut a = Arbiter::new(ArbiterParams { batch_aging_ticks: 5, ..ArbiterParams::DEFAULT });
    let w = Window::default();
    // 交互一直可运行、批处理一直等着。
    let demand = Demand { realtime: false, interactive: true, batch: true };
    for _ in 0..5 {
        assert_eq!(a.pick(demand, &w), Some(Class::Interactive));
    }
    assert_eq!(a.pick(demand, &w), Some(Class::Batch), "等待达到阈值必须补偿批处理");
    assert_eq!(a.batch_wait(), 0, "补偿后等待计数清零");
}

#[test]
fn idle_returns_none() {
    let mut a = Arbiter::new(ArbiterParams::DEFAULT);
    assert_eq!(a.pick(Demand::default(), &Window::default()), None);
}

#[test]
fn decision_is_deterministic() {
    let w = Window { ticks: 50, realtime: 10, interactive: 30, batch: 10 };
    let demand = Demand { realtime: true, interactive: true, batch: true };
    let mut a = Arbiter::new(ArbiterParams::DEFAULT);
    let mut b = Arbiter::new(ArbiterParams::DEFAULT);
    for _ in 0..20 {
        assert_eq!(a.pick(demand, &w), b.pick(demand, &w));
    }
}

#[test]
fn window_accounting_is_permille() {
    let mut w = Window::default();
    for _ in 0..80 {
        w.charge(Class::Interactive);
    }
    for _ in 0..20 {
        w.charge(Class::Batch);
    }
    assert_eq!(w.share_permille(Class::Interactive), 800);
    assert_eq!(w.share_permille(Class::Batch), 200);
    assert_eq!(w.share_permille(Class::RealTime), 0);
}

#[test]
fn batch_floor_check_reports_shortfall() {
    let a = Arbiter::new(ArbiterParams { batch_floor_permille: 100, ..ArbiterParams::DEFAULT });
    let starved = Window { ticks: 100, realtime: 0, interactive: 100, batch: 0 };
    assert!(!a.batch_floor_met(&starved));
    let ok = Window { ticks: 100, realtime: 0, interactive: 90, batch: 10 };
    assert!(a.batch_floor_met(&ok));
}
