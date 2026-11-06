//! issue #6：服务装配契约 kernel_core::assembly 的差分性质测试、Miri 固定序列与 Loom 发布协议模型。
//! 参照实现用标准库直接写出规格。
use std::cell::RefCell;

use kernel_core::assembly::{
    mask_has, Assembly, AssemblyError, Availability, Binding, Health, Policy, State,
};
use kernel_core::config::KernelConfig;
use kernel_core::profile::{self, ModuleDecl, SchedClass, SystemProfile};
use proptest::prelude::*;

static NAMES: [&str; 8] = ["m0", "m1", "m2", "m3", "m4", "m5", "m6", "m7"];
static CAPS: [&str; 8] = ["p.m0", "p.m1", "p.m2", "p.m3", "p.m4", "p.m5", "p.m6", "p.m7"];

thread_local! {
    /// 第 k 个模块（按名字 m<k>）的激活结果。
    static OUTCOME: RefCell<[bool; 8]> = const { RefCell::new([true; 8]) };
    static LOG: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

fn act(k: usize) -> Result<(), &'static str> {
    LOG.with(|l| l.borrow_mut().push(format!("a{k}")));
    if OUTCOME.with(|o| o.borrow()[k]) {
        Ok(())
    } else {
        Err("planned failure")
    }
}
fn fini(k: usize) {
    LOG.with(|l| l.borrow_mut().push(format!("f{k}")));
}
macro_rules! pair {
    ($a:ident, $f:ident, $k:expr) => {
        fn $a() -> Result<(), &'static str> {
            act($k)
        }
        fn $f() {
            fini($k)
        }
    };
}
pair!(a0, f0, 0);
pair!(a1, f1, 1);
pair!(a2, f2, 2);
pair!(a3, f3, 3);
pair!(a4, f4, 4);
pair!(a5, f5, 5);
pair!(a6, f6, 6);
pair!(a7, f7, 7);
const ACTS: [fn() -> Result<(), &'static str>; 8] = [a0, a1, a2, a3, a4, a5, a6, a7];
const FINIS: [fn(); 8] = [f0, f1, f2, f3, f4, f5, f6, f7];

fn take_log() -> Vec<String> {
    LOG.with(|l| std::mem::take(&mut *l.borrow_mut()))
}

/// 一份随机 Profile：模块 k 只能依赖 k 之前的模块（保证无环），声明顺序为 `decl_order`。
#[derive(Debug, Clone)]
struct Case {
    n: usize,
    deps: Vec<Vec<usize>>,
    decl_order: Vec<usize>,
    ok: Vec<bool>,
    all_or_nothing: bool,
}

/// 测试构造的 `'static` Profile 留在这里，保持可达（Miri 不把可达内存当作泄漏）。
static KEEP: std::sync::Mutex<Vec<&'static SystemProfile>> = std::sync::Mutex::new(Vec::new());

fn build(c: &Case) -> &'static SystemProfile {
    let modules: Vec<ModuleDecl> = c
        .decl_order
        .iter()
        .map(|&k| {
            let req: Vec<&'static str> = c.deps[k].iter().map(|&d| CAPS[d]).collect();
            ModuleDecl {
                name: NAMES[k],
                provides: std::slice::from_ref(&CAPS[k]),
                requires: Box::leak(req.into_boxed_slice()),
                services: &[],
                hot_load: false,
                sched_class: SchedClass::Interactive,
                min_tasks: 0,
                min_objects: 0,
            }
        })
        .collect();
    let p: &'static SystemProfile = Box::leak(Box::new(SystemProfile {
        name: "prop",
        display_zh: "性质",
        display_en: "prop",
        config: KernelConfig::STANDARD,
        modules: Box::leak(modules.into_boxed_slice()),
        guarantees: &[],
        hot_load: false,
    }));
    KEEP.lock().unwrap().push(p);
    p
}

fn bindings(n: usize) -> Vec<Binding> {
    (0..n).map(|k| Binding { module: NAMES[k], activate: ACTS[k], deactivate: Some(FINIS[k]) }).collect()
}

fn idx(name: &str) -> usize {
    NAMES.iter().position(|n| *n == name).unwrap()
}

/// 运行一例并核对全部性质。
fn check_case(c: &Case) {
    OUTCOME.with(|o| {
        let mut o = o.borrow_mut();
        for k in 0..8 {
            o[k] = c.ok.get(k).copied().unwrap_or(true);
        }
    });
    take_log();
    let p = build(c);
    let declared = profile::resolve(p).expect("generated profile is valid");
    let mut a = Assembly::new(p, &bindings(c.n)).unwrap();
    // 1. 启动顺序是拓扑序。
    let order: Vec<usize> = (0..c.n).map(|k| idx(a.order(k).unwrap())).collect();
    let pos = |m: usize| order.iter().position(|&x| x == m).unwrap();
    for m in 0..c.n {
        for &d in &c.deps[m] {
            assert!(pos(d) < pos(m), "provider {d} must start before {m}");
        }
    }
    // 2. 启动前什么都不发布。
    assert_eq!(a.published_mask(&declared), 0);
    let policy = if c.all_or_nothing { Policy::AllOrNothing } else { Policy::Partial };
    let r = a.start(policy).unwrap();
    let log = take_log();
    // 3. 状态与参照一致。
    let mut ready = vec![false; c.n];
    let mut expect_state = vec![State::Declared; c.n];
    let mut expect_log = Vec::new();
    let mut aborted = false;
    for &m in &order {
        if aborted {
            continue;
        }
        if !c.deps[m].iter().all(|&d| ready[d]) {
            expect_state[m] = State::Blocked;
            continue;
        }
        expect_log.push(format!("a{m}"));
        if c.ok[m] {
            ready[m] = true;
            expect_state[m] = State::Ready;
        } else {
            expect_state[m] = State::Failed;
            if c.all_or_nothing {
                aborted = true;
                let mut started: Vec<usize> = order.iter().copied().filter(|&x| ready[x]).collect();
                started.reverse();
                for s in started {
                    ready[s] = false;
                    expect_state[s] = State::Stopped;
                    expect_log.push(format!("f{s}"));
                }
            }
        }
    }
    assert_eq!(log, expect_log);
    for m in 0..c.n {
        assert_eq!(a.state(NAMES[m]).unwrap().0, expect_state[m], "module {m}");
        let av = a.availability(CAPS[m]);
        assert_eq!(av == Availability::Ready, ready[m]);
    }
    assert_eq!(r.ready as usize, ready.iter().filter(|x| **x).count());
    // 4. 发布掩码与参照一致，通过审计；任意偏离被拒。
    let mask = a.published_mask(&declared);
    for m in 0..c.n {
        assert_eq!(mask_has(&declared, mask, CAPS[m]), ready[m]);
    }
    assert_eq!(a.audit(&declared, mask), Ok(()));
    let known = (1u32 << declared.capabilities().len()) - 1;
    for flip in 1..=known.min(255) {
        assert!(a.audit(&declared, mask ^ flip).is_err());
    }
    if c.all_or_nothing && r.failed > 0 {
        assert_eq!(mask, 0);
    }
    // 5. 重复启动被拒且不调用激活；全部停用按就绪逆序。
    assert_eq!(a.start(policy), Err(AssemblyError::AlreadyStarted));
    assert!(take_log().is_empty());
    let ready_order: Vec<usize> = order.iter().copied().filter(|&x| ready[x]).collect();
    assert_eq!(a.stop_all(), (ready_order.len(), 0));
    let expect_fini: Vec<String> = ready_order.iter().rev().map(|k| format!("f{k}")).collect();
    assert_eq!(take_log(), expect_fini);
    assert_eq!(a.published_mask(&declared), 0);
    assert_eq!(a.audit(&declared, 0), Ok(()));
}

fn case_strategy() -> impl Strategy<Value = Case> {
    (1usize..=8)
        .prop_flat_map(|n| {
            (
                Just(n),
                proptest::collection::vec(any::<u8>(), n),
                Just((0..n).collect::<Vec<_>>()).prop_shuffle(),
                proptest::collection::vec(proptest::bool::weighted(0.8), n),
                any::<bool>(),
            )
        })
        .prop_map(|(n, masks, decl_order, ok, all_or_nothing)| Case {
            n,
            deps: (0..n).map(|k| (0..k).filter(|d| masks[k] & (1 << d) != 0).collect()).collect(),
            decl_order,
            ok,
            all_or_nothing,
        })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn assembly_matches_reference(c in case_strategy()) {
        check_case(&c);
    }

}

/// 依赖环在构造时被拒（两个模块互相依赖）。
#[test]
fn cycle_rejected() {
    let c = Case { n: 2, deps: vec![vec![1], vec![0]], decl_order: vec![0, 1], ok: vec![true, true], all_or_nothing: true };
    let p = build(&c);
    assert!(profile::resolve(p).is_ok());
    assert_eq!(Assembly::new(p, &bindings(2)).err(), Some(AssemblyError::DependencyCycle("m0")));
}

/// Miri：固定序列覆盖成功、全有全无回滚、部分启动阻塞三类路径。
#[test]
fn fixed_sequence_under_miri() {
    let base = Case {
        n: 4,
        deps: vec![vec![], vec![0], vec![1], vec![]],
        decl_order: vec![2, 3, 1, 0],
        ok: vec![true; 4],
        all_or_nothing: true,
    };
    check_case(&base);
    check_case(&Case { ok: vec![true, false, true, true], ..base.clone() });
    check_case(&Case { ok: vec![true, false, true, true], all_or_nothing: false, ..base.clone() });

    OUTCOME.with(|o| *o.borrow_mut() = [true; 8]);
    let p = build(&base);
    let declared = profile::resolve(p).unwrap();
    let mut a = Assembly::new(p, &bindings(base.n)).unwrap();
    a.start(Policy::Partial).unwrap();
    a.set_health("m0", Health::Degraded).unwrap();
    assert_eq!(a.availability(CAPS[1]), Availability::Degraded);
    let withdrawn = a.mask_with_health("m0", Health::Unhealthy, &declared).unwrap();
    assert!(!mask_has(&declared, withdrawn, CAPS[0]));
    assert!(!mask_has(&declared, withdrawn, CAPS[1]));
    a.set_health("m0", Health::Unhealthy).unwrap();
    assert_eq!(a.published_mask(&declared), withdrawn);
    let bits = a.preflight_stop("m2").unwrap();
    a.stop_with("m2", |withdraw| assert_eq!(withdraw, bits)).unwrap();
    assert_eq!(a.state("m2").map(|s| s.0), Some(State::Stopped));

    let gate = kernel_core::service_gate::Gate::new();
    gate.publish(0b1);
    let lease = gate.acquire(0).expect("published service lease");
    gate.withdraw(0b1);
    drop(lease);
    gate.wait_quiescent(|| {});
    assert!(gate.acquire(0).is_none());
}

#[derive(Debug, Clone)]
struct HealthCase {
    n: usize,
    deps: Vec<Vec<usize>>,
    decl_order: Vec<usize>,
    health: Vec<u8>,
}

fn health_case_strategy() -> impl Strategy<Value = HealthCase> {
    (1usize..=8).prop_flat_map(|n| {
        (
            Just(n),
            proptest::collection::vec(any::<u8>(), n),
            Just((0..n).collect::<Vec<_>>()).prop_shuffle(),
            proptest::collection::vec(0u8..3, n),
        )
    })
    .prop_map(|(n, masks, decl_order, health)| HealthCase {
        n,
        deps: (0..n).map(|k| (0..k).filter(|d| masks[k] & (1 << d) != 0).collect()).collect(),
        decl_order,
        health,
    })
}

fn expected_availability(c: &HealthCase, m: usize) -> Health {
    let own = match c.health[m] {
        0 => Health::Healthy,
        1 => Health::Degraded,
        _ => Health::Unhealthy,
    };
    if own == Health::Unhealthy {
        return Health::Unhealthy;
    }
    if c.deps[m].iter().any(|&d| expected_availability(c, d) == Health::Unhealthy) {
        Health::Unhealthy
    } else if own == Health::Degraded
        || c.deps[m].iter().any(|&d| expected_availability(c, d) == Health::Degraded)
    {
        Health::Degraded
    } else {
        Health::Healthy
    }
}

fn check_health_case(c: &HealthCase) {
    let base = Case {
        n: c.n,
        deps: c.deps.clone(),
        decl_order: c.decl_order.clone(),
        ok: vec![true; c.n],
        all_or_nothing: true,
    };
    let p = build(&base);
    let declared = profile::resolve(p).unwrap();
    let mut a = Assembly::new(p, &bindings(c.n)).unwrap();
    a.start(Policy::AllOrNothing).unwrap();
    for m in 0..c.n {
        let health = match c.health[m] {
            0 => Health::Healthy,
            1 => Health::Degraded,
            _ => Health::Unhealthy,
        };
        a.set_health(NAMES[m], health).unwrap();
    }
    let mut mask = 0u32;
    for m in 0..c.n {
        let expected = expected_availability(c, m);
        assert_eq!(a.effective_health(NAMES[m]), Some(expected));
        let available = expected.usable();
        assert_eq!(a.availability(CAPS[m]) == Availability::Ready || a.availability(CAPS[m]) == Availability::Degraded, available);
        if available {
            mask |= 1 << declared.capabilities().iter().position(|cap| *cap == CAPS[m]).unwrap();
        }
    }
    assert_eq!(a.published_mask(&declared), mask);
    assert_eq!(a.audit(&declared, mask), Ok(()));
    if mask != (1u32 << c.n) - 1 {
        assert!(a.audit(&declared, (1u32 << c.n) - 1).is_err());
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn health_and_transitive_availability_match_reference(c in health_case_strategy()) {
        check_health_case(&c);
    }
}

// ---- Loom：内核发布协议模型 ------------------------------------------------------

/// 模型对应 kernel::assembly：激活函数建立服务状态（这里以 Relaxed 写入的容量字代表），
/// 装配完成后以 Release 写发布掩码；任意核以 Acquire 读掩码，读到位为 1 时必须看见激活建立的状态；
/// 装配前读到 0 ⇒ 不可用。
#[test]
fn publication_protocol_loom() {
    use loom::sync::atomic::{AtomicU32, Ordering};
    use loom::sync::Arc;
    loom::model(|| {
        let published = Arc::new(AtomicU32::new(1));
        let state = Arc::new(AtomicU32::new(0));
        let stopped = Arc::new(loom::sync::atomic::AtomicBool::new(false));
        let writer = {
            let published = published.clone();
            let state = state.clone();
            let stopped = stopped.clone();
            loom::thread::spawn(move || {
                loop {
                    let initial = state.load(Ordering::SeqCst);
                    let writer = (initial ^ (1 << 30)) | (1 << 31);
                    if state.compare_exchange(initial, writer, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
                        break;
                    }
                    loom::thread::yield_now();
                }
                published.fetch_and(!1, Ordering::SeqCst);
                while state.load(Ordering::SeqCst) & ((1 << 30) - 1) != 0 {
                    loom::thread::yield_now();
                }
                state.fetch_and(!(1 << 31), Ordering::SeqCst);
                stopped.store(true, Ordering::SeqCst);
            })
        };
        let mut readers_out = Vec::new();
        for _ in 0..1 {
            let published = published.clone();
            let state = state.clone();
            let stopped = stopped.clone();
            readers_out.push(loom::thread::spawn(move || {
                let current = state.load(Ordering::SeqCst);
                if current & (1 << 31) != 0 {
                    return 0;
                }
                if state.compare_exchange(current, current + 1, Ordering::SeqCst, Ordering::SeqCst).is_err() {
                    return 0;
                }
                if published.load(Ordering::SeqCst) & 1 == 0 {
                    state.fetch_sub(1, Ordering::SeqCst);
                    return 0;
                }
                assert!(!stopped.load(Ordering::SeqCst), "stop completed with an active reader");
                state.fetch_sub(1, Ordering::SeqCst);
                1
            }));
        }
        writer.join().unwrap();
        for reader in readers_out {
            let _ = reader.join().unwrap();
        }
        assert!(stopped.load(Ordering::SeqCst));
        assert_eq!(published.load(Ordering::SeqCst) & 1, 0);
        let final_state = state.load(Ordering::SeqCst);
        assert_eq!(final_state & ((1 << 30) - 1), 0, "final state={final_state:#x}");
    });
}
