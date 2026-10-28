#![no_main]
//! issue #6 第一片：服务装配契约与参照语义的差分（启动顺序为拓扑序、就绪 ⇔ 自身成功 ∧ 依赖全部就绪、
//! 发布掩码通过审计且任意偏离被拒、全有全无失败时不发布、重复启动被拒）。
use std::sync::atomic::{AtomicU8, Ordering};

use kernel_core::assembly::{mask_has, Assembly, AssemblyError, Binding, Policy, State};
use kernel_core::config::KernelConfig;
use kernel_core::profile::{self, ModuleDecl, SchedClass, SystemProfile};

static NAMES: [&str; 6] = ["m0", "m1", "m2", "m3", "m4", "m5"];
static CAPS: [&str; 6] = ["p.m0", "p.m1", "p.m2", "p.m3", "p.m4", "p.m5"];
/// 第 k 位 = 模块 k 激活成功。
static OK: AtomicU8 = AtomicU8::new(0);

fn act(k: usize) -> Result<(), &'static str> {
    if OK.load(Ordering::Relaxed) & (1 << k) != 0 { Ok(()) } else { Err("planned") }
}
fn a0() -> Result<(), &'static str> { act(0) }
fn a1() -> Result<(), &'static str> { act(1) }
fn a2() -> Result<(), &'static str> { act(2) }
fn a3() -> Result<(), &'static str> { act(3) }
fn a4() -> Result<(), &'static str> { act(4) }
fn a5() -> Result<(), &'static str> { act(5) }
const ACTS: [fn() -> Result<(), &'static str>; 6] = [a0, a1, a2, a3, a4, a5];

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if data.len() < 9 {
        return;
    }
    let n = 1 + data[0] as usize % 6;
    OK.store(data[1], Ordering::Relaxed);
    let all_or_nothing = data[2] & 1 != 0;
    // 声明顺序：按 data[3..] 旋转。
    let rot = data[3] as usize % n;
    let deps: Vec<Vec<usize>> = (0..n).map(|k| (0..k).filter(|d| data[4 + k % 5] & (1 << d) != 0).collect()).collect();
    // 装配要求 `&'static`：数据由本函数拥有，经裸指针延长生命期，`check` 返回（装配已销毁）后再释放，
    // 这样每个输入都不泄漏（LeakSanitizer 开启）。
    let reqs: Vec<Box<[&'static str]>> = deps.iter().map(|d| d.iter().map(|&x| CAPS[x]).collect()).collect();
    let modules: Box<[ModuleDecl]> = (0..n)
        .map(|i| (i + rot) % n)
        .map(|k| ModuleDecl {
            name: NAMES[k],
            provides: std::slice::from_ref(&CAPS[k]),
            // SAFETY：reqs 活到本函数末尾，晚于一切对它的引用（check 内的装配）。
            requires: unsafe { &*(&*reqs[k] as *const [&'static str]) },
            services: &[],
            hot_load: false,
            sched_class: SchedClass::Interactive,
            min_tasks: 0,
            min_objects: 0,
        })
        .collect();
    let prof = Box::new(SystemProfile {
        name: "fuzz",
        display_zh: "f",
        display_en: "f",
        config: KernelConfig::STANDARD,
        // SAFETY：同上，modules 晚于 prof 的使用者释放。
        modules: unsafe { &*(&*modules as *const [ModuleDecl]) },
        guarantees: &[],
        hot_load: false,
    });
    // SAFETY：同上，prof 在 check 返回后才释放。
    let p: &'static SystemProfile = unsafe { &*(&*prof as *const SystemProfile) };
    check(p, data, n, all_or_nothing, &deps);
    drop(prof);
    drop(modules);
    drop(reqs);
});

fn check(p: &'static SystemProfile, data: &[u8], n: usize, all_or_nothing: bool, deps: &[Vec<usize>]) {
    let binds: Vec<Binding> = (0..n).map(|k| Binding { module: NAMES[k], activate: ACTS[k], deactivate: None }).collect();
    let declared = profile::resolve(p).unwrap();
    let mut a = Assembly::new(p, &binds).unwrap();
    let order: Vec<usize> = (0..n).map(|k| NAMES.iter().position(|x| *x == a.order(k).unwrap()).unwrap()).collect();
    for m in 0..n {
        for &d in &deps[m] {
            assert!(order.iter().position(|&x| x == d) < order.iter().position(|&x| x == m));
        }
    }
    let policy = if all_or_nothing { Policy::AllOrNothing } else { Policy::Partial };
    let r = a.start(policy).unwrap();
    let ok = |k: usize| data[1] & (1 << k) != 0;
    let mut ready = [false; 6];
    let any_attempted_fail = {
        let mut f = false;
        for &m in &order {
            if deps[m].iter().all(|&d| ready[d]) {
                if ok(m) { ready[m] = true } else { f = true; if all_or_nothing { break } }
            }
        }
        f
    };
    if all_or_nothing && any_attempted_fail {
        ready = [false; 6];
    }
    let mask = a.published_mask(&declared);
    for m in 0..n {
        assert_eq!(a.state(NAMES[m]).unwrap().0 == State::Ready, ready[m]);
        assert_eq!(mask_has(&declared, mask, CAPS[m]), ready[m]);
    }
    assert_eq!(r.ready as usize, ready.iter().filter(|x| **x).count());
    assert!(a.audit(&declared, mask).is_ok());
    let flip = u32::from(data[8]) & ((1u32 << n) - 1);
    if flip != 0 {
        assert!(a.audit(&declared, mask ^ flip).is_err());
    }
    assert_eq!(a.start(policy), Err(AssemblyError::AlreadyStarted));
}
