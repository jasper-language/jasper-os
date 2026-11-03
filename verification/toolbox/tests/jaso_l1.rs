//! `.jaso` L1 的属性测试（Proptest）：
//! * 任意操作序列下模块表保持「运行中模块的依赖都在运行中」，`stop` 被拒当且仅当存在运行中的依赖者，卸载请求从不改变状态；
//! * 合法绑定（打乱顺序、加注释）被接受；删去任一 `fn`、增加未声明的 `fn`、超出清单的 `cap`、任一语法破坏都被拒；任意文本不 panic。
use jaso::binding::check;
use jaso::lifecycle::{ModuleId, Phase, Registry, StopError, UnloadReply};
use jaso::Manifest;
use proptest::prelude::*;

#[derive(Debug, Clone)]
enum Op {
    /// 装入模块 `m<i>`，依赖 `depends` 所列模块（只取编号小于 i 的）。
    Load(usize, Vec<usize>, bool),
    Stop(usize),
    Unload(usize),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (0usize..6, proptest::collection::vec(0usize..6, 0..3), any::<bool>()).prop_map(|(i, d, s)| Op::Load(i, d, s)),
        (0usize..8).prop_map(Op::Stop),
        (0usize..8).prop_map(Op::Unload),
    ]
}

fn manifest_text(i: usize, deps: &[usize], system: bool) -> String {
    let mut m = format!("core.name = m{i}\ncore.version = 1.0.0\ncore.abi = c.v1\ncore.stage = runtime\n");
    if system {
        m.push_str("core.lifecycle = system\n");
    }
    let mut d: Vec<usize> = deps.iter().copied().filter(|x| *x != i).collect();
    d.sort_unstable();
    d.dedup();
    if !d.is_empty() {
        let names: Vec<String> = d.iter().map(|x| format!("m{x}")).collect();
        m.push_str(&format!("core.depends = {}\n", names.join(", ")));
    }
    m
}

/// 参考模型：(名字编号, 依赖, 运行中, 系统模块)。
type Model = Vec<(usize, Vec<usize>, bool, bool)>;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn registry_matches_the_model(ops in proptest::collection::vec(op(), 1..40)) {
        let mut r = Registry::new();
        let mut model: Model = Vec::new();
        for o in ops {
            match o {
                Op::Load(i, deps, system) => {
                    let text = manifest_text(i, &deps, system);
                    let m = Manifest::parse(&text).unwrap();
                    let all_running = m.depends().all(|d| r.satisfies(&d));
                    let want = m.depends().all(|d| model.iter().any(|e| format!("m{}", e.0) == d.name && e.2));
                    prop_assert_eq!(all_running, want);
                    if want && !r.contains(m.name) {
                        let id = r.insert(&m);
                        prop_assert_eq!(id.0, model.len());
                        model.push((i, m.depends().map(|d| d.name[1..].parse().unwrap()).collect(), true, system));
                    }
                }
                Op::Stop(k) => {
                    let got = r.begin_stop(ModuleId(k));
                    match model.get(k).cloned() {
                        None => prop_assert_eq!(got, Err(StopError::UnknownModule)),
                        Some((_, _, false, _)) => prop_assert_eq!(got, Err(StopError::AlreadyStopped)),
                        Some((name, _, true, _)) => {
                            let dependent = model.iter().find(|e| e.2 && e.1.contains(&name));
                            match dependent {
                                Some(e) => prop_assert_eq!(got, Err(StopError::Dependent(format!("m{}", e.0)))),
                                None => {
                                    prop_assert_eq!(got, Ok(()));
                                    model[k].2 = false;
                                }
                            }
                        }
                    }
                }
                Op::Unload(k) => {
                    let want = model.get(k).map(|e| if e.3 { UnloadReply::Refused } else { UnloadReply::Deferred });
                    prop_assert_eq!(r.unload_request(ModuleId(k)), want);
                }
            }
            prop_assert!(r.dependencies_hold());
            prop_assert_eq!(r.len(), model.len());
            for (k, e) in model.iter().enumerate() {
                prop_assert_eq!(r.phase(ModuleId(k)), Some(if e.2 { Phase::Running } else { Phase::Stopped }));
            }
        }
    }

    #[test]
    fn valid_bindings_accepted_and_breaking_them_rejected(
        n in 1usize..6, seed in any::<u64>(), drop_at in any::<prop::sample::Index>(), bad_ty in "[*&#(]{1}",
    ) {
        let names: Vec<String> = (0..n).map(|i| format!("f{i}")).collect();
        let m_text = format!("core.name = m\ncore.version = 1.0.0\ncore.abi = c.v1\ncore.stage = runtime\ncore.requires = log\ncore.exports = jaso_init, {}\n", names.join(", "));
        let m = Manifest::parse(&m_text).unwrap();
        // 确定性打乱
        let mut lines: Vec<String> = names.iter().map(|f| format!("fn {f}(a: own List<Int?>, b: borrow x.Y?): Unit")).collect();
        lines.rotate_left((seed as usize) % n);
        let good = format!("package p.q\n# c\ncap log\n{}\n", lines.join("\n"));
        prop_assert_eq!(check(good.as_bytes(), &m), Ok(()));
        let k = drop_at.index(n);
        let mut missing = lines.clone();
        missing.remove(k);
        prop_assert!(check(missing.join("\n").as_bytes(), &m).is_err());
        let extra = format!("{good}fn extra(): Unit\n");
        prop_assert!(check(extra.as_bytes(), &m).is_err());
        let more_caps = format!("{good}cap net\n");
        prop_assert!(check(more_caps.as_bytes(), &m).is_err());
        let mut broken = lines.clone();
        broken[k] = format!("fn f{k}(a: {bad_ty}Int): Unit");
        prop_assert!(check(broken.join("\n").as_bytes(), &m).is_err());
    }

    #[test]
    fn arbitrary_text_never_panics(s in "[ -~\\n]{0,200}", b in proptest::collection::vec(any::<u8>(), 0..200)) {
        let m = Manifest::parse("core.name = m\ncore.version = 1.0.0\ncore.abi = c.v1\ncore.stage = runtime\ncore.exports = f\n").unwrap();
        let _ = check(s.as_bytes(), &m);
        let _ = check(&b, &m);
    }
}
