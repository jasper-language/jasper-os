//! `jasper.import` 判定（SPEC §9.4）与 L1 模块表（SPEC §12.2）的宿主测试。

extern crate std;

use crate::binding::{check, BindingError, MAX_BINDING_BYTES, MAX_BINDING_LINES};
use crate::lifecycle::{ModuleId, Phase, Registry, StopError, UnloadReply};
use crate::{ErrorCode, Manifest};

const MANIFEST: &str = "core.name = jaso-m\ncore.version = 1.2.3\ncore.abi = c.v1\ncore.stage = runtime\n\
                        core.requires = log, alloc\ncore.exports = jaso_init, jaso_start, jaso_stop, f_one, f.two$x\n";

fn manifest() -> Manifest<'static> {
    Manifest::parse(MANIFEST).unwrap()
}

const FULL: &str = "fn f_one(): Unit\nfn f.two$x(): Unit\n";

fn run(text: &str) -> Result<(), BindingError> {
    check(text.as_bytes(), &manifest())
}

#[test]
fn binding_accepts_the_grammar() {
    run(FULL).unwrap();
    // 顺序无关、注释与空行、两端空白、CRLF
    run("  # c\r\n\r\n  fn f.two$x(): Unit  \r\nfn f_one(): Unit\r\n").unwrap();
    run("package a.b_c.D\ntype Buf\ntype Other\ncap log\ncap alloc\nfn f_one(a: Int, b : own Buf?, c: borrow a.b.C<Int, own List<Str?>?>) : own Map<K,V>?\nfn f.two$x( ): Unit\n").unwrap();
    // 嵌套到上限为止
    run("fn f_one(): A<A<A<A<A<A<A<A<B>>>>>>>>\nfn f.two$x(): Unit").unwrap();
}

#[test]
fn binding_rejects_bad_syntax() {
    for line in [
        "fn",
        "fn f_one",
        "fn f_one()",
        "fn f_one():",
        "fn f_one(): ",
        "fn f_one(a): Unit",
        "fn f_one(a:): Unit",
        "fn f_one(a: Int,): Unit",
        "fn f_one(: Int): Unit",
        "fn f_one(a: *u8): Unit",
        "fn f_one(a: &u8): Unit",
        "fn f_one(): Unit trailing",
        "fn f_one(): Unit?? ",
        "fn f_one(): A<>",
        "fn f_one(): A<B",
        "fn f_one(): A.",
        "fn f_one(): 1A",
        "fn f_one(): 类型",
        "fn f_one(): A<A<A<A<A<A<A<A<A<B>>>>>>>>>",
        "fn (): Unit",
        "fn f one(): Unit",
        "package",
        "package a..b",
        "package a b",
        "type",
        "type a.b",
        "cap",
        "cap a b",
        "unknown thing",
        "fn\tf_one(): Unit",
    ] {
        let text = std::format!("{line}\n{FULL}");
        assert_eq!(run(&text), Err(BindingError::BadLine(1)), "{line}");
    }
}

#[test]
fn binding_must_agree_with_the_manifest() {
    assert_eq!(run("fn f_one(): Unit"), Err(BindingError::MissingFunction));
    assert_eq!(run(""), Err(BindingError::MissingFunction));
    assert_eq!(run(&std::format!("{FULL}fn f_three(): Unit")), Err(BindingError::UndeclaredFunction(3)));
    for l in ["jaso_init", "jaso_start", "jaso_stop"] {
        assert_eq!(run(&std::format!("{FULL}fn {l}(): Unit")), Err(BindingError::UndeclaredFunction(3)));
    }
    assert_eq!(run(&std::format!("{FULL}fn f_one(x: Int): Unit")), Err(BindingError::Duplicate(3)));
    assert_eq!(run(&std::format!("{FULL}cap net")), Err(BindingError::Capability(3)));
    assert_eq!(run(&std::format!("cap log\ncap log\n{FULL}")), Err(BindingError::Duplicate(2)));
    assert_eq!(run(&std::format!("type T\ntype T\n{FULL}")), Err(BindingError::Duplicate(2)));
    assert_eq!(run(&std::format!("package a\npackage b\n{FULL}")), Err(BindingError::Duplicate(2)));
    assert_eq!(check(b"\xFF", &manifest()), Err(BindingError::NotUtf8));
    // 没有导出的模块（除生命周期之外）可以只声明包
    let lifecycle_only = Manifest::parse("core.name = m\ncore.version = 1.0.0\ncore.abi = c.v1\ncore.stage = runtime\ncore.exports = jaso_init\n").unwrap();
    check(b"package a", &lifecycle_only).unwrap();
    assert_eq!(BindingError::MissingFunction.code(), ErrorCode::ExtensionBinding);
    assert!(ErrorCode::ExtensionBinding.is_load());
}

#[test]
fn binding_limits() {
    let big = std::format!("{FULL}{}", "#".repeat(MAX_BINDING_BYTES));
    assert_eq!(run(&big), Err(BindingError::TooLong));
    let mut many = std::string::String::from(FULL);
    for i in 0..MAX_BINDING_LINES {
        many.push_str(&std::format!("type T{i}\n"));
    }
    assert_eq!(run(&many), Err(BindingError::TooLong));
}

fn module(name: &str, version: &str, extra: &str) -> std::string::String {
    std::format!("core.name = {name}\ncore.version = {version}\ncore.abi = c.v1\ncore.stage = runtime\n{extra}")
}

fn insert(r: &mut Registry, text: &str) -> Result<ModuleId, &'static str> {
    let m = Manifest::parse(text).unwrap();
    if r.contains(m.name) {
        return Err("taken");
    }
    if m.depends().any(|d| !r.satisfies(&d)) {
        return Err("unsatisfied");
    }
    Ok(r.insert(&m))
}

#[test]
fn dependencies_are_satisfied_only_by_running_modules_in_range() {
    let mut r = Registry::new();
    assert!(r.is_empty());
    let dep = module("user", "1.0.0", "core.depends = base@>=1.0,<2.0\n");
    assert_eq!(insert(&mut r, &dep), Err("unsatisfied"));
    let old = module("base", "0.9.0", "");
    let base = insert(&mut r, &old).unwrap();
    assert_eq!(insert(&mut r, &dep), Err("unsatisfied"), "版本不在区间内");
    assert_eq!(insert(&mut r, &old), Err("taken"));
    r.begin_stop(base).unwrap();
    let any = module("any", "1.0.0", "core.depends = base\n");
    assert_eq!(insert(&mut r, &any), Err("unsatisfied"), "已停止的模块不算满足");

    let mut r = Registry::new();
    let base = insert(&mut r, &module("base", "1.5.0", "")).unwrap();
    let user = insert(&mut r, &dep).unwrap();
    assert_eq!(r.len(), 2);
    assert!(r.dependencies_hold());
    assert_eq!(r.begin_stop(base), Err(StopError::Dependent("user".into())));
    assert_eq!(r.phase(base), Some(Phase::Running));
    assert_eq!(r.begin_stop(user), Ok(()));
    assert_eq!(r.begin_stop(user), Err(StopError::AlreadyStopped));
    assert_eq!(r.begin_stop(base), Ok(()));
    assert!(r.dependencies_hold());
    assert_eq!(r.begin_stop(ModuleId(9)), Err(StopError::UnknownModule));
    assert_eq!(r.phase(ModuleId(9)), None);
}

#[test]
fn unload_is_never_reported_as_done() {
    let mut r = Registry::new();
    let p = insert(&mut r, &module("p", "1.0.0", "core.lifecycle = plugin\n")).unwrap();
    let s = insert(&mut r, &module("s", "1.0.0", "core.lifecycle = system\n")).unwrap();
    let d = insert(&mut r, &module("d", "1.0.0", "")).unwrap();
    assert_eq!(r.unload_request(p), Some(UnloadReply::Deferred));
    assert_eq!(r.unload_request(s), Some(UnloadReply::Refused));
    assert_eq!(r.unload_request(d), Some(UnloadReply::Deferred), "缺省是 plugin");
    assert_eq!(r.unload_request(ModuleId(9)), None);
    // 答复不改变任何状态
    assert_eq!((r.len(), r.phase(p), r.phase(s)), (3, Some(Phase::Running), Some(Phase::Running)));
    r.begin_stop(p).unwrap();
    assert_eq!(r.unload_request(p), Some(UnloadReply::Deferred), "停止之后同样只推迟");
    assert!(r.contains("p"));
}

#[cfg(feature = "pack")]
mod kernel_gate {
    use super::*;
    use crate::build::Builder;
    use crate::kernel_gate::{admit_kernel, KernelLoadError, KernelPhase};
    use crate::trust::{Publisher, TrustError, TrustMode, TrustPolicy, DEVELOPMENT_NAMESPACE, DEVELOPMENT_PUBLISHER};
    use crate::{Arch, Stage};

    fn file(stage: Stage, signer: Option<&crate::build::Signer>) -> std::vec::Vec<u8> {
        let text = std::format!("core.name = jaso-k\ncore.version = 1.0.0\ncore.abi = c.v1\ncore.stage = {}\ncore.publisher = jasper.dev\n", stage.name());
        let mut b = Builder::native(Arch::X86_64, stage, text.as_bytes());
        b.segments = std::vec![crate::build::SegmentIn { vaddr: 0, mem_size: 16, flags: crate::FLAG_R | crate::FLAG_X, data: std::vec![0x90; 16] }];
        match signer {
            Some(s) => b.finish_signed(s).unwrap(),
            None => b.finish().unwrap(),
        }
    }

    #[test]
    fn only_allow_listed_build_or_boot_files_outside_run_time() {
        let dev = crate::pack::development_signer();
        let table = [Publisher { name: DEVELOPMENT_PUBLISHER, namespace: DEVELOPMENT_NAMESPACE, key: dev.public_key() }];
        let enforce = TrustPolicy::new(&table, TrustMode::Enforce).unwrap();
        let (boot, build, runtime) = (file(Stage::Boot, Some(&dev)), file(Stage::Build, Some(&dev)), file(Stage::Runtime, Some(&dev)));
        assert!(admit_kernel(&boot, &enforce, KernelPhase::Boot).is_ok());
        assert!(admit_kernel(&build, &enforce, KernelPhase::Build).is_ok());
        // 运行期：连文件都不读
        assert_eq!(admit_kernel(&boot, &enforce, KernelPhase::Running).err(), Some(KernelLoadError::RuntimeLoad));
        assert_eq!(admit_kernel(b"garbage", &enforce, KernelPhase::Running).err(), Some(KernelLoadError::RuntimeLoad));
        // 阶段不符
        assert_eq!(admit_kernel(&runtime, &enforce, KernelPhase::Boot).err(), Some(KernelLoadError::Stage(Stage::Runtime)));
        assert_eq!(admit_kernel(&boot, &enforce, KernelPhase::Build).err(), Some(KernelLoadError::Stage(Stage::Boot)));
        // 未签名、白名单外、开发模式、坏文件
        let unsigned = file(Stage::Boot, None);
        assert_eq!(admit_kernel(&unsigned, &enforce, KernelPhase::Boot).err(), Some(KernelLoadError::Untrusted(TrustError::Unsigned)));
        let other = crate::pack::signer_from_phrase(b"other");
        let foreign = file(Stage::Boot, Some(&other));
        assert_eq!(admit_kernel(&foreign, &enforce, KernelPhase::Boot).err(), Some(KernelLoadError::Untrusted(TrustError::KeyMismatch)));
        let dev_mode = TrustPolicy::new(&table, TrustMode::Development).unwrap();
        assert_eq!(admit_kernel(&boot, &dev_mode, KernelPhase::Boot).err(), Some(KernelLoadError::DevelopmentPolicy));
        assert!(matches!(admit_kernel(b"garbage", &enforce, KernelPhase::Boot), Err(KernelLoadError::Format(_))));
    }
}
