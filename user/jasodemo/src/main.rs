//! user-jasodemo：`.jaso` 模块装载器的验收程序。
//! Acceptance program for the `.jaso` loader.
//!
//! 逐步检查（失败以步骤编号退出）：
//! 1. 装入合格模块：初始化经宿主接口表输出一行；调用各导出（读调用者内存、重定位过的只读指针表、可写数据、经宿主分配）
//! 2. 导出地址落在映像内；对代码页请求「可写 + 可执行」被内核拒绝（W^X）
//! 3. 同一模块装入两个实例：基址不同、可写数据各自独立
//! 4. 卸载：映射消失、槽位可复用、重新装入后状态从头开始
//! 5. 拒绝：篡改任一字节、截断、指令集不符、装载阶段不符、能力未授予、缺宿主接口表、缺初始化入口；
//!    format 1 的装载步骤：宿主运行时版本不在 `core.runtime` 内、依赖未满足、旧调用约定 `c.v0`（平台不符）
//! 6. 来源（发布者签名）：签名模块按受信发布者装入；未签名、篡改后重算完整性摘要（签名失效）、换发布者、
//!    他人重签、他人重签并改称自己、发布者不在表中——全部在映射之前被拒且不留映射；
//!    开发模式放行未签名模块并留下审计事件，但坏签名照样被拒
//! 7. L1 全流程（[`jasper_rt::loader`]）：运行时装入签名的 Native 与 Hybrid 模块并调用导出、依赖、服务发现；
//!    篡改、错误平台、缺能力、缺依赖、绑定不一致、启动失败都被拒且无残留；`stop` 与卸载答复（推迟 / 拒绝）；
//!    内核态准入门：运行期请求一律拒绝，启动期只接受白名单签名的 boot 阶段文件
#![no_std]
#![no_main]

extern crate alloc;

use alloc::alloc::{alloc, dealloc, Layout};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use jasper_rt::module::{
    unsigned_admitted, Grant, HostV1, LoadError, Module, Origin, Publisher, Standard, TrustError, TrustMode, TrustPolicy, DEVELOPMENT_NAMESPACE,
    DEVELOPMENT_PUBLISHER,
};
use jasper_rt::loader::{Loader, Phase, StopError, UnloadReply};
use jasper_rt::isolate::{IsolatedGrant, IsolatedModule};
use jasper_rt::{entry, io, mem, println, Error};

entry!(main);

static DEMO: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/demo.jaso"));
static MULTI: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/demo-multi.jaso"));
static CONTAINER: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/modbox.elf"));
static DEMO_OTHER_ARCH: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/demo-otherarch.jaso"));
static DEMO_BOOT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/demo-boot.jaso"));
static DEMO_NOINIT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/demo-noinit.jaso"));
static DEMO_MORECAPS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/demo-morecaps.jaso"));
static DEMO_RUNTIME: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/demo-runtime.jaso"));
static DEMO_DEPENDS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/demo-depends.jaso"));
static DEMO_OLDABI: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/demo-oldabi.jaso"));
static DEMO_UNSIGNED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/demo-unsigned.jaso"));
static DEMO_OTHERPUB: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/demo-otherpub.jaso"));
static DEMO_RESIGNED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/demo-resigned.jaso"));
static DEMO_CLAIMED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/demo-claimed.jaso"));

static L1_NATIVE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/l1-native.jaso"));
static L1_HYBRID: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/l1-hybrid.jaso"));
static L1_STARTFAIL: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/l1-native-startfail.jaso"));
static L1_OTHERARCH: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/l1-hybrid-otherarch.jaso"));
static L1_MORECAPS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/l1-hybrid-morecaps.jaso"));
static L1_RANGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/l1-hybrid-range.jaso"));
static L1_BIND_MISSING: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/l1-hybrid-bind-missing.jaso"));
static L1_BIND_EXTRA: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/l1-hybrid-bind-extra.jaso"));
static L1_BIND_CAP: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/l1-hybrid-bind-cap.jaso"));
static L1_BIND_RAW: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/l1-hybrid-bind-raw.jaso"));

/// 另一个受信发布者（验收用）：命名空间 `other-`，管不到 `jaso-demo`。
const OTHER_PUBLISHER: Publisher<'static> =
    Publisher { name: "jasper.other", namespace: "other-", key: *include_bytes!(concat!(env!("OUT_DIR"), "/trust-other.key")) };
/// 开发用发布者。
const DEV_PUBLISHER: Publisher<'static> =
    Publisher { name: DEVELOPMENT_PUBLISHER, namespace: DEVELOPMENT_NAMESPACE, key: *include_bytes!(concat!(env!("OUT_DIR"), "/trust-dev.key")) };
/// 受信发布者表：开发用发布者 + 另一个发布者。
static PUBLISHERS: [Publisher<'static>; 2] = [DEV_PUBLISHER, OTHER_PUBLISHER];
/// 只有另一个发布者的表（开发用发布者不受信）。
static OTHER_ONLY: [Publisher<'static>; 1] = [OTHER_PUBLISHER];

static ALLOCS: AtomicU32 = AtomicU32::new(0);
static FREES: AtomicU32 = AtomicU32::new(0);
/// 模块经宿主接口表报告 `jaso_stop` 被调用的次数。
static STOP_HOOKS: AtomicU32 = AtomicU32::new(0);

extern "C" fn host_log(ptr: *const u8, len: usize) {
    // SAFETY：模块按约定传入一段有效的 UTF-8 文本。
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
    if let Ok(s) = core::str::from_utf8(bytes) {
        if s == "jaso-l1: stopped" {
            STOP_HOOKS.fetch_add(1, Ordering::Relaxed);
        }
        let _ = io::write_str(s);
    }
}

extern "C" fn host_alloc(size: usize, align: usize) -> *mut u8 {
    match Layout::from_size_align(size.max(1), align) {
        Ok(l) => {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
            // SAFETY：布局合法且大小非零。
            unsafe { alloc(l) }
        }
        Err(_) => core::ptr::null_mut(),
    }
}

extern "C" fn host_dealloc(ptr: *mut u8, size: usize, align: usize) {
    if let Ok(l) = Layout::from_size_align(size.max(1), align) {
        FREES.fetch_add(1, Ordering::Relaxed);
        // SAFETY：模块按约定以分配时的参数归还。
        unsafe { dealloc(ptr, l) }
    }
}

/// 本程序提供给模块的宿主接口表。
static HOST: HostV1 = HostV1 {
    version: jasper_rt::module::HOST_TABLE_VERSION,
    size: core::mem::size_of::<HostV1>() as u32,
    log: host_log,
    alloc: host_alloc,
    dealloc: host_dealloc,
};

const CAPS: &[&str] = &["system.console.write"];

fn grant<'a>(trust: &'a TrustPolicy<'a>) -> Grant<'a> {
    Grant { capabilities: CAPS, host: Some(&HOST), trust, origin: Origin::Local, placement: &Standard }
}

struct Steps(u32);

impl Steps {
    fn check(&mut self, ok: bool) -> Result<(), u32> {
        self.0 += 1;
        if ok {
            Ok(())
        } else {
            Err(self.0)
        }
    }
}

fn main(_: u64, _: u64) -> i32 {
    let mut s = Steps(0);
    match run(&mut s) {
        Ok(()) => {
            println!("jasodemo: ok checks={}", s.0);
            0
        }
        Err(step) => {
            println!("jasodemo: FAIL step={}", step);
            step as i32
        }
    }
}

type SumFn = unsafe extern "C" fn(*const u8, usize) -> u64;
type GreetFn = unsafe extern "C" fn(usize, *mut u8, usize) -> usize;
type CountFn = extern "C" fn() -> u64;
type AllocSumFn = extern "C" fn(usize) -> u64;

fn greeting(m: &Module, i: usize) -> Option<Vec<u8>> {
    // SAFETY：签名与模块中的 demo_greeting 一致。
    let f = unsafe { m.function::<GreetFn>("demo_greeting") }?;
    let mut buf = [0u8; 64];
    // SAFETY：buf 可写 64 字节。
    let n = unsafe { (f.get())(i, buf.as_mut_ptr(), buf.len()) };
    Some(buf[..n.min(64)].to_vec())
}

fn counter(m: &Module) -> u64 {
    // SAFETY：签名与模块中的 demo_counter 一致。
    unsafe { m.function::<CountFn>("demo_counter") }.map(|f| (f.get())()).unwrap_or(0)
}

fn run(s: &mut Steps) -> Result<(), u32> {
    let trust = TrustPolicy::new(&PUBLISHERS, TrustMode::Enforce).map_err(|_| 99u32)?;
    let t = &trust;
    // 1. 装入并调用
    let m = Module::load(DEMO, grant(t)).map_err(|_| 100 + s.0)?;
    s.check(m.name() == "jaso-demo" && m.version() == (0, 1, 0))?;
    let data: Vec<u8> = (0..1000u32).map(|i| (i % 256) as u8).collect();
    // SAFETY：签名与模块中的 demo_sum 一致；data 可读。
    let sum = unsafe { m.function::<SumFn>("demo_sum") }.map(|f| unsafe { (f.get())(data.as_ptr(), data.len()) });
    s.check(sum == Some(data.iter().map(|&b| b as u64).sum()))?;
    s.check(greeting(&m, 0).as_deref() == Some("你好，来自 .jaso 模块".as_bytes()))?; // 只读指针表经重定位
    s.check(greeting(&m, 1).as_deref() == Some(&b"hello from a .jaso module"[..]))?;
    s.check(counter(&m) == 1 && counter(&m) == 2)?; // 可写数据
    let (a0, f0) = (ALLOCS.load(Ordering::Relaxed), FREES.load(Ordering::Relaxed));
    // SAFETY：签名与模块中的 demo_alloc_sum 一致。
    let asum = unsafe { m.function::<AllocSumFn>("demo_alloc_sum") }.map(|f| (f.get())(10_000));
    let want: u64 = (0..10_000u64).map(|i| i % 251).sum();
    s.check(asum == Some(want))?;
    s.check(ALLOCS.load(Ordering::Relaxed) == a0 + 1 && FREES.load(Ordering::Relaxed) == f0 + 1)?; // 经宿主分配且归还
    s.check(m.symbol("no_such_symbol").is_none())?;
    // SAFETY：类型大小不是指针大小时必须拒绝（不发生转换）。
    s.check(unsafe { m.function::<u8>("demo_sum") }.is_none())?;

    // 2. 导出地址落在映像内；对代码页请求「可写 + 可执行」被内核拒绝（W^X）
    let text = m.symbol("demo_sum").unwrap_or(0) & !0xFFF;
    s.check(text >= m.base() && text < m.base() + m.pages() * 4096)?;
    s.check(mem::protect(text, 1, mem::WRITE | mem::EXEC) == Err(Error::INVALID_ARGUMENT))?;
    println!("jasodemo: loaded name={} base={:#x} pages={} sum_ok=true relocated_greeting=true counter=2 host_alloc=1/1", m.name(), m.base(), m.pages());

    // 3. 第二个实例：基址不同、数据独立
    let m2 = Module::load(DEMO, grant(t)).map_err(|_| 100 + s.0)?;
    s.check(m2.base() != m.base())?;
    s.check(counter(&m2) == 1 && counter(&m) == 3)?;
    println!("jasodemo: two_instances bases={:#x},{:#x} independent_data=true", m.base(), m2.base());

    // 4. 卸载：映射消失；槽位可复用；重新装入后从头开始
    let (base, pages) = (m.base(), m.pages());
    drop(m);
    s.check(mem::unmap(base, 1) == Err(Error::MEMORY_INVALID_ADDRESS))?;
    s.check(mem::map(base, pages, mem::WRITE).is_ok() && mem::unmap(base, pages).is_ok())?; // 区间确已空出
    let m3 = Module::load(DEMO, grant(t)).map_err(|_| 100 + s.0)?;
    s.check(m3.base() == base && counter(&m3) == 1)?;
    drop(m2);
    drop(m3);
    println!("jasodemo: unload unmapped=true slot_reused=true fresh_state=true");
    multi_arch(s, t)?;

    // 5. 拒绝
    let mut tampered = DEMO.to_vec();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0x01;
    let r_tamper = Module::load(&tampered, grant(t)).err();
    s.check(r_tamper == Some(LoadError::Format(jaso_err::DigestMismatch)))?;
    let r_trunc = Module::load(&DEMO[..DEMO.len() - 1], grant(t)).err();
    s.check(r_trunc == Some(LoadError::Format(jaso_err::LengthMismatch)))?;
    let r_arch = Module::load(DEMO_OTHER_ARCH, grant(t)).err();
    s.check(matches!(r_arch, Some(LoadError::Platform(m)) if m.field == jaso::PlatformField::Isa))?;
    let r_stage = Module::load(DEMO_BOOT, grant(t)).err();
    s.check(matches!(r_stage, Some(LoadError::WrongStage(_))))?;
    let r_caps = Module::load(DEMO, Grant { capabilities: &[], host: Some(&HOST), trust: t, origin: Origin::Local, placement: &Standard }).err();
    s.check(matches!(&r_caps, Some(LoadError::MissingCapability(c)) if c == "system.console.write"))?;
    let r_more = Module::load(DEMO_MORECAPS, grant(t)).err();
    s.check(matches!(&r_more, Some(LoadError::MissingCapability(c)) if c == "system.channel.send"))?;
    s.check(Module::load(DEMO_MORECAPS, Grant { capabilities: &["system.console.write", "system.channel.send"], host: Some(&HOST), trust: t, origin: Origin::Local, placement: &Standard }).is_ok())?;
    let r_host = Module::load(DEMO, Grant { capabilities: CAPS, host: None, trust: t, origin: Origin::Local, placement: &Standard }).err();
    s.check(r_host == Some(LoadError::HostRequired))?;
    let r_init = Module::load(DEMO_NOINIT, grant(t)).err();
    s.check(r_init == Some(LoadError::MissingInit))?;
    let r_runtime = Module::load(DEMO_RUNTIME, grant(t)).err();
    s.check(r_runtime == Some(LoadError::RuntimeVersion))?;
    let r_depends = Module::load(DEMO_DEPENDS, grant(t)).err();
    s.check(matches!(&r_depends, Some(LoadError::Dependency(d)) if d == "jaso-base"))?;
    let r_oldabi = Module::load(DEMO_OLDABI, grant(t)).err();
    s.check(matches!(r_oldabi, Some(LoadError::Platform(m)) if m.field == jaso::PlatformField::Abi && m.actual.as_str() == "c.v0"))?;
    // 所有被拒的装载都没有留下映射：全部槽位空闲，第一个槽位可再次装入
    let again = Module::load(DEMO, grant(t)).map_err(|_| 100 + s.0)?;
    s.check(again.base() == base)?;
    println!(
        "jasodemo: rejected tamper={:?} truncated={:?} arch={:?} stage={:?} caps={:?} host={:?} init={:?}",
        r_tamper, r_trunc, r_arch, r_stage, r_caps, r_host, r_init
    );
    println!("jasodemo: format1 rejected runtime={:?} depends={:?} oldabi={:?}", r_runtime, r_depends, r_oldabi);
    drop(again);
    signatures(s, t, base)?;
    l1(s, t)
}

/// Four-ISA container acceptance shared by every architecture's QEMU boot.
fn multi_arch(s: &mut Steps, t: &TrustPolicy<'_>) -> Result<(), u32> {
    let file = jaso::Jaso::parse(MULTI).map_err(|_| 100 + s.0)?;
    let images = file.images().count();
    println!(
        "jasodemo: multi_begin images={} arch_any={} source={}",
        images,
        file.arch.is_none(),
        file.source_v1().is_some()
    );
    if images > 1 {
        s.check(images == 4 && file.arch.is_none())?;
        let host = jaso::HostPlatform::jasper_os_native().ok_or(100 + s.0)?;
        let selected = file.select(&host).map_err(|_| 100 + s.0)?;
        s.check(selected.platform.isa == host.isa)?;
        let source = file.source_v1().ok_or(100 + s.0)?;
        s.check(
            source.language() == jaso::source::LANGUAGE_JASPER
                && source.compression() == jaso::source::COMPRESSION_NONE,
        )?;
        let decoded = source.decode(|_, _| None).map_err(|_| 100 + s.0)?;
        s.check(decoded.as_bytes() == b"module jaso_demo\n")?;
    } else {
        s.check(images == 1)?;
    }

    let m = Module::load(MULTI, grant(t)).map_err(|_| 100 + s.0)?;
    s.check(m.name() == "jaso-demo")?;
    let data = b"multi-arch";
    // SAFETY: the C signature matches `demo_sum`; `data` is readable.
    let sum = unsafe { m.function::<SumFn>("demo_sum") }
        .map(|f| unsafe { (f.get())(data.as_ptr(), data.len()) });
    s.check(sum == Some(data.iter().map(|&byte| byte as u64).sum()))?;
    s.check(counter(&m) == 1)?;
    drop(m);
    println!("jasodemo: multi_in_process ok=true");

    let mut isolated = match IsolatedModule::spawn(
        MULTI,
        IsolatedGrant {
            container: CONTAINER,
            capabilities: CAPS,
            trust: t,
            handles: Vec::new(),
            cpu_limit_permille: None,
        },
    ) {
        Ok(module) => module,
        Err(error) => {
            println!("jasodemo: multi_isolated_fail={:?}", error);
            return Err(100 + s.0);
        }
    };
    println!("jasodemo: multi_isolated_name={}", isolated.name());
    s.check(isolated.name() == "jaso-demo")?;
    // SAFETY: `demo_counter` ignores the byte-protocol input pointers and only
    // increments module-local state. The container enforces the response bound.
    let first = match isolated.call("demo_counter", &[], 2) {
        Ok(value) => value,
        Err(error) => {
            println!("jasodemo: multi_isolated_first_fail={:?}", error);
            return Err(100 + s.0);
        }
    };
    let second = match isolated.call("demo_counter", &[], 2) {
        Ok(value) => value,
        Err(error) => {
            println!("jasodemo: multi_isolated_second_fail={:?}", error);
            return Err(100 + s.0);
        }
    };
    println!(
        "jasodemo: multi_isolated first={} second={}",
        first.value, second.value
    );
    s.check(first.value == 1 && second.value == 2)?;
    drop(isolated);

    let host = jaso::HostPlatform::jasper_os_native().ok_or(100 + s.0)?;
    let selected = file.select(&host).map_err(|_| 100 + s.0)?.platform.isa.map_or("any", |a| a.name());
    println!(
        "jasodemo: multi_arch images={} arch=any selected={} in_process=true isolated=true source_v1=true",
        file.images().count(),
        selected
    );
    Ok(())
}

/// 被拒装载的稳定错误码。
fn code(r: &Result<jasper_rt::loader::ModuleId, LoadError>) -> &'static str {
    match r {
        Ok(_) => "accepted",
        Err(e) => e.code().map_or("none", |c| c.name()),
    }
}

/// 把 `bytes` 中 `part` 这段内的一个字节翻转并重算完整性摘要：文件结构与完整性都合格，只有签名失效。
fn flipped(bytes: &[u8], part: &[u8]) -> Vec<u8> {
    let at = part.as_ptr() as usize - bytes.as_ptr() as usize + part.len() / 2;
    let mut t = bytes.to_vec();
    t[at] ^= 0x01;
    let d = jaso::digest_of(&t);
    t[jaso::DIGEST_OFFSET..jaso::DIGEST_OFFSET + 32].copy_from_slice(&d);
    t
}

type AddFn = extern "C" fn(u64, u64) -> u64;
type StateFn = extern "C" fn() -> u32;

/// 7. L1 全流程。
fn l1(s: &mut Steps, t: &TrustPolicy<'_>) -> Result<(), u32> {
    let mut l = Loader::new();
    // 运行时装入签名的 Native 模块：init → start，读清单发现服务，调用导出
    let native = l.load(L1_NATIVE, grant(t)).map_err(|_| 100 + s.0)?;
    let v = l.get(native).ok_or(100 + s.0)?;
    let services: Vec<&str> = v.services().collect();
    s.check(services == ["l1_add", "l1_fail", "l1_state"] && v.manifest_value("demo.service") == Some("adder"))?;
    // SAFETY：签名与模块中的 l1_add 一致。
    let add = unsafe { v.function::<AddFn>("l1_add") }.map(|f| (f.get())(40, 2));
    // SAFETY：签名与模块中的 l1_state 一致。
    let state = unsafe { v.function::<StateFn>("l1_state") }.map(|f| (f.get())());
    s.check(add == Some(42) && state == Some(1) && v.publisher() == Some(DEVELOPMENT_PUBLISHER))?;
    println!(
        "jasodemo: l1 native name={} publisher={} services={} service_key=adder add_ok=true state=1",
        v.name(),
        DEVELOPMENT_PUBLISHER,
        services.join(",")
    );
    let native_base = v.base();
    // 下一个空闲槽位：之后每批拒绝都检查它没有映射
    let free = Module::load(DEMO, grant(t)).map_err(|_| 100 + s.0)?.base();
    let no_residue = |l: &Loader, n: usize| mem::unmap(free, 1) == Err(Error::MEMORY_INVALID_ADDRESS) && l.len() == n;

    // 拒绝：篡改（摘要 / 代码 / 绑定字节）、错误平台、缺能力、缺依赖（版本不符）、阶段；全部不留映射、不进模块表
    let mut tampered = L1_HYBRID.to_vec();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0x01;
    let r_tamper = l.load(&tampered, grant(t));
    let f = jaso::Jaso::parse(L1_HYBRID).map_err(|_| 100 + s.0)?;
    let code_seg = f.image(0).and_then(|i| i.segments().find(|seg| seg.flags & jaso::FLAG_X != 0)).ok_or(100 + s.0)?;
    let r_badsig = l.load(&flipped(L1_HYBRID, code_seg.data), grant(t));
    let import = f.extension(jaso::EXT_JASPER_IMPORT, 1).ok_or(100 + s.0)?;
    let r_bindsig = l.load(&flipped(L1_HYBRID, import.content), grant(t));
    let r_platform = l.load(L1_OTHERARCH, grant(t));
    let r_caps = l.load(L1_MORECAPS, grant(t));
    let r_range = l.load(L1_RANGE, grant(t));
    let r_stage = l.load(DEMO_BOOT, grant(t)).err();
    s.check(code(&r_tamper) == "format.digest" && code(&r_badsig) == "signature.invalid" && code(&r_bindsig) == "signature.invalid")?;
    s.check(code(&r_platform) == "platform.mismatch" && code(&r_caps) == "capability.denied" && code(&r_range) == "dependency.unsatisfied")?;
    s.check(matches!(r_stage, Some(LoadError::WrongStage(_))) && no_residue(&l, 1))?;
    // 依赖缺失：另开一张空表，同一个 Hybrid 文件因依赖未装入被拒
    let mut empty = Loader::new();
    let r_deps = empty.load(L1_HYBRID, grant(t));
    s.check(matches!(&r_deps, Err(LoadError::Dependency(d)) if d == "jaso-l1-native") && no_residue(&empty, 0))?;
    drop(empty);
    println!(
        "jasodemo: l1 rejected tamper={} badsig={} bindsig={} platform={} caps={} deps={} range={} stage={:?} no_residue=true",
        code(&r_tamper),
        code(&r_badsig),
        code(&r_bindsig),
        code(&r_platform),
        code(&r_caps),
        code(&r_deps),
        code(&r_range),
        r_stage
    );

    // 绑定与清单不一致：语法、缺函数、多函数、能力超出清单
    let bind = |l: &mut Loader, b: &[u8]| matches!(l.load(b, grant(t)), Err(LoadError::Binding(_)));
    let (b_missing, b_extra, b_cap, b_raw) = (bind(&mut l, L1_BIND_MISSING), bind(&mut l, L1_BIND_EXTRA), bind(&mut l, L1_BIND_CAP), bind(&mut l, L1_BIND_RAW));
    s.check(b_missing && b_extra && b_cap && b_raw && no_residue(&l, 1))?;
    println!("jasodemo: l1 binding rejected missing={} extra={} cap={} raw={} no_residue=true", b_missing, b_extra, b_cap, b_raw);

    // 启动失败：init 成功、start 返回非 0 ⇒ 装载失败，映像取消映射，不进模块表
    let r_start = l.load(L1_STARTFAIL, grant(t)).err();
    s.check(r_start == Some(LoadError::StartFailed(7)) && no_residue(&l, 1))?;

    // Hybrid：依赖满足后装入并调用
    let hybrid = l.load(L1_HYBRID, grant(t)).map_err(|_| 100 + s.0)?;
    let h = l.get(hybrid).ok_or(100 + s.0)?;
    // SAFETY：签名与模块中的 l1_add 一致。
    let hadd = unsafe { h.function::<AddFn>("l1_add") }.map(|f| (f.get())(1, 2));
    s.check(hadd == Some(3) && h.name() == "jaso-l1-hybrid" && h.base() != native_base)?;
    println!("jasodemo: l1 hybrid name={} kind=hybrid depends=jaso-l1-native binding_ok=true add_ok=true", h.name());
    // 同名不重复装入（beta 没有热替换）
    s.check(matches!(l.load(L1_NATIVE, grant(t)), Err(LoadError::AlreadyLoaded(_))))?;

    // stop 与卸载答复
    let hooks0 = STOP_HOOKS.load(Ordering::Relaxed);
    let blocked = l.stop(native);
    s.check(matches!(&blocked, Err(StopError::Dependent(d)) if d == "jaso-l1-hybrid") && STOP_HOOKS.load(Ordering::Relaxed) == hooks0)?;
    let (u_plugin, u_system) = (l.unload(native), l.unload(hybrid));
    s.check(u_plugin == Some(UnloadReply::Deferred) && u_system == Some(UnloadReply::Refused))?;
    // 卸载请求之后两个模块都还在服务
    // SAFETY：签名与模块中的 l1_add 一致。
    let still = unsafe { l.get(native).ok_or(100 + s.0)?.function::<AddFn>("l1_add") }.map(|f| (f.get())(5, 6));
    s.check(still == Some(11))?;
    s.check(l.stop(hybrid) == Ok(()) && l.get(hybrid).is_some_and(|h| h.phase() == Phase::Stopped))?;
    // 已停止：不再服务，映像仍在（beta 不卸载），再停一次被拒且不再调用 jaso_stop
    // SAFETY：签名与模块中的 l1_add 一致。
    s.check(unsafe { l.get(hybrid).ok_or(100 + s.0)?.function::<AddFn>("l1_add") }.is_none())?;
    s.check(l.stop(hybrid) == Err(StopError::AlreadyStopped))?;
    s.check(l.stop(native) == Ok(()) && STOP_HOOKS.load(Ordering::Relaxed) == hooks0 + 2)?;
    s.check(l.unload(native) == Some(UnloadReply::Deferred) && mem::protect(native_base, 1, 0).is_ok())?; // 映像仍映射
    // 依赖已停止的模块不算满足
    let r_after = l.load(L1_HYBRID, grant(t));
    let code_after = code(&r_after);
    s.check(code_after == "dependency.unsatisfied")?;
    println!(
        "jasodemo: l1 lifecycle start_failed=7 stop_blocked=jaso-l1-hybrid unload_plugin={:?} unload_system={:?} still_serving=true stopped_serving=false stop_twice=AlreadyStopped stop_hooks=2 dep_on_stopped={} no_residue=true",
        u_plugin.ok_or(100 + s.0)?,
        u_system.ok_or(100 + s.0)?,
        code_after
    );
    kernel_gate(s, t)
}

/// 内核态准入门（内核自身没有运行期装载路径，见 `jaso::kernel_gate`）。
fn kernel_gate(s: &mut Steps, t: &TrustPolicy<'_>) -> Result<(), u32> {
    use jaso::kernel_gate::{admit_kernel, KernelLoadError, KernelPhase};
    let running = admit_kernel(DEMO_BOOT, t, KernelPhase::Running).err();
    s.check(running == Some(KernelLoadError::RuntimeLoad))?;
    s.check(admit_kernel(DEMO_BOOT, t, KernelPhase::Boot).is_ok())?;
    let stage = admit_kernel(DEMO, t, KernelPhase::Boot).err();
    s.check(matches!(stage, Some(KernelLoadError::Stage(_))))?;
    let dev = TrustPolicy::new(&PUBLISHERS, TrustMode::Development).map_err(|_| 100 + s.0)?;
    let dev_policy = admit_kernel(DEMO_BOOT, &dev, KernelPhase::Boot).err();
    s.check(dev_policy == Some(KernelLoadError::DevelopmentPolicy))?;
    let other_only = TrustPolicy::new(&OTHER_ONLY, TrustMode::Enforce).map_err(|_| 100 + s.0)?;
    let unlisted = admit_kernel(DEMO_BOOT, &other_only, KernelPhase::Boot).err();
    s.check(matches!(unlisted, Some(KernelLoadError::Untrusted(_))))?;
    println!("jasodemo: l1 kernel_gate running={:?} boot_signed=ok stage={:?} dev_policy={:?} unlisted={:?}", running, stage, dev_policy, unlisted);
    Ok(())
}

/// 篡改代码段的一个字节并重算完整性摘要：文件结构与完整性都合格，只有签名失效。
fn code_tampered() -> Option<Vec<u8>> {
    let img = jaso::Jaso::parse(DEMO).ok()?.image(0)?;
    let code = img.segments().find(|seg| seg.flags & jaso::FLAG_X != 0)?;
    let at = code.data.as_ptr() as usize - DEMO.as_ptr() as usize + code.data.len() / 2;
    let mut t = DEMO.to_vec();
    t[at] ^= 0x01;
    let d = jaso::digest_of(&t);
    t[jaso::DIGEST_OFFSET..jaso::DIGEST_OFFSET + 32].copy_from_slice(&d);
    Some(t)
}

/// 6. 来源（发布者签名）；`base` 是第一个槽位的基址（此时全部槽位空闲）。
fn signatures(s: &mut Steps, t: &TrustPolicy<'_>, base: u64) -> Result<(), u32> {
    // 签名模块：按受信发布者装入
    let m = Module::load(DEMO, grant(t)).map_err(|_| 100 + s.0)?;
    s.check(m.publisher() == Some(DEVELOPMENT_PUBLISHER) && m.base() == base && counter(&m) == 1)?;
    drop(m);
    // 各类拒绝（强制模式）
    let untrusted = |e: TrustError| Some(LoadError::Untrusted(e));
    let r_unsigned = Module::load(DEMO_UNSIGNED, grant(t)).err();
    s.check(r_unsigned == untrusted(TrustError::Unsigned))?;
    let tampered = code_tampered().ok_or(100 + s.0)?;
    let r_badsig = Module::load(&tampered, grant(t)).err();
    s.check(r_badsig == untrusted(TrustError::BadSignature))?;
    let r_otherpub = Module::load(DEMO_OTHERPUB, grant(t)).err();
    s.check(r_otherpub == untrusted(TrustError::KeyMismatch))?;
    let r_resigned = Module::load(DEMO_RESIGNED, grant(t)).err();
    s.check(r_resigned == untrusted(TrustError::KeyMismatch))?;
    let r_claimed = Module::load(DEMO_CLAIMED, grant(t)).err();
    s.check(r_claimed == untrusted(TrustError::OutOfNamespace))?;
    let other_only = TrustPolicy::new(&OTHER_ONLY, TrustMode::Enforce).map_err(|_| 100 + s.0)?;
    let r_unknown = Module::load(DEMO, grant(&other_only)).err();
    s.check(r_unknown == untrusted(TrustError::UnknownPublisher))?;
    // 被拒的装载都发生在映射之前：第一个槽位仍未映射，也没有产生任何审计放行
    s.check(mem::unmap(base, 1) == Err(Error::MEMORY_INVALID_ADDRESS) && unsigned_admitted() == 0)?;
    println!(
        "jasodemo: signature rejected unsigned={:?} badsig={:?} otherpub={:?} resigned={:?} claimed={:?} unknown={:?} no_residue=true",
        r_unsigned, r_badsig, r_otherpub, r_resigned, r_claimed, r_unknown
    );

    // 开发模式：未签名模块放行且被审计；签名模块仍按发布者认定；坏签名照样被拒
    let dev = TrustPolicy::new(&PUBLISHERS, TrustMode::Development).map_err(|_| 100 + s.0)?;
    let u = Module::load(DEMO_UNSIGNED, grant(&dev)).map_err(|_| 100 + s.0)?;
    s.check(u.publisher().is_none() && unsigned_admitted() == 1 && counter(&u) == 1)?;
    drop(u);
    let signed = Module::load(DEMO, grant(&dev)).map_err(|_| 100 + s.0)?;
    s.check(signed.publisher() == Some(DEVELOPMENT_PUBLISHER) && unsigned_admitted() == 1)?;
    drop(signed);
    let r_dev_badsig = Module::load(&tampered, grant(&dev)).err();
    s.check(r_dev_badsig == untrusted(TrustError::BadSignature))?;
    let r_dev_resigned = Module::load(DEMO_RESIGNED, grant(&dev)).err();
    s.check(r_dev_resigned == untrusted(TrustError::KeyMismatch) && unsigned_admitted() == 1)?;
    s.check(mem::unmap(base, 1) == Err(Error::MEMORY_INVALID_ADDRESS))?;
    println!(
        "jasodemo: trust dev_mode unsigned_loaded=true audited={} signed_publisher={} badsig={:?} resigned={:?} no_residue=true",
        unsigned_admitted(),
        DEVELOPMENT_PUBLISHER,
        r_dev_badsig,
        r_dev_resigned
    );
    Ok(())
}

/// 格式错误类型（经运行时转出）。
mod jaso_err {
    pub use jasper_rt::module::JasoError::*;
}
