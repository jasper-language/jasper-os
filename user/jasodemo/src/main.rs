//! user-jasodemo：`.jaso` 模块装载器的验收程序。
//! Acceptance program for the `.jaso` loader.
//!
//! 逐步检查（失败以步骤编号退出）：
//! 1. 装入合格模块：初始化经宿主接口表输出一行；调用各导出（读调用者内存、重定位过的只读指针表、可写数据、经宿主分配）
//! 2. 导出地址落在映像内；对代码页请求「可写 + 可执行」被内核拒绝（W^X）
//! 3. 同一模块装入两个实例：基址不同、可写数据各自独立
//! 4. 卸载：映射消失、槽位可复用、重新装入后状态从头开始
//! 5. 拒绝：篡改任一字节、截断、指令集不符、装载阶段不符、能力未授予、缺宿主接口表、缺初始化入口
//! 6. 来源（发布者签名）：签名模块按受信发布者装入；未签名、篡改后重算完整性摘要（签名失效）、换发布者、
//!    他人重签、他人重签并改称自己、发布者不在表中——全部在映射之前被拒且不留映射；
//!    开发模式放行未签名模块并留下审计事件，但坏签名照样被拒
#![no_std]
#![no_main]

extern crate alloc;

use alloc::alloc::{alloc, dealloc, Layout};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use jasper_rt::module::{
    unsigned_admitted, Grant, HostV0, LoadError, Module, Origin, Publisher, Standard, TrustError, TrustMode, TrustPolicy, DEVELOPMENT_NAMESPACE,
    DEVELOPMENT_PUBLISHER,
};
use jasper_rt::{entry, io, mem, println, Error};

entry!(main);

static DEMO: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/demo.jaso"));
static DEMO_OTHER_ARCH: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/demo-otherarch.jaso"));
static DEMO_BOOT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/demo-boot.jaso"));
static DEMO_NOINIT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/demo-noinit.jaso"));
static DEMO_MORECAPS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/demo-morecaps.jaso"));
static DEMO_UNSIGNED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/demo-unsigned.jaso"));
static DEMO_OTHERPUB: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/demo-otherpub.jaso"));
static DEMO_RESIGNED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/demo-resigned.jaso"));
static DEMO_CLAIMED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/demo-claimed.jaso"));

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

extern "C" fn host_log(ptr: *const u8, len: usize) {
    // SAFETY：模块按约定传入一段有效的 UTF-8 文本。
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
    if let Ok(s) = core::str::from_utf8(bytes) {
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
static HOST: HostV0 = HostV0 {
    version: 0,
    size: core::mem::size_of::<HostV0>() as u32,
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

    // 5. 拒绝
    let mut tampered = DEMO.to_vec();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0x01;
    let r_tamper = Module::load(&tampered, grant(t)).err();
    s.check(r_tamper == Some(LoadError::Format(jaso_err::DigestMismatch)))?;
    let r_trunc = Module::load(&DEMO[..DEMO.len() - 1], grant(t)).err();
    s.check(r_trunc == Some(LoadError::Format(jaso_err::LengthMismatch)))?;
    let r_arch = Module::load(DEMO_OTHER_ARCH, grant(t)).err();
    s.check(matches!(r_arch, Some(LoadError::WrongArch(_))))?;
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
    // 所有被拒的装载都没有留下映射：全部槽位空闲，第一个槽位可再次装入
    let again = Module::load(DEMO, grant(t)).map_err(|_| 100 + s.0)?;
    s.check(again.base() == base)?;
    println!(
        "jasodemo: rejected tamper={:?} truncated={:?} arch={:?} stage={:?} caps={:?} host={:?} init={:?}",
        r_tamper, r_trunc, r_arch, r_stage, r_caps, r_host, r_init
    );
    drop(again);
    signatures(s, t, base)
}

/// 篡改代码段的一个字节并重算完整性摘要：文件结构与完整性都合格，只有签名失效。
fn code_tampered() -> Option<Vec<u8>> {
    let img = jaso::Image::parse(DEMO).ok()?;
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
