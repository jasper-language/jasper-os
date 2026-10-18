//! user-isohost：隔离模块与进程内模块卸载的验收程序。
//! Acceptance program for isolated modules and quiescent in-process unloading.
//!
//! 内嵌构建期签名的探测模块（`jaso-probe`）与容器程序（`user-modbox`），依次检查：
//! 1. **创建子进程的权力边界**：请求本进程没有的系统调用 ⇒ `rights_denied`，非法映像 ⇒ `invalid_argument`，
//!    随后正常创建仍然成功（被拒那次不占配额）；同时持有的子进程达到上限时被拒，归还一个后又能创建；
//!    反复创建—丢弃远超上限也不积压
//! 2. **创建前拒绝**：句柄登记在清单未声明的能力名下 ⇒ 在创建隔离进程之前被拒
//! 3. **权限边界**：隔离模块自己执行系统调用——授予的调用配授予的句柄可用；未授予的调用 ⇒ `rights_denied`；
//!    宿主的句柄值在隔离进程里无效（`handle.invalid`），宿主的句柄原样可用
//! 4. **地址空间**：隔离模块向宿主数据的地址写入，宿主的数据不变
//! 5. **崩溃隔离**：隔离模块写入未映射的地址 ⇒ 隔离进程以故障终止，宿主得到 `Crashed`，之后的调用同样得到 `Crashed`；
//!    宿主不受影响，随即新建的隔离模块照常工作
//! 6. **CPU 压力**：两个隔离模块进入死循环吃满处理器时，宿主对第三个隔离模块的往返调用延迟有上界；
//!    丢弃它们（内核终止）后延迟立即恢复
//! 7. **放置规则**：自动获取的模块不得装入本进程（`IsolationRequired`，不占槽位）
//! 8. **静默判定**：另一线程停在模块代码里（模块回调宿主、宿主在回调里阻塞）时卸载被拒，模块仍可用；
//!    线程离开后卸载成功，之后取不到导出、重复卸载被拒
//!
//! 全部通过以 0 退出；第一个失败的步骤号作为退出码。
#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use jasper_rt::channel;
use jasper_rt::isolate::{CallError, IsolateError, IsolatedGrant, IsolatedModule};
use jasper_rt::module::{
    Grant, HostV0, LoadError, Module, Origin, Publisher, Standard, TrustMode, TrustPolicy, UnloadError, DEVELOPMENT_NAMESPACE,
    DEVELOPMENT_PUBLISHER, STD_HOST,
};
use jasper_rt::process::{self, FAULT_CODE};
use jasper_rt::{entry, ids, io, println, task, time, Error, Rights};

entry!(main);

/// 探测模块（以开发用发布者签名）。
static PROBE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/probe.jaso"));
/// 容器程序的 ELF 映像。
static CONTAINER: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/modbox.elf"));
/// 受信发布者表：只信任开发用发布者。
static PUBLISHERS: [Publisher<'static>; 1] = [Publisher {
    name: DEVELOPMENT_PUBLISHER,
    namespace: DEVELOPMENT_NAMESPACE,
    key: *include_bytes!(concat!(env!("OUT_DIR"), "/trust-dev.key")),
}];
/// 探测模块清单声明的能力（宿主全部授予）。
const PROBE_CAPS: &[&str] = &["system.console.write", "system.task.wait", "system.handle.duplicate"];

/// 字节调用约定的导出类型。
type BytesFn = unsafe extern "C" fn(*const u8, usize, *mut u8, usize) -> isize;

/// 宿主的一段数据：隔离模块向它的地址写入后检查它不变。
static MARKER: AtomicU32 = AtomicU32::new(0x5a5a_5a5a);

/// CPU 压力下往返调用延迟的上界（tick）：两个吃满处理器的隔离进程与宿主轮转，每轮往返最多等过几个时间片。
const LOADED_BOUND_TICKS: u64 = 4;
/// 压力撤销后的延迟上界（tick；允许一次跨 tick 的读数误差）。
const IDLE_BOUND_TICKS: u64 = 1;
/// 每阶段的往返调用次数。
const ROUNDS: u32 = 20;
/// 每个父进程同时拥有的子进程上限（与内核的配额一致）。
const MAX_CHILDREN: usize = 8;
/// 等待另一线程进入模块的最长时间（tick）。
const ENTER_TIMEOUT_TICKS: u64 = 500;

// ———————————————————————— 宿主接口表：可在回调里阻塞 ————————————————————————

/// 回调阻塞闸门：1 = 下一次 `log` 回调进入后阻塞，直到被放行。
static GATE_ARMED: AtomicU32 = AtomicU32::new(0);
/// 已有线程在回调里阻塞（即停在模块的调用栈中）。
static GATE_ENTERED: AtomicU32 = AtomicU32::new(0);
/// 放行阻塞的回调。
static GATE_RELEASE: AtomicU32 = AtomicU32::new(0);

extern "C" fn gate_log(ptr: *const u8, len: usize) {
    // SAFETY：模块按约定传入一段有效的 UTF-8 文本。
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
    if let Ok(s) = core::str::from_utf8(bytes) {
        let _ = io::write_str(s);
        let _ = io::write_str("\n");
    }
    if GATE_ARMED.swap(0, Ordering::AcqRel) == 1 {
        GATE_ENTERED.store(1, Ordering::Release);
        while GATE_RELEASE.load(Ordering::Acquire) == 0 {
            task::yield_now();
        }
    }
}

/// 进程内装载探测模块所用的宿主接口表（分配走标准表的实现）。
static GATE_HOST: HostV0 = HostV0 { version: 0, size: core::mem::size_of::<HostV0>() as u32, log: gate_log, alloc: STD_HOST.alloc, dealloc: STD_HOST.dealloc };

// ———————————————————————— 辅助 ————————————————————————

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

/// 系统调用以 `-(错误 ID)` 返回的错误值。
fn neg(e: Error) -> i64 {
    -(e.id() as i64)
}

fn le64(v: &[u8]) -> Option<u64> {
    v.try_into().ok().map(u64::from_le_bytes)
}

/// 请隔离模块自己执行一次系统调用，返回内核给它的返回值。
fn raw_call(m: &mut IsolatedModule, id: u64, a: u64, b: u64, c: u64) -> Result<i64, CallError> {
    let mut input = [0u8; 32];
    for (i, v) in [id, a, b, c].into_iter().enumerate() {
        input[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    let o = m.call("probe_syscall", &input, 8)?;
    le64(&o.bytes).map(|v| v as i64).ok_or(CallError::Protocol)
}

/// 请隔离模块向地址 `at` 写入 `value` 并读回。
fn poke(m: &mut IsolatedModule, at: u64, value: u64) -> Result<Option<u64>, CallError> {
    let mut input = [0u8; 16];
    input[..8].copy_from_slice(&at.to_le_bytes());
    input[8..].copy_from_slice(&value.to_le_bytes());
    m.call("probe_poke", &input, 8).map(|o| le64(&o.bytes))
}

/// 求和导出（`"abc"` ⇒ 294）。
fn sum_ok(m: &mut IsolatedModule) -> bool {
    matches!(m.call("probe_sum", b"abc", 8), Ok(o) if le64(&o.bytes) == Some(294))
}

fn trust() -> Result<TrustPolicy<'static>, u32> {
    TrustPolicy::new(&PUBLISHERS, TrustMode::Enforce).map_err(|_| 99)
}

/// 不带句柄的隔离授权。
fn plain_grant<'a>(t: &'a TrustPolicy<'a>, cpu: Option<u32>) -> IsolatedGrant<'a> {
    IsolatedGrant { container: CONTAINER, capabilities: PROBE_CAPS, trust: t, handles: Vec::new(), cpu_limit_permille: cpu }
}

/// 往返调用 `ROUNDS` 次，返回（最大延迟 tick, 全部正确）。
fn latency(m: &mut IsolatedModule) -> (u64, bool) {
    let mut worst = 0;
    let mut ok = true;
    for _ in 0..ROUNDS {
        let t0 = time::now();
        ok &= sum_ok(m);
        worst = worst.max(time::now() - t0);
    }
    (worst, ok)
}

// ———————————————————————— 用例 ————————————————————————

fn main(_: u64, _: u64) -> i32 {
    let mut s = Steps(0);
    match run(&mut s) {
        Ok(()) => {
            println!("isohost: ok checks={}", s.0);
            0
        }
        Err(step) => {
            println!("isohost: FAIL step={}", step);
            step as i32
        }
    }
}

fn run(s: &mut Steps) -> Result<(), u32> {
    let t = trust()?;
    spawn_boundary(s)?;
    handle_admission(s, &t)?;
    rights_boundary(s, &t)?;
    address_space(s, &t)?;
    crash_isolation(s, &t)?;
    cpu_pressure(s, &t)?;
    placement(s, &t)?;
    quiescence(s, &t)?;
    Ok(())
}

/// 用例 1：创建子进程只能授予自己拥有的系统调用。
fn spawn_boundary(s: &mut Steps) -> Result<(), u32> {
    // 本进程没有 system.task.qos.set
    let over = [ids::SYSTEM_CONSOLE_WRITE, ids::SYSTEM_PROCESS_EXIT, ids::SYSTEM_TASK_QOS_SET];
    let denied = process::spawn(process::Spec { image: CONTAINER, calls: &over, arg: 0, cpu_limit_permille: None }).err();
    s.check(denied == Some(Error::RIGHTS_DENIED))?;
    // 非法映像被拒
    let bad = process::spawn(process::Spec { image: b"not an elf", calls: &[ids::SYSTEM_PROCESS_EXIT], arg: 0, cpu_limit_permille: None }).err();
    s.check(bad == Some(Error::INVALID_ARGUMENT))?;
    // 被拒之后正常创建成功：子进程只拿到退出调用，关闭引导通道后它收不到请求，退出
    let calls = [ids::SYSTEM_CONSOLE_WRITE, ids::SYSTEM_PROCESS_EXIT, ids::SYSTEM_TASK_EXIT, ids::SYSTEM_CHANNEL_RECV, ids::SYSTEM_CHANNEL_SEND,
                 ids::SYSTEM_MEMORY_MAP, ids::SYSTEM_MEMORY_UNMAP, ids::SYSTEM_MEMORY_PROTECT, ids::SYSTEM_HANDLE_CLOSE, ids::SYSTEM_TASK_YIELD];
    let child = process::spawn(process::Spec { image: CONTAINER, calls: &calls, arg: 0, cpu_limit_permille: None }).map_err(|_| s.0 + 1)?;
    let process::Child { process: ph, channel: ch } = child;
    drop(ch);
    let code = task::wait_process(&ph);
    drop(ph);
    s.check(code == Ok(0))?;
    // 配额：同时持有 MAX_CHILDREN 个子进程时再创建被拒；关闭一个后又能创建
    let spec = process::Spec { image: CONTAINER, calls: &calls, arg: 0, cpu_limit_permille: None };
    let mut held = Vec::new();
    for _ in 0..MAX_CHILDREN {
        held.push(process::spawn(spec).map_err(|_| s.0 + 1)?);
    }
    s.check(process::spawn(spec).err() == Some(Error::QUOTA_EXCEEDED))?;
    let first = held.remove(0);
    drop(first.channel);
    s.check(task::wait_process(&first.process) == Ok(0))?;
    drop(first.process);
    held.push(process::spawn(spec).map_err(|_| s.0 + 1)?);
    drop(held);
    // 反复「创建—丢弃」远超配额：已死亡的子进程被回收，不会积压
    for _ in 0..3 * MAX_CHILDREN {
        drop(process::spawn(spec).map_err(|_| s.0 + 1)?);
    }
    s.check(true)?;
    println!("isohost: spawn escalation_denied=true bad_image_rejected=true child_exit=0 quota={} quota_exceeded_rejected=true churn={} ok=true", MAX_CHILDREN, 3 * MAX_CHILDREN);
    Ok(())
}

/// 用例 2：句柄登记在清单未声明的能力名下 ⇒ 创建隔离进程之前被拒。
fn handle_admission(s: &mut Steps, t: &TrustPolicy<'_>) -> Result<(), u32> {
    let (a, _b) = channel::pair().map_err(|_| s.0 + 1)?;
    let mut g = plain_grant(t, None);
    g.capabilities = &["system.console.write", "system.task.wait", "system.handle.duplicate", "system.channel.send"];
    g.handles.push(("system.channel.send", a.into_handle()));
    let r = IsolatedModule::spawn(PROBE, g).err();
    s.check(matches!(&r, Some(IsolateError::UndeclaredHandle(c)) if c == "system.channel.send"))?;
    // 能力未授予 ⇒ 无状态检查即被拒
    let mut g = plain_grant(t, None);
    g.capabilities = &["system.console.write", "system.task.wait"];
    let r = IsolatedModule::spawn(PROBE, g).err();
    s.check(matches!(&r, Some(IsolateError::Load(LoadError::MissingCapability(c))) if c == "system.handle.duplicate"))?;
    println!("isohost: admission undeclared_handle_rejected=true missing_capability_rejected=true");
    Ok(())
}

/// 用例 3：隔离模块自己执行系统调用时的权限边界。
fn rights_boundary(s: &mut Steps, t: &TrustPolicy<'_>) -> Result<(), u32> {
    // 授予一个句柄：宿主一个线程的任务句柄（可移动），登记在清单声明的 system.task.wait 名下
    let worker = task::spawn(|| 7).map_err(|_| s.0 + 1)?;
    let granted = worker.handle().duplicate(Rights::WAIT.union(Rights::DUPLICATE).union(Rights::TRANSFER)).map_err(|_| s.0 + 1)?;
    // 宿主自己的句柄：多建几对通道，使其槽位号超出隔离进程句柄表已用的部分
    let mut keep = Vec::new();
    for _ in 0..6 {
        keep.push(channel::pair().map_err(|_| s.0 + 1)?);
    }
    let host_raw = keep[5].0.handle().raw();
    let mut g = plain_grant(t, None);
    g.handles.push(("system.task.wait", granted));
    let mut m = IsolatedModule::spawn(PROBE, g).map_err(|_| s.0 + 1)?;
    s.check(m.name() == "jaso-probe" && m.publisher() == Some(DEVELOPMENT_PUBLISHER))?;
    s.check(sum_ok(&mut m))?;
    let bound = m.call("probe_bound", &[], 8).ok().and_then(|o| le64(&o.bytes)).ok_or(s.0 + 1)?;
    // 授予的调用 + 授予的句柄：复制成功
    let dup = raw_call(&mut m, ids::SYSTEM_HANDLE_DUPLICATE, bound, Rights::WAIT.bits() as u64, 0).map_err(|_| s.0 + 1)?;
    s.check(dup > 0)?;
    // 未授予的调用：被拒
    let create = raw_call(&mut m, ids::SYSTEM_CHANNEL_CREATE, 0, 0, 0).map_err(|_| s.0 + 1)?;
    s.check(create == neg(Error::RIGHTS_DENIED))?;
    let spawn = raw_call(&mut m, ids::SYSTEM_PROCESS_SPAWN, 0, 0, 0).map_err(|_| s.0 + 1)?;
    s.check(spawn == neg(Error::RIGHTS_DENIED))?;
    let sleep = raw_call(&mut m, ids::SYSTEM_TIME_WAIT, 1, 0, 0).map_err(|_| s.0 + 1)?;
    s.check(sleep == neg(Error::RIGHTS_DENIED))?;
    // 宿主的句柄值在隔离进程里无效
    let foreign = raw_call(&mut m, ids::SYSTEM_HANDLE_DUPLICATE, host_raw as u64, Rights::WAIT.bits() as u64, 0).map_err(|_| s.0 + 1)?;
    s.check(foreign == neg(Error::HANDLE_INVALID))?;
    // 宿主的句柄原样可用
    let (h0, h1) = &keep[5];
    s.check(h0.send(b"still-mine").is_ok() && matches!(h1.recv_vec(), Ok((b, _)) if b == b"still-mine"))?;
    // 被拒的调用不影响会话；宿主线程照常结束
    s.check(sum_ok(&mut m))?;
    s.check(worker.join() == Ok(7))?;
    println!("isohost: rights granted_call_ok=true denied=channel.create,process.spawn,time.wait foreign_handle=invalid host_handle_intact=true");
    Ok(())
}

/// 用例 4：隔离模块写不到宿主的数据。
fn address_space(s: &mut Steps, t: &TrustPolicy<'_>) -> Result<(), u32> {
    let mut m = IsolatedModule::spawn(PROBE, plain_grant(t, None)).map_err(|_| s.0 + 1)?;
    let at = &MARKER as *const AtomicU32 as u64;
    // 该地址在隔离进程里要么是它自己的内存（写入只改它自己的），要么未映射（隔离进程故障终止）
    let outcome = match poke(&mut m, at, 0xdead_beef) {
        Ok(_) => "own_memory",
        Err(CallError::Crashed(c)) if c == FAULT_CODE => "faulted",
        Err(_) => return Err(s.0 + 1),
    };
    s.check(MARKER.load(Ordering::Acquire) == 0x5a5a_5a5a)?;
    println!("isohost: address_space outcome={} host_data_intact=true", outcome);
    Ok(())
}

/// 用例 5：模块崩溃只终止隔离进程。
fn crash_isolation(s: &mut Steps, t: &TrustPolicy<'_>) -> Result<(), u32> {
    let mut m = IsolatedModule::spawn(PROBE, plain_grant(t, None)).map_err(|_| s.0 + 1)?;
    s.check(sum_ok(&mut m))?;
    // 第 0 页从不映射：写入即页故障
    let r = poke(&mut m, 8, 1);
    s.check(r == Err(CallError::Crashed(FAULT_CODE)) && m.crashed() == Some(FAULT_CODE))?;
    s.check(m.call("probe_sum", b"abc", 8) == Err(CallError::Crashed(FAULT_CODE)))?;
    drop(m);
    // 宿主照常：新建的隔离模块工作正常
    let mut again = IsolatedModule::spawn(PROBE, plain_grant(t, None)).map_err(|_| s.0 + 1)?;
    s.check(sum_ok(&mut again))?;
    println!("isohost: crash code={} host_alive=true respawn_ok=true", FAULT_CODE as u32 as i32);
    Ok(())
}

/// 用例 6：隔离模块吃满处理器时宿主仍有响应；丢弃后立即恢复。
fn cpu_pressure(s: &mut Steps, t: &TrustPolicy<'_>) -> Result<(), u32> {
    let mut probe = IsolatedModule::spawn(PROBE, plain_grant(t, None)).map_err(|_| s.0 + 1)?;
    let (base, ok) = latency(&mut probe);
    s.check(ok)?;
    let mut hogs = Vec::new();
    for _ in 0..2 {
        let mut h = IsolatedModule::spawn(PROBE, plain_grant(t, None)).map_err(|_| s.0 + 1)?;
        h.submit("probe_spin", &[], 8).map_err(|_| s.0 + 1)?;
        hogs.push(h);
    }
    // 让两个死循环真正跑起来
    let _ = time::sleep(2);
    let (loaded, ok) = latency(&mut probe);
    s.check(ok && loaded <= LOADED_BOUND_TICKS)?;
    // 丢弃 ⇒ 内核终止仍在运行的隔离进程
    drop(hogs);
    let (after, ok) = latency(&mut probe);
    s.check(ok && after <= IDLE_BOUND_TICKS)?;
    println!(
        "isohost: cpu_pressure hogs=2 rounds={} idle_max_ticks={} loaded_max_ticks={} bound={} recovered_max_ticks={} recovered=true",
        ROUNDS, base, loaded, LOADED_BOUND_TICKS, after
    );
    Ok(())
}

/// 用例 7：自动获取的模块不得进程内运行。
fn placement(s: &mut Steps, t: &TrustPolicy<'_>) -> Result<(), u32> {
    let acquired = Grant { capabilities: PROBE_CAPS, host: Some(&STD_HOST), trust: t, origin: Origin::Acquired, placement: &Standard };
    s.check(Module::load(PROBE, acquired).err() == Some(LoadError::IsolationRequired))?;
    // 被拒那次没有占用槽位、没有映射：随后的本地装载照常成功
    let local = Grant { origin: Origin::Local, ..acquired };
    let m = Module::load(PROBE, local).map_err(|_| s.0 + 1)?;
    s.check(m.unload().is_ok())?;
    // 同一份字节以隔离方式运行
    let mut iso = IsolatedModule::spawn(PROBE, plain_grant(t, None)).map_err(|_| s.0 + 1)?;
    s.check(sum_ok(&mut iso))?;
    println!("isohost: placement acquired_in_process=rejected acquired_isolated=ok local_in_process=ok");
    Ok(())
}

/// 用例 8：进程内卸载的静默判定。
fn quiescence(s: &mut Steps, t: &TrustPolicy<'_>) -> Result<(), u32> {
    let grant = Grant { capabilities: PROBE_CAPS, host: Some(&GATE_HOST), trust: t, origin: Origin::Local, placement: &Standard };
    let m = Arc::new(Module::load(PROBE, grant).map_err(|_| s.0 + 1)?);
    GATE_ENTERED.store(0, Ordering::Release);
    GATE_RELEASE.store(0, Ordering::Release);
    GATE_ARMED.store(1, Ordering::Release);
    let inner = m.clone();
    let worker = task::spawn(move || {
        // SAFETY：probe_wait 遵守字节调用约定。
        let Some(f) = (unsafe { inner.function::<BytesFn>("probe_wait") }) else { return 1 };
        // SAFETY：空输入、空输出。
        let r = unsafe { (f.get())(core::ptr::null(), 0, core::ptr::null_mut(), 0) };
        drop(f);
        r as u64
    })
    .map_err(|_| s.0 + 1)?;
    let start = time::now();
    while GATE_ENTERED.load(Ordering::Acquire) == 0 && time::now() - start < ENTER_TIMEOUT_TICKS {
        task::yield_now();
    }
    s.check(GATE_ENTERED.load(Ordering::Acquire) == 1)?;
    // 线程停在模块里：卸载被拒，模块原样可用
    let busy = m.unload();
    s.check(busy == Err(UnloadError::Busy { active: 1 }) && !m.is_unloaded())?;
    // SAFETY：probe_sum 遵守字节调用约定；输入输出缓冲区有效。
    let sum = unsafe {
        let f = m.function::<BytesFn>("probe_sum").ok_or(s.0 + 1)?;
        let mut out = [0u8; 8];
        let n = (f.get())(b"abc".as_ptr(), 3, out.as_mut_ptr(), 8);
        (n == 8).then(|| u64::from_le_bytes(out))
    };
    s.check(sum == Some(294))?;
    // 放行：线程离开模块后卸载成功
    GATE_RELEASE.store(1, Ordering::Release);
    s.check(worker.join() == Ok(0))?;
    s.check(m.active() == 0 && m.unload().is_ok() && m.is_unloaded())?;
    // SAFETY：只检查能否取得导出，不调用。
    s.check(unsafe { m.function::<BytesFn>("probe_sum") }.is_none())?;
    s.check(m.unload() == Err(UnloadError::AlreadyUnloaded))?;
    println!("isohost: quiescence busy_refused=true active_at_refusal=1 usable_while_busy=true unloaded_after_exit=true");
    Ok(())
}
