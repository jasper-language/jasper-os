//! 隔离模块：在独立子进程中运行不可信的 `.jaso` 模块。
//! Isolated modules: untrusted `.jaso` modules running in their own child process.
//!
//! # 角色
//! * **宿主**（[`IsolatedModule`]）：在创建任何东西之前完成全部无状态检查（与进程内装载共用 [`admit`]），
//!   再创建隔离进程、经引导通道送去模块文件与授权，之后把调用转成通道上的请求
//! * **容器**（[`serve`]）：隔离进程里运行的服务循环——重新校验并装入模块、绑定句柄、按请求调用导出
//!
//! # 权限模型
//! 隔离进程只拥有：
//! * 系统调用：运行时自身所需的 [`CONTAINER_CALLS`]，加上**模块清单声明、且宿主授权**的能力中属于系统调用的那些
//! * 句柄：引导通道端点，加上宿主随装入请求发送的句柄——每个句柄都要登记在一个能力名下，
//!   该能力必须同时被清单声明、被宿主授权，否则在创建隔离进程之前就被拒绝
//!
//! 它看不到宿主的地址空间与句柄表：越权的系统调用得到 `rights_denied`，宿主的句柄值在它那里无效，
//! 访问宿主的地址只会触及它自己的地址空间（未映射即故障）。
//!
//! # 生命周期
//! 隔离进程活不过 [`IsolatedModule`]：丢弃它即关闭进程句柄，仍在运行的隔离进程被内核终止。
//! 模块崩溃只终止隔离进程，宿主在下一次收取回复时得到 [`CallError::Crashed`]（带退出码）。

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use jaso::wire::{self, BoxError, Reply, ReplyKind, Request, TrustSpec, BytesFn, BindFn, BIND_SYMBOL};
use jaso::Image;

use crate::channel::Channel;
use crate::error::Error;
use crate::handle::Handle;
use crate::module::{admit, AlwaysIsolated, Grant, LoadError, Module, Origin, Provenance, Publisher, Site, TrustMode, TrustPolicy, STD_HOST};
use crate::process::{self, Child};
use crate::ids;

/// 容器运行时自身所需的系统调用（输出诊断、退出、让出、引导通道收发、堆与模块映射、关闭句柄）。
/// System calls the container runtime itself needs.
pub const CONTAINER_CALLS: &[u64] = &[
    ids::SYSTEM_CONSOLE_WRITE,
    ids::SYSTEM_TASK_EXIT,
    ids::SYSTEM_PROCESS_EXIT,
    ids::SYSTEM_TASK_YIELD,
    ids::SYSTEM_CHANNEL_SEND,
    ids::SYSTEM_CHANNEL_RECV,
    ids::SYSTEM_MEMORY_MAP,
    ids::SYSTEM_MEMORY_UNMAP,
    ids::SYSTEM_MEMORY_PROTECT,
    ids::SYSTEM_HANDLE_CLOSE,
];

/// 容器接收的模块文件字节数上限。
/// Upper bound on the module file a container accepts.
pub const MAX_MODULE_BYTES: usize = 4 * 1024 * 1024;

/// 创建隔离模块的授权。
/// What the host grants to an isolated module.
pub struct IsolatedGrant<'a> {
    /// 容器程序的 ELF 映像（以本运行时写成、入口调用 [`serve`] 的程序）。
    pub container: &'a [u8],
    /// 授予的能力名（清单要求的每一项都必须在此）。
    pub capabilities: &'a [&'a str],
    /// 信任策略。
    pub trust: &'a TrustPolicy<'a>,
    /// 交给模块的句柄，各自登记在一个能力名下（须带 TRANSFER；随装入请求移动给隔离进程）。
    pub handles: Vec<(&'a str, Handle)>,
    /// 隔离进程的 CPU 上限（千分比；`None` = 不限）。
    pub cpu_limit_permille: Option<u32>,
}

/// 创建隔离模块失败的原因。失败时不留下隔离进程（已创建的随即被终止并回收）。
/// Why creating an isolated module failed; no container is left behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IsolateError {
    /// 无状态检查未通过（与进程内装载相同的原因）；此时尚未创建隔离进程。
    Load(LoadError),
    /// 句柄登记在一个未被清单声明或未被授权的能力名下；此时尚未创建隔离进程。
    UndeclaredHandle(String),
    /// 句柄数超过单条消息的上限。
    TooManyHandles,
    /// 创建隔离进程失败。
    Spawn(Error),
    /// 通道收发失败。
    Channel(Error),
    /// 容器拒绝了请求。
    Refused(BoxError),
    /// 容器在会话中途退出（带退出码）。
    Crashed(u64),
    /// 回复无法解码。
    Protocol,
}

/// 调用失败的原因。
/// Why a call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallError {
    /// 容器拒绝了请求（没有这个导出、输出越界……），会话仍可继续。
    Refused(BoxError),
    /// 隔离进程已终止（模块崩溃或被终止），退出码见内容；之后的调用都得到同样的结果。
    Crashed(u64),
    /// 请求无法编码（导出名或输入过长）。
    TooLarge,
    /// 通道收发失败。
    Channel(Error),
    /// 回复无法解码。
    Protocol,
}

/// 一次成功调用的结果。
/// Result of a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    /// 导出的返回值（≥ 0 为输出字节数；负数是模块自己的错误码）。
    pub value: i64,
    /// 输出字节。
    pub bytes: Vec<u8>,
}

/// 一个在隔离进程中运行的模块（宿主侧代理）。
/// Host-side proxy of a module running in an isolated process.
pub struct IsolatedModule {
    child: Child,
    name: String,
    version: (u32, u32, u32),
    publisher: Option<String>,
    crashed: Option<u64>,
}

/// 能力名中属于系统调用的那些对应的 ID。
fn call_id(name: &str) -> Option<u64> {
    ids::OPS.iter().find(|(n, _)| *n == name).map(|(_, id)| *id)
}

/// 发送一条请求并收取回复（严格一问一答）。返回（种类, 值, 输出）。对端关闭 ⇒ `Err(None)`。
fn exchange(ch: &Channel, msg: &[u8], handles: Vec<Handle>) -> Result<(ReplyKind, i64, Vec<u8>), Option<Error>> {
    ch.send_with(msg, handles).map_err(|(e, _)| if e == Error::CHANNEL_PEER_CLOSED { None } else { Some(e) })?;
    let (b, _) = ch.recv_vec().map_err(|e| if e == Error::CHANNEL_PEER_CLOSED { None } else { Some(e) })?;
    let r = wire::decode_reply(&b).map_err(|_| Some(Error::INVALID_ARGUMENT))?;
    Ok((r.kind, r.value, r.payload.to_vec()))
}

impl IsolatedModule {
    /// 检查、创建隔离进程、送去模块并装入（见模块文档）。
    /// Checks the module, starts its container and loads it there.
    pub fn spawn(bytes: &[u8], grant: IsolatedGrant<'_>) -> Result<IsolatedModule, IsolateError> {
        // 1. 无状态检查（与进程内装载相同）；容器总是提供标准宿主接口表
        let view = Grant { capabilities: grant.capabilities, host: Some(&STD_HOST), trust: grant.trust, origin: Origin::Acquired, placement: &AlwaysIsolated };
        let admitted = admit(bytes, &view).map_err(IsolateError::Load)?;
        let img: &Image<'_> = &admitted.image;
        let m = img.manifest;
        // 2. 句柄：每个都登记在清单声明且被授权的能力名下
        if grant.handles.len() > wire::MAX_HANDLES {
            return Err(IsolateError::TooManyHandles);
        }
        for (cap, _) in &grant.handles {
            if !m.requires().any(|c| c == *cap) || !grant.capabilities.contains(cap) {
                return Err(IsolateError::UndeclaredHandle(cap.to_string()));
            }
        }
        // 3. 转交信任参数：宿主验签时匹配到的那个发布者（或开发模式）
        let trust = match admitted.provenance {
            Provenance::Signed { publisher } => {
                let p = grant.trust.publishers().iter().find(|p| p.name == publisher).ok_or(IsolateError::Protocol)?;
                TrustSpec::Signed { name: p.name, namespace: p.namespace, key: p.key }
            }
            Provenance::UnsignedDevelopment => {
                crate::module::audit_unsigned(img);
                TrustSpec::Development
            }
        };
        // 4. 隔离进程的系统调用：运行时所需 + 清单声明（已证明 ⊆ 授权）的系统调用
        let mut calls: Vec<u64> = CONTAINER_CALLS.to_vec();
        calls.extend(m.requires().filter_map(call_id).filter(|id| !CONTAINER_CALLS.contains(id)));
        let caps: Vec<&str> = m.requires().collect();
        let handle_caps: Vec<&str> = grant.handles.iter().map(|(c, _)| *c).collect();
        let handles: Vec<Handle> = grant.handles.into_iter().map(|(_, h)| h).collect();
        let mut load = vec![0u8; 2048];
        let n = wire::encode_load(&trust, &caps, &handle_caps, &mut load).map_err(|_| IsolateError::Protocol)?;
        load.truncate(n);
        let proxy_name = m.name.to_string();
        let version = m.version;
        let publisher = match admitted.provenance {
            Provenance::Signed { publisher } => Some(publisher.to_string()),
            Provenance::UnsignedDevelopment => None,
        };
        // 5. 创建隔离进程；此后任何失败都随 `child` 被丢弃而终止它
        let child = process::spawn(process::Spec { image: grant.container, calls: &calls, arg: 0, cpu_limit_permille: grant.cpu_limit_permille })
            .map_err(IsolateError::Spawn)?;
        let fail = |child: &Child, e: Option<Error>| match e {
            Some(e) => IsolateError::Channel(e),
            None => IsolateError::Crashed(child.wait().unwrap_or(process::FAULT_CODE)),
        };
        let mut msg = vec![0u8; wire::MAX_MESSAGE];
        for part in bytes.chunks(wire::MAX_CHUNK) {
            let n = wire::encode_chunk(part, &mut msg).map_err(|_| IsolateError::Protocol)?;
            match exchange(&child.channel, &msg[..n], Vec::new()) {
                Ok((ReplyKind::Ok, _, _)) => {}
                Ok((ReplyKind::Refused, v, _)) => return Err(IsolateError::Refused(BoxError::from_code(v).unwrap_or(BoxError::BadRequest))),
                Err(e) => return Err(fail(&child, e)),
            }
        }
        match exchange(&child.channel, &load, handles) {
            Ok((ReplyKind::Ok, _, _)) => {}
            Ok((ReplyKind::Refused, v, _)) => return Err(IsolateError::Refused(BoxError::from_code(v).unwrap_or(BoxError::BadRequest))),
            Err(e) => return Err(fail(&child, e)),
        }
        Ok(IsolatedModule { child, name: proxy_name, version, publisher, crashed: None })
    }

    /// 模块名。
    pub fn name(&self) -> &str {
        &self.name
    }

    /// 模块版本。
    pub fn version(&self) -> (u32, u32, u32) {
        self.version
    }

    /// 签名发布者（开发模式下放行的未签名模块为 `None`）。
    pub fn publisher(&self) -> Option<&str> {
        self.publisher.as_deref()
    }

    /// 只发送调用请求、不等待回复（与 [`IsolatedModule::complete`] 成对使用；例如交给隔离进程一项长时间的计算）。
    /// Sends a call request without waiting for the reply.
    pub fn submit(&mut self, export: &str, input: &[u8], out_cap: u32) -> Result<(), CallError> {
        if let Some(code) = self.crashed {
            return Err(CallError::Crashed(code));
        }
        let mut msg = vec![0u8; wire::MAX_MESSAGE];
        let n = wire::encode_call(export, out_cap, input, &mut msg).map_err(|_| CallError::TooLarge)?;
        match self.child.channel.send(&msg[..n]) {
            Ok(()) => Ok(()),
            Err(e) if e == Error::CHANNEL_PEER_CLOSED => Err(self.mark_crashed()),
            Err(e) => Err(CallError::Channel(e)),
        }
    }

    /// 收取上一次 [`IsolatedModule::submit`] 的回复。
    /// Receives the reply to the previous submit.
    pub fn complete(&mut self) -> Result<Output, CallError> {
        if let Some(code) = self.crashed {
            return Err(CallError::Crashed(code));
        }
        let b = match self.child.channel.recv_vec() {
            Ok((b, _)) => b,
            Err(e) if e == Error::CHANNEL_PEER_CLOSED => return Err(self.mark_crashed()),
            Err(e) => return Err(CallError::Channel(e)),
        };
        match wire::decode_reply(&b) {
            Ok(Reply { kind: ReplyKind::Ok, value, payload }) => Ok(Output { value, bytes: payload.to_vec() }),
            Ok(Reply { kind: ReplyKind::Refused, value, .. }) => Err(CallError::Refused(BoxError::from_code(value).unwrap_or(BoxError::BadRequest))),
            Err(_) => Err(CallError::Protocol),
        }
    }

    /// 调用导出：发送输入字节，等待输出（最多 `out_cap` 字节）。
    /// Calls an export with input bytes and waits for the output.
    pub fn call(&mut self, export: &str, input: &[u8], out_cap: u32) -> Result<Output, CallError> {
        self.submit(export, input, out_cap)?;
        self.complete()
    }

    /// 隔离进程已终止时的退出码（尚未观察到终止为 `None`）。
    pub fn crashed(&self) -> Option<u64> {
        self.crashed
    }

    fn mark_crashed(&mut self) -> CallError {
        let code = self.child.wait().unwrap_or(process::FAULT_CODE);
        self.crashed = Some(code);
        CallError::Crashed(code)
    }
}

// ———————————————————————— 容器侧 ————————————————————————

/// 容器的会话状态。
struct Session {
    file: Vec<u8>,
    module: Option<Module>,
    /// 交给模块的句柄：会话期间保持打开（模块持有的是它们的值）。
    bound: Vec<Handle>,
}

fn refuse(e: BoxError) -> (ReplyKind, i64, Vec<u8>) {
    (ReplyKind::Refused, e as i64, Vec::new())
}

impl Session {
    fn chunk(&mut self, data: &[u8]) -> (ReplyKind, i64, Vec<u8>) {
        if self.module.is_some() {
            return refuse(BoxError::AlreadyLoaded);
        }
        if self.file.len() + data.len() > MAX_MODULE_BYTES {
            return refuse(BoxError::TooLarge);
        }
        self.file.extend_from_slice(data);
        (ReplyKind::Ok, 0, Vec::new())
    }

    fn load(&mut self, trust: TrustSpec<'_>, caps: wire::Caps<'_>, handle_caps: wire::Caps<'_>, handles: Vec<Handle>) -> (ReplyKind, i64, Vec<u8>) {
        if self.module.is_some() {
            return refuse(BoxError::AlreadyLoaded);
        }
        if handle_caps.len() != handles.len() || handle_caps.iter().any(|c| !caps.contains(c)) {
            return refuse(BoxError::BindFailed);
        }
        let publishers;
        let policy = match trust {
            TrustSpec::Signed { name, namespace, key } => {
                publishers = [Publisher { name, namespace, key }];
                TrustPolicy::new(&publishers, TrustMode::Enforce)
            }
            TrustSpec::Development => TrustPolicy::new(&[], TrustMode::Development),
        };
        let Ok(policy) = policy else { return refuse(BoxError::LoadFailed) };
        let cap_list: Vec<&str> = caps.iter().collect();
        let grant = Grant { capabilities: &cap_list, host: Some(&STD_HOST), trust: &policy, origin: Origin::Acquired, placement: &AlwaysIsolated };
        let module = match Module::load_at(&self.file, grant, Site::Container) {
            Ok(m) => m,
            Err(_) => return refuse(BoxError::LoadFailed),
        };
        if !handles.is_empty() {
            // SAFETY：jaso_bind 的签名由约定固定为 BindFn。
            let Some(bind) = (unsafe { module.function::<BindFn>(BIND_SYMBOL) }) else { return refuse(BoxError::BindFailed) };
            // SAFETY：能力名在调用期间有效；句柄值属于本进程。
            let ok = handle_caps.iter().zip(handles.iter()).all(|(cap, h)| unsafe { (bind.get())(cap.as_ptr(), cap.len(), h.raw()) } == 0);
            drop(bind);
            if !ok {
                return refuse(BoxError::BindFailed);
            }
        }
        self.bound = handles;
        self.file = Vec::new();
        self.module = Some(module);
        (ReplyKind::Ok, 0, Vec::new())
    }

    fn call(&mut self, export: &str, out_cap: u32, input: &[u8]) -> (ReplyKind, i64, Vec<u8>) {
        let Some(m) = &self.module else { return refuse(BoxError::NotLoaded) };
        // SAFETY：隔离运行的导出按约定遵守 BytesFn；签名不符只会损害本隔离进程。
        let Some(f) = (unsafe { m.function::<BytesFn>(export) }) else { return refuse(BoxError::NoExport) };
        let mut out = vec![0u8; (out_cap as usize).min(wire::MAX_CHUNK)];
        // SAFETY：输入与输出缓冲区在调用期间有效，长度如实给出。
        let ret = unsafe { (f.get())(input.as_ptr(), input.len(), out.as_mut_ptr(), out.len()) };
        if ret < 0 {
            return (ReplyKind::Ok, ret as i64, Vec::new());
        }
        if ret as usize > out.len() {
            return refuse(BoxError::BadOutput);
        }
        out.truncate(ret as usize);
        (ReplyKind::Ok, ret as i64, out)
    }
}

/// 容器的服务循环：处理宿主的请求，直到引导通道关闭（返回 0，作为隔离进程的退出码）。
/// The container's service loop; returns when the host closes the channel.
pub fn serve(ch: Channel) -> i32 {
    let mut s = Session { file: Vec::new(), module: None, bound: Vec::new() };
    let mut out = vec![0u8; wire::MAX_MESSAGE];
    loop {
        let Ok((msg, handles)) = ch.recv_vec() else { return 0 };
        let (kind, value, payload) = match wire::decode_request(&msg) {
            Ok(Request::Chunk(d)) => s.chunk(d),
            Ok(Request::Load { trust, caps, handle_caps }) => s.load(trust, caps, handle_caps, handles),
            Ok(Request::Call { export, out_cap, input }) => s.call(export, out_cap, input),
            Err(_) => refuse(BoxError::BadRequest),
        };
        let n = match wire::encode_reply(kind, value, &payload, &mut out) {
            Ok(n) => n,
            Err(_) => match wire::encode_reply(ReplyKind::Refused, BoxError::BadOutput as i64, &[], &mut out) {
                Ok(n) => n,
                Err(_) => return 1,
            },
        };
        if ch.send(&out[..n]).is_err() {
            return 0;
        }
    }
}
