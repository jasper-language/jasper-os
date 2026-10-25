//! 子进程：从内存中的 ELF 映像创建，只授予调用者自己权力的子集。
//! Child processes created from an in-memory ELF image with a subset of the caller's rights.
//!
//! 内核语义（`system.process.spawn`）：
//! * 子进程的系统调用集合必须是调用者集合的子集，否则 `rights_denied`
//! * 子进程起步时只有一个句柄：与父进程相连的引导通道端点（主线程入口参数 0）；其它句柄只能由父进程经该通道发送
//! * 父进程得到的 [`Child::process`] 是子进程唯一的外部所有权：它被关闭（或父进程退出）时子进程若仍在运行即被终止
//! * 全有或全无：失败时不留下子进程、句柄或配额占用

use kernel_core::spawn_abi::{SpawnDesc, CPU_UNLIMITED};

use crate::channel::Channel;
use crate::error::{check, Result};
use crate::handle::Handle;
use crate::{ids, sys};

/// 故障（缺页、非法指令……）终止的进程的退出码（`-1`；退出码按 32 位无符号值报告）。
/// Exit code of a process terminated by a fault (`-1` reported as a 32-bit unsigned value).
pub const FAULT_CODE: u64 = (-1i32) as u32 as u64;
/// 因父进程释放最后一个句柄而被终止的进程的退出码（`-2`，同样按 32 位无符号值报告）。
/// Exit code of a process terminated because its last handle was released.
pub const KILLED_CODE: u64 = (-2i32) as u32 as u64;

/// 创建子进程的参数。
/// Parameters for creating a child.
#[derive(Clone, Copy)]
pub struct Spec<'a> {
    /// ELF 映像。
    pub image: &'a [u8],
    /// 授予子进程的系统调用 ID（每一个都必须是调用者自己被授予的）。
    pub calls: &'a [u64],
    /// 主线程的第二个入口参数。
    pub arg: u64,
    /// CPU 上限（千分比；`None` = 不限）。
    pub cpu_limit_permille: Option<u32>,
}

/// 已创建的子进程。
/// A created child process.
#[derive(Debug)]
pub struct Child {
    /// 指向子进程的句柄（WAIT|SUBSCRIBE）；关闭它会终止仍在运行的子进程。
    pub process: Handle,
    /// 引导通道在父进程一侧的端点。
    pub channel: Channel,
}

/// 把调用 ID 列表转为位集合（ID ≥ 64 不可能被授予，按参数非法处理）。
fn mask(calls: &[u64]) -> Option<u64> {
    calls.iter().try_fold(0u64, |m, &id| (id < 64).then(|| m | 1 << id))
}

/// 创建子进程（见模块文档）。
/// Creates a child process.
pub fn spawn(spec: Spec<'_>) -> Result<Child> {
    let calls = mask(spec.calls).ok_or(crate::Error::INVALID_ARGUMENT)?;
    let d = SpawnDesc {
        image_ptr: spec.image.as_ptr() as u64,
        image_len: spec.image.len() as u64,
        calls,
        arg: spec.arg,
        cpu_limit_permille: spec.cpu_limit_permille.unwrap_or(CPU_UNLIMITED),
        ..Default::default()
    };
    let mut b = d.encode();
    // SAFETY：参数块与映像在调用期间有效；内核在返回前读完映像并写回输出字段。
    check(unsafe { sys::call3(ids::SYSTEM_PROCESS_SPAWN, b.as_mut_ptr() as u64, 0, 0) })?;
    let out = SpawnDesc::decode(&b);
    // SAFETY：内核刚放入本进程句柄表的两个新句柄。
    Ok(unsafe { Child { process: Handle::from_raw(out.out_process), channel: Channel::from_handle(Handle::from_raw(out.out_channel)) } })
}

impl Child {
    /// 等待子进程退出并返回退出码（按 32 位无符号值；故障为 [`FAULT_CODE`]）。
    /// Waits for the child to exit.
    pub fn wait(&self) -> Result<u64> {
        crate::task::wait_process(&self.process)
    }
}
