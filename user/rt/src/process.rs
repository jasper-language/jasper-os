//! 子进程：从内存中的 ELF 映像创建，只授予调用者自己权力的子集。
//! Child processes created from an in-memory ELF image with a subset of the caller's rights.
//!
//! 内核语义（`system.process.spawn`）：
//! * [`Spec::calls`] 是显式 [`CallSet`]；构造时只接受登记操作，重复、未登记或越界 ID 整体拒绝
//! * 子进程的系统调用集合必须是调用者集合的子集，否则 `rights_denied`
//! * 子进程起步时只有一个句柄：与父进程相连的引导通道端点（主线程入口参数 0）；其它句柄只能由父进程经该通道发送
//! * 父进程得到的 [`Child::process`] 是子进程唯一的外部所有权：它被关闭（或父进程退出）时子进程若仍在运行即被终止
//! * 全有或全无：失败时不留下子进程、句柄或配额占用

use kernel_core::spawn_abi::{SpawnDesc, CPU_UNLIMITED};
use kernel_core::syscall_set::SyscallSet;

use crate::channel::Channel;
use crate::error::{check, Result};
use crate::handle::Handle;
use crate::{ids, sys};

pub use kernel_core::syscall_set::CallIdError as CallSetError;

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
    /// 授予子进程的显式系统调用能力集合（每一个都必须是调用者自己持有的子集）。
    pub calls: CallSet,
    /// 主线程的第二个入口参数。
    pub arg: u64,
    /// CPU 上限（千分比；`None` = 不限）。
    pub cpu_limit_permille: Option<u32>,
}

/// 用户态显式系统调用能力集合。
///
/// 内部唯一状态是内核的 [`SyscallSet`]；本类型不定义第二套位语义、序列化或授权通道。
/// 构造时只接受登记表中的操作 ID，并拒绝越界、未登记和重复输入。其私有字段保证调用者
/// 不能绕过这些检查直接向 spawn 参数块写入任意位图。
/// Explicit user-space call capability set backed by the kernel's sole `SyscallSet`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallSet {
    set: SyscallSet,
}

impl CallSet {
    /// 规范能力集合的线上字节数。
    pub const BYTES: usize = kernel_core::syscall_set::BYTES;

    /// 空能力集合；spawn 仍允许创建不持有任何系统调用的子进程。
    /// Empty capability set.
    pub const EMPTY: CallSet = CallSet { set: SyscallSet::EMPTY };

    /// 严格从操作 ID 构造集合；任一越界、未登记或重复 ID 都使整个构造失败。
    /// Strictly constructs a set and rejects the whole request on any invalid ID.
    pub fn try_from_ids(ids: &[u64]) -> core::result::Result<CallSet, CallSetError> {
        SyscallSet::try_from_ids(ids, ids::REGISTERED_CALLS).map(|set| CallSet { set })
    }

    /// 加入一个已登记操作；失败时集合保持不变。
    /// Adds one registered operation, leaving the set unchanged on failure.
    pub fn try_insert(&mut self, id: u64) -> core::result::Result<(), CallSetError> {
        self.set = self.set.try_with_id(id, ids::REGISTERED_CALLS)?;
        Ok(())
    }

    /// 集合是否包含指定操作 ID。
    /// Whether this set contains the operation ID.
    pub const fn contains(self, id: u64) -> bool {
        self.set.contains(id)
    }

    /// 集合中的操作数。
    /// Number of operations in the set.
    pub const fn len(self) -> usize {
        self.set.count()
    }

    /// 把小端规范位图写入调用方提供的 32 字节缓冲区。
    ///
    /// 这只是既有 [`SyscallSet`] 的线上编码，不提供第二套集合表示；缓冲区应由
    /// [`crate::process::spawn`] 或 [`crate::task::set_calls`] 在调用期间保持有效。
    pub fn encode(self, out: &mut [u8; Self::BYTES]) {
        self.set.encode(out);
    }
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

/// 创建子进程（见模块文档）。
/// Creates a child process.
pub fn spawn(spec: Spec<'_>) -> Result<Child> {
    let d = SpawnDesc {
        image_ptr: spec.image.as_ptr() as u64,
        image_len: spec.image.len() as u64,
        calls: spec.calls.set,
        arg: spec.arg,
        cpu_limit_permille: spec.cpu_limit_permille.unwrap_or(CPU_UNLIMITED),
        ..Default::default()
    };
    let mut b = d.encode();
    // SAFETY：参数块与映像在调用期间有效；内核在返回前读完映像并写回输出字段。
    check(unsafe { sys::call3(ids::SYSTEM_PROCESS_SPAWN, b.as_mut_ptr() as u64, 0, 0) })?;
    let out = SpawnDesc::decode(&b).map_err(|_| crate::Error::INVALID_ARGUMENT)?;
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
