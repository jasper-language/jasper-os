//! Verification-only virtual read-only files for the unmodified Ubuntu loader.
//!
//! 职责：为动态 libc 验收暴露真实、未修改的上游 `libc.so.6` 字节和稳定虚拟身份。
//! 边界：不是生产 VFS，不接受任意宿主路径，也不暴露宿主机文件系统。
//! Responsibility: expose the exact unmodified upstream `libc.so.6` bytes and stable virtual
//! identities needed by the real loader. This is not the production VFS.

#[cfg(feature = "lifecycle-root-exec-verify")]
use alloc::sync::Arc;
#[cfg(feature = "lifecycle-root-exec-verify")]
use alloc::vec::Vec;
#[cfg(feature = "lifecycle-root-exec-verify")]
use spin::{Mutex, Once};
#[cfg(feature = "lifecycle-root-exec-verify")]
use compat_core::executable::{ExecutableRegistry, SystemImage};
#[cfg(feature = "lifecycle-root-exec-verify")]
use jasper_lifecycle_boot::P0_SYSTEM_BYTES;
#[cfg(feature = "lifecycle-root-exec-verify")]
use kernel_core::block::{self, Request, Terminal};
#[cfg(feature = "lifecycle-root-exec-verify")]
use kernel_core::ext4_view::{Ext4ByteSource, Ext4Reader, Ext4SourceError};

#[cfg(feature = "lifecycle-root-exec-verify")]
use crate::blk::BlockDevice;
#[cfg(feature = "lifecycle-root-exec-verify")]
use crate::sync::IrqSpinLock;

#[cfg(feature = "compat-dynamic-libc-verify")]
static LIBC: &[u8] = include_bytes!(env!("JSR_UBUNTU_LIBC"));
#[cfg(not(feature = "compat-dynamic-libc-verify"))]
static LIBC: &[u8] = &[];
#[cfg(feature = "compat-dynamic-libc-verify")]
static LIBSYSTEMD: &[u8] = include_bytes!(env!("JSR_UBUNTU_LIBSYSTEMD"));
#[cfg(not(feature = "compat-dynamic-libc-verify"))]
static LIBSYSTEMD: &[u8] = &[];
#[cfg(feature = "compat-dynamic-libc-verify")]
static LIBSELINUX: &[u8] = include_bytes!(env!("JSR_UBUNTU_LIBSELINUX"));
#[cfg(not(feature = "compat-dynamic-libc-verify"))]
static LIBSELINUX: &[u8] = &[];
#[cfg(feature = "compat-dynamic-libc-verify")]
static LIBGCC_S: &[u8] = include_bytes!(env!("JSR_UBUNTU_LIBGCC_S"));
#[cfg(not(feature = "compat-dynamic-libc-verify"))]
static LIBGCC_S: &[u8] = &[];
#[cfg(feature = "compat-dynamic-libc-verify")]
static LIBM: &[u8] = include_bytes!(env!("JSR_UBUNTU_LIBM"));
#[cfg(not(feature = "compat-dynamic-libc-verify"))]
static LIBM: &[u8] = &[];
#[cfg(feature = "compat-dynamic-libc-verify")]
static LIBPCRE2: &[u8] = include_bytes!(env!("JSR_UBUNTU_LIBPCRE2"));
#[cfg(not(feature = "compat-dynamic-libc-verify"))]
static LIBPCRE2: &[u8] = &[];
#[cfg(feature = "lifecycle-root-exec-verify")]
static ROOT_LIBRARIES: [Once<Vec<u8>>; 6] = [const { Once::new() }; 6];
#[cfg(feature = "lifecycle-root-exec-verify")]
static ROOT_EXECUTABLES: Mutex<ExecutableRegistry> = Mutex::new(ExecutableRegistry::new());
#[cfg(feature = "lifecycle-root-exec-verify")]
static ROOT_ORIGIN: Mutex<Option<SystemImage>> = Mutex::new(None);
#[cfg(feature = "lifecycle-root-exec-verify")]
static ROOT_SOURCE: Mutex<Option<RootImageSource>> = Mutex::new(None);

#[cfg(feature = "lifecycle-root-exec-verify")]
const ROOT_INTERPRETER_PATH: &str = "/lib64/ld-linux-x86-64.so.2";

#[cfg(feature = "lifecycle-root-exec-verify")]
#[derive(Clone)]
struct RootImageSource {
    device: Arc<IrqSpinLock<BlockDevice>>,
    start_lba: u64,
}

#[cfg(feature = "lifecycle-root-exec-verify")]
impl Ext4ByteSource for RootImageSource {
    fn read_exact(&mut self, offset: u64, dst: &mut [u8]) -> Result<(), Ext4SourceError> {
        let mut done = 0usize;
        let mut page = [0u8; block::IO_ALIGNMENT as usize];
        while done < dst.len() {
            let absolute = offset.checked_add(done as u64).ok_or(Ext4SourceError)?;
            let io_block = absolute / block::IO_ALIGNMENT;
            let inner = (absolute % block::IO_ALIGNMENT) as usize;
            let take = (dst.len() - done).min(page.len() - inner);
            if absolute
                .checked_add(take as u64)
                .filter(|end| *end <= P0_SYSTEM_BYTES)
                .is_none()
            {
                return Err(Ext4SourceError);
            }
            let sector = self
                .start_lba
                .checked_add(
                    io_block
                        .checked_mul(block::SECTORS_PER_IO_UNIT)
                        .ok_or(Ext4SourceError)?,
                )
                .ok_or(Ext4SourceError)?;
            let mut device = self.device.lock();
            if !matches!(
                device.execute(Request::read(sector, 1), false),
                Ok(Terminal::Completed)
            ) {
                return Err(Ext4SourceError);
            }
            device
                .copy_prefix(&mut page)
                .map_err(|_| Ext4SourceError)?;
            drop(device);
            dst[done..done + take].copy_from_slice(&page[inner..inner + take]);
            done += take;
        }
        Ok(())
    }
}

const HANDLE_BASE: u64 = 0xffff_0000_0000_0000;
const DIRECTORY_HANDLE_BASE: u64 = HANDLE_BASE | 0x1000;

/// Stable virtual file identities exposed by this verification slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileId {
    Libc,
    LibSystemd,
    LibSelinux,
    LibGccS,
    LibM,
    LibPcre2,
    /// Synthetic, non-empty data used only to exercise the real Linux read
    /// syscall path from a Workload-bound guest.
    IoProbe,
}

impl FileId {
    /// Returns a stable virtual inode unique within this read-only file namespace.
    ///
    /// 返回本只读虚拟命名空间内稳定的唯一 inode；动态装载器依赖它区分不同共享库。
    pub const fn inode(self) -> u64 {
        match self {
            Self::Libc => 1,
            Self::LibSystemd => 2,
            Self::LibSelinux => 3,
            Self::LibGccS => 4,
            Self::LibM => 5,
            Self::LibPcre2 => 6,
            Self::IoProbe => 7,
        }
    }

    /// Returns the non-zero virtual handle for this file.
    ///
    /// 返回本文件的非零虚拟句柄。
    pub const fn handle(self) -> u64 {
        HANDLE_BASE
            | match self {
                Self::Libc => 1,
                Self::LibSystemd => 2,
                Self::LibSelinux => 3,
                Self::LibGccS => 4,
                Self::LibM => 5,
                Self::LibPcre2 => 6,
                Self::IoProbe => 7,
            }
    }

    /// Resolves a virtual handle back to a file.
    ///
    /// 将虚拟句柄解析回文件；未知句柄返回 `None`。
    pub const fn from_handle(handle: u64) -> Option<Self> {
        match handle {
            value if value == (HANDLE_BASE | 1) => Some(Self::Libc),
            value if value == (HANDLE_BASE | 2) => Some(Self::LibSystemd),
            value if value == (HANDLE_BASE | 3) => Some(Self::LibSelinux),
            value if value == (HANDLE_BASE | 4) => Some(Self::LibGccS),
            value if value == (HANDLE_BASE | 5) => Some(Self::LibM),
            value if value == (HANDLE_BASE | 6) => Some(Self::LibPcre2),
            value if value == (HANDLE_BASE | 7) => Some(Self::IoProbe),
            _ => None,
        }
    }

    #[cfg(feature = "lifecycle-root-exec-verify")]
    const fn root_slot(self) -> Option<usize> {
        Some(match self {
            Self::Libc => 0,
            Self::LibSystemd => 1,
            Self::LibSelinux => 2,
            Self::LibGccS => 3,
            Self::LibM => 4,
            Self::LibPcre2 => 5,
            Self::IoProbe => return None,
        })
    }

    /// Returns the exact file bytes.
    ///
    /// 返回未修改的真实文件字节。
    pub fn bytes(self) -> &'static [u8] {
        #[cfg(feature = "lifecycle-root-exec-verify")]
        if let Some(slot) = self.root_slot() {
            if let Some(bytes) = ROOT_LIBRARIES[slot].get() {
                return bytes.as_slice();
            }
        }
        match self {
            Self::Libc => LIBC,
            Self::LibSystemd => LIBSYSTEMD,
            Self::LibSelinux => LIBSELINUX,
            Self::LibGccS => LIBGCC_S,
            Self::LibM => LIBM,
            Self::LibPcre2 => LIBPCRE2,
            Self::IoProbe => {
                #[cfg(feature = "workload-io-verify")]
                {
                    b"JASPERIO01234567"
                }
                #[cfg(not(feature = "workload-io-verify"))]
                {
                    &[]
                }
            }
        }
    }
}

/// Read-only compatibility directory identities.
///
/// 只读 Linux 兼容目录身份；这是可选 Linux rootfs 的验收视图，不是 Jasper 原生目录 ABI。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectoryId {
    Root,
    Lib,
    LibX86_64,
    Usr,
    UsrLib,
    UsrLibX86_64,
    UsrBin,
}

impl DirectoryId {
    /// Stable inode inside the compatibility namespace.
    ///
    /// 兼容命名空间内的稳定 inode。
    pub const fn inode(self) -> u64 {
        0x100
            + match self {
                Self::Root => 0,
                Self::Lib => 1,
                Self::LibX86_64 => 2,
                Self::Usr => 3,
                Self::UsrLib => 4,
                Self::UsrLibX86_64 => 5,
                Self::UsrBin => 6,
            }
    }

    /// Stable virtual handle.
    ///
    /// 稳定的虚拟目录句柄。
    pub const fn handle(self) -> u64 {
        DIRECTORY_HANDLE_BASE
            | match self {
                Self::Root => 1,
                Self::Lib => 2,
                Self::LibX86_64 => 3,
                Self::Usr => 4,
                Self::UsrLib => 5,
                Self::UsrLibX86_64 => 6,
                Self::UsrBin => 7,
            }
    }

    /// Resolves one virtual directory handle.
    ///
    /// 将虚拟句柄解析为目录；未知句柄返回 `None`。
    pub const fn from_handle(handle: u64) -> Option<Self> {
        match handle {
            value if value == (DIRECTORY_HANDLE_BASE | 1) => Some(Self::Root),
            value if value == (DIRECTORY_HANDLE_BASE | 2) => Some(Self::Lib),
            value if value == (DIRECTORY_HANDLE_BASE | 3) => Some(Self::LibX86_64),
            value if value == (DIRECTORY_HANDLE_BASE | 4) => Some(Self::Usr),
            value if value == (DIRECTORY_HANDLE_BASE | 5) => Some(Self::UsrLib),
            value if value == (DIRECTORY_HANDLE_BASE | 6) => Some(Self::UsrLibX86_64),
            value if value == (DIRECTORY_HANDLE_BASE | 7) => Some(Self::UsrBin),
            _ => None,
        }
    }

    /// Canonical path used only to resolve relative entries under this handle.
    ///
    /// 仅用于从目录句柄解析相对子项的规范路径；它不是原生授权凭证。
    pub const fn path(self) -> &'static [u8] {
        match self {
            Self::Root => b"/",
            Self::Lib => b"/lib",
            Self::LibX86_64 => b"/lib/x86_64-linux-gnu",
            Self::Usr => b"/usr",
            Self::UsrBin => b"/usr/bin",
            Self::UsrLib => b"/usr/lib",
            Self::UsrLibX86_64 => b"/usr/lib/x86_64-linux-gnu",
        }
    }
}

/// One node in the read-only compatibility namespace.
///
/// 只读兼容命名空间中的一个节点。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Node {
    File(FileId),
    /// Verification executable metadata without readable content.
    /// 仅暴露元数据、不提供内容读取的验收可执行文件。
    Executable(u64),
    Directory(DirectoryId),
}

impl Node {
    /// Whether this node is a directory.
    ///
    /// 是否为目录。
    pub const fn is_directory(self) -> bool {
        matches!(self, Self::Directory(_))
    }

    /// Stable compatibility inode for this node.
    ///
    /// 返回节点的稳定兼容 inode。
    pub const fn inode(self) -> u64 {
        match self {
            Self::File(file) => file.inode(),
            Self::Executable(inode) => inode,
            Self::Directory(directory) => directory.inode(),
        }
    }

    /// Linux `(size, link count, mode)` metadata for this node.
    ///
    /// 返回 Linux `(大小, 链接数, 模式)` 元数据。验收可执行文件只暴露稳定的可执行
    /// 文件属性，不提供可读内容，因此大小固定为 0。
    pub fn stat_metadata(self) -> (u64, u64, u32) {
        match self {
            Self::File(file) => (file.bytes().len() as u64, 1, 0o100444),
            Self::Executable(_) => (0, 1, 0o100555),
            Self::Directory(_) => (0, 2, 0o040555),
        }
    }
}

/// One named directory child.
///
/// 一个具名目录子项。
#[derive(Clone, Copy)]
pub struct DirEntry {
    pub name: &'static [u8],
    pub node: Node,
}

/// Resolves one Linux-compatible absolute path to a verification file.
///
/// 解析已知绝对路径；其他路径（包括 `/etc/ld.so.cache`）返回 `None`，由调用者产生
/// `ENOENT`。只接受精确路径，不做前缀匹配或宿主重定向。
pub fn lookup(path: &[u8]) -> Option<FileId> {
    if !cfg!(feature = "compat-dynamic-libc-verify")
        && !cfg!(feature = "lifecycle-root-exec-verify")
        && !cfg!(feature = "workload-io-verify")
    {
        return None;
    }
    match path {
        b"/lib/x86_64-linux-gnu/libc.so.6" | b"/usr/lib/x86_64-linux-gnu/libc.so.6" => {
            Some(FileId::Libc)
        }
        b"/lib/x86_64-linux-gnu/libsystemd.so.0" | b"/usr/lib/x86_64-linux-gnu/libsystemd.so.0" => {
            Some(FileId::LibSystemd)
        }
        b"/lib/x86_64-linux-gnu/libselinux.so.1" | b"/usr/lib/x86_64-linux-gnu/libselinux.so.1" => {
            Some(FileId::LibSelinux)
        }
        b"/lib/x86_64-linux-gnu/libgcc_s.so.1" | b"/usr/lib/x86_64-linux-gnu/libgcc_s.so.1" => {
            Some(FileId::LibGccS)
        }
        b"/lib/x86_64-linux-gnu/libm.so.6" | b"/usr/lib/x86_64-linux-gnu/libm.so.6" => {
            Some(FileId::LibM)
        }
        b"/lib/x86_64-linux-gnu/libpcre2-8.so.0" | b"/usr/lib/x86_64-linux-gnu/libpcre2-8.so.0" => {
            Some(FileId::LibPcre2)
        }
        #[cfg(feature = "workload-io-verify")]
        b"/io-probe" => Some(FileId::IoProbe),
        _ => None,
    }
}

/// Resolves one absolute path to a file or directory in the bounded namespace.
///
/// 将绝对路径解析为有界命名空间中的文件或目录；未知路径返回 `None`。
pub fn lookup_node(path: &[u8]) -> Option<Node> {
    let directory = match path {
        b"/" => Some(DirectoryId::Root),
        b"/lib" => Some(DirectoryId::Lib),
        b"/lib/x86_64-linux-gnu" => Some(DirectoryId::LibX86_64),
        b"/usr" => Some(DirectoryId::Usr),
        b"/usr/bin" => Some(DirectoryId::UsrBin),
        b"/usr/lib" => Some(DirectoryId::UsrLib),
        b"/usr/lib/x86_64-linux-gnu" => Some(DirectoryId::UsrLibX86_64),
        _ => None,
    };
    let exact = directory
        .map(Node::Directory)
        .or_else(|| lookup(path).map(Node::File));
    if exact.is_some() {
        return exact;
    }
    let separator = path.iter().rposition(|byte| *byte == b'/')?;
    let parent = if separator == 0 {
        b"/".as_slice()
    } else {
        &path[..separator]
    };
    let name = &path[separator + 1..];
    let directory = match parent {
        b"/" => Some(DirectoryId::Root),
        b"/lib" => Some(DirectoryId::Lib),
        b"/lib/x86_64-linux-gnu" => Some(DirectoryId::LibX86_64),
        b"/usr" => Some(DirectoryId::Usr),
        b"/usr/bin" => Some(DirectoryId::UsrBin),
        b"/usr/lib" => Some(DirectoryId::UsrLib),
        b"/usr/lib/x86_64-linux-gnu" => Some(DirectoryId::UsrLibX86_64),
        _ => None,
    }?;
    directory_entries(directory)
        .iter()
        .find(|entry| entry.name == name)
        .map(|entry| entry.node)
}

/// Returns the children of one compatibility directory.
///
/// 返回一个兼容目录的子项；`.` 与 `..` 由 `getdents64` 动态生成。
pub fn directory_entries(directory: DirectoryId) -> &'static [DirEntry] {
    const ROOT: &[DirEntry] = &[
        DirEntry {
            name: b"lib",
            node: Node::Directory(DirectoryId::Lib),
        },
        DirEntry {
            name: b"usr",
            node: Node::Directory(DirectoryId::Usr),
        },
    ];
    const LIB: &[DirEntry] = &[DirEntry {
        name: b"x86_64-linux-gnu",
        node: Node::Directory(DirectoryId::LibX86_64),
    }];
    const LIB_X86_64: &[DirEntry] = &[
        DirEntry {
            name: b"libc.so.6",
            node: Node::File(FileId::Libc),
        },
        DirEntry {
            name: b"libsystemd.so.0",
            node: Node::File(FileId::LibSystemd),
        },
        DirEntry {
            name: b"libselinux.so.1",
            node: Node::File(FileId::LibSelinux),
        },
        DirEntry {
            name: b"libgcc_s.so.1",
            node: Node::File(FileId::LibGccS),
        },
        DirEntry {
            name: b"libm.so.6",
            node: Node::File(FileId::LibM),
        },
        DirEntry {
            name: b"libpcre2-8.so.0",
            node: Node::File(FileId::LibPcre2),
        },
    ];
    const USR: &[DirEntry] = &[
        DirEntry {
            name: b"bin",
            node: Node::Directory(DirectoryId::UsrBin),
        },
        DirEntry {
            name: b"lib",
            node: Node::Directory(DirectoryId::UsrLib),
        },
    ];
    const USR_BIN: &[DirEntry] = &[
        DirEntry {
            name: b"basename",
            node: Node::Executable(0x3000),
        },
        DirEntry {
            name: b"dash",
            node: Node::Executable(0x3001),
        },
        DirEntry {
            name: b"dirname",
            node: Node::Executable(0x3002),
        },
        DirEntry {
            name: b"find",
            node: Node::Executable(0x3003),
        },
        DirEntry {
            name: b"getconf",
            node: Node::Executable(0x3004),
        },
        DirEntry {
            name: b"hostname",
            node: Node::Executable(0x3005),
        },
        DirEntry {
            name: b"id",
            node: Node::Executable(0x3006),
        },
        DirEntry {
            name: b"jasper-getppid",
            node: Node::Executable(0x3007),
        },
        DirEntry {
            name: b"jasper-signal-basic",
            node: Node::Executable(0x3008),
        },
        DirEntry {
            name: b"ls",
            node: Node::Executable(0x3009),
        },
        DirEntry {
            name: b"nproc",
            node: Node::Executable(0x300a),
        },
        DirEntry {
            name: b"printf",
            node: Node::Executable(0x300b),
        },
        DirEntry {
            name: b"pwd",
            node: Node::Executable(0x300c),
        },
        DirEntry {
            name: b"sleep",
            node: Node::Executable(0x300d),
        },
        DirEntry {
            name: b"true",
            node: Node::Executable(0x300e),
        },
        DirEntry {
            name: b"uname",
            node: Node::Executable(0x300f),
        },
        DirEntry {
            name: b"wc",
            node: Node::Executable(0x3010),
        },
    ];
    const USR_LIB: &[DirEntry] = &[DirEntry {
        name: b"x86_64-linux-gnu",
        node: Node::Directory(DirectoryId::UsrLibX86_64),
    }];
    match directory {
        DirectoryId::Root => ROOT,
        DirectoryId::Lib => LIB,
        DirectoryId::LibX86_64 | DirectoryId::UsrLibX86_64 => LIB_X86_64,
        DirectoryId::Usr => USR,
        DirectoryId::UsrBin => USR_BIN,
        DirectoryId::UsrLib => USR_LIB,
    }
}

/// Installs the libc bytes read from the selected System A/B root.
/// 安装从所选 System A/B 根卷读取的 libc 字节。
#[cfg(feature = "lifecycle-root-exec-verify")]
pub fn install_root_libc(bytes: Vec<u8>) -> bool {
    install_root_library(FileId::Libc, bytes)
}

/// Installs one known library from the selected System A/B root.
/// 安装一条来自所选 System A/B 根卷的已知共享库。
#[cfg(feature = "lifecycle-root-exec-verify")]
pub fn install_root_library(file: FileId, bytes: Vec<u8>) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let Some(slot) = file.root_slot() else {
        return false;
    };
    ROOT_LIBRARIES[slot].call_once(|| bytes);
    ROOT_LIBRARIES[slot]
        .get()
        .is_some_and(|installed| !installed.is_empty())
}

/// Registers one executable/interpreter pair from the selected System A/B root.
/// 从所选 System A/B 根卷登记一对可执行映像和解释器。
#[cfg(feature = "lifecycle-root-exec-verify")]
pub fn configure_root_image(
    origin: SystemImage,
    device: Arc<IrqSpinLock<BlockDevice>>,
    start_lba: u64,
) -> bool {
    let mut active = ROOT_ORIGIN.lock();
    if active.is_some_and(|selected| selected != origin) {
        return false;
    }
    let mut source = ROOT_SOURCE.lock();
    if source.is_some() {
        return *active == Some(origin)
            && source
                .as_ref()
                .is_some_and(|configured| configured.start_lba == start_lba);
    }
    *active = Some(origin);
    *source = Some(RootImageSource { device, start_lba });
    true
}

#[cfg(feature = "lifecycle-root-exec-verify")]
pub fn install_root_program(
    origin: SystemImage,
    path: &[u8],
    executable_len: usize,
    interpreter_len: usize,
) -> bool {
    let mut active = ROOT_ORIGIN.lock();
    if active.is_some_and(|selected| selected != origin) {
        return false;
    }
    let registered = ROOT_EXECUTABLES.lock().register_program(
        origin,
        path,
        executable_len,
        ROOT_INTERPRETER_PATH.as_bytes(),
        interpreter_len,
    );
    if registered.is_ok() {
        *active = Some(origin);
        true
    } else {
        false
    }
}

#[cfg(feature = "lifecycle-root-exec-verify")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootExecutableError {
    NotFound,
    Quota,
    Io,
}

/// Reads one declared image pair from the selected System root on demand.
///
/// 从所选 System 根按需读取已声明映像；成功解析不是 Jasper 执行授权。
#[cfg(feature = "lifecycle-root-exec-verify")]
pub fn root_executable(
    pid: kernel_core::objtable::ObjId,
    path: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), RootExecutableError> {
    let origin = (*ROOT_ORIGIN.lock()).ok_or(RootExecutableError::NotFound)?;
    let (logical_path, executable_len, interpreter_len) = {
        let executables = ROOT_EXECUTABLES.lock();
        let resolved = executables
            .resolve(origin, path)
            .map_err(|_| RootExecutableError::NotFound)?;
        (
            resolved.path,
            resolved.executable_len,
            resolved.interpreter_len,
        )
    };
    let bytes = u64::try_from(executable_len)
        .map_err(|_| RootExecutableError::Io)?
        .checked_add(
            u64::try_from(interpreter_len).map_err(|_| RootExecutableError::Io)?,
        )
        .ok_or(RootExecutableError::Io)?;
    let io = crate::workload::begin_process_io(pid, bytes, 2).map_err(|error| match error {
        kernel_core::workload::WorkloadError::Quota
        | kernel_core::workload::WorkloadError::InvalidState => RootExecutableError::Quota,
        _ => RootExecutableError::Io,
    })?;
    let source = ROOT_SOURCE
        .lock()
        .as_ref()
        .cloned()
        .ok_or(RootExecutableError::NotFound)?;
    let root = Ext4Reader::open(source).map_err(|_| RootExecutableError::Io)?;
    let logical_path =
        core::str::from_utf8(logical_path.as_bytes()).map_err(|_| RootExecutableError::Io)?;
    let executable = root
        .read_file(logical_path, executable_len)
        .map_err(|_| RootExecutableError::Io)?;
    let interpreter = root
        .read_file(ROOT_INTERPRETER_PATH, interpreter_len)
        .map_err(|_| RootExecutableError::Io)?;
    if executable.len() != executable_len || interpreter.len() != interpreter_len {
        return Err(RootExecutableError::Io);
    }
    io.commit();
    Ok((executable, interpreter))
}

/// Returns whether the verification slice contains any bytes.
///
/// 验证据此明确真实 libc fixture 非空，而不是以空文件制造成功。
pub fn fixture_nonempty() -> bool {
    cfg!(feature = "compat-dynamic-libc-verify") && !LIBC.is_empty()
}
