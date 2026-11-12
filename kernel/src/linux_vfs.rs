//! Verification-only virtual read-only files for the unmodified Ubuntu loader.
//!
//! 职责：为动态 libc 验收暴露真实、未修改的上游 `libc.so.6` 字节和稳定虚拟身份。
//! 边界：不是生产 VFS，不接受任意宿主路径，也不暴露宿主机文件系统。
//! Responsibility: expose the exact unmodified upstream `libc.so.6` bytes and stable virtual
//! identities needed by the real loader. This is not the production VFS.

#[cfg(feature = "lifecycle-root-exec-verify")]
use alloc::vec::Vec;
#[cfg(feature = "lifecycle-root-exec-verify")]
use spin::{Mutex, Once};

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
static ROOT_INTERPRETER: Once<Vec<u8>> = Once::new();
#[cfg(feature = "lifecycle-root-exec-verify")]
static ROOT_EXECUTABLES: Mutex<Vec<RootExecutable>> = Mutex::new(Vec::new());

#[cfg(feature = "lifecycle-root-exec-verify")]
struct RootExecutable {
    path: Vec<u8>,
    bytes: Vec<u8>,
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
            _ => None,
        }
    }

    #[cfg(feature = "lifecycle-root-exec-verify")]
    const fn root_slot(self) -> usize {
        match self {
            Self::Libc => 0,
            Self::LibSystemd => 1,
            Self::LibSelinux => 2,
            Self::LibGccS => 3,
            Self::LibM => 4,
            Self::LibPcre2 => 5,
        }
    }

    /// Returns the exact file bytes.
    ///
    /// 返回未修改的真实文件字节。
    pub fn bytes(self) -> &'static [u8] {
        #[cfg(feature = "lifecycle-root-exec-verify")]
        if let Some(bytes) = ROOT_LIBRARIES[self.root_slot()].get() {
            return bytes.as_slice();
        }
        match self {
            Self::Libc => LIBC,
            Self::LibSystemd => LIBSYSTEMD,
            Self::LibSelinux => LIBSELINUX,
            Self::LibGccS => LIBGCC_S,
            Self::LibM => LIBM,
            Self::LibPcre2 => LIBPCRE2,
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
    let slot = file.root_slot();
    ROOT_LIBRARIES[slot].call_once(|| bytes);
    ROOT_LIBRARIES[slot]
        .get()
        .is_some_and(|installed| !installed.is_empty())
}

/// Installs one exact executable read from the selected System A/B root.
/// 安装一个从所选 System A/B 根卷读取的精确可执行映像。
#[cfg(feature = "lifecycle-root-exec-verify")]
pub fn install_root_executable(path: &[u8], bytes: Vec<u8>) -> bool {
    const MAX_EXECUTABLES: usize = 64;
    const MAX_PATH: usize = 256;
    if path.is_empty()
        || path.len() > MAX_PATH
        || !path.starts_with(b"/")
        || bytes.is_empty()
    {
        return false;
    }
    let mut executables = ROOT_EXECUTABLES.lock();
    if let Some(existing) = executables.iter().find(|entry| entry.path == path) {
        return existing.bytes == bytes;
    }
    if executables.len() == MAX_EXECUTABLES {
        return false;
    }
    executables.push(RootExecutable {
        path: path.to_vec(),
        bytes,
    });
    true
}

/// Installs the exact root ELF interpreter used by executable images.
/// 安装可执行映像使用的根卷 ELF 解释器。
#[cfg(feature = "lifecycle-root-exec-verify")]
pub fn install_root_interpreter(bytes: Vec<u8>) -> bool {
    if bytes.is_empty() {
        return false;
    }
    ROOT_INTERPRETER.call_once(|| bytes);
    ROOT_INTERPRETER
        .get()
        .is_some_and(|installed| !installed.is_empty())
}

/// Returns cloned executable bytes and the interpreter for one trusted exact path.
/// 返回可信精确路径的可执行字节副本及解释器。
#[cfg(feature = "lifecycle-root-exec-verify")]
pub fn root_executable(path: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let bytes = ROOT_EXECUTABLES
        .lock()
        .iter()
        .find(|entry| entry.path == path)?
        .bytes
        .clone();
    let interpreter = ROOT_INTERPRETER.get()?.clone();
    Some((bytes, interpreter))
}

/// Returns whether the verification slice contains any bytes.
///
/// 验证据此明确真实 libc fixture 非空，而不是以空文件制造成功。
pub fn fixture_nonempty() -> bool {
    cfg!(feature = "compat-dynamic-libc-verify") && !LIBC.is_empty()
}
