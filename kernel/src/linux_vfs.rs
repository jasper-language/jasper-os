//! Verification-only virtual read-only files for the unmodified Ubuntu loader.
//!
//! 职责：为动态 libc 验收暴露真实、未修改的上游 `libc.so.6` 字节和稳定虚拟身份。
//! 边界：不是生产 VFS，不接受任意宿主路径，也不暴露宿主机文件系统。
//! Responsibility: expose the exact unmodified upstream `libc.so.6` bytes and stable virtual
//! identities needed by the real loader. This is not the production VFS.

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

const HANDLE_BASE: u64 = 0xffff_0000_0000_0000;

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

    /// Returns the exact file bytes.
    ///
    /// 返回未修改的真实文件字节。
    pub const fn bytes(self) -> &'static [u8] {
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

/// Resolves one Linux-compatible absolute path to a verification file.
///
/// 解析已知绝对路径；其他路径（包括 `/etc/ld.so.cache`）返回 `None`，由调用者产生
/// `ENOENT`。只接受精确路径，不做前缀匹配或宿主重定向。
pub fn lookup(path: &[u8]) -> Option<FileId> {
    if !cfg!(feature = "compat-dynamic-libc-verify") {
        return None;
    }
    match path {
        b"/lib/x86_64-linux-gnu/libc.so.6" | b"/usr/lib/x86_64-linux-gnu/libc.so.6" => {
            Some(FileId::Libc)
        }
        b"/lib/x86_64-linux-gnu/libsystemd.so.0"
        | b"/usr/lib/x86_64-linux-gnu/libsystemd.so.0" => Some(FileId::LibSystemd),
        b"/lib/x86_64-linux-gnu/libselinux.so.1"
        | b"/usr/lib/x86_64-linux-gnu/libselinux.so.1" => Some(FileId::LibSelinux),
        b"/lib/x86_64-linux-gnu/libgcc_s.so.1"
        | b"/usr/lib/x86_64-linux-gnu/libgcc_s.so.1" => Some(FileId::LibGccS),
        b"/lib/x86_64-linux-gnu/libm.so.6" | b"/usr/lib/x86_64-linux-gnu/libm.so.6" => {
            Some(FileId::LibM)
        }
        b"/lib/x86_64-linux-gnu/libpcre2-8.so.0"
        | b"/usr/lib/x86_64-linux-gnu/libpcre2-8.so.0" => Some(FileId::LibPcre2),
        _ => None,
    }
}

/// Returns whether the verification slice contains any bytes.
///
/// 验证据此明确真实 libc fixture 非空，而不是以空文件制造成功。
pub fn fixture_nonempty() -> bool {
    cfg!(feature = "compat-dynamic-libc-verify") && !LIBC.is_empty()
}
