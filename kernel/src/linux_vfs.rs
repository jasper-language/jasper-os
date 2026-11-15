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
const ROOT_LIBRARY_SLOTS: usize = 96;
#[cfg(feature = "lifecycle-root-exec-verify")]
static ROOT_LIBRARIES: [Once<Vec<u8>>; ROOT_LIBRARY_SLOTS] =
    [const { Once::new() }; ROOT_LIBRARY_SLOTS];
#[cfg(feature = "lifecycle-root-exec-verify")]
static ROOT_EXECUTABLES: Mutex<ExecutableRegistry> = Mutex::new(ExecutableRegistry::new());
#[cfg(feature = "lifecycle-root-exec-verify")]
static ROOT_ORIGIN: Mutex<Option<SystemImage>> = Mutex::new(None);
#[cfg(feature = "lifecycle-root-exec-verify")]
static ROOT_SOURCE: Mutex<Option<RootImageSource>> = Mutex::new(None);

#[cfg(feature = "lifecycle-root-exec-verify")]
const ROOT_INTERPRETER_PATH: &str = "/lib64/ld-linux-x86-64.so.2";

pub(crate) const ANDROID_FILE_PATHS: &[&[u8]] = &[
    b"/system/bin/linker64",
    b"/system/bin/toybox",
    b"/system/bin/sh",
    b"/system/bin/dalvikvm64",
    b"/system/lib64/libc.so",
    b"/system/lib64/libm.so",
    b"/system/lib64/libdl.so",
    b"/system/lib64/libdl_android.so",
    b"/system/lib64/libc++.so",
    b"/system/lib64/libbase.so",
    b"/system/lib64/liblog.so",
    b"/system/lib64/libcrypto.so",
    b"/system/lib64/libz.so",
    b"/system/lib64/libprocessgroup.so",
    b"/system/lib64/libselinux.so",
    b"/system/lib64/libcgrouprc.so",
    b"/system/lib64/libpcre2.so",
    b"/system/lib64/libpackagelistparser.so",
    b"/system/lib64/libstatssocket.so",
    b"/system/lib64/libart.so",
    b"/system/lib64/libartbase.so",
    b"/system/lib64/libartpalette.so",
    b"/system/lib64/libdexfile.so",
    b"/system/lib64/libart-compiler.so",
    b"/system/lib64/libnativehelper.so",
    b"/system/lib64/libsigchain.so",
    b"/system/lib64/liblz4.so",
    b"/system/lib64/liblzma.so",
    b"/system/lib64/libnativebridge.so",
    b"/system/lib64/libnativeloader.so",
    b"/system/lib64/libunwindstack.so",
    b"/system/lib64/libprofile.so",
    b"/system/lib64/libartpalette-system.so",
    b"/system/lib64/heapprofd_client_api.so",
    b"/system/lib64/libprocinfo.so",
    b"/system/lib64/libnetd_client.so",
    b"/system/lib64/libcutils.so",
    b"/system/lib64/libtombstoned_client.so",
    b"/system/lib64/libjavacore.so",
    b"/system/lib64/libandroidicu.so",
    b"/system/lib64/libicu.so",
    b"/system/lib64/libicu_jni.so",
    b"/system/lib64/libicui18n.so",
    b"/system/lib64/libicuuc.so",
    b"/system/framework/core-oj.jar",
    b"/system/framework/core-libart.jar",
    b"/system/framework/apache-xml.jar",
    b"/system/framework/bouncycastle.jar",
    b"/system/framework/boot.art",
    b"/system/framework/boot.oat",
    b"/system/framework/boot.vdex",
    b"/system/framework/x86_64/boot.oat",
    b"/system/framework/x86_64/boot.art",
    b"/system/framework/x86_64/boot-core-libart.oat",
    b"/system/framework/x86_64/boot-core-libart.art",
    b"/system/framework/boot-core-libart.vdex",
    b"/system/etc/public.libraries.txt",
    b"/data/local/tmp/classes.dex",
    b"/data/local/tmp/app.apk",
    b"/apex/com.android.art/javalib/core-oj.jar",
    b"/apex/com.android.art/javalib/core-libart.jar",
    b"/apex/com.android.i18n/javalib/core-icu4j.jar",
    b"/apex/com.android.i18n/etc/icu/icudt72l.dat",
    b"/apex/com.android.i18n/lib64/libandroidicu.so",
    b"/apex/com.android.i18n/lib64/libicu.so",
    b"/apex/com.android.i18n/lib64/libicu_jni.so",
    b"/apex/com.android.i18n/lib64/libicui18n.so",
    b"/apex/com.android.i18n/lib64/libicuuc.so",
    b"/linkerconfig/ld.config.txt",
    b"/system/lib64/libandroidio.so",
    b"/system/lib64/libexpat.so",
    b"/system/lib64/libopenjdk.so",
    b"/system/lib64/libopenjdkjvm.so",
    b"/data/local/tmp/art-official-001.dex",
    b"/data/local/tmp/art-official-002.dex",
    b"/data/local/tmp/art-official-003.dex",
    b"/usr/lib/x86_64-linux-gnu/libvulkan.so.1",
    b"/usr/lib/x86_64-linux-gnu/libvk_swiftshader.so",
    b"/usr/lib/x86_64-linux-gnu/vk_swiftshader_icd.json",
    b"/usr/lib/x86_64-linux-gnu/libdl.so.2",
    b"/usr/lib/x86_64-linux-gnu/libpthread.so.0",
    b"/usr/lib/x86_64-linux-gnu/runtime_examples.air",
    b"/usr/bin/llvm-as",
    b"/sys/devices/system/cpu/online",
    b"/proc/stat",
    b"/SwiftShader.ini",
];

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
    /// One bounded upstream Android file staged under `/system` or `/data`.
    AndroidFile(u8),
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
            Self::AndroidFile(slot) => 0x4000 + slot as u64,
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
                Self::AndroidFile(slot) => 0x8000 + slot as u64,
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
            value if value >= (HANDLE_BASE | 0x8000)
                && value <= (HANDLE_BASE | 0x80ff) =>
            {
                Some(Self::AndroidFile((value - (HANDLE_BASE | 0x8000)) as u8))
            }
            _ => None,
        }
    }

    /// Stable canonical namespace path exposed to open-by-handle consumers.
    pub fn path(self) -> &'static [u8] {
        match self {
            Self::Libc => b"/usr/lib/x86_64-linux-gnu/libc.so.6",
            Self::LibSystemd => b"/usr/lib/x86_64-linux-gnu/libsystemd.so.0",
            Self::LibSelinux => b"/usr/lib/x86_64-linux-gnu/libselinux.so.1",
            Self::LibGccS => b"/usr/lib/x86_64-linux-gnu/libgcc_s.so.1",
            Self::LibM => b"/usr/lib/x86_64-linux-gnu/libm.so.6",
            Self::LibPcre2 => b"/usr/lib/x86_64-linux-gnu/libpcre2-8.so.0",
            Self::AndroidFile(slot) => ANDROID_FILE_PATHS
                .get(slot as usize)
                .copied()
                .unwrap_or(b"/system"),
            Self::IoProbe => b"/io-probe",
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
            Self::AndroidFile(slot) => 6 + slot as usize,
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
            #[cfg(feature = "lifecycle-root-exec-verify")]
            Self::AndroidFile(slot) => ROOT_LIBRARIES
                .get(usize::from(slot) + 6)
                .and_then(Once::get)
                .map_or(&[], Vec::as_slice),
            #[cfg(not(feature = "lifecycle-root-exec-verify"))]
            Self::AndroidFile(_) => &[],
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
    System,
    SystemBin,
    SystemLib64,
    SystemFramework,
    SystemEtc,
    Apex,
    ApexArt,
    ApexArtJavalib,
    ApexI18n,
    ApexI18nJavalib,
    ApexI18nEtc,
    ApexI18nEtcIcu,
    ApexI18nLib64,
    LinkerConfig,
    Data,
    DataLocal,
    DataLocalTmp,
    DataCache,
    DataCacheMetal,
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
            Self::System => 7,
            Self::SystemBin => 8,
            Self::SystemLib64 => 9,
            Self::SystemFramework => 10,
            Self::SystemEtc => 11,
            Self::Apex => 12,
            Self::ApexArt => 13,
            Self::ApexArtJavalib => 14,
            Self::ApexI18n => 15,
            Self::ApexI18nJavalib => 16,
            Self::ApexI18nEtc => 17,
            Self::ApexI18nEtcIcu => 18,
            Self::ApexI18nLib64 => 19,
            Self::LinkerConfig => 20,
            Self::Data => 21,
            Self::DataLocal => 22,
            Self::DataLocalTmp => 23,
            Self::DataCache => 24,
            Self::DataCacheMetal => 25,
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
            Self::System => 8,
            Self::SystemBin => 9,
            Self::SystemLib64 => 10,
            Self::SystemFramework => 11,
            Self::SystemEtc => 12,
            Self::Apex => 13,
            Self::ApexArt => 14,
            Self::ApexArtJavalib => 15,
            Self::ApexI18n => 16,
            Self::ApexI18nJavalib => 17,
            Self::ApexI18nEtc => 18,
            Self::ApexI18nEtcIcu => 19,
            Self::ApexI18nLib64 => 20,
            Self::LinkerConfig => 21,
            Self::Data => 22,
            Self::DataLocal => 23,
            Self::DataLocalTmp => 24,
            Self::DataCache => 25,
            Self::DataCacheMetal => 26,
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
            value if value == (DIRECTORY_HANDLE_BASE | 8) => Some(Self::System),
            value if value == (DIRECTORY_HANDLE_BASE | 9) => Some(Self::SystemBin),
            value if value == (DIRECTORY_HANDLE_BASE | 10) => Some(Self::SystemLib64),
            value if value == (DIRECTORY_HANDLE_BASE | 11) => Some(Self::SystemFramework),
            value if value == (DIRECTORY_HANDLE_BASE | 12) => Some(Self::SystemEtc),
            value if value == (DIRECTORY_HANDLE_BASE | 13) => Some(Self::Apex),
            value if value == (DIRECTORY_HANDLE_BASE | 14) => Some(Self::ApexArt),
            value if value == (DIRECTORY_HANDLE_BASE | 15) => Some(Self::ApexArtJavalib),
            value if value == (DIRECTORY_HANDLE_BASE | 16) => Some(Self::ApexI18n),
            value if value == (DIRECTORY_HANDLE_BASE | 17) => Some(Self::ApexI18nJavalib),
            value if value == (DIRECTORY_HANDLE_BASE | 18) => Some(Self::ApexI18nEtc),
            value if value == (DIRECTORY_HANDLE_BASE | 19) => Some(Self::ApexI18nEtcIcu),
            value if value == (DIRECTORY_HANDLE_BASE | 20) => Some(Self::ApexI18nLib64),
            value if value == (DIRECTORY_HANDLE_BASE | 21) => Some(Self::LinkerConfig),
            value if value == (DIRECTORY_HANDLE_BASE | 22) => Some(Self::Data),
            value if value == (DIRECTORY_HANDLE_BASE | 23) => Some(Self::DataLocal),
            value if value == (DIRECTORY_HANDLE_BASE | 24) => Some(Self::DataLocalTmp),
            value if value == (DIRECTORY_HANDLE_BASE | 25) => Some(Self::DataCache),
            value if value == (DIRECTORY_HANDLE_BASE | 26) => Some(Self::DataCacheMetal),
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
            Self::System => b"/system",
            Self::SystemBin => b"/system/bin",
            Self::SystemLib64 => b"/system/lib64",
            Self::SystemFramework => b"/system/framework",
            Self::SystemEtc => b"/system/etc",
            Self::Apex => b"/apex",
            Self::ApexArt => b"/apex/com.android.art",
            Self::ApexArtJavalib => b"/apex/com.android.art/javalib",
            Self::ApexI18n => b"/apex/com.android.i18n",
            Self::ApexI18nJavalib => b"/apex/com.android.i18n/javalib",
            Self::ApexI18nEtc => b"/apex/com.android.i18n/etc",
            Self::ApexI18nEtcIcu => b"/apex/com.android.i18n/etc/icu",
            Self::ApexI18nLib64 => b"/apex/com.android.i18n/lib64",
            Self::LinkerConfig => b"/linkerconfig",
            Self::Data => b"/data",
            Self::DataLocal => b"/data/local",
            Self::DataLocalTmp => b"/data/local/tmp",
            Self::DataCache => b"/data/.cache",
            Self::DataCacheMetal => b"/data/.cache/metal2vulkan",
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
    if let Some(index) = ANDROID_FILE_PATHS
        .iter()
        .position(|candidate| *candidate == path)
    {
        return Some(FileId::AndroidFile(index as u8));
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
        b"/lib/libvulkan.so.1" | b"/usr/lib/libvulkan.so.1" => {
            Some(FileId::AndroidFile(76))
        }
        b"/lib/libvk_swiftshader.so" | b"/usr/lib/libvk_swiftshader.so" => {
            Some(FileId::AndroidFile(77))
        }
        b"/lib/vk_swiftshader_icd.json" | b"/usr/lib/vk_swiftshader_icd.json" => {
            Some(FileId::AndroidFile(78))
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
        b"/system" => Some(DirectoryId::System),
        b"/system/bin" => Some(DirectoryId::SystemBin),
        b"/system/lib64" => Some(DirectoryId::SystemLib64),
        b"/system/framework" => Some(DirectoryId::SystemFramework),
        b"/system/etc" => Some(DirectoryId::SystemEtc),
        b"/apex" => Some(DirectoryId::Apex),
        b"/apex/com.android.art" => Some(DirectoryId::ApexArt),
        b"/apex/com.android.art/javalib" => Some(DirectoryId::ApexArtJavalib),
        b"/apex/com.android.i18n" => Some(DirectoryId::ApexI18n),
        b"/apex/com.android.i18n/javalib" => Some(DirectoryId::ApexI18nJavalib),
        b"/apex/com.android.i18n/etc" => Some(DirectoryId::ApexI18nEtc),
        b"/apex/com.android.i18n/etc/icu" => Some(DirectoryId::ApexI18nEtcIcu),
        b"/apex/com.android.i18n/lib64" => Some(DirectoryId::ApexI18nLib64),
        b"/linkerconfig" => Some(DirectoryId::LinkerConfig),
        b"/data" => Some(DirectoryId::Data),
        b"/data/local" => Some(DirectoryId::DataLocal),
        b"/data/local/tmp" => Some(DirectoryId::DataLocalTmp),
        b"/data/.cache" => Some(DirectoryId::DataCache),
        b"/data/.cache/metal2vulkan" => Some(DirectoryId::DataCacheMetal),
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
        b"/system" => Some(DirectoryId::System),
        b"/system/bin" => Some(DirectoryId::SystemBin),
        b"/system/lib64" => Some(DirectoryId::SystemLib64),
        b"/system/framework" => Some(DirectoryId::SystemFramework),
        b"/system/etc" => Some(DirectoryId::SystemEtc),
        b"/apex" => Some(DirectoryId::Apex),
        b"/apex/com.android.art" => Some(DirectoryId::ApexArt),
        b"/apex/com.android.art/javalib" => Some(DirectoryId::ApexArtJavalib),
        b"/apex/com.android.i18n" => Some(DirectoryId::ApexI18n),
        b"/apex/com.android.i18n/javalib" => Some(DirectoryId::ApexI18nJavalib),
        b"/apex/com.android.i18n/etc" => Some(DirectoryId::ApexI18nEtc),
        b"/apex/com.android.i18n/etc/icu" => Some(DirectoryId::ApexI18nEtcIcu),
        b"/apex/com.android.i18n/lib64" => Some(DirectoryId::ApexI18nLib64),
        b"/linkerconfig" => Some(DirectoryId::LinkerConfig),
        b"/data" => Some(DirectoryId::Data),
        b"/data/local" => Some(DirectoryId::DataLocal),
        b"/data/local/tmp" => Some(DirectoryId::DataLocalTmp),
        b"/data/.cache" => Some(DirectoryId::DataCache),
        b"/data/.cache/metal2vulkan" => Some(DirectoryId::DataCacheMetal),
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
        DirEntry {
            name: b"system",
            node: Node::Directory(DirectoryId::System),
        },
        DirEntry {
            name: b"apex",
            node: Node::Directory(DirectoryId::Apex),
        },
        DirEntry {
            name: b"linkerconfig",
            node: Node::Directory(DirectoryId::LinkerConfig),
        },
        DirEntry {
            name: b"data",
            node: Node::Directory(DirectoryId::Data),
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
        DirEntry {
            name: b"libvulkan.so.1",
            node: Node::File(FileId::AndroidFile(76)),
        },
        DirEntry {
            name: b"libvk_swiftshader.so",
            node: Node::File(FileId::AndroidFile(77)),
        },
        DirEntry {
            name: b"vk_swiftshader_icd.json",
            node: Node::File(FileId::AndroidFile(78)),
        },
        DirEntry {
            name: b"libdl.so.2",
            node: Node::File(FileId::AndroidFile(79)),
        },
        DirEntry {
            name: b"libpthread.so.0",
            node: Node::File(FileId::AndroidFile(80)),
        },
        DirEntry {
            name: b"runtime_examples.air",
            node: Node::File(FileId::AndroidFile(81)),
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
            name: b"llvm-as",
            node: Node::File(FileId::AndroidFile(82)),
        },
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
    const SYSTEM: &[DirEntry] = &[
        DirEntry {
            name: b"bin",
            node: Node::Directory(DirectoryId::SystemBin),
        },
        DirEntry {
            name: b"lib64",
            node: Node::Directory(DirectoryId::SystemLib64),
        },
        DirEntry {
            name: b"framework",
            node: Node::Directory(DirectoryId::SystemFramework),
        },
        DirEntry {
            name: b"etc",
            node: Node::Directory(DirectoryId::SystemEtc),
        },
    ];
    const SYSTEM_BIN: &[DirEntry] = &[
        DirEntry {
            name: b"linker64",
            node: Node::File(FileId::AndroidFile(0)),
        },
        DirEntry {
            name: b"toybox",
            node: Node::File(FileId::AndroidFile(1)),
        },
        DirEntry {
            name: b"sh",
            node: Node::File(FileId::AndroidFile(2)),
        },
        DirEntry {
            name: b"dalvikvm64",
            node: Node::File(FileId::AndroidFile(3)),
        },
    ];
    const SYSTEM_LIB64: &[DirEntry] = &[
        DirEntry { name: b"libc.so", node: Node::File(FileId::AndroidFile(4)) },
        DirEntry { name: b"libm.so", node: Node::File(FileId::AndroidFile(5)) },
        DirEntry { name: b"libdl.so", node: Node::File(FileId::AndroidFile(6)) },
        DirEntry { name: b"libdl_android.so", node: Node::File(FileId::AndroidFile(7)) },
        DirEntry { name: b"libc++.so", node: Node::File(FileId::AndroidFile(8)) },
        DirEntry { name: b"libbase.so", node: Node::File(FileId::AndroidFile(9)) },
        DirEntry { name: b"liblog.so", node: Node::File(FileId::AndroidFile(10)) },
        DirEntry { name: b"libcrypto.so", node: Node::File(FileId::AndroidFile(11)) },
        DirEntry { name: b"libz.so", node: Node::File(FileId::AndroidFile(12)) },
        DirEntry { name: b"libprocessgroup.so", node: Node::File(FileId::AndroidFile(13)) },
        DirEntry { name: b"libselinux.so", node: Node::File(FileId::AndroidFile(14)) },
        DirEntry { name: b"libcgrouprc.so", node: Node::File(FileId::AndroidFile(15)) },
        DirEntry { name: b"libpcre2.so", node: Node::File(FileId::AndroidFile(16)) },
        DirEntry { name: b"libpackagelistparser.so", node: Node::File(FileId::AndroidFile(17)) },
        DirEntry { name: b"libstatssocket.so", node: Node::File(FileId::AndroidFile(18)) },
        DirEntry { name: b"libart.so", node: Node::File(FileId::AndroidFile(19)) },
        DirEntry { name: b"libartbase.so", node: Node::File(FileId::AndroidFile(20)) },
        DirEntry { name: b"libartpalette.so", node: Node::File(FileId::AndroidFile(21)) },
        DirEntry { name: b"libdexfile.so", node: Node::File(FileId::AndroidFile(22)) },
        DirEntry { name: b"libart-compiler.so", node: Node::File(FileId::AndroidFile(23)) },
        DirEntry { name: b"libnativehelper.so", node: Node::File(FileId::AndroidFile(24)) },
        DirEntry { name: b"libsigchain.so", node: Node::File(FileId::AndroidFile(25)) },
        DirEntry { name: b"liblz4.so", node: Node::File(FileId::AndroidFile(26)) },
        DirEntry { name: b"liblzma.so", node: Node::File(FileId::AndroidFile(27)) },
        DirEntry { name: b"libnativebridge.so", node: Node::File(FileId::AndroidFile(28)) },
        DirEntry { name: b"libnativeloader.so", node: Node::File(FileId::AndroidFile(29)) },
        DirEntry { name: b"libunwindstack.so", node: Node::File(FileId::AndroidFile(30)) },
        DirEntry { name: b"libprofile.so", node: Node::File(FileId::AndroidFile(31)) },
        DirEntry { name: b"libartpalette-system.so", node: Node::File(FileId::AndroidFile(32)) },
        DirEntry { name: b"heapprofd_client_api.so", node: Node::File(FileId::AndroidFile(33)) },
        DirEntry { name: b"libprocinfo.so", node: Node::File(FileId::AndroidFile(34)) },
        DirEntry { name: b"libnetd_client.so", node: Node::File(FileId::AndroidFile(35)) },
        DirEntry { name: b"libcutils.so", node: Node::File(FileId::AndroidFile(36)) },
        DirEntry { name: b"libtombstoned_client.so", node: Node::File(FileId::AndroidFile(37)) },
        DirEntry { name: b"libjavacore.so", node: Node::File(FileId::AndroidFile(38)) },
        DirEntry { name: b"libandroidicu.so", node: Node::File(FileId::AndroidFile(39)) },
        DirEntry { name: b"libicu.so", node: Node::File(FileId::AndroidFile(40)) },
        DirEntry { name: b"libicu_jni.so", node: Node::File(FileId::AndroidFile(41)) },
        DirEntry { name: b"libicui18n.so", node: Node::File(FileId::AndroidFile(42)) },
        DirEntry { name: b"libicuuc.so", node: Node::File(FileId::AndroidFile(43)) },
    ];
    const SYSTEM_FRAMEWORK: &[DirEntry] = &[
        DirEntry { name: b"core-oj.jar", node: Node::File(FileId::AndroidFile(44)) },
        DirEntry { name: b"core-libart.jar", node: Node::File(FileId::AndroidFile(45)) },
        DirEntry { name: b"apache-xml.jar", node: Node::File(FileId::AndroidFile(46)) },
        DirEntry { name: b"bouncycastle.jar", node: Node::File(FileId::AndroidFile(47)) },
        DirEntry { name: b"boot.art", node: Node::File(FileId::AndroidFile(48)) },
        DirEntry { name: b"boot.oat", node: Node::File(FileId::AndroidFile(49)) },
        DirEntry { name: b"boot.vdex", node: Node::File(FileId::AndroidFile(50)) },
    ];
    const SYSTEM_ETC: &[DirEntry] = &[DirEntry {
        name: b"public.libraries.txt",
        node: Node::File(FileId::AndroidFile(56)),
    }];
    const APEX: &[DirEntry] = &[
        DirEntry {
            name: b"com.android.art",
            node: Node::Directory(DirectoryId::ApexArt),
        },
        DirEntry {
            name: b"com.android.i18n",
            node: Node::Directory(DirectoryId::ApexI18n),
        },
    ];
    const APEX_ART: &[DirEntry] = &[DirEntry {
        name: b"javalib",
        node: Node::Directory(DirectoryId::ApexArtJavalib),
    }];
    const APEX_ART_JAVALIB: &[DirEntry] = &[
        DirEntry { name: b"core-oj.jar", node: Node::File(FileId::AndroidFile(59)) },
        DirEntry { name: b"core-libart.jar", node: Node::File(FileId::AndroidFile(60)) },
    ];
    const APEX_I18N: &[DirEntry] = &[
        DirEntry {
            name: b"javalib",
            node: Node::Directory(DirectoryId::ApexI18nJavalib),
        },
        DirEntry {
            name: b"etc",
            node: Node::Directory(DirectoryId::ApexI18nEtc),
        },
        DirEntry {
            name: b"lib64",
            node: Node::Directory(DirectoryId::ApexI18nLib64),
        },
    ];
    const APEX_I18N_JAVALIB: &[DirEntry] = &[DirEntry {
        name: b"core-icu4j.jar",
        node: Node::File(FileId::AndroidFile(61)),
    }];
    const APEX_I18N_ETC: &[DirEntry] = &[DirEntry {
        name: b"icu",
        node: Node::Directory(DirectoryId::ApexI18nEtcIcu),
    }];
    const APEX_I18N_ETC_ICU: &[DirEntry] = &[DirEntry {
        name: b"icudt72l.dat",
        node: Node::File(FileId::AndroidFile(62)),
    }];
    const APEX_I18N_LIB64: &[DirEntry] = &[
        DirEntry { name: b"libandroidicu.so", node: Node::File(FileId::AndroidFile(63)) },
        DirEntry { name: b"libicu.so", node: Node::File(FileId::AndroidFile(64)) },
        DirEntry { name: b"libicu_jni.so", node: Node::File(FileId::AndroidFile(65)) },
        DirEntry { name: b"libicui18n.so", node: Node::File(FileId::AndroidFile(66)) },
        DirEntry { name: b"libicuuc.so", node: Node::File(FileId::AndroidFile(67)) },
    ];
    const LINKER_CONFIG: &[DirEntry] = &[DirEntry {
        name: b"ld.config.txt",
        node: Node::File(FileId::AndroidFile(68)),
    }];
    const DATA: &[DirEntry] = &[
        DirEntry {
            name: b"local",
            node: Node::Directory(DirectoryId::DataLocal),
        },
        DirEntry {
            name: b".cache",
            node: Node::Directory(DirectoryId::DataCache),
        },
    ];
    const DATA_LOCAL: &[DirEntry] = &[DirEntry {
        name: b"tmp",
        node: Node::Directory(DirectoryId::DataLocalTmp),
    }];
    const DATA_LOCAL_TMP: &[DirEntry] = &[
        DirEntry { name: b"classes.dex", node: Node::File(FileId::AndroidFile(57)) },
        DirEntry { name: b"app.apk", node: Node::File(FileId::AndroidFile(58)) },
        DirEntry { name: b"art-official-001.dex", node: Node::File(FileId::AndroidFile(73)) },
        DirEntry { name: b"art-official-002.dex", node: Node::File(FileId::AndroidFile(74)) },
        DirEntry { name: b"art-official-003.dex", node: Node::File(FileId::AndroidFile(75)) },
    ];
    const DATA_CACHE: &[DirEntry] = &[DirEntry {
        name: b"metal2vulkan",
        node: Node::Directory(DirectoryId::DataCacheMetal),
    }];
    match directory {
        DirectoryId::Root => ROOT,
        DirectoryId::Lib => LIB,
        DirectoryId::LibX86_64 | DirectoryId::UsrLibX86_64 => LIB_X86_64,
        DirectoryId::Usr => USR,
        DirectoryId::UsrBin => USR_BIN,
        DirectoryId::UsrLib => USR_LIB,
        DirectoryId::System => SYSTEM,
        DirectoryId::SystemBin => SYSTEM_BIN,
        DirectoryId::SystemLib64 => SYSTEM_LIB64,
        DirectoryId::SystemFramework => SYSTEM_FRAMEWORK,
        DirectoryId::SystemEtc => SYSTEM_ETC,
        DirectoryId::Apex => APEX,
        DirectoryId::ApexArt => APEX_ART,
        DirectoryId::ApexArtJavalib => APEX_ART_JAVALIB,
        DirectoryId::ApexI18n => APEX_I18N,
        DirectoryId::ApexI18nJavalib => APEX_I18N_JAVALIB,
        DirectoryId::ApexI18nEtc => APEX_I18N_ETC,
        DirectoryId::ApexI18nEtcIcu => APEX_I18N_ETC_ICU,
        DirectoryId::ApexI18nLib64 => APEX_I18N_LIB64,
        DirectoryId::LinkerConfig => LINKER_CONFIG,
        DirectoryId::Data => DATA,
        DirectoryId::DataLocal => DATA_LOCAL,
        DirectoryId::DataLocalTmp => DATA_LOCAL_TMP,
        DirectoryId::DataCache => DATA_CACHE,
        DirectoryId::DataCacheMetal => &[],
    }
}

/// Resolves one stable compatibility inode back to its read-only node.
pub fn node_from_inode(inode: u64) -> Option<Node> {
    const FILES: [FileId; 7] = [
        FileId::Libc,
        FileId::LibSystemd,
        FileId::LibSelinux,
        FileId::LibGccS,
        FileId::LibM,
        FileId::LibPcre2,
        FileId::IoProbe,
    ];
    if let Some(file) = FILES.into_iter().find(|file| file.inode() == inode) {
        return Some(Node::File(file));
    }
    fn search(directory: DirectoryId, inode: u64) -> Option<Node> {
        for entry in directory_entries(directory) {
            if entry.node.inode() == inode {
                return Some(entry.node);
            }
            if let Node::Directory(child) = entry.node {
                if let Some(node) = search(child, inode) {
                    return Some(node);
                }
            }
        }
        None
    }
    let root = DirectoryId::Root;
    if root.inode() == inode {
        Some(Node::Directory(root))
    } else {
        search(root, inode)
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

/// Installs one upstream Android file from the selected System A/B root.
#[cfg(feature = "lifecycle-root-exec-verify")]
pub fn install_root_android_file(path: &[u8], bytes: Vec<u8>) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let Some(index) = ANDROID_FILE_PATHS
        .iter()
        .position(|candidate| *candidate == path)
    else {
        return false;
    };
    let Some(slot) = ROOT_LIBRARIES.get(index + 6) else {
        return false;
    };
    slot.call_once(|| bytes);
    slot.get().is_some_and(|installed| !installed.is_empty())
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
