//! P0 A/B 最小生产健康门。
//! Minimum production health gate for P0 A/B boots.
//!
//! 只有全部启动阶段、设备装配、首个用户程序、P0 GPT 校验和真实 virtio-blk 控制记录
//! 读写均通过后，本模块才把当前试启动槽确认为健康。它不挂载 System A/B 根映像，也不
//! 代表完整系统服务健康。
//! This module confirms the current trial slot only after all boot stages, device assembly,
//! the first user program, P0 GPT validation and real virtio-blk control I/O pass. It does
//! not mount the System A/B root images or represent full-service health.

use alloc::sync::Arc;

use crc::{Crc, CRC_32_ISO_HDLC};
use jasper_lifecycle_boot::{
    recover, BootControlError, ControlIo, ControlIoError, CONTROL_RECORD_BYTES, P0_CONTROL_A_LBA,
    P0_CONTROL_A_PARTITION_GUID, P0_CONTROL_A_TYPE_GUID, P0_CONTROL_B_LBA,
    P0_CONTROL_B_PARTITION_GUID, P0_CONTROL_B_TYPE_GUID, P0_DISK_GUID, P0_SYSTEM_A_LBA,
    P0_SYSTEM_B_LBA, P0_SYSTEM_BYTES, Slot,
};
#[cfg(not(feature = "lifecycle-health-fail-verify"))]
use jasper_lifecycle_boot::commit;
use jasper_lifecycle_boot::CommitError;
use kernel_core::block::{self, Request, Terminal};
use kernel_core::ext4_view::{Ext4ByteSource, Ext4Reader, Ext4SourceError};

use crate::blk::BlockDevice;
use crate::sync::IrqSpinLock;
#[cfg(any(
    not(feature = "lifecycle-health-fail-verify"),
    feature = "lifecycle-root-exec-verify"
))]
use crate::kprintln;
use crate::{mmio, pci, virtio};

const HEALTH_PAGES: u64 = 5;
const GPT_HEADER_LBA: u64 = 1;
const GPT_ENTRY_LBA: u64 = 2;
const GPT_HEADER_BYTES: usize = 92;
const GPT_ENTRY_BYTES: usize = 128;
const GPT_REVISION: u32 = 0x0001_0000;
const ELF_HEADER_BYTES: usize = 64;
const ROOT_TEXT_FILE_BYTES: usize = 256;
const ROOT_USERLAND_MANIFEST: &[u8] =
    b"arch=x86_64\nabi=linux\nentry=/bin/true\ninterpreter=/lib64/ld-linux-x86-64.so.2\nlibrary=/usr/lib/x86_64-linux-gnu/libc.so.6\n";
#[cfg(feature = "lifecycle-root-exec-verify")]
const ROOT_EXEC_PROBE_PATH: &str = "/usr/libexec/jasper/health-probe";

/// 健康门失败原因。
/// Health-gate failure reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthError {
    /// 当前平台没有可验证的 Jasper P0 磁盘。No verifiable Jasper P0 disk is present.
    Unsupported,
    /// virtio-blk 初始化或 I/O 失败。virtio-blk initialization or I/O failed.
    Block,
    /// GPT 保护性 MBR 不符。The protective MBR does not match.
    GptMbr,
    /// GPT 头字段、磁盘 GUID 或位置不符。The GPT header fields, disk GUID or locations do not match.
    GptHeader,
    /// GPT 头 CRC 不符。The GPT header CRC does not match.
    GptCrc,
    /// Control 分区项不符。A Control partition entry does not match.
    GptPartition,
    /// 所选系统 ext4 无法挂载。The selected system ext4 cannot be mounted.
    RootMount,
    /// 系统根卷标不符。The system-root label does not match.
    RootLabel,
    /// 系统根标识文件缺失或不可读。The root marker is missing or unreadable.
    RootFile,
    /// 系统根标识内容不符。The root marker content does not match.
    RootContent,
    /// 系统发布描述不符。The system release description does not match.
    RootRelease,
    /// 用户态入口清单不符。The userland entry manifest does not match.
    RootUserland,
    /// 必需用户态 ELF 缺失、不可执行或不是 x86-64 Linux ELF。
    /// A required userland ELF is missing, non-executable or not an x86-64 Linux ELF.
    RootPayload,
    /// 根卷 Linux 健康探针未能完成真实执行或资源回收。
    /// The root-backed Linux health probe failed execution or resource reclamation.
    RootExecute,
    /// 两份控制记录不能恢复。The two control records cannot be recovered.
    Recovery(BootControlError),
    /// 健康状态机拒绝当前槽。The health state machine rejected the current slot.
    State(BootControlError),
    /// 控制记录提交失败。Control-record commit failed.
    Commit(CommitError),
    /// 专用负向构建在健康门注入失败。The dedicated negative build injected a health failure.
    InjectedFailure,
}

impl HealthError {
    /// 稳定失败名。Stable failure name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unsupported => "unsupported",
            Self::Block => "block",
            Self::GptMbr => "gpt_mbr",
            Self::GptHeader => "gpt_header",
            Self::GptCrc => "gpt_crc",
            Self::GptPartition => "gpt_partition",
            Self::RootMount => "root_mount",
            Self::RootLabel => "root_label",
            Self::RootFile => "root_file",
            Self::RootContent => "root_content",
            Self::RootRelease => "root_release",
            Self::RootUserland => "root_userland",
            Self::RootPayload => "root_payload",
            Self::RootExecute => "root_execute",
            Self::Recovery(_) => "recovery",
            Self::State(_) => "state",
            Self::Commit(_) => "commit",
            Self::InjectedFailure => "injected_failure",
        }
    }
}

struct KernelControlIo {
    device: Arc<IrqSpinLock<BlockDevice>>,
}

impl KernelControlIo {
    fn read_page(&self, lba: u64) -> Result<[u8; block::IO_ALIGNMENT as usize], HealthError> {
        if !lba.is_multiple_of(block::SECTORS_PER_IO_UNIT) {
            return Err(HealthError::Block);
        }
        let mut device = self.device.lock();
        if !matches!(
            device.execute(Request::read(lba, 1), false),
            Ok(Terminal::Completed)
        ) {
            return Err(HealthError::Block);
        }
        let mut page = [0u8; block::IO_ALIGNMENT as usize];
        device
            .copy_prefix(&mut page)
            .map_err(|_| HealthError::Block)?;
        Ok(page)
    }

    fn read_gpt(&self) -> Result<alloc::vec::Vec<u8>, HealthError> {
        let mut device = self.device.lock();
        if !matches!(
            device.execute(Request::read(0, HEALTH_PAGES), false),
            Ok(Terminal::Completed)
        ) {
            return Err(HealthError::Block);
        }
        let mut bytes = alloc::vec![0u8; HEALTH_PAGES as usize * block::IO_ALIGNMENT as usize];
        device
            .copy_prefix(&mut bytes)
            .map_err(|_| HealthError::Block)?;
        Ok(bytes)
    }

    fn write_page(
        &self,
        lba: u64,
        page: &[u8; block::IO_ALIGNMENT as usize],
    ) -> Result<(), HealthError> {
        if !lba.is_multiple_of(block::SECTORS_PER_IO_UNIT) {
            return Err(HealthError::Block);
        }
        let mut device = self.device.lock();
        device
            .fill_pattern(0, page)
            .map_err(|_| HealthError::Block)?;
        if matches!(
            device.execute(Request::write(lba, 1, true), false),
            Ok(Terminal::Completed)
        ) {
            Ok(())
        } else {
            Err(HealthError::Block)
        }
    }

    fn copy_lba(copy: usize) -> Result<u64, ControlIoError> {
        match copy {
            0 => Ok(P0_CONTROL_A_LBA),
            1 => Ok(P0_CONTROL_B_LBA),
            _ => Err(ControlIoError::Failed),
        }
    }
}

impl ControlIo for KernelControlIo {
    fn write_copy(
        &mut self,
        copy: usize,
        bytes: &[u8; CONTROL_RECORD_BYTES],
    ) -> Result<(), ControlIoError> {
        let mut page = self
            .read_page(Self::copy_lba(copy)?)
            .map_err(|_| ControlIoError::Failed)?;
        page[..CONTROL_RECORD_BYTES].copy_from_slice(bytes);
        self.write_page(Self::copy_lba(copy)?, &page)
            .map_err(|_| ControlIoError::Failed)
    }

    fn flush(&mut self) -> Result<(), ControlIoError> {
        if matches!(
            self.device.lock().execute(Request::flush(), false),
            Ok(Terminal::Completed)
        ) {
            Ok(())
        } else {
            Err(ControlIoError::Failed)
        }
    }

    fn read_copy(
        &mut self,
        copy: usize,
        out: &mut [u8; CONTROL_RECORD_BYTES],
    ) -> Result<(), ControlIoError> {
        let page = self
            .read_page(Self::copy_lba(copy)?)
            .map_err(|_| ControlIoError::Failed)?;
        out.copy_from_slice(&page[..CONTROL_RECORD_BYTES]);
        Ok(())
    }
}

struct PartitionExt4Source {
    device: Arc<IrqSpinLock<BlockDevice>>,
    start_lba: u64,
}

impl Ext4ByteSource for PartitionExt4Source {
    fn read_exact(&mut self, offset: u64, dst: &mut [u8]) -> Result<(), Ext4SourceError> {
        let mut done = 0usize;
        let mut page = [0u8; block::IO_ALIGNMENT as usize];
        while done < dst.len() {
            let absolute = offset.checked_add(done as u64).ok_or(Ext4SourceError)?;
            let block = absolute / block::IO_ALIGNMENT;
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
                    block
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

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes[..4].try_into().expect("fixed u32 field"))
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes[..8].try_into().expect("fixed u64 field"))
}

fn validate_gpt(
    page: &[u8],
    capacity: u64,
) -> Result<(), HealthError> {
    let mbr = &page[..block::SECTOR_BYTES as usize];
    if mbr[510..512] != [0x55, 0xaa]
        || mbr[446 + 4] != 0xee
        || read_u32(&mbr[446 + 8..446 + 12]) != 1
    {
        return Err(HealthError::GptMbr);
    }
    let header =
        &page[block::SECTOR_BYTES as usize..block::SECTOR_BYTES as usize + GPT_HEADER_BYTES];
    if &header[..8] != b"EFI PART"
        || read_u32(&header[8..12]) != GPT_REVISION
        || read_u32(&header[12..16]) as usize != GPT_HEADER_BYTES
        || read_u64(&header[24..32]) != GPT_HEADER_LBA
        || read_u64(&header[72..80]) != GPT_ENTRY_LBA
        || read_u32(&header[80..84]) != 128
        || read_u32(&header[84..88]) as usize != GPT_ENTRY_BYTES
        || header[56..72] != P0_DISK_GUID
    {
        return Err(HealthError::GptHeader);
    }
    let backup_lba = read_u64(&header[32..40]);
    if backup_lba.checked_add(1).is_none_or(|end| end > capacity) {
        return Err(HealthError::GptHeader);
    }
    let crc = Crc::<u32>::new(&CRC_32_ISO_HDLC);
    let stored_crc = read_u32(&header[16..20]);
    let mut crc_header = [0u8; GPT_HEADER_BYTES];
    crc_header.copy_from_slice(header);
    crc_header[16..20].fill(0);
    if crc.checksum(&crc_header) != stored_crc {
        return Err(HealthError::GptCrc);
    }
    let entries_start = GPT_ENTRY_LBA as usize * block::SECTOR_BYTES as usize;
    let entries_end = entries_start + 128 * GPT_ENTRY_BYTES;
    let entries = page
        .get(entries_start..entries_end)
        .ok_or(HealthError::GptHeader)?;
    if crc.checksum(entries) != read_u32(&header[88..92]) {
        return Err(HealthError::GptCrc);
    }
    validate_partition_entry(
        &entries[3 * GPT_ENTRY_BYTES..4 * GPT_ENTRY_BYTES],
        P0_CONTROL_A_TYPE_GUID,
        P0_CONTROL_A_PARTITION_GUID,
        P0_CONTROL_A_LBA,
    )?;
    validate_partition_entry(
        &entries[4 * GPT_ENTRY_BYTES..5 * GPT_ENTRY_BYTES],
        P0_CONTROL_B_TYPE_GUID,
        P0_CONTROL_B_PARTITION_GUID,
        P0_CONTROL_B_LBA,
    )
}

fn validate_partition_entry(
    entry: &[u8],
    expected_type: [u8; 16],
    expected_unique: [u8; 16],
    expected_start: u64,
) -> Result<(), HealthError> {
    let first = read_u64(&entry[32..40]);
    let last = read_u64(&entry[40..48]);
    let sectors = last
        .checked_sub(first)
        .and_then(|value| value.checked_add(1))
        .ok_or(HealthError::GptPartition)?;
    if entry[..16] != expected_type
        || entry[16..32] != expected_unique
        || first != expected_start
        || sectors < (64 * 1024 * 1024 / block::SECTOR_BYTES)
    {
        return Err(HealthError::GptPartition);
    }
    Ok(())
}

fn validate_system_root(
    device: Arc<IrqSpinLock<BlockDevice>>,
    slot: Slot,
    release: u64,
) -> Result<(), HealthError> {
    let (start_lba, label) = match slot {
        Slot::A => (P0_SYSTEM_A_LBA, b"JASPER-SYS-A".as_slice()),
        Slot::B => (P0_SYSTEM_B_LBA, b"JASPER-SYS-B".as_slice()),
    };
    let root = Ext4Reader::open(PartitionExt4Source { device, start_lba })
        .map_err(|_| HealthError::RootMount)?;
    let actual_label = root
        .label()
        .split(|byte| *byte == 0 || *byte == b' ')
        .next()
        .unwrap_or(&[]);
    if actual_label != label {
        return Err(HealthError::RootLabel);
    }
    let marker = root
        .read_file("/etc/jasper-root", ROOT_TEXT_FILE_BYTES)
        .map_err(|_| HealthError::RootFile)?;
    let expected_slot = match slot {
        Slot::A => b'A',
        Slot::B => b'B',
    };
    let expected_prefix = alloc::format!(
        "slot={}\nrelease={release}\nschema=1\n",
        expected_slot as char
    );
    if marker != expected_prefix.as_bytes() {
        return Err(HealthError::RootContent);
    }
    let expected_release = alloc::format!(
        "name=Jasper-OS\nvariant=p0-x86_64-uefi-ab-v1\nrelease={release}\nschema=1\n"
    );
    let release_file = root
        .read_file("/etc/jasper-release", ROOT_TEXT_FILE_BYTES)
        .map_err(|_| HealthError::RootFile)?;
    if release_file != expected_release.as_bytes() {
        return Err(HealthError::RootRelease);
    }
    let userland = root
        .read_file("/etc/jasper-userland", ROOT_TEXT_FILE_BYTES)
        .map_err(|_| HealthError::RootFile)?;
    if userland != ROOT_USERLAND_MANIFEST {
        return Err(HealthError::RootUserland);
    }
    validate_elf_payload(&root, "/bin/true", true)?;
    validate_elf_payload(&root, "/lib64/ld-linux-x86-64.so.2", true)?;
    validate_elf_payload(&root, "/usr/lib/x86_64-linux-gnu/libc.so.6", false)?;
    #[cfg(feature = "lifecycle-root-exec-verify")]
    {
        validate_elf_payload(&root, ROOT_EXEC_PROBE_PATH, true)?;
        execute_root_linux_probe(&root)?;
        execute_root_dynamic_programs(&root)?;
    }
    Ok(())
}

/// Validates the bounded metadata and ELF identity of a required userland payload.
/// 校验必需用户态载荷的受限元数据和 ELF 身份。
fn validate_elf_payload(
    root: &Ext4Reader,
    path: &str,
    executable: bool,
) -> Result<(), HealthError> {
    let metadata = root.metadata(path).map_err(|_| HealthError::RootPayload)?;
    if metadata.is_dir
        || metadata.is_symlink
        || metadata.len < ELF_HEADER_BYTES as u64
        || (executable && metadata.mode & 0o111 == 0)
    {
        return Err(HealthError::RootPayload);
    }
    let mut header = [0u8; ELF_HEADER_BYTES];
    if root
        .read_file_prefix(path, &mut header)
        .map_err(|_| HealthError::RootPayload)?
        != ELF_HEADER_BYTES
        || header[..4] != b"\x7fELF"[..]
        || header[4] != 2
        || header[5] != 1
        || header[6] != 1
        || u16::from_le_bytes([header[18], header[19]]) != 0x003e
    {
        return Err(HealthError::RootPayload);
    }
    Ok(())
}

#[cfg(feature = "lifecycle-root-exec-verify")]
fn execute_root_linux_probe(root: &Ext4Reader) -> Result<(), HealthError> {
    const MAX_PROBE_BYTES: usize = 1024 * 1024;
    let image = root
        .read_file(ROOT_EXEC_PROBE_PATH, MAX_PROBE_BYTES)
        .map_err(|_| HealthError::RootExecute)?;
    let frames_before = crate::mm::frame::free_frames();
    let calls_before = crate::syscall::call_count();
    let calls = compat_core::syscall::LinuxSyscallSet::of(&[
        compat_core::syscall::LinuxSyscall::Write,
        compat_core::syscall::LinuxSyscall::GetPid,
        compat_core::syscall::LinuxSyscall::GetTid,
        compat_core::syscall::LinuxSyscall::ExitGroup,
    ]);
    let pid = crate::proc::create_linux("root-linux-probe", calls)
        .map_err(|_| HealthError::RootExecute)?;
    let entry = match crate::proc::load_linux_elf(pid, &image) {
        Ok(entry) => entry,
        Err(_) => {
            crate::proc::exit_idle(pid, -1);
            let _ = crate::proc::reap(pid);
            crate::kobj::run_cleanup(usize::MAX);
            return Err(HealthError::RootExecute);
        }
    };
    let stack = crate::arch::USER_WINDOW.0 + 0xC0_0000;
    let mapped = crate::proc::map_new(
        pid,
        stack - kernel_core::frame::FRAME_SIZE,
        kernel_core::paging::MapFlags::USER | kernel_core::paging::MapFlags::WRITE,
    )
    .is_ok();
    let started = mapped
        && crate::proc::spawn_thread(pid, "root-linux-probe", entry, stack, 0, 0).is_ok();
    if started {
        crate::sched::run();
    }
    let state = crate::proc::state(pid);
    let _ = crate::proc::reap(pid);
    crate::kobj::run_cleanup(usize::MAX);
    let frames_after = crate::mm::frame::free_frames();
    let syscalls = crate::syscall::call_count().saturating_sub(calls_before);
    let exited = state == Some(crate::proc::ProcState::Exited { code: 0 });
    let resources = frames_after == frames_before;
    crate::kprintln!(
        "[JSR-LIFE-ROOT-EXEC] path={} bytes={} mapped={} cpl3={} exited={} syscalls={} frames_before={} resources={}",
        ROOT_EXEC_PROBE_PATH,
        image.len(),
        mapped,
        started,
        exited,
        syscalls,
        frames_before,
        resources
    );
    if mapped && started && exited && syscalls != 0 && resources {
        Ok(())
    } else {
        Err(HealthError::RootExecute)
    }
}

#[cfg(feature = "lifecycle-root-exec-verify")]
fn install_root_libraries(root: &Ext4Reader) -> Result<(), HealthError> {
    const MAX_LIBRARY_BYTES: usize = 16 * 1024 * 1024;
    let libraries = [
        (
            "/usr/lib/x86_64-linux-gnu/libc.so.6",
            crate::linux_vfs::FileId::Libc,
        ),
        (
            "/usr/lib/x86_64-linux-gnu/libsystemd.so.0",
            crate::linux_vfs::FileId::LibSystemd,
        ),
        (
            "/usr/lib/x86_64-linux-gnu/libselinux.so.1",
            crate::linux_vfs::FileId::LibSelinux,
        ),
        (
            "/usr/lib/x86_64-linux-gnu/libgcc_s.so.1",
            crate::linux_vfs::FileId::LibGccS,
        ),
        (
            "/usr/lib/x86_64-linux-gnu/libm.so.6",
            crate::linux_vfs::FileId::LibM,
        ),
        (
            "/usr/lib/x86_64-linux-gnu/libpcre2-8.so.0",
            crate::linux_vfs::FileId::LibPcre2,
        ),
    ];
    let mut total = 0usize;
    for (path, file) in libraries {
        let bytes = root
            .read_file(path, MAX_LIBRARY_BYTES)
            .map_err(|_| HealthError::RootExecute)?;
        total = total.saturating_add(bytes.len());
        if !crate::linux_vfs::install_root_library(file, bytes) {
            return Err(HealthError::RootExecute);
        }
    }
    crate::kprintln!(
        "[JSR-LIFE-ROOT-LIBS] count={} bytes={} source=system-ab",
        libraries.len(),
        total
    );
    Ok(())
}

#[cfg(feature = "lifecycle-root-exec-verify")]
fn run_root_program(
    root: &Ext4Reader,
    path: &'static str,
    argv: &[&[u8]],
) -> Result<(), HealthError> {
    const MAX_EXECUTABLE_BYTES: usize = 16 * 1024 * 1024;
    const MAX_INTERPRETER_BYTES: usize = 16 * 1024 * 1024;
    let executable = root
        .read_file(path, MAX_EXECUTABLE_BYTES)
        .map_err(|_| HealthError::RootExecute)?;
    let interpreter = root
        .read_file("/lib64/ld-linux-x86-64.so.2", MAX_INTERPRETER_BYTES)
        .map_err(|_| HealthError::RootExecute)?;
    let warm_frames = crate::mm::frame::free_frames();
    if !crate::compat_dynamic_demo::run_root_dynamic_program(
        path.trim_start_matches('/'),
        path,
        &executable,
        &interpreter,
        argv,
        warm_frames,
        false,
    ) {
        return Err(HealthError::RootExecute);
    }
    let frames_before = crate::mm::frame::free_frames();
    if crate::compat_dynamic_demo::run_root_dynamic_program(
        path.trim_start_matches('/'),
        path,
        &executable,
        &interpreter,
        argv,
        frames_before,
        true,
    ) {
        Ok(())
    } else {
        Err(HealthError::RootExecute)
    }
}

#[cfg(feature = "lifecycle-root-exec-verify")]
fn execute_root_dynamic_programs(root: &Ext4Reader) -> Result<(), HealthError> {
    install_root_libraries(root)?;
    let true_argv: [&[u8]; 1] = [b"/bin/true"];
    run_root_program(root, "/bin/true", &true_argv)?;
    let getconf_argv: [&[u8]; 2] = [b"/usr/bin/getconf", b"GNU_LIBC_VERSION"];
    run_root_program(root, "/usr/bin/getconf", &getconf_argv)?;
    let uname_argv: [&[u8]; 2] = [b"/usr/bin/uname", b"-a"];
    run_root_program(root, "/usr/bin/uname", &uname_argv)?;
    let hostname_argv: [&[u8]; 1] = [b"/usr/bin/hostname"];
    run_root_program(root, "/usr/bin/hostname", &hostname_argv)?;
    let basename_argv: [&[u8]; 2] =
        [b"/usr/bin/basename", b"/usr/lib/x86_64-linux-gnu/libc.so.6"];
    run_root_program(root, "/usr/bin/basename", &basename_argv)?;
    let dirname_argv: [&[u8]; 2] =
        [b"/usr/bin/dirname", b"/usr/lib/x86_64-linux-gnu/libc.so.6"];
    run_root_program(root, "/usr/bin/dirname", &dirname_argv)?;
    let id_argv: [&[u8]; 2] = [b"/usr/bin/id", b"-u"];
    run_root_program(root, "/usr/bin/id", &id_argv)?;
    let pwd_argv: [&[u8]; 1] = [b"/usr/bin/pwd"];
    run_root_program(root, "/usr/bin/pwd", &pwd_argv)?;
    let nproc_argv: [&[u8]; 1] = [b"/usr/bin/nproc"];
    run_root_program(root, "/usr/bin/nproc", &nproc_argv)?;
    let sleep_argv: [&[u8]; 2] = [b"/usr/bin/sleep", b"0.05"];
    run_root_program(root, "/usr/bin/sleep", &sleep_argv)?;
    let find_argv: [&[u8]; 6] = [
        b"/usr/bin/find",
        b"/",
        b"-maxdepth",
        b"1",
        b"-mindepth",
        b"1",
    ];
    run_root_program(root, "/usr/bin/find", &find_argv)?;
    let ls_argv: [&[u8]; 3] = [b"/usr/bin/ls", b"-1", b"/"];
    run_root_program(root, "/usr/bin/ls", &ls_argv)?;
    let dash_argv: [&[u8]; 3] = [
        b"/bin/dash",
        b"-c",
        b"echo jasper-shell-ok\ncd /usr\npwd\n",
    ];
    run_root_program(root, "/bin/dash", &dash_argv)?;
    let printf_argv: [&[u8]; 3] = [b"/usr/bin/printf", b"jasper-%s\n", b"dynamic"];
    run_root_program(root, "/usr/bin/printf", &printf_argv)?;
    let signal_argv: [&[u8]; 1] = [b"/usr/bin/jasper-signal-basic"];
    run_root_program(root, "/usr/bin/jasper-signal-basic", &signal_argv)?;
    let ppid_argv: [&[u8]; 1] = [b"/usr/bin/jasper-getppid"];
    run_root_program(root, "/usr/bin/jasper-getppid", &ppid_argv)
}

/// 确认当前 A/B 槽的最小健康集合并持久提交。
/// Confirms the minimum health set for the current A/B slot and commits it durably.
pub fn confirm_minimum_health() -> Result<(), HealthError> {
    mmio::prepare_window().map_err(|_| HealthError::Block)?;
    let device = pci::table()
        .devices()
        .find(|device| {
            device.header.vendor == virtio::VIRTIO_VENDOR
                && virtio::is_blk_device(device.header.device)
        })
        .ok_or(HealthError::Unsupported)?;
    let blockdev = BlockDevice::new(device, HEALTH_PAGES).map_err(|_| HealthError::Block)?;
    let capacity = blockdev.geometry().capacity_sectors;
    let device = Arc::new(IrqSpinLock::new(blockdev));
    let mut io = KernelControlIo {
        device: Arc::clone(&device),
    };
    let gpt = io.read_gpt()?;
    validate_gpt(&gpt, capacity)?;

    let mut first = [0u8; CONTROL_RECORD_BYTES];
    let mut second = [0u8; CONTROL_RECORD_BYTES];
    io.read_copy(0, &mut first)
        .map_err(|_| HealthError::Block)?;
    io.read_copy(1, &mut second)
        .map_err(|_| HealthError::Block)?;
    let current = recover(Some(&first), Some(&second)).map_err(HealthError::Recovery)?;

#[cfg(all(
    feature = "lifecycle-health-fail-verify",
    not(feature = "lifecycle-root-exec-verify")
))]
    {
        let _ = current;
        Err(HealthError::InjectedFailure)
    }
#[cfg(feature = "lifecycle-root-exec-verify")]
    {
        let slot = current
            .candidate()
            .map(|(slot, _)| slot)
            .unwrap_or_else(|| current.active_slot());
        let release = current.slot(slot).release();
        validate_system_root(Arc::clone(&device), slot, release)?;
        kprintln!(
            "[JSR-LIFE-ROOT] slot={:?} release={} schema=1 userland=x86_64-linux-elf files=6",
            slot,
            release
        );
        Ok(())
    }
#[cfg(not(feature = "lifecycle-health-fail-verify"))]
    {
        let slot = current
            .candidate()
            .map(|(slot, _)| slot)
            .unwrap_or_else(|| current.active_slot());
        let release = current.slot(slot).release();
        validate_system_root(Arc::clone(&device), slot, release)?;
        kprintln!(
            "[JSR-LIFE-ROOT] slot={:?} release={} schema=1 userland=x86_64-linux-elf files=6",
            slot,
            release
        );
        let mut next = current;
        next.report_health(slot, true).map_err(HealthError::State)?;
        let mut published = current;
        commit(&mut io, &mut published, next).map_err(HealthError::Commit)?;
        kprintln!(
            "[JSR-LIFE-HEALTH] result=confirmed slot={:?} generation={} release={} attempts=0 storage=virtio-blk",
            slot,
            published.generation(),
            published.slot(slot).release()
        );
        drop(io);
        drop(device);
        Ok(())
    }
}
