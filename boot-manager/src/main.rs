//! Jasper-OS P0 UEFI 槽位选择器。
//! UEFI slot selector for Jasper-OS P0 installations.
//!
//! 选择器读取 GPT Control A/B 分区，在跳转前持久记录启动决策，校验所选槽的
//! 内核摘要，然后把内核装载与跳转交给成熟 `bootloader-x86_64-common`。
//! The selector reads the GPT Control A/B partitions, persists the boot decision
//! before transfer, verifies the selected slot kernel digest, and delegates ELF
//! loading and transfer to mature `bootloader-x86_64-common`.

#![no_main]
#![no_std]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use jasper_lifecycle_boot::{
    commit, recover, BootControlError, ControlBlock, ControlIo, ControlIoError, Slot,
    CONTROL_RECORD_BYTES,
};
use sha2::{Digest, Sha256};
use uefi::boot::{self, AllocateType, MemoryType, SearchType};
use uefi::fs::{FileSystem, PathBuf};
use uefi::prelude::*;
use uefi::proto::media::block::BlockIO;
use uefi::proto::media::partition::PartitionInfo;
use uefi::{guid, CString16, Guid, Identify};

mod loader;
mod memory_descriptor;

const CONTROL_A_GUID: Guid = guid!("4a617370-6572-4f53-a004-000000000004");
const CONTROL_B_GUID: Guid = guid!("4a617370-6572-4f53-a005-000000000005");
struct UefiControlIo {
    first: boot::ScopedProtocol<BlockIO>,
    second: boot::ScopedProtocol<BlockIO>,
}

impl UefiControlIo {
    fn open() -> uefi::Result<Self> {
        let first = open_partition(CONTROL_A_GUID)?;
        let second = open_partition(CONTROL_B_GUID)?;
        Ok(Self { first, second })
    }

    fn block(&mut self, copy: usize) -> Result<&mut boot::ScopedProtocol<BlockIO>, ControlIoError> {
        match copy {
            0 => Ok(&mut self.first),
            1 => Ok(&mut self.second),
            _ => Err(ControlIoError::Failed),
        }
    }
}

impl ControlIo for UefiControlIo {
    fn write_copy(
        &mut self,
        copy: usize,
        bytes: &[u8; CONTROL_RECORD_BYTES],
    ) -> Result<(), ControlIoError> {
        let block = self.block(copy)?;
        let media_id = block.media().media_id();
        let block_size =
            usize::try_from(block.media().block_size()).map_err(|_| ControlIoError::Failed)?;
        if block_size < CONTROL_RECORD_BYTES {
            return Err(ControlIoError::Failed);
        }
        let mut raw = vec![0u8; block_size];
        raw[..CONTROL_RECORD_BYTES].copy_from_slice(bytes);
        block
            .write_blocks(media_id, 0, &raw)
            .map_err(|_| ControlIoError::Failed)?;
        block.flush_blocks().map_err(|_| ControlIoError::Failed)
    }

    fn flush(&mut self) -> Result<(), ControlIoError> {
        self.first
            .flush_blocks()
            .and_then(|_| self.second.flush_blocks())
            .map_err(|_| ControlIoError::Failed)
    }

    fn read_copy(
        &mut self,
        copy: usize,
        out: &mut [u8; CONTROL_RECORD_BYTES],
    ) -> Result<(), ControlIoError> {
        let block = self.block(copy)?;
        let media_id = block.media().media_id();
        let block_size =
            usize::try_from(block.media().block_size()).map_err(|_| ControlIoError::Failed)?;
        if block_size < CONTROL_RECORD_BYTES {
            return Err(ControlIoError::Failed);
        }
        let mut raw = vec![0u8; block_size];
        block
            .read_blocks(media_id, 0, &mut raw)
            .map_err(|_| ControlIoError::Failed)?;
        out.copy_from_slice(&raw[..CONTROL_RECORD_BYTES]);
        Ok(())
    }
}

fn open_partition(guid: Guid) -> uefi::Result<boot::ScopedProtocol<BlockIO>> {
    let handles = boot::locate_handle_buffer(SearchType::ByProtocol(&PartitionInfo::GUID))?;
    let mut matches = Vec::new();
    for handle in handles.iter().copied() {
        let info = boot::open_protocol_exclusive::<PartitionInfo>(handle)?;
        let Some(entry) = info.gpt_partition_entry() else {
            continue;
        };
        let unique_partition_guid = entry.unique_partition_guid;
        if unique_partition_guid == guid {
            matches.push(handle);
        }
    }
    if matches.len() != 1 {
        log::error!(
            "expected exactly one control partition {guid}, found {}",
            matches.len()
        );
        return Err(uefi::Error::from(Status::NOT_FOUND));
    }
    boot::open_protocol_exclusive::<BlockIO>(matches[0])
}

fn recover_control(io: &mut UefiControlIo) -> Result<ControlBlock, String> {
    let mut first = [0u8; CONTROL_RECORD_BYTES];
    let mut second = [0u8; CONTROL_RECORD_BYTES];
    io.read_copy(0, &mut first)
        .map_err(|_| String::from("read Control A failed"))?;
    io.read_copy(1, &mut second)
        .map_err(|_| String::from("read Control B failed"))?;
    recover(Some(&first), Some(&second))
        .map_err(|error: BootControlError| format!("control recovery failed: {error:?}"))
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn select_kernel(
    io: &mut UefiControlIo,
    file_system: &mut FileSystem,
) -> Result<&'static mut [u8], String> {
    let mut current = recover_control(io)?;
    let mut next = current;
    let decision = next
        .prepare_boot()
        .map_err(|error| format!("boot decision failed: {error:?}"))?;
    commit(io, &mut current, next).map_err(|error| format!("decision commit failed: {error:?}"))?;

    let slot = match decision.slot {
        Slot::A => "a",
        Slot::B => "b",
    };
    let source_text = format!("slots\\{slot}\\kernel-x86_64");
    let source = CString16::try_from(source_text.as_str())
        .map(PathBuf::from)
        .map_err(|error| format!("invalid slot kernel path: {error:?}"))?;
    let kernel = file_system
        .read(&source)
        .map_err(|error| format!("read {source} failed: {error:?}"))?;
    let expected = current.slot(decision.slot).digest();
    let actual = digest(&kernel);
    if actual != expected {
        return Err(format!(
            "slot {slot} kernel digest mismatch: expected {}, got {}",
            hex(&expected),
            hex(&actual)
        ));
    }
    let mut kernel = kernel;
    let loader_kernel = allocate_loader_data(kernel.len())?;
    loader_kernel.copy_from_slice(&kernel);
    kernel.clear();
    uefi::println!(
        "selecting slot={:?} reason={:?} attempt={} release={} kernel_bytes={}",
        decision.slot,
        decision.reason,
        decision.attempt,
        current.slot(decision.slot).release(),
        loader_kernel.len()
    );
    Ok(loader_kernel)
}

fn allocate_loader_data(size: usize) -> Result<&'static mut [u8], String> {
    let pages = size
        .checked_add(0xfff)
        .ok_or_else(|| String::from("kernel size overflow"))?
        / 0x1000;
    let pointer = boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, pages)
        .map_err(|error| format!("allocate aligned kernel buffer failed: {error:?}"))?;
    unsafe {
        core::ptr::write_bytes(pointer.as_ptr(), 0, size);
        Ok(core::slice::from_raw_parts_mut(pointer.as_ptr(), size))
    }
}

#[entry]
fn main() -> Status {
    uefi::println!("Jasper-OS boot manager starting");
    let mut io = match UefiControlIo::open() {
        Ok(io) => io,
        Err(error) => {
            uefi::println!("open control partitions failed: {error:?}");
            return Status::ABORTED;
        }
    };
    let mut file_system = match boot::get_image_file_system(boot::image_handle()) {
        Ok(fs) => FileSystem::new(fs),
        Err(error) => {
            uefi::println!("open ESP failed: {error:?}");
            return Status::ABORTED;
        }
    };
    let kernel = match select_kernel(&mut io, &mut file_system) {
        Ok(kernel) => kernel,
        Err(error) => {
            uefi::println!("Jasper-OS boot manager failed: {error}");
            return Status::ABORTED;
        }
    };
    drop(file_system);
    drop(io);
    loader::boot(kernel)
}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

#[cfg(target_os = "uefi")]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    use core::arch::asm;
    use core::fmt::Write;

    let stdout_available = uefi::table::system_table_raw()
        .map(|table| {
            // SAFETY: the UEFI entry macro installs a non-null system table before main.
            let table = unsafe { table.as_ref() };
            !table.boot_services.is_null() && !table.stdout.is_null()
        })
        .unwrap_or(false);
    if stdout_available {
        uefi::system::with_stdout(|stdout| {
            let _ = stdout.clear();
            let _ = writeln!(stdout, "{info}");
        });
    }
    unsafe {
        bootloader_x86_64_common::logger::LOGGER
            .get()
            .map(|logger| logger.force_unlock())
    };
    log::error!("{info}");
    loop {
        unsafe { asm!("cli; hlt") };
    }
}
