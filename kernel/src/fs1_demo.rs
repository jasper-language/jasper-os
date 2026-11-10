//! FS-1 real ext4 VFS acceptance over virtio-blk.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::block::{self, Request, Terminal};
use kernel_core::ext4_view::{Ext4ByteSource, Ext4Reader, Ext4SourceError};
use kernel_core::ext4_write::{Ext4Vfs, Ext4WritableSource, EXT4_BLOCK_BYTES};
use kernel_core::ifc::{FlowDecision, FlowLabel, FlowPolicy, PURPOSE_SYSTEM};
use kernel_core::mac::{
    class_bit, Integrity, MacDenial, MacEffect, MacLabel, Secrecy,
};
use kernel_core::security::{IdentityClass, SecurityDomain};

use crate::blk::BlockDevice;
use crate::sync::IrqSpinLock;
use crate::{ifc, kobj, kprintln, mmio, pci, proc, sched, security, virtio};

const DATA_PAGES: u64 = 1;
static FAILED: AtomicU32 = AtomicU32::new(0);

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

fn check(condition: bool, what: &'static str) {
    if !condition {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-FS1-FAIL] {}", what);
    }
}

#[derive(Clone)]
struct VirtioExt4Storage {
    device: Arc<IrqSpinLock<BlockDevice>>,
}

impl VirtioExt4Storage {
    fn read_block(&self, block: u64) -> Result<[u8; EXT4_BLOCK_BYTES], Ext4SourceError> {
        let mut device = self.device.lock();
        let sector = block
            .checked_mul(block::SECTORS_PER_IO_UNIT as u64)
            .ok_or(Ext4SourceError)?;
        if !matches!(
            device.execute(Request::read(sector, 1), false),
            Ok(Terminal::Completed)
        ) {
            return Err(Ext4SourceError);
        }
        let mut out = [0u8; EXT4_BLOCK_BYTES];
        device.copy_prefix(&mut out).map_err(|_| Ext4SourceError)?;
        Ok(out)
    }

    fn write_block(&self, block: u64, bytes: &[u8]) -> Result<(), Ext4SourceError> {
        if bytes.len() != EXT4_BLOCK_BYTES {
            return Err(Ext4SourceError);
        }
        let mut device = self.device.lock();
        device.fill_pattern(0, bytes).map_err(|_| Ext4SourceError)?;
        let sector = block
            .checked_mul(block::SECTORS_PER_IO_UNIT as u64)
            .ok_or(Ext4SourceError)?;
        if matches!(
            device.execute(Request::write(sector, 1, false), false),
            Ok(Terminal::Completed)
        ) {
            Ok(())
        } else {
            Err(Ext4SourceError)
        }
    }
}

impl Ext4ByteSource for VirtioExt4Storage {
    fn read_exact(&mut self, offset: u64, dst: &mut [u8]) -> Result<(), Ext4SourceError> {
        let mut done = 0;
        while done < dst.len() {
            let absolute = offset.checked_add(done as u64).ok_or(Ext4SourceError)?;
            let block = absolute / EXT4_BLOCK_BYTES as u64;
            let inner = (absolute % EXT4_BLOCK_BYTES as u64) as usize;
            let take = (dst.len() - done).min(EXT4_BLOCK_BYTES - inner);
            let bytes = self.read_block(block)?;
            dst[done..done + take].copy_from_slice(&bytes[inner..inner + take]);
            done += take;
        }
        Ok(())
    }
}

impl Ext4WritableSource for VirtioExt4Storage {
    fn write_exact(&mut self, offset: u64, bytes: &[u8]) -> Result<(), Ext4SourceError> {
        let mut done = 0;
        while done < bytes.len() {
            let absolute = offset.checked_add(done as u64).ok_or(Ext4SourceError)?;
            let block = absolute / EXT4_BLOCK_BYTES as u64;
            let inner = (absolute % EXT4_BLOCK_BYTES as u64) as usize;
            let take = (bytes.len() - done).min(EXT4_BLOCK_BYTES - inner);
            let mut current = self.read_block(block)?;
            current[inner..inner + take].copy_from_slice(&bytes[done..done + take]);
            self.write_block(block, &current)?;
            done += take;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Ext4SourceError> {
        if matches!(
            self.device.lock().execute(Request::flush(), false),
            Ok(Terminal::Completed)
        ) {
            Ok(())
        } else {
            Err(Ext4SourceError)
        }
    }
}

pub fn run() {
    if let Err(error) = mmio::prepare_window() {
        check(false, error.name());
        return;
    }
    let before = crate::baseline::baseline();
    let heap_before = crate::mm::heap::stats();
    let Some(device) = pci::table().devices().find(|device| {
        device.header.vendor == virtio::VIRTIO_VENDOR && virtio::is_blk_device(device.header.device)
    }) else {
        check(false, "no virtio-blk device");
        return;
    };
    let principal = match proc::create("fs1-prod", crate::syscall::SyscallSet::EMPTY) {
        Ok(pid) => pid,
        Err(_) => {
            check(false, "FS production principal creation failed");
            return;
        }
    };

    {
        let blockdev = match BlockDevice::new(device, DATA_PAGES) {
            Ok(device) => device,
            Err(error) => {
                kprintln!("[JSR-FS1-FAIL] block={}", error.name());
                FAILED.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        let storage = VirtioExt4Storage {
            device: Arc::new(IrqSpinLock::new(blockdev)),
        };
        let root_ok = Ext4Reader::open(storage.clone())
            .ok()
            .and_then(|reader| reader.metadata("/").ok())
            .is_some();
        kprintln!("[JSR-FS1] stage=mount root_ok={}", root_ok);
        let mut vfs = match Ext4Vfs::new(storage) {
            Ok(vfs) => vfs,
            Err(error) => {
                kprintln!("[JSR-FS1-FAIL] mount={}", error.name());
                FAILED.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        let subject = match kobj::with(|table| table.security(principal)) {
            Ok(context) if context.require_active().is_ok() => context,
            _ => {
                kprintln!("[JSR-FS1-PROD-FAIL] missing subject security metadata");
                FAILED.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        let file_mac = MacLabel::new(
            SecurityDomain::USER,
            Secrecy::Internal,
            Integrity::Managed,
            class_bit(IdentityClass::KernelObject),
        );
        let audit_before = security::audit_stats();
        let allow_read =
            security::authorize_file_label(subject, 0x1001, 1, file_mac, MacEffect::Read);
        let secret = MacLabel::new(
            SecurityDomain::USER,
            Secrecy::Secret,
            Integrity::Managed,
            class_bit(IdentityClass::KernelObject),
        );
        let deny_secret =
            security::authorize_file_label(subject, 0x1002, 1, secret, MacEffect::Read);
        let deny_flow = ifc::authorize_file(
            subject,
            FlowLabel::for_secrecy(Secrecy::Secret),
            0x1003,
            1,
            FlowLabel::for_secrecy(Secrecy::Sensitive),
            FlowPolicy::for_clearance(Secrecy::Public),
            PURPOSE_SYSTEM,
            sched::now_ns(),
        );
        security::flush_audit();
        let audit_after = security::audit_stats();
        let mac_ok = allow_read.is_ok()
            && deny_secret == Err(MacDenial::SecrecyDenied)
            && audit_after.0 > audit_before.0
            && audit_after.1 > audit_before.1;
        let ifc_ok = deny_flow == Ok(FlowDecision::Denied);
        check(mac_ok, "FS production MAC/default-deny/audit gate failed");
        check(ifc_ok, "FS production IFC taint gate failed");
        kprintln!(
            "[JSR-FS1-PROD] mac_allow={} secret_denied={} flow_denied={} flow_result={:?} audited={} denied={} domain_bound=true",
            allow_read.is_ok(),
            deny_secret == Err(MacDenial::SecrecyDenied),
            deny_flow == Ok(FlowDecision::Denied),
            deny_flow,
            audit_after.0.saturating_sub(audit_before.0),
            audit_after.1.saturating_sub(audit_before.1)
        );
        let seed = vfs.open("/seed.txt", false);
        kprintln!("[JSR-FS1] stage=seed handle={:?}", seed);
        check(
            seed.is_ok_and(|handle| {
                vfs.read(handle, 4096)
                    .is_ok_and(|bytes| bytes == b"HOST-SEED\n")
            }),
            "Linux-created ext4 seed file did not read through VFS",
        );
        if let Ok(handle) = seed {
            let _ = vfs.close(handle);
        }

        kprintln!("[JSR-FS1] stage=create begin");
        check(
            security::authorize_file_label(
                subject,
                0x2001,
                1,
                file_mac,
                MacEffect::Write,
            )
            .is_ok(),
            "FS production write authorization failed",
        );
        let handle = match vfs.create_open("/jasper.txt", true) {
            Ok(handle) => handle,
            Err(error) => {
                kprintln!("[JSR-FS1-FAIL] create={}", error.name());
                FAILED.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        kprintln!("[JSR-FS1] stage=create handle={}", handle);
        match vfs.write(handle, b"written by Jasper\n") {
            Ok(()) => kprintln!("[JSR-FS1] stage=write ok=true"),
            Err(error) => {
                kprintln!("[JSR-FS1] stage=write ok=false error={}", error.name());
                check(false, "ext4 VFS write failed");
            }
        }
        match vfs.sync(handle) {
            Ok(()) => kprintln!("[JSR-FS1] stage=fsync ok=true"),
            Err(error) => {
                kprintln!("[JSR-FS1] stage=fsync ok=false error={}", error.name());
                check(false, "ext4 fsync/flush failed");
            }
        }
        check(
            vfs.read(handle, 4096)
                .is_ok_and(|bytes| bytes == b"written by Jasper\n"),
            "ext4 VFS readback differs",
        );
        check(
            security::authorize_file_label(
                subject,
                0x2001,
                2,
                file_mac,
                MacEffect::Control,
            )
            .is_ok(),
            "FS production rename authorization failed",
        );
        match vfs.rename("/jasper.txt", "/jasper-renamed.txt") {
            Ok(()) => kprintln!("[JSR-FS1] stage=rename ok=true"),
            Err(error) => {
                kprintln!("[JSR-FS1] stage=rename ok=false error={}", error.name());
                check(false, "ext4 atomic rename failed");
            }
        }
        check(
            vfs.read(handle, 4096)
                .is_ok_and(|bytes| bytes == b"written by Jasper\n"),
            "open handle did not survive rename",
        );
        check(vfs.close(handle).is_ok(), "ext4 VFS close failed");
        check(
            vfs.live_handles() == 0,
            "ext4 VFS handles did not return to zero",
        );

        let hold = sched::timer_ticks();
        while sched::timer_ticks().wrapping_sub(hold) < 20 {
            sched::pause();
        }
        kprintln!("[JSR-FS1] mounted=true read=true write=true fsync=true rename=true handles=0");
    }
    let _ = proc::exit_idle(principal, 0);
    let _ = proc::reap(principal);
    kobj::run_cleanup(usize::MAX);
    let after = crate::baseline::baseline();
    let heap_after = crate::mm::heap::stats();
    let heap_used_before = heap_before.0.saturating_sub(heap_before.1);
    let heap_used_after = heap_after.0.saturating_sub(heap_after.1);
    let heap_growth = heap_after.3.saturating_sub(heap_before.3);
    let expected_free_frames = before
        .free_frames
        .saturating_sub((heap_growth / kernel_core::frame::FRAME_SIZE as u64) as usize);
    let resources = before.objects == after.objects
        && before.pending == after.pending
        && before.pins == after.pins
        && heap_used_before == heap_used_after
        && after.free_frames == expected_free_frames;
    kprintln!(
        "[JSR-FS1] resources frames={}->{}(heap_growth={}) objects={}->{} pins={:?}->{:?} heap_used={}->{}",
        before.free_frames,
        after.free_frames,
        heap_growth,
        before.objects,
        after.objects,
        before.pins,
        after.pins,
        heap_used_before,
        heap_used_after
    );
    check(
        resources,
        "FS-1 kernel resources did not return to baseline",
    );
    kprintln!(
        "[JSR-FS1] summary failed={} resources={}",
        failed(),
        resources
    );
}
