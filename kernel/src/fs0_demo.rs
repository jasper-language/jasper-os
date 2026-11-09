//! FS-0 journal integration and same-disk power-cut acceptance.

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::block::{self, Request, Terminal};
use kernel_core::fs::journal::{
    BlockJournalStorage, FsJournal, JournalError, SectorIo, STORAGE_UNIT_BYTES,
};
use kernel_core::fs::{
    EntryName, FsCapabilities, FsContract, FsServiceReply, FsServiceRequest, MountIdentity,
    NodeKind, PersistentIdentity,
};
use kernel_core::object::Rights;

use crate::blk::BlockDevice;
use crate::{kprintln, mmio, pci, sched, virtio};

const DATA_PAGES: u64 = 1;
const JOURNAL_NODES: usize = 8;
const JOURNAL_HANDLES: usize = 8;
const JOURNAL_BYTES: usize = STORAGE_UNIT_BYTES * 2;
const JOURNAL_BASE_SECTOR: u64 = 64;
const MOUNT: MountIdentity = MountIdentity::new(0x4653_3001, 0x0909, 1);
const SCRATCH_BYTES: usize = kernel_core::fs::journal::CHECKPOINT_HEADER_BYTES
    + JOURNAL_NODES * kernel_core::fs::journal::NODE_RECORD_BYTES;

static FAILED: AtomicU32 = AtomicU32::new(0);

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

fn check(condition: bool, what: &'static str) {
    if !condition {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-FS0-FAIL] {}", what);
    }
}

struct VirtioSectorIo<'a> {
    device: &'a mut BlockDevice,
}

impl<'a> VirtioSectorIo<'a> {
    fn new(device: &'a mut BlockDevice) -> Self {
        Self { device }
    }
}

impl SectorIo for VirtioSectorIo<'_> {
    fn capacity_sectors(&self) -> u64 {
        self.device.geometry().capacity_sectors
    }

    fn read_unit(
        &mut self,
        absolute: u64,
        out: &mut [u8; STORAGE_UNIT_BYTES],
    ) -> Result<(), JournalError> {
        if !matches!(
            self.device.execute(Request::read(absolute, 1), false),
            Ok(Terminal::Completed)
        ) {
            return Err(JournalError::Storage);
        }
        self.device
            .copy_prefix(out)
            .map_err(|_| JournalError::Storage)
    }

    fn write_unit(
        &mut self,
        absolute: u64,
        bytes: &[u8; STORAGE_UNIT_BYTES],
    ) -> Result<(), JournalError> {
        self.device
            .fill_pattern(0, bytes)
            .map_err(|_| JournalError::Storage)?;
        if !matches!(
            self.device.execute(Request::write(absolute, 1, false), false),
            Ok(Terminal::Completed)
        ) {
            return Err(JournalError::Storage);
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), JournalError> {
        if matches!(
            self.device.execute(Request::flush(), false),
            Ok(Terminal::Completed)
        ) {
            Ok(())
        } else {
            Err(JournalError::Storage)
        }
    }
}

struct Outcome {
    recovered: bool,
    seed_present: bool,
    final_sequence: u64,
    after_reboot_present: bool,
}

fn create_file(
    fs: &mut FsContract<JOURNAL_NODES, JOURNAL_HANDLES>,
    name: &[u8],
) -> Result<PersistentIdentity, kernel_core::fs::FsError> {
    let root = fs.root();
    fs.create(
        root,
        EntryName::new(name).map_err(|_| kernel_core::fs::FsError::InvalidName)?,
        NodeKind::File,
        Rights::READ.union(Rights::WRITE),
    )
}

fn exercise_file_service(
    fs: &mut FsContract<JOURNAL_NODES, JOURNAL_HANDLES>,
) -> bool {
    let root = fs.root();
    let create = FsServiceRequest::create(
        root,
        EntryName::new(b"wire").unwrap(),
        NodeKind::File,
        Rights::READ.union(Rights::WRITE),
    );
    let Ok(FsServiceReply::Created(_)) = fs.dispatch(create) else {
        return false;
    };
    let open = FsServiceRequest::open(
        root,
        EntryName::new(b"wire").unwrap(),
        Rights::READ
            .union(Rights::WRITE)
            .union(Rights::MAP),
    );
    let Ok(FsServiceReply::Open(handle)) = fs.dispatch(open) else {
        return false;
    };
    if fs.write(handle, 4096).is_err() {
        return false;
    }
    let mmap = FsServiceRequest::mmap(handle, 0, 4096, false);
    if !matches!(
        fs.dispatch(mmap),
        Ok(FsServiceReply::Mapped(mapping)) if fs.mapping_valid(mapping)
    ) {
        return false;
    }
    if fs.dispatch(FsServiceRequest::close(handle)) != Ok(FsServiceReply::Closed) {
        return false;
    }
    let rename = FsServiceRequest::rename(
        root,
        EntryName::new(b"wire").unwrap(),
        root,
        EntryName::new(b"wire-renamed").unwrap(),
        false,
        Rights::READ
            .union(Rights::WRITE)
            .union(Rights::CONTROL),
    );
    if !matches!(
        fs.dispatch(rename),
        Ok(FsServiceReply::Renamed(_))
    ) {
        return false;
    }
    let unlink = FsServiceRequest::unlink(
        root,
        EntryName::new(b"wire-renamed").unwrap(),
        Rights::READ
            .union(Rights::WRITE)
            .union(Rights::CONTROL),
    );
    matches!(fs.dispatch(unlink), Ok(FsServiceReply::Unlinked(_)))
}

fn run_journal(block: &mut BlockDevice) -> Outcome {
    // BlockJournalStorage translates its partition-relative offsets to absolute
    // device sectors before calling SectorIo. The adapter must not offset again.
    let io = VirtioSectorIo::new(block);
    let mut storage =
        BlockJournalStorage::new(io, JOURNAL_BASE_SECTOR, JOURNAL_BYTES).expect("journal capacity");
    let mut scratch = [0u8; SCRATCH_BYTES];

    match FsJournal::open(&mut storage) {
        Ok(mut journal) => {
            let replay = match journal.recover::<JOURNAL_NODES, JOURNAL_HANDLES>(
                MOUNT,
                FsCapabilities::OPEN,
                &mut scratch,
            ) {
                Ok(replay) => replay,
                Err(error) => {
                    kprintln!("[JSR-FS0-FAIL] recover={}", error.name());
                    FAILED.fetch_add(1, Ordering::Relaxed);
                    return Outcome {
                        recovered: false,
                        seed_present: false,
                        final_sequence: journal.head().sequence,
                        after_reboot_present: false,
                    };
                }
            };
            check(replay.sequence == 1, "unexpected recovered sequence");
            let root = replay.state.root();
            let seed_present = replay
                .state
                .lookup(root, EntryName::new(b"fs0-seed").unwrap(), Rights::READ)
                .is_ok();
            check(seed_present, "recovered checkpoint lost seed file");
            kprintln!(
                "[JSR-FS0] recovered=true sequence={} seed={}",
                replay.sequence,
                seed_present
            );
            let mut state = replay.state;
            let service = exercise_file_service(&mut state);
            check(service, "file-service contract dispatch failed");
            kprintln!("[JSR-FS0] service={}", service);
            if create_file(&mut state, b"after-reboot").is_err() {
                check(false, "could not create post-reboot file");
            }
            let receipt = match journal.commit(&state, &mut scratch) {
                Ok(receipt) => receipt,
                Err(error) => {
                    kprintln!("[JSR-FS0-FAIL] commit={}", error.name());
                    FAILED.fetch_add(1, Ordering::Relaxed);
                    return Outcome {
                        recovered: true,
                        seed_present,
                        final_sequence: journal.head().sequence,
                        after_reboot_present: false,
                    };
                }
            };
            drop(journal);
            let mut reopened = match FsJournal::open(&mut storage) {
                Ok(journal) => journal,
                Err(error) => {
                    kprintln!("[JSR-FS0-FAIL] reopen={}", error.name());
                    FAILED.fetch_add(1, Ordering::Relaxed);
                    return Outcome {
                        recovered: true,
                        seed_present,
                        final_sequence: receipt.sequence,
                        after_reboot_present: false,
                    };
                }
            };
            let final_replay = match reopened.recover::<JOURNAL_NODES, JOURNAL_HANDLES>(
                MOUNT,
                FsCapabilities::OPEN,
                &mut scratch,
            ) {
                Ok(replay) => replay,
                Err(error) => {
                    kprintln!("[JSR-FS0-FAIL] final_recover={}", error.name());
                    FAILED.fetch_add(1, Ordering::Relaxed);
                    return Outcome {
                        recovered: true,
                        seed_present,
                        final_sequence: receipt.sequence,
                        after_reboot_present: false,
                    };
                }
            };
            let root = final_replay.state.root();
            let after_reboot_present = final_replay
                .state
                .lookup(
                    root,
                    EntryName::new(b"after-reboot").unwrap(),
                    Rights::READ,
                )
                .is_ok();
            check(
                final_replay.sequence == 2,
                "post-reboot checkpoint sequence mismatch",
            );
            check(
                after_reboot_present,
                "post-reboot checkpoint lost new file",
            );
            Outcome {
                recovered: true,
                seed_present,
                final_sequence: final_replay.sequence,
                after_reboot_present,
            }
        }
        Err(JournalError::NoCommittedCheckpoint) => {
            let mut journal = match FsJournal::format(&mut storage) {
                Ok(journal) => journal,
                Err(error) => {
                    kprintln!("[JSR-FS0-FAIL] format={}", error.name());
                    FAILED.fetch_add(1, Ordering::Relaxed);
                    return Outcome {
                        recovered: false,
                        seed_present: false,
                        final_sequence: 0,
                        after_reboot_present: false,
                    };
                }
            };
            let mut state =
                FsContract::format(MOUNT, FsCapabilities::ALL, FsCapabilities::OPEN).unwrap();
            if create_file(&mut state, b"fs0-seed").is_err() {
                check(false, "could not create seed file");
            }
            let receipt = match journal.commit(&state, &mut scratch) {
                Ok(receipt) => receipt,
                Err(error) => {
                    kprintln!("[JSR-FS0-FAIL] initial_commit={}", error.name());
                    FAILED.fetch_add(1, Ordering::Relaxed);
                    return Outcome {
                        recovered: false,
                        seed_present: true,
                        final_sequence: 0,
                        after_reboot_present: false,
                    };
                }
            };
            kprintln!(
                "[JSR-FS0] checkpoint=true sequence={} slot={} bytes={}",
                receipt.sequence,
                receipt.slot,
                receipt.checkpoint_bytes
            );
            let hold = sched::timer_ticks();
            while sched::timer_ticks().wrapping_sub(hold) < 200 {
                sched::pause();
            }
            check(false, "first boot was not interrupted by host power-cut");
            Outcome {
                recovered: false,
                seed_present: true,
                final_sequence: receipt.sequence,
                after_reboot_present: false,
            }
        }
        Err(error) => {
            kprintln!("[JSR-FS0-FAIL] open={}", error.name());
            FAILED.fetch_add(1, Ordering::Relaxed);
            Outcome {
                recovered: false,
                seed_present: false,
                final_sequence: 0,
                after_reboot_present: false,
            }
        }
    }
}

pub fn run() {
    if let Err(error) = mmio::prepare_window() {
        check(false, error.name());
        return;
    }
    let before = crate::baseline::baseline();
    let Some(device) = pci::table()
        .devices()
        .find(|device| {
            device.header.vendor == virtio::VIRTIO_VENDOR
                && virtio::is_blk_device(device.header.device)
        })
    else {
        check(false, "no virtio-blk device");
        return;
    };
    let outcome = {
        let mut block = match BlockDevice::new(device, DATA_PAGES) {
            Ok(block) => block,
            Err(error) => {
                kprintln!("[JSR-FS0-FAIL] device={}", error.name());
                FAILED.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        let geometry = block.geometry();
        check(
            geometry.capacity_sectors
                >= JOURNAL_BASE_SECTOR + block::SECTORS_PER_IO_UNIT * 2,
            "block device too small for journal",
        );
        run_journal(&mut block)
    };
    let after = crate::baseline::baseline();
    let resources = after == before;
    check(resources, "FS-0 resources did not return to baseline");
    kprintln!(
        "[JSR-FS0] summary failed={} recovered={} seed={} final_sequence={} after_reboot={} resources={}",
        failed(),
        outcome.recovered,
        outcome.seed_present,
        outcome.final_sequence,
        outcome.after_reboot_present,
        resources
    );
}
