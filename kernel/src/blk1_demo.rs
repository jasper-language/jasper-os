//! BLK-1 real virtio-blk acceptance.

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::block::{self, Request, Terminal};

use crate::blk::BlockDevice;
use crate::{kprintln, mmio, pci, sched, virtio};

const DATA_PAGES: u64 = 2;
const TEST_SECTOR: u64 = 8;
const PATTERN_SEED: u8 = 0x31;
const MARKER: &[u8] = b"JASPER-BLK1-FLUSH";

static FAILED: AtomicU32 = AtomicU32::new(0);

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

fn check(condition: bool, what: &'static str) {
    if !condition {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-BLK1-FAIL] {}", what);
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
        .find(|device| device.header.vendor == virtio::VIRTIO_VENDOR && virtio::is_blk_device(device.header.device))
    else {
        check(false, "no virtio-blk device");
        return;
    };

    let restored;
    {
        let mut blockdev = match BlockDevice::new(device, DATA_PAGES) {
            Ok(device) => device,
            Err(error) => {
                kprintln!("[JSR-BLK1-FAIL] setup={}", error.name());
                FAILED.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        let geometry = blockdev.geometry();
        check(geometry.capacity_sectors >= TEST_SECTOR + DATA_PAGES * block::SECTORS_PER_IO_UNIT, "block capacity too small");
        check(geometry.logical_block_size.is_power_of_two(), "logical block size is not a power of two");
        check(
            geometry.physical_block_size >= geometry.logical_block_size
                && geometry.physical_block_size % geometry.logical_block_size == 0,
            "physical block size relationship is invalid",
        );
        check(geometry.discard, "virtio-blk discard feature is unavailable");
        check(geometry.fua, "virtio-blk FUA/flush feature is unavailable");
        check(
            Request::read(1, 1).validate(
                block::Features {
                    flush: geometry.fua,
                    discard: geometry.discard,
                    block_size: true,
                },
                geometry.capacity_sectors,
            ) == Err(block::Error::Alignment),
            "misaligned request was admitted",
        );

        blockdev
            .fill_pattern(0xA5, &[])
            .expect("fill initial DMA pattern");
        check(
            matches!(blockdev.execute(Request::read(TEST_SECTOR, DATA_PAGES), false), Ok(Terminal::Completed)),
            "initial read failed",
        );
        restored = blockdev
            .data_equals(PATTERN_SEED, MARKER)
            .unwrap_or(false);

        blockdev
            .fill_pattern(PATTERN_SEED, MARKER)
            .expect("fill write pattern");
        check(
            matches!(
                blockdev.execute(Request::write(TEST_SECTOR, DATA_PAGES, true), false),
                Ok(Terminal::Completed)
            ),
            "FUA write failed",
        );
        check(
            matches!(blockdev.execute(Request::flush(), false), Ok(Terminal::Completed)),
            "flush failed",
        );
        kprintln!(
            "[JSR-BLK1] checkpoint=true sector={} pages={} fua=true flush=true",
            TEST_SECTOR,
            DATA_PAGES
        );
        // Keep the checkpoint observable long enough for the host power-cut
        // test to terminate QEMU after flush but before later requests.
        let hold = sched::timer_ticks();
        while sched::timer_ticks().wrapping_sub(hold) < 200 {
            sched::pause();
        }

        blockdev
            .fill_pattern(0xCC, &[])
            .expect("fill readback poison");
        check(
            matches!(blockdev.execute(Request::read(TEST_SECTOR, DATA_PAGES), false), Ok(Terminal::Completed)),
            "readback request failed",
        );
        let equals = blockdev
            .data_equals(PATTERN_SEED, MARKER)
            .unwrap_or(false);
        check(equals, "flushed data did not read back");

        blockdev
            .fill_pattern(0x55, MARKER)
            .expect("fill cancellation pattern");
        check(
            matches!(
                blockdev.execute(Request::write(TEST_SECTOR + DATA_PAGES * block::SECTORS_PER_IO_UNIT, DATA_PAGES, false), true),
                Ok(Terminal::Cancelled)
            ),
            "submitted I/O cancellation did not publish Cancelled after device retirement",
        );
        check(
            matches!(
                blockdev.execute(Request::discard(TEST_SECTOR, DATA_PAGES), false),
                Ok(Terminal::Completed)
            ),
            "discard failed",
        );

        kprintln!(
            "[JSR-BLK1] device=0x{:x} capacity_sectors={} logical_block={} physical_block={} atomic_write={} discard={} fua={} checkpoint=true restored={}",
            kernel_core::device::pack_bdf(device.bdf),
            geometry.capacity_sectors,
            geometry.logical_block_size,
            geometry.physical_block_size,
            geometry.atomic_write_bytes,
            geometry.discard,
            geometry.fua,
            restored
        );
    }

    let after = crate::baseline::baseline();
    check(after == before, "BLK-1 resources did not return to baseline");
    kprintln!(
        "[JSR-BLK1] summary failed={} restored={} resources={}",
        failed(),
        restored,
        after == before
    );
}
