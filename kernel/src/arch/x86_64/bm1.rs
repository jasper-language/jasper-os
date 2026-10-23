//! QEMU-only BM-1 profile. No effect on the default kernel.
//! RTL8139 C-mode TX registers follow QEMU hw/net/rtl8139.c;
//! IB700 ports follow hw/watchdog/wdt_ib700.c. No RX or general network service.
use super::port::{inb, inl, outb, outl};
use bootloader_api::info::{FrameBuffer, PixelFormat};
use noto_sans_mono_bitmap::{get_raster, FontWeight, RasterHeight};
use spin::Mutex;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use crate::arch::{ExitStatus, Platform};

const CAPACITY: usize = 8 * 1024 * 1024;
struct Log { bytes: [u8; CAPACITY], len: usize, overflow: bool }
static LOG: Mutex<Log> = Mutex::new(Log { bytes: [0; CAPACITY], len: 0, overflow: false });
static BOOT_ID: AtomicU64 = AtomicU64::new(0);
static LOST: AtomicU32 = AtomicU32::new(0);
struct Screen { fb: FrameBuffer, x: usize, y: usize, line: [u8; 1024], len: usize }
static SCREEN: Mutex<Option<Screen>> = Mutex::new(None);

pub fn init(fb: Option<FrameBuffer>) {
    // Nonce collisions are rejected by the receiver, never counted as a new boot.
    BOOT_ID.store(unsafe { core::arch::x86_64::_rdtsc() }, Ordering::Relaxed);
    if let Some(mut fb) = fb {
        let i = fb.info();
        if i.width >= 16 && i.height >= 32 && i.stride >= i.width
            && i.bytes_per_pixel >= 3 && matches!(i.pixel_format, PixelFormat::Rgb | PixelFormat::Bgr)
            && i.stride.checked_mul(i.height).and_then(|n| n.checked_mul(i.bytes_per_pixel))
                .is_some_and(|n| n <= i.byte_len)
        {
            fb.buffer_mut().fill(0);
            *SCREEN.lock() = Some(Screen { fb, x: 0, y: 0, line: [0; 1024], len: 0 });
        }
    }
    // SAFETY: only enabled by the explicit VM profile with an IB700 device.
    unsafe { outb(0x443, 0); } // 30 virtual seconds; fed on each log newline.
    #[cfg(feature = "bm1-hang")]
    {
        super::uart::init();
        for b in b"[BM1] injected_hang watchdog=ib700\n" { super::uart::write_byte(*b); }
        // Leave watchdog armed while stopping all guest progress.
        super::X86_64::halt_forever();
    }
}

pub fn write_byte(b: u8) {
    if b == b'\n' { unsafe { outb(0x443, 0); } }
    if let Some(mut log) = LOG.try_lock() {
        let n = log.len;
        if n < CAPACITY { log.bytes[n] = b; log.len += 1; }
        else { log.overflow = true; }
    } else { LOST.fetch_add(1, Ordering::Relaxed); }
    if let Some(mut guard) = SCREEN.try_lock() {
        if let Some(s) = guard.as_mut() { s.input(b); }
    }
}

impl Screen {
    // Screen is a boot/selftest summary; the full trace stays in serial/UDP.
    // Rendering interrupt trace lines would itself amplify timer interrupt load.
    fn input(&mut self, b: u8) {
        if b == b'\r' { return; }
        if b != b'\n' {
            if self.len < self.line.len() { self.line[self.len] = b; self.len += 1; }
            return;
        }
        let line = &self.line[..self.len];
        if line.starts_with(b"[JSR-BOOT]") || line.starts_with(b"[JSR-EXIT]")
            || line.starts_with(b"[BM1]") || line.starts_with(b"[JSR-PANIC]")
        {
            for n in 0..self.len { self.byte(self.line[n]); }
            self.byte(b'\n');
        }
        self.len = 0;
    }
    fn byte(&mut self, b: u8) {
        let i = self.fb.info();
        if b == b'\r' { return; }
        if b == b'\n' || self.x + 9 > i.width { self.x = 0; self.y += 16; }
        if self.y + 16 > i.height {
            // Scroll in place so the final result remains on screen.
            let row = i.stride * i.bytes_per_pixel * 16;
            let end = i.stride * i.bytes_per_pixel * i.height;
            self.fb.buffer_mut().copy_within(row..end, 0);
            self.fb.buffer_mut()[end-row..end].fill(0);
            self.y -= 16;
        }
        if b == b'\n' { return; }
        let c = if b.is_ascii_graphic() || b == b' ' { b as char } else { '?' };
        if let Some(g) = get_raster(c, FontWeight::Regular, RasterHeight::Size16) {
            for (dy, row) in g.raster().iter().enumerate() {
                for (dx, v) in row.iter().enumerate() {
                    let at = ((self.y+dy)*i.stride + self.x+dx)*i.bytes_per_pixel;
                    let buf = self.fb.buffer_mut();
                    // SAFETY: validated geometry, glyph fits within screen and slice.
                    unsafe { for k in 0..3 { core::ptr::write_volatile(buf.as_mut_ptr().add(at+k), *v); } }
                }
            }
            self.x += g.width();
        }
    }
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in bytes.chunks(2) { sum += ((chunk[0] as u32) << 8) | *chunk.get(1).unwrap_or(&0) as u32; }
    while sum >> 16 != 0 { sum = (sum & 65535) + (sum >> 16); }
    !(sum as u16)
}

/// Send buffered serial bytes as actual Ethernet/IPv4/UDP frames using RTL8139
/// DMA. Static private link: 192.0.2.2:5555 -> 192.0.2.1:5555, broadcast MAC.
/// Payload header: BM1L, offset:u32, total:u32, FNV1a:u32, boot_nonce:u64, all big endian.
fn upload(log: &Log) -> Result<(), &'static str> {
    use kernel_core::pci::Bar;
    let dev = crate::pci::table().devices().find(|d| d.header.vendor == 0x10ec && d.header.device == 0x8139).ok_or("missing_rtl8139")?;
    let base = dev.bars.iter().find_map(|b| match b { Bar::Io { base, size } if *base > 0 && *base + *size <= 65536 && *size >= 0x100 => Some(*base as u16), _ => None }).ok_or("missing_io_bar")?;
    // Enable IO decode without writing back W1C PCI status bits.
    let command = crate::pci::read_config32(dev.bdf, 4).ok_or("pci_read")?;
    if !crate::pci::write_config32(dev.bdf, 4, (command & 65535) | 1) { return Err("pci_write"); }
    let frame = crate::mm::frame::allocate_below(1u64 << 32).map_err(|_| "dma_frame")?;
    let ptr = crate::mm::phys_to_virt(frame.start()).ok_or("dma_mapping")?;
    // Frame remains allocated until reset, even on failure: never recycle DMA
    // memory without a quiescence acknowledgement. Only one terminal uploader.
    unsafe {
        outb(base+0x37, 0x10);
        let mut ready = false;
        for _ in 0..1_000_000 { if inb(base+0x37)&0x10 == 0 { ready = true; break; } }
        if !ready { return Err("reset_timeout"); }
        outb(base+0x3c, 0); outb(base+0x3d, 0); // no IRQs
        crate::pci::set_bus_master(dev.bdf, true).map_err(|_| "bus_master")?;
        outb(base+0x37, 4); // TX only; no unallocated RX ring
        outl(base+0x40, 0x0300_0700); // normal interframe gap, max DMA burst
        // RTL8139 consumes four C-mode descriptors in order, even with
        // just one outstanding packet. All slots share this synchronous buffer.
        for slot in 0..4 { outl(base+0x20+slot*4, frame.start() as u32); }
        let packet = core::slice::from_raw_parts_mut(ptr, 4096);
        let hash = log.bytes[..log.len].iter().fold(2166136261u32, |h, b| (h ^ *b as u32).wrapping_mul(16777619));
        for offset in (0..log.len).step_by(1024) {
            outb(0x443, 0);
            let n = (log.len-offset).min(1024);
            let size = 14+20+8+24+n;
            packet[..size].fill(0);
            packet[..6].fill(255);
            for j in 0..6 { packet[6+j] = inb(base+j as u16); }
            packet[12..14].copy_from_slice(&[8,0]);
            packet[14] = 0x45;
            packet[16..18].copy_from_slice(&((size-14) as u16).to_be_bytes());
            packet[22] = 64; packet[23] = 17;
            packet[26..30].copy_from_slice(&[192,0,2,2]);
            packet[30..34].copy_from_slice(&[192,0,2,1]);
            let cs = checksum(&packet[14..34]); packet[24..26].copy_from_slice(&cs.to_be_bytes());
            packet[34..36].copy_from_slice(&5555u16.to_be_bytes());
            packet[36..38].copy_from_slice(&5555u16.to_be_bytes());
            packet[38..40].copy_from_slice(&((size-34) as u16).to_be_bytes());
            // UDP checksum zero is legal for IPv4; whole log checked by hash +
            // byte-for-byte serial comparison on receiver, not a security MAC.
            packet[42..46].copy_from_slice(b"BM1L");
            packet[46..50].copy_from_slice(&(offset as u32).to_be_bytes());
            packet[50..54].copy_from_slice(&(log.len as u32).to_be_bytes());
            packet[54..58].copy_from_slice(&hash.to_be_bytes());
            packet[58..66].copy_from_slice(&BOOT_ID.load(Ordering::Relaxed).to_be_bytes());
            packet[66..66+n].copy_from_slice(&log.bytes[offset..offset+n]);
            core::sync::atomic::fence(Ordering::SeqCst);
            let tsd = base + 0x10 + ((offset / 1024) % 4) as u16 * 4;
            outl(tsd, size as u32);
            let mut done = false;
            for _ in 0..1_000_000 {
                let status = inl(tsd);
                if status & 0xc000_4000 != 0 { return Err("tx_error"); }
                if status & 0x8000 != 0 { done = true; break; }
            }
            if !done { return Err("tx_timeout"); }
        }
        outb(base+0x37, 0); // TX engine disabled before closing bus mastering
        crate::pci::set_bus_master(dev.bdf, false).map_err(|_| "bus_master_off")?;
    }
    Ok(())
}

pub fn finish(status: ExitStatus) -> ! {
    super::X86_64::irq_disable();
    let good = matches!(status, ExitStatus::Success | ExitStatus::TimingOnly);
    let framebuffer = SCREEN.lock().is_some();
    crate::kprintln!("[BM1] selftest={} framebuffer={}", if good { "PASS" } else { "FAIL" }, framebuffer);
    let result = {
        let log = LOG.lock();
        if log.overflow || LOST.load(Ordering::Relaxed) != 0 { Err("capture_overflow_or_contention") }
        else { upload(&log) }
    };
    // Serial-only transport status, deliberately outside uploaded byte range.
    for b in if result.is_ok() { b"[BM1] udp=sent reset=cf9\r\n".as_slice() } else { b"[BM1] udp=FAIL reset=cf9\r\n".as_slice() } { super::uart::write_byte(*b); }
    if let Err(reason) = result {
        for b in b"[BM1] transport_error=" { super::uart::write_byte(*b); }
        for b in reason.bytes() { super::uart::write_byte(b); }
        for b in b"\r\n" { super::uart::write_byte(*b); }
    }
    // Leave a bounded window for QMP to capture the final framebuffer.
    for _ in 0..2_000_000 { core::hint::spin_loop(); }
    // CF9 full reset. The VM supervisor stops after ten validated reset events.
    unsafe { outb(0xcf9, 0x02); outb(0xcf9, 0x06); }
    super::X86_64::halt_forever()
}
