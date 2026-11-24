//! Allocation-free boot observability.
//!
//! This module is independent of the heap, interrupt controller, allocator,
//! and normal console lock. It can therefore report the first instructions
//! after the bootloader handoff and remain usable from panic.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use crate::arch;

#[cfg(target_arch = "x86_64")]
use bootloader_api::info::{FrameBuffer, PixelFormat};

static SERIAL_READY: AtomicBool = AtomicBool::new(false);
static BOOT_DEADLINE: AtomicU64 = AtomicU64::new(0);
static BOOT_ID: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "x86_64")]
static TSC_HZ: AtomicU64 = AtomicU64::new(0);
/// 1 = CPUID.15H ratio, 2 = PIT calibration.
#[cfg(target_arch = "x86_64")]
static TSC_SOURCE: AtomicU32 = AtomicU32::new(0);
#[cfg(target_arch = "x86_64")]
static TEXT_ROW: AtomicU32 = AtomicU32::new(0);

#[cfg(target_arch = "x86_64")]
static DISPLAY_READY: AtomicBool = AtomicBool::new(false);
#[cfg(target_arch = "x86_64")]
static FRAMEBUFFER_BASE: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_arch = "x86_64")]
static FRAMEBUFFER_LEN: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_arch = "x86_64")]
static FRAMEBUFFER_WIDTH: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_arch = "x86_64")]
static FRAMEBUFFER_HEIGHT: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_arch = "x86_64")]
static FRAMEBUFFER_STRIDE: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_arch = "x86_64")]
static FRAMEBUFFER_BPP: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_arch = "x86_64")]
static FRAMEBUFFER_FORMAT: AtomicUsize = AtomicUsize::new(usize::MAX);
/// Initialize the raw serial console once.
pub fn serial_init() {
    if !SERIAL_READY.swap(true, Ordering::Relaxed) {
        arch::console_init();
    }
}

fn serial_line(text: &str) {
    serial_init();
    serial_bytes(text.as_bytes());
    arch::console_write_byte(b'\r');
    arch::console_write_byte(b'\n');
}

fn serial_bytes(bytes: &[u8]) {
    for &byte in bytes {
        if byte == b'\n' {
            arch::console_write_byte(b'\r');
        }
        arch::console_write_byte(byte);
    }
}

/// Record the first instruction after the bootloader jump on both visible
/// output paths.
#[cfg(target_arch = "x86_64")]
pub fn entry(framebuffer: Option<&mut FrameBuffer>) -> bool {
    BOOT_ID.store(arch::cycles(), Ordering::Release);
    serial_line("[JSR-EARLY] stage=entry cpu=x86_64 framebuffer=probe");
    framebuffer.is_some_and(install)
}

pub fn boot_id() -> u64 {
    BOOT_ID.load(Ordering::Acquire)
}

/// Install and paint the direct framebuffer backend.
#[cfg(target_arch = "x86_64")]
pub fn install(framebuffer: &mut FrameBuffer) -> bool {
    let info = framebuffer.info();
    let format = match info.pixel_format {
        PixelFormat::Rgb => 0,
        PixelFormat::Bgr => 1,
        PixelFormat::U8 => 2,
        _ => return false,
    };
    let Some(frame_len) = info
        .stride
        .checked_mul(info.height)
        .and_then(|value| value.checked_mul(info.bytes_per_pixel))
    else {
        return false;
    };
    if info.width == 0 || info.height == 0 || info.stride < info.width || frame_len > info.byte_len {
        return false;
    }
    FRAMEBUFFER_BASE.store(
        framebuffer.buffer_mut().as_mut_ptr() as usize,
        Ordering::Relaxed,
    );
    FRAMEBUFFER_LEN.store(info.byte_len, Ordering::Relaxed);
    FRAMEBUFFER_WIDTH.store(info.width, Ordering::Relaxed);
    FRAMEBUFFER_HEIGHT.store(info.height, Ordering::Relaxed);
    FRAMEBUFFER_STRIDE.store(info.stride, Ordering::Relaxed);
    FRAMEBUFFER_BPP.store(info.bytes_per_pixel, Ordering::Relaxed);
    FRAMEBUFFER_FORMAT.store(format, Ordering::Relaxed);
    DISPLAY_READY.store(true, Ordering::Release);

    fill(0x08, 0x11, 0x18);
    draw_text(12, 8, 1, b"JASPER-OS BOOT CONSOLE");
    TEXT_ROW.store(2, Ordering::Release);
    append_kind("[INIT] ", "K00 ENTRY");
    true
}

/// Publish a bounded boot-stage marker to serial and, when available, directly
/// to the framebuffer.
pub fn mark(stage: &str) {
    serial_init();
    serial_bytes(b"[JSR-EARLY] stage=");
    serial_bytes(stage.as_bytes());
    arch::console_write_byte(b'\r');
    arch::console_write_byte(b'\n');

    #[cfg(target_arch = "x86_64")]
    paint_stage(stage);
}

/// Report successful completion of a boot component.
pub fn mark_ok(component: &str) {
    serial_init();
    serial_bytes(b"[ OK ] ");
    serial_bytes(component.as_bytes());
    arch::console_write_byte(b'\r');
    arch::console_write_byte(b'\n');

    #[cfg(target_arch = "x86_64")]
    append_kind("[ OK ] ", component);
}

/// Append a status line to the framebuffer without writing serial output.
///
/// This is used by pre-heap boot stages that already emit the structured line
/// through the console formatter and must not allocate.
#[cfg(target_arch = "x86_64")]
pub fn append_status(kind: &str, text: &str) {
    if DISPLAY_READY.load(Ordering::Acquire) {
        append_kind(kind, text);
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn append_status(_kind: &str, _text: &str) {}

/// Switch the direct framebuffer into a text results panel without starting the
/// compositor or window-system services.
#[cfg(target_arch = "x86_64")]
pub fn results_begin() {
    if !DISPLAY_READY.load(Ordering::Acquire) {
        return;
    }
    fill(0x08, 0x11, 0x18);
    draw_text(12, 8, 1, b"JASPER-OS PERFORMANCE");
    TEXT_ROW.store(2, Ordering::Release);
}

/// Append one plain result line to the direct framebuffer text panel.
#[cfg(target_arch = "x86_64")]
pub fn append_line(text: &str) {
    if !DISPLAY_READY.load(Ordering::Acquire) {
        return;
    }
    let row = TEXT_ROW.fetch_add(1, Ordering::Relaxed);
    let y = 24u32.saturating_add((row % 56) * 10);
    let width = FRAMEBUFFER_WIDTH.load(Ordering::Relaxed) as u32;
    fill_rect(8, y.saturating_sub(1), width.saturating_sub(16), 9, 0x08, 0x11, 0x18);
    draw_text(12, y, 1, text.as_bytes());
}

/// Arm a cycle-based deadline for hardware debugging builds.
#[cfg(feature = "boot-autorecovery")]
pub fn arm_boot_deadline(seconds: u64) -> bool {
    let Some(hz) = tsc_frequency_hz() else {
        serial_line("[JSR-BOOT-WATCHDOG] backend=tsc available=false");
        return false;
    };
    let cycles = hz.saturating_mul(seconds);
    let Some(deadline) = arch::cycles().checked_add(cycles) else {
        return false;
    };
    BOOT_DEADLINE.store(deadline, Ordering::Release);
    serial_line("[JSR-BOOT-WATCHDOG] backend=tsc available=true timeout_s=60");
    true
}

/// Check the boot deadline at a stage boundary.
#[cfg(feature = "boot-autorecovery")]
pub fn check_boot_deadline(stage: &str) {
    let deadline = BOOT_DEADLINE.load(Ordering::Acquire);
    if deadline != 0 && arch::cycles() >= deadline {
        mark("BOOT TIMEOUT");
        serial_init();
        serial_bytes(b"[JSR-BOOT-WATCHDOG] expired stage=");
        serial_bytes(stage.as_bytes());
        arch::console_write_byte(b'\r');
        arch::console_write_byte(b'\n');
        arch::panic_reset();
    }
}

#[cfg(not(feature = "boot-autorecovery"))]
pub fn check_boot_deadline(_stage: &str) {}

#[cfg(target_arch = "x86_64")]
pub fn tsc_frequency_hz() -> Option<u64> {
    let cached = TSC_HZ.load(Ordering::Acquire);
    if cached != 0 {
        return Some(cached);
    }
    let maximum = core::arch::x86_64::__cpuid(0).eax;
    if maximum >= 0x15 {
        let ratio = core::arch::x86_64::__cpuid(0x15);
        if ratio.eax != 0 && ratio.ebx != 0 && ratio.ecx != 0 {
            let frequency = (u64::from(ratio.ecx) as u128)
                .checked_mul(u64::from(ratio.ebx) as u128)?
                .checked_div(u64::from(ratio.eax) as u128)?
                .try_into()
                .ok()?;
            TSC_HZ.store(frequency, Ordering::Release);
            TSC_SOURCE.store(1, Ordering::Release);
            return Some(frequency);
        }
    }
    // CPUID.16H reports the processor's nominal/reference frequency, not
    // necessarily the invariant TSC frequency. It is not a calibration source.
    let frequency = arch::calibrate_tsc_hz()?;
    TSC_HZ.store(frequency, Ordering::Release);
    TSC_SOURCE.store(2, Ordering::Release);
    Some(frequency)
}

#[cfg(target_arch = "x86_64")]
pub fn tsc_frequency_source() -> &'static str {
    match TSC_SOURCE.load(Ordering::Acquire) {
        1 => "cpuid.15h",
        2 => "pit.channel2",
        _ => "unavailable",
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn tsc_frequency_hz() -> Option<u64> {
    None
}

#[cfg(not(target_arch = "x86_64"))]
pub fn tsc_frequency_source() -> &'static str {
    "unavailable"
}

#[cfg(target_arch = "x86_64")]
fn paint_stage(stage: &str) {
    if !DISPLAY_READY.load(Ordering::Acquire) {
        return;
    }
    append_kind("[INIT] ", stage);
}

#[cfg(target_arch = "x86_64")]
fn append_kind(kind: &str, text: &str) {
    let row = TEXT_ROW.fetch_add(1, Ordering::Relaxed);
    let y = 24u32.saturating_add((row % 56) * 10);
    let width = FRAMEBUFFER_WIDTH.load(Ordering::Relaxed) as u32;
    fill_rect(8, y.saturating_sub(1), width.saturating_sub(16), 9, 0x08, 0x11, 0x18);
    draw_text(12, y, 1, kind.as_bytes());
    draw_text(
        12 + kind.len() as u32 * 6,
        y,
        1,
        text.as_bytes(),
    );
}

#[cfg(target_arch = "x86_64")]
fn draw_text(mut x: u32, y: u32, scale: u32, text: &[u8]) {
    for byte in text.iter().copied().take(90) {
        if byte == b' ' {
            x = x.saturating_add(6 * scale);
            continue;
        }
        let glyph = crate::display::glyph(byte);
        for (row, bits) in glyph.iter().copied().enumerate() {
            for column in 0..5u8 {
                if bits & (1u8 << (4 - column)) != 0 {
                    fill_rect(
                        x + u32::from(column) * scale,
                        y + row as u32 * scale,
                        scale,
                        scale,
                        0xd8,
                        0xf3,
                        0xea,
                    );
                }
            }
        }
        x = x.saturating_add(6 * scale);
    }
}

#[cfg(target_arch = "x86_64")]
fn fill(red: u8, green: u8, blue: u8) {
    let width = FRAMEBUFFER_WIDTH.load(Ordering::Relaxed) as u32;
    let height = FRAMEBUFFER_HEIGHT.load(Ordering::Relaxed) as u32;
    fill_rect(0, 0, width, height, red, green, blue);
}

#[cfg(target_arch = "x86_64")]
fn fill_rect(x: u32, y: u32, width: u32, height: u32, red: u8, green: u8, blue: u8) {
    let surface_width = FRAMEBUFFER_WIDTH.load(Ordering::Relaxed) as u32;
    let surface_height = FRAMEBUFFER_HEIGHT.load(Ordering::Relaxed) as u32;
    let right = x.saturating_add(width).min(surface_width);
    let bottom = y.saturating_add(height).min(surface_height);
    for row in y..bottom {
        for column in x..right {
            pixel(column, row, red, green, blue);
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn pixel(x: u32, y: u32, red: u8, green: u8, blue: u8) {
    let base = FRAMEBUFFER_BASE.load(Ordering::Relaxed);
    let len = FRAMEBUFFER_LEN.load(Ordering::Relaxed);
    let stride = FRAMEBUFFER_STRIDE.load(Ordering::Relaxed);
    let bpp = FRAMEBUFFER_BPP.load(Ordering::Relaxed);
    let format = FRAMEBUFFER_FORMAT.load(Ordering::Relaxed);
    let Some(offset) = (y as usize)
        .checked_mul(stride)
        .and_then(|value| value.checked_add(x as usize))
        .and_then(|value| value.checked_mul(bpp))
    else {
        return;
    };
    let Some(end) = offset.checked_add(bpp) else {
        return;
    };
    if base == 0 || end > len {
        return;
    }
    let pointer = base as *mut u8;
    unsafe {
        match format {
            0 | 1 => {
                let (first, third) = if format == 0 {
                    (red, blue)
                } else {
                    (blue, red)
                };
                core::ptr::write_volatile(pointer.add(offset), first);
                core::ptr::write_volatile(pointer.add(offset + 1), green);
                core::ptr::write_volatile(pointer.add(offset + 2), third);
                for padding in 3..bpp {
                    core::ptr::write_volatile(pointer.add(offset + padding), 0xff);
                }
            }
            2 => {
                let gray = ((u16::from(red) + u16::from(green) + u16::from(blue)) / 3) as u8;
                core::ptr::write_volatile(pointer.add(offset), gray);
            }
            _ => {}
        }
    }
}
