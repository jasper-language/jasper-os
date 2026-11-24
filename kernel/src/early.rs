//! Allocation-free boot observability.
//!
//! This module is independent of the heap, interrupt controller, allocator,
//! and normal console lock. It can therefore report the first instructions
//! after the bootloader handoff and remain usable from panic.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use crate::arch;

#[cfg(target_arch = "x86_64")]
use bootloader_api::info::{FrameBuffer, PixelFormat};
#[cfg(all(feature = "noto-console", target_arch = "x86_64"))]
use noto_sans_mono_bitmap::{get_raster, FontWeight, RasterHeight};

#[cfg(target_arch = "x86_64")]
const TEXT_CELL_WIDTH: u32 = 12;
#[cfg(target_arch = "x86_64")]
const TEXT_GLYPH_HEIGHT: u32 = 20;
#[cfg(target_arch = "x86_64")]
const TEXT_LINE_HEIGHT: u32 = 24;
#[cfg(target_arch = "x86_64")]
const TEXT_LEFT: u32 = 12;
#[cfg(target_arch = "x86_64")]
const TEXT_RIGHT_MARGIN: u32 = 12;
#[cfg(target_arch = "x86_64")]
const TEXT_TOP: u32 = 32;
#[cfg(target_arch = "x86_64")]
const TEXT_FOREGROUND: (u8, u8, u8) = (0xd8, 0xf3, 0xea);
#[cfg(target_arch = "x86_64")]
const TEXT_BACKGROUND: (u8, u8, u8) = (0x08, 0x11, 0x18);

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
    if info.width == 0 || info.height == 0 || info.stride < info.width || frame_len > info.byte_len
    {
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
    let width = FRAMEBUFFER_WIDTH.load(Ordering::Relaxed) as u32;
    draw_text(
        TEXT_LEFT,
        8,
        width.saturating_sub(TEXT_LEFT + TEXT_RIGHT_MARGIN),
        "JASPER-OS BOOT CONSOLE",
    );
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
    let width = FRAMEBUFFER_WIDTH.load(Ordering::Relaxed) as u32;
    draw_text(
        TEXT_LEFT,
        8,
        width.saturating_sub(TEXT_LEFT + TEXT_RIGHT_MARGIN),
        "JASPER-OS PERFORMANCE",
    );
    TEXT_ROW.store(2, Ordering::Release);
}

/// Append one plain result line to the direct framebuffer text panel.
#[cfg(target_arch = "x86_64")]
pub fn append_line(text: &str) {
    if !DISPLAY_READY.load(Ordering::Acquire) {
        return;
    }
    append_text("", text);
}

/// Draw transient benchmark progress on a dedicated footer row without
/// advancing the result log.
#[cfg(target_arch = "x86_64")]
pub fn append_progress(text: &str) {
    if !DISPLAY_READY.load(Ordering::Acquire) {
        return;
    }
    let height = FRAMEBUFFER_HEIGHT.load(Ordering::Relaxed) as u32;
    let width = FRAMEBUFFER_WIDTH.load(Ordering::Relaxed) as u32;
    let y = height.saturating_sub(TEXT_LINE_HEIGHT);
    fill_rect(
        TEXT_LEFT.saturating_sub(4),
        y.saturating_sub(1),
        width.saturating_sub(TEXT_LEFT + TEXT_RIGHT_MARGIN - 4),
        TEXT_LINE_HEIGHT,
        TEXT_BACKGROUND.0,
        TEXT_BACKGROUND.1,
        TEXT_BACKGROUND.2,
    );
    draw_text(
        TEXT_LEFT,
        y + (TEXT_LINE_HEIGHT - TEXT_GLYPH_HEIGHT) / 2,
        width.saturating_sub(TEXT_LEFT + TEXT_RIGHT_MARGIN),
        text,
    );
}

#[cfg(not(target_arch = "x86_64"))]
pub fn append_progress(_text: &str) {}

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
    append_text(kind, text);
}

#[cfg(target_arch = "x86_64")]
fn append_text(prefix: &str, text: &str) {
    let width = FRAMEBUFFER_WIDTH.load(Ordering::Relaxed) as u32;
    let right = width.saturating_sub(TEXT_RIGHT_MARGIN);
    let available = right.saturating_sub(TEXT_LEFT);
    let columns = available / TEXT_CELL_WIDTH;
    if columns == 0 {
        return;
    }
    let mut x = TEXT_LEFT;
    let mut y = begin_text_row();
    for character in prefix.chars().chain(text.chars()) {
        match character {
            '\r' => continue,
            '\n' => {
                x = TEXT_LEFT;
                y = begin_text_row();
                continue;
            }
            '\t' => {
                let column = x.saturating_sub(TEXT_LEFT) / TEXT_CELL_WIDTH;
                let next_stop = (column / 4 + 1) * 4;
                while x.saturating_sub(TEXT_LEFT) / TEXT_CELL_WIDTH < next_stop {
                    x = x.saturating_add(TEXT_CELL_WIDTH);
                    if x + TEXT_CELL_WIDTH > right {
                        x = TEXT_LEFT;
                        y = begin_text_row();
                    }
                }
                continue;
            }
            character if character.is_control() => {
                if !draw_character(x, y, '?', 1) {
                    return;
                }
                x = x.saturating_add(TEXT_CELL_WIDTH);
                continue;
            }
            _ => {}
        }

        let cell_columns = character_cell_width(character);
        if cell_columns == 0 {
            // The early path has no full shaping engine. The complete original
            // string remains available on the independent serial/log path.
            continue;
        }
        let character_width = TEXT_CELL_WIDTH.saturating_mul(cell_columns as u32);
        if x.saturating_add(character_width) > right {
            x = TEXT_LEFT;
            y = begin_text_row();
        }
        if !draw_character(x, y, character, cell_columns) {
            return;
        }
        x = x.saturating_add(character_width);
    }
}

#[cfg(target_arch = "x86_64")]
fn begin_text_row() -> u32 {
    let rows = text_rows();
    let row = TEXT_ROW.load(Ordering::Acquire);
    let row = if row >= rows {
        scroll_text_rows();
        rows.saturating_sub(1)
    } else {
        row
    };
    TEXT_ROW.store(row.saturating_add(1), Ordering::Release);
    let y = TEXT_TOP.saturating_add(row * TEXT_LINE_HEIGHT);
    clear_text_row(y);
    y
}

#[cfg(target_arch = "x86_64")]
fn text_rows() -> u32 {
    let height = FRAMEBUFFER_HEIGHT.load(Ordering::Relaxed) as u32;
    height
        .saturating_sub(TEXT_TOP)
        .saturating_sub(TEXT_LINE_HEIGHT)
        .checked_div(TEXT_LINE_HEIGHT)
        .unwrap_or(1)
        .max(1)
}

#[cfg(target_arch = "x86_64")]
fn clear_text_row(y: u32) {
    let width = FRAMEBUFFER_WIDTH.load(Ordering::Relaxed) as u32;
    fill_rect(
        TEXT_LEFT.saturating_sub(4),
        y.saturating_sub(2),
        width.saturating_sub(TEXT_LEFT + TEXT_RIGHT_MARGIN - 4),
        TEXT_LINE_HEIGHT,
        TEXT_BACKGROUND.0,
        TEXT_BACKGROUND.1,
        TEXT_BACKGROUND.2,
    );
}

#[cfg(target_arch = "x86_64")]
fn scroll_text_rows() {
    let rows = text_rows();
    if rows <= 1 {
        return;
    }
    let base = FRAMEBUFFER_BASE.load(Ordering::Relaxed);
    let len = FRAMEBUFFER_LEN.load(Ordering::Relaxed);
    let stride = FRAMEBUFFER_STRIDE.load(Ordering::Relaxed);
    let bpp = FRAMEBUFFER_BPP.load(Ordering::Relaxed);
    let Some(row_bytes) = stride
        .checked_mul(bpp)
        .and_then(|value| value.checked_mul(TEXT_LINE_HEIGHT as usize))
    else {
        return;
    };
    let Some(top) = (TEXT_TOP as usize)
        .checked_mul(stride)
        .and_then(|value| value.checked_mul(bpp))
    else {
        return;
    };
    let Some(area) = row_bytes.checked_mul(rows as usize) else {
        return;
    };
    let Some(bottom) = top.checked_add(area) else {
        return;
    };
    if base == 0 || bottom > len {
        return;
    }
    unsafe {
        let pointer = base as *mut u8;
        core::ptr::copy(
            pointer.add(top + row_bytes),
            pointer.add(top),
            area - row_bytes,
        );
    }
    clear_text_row(
        TEXT_TOP.saturating_add(rows.saturating_sub(1).saturating_mul(TEXT_LINE_HEIGHT)),
    );
}

#[cfg(target_arch = "x86_64")]
fn character_cell_width(character: char) -> u8 {
    kernel_core::text_grid::cell_width(character)
}

#[cfg(target_arch = "x86_64")]
fn draw_text(x: u32, y: u32, max_width: u32, text: &str) -> bool {
    let mut cursor = x;
    let right = x.saturating_add(max_width);
    for character in text.chars() {
        let columns = character_cell_width(character);
        if columns == 0 {
            continue;
        }
        let width = TEXT_CELL_WIDTH.saturating_mul(columns as u32);
        if cursor.saturating_add(width) > right {
            return true;
        }
        if !draw_character(cursor, y, character, columns) {
            return false;
        }
        cursor = cursor.saturating_add(width);
    }
    true
}

#[cfg(target_arch = "x86_64")]
fn draw_character(x: u32, y: u32, character: char, columns: u8) -> bool {
    if character == ' ' {
        return true;
    }
    #[cfg(feature = "noto-console")]
    if let Some(glyph) = get_raster(character, FontWeight::Regular, RasterHeight::Size20) {
        for (row, pixels) in glyph.raster().iter().enumerate() {
            for (column, coverage) in pixels.iter().copied().enumerate() {
                if coverage != 0 {
                    blend_pixel(
                        x.saturating_add(column as u32),
                        y.saturating_add(row as u32),
                        TEXT_FOREGROUND.0,
                        TEXT_FOREGROUND.1,
                        TEXT_FOREGROUND.2,
                        coverage,
                    );
                }
            }
        }
        return true;
    }

    let fallback = if character.is_ascii() {
        character as u8
    } else {
        b'?'
    };
    let glyph = crate::display::glyph(fallback);
    let scale = 2;
    let origin_x = x.saturating_add((TEXT_CELL_WIDTH.saturating_mul(columns as u32) - 10) / 2);
    let origin_y = y.saturating_add(3);
    for (row, bits) in glyph.iter().copied().enumerate() {
        for column in 0..5u8 {
            if bits & (1u8 << (4 - column)) != 0 {
                fill_rect(
                    origin_x + u32::from(column) * scale,
                    origin_y + row as u32 * scale,
                    scale,
                    scale,
                    TEXT_FOREGROUND.0,
                    TEXT_FOREGROUND.1,
                    TEXT_FOREGROUND.2,
                );
            }
        }
    }
    true
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
fn blend_pixel(x: u32, y: u32, red: u8, green: u8, blue: u8, coverage: u8) {
    if coverage == 0 {
        return;
    }
    if coverage == 255 {
        pixel(x, y, red, green, blue);
        return;
    }
    let Some((background_red, background_green, background_blue)) = read_pixel(x, y) else {
        return;
    };
    pixel(
        x,
        y,
        kernel_core::raster::blend_coverage(red, background_red, coverage),
        kernel_core::raster::blend_coverage(green, background_green, coverage),
        kernel_core::raster::blend_coverage(blue, background_blue, coverage),
    );
}

#[cfg(target_arch = "x86_64")]
fn read_pixel(x: u32, y: u32) -> Option<(u8, u8, u8)> {
    let base = FRAMEBUFFER_BASE.load(Ordering::Relaxed);
    let len = FRAMEBUFFER_LEN.load(Ordering::Relaxed);
    let stride = FRAMEBUFFER_STRIDE.load(Ordering::Relaxed);
    let bpp = FRAMEBUFFER_BPP.load(Ordering::Relaxed);
    let format = FRAMEBUFFER_FORMAT.load(Ordering::Relaxed);
    let offset = (y as usize)
        .checked_mul(stride)?
        .checked_add(x as usize)?
        .checked_mul(bpp)?;
    let end = offset.checked_add(bpp)?;
    if base == 0 || end > len {
        return None;
    }
    let pointer = base as *const u8;
    unsafe {
        Some(match format {
            0 => (
                core::ptr::read_volatile(pointer.add(offset)),
                core::ptr::read_volatile(pointer.add(offset + 1)),
                core::ptr::read_volatile(pointer.add(offset + 2)),
            ),
            1 => (
                core::ptr::read_volatile(pointer.add(offset + 2)),
                core::ptr::read_volatile(pointer.add(offset + 1)),
                core::ptr::read_volatile(pointer.add(offset)),
            ),
            2 => {
                let gray = core::ptr::read_volatile(pointer.add(offset));
                (gray, gray, gray)
            }
            _ => return None,
        })
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
