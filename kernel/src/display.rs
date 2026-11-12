//! Native framebuffer and keyboard session integration.
//!
//! Responsibility: bind one firmware framebuffer and the real x86 keyboard to
//! the bounded mechanism in `kernel-core`. It draws a deterministic first frame,
//! renders terminal bytes with a built-in ASCII font and forwards real key
//! transitions to the native terminal session. It does not claim a compositor
//! or window system.
//!
//! 原生帧缓冲与键盘会话集成。把固件 framebuffer 和真实 x86 键盘绑定到
//! `kernel-core` 的有界机制，绘制首帧、用内建 ASCII 字体呈现终端字节并把真实
//! 按键送入原生终端会话；不宣称 compositor 或窗口系统已经完成。

use bootloader_api::info::{FrameBuffer, PixelFormat};
use kernel_core::display_input::{
    DisplayBackend, DisplayCapabilities, DisplayInputError, DisplayInputSession, KeyInput,
    PixelLayout, SurfaceSpec,
};

use crate::kprintln;
use crate::sync::IrqSpinLock;

const KEY_CAPACITY: usize = 64;
const TEXT_COLUMNS: usize = 96;
const TEXT_ROWS: usize = 32;
const TEXT_CELLS: usize = TEXT_COLUMNS * TEXT_ROWS;

struct Runtime {
    base: usize,
    len: usize,
    surface: SurfaceSpec,
    session: DisplayInputSession<KEY_CAPACITY>,
    pressed: u32,
    released: u32,
    text: [u8; TEXT_CELLS],
    cursor: usize,
    prompt_reported: bool,
    echo_reported: bool,
}

static DISPLAY: IrqSpinLock<Option<Runtime>> = IrqSpinLock::ranked(crate::lockorder::DISPLAY, None);

/// Bind and immediately paint one boot frame from the firmware framebuffer.
///
/// 绑定固件帧缓冲并立即绘制一帧启动画面。
pub fn init(framebuffer: FrameBuffer) -> Result<(), DisplayInputError> {
    let info = framebuffer.info();
    let layout = match info.pixel_format {
        PixelFormat::Rgb => PixelLayout::Rgb,
        PixelFormat::Bgr => PixelLayout::Bgr,
        PixelFormat::U8 => PixelLayout::Gray,
        _ => return Err(DisplayInputError::Unsupported),
    };
    let width = u32::try_from(info.width).map_err(|_| DisplayInputError::InvalidSurface)?;
    let height = u32::try_from(info.height).map_err(|_| DisplayInputError::InvalidSurface)?;
    let stride = u32::try_from(info.stride).map_err(|_| DisplayInputError::InvalidSurface)?;
    let bytes_per_pixel =
        u8::try_from(info.bytes_per_pixel).map_err(|_| DisplayInputError::InvalidSurface)?;
    let surface = SurfaceSpec {
        width,
        height,
        stride,
        bytes_per_pixel,
        layout,
    };
    let required = surface.validate()?;
    if required > info.byte_len as u64 {
        return Err(DisplayInputError::InvalidSurface);
    }
    #[cfg(target_arch = "x86_64")]
    let keyboard = crate::arch::x86_64::keyboard::init();
    #[cfg(not(target_arch = "x86_64"))]
    let keyboard = false;
    let session = DisplayInputSession::open(DisplayCapabilities {
        backend: Some(DisplayBackend::Framebuffer),
        surface: Some(surface),
        keyboard,
    })?;
    let buffer = framebuffer.into_buffer();
    let mut runtime = Runtime {
        base: buffer.as_mut_ptr() as usize,
        len: buffer.len(),
        surface,
        session,
        pressed: 0,
        released: 0,
        text: [b' '; TEXT_CELLS],
        cursor: 0,
        prompt_reported: false,
        echo_reported: false,
    };
    runtime.append_text(b"JASPER-OS NATIVE TERMINAL\n\n");
    runtime.paint_boot_frame()?;
    *DISPLAY.lock() = Some(runtime);
    Ok(())
}

/// Poll the real keyboard into the bounded session and update the visible state.
///
/// 轮询真实键盘并写入有界会话，同时更新可见状态。
pub fn poll_input() -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        let mut count = 0;
        for _ in 0..32 {
            let Some(key) = crate::arch::x86_64::keyboard::try_read_event() else {
                break;
            };
            let mut guard = DISPLAY.lock();
            let Some(runtime) = guard.as_mut() else {
                break;
            };
            if runtime.session.push_key(key).is_err() {
                break;
            }
            if key.pressed {
                runtime.pressed = runtime.pressed.saturating_add(1);
            } else {
                runtime.released = runtime.released.saturating_add(1);
            }
            runtime.paint_input_indicator();
            count += 1;
        }
        if count != 0 {
            report();
        }
        count
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

/// Remove one key transition for a terminal frontend.
///
/// 为终端前端取出一次按键状态变化。
pub fn next_key() -> Option<KeyInput> {
    DISPLAY
        .lock()
        .as_mut()
        .and_then(|runtime| runtime.session.pop_key().ok())
}

/// Render bytes emitted by the native terminal into the framebuffer text view.
///
/// 将原生终端输出绘制到 framebuffer 文本视图；无显示后端时安全忽略。
pub fn terminal_write(bytes: &[u8]) {
    let mut guard = DISPLAY.lock();
    let Some(runtime) = guard.as_mut() else {
        return;
    };
    runtime.append_text(bytes);
    let _ = runtime.paint_text_frame();
}

/// Report the real backend state without holding the display lock across output.
///
/// 不跨输出持有显示锁地报告真实后端状态。
pub fn report() {
    let snapshot = DISPLAY.lock().as_ref().map(|runtime| {
        (
            runtime.surface,
            runtime.session.keyboard_available(),
            runtime.session.frames(),
            runtime.session.pending_keys(),
            runtime.session.dropped_keys(),
            runtime.pressed,
            runtime.released,
        )
    });
    if let Some((surface, keyboard, frames, keys, dropped, pressed, released)) = snapshot {
        kprintln!(
            "[JSR-DISPLAY] backend=framebuffer keyboard={} width={} height={} stride={} bpp={} frames={} keys={} dropped={} pressed={} released={}",
            keyboard,
            surface.width,
            surface.height,
            surface.stride,
            surface.bytes_per_pixel,
            frames,
            keys,
            dropped,
            pressed,
            released
        );
    } else {
        kprintln!("[JSR-DISPLAY] backend=none keyboard=unavailable");
    }
}

impl Runtime {
    fn paint_boot_frame(&mut self) -> Result<(), DisplayInputError> {
        let required = usize::try_from(self.required_bytes()?)
            .map_err(|_| DisplayInputError::InvalidSurface)?;
        if self.len < required {
            return Err(DisplayInputError::InvalidSurface);
        }
        self.fill(0x0f, 0x17, 0x20);
        self.rect(0, 0, self.surface.width, 8, 0x29, 0xd3, 0xb6);
        self.rect(0, 8, self.surface.width, 2, 0x12, 0x36, 0x4a);
        let margin = self.surface.width / 12;
        let panel = self.surface.width / 4;
        let top = self.surface.height / 4;
        let height = self.surface.height / 3;
        self.rect(margin, top, panel, height, 0x17, 0x2a, 0x3c);
        self.rect(
            margin + panel + margin,
            top,
            panel,
            height,
            0x1c,
            0x35,
            0x4b,
        );
        self.rect(
            margin + 2 * (panel + margin),
            top,
            panel,
            height,
            0x20,
            0x40,
            0x59,
        );
        self.paint_text();
        let ticket = self.session.prepare_frame(self.required_bytes()?)?;
        self.session.commit_frame(ticket)?;
        Ok(())
    }

    fn paint_text_frame(&mut self) -> Result<(), DisplayInputError> {
        self.fill(0x08, 0x11, 0x18);
        self.rect(0, 0, self.surface.width, 6, 0x29, 0xd3, 0xb6);
        self.paint_text();
        let ticket = self.session.prepare_frame(self.required_bytes()?)?;
        self.session.commit_frame(ticket)?;
        Ok(())
    }

    fn append_text(&mut self, bytes: &[u8]) {
        for byte in bytes.iter().copied() {
            match byte {
                b'\r' => self.cursor -= self.cursor % TEXT_COLUMNS,
                b'\n' => self.newline(),
                0x08 => {
                    if self.cursor % TEXT_COLUMNS != 0 {
                        self.cursor -= 1;
                        self.text[self.cursor] = b' ';
                    }
                }
                0x20..=0x7e => {
                    self.text[self.cursor] = byte.to_ascii_uppercase();
                    self.cursor += 1;
                    if self.cursor % TEXT_COLUMNS == 0 {
                        self.newline();
                    }
                }
                _ => {}
            }
        }
        if !self.prompt_reported && self.contains_text(b"JASPER> ") {
            self.prompt_reported = true;
            kprintln!("[JSR-GTERM] prompt=visible");
        }
        if !self.echo_reported && self.contains_text(b"NATIVE-ECHO-OK") {
            self.echo_reported = true;
            kprintln!("[JSR-GTERM] output=echo-ok visible=true");
        }
    }

    fn newline(&mut self) {
        let row = self.cursor / TEXT_COLUMNS;
        if row + 1 == TEXT_ROWS {
            self.text.copy_within(TEXT_COLUMNS.., 0);
            self.text[TEXT_CELLS - TEXT_COLUMNS..].fill(b' ');
            self.cursor = TEXT_CELLS - TEXT_COLUMNS;
        } else {
            self.cursor = (row + 1) * TEXT_COLUMNS;
        }
    }

    fn contains_text(&self, needle: &[u8]) -> bool {
        if needle.is_empty() || needle.len() > TEXT_CELLS {
            return false;
        }
        self.text
            .windows(needle.len())
            .any(|window| window == needle)
    }

    fn paint_text(&mut self) {
        let origin_x = 16u32;
        let origin_y = 16u32;
        let cell_width = 12u32;
        let cell_height = 20u32;
        for row in 0..TEXT_ROWS {
            for column in 0..TEXT_COLUMNS {
                let character = self.text[row * TEXT_COLUMNS + column];
                if character == b' ' || character == 0 {
                    continue;
                }
                let glyph = glyph(character);
                for (glyph_row, bits) in glyph.iter().copied().enumerate() {
                    for glyph_column in 0..5u32 {
                        if bits & (1u8 << (4 - glyph_column as u8)) == 0 {
                            continue;
                        }
                        let x = origin_x + column as u32 * cell_width + glyph_column * 2;
                        let y = origin_y + row as u32 * cell_height + glyph_row as u32 * 2;
                        self.rect(x, y, 2, 2, 0xd8, 0xf3, 0xea);
                    }
                }
            }
        }
    }

    fn paint_input_indicator(&mut self) {
        let color = if self.pressed.wrapping_sub(self.released) & 1 == 0 {
            (0x29, 0xd3, 0xb6)
        } else {
            (0xf4, 0xb8, 0x42)
        };
        self.rect(
            self.surface.width.saturating_sub(24),
            16,
            16,
            16,
            color.0,
            color.1,
            color.2,
        );
        if let Ok(bytes) = self.required_bytes() {
            if let Ok(ticket) = self.session.prepare_frame(bytes) {
                let _ = self.session.commit_frame(ticket);
            }
        }
    }

    fn required_bytes(&self) -> Result<u64, DisplayInputError> {
        self.surface.validate()
    }

    fn fill(&mut self, red: u8, green: u8, blue: u8) {
        let width = self.surface.width as usize;
        let height = self.surface.height as usize;
        self.rect(0, 0, width as u32, height as u32, red, green, blue);
    }

    fn rect(&mut self, x: u32, y: u32, width: u32, height: u32, red: u8, green: u8, blue: u8) {
        let right = x.saturating_add(width).min(self.surface.width);
        let bottom = y.saturating_add(height).min(self.surface.height);
        for row in y..bottom {
            for column in x..right {
                self.pixel(column, row, red, green, blue);
            }
        }
    }

    fn pixel(&mut self, x: u32, y: u32, red: u8, green: u8, blue: u8) {
        let bpp = self.surface.bytes_per_pixel as usize;
        let offset = (y as usize * self.surface.stride as usize + x as usize).saturating_mul(bpp);
        if offset + bpp > self.len {
            return;
        }
        // SAFETY: geometry was validated against the owned framebuffer length.
        unsafe {
            let pointer = self.base as *mut u8;
            match self.surface.layout {
                PixelLayout::Rgb | PixelLayout::Bgr => {
                    let (first, third) = if self.surface.layout == PixelLayout::Rgb {
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
                PixelLayout::Gray => {
                    let gray = ((u16::from(red) + u16::from(green) + u16::from(blue)) / 3) as u8;
                    core::ptr::write_volatile(pointer.add(offset), gray);
                }
            }
        }
    }
}

/// Minimal 5x7 glyph set for the native text frontend.
///
/// 原生文本前端使用的最小 5x7 字形集；未知字符绘制为问号。
fn glyph(character: u8) -> [u8; 7] {
    match character.to_ascii_uppercase() {
        b'A' => [0x0e, 0x11, 0x11, 0x1f, 0x11, 0x11, 0x11],
        b'B' => [0x1e, 0x11, 0x11, 0x1e, 0x11, 0x11, 0x1e],
        b'C' => [0x0f, 0x10, 0x10, 0x10, 0x10, 0x10, 0x0f],
        b'D' => [0x1e, 0x11, 0x11, 0x11, 0x11, 0x11, 0x1e],
        b'E' => [0x1f, 0x10, 0x10, 0x1e, 0x10, 0x10, 0x1f],
        b'F' => [0x1f, 0x10, 0x10, 0x1e, 0x10, 0x10, 0x10],
        b'G' => [0x0f, 0x10, 0x10, 0x13, 0x11, 0x11, 0x0f],
        b'H' => [0x11, 0x11, 0x11, 0x1f, 0x11, 0x11, 0x11],
        b'I' => [0x1f, 0x04, 0x04, 0x04, 0x04, 0x04, 0x1f],
        b'J' => [0x01, 0x01, 0x01, 0x01, 0x11, 0x11, 0x0e],
        b'K' => [0x11, 0x12, 0x14, 0x18, 0x14, 0x12, 0x11],
        b'L' => [0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1f],
        b'M' => [0x11, 0x1b, 0x15, 0x15, 0x11, 0x11, 0x11],
        b'N' => [0x11, 0x19, 0x15, 0x13, 0x11, 0x11, 0x11],
        b'O' => [0x0e, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0e],
        b'P' => [0x1e, 0x11, 0x11, 0x1e, 0x10, 0x10, 0x10],
        b'Q' => [0x0e, 0x11, 0x11, 0x11, 0x15, 0x12, 0x0d],
        b'R' => [0x1e, 0x11, 0x11, 0x1e, 0x14, 0x12, 0x11],
        b'S' => [0x0f, 0x10, 0x10, 0x0e, 0x01, 0x01, 0x1e],
        b'T' => [0x1f, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04],
        b'U' => [0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0e],
        b'V' => [0x11, 0x11, 0x11, 0x11, 0x11, 0x0a, 0x04],
        b'W' => [0x11, 0x11, 0x11, 0x15, 0x15, 0x15, 0x0a],
        b'X' => [0x11, 0x11, 0x0a, 0x04, 0x0a, 0x11, 0x11],
        b'Y' => [0x11, 0x11, 0x0a, 0x04, 0x04, 0x04, 0x04],
        b'Z' => [0x1f, 0x01, 0x02, 0x04, 0x08, 0x10, 0x1f],
        b'0' => [0x0e, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0e],
        b'1' => [0x04, 0x0c, 0x04, 0x04, 0x04, 0x04, 0x0e],
        b'2' => [0x0e, 0x11, 0x01, 0x02, 0x04, 0x08, 0x1f],
        b'3' => [0x1e, 0x01, 0x01, 0x0e, 0x01, 0x01, 0x1e],
        b'4' => [0x02, 0x06, 0x0a, 0x12, 0x1f, 0x02, 0x02],
        b'5' => [0x1f, 0x10, 0x10, 0x1e, 0x01, 0x01, 0x1e],
        b'6' => [0x0e, 0x10, 0x10, 0x1e, 0x11, 0x11, 0x0e],
        b'7' => [0x1f, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08],
        b'8' => [0x0e, 0x11, 0x11, 0x0e, 0x11, 0x11, 0x0e],
        b'9' => [0x0e, 0x11, 0x11, 0x0f, 0x01, 0x01, 0x0e],
        b'>' => [0x10, 0x08, 0x04, 0x02, 0x04, 0x08, 0x10],
        b'<' => [0x01, 0x02, 0x04, 0x08, 0x04, 0x02, 0x01],
        b':' => [0x00, 0x04, 0x04, 0x00, 0x04, 0x04, 0x00],
        b'-' => [0x00, 0x00, 0x00, 0x1f, 0x00, 0x00, 0x00],
        b'=' => [0x00, 0x00, 0x1f, 0x00, 0x1f, 0x00, 0x00],
        b',' => [0x00, 0x00, 0x00, 0x00, 0x04, 0x04, 0x08],
        b'.' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x0c],
        b'/' => [0x01, 0x02, 0x02, 0x04, 0x08, 0x08, 0x10],
        b'_' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f],
        b'!' => [0x04, 0x04, 0x04, 0x04, 0x04, 0x00, 0x04],
        b'?' => [0x0e, 0x11, 0x01, 0x02, 0x04, 0x00, 0x04],
        _ => [0x0e, 0x11, 0x01, 0x02, 0x04, 0x00, 0x04],
    }
}
