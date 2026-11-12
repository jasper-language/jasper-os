//! Polled i8042 keyboard input for the native display session.
//!
//! Responsibility: turn PS/2 set-1 make/break bytes into bounded key transitions.
//! The driver does not own terminal policy, execute shortcuts, or inject input
//! into another process.
//!
//! 原生显示会话使用的轮询式 i8042 键盘输入。驱动只把 PS/2 set-1 通码/断码
//! 转换为按键状态变化，不执行终端策略或跨进程输入注入。

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use kernel_core::display_input::KeyInput;

use super::port::{inb, outb};

const I8042_STATUS: u16 = 0x64;
const I8042_DATA: u16 = 0x60;
const STATUS_OUTPUT_FULL: u8 = 1 << 0;
const STATUS_INPUT_FULL: u8 = 1 << 1;
const STATUS_AUX_DATA: u8 = 1 << 5;
const COMMAND_ENABLE_FIRST_PORT: u8 = 0xAE;

const MOD_SHIFT: u8 = 1 << 0;
const MOD_CONTROL: u8 = 1 << 1;
const MOD_ALT: u8 = 1 << 2;

const CODE_ESCAPE: u16 = 0x0100;
const CODE_BACKSPACE: u16 = 0x0101;
const CODE_TAB: u16 = 0x0102;
const CODE_ENTER: u16 = 0x0103;
const CODE_LEFT_SHIFT: u16 = 0x0104;
const CODE_RIGHT_SHIFT: u16 = 0x0105;
const CODE_LEFT_CONTROL: u16 = 0x0106;
const CODE_LEFT_ALT: u16 = 0x0107;
const CODE_UP: u16 = 0x0110;
const CODE_DOWN: u16 = 0x0111;
const CODE_LEFT: u16 = 0x0112;
const CODE_RIGHT: u16 = 0x0113;

static MODIFIERS: AtomicU8 = AtomicU8::new(0);
static EXTENDED: AtomicBool = AtomicBool::new(false);

/// Enable and probe the first i8042 keyboard port.
///
/// 启用并探测 i8042 第一键盘端口。
pub fn init() -> bool {
    for _ in 0..100_000 {
        // SAFETY: read-only status polling before programming the standard controller.
        if unsafe { inb(I8042_STATUS) } & STATUS_INPUT_FULL == 0 {
            break;
        }
        core::hint::spin_loop();
    }
    // SAFETY: 0xAE is the standard i8042 command that enables the first PS/2 port.
    unsafe { outb(I8042_STATUS, COMMAND_ENABLE_FIRST_PORT) };
    for _ in 0..64 {
        // SAFETY: status bit 0 reports whether reading the data port is required.
        let status = unsafe { inb(I8042_STATUS) };
        if status == 0xFF || status & STATUS_OUTPUT_FULL == 0 {
            break;
        }
        // SAFETY: drain the controller output buffer before polling starts.
        let _ = unsafe { inb(I8042_DATA) };
    }
    // SAFETY: a controller with no ports reports 0xff on the status register.
    (unsafe { inb(I8042_STATUS) }) != 0xFF
}

/// Return one key transition without blocking.
///
/// 非阻塞返回一次按键状态变化。
pub fn try_read_event() -> Option<KeyInput> {
    for _ in 0..32 {
        // SAFETY: polling the standard i8042 status register is read-only.
        let status = unsafe { inb(I8042_STATUS) };
        if status == 0xFF || status & STATUS_OUTPUT_FULL == 0 {
            return None;
        }
        // SAFETY: the output-full bit guarantees one data-port read.
        let raw = unsafe { inb(I8042_DATA) };
        if status & STATUS_AUX_DATA != 0 {
            continue;
        }
        if raw == 0xE0 {
            EXTENDED.store(true, Ordering::Release);
            continue;
        }
        let extended = EXTENDED.swap(false, Ordering::AcqRel);
        let pressed = raw & 0x80 == 0;
        let make = raw & 0x7F;
        update_modifier(make, pressed);
        if let Some(code) = key_code(make, extended) {
            return Some(KeyInput {
                code,
                pressed,
                modifiers: MODIFIERS.load(Ordering::Acquire),
            });
        }
    }
    None
}

fn update_modifier(make: u8, pressed: bool) {
    let bit = match make {
        0x2A | 0x36 => MOD_SHIFT,
        0x1D => MOD_CONTROL,
        0x38 => MOD_ALT,
        _ => return,
    };
    let mut current = MODIFIERS.load(Ordering::Acquire);
    loop {
        let next = if pressed {
            current | bit
        } else {
            current & !bit
        };
        match MODIFIERS.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

fn key_code(make: u8, extended: bool) -> Option<u16> {
    if extended {
        return match make {
            0x48 => Some(CODE_UP),
            0x50 => Some(CODE_DOWN),
            0x4B => Some(CODE_LEFT),
            0x4D => Some(CODE_RIGHT),
            _ => None,
        };
    }
    match make {
        0x01 => Some(CODE_ESCAPE),
        0x0E => Some(CODE_BACKSPACE),
        0x0F => Some(CODE_TAB),
        0x1C => Some(CODE_ENTER),
        0x2A => Some(CODE_LEFT_SHIFT),
        0x36 => Some(CODE_RIGHT_SHIFT),
        0x1D => Some(CODE_LEFT_CONTROL),
        0x38 => Some(CODE_LEFT_ALT),
        0x10..=0x19 | 0x1E..=0x26 | 0x2C..=0x32 => {
            Some(u16::from(scancode_letter(make).to_ascii_uppercase()))
        }
        0x39 => Some(u16::from(b' ')),
        _ => None,
    }
}

fn scancode_letter(make: u8) -> u8 {
    const MAP: [u8; 54] = *b"??1234567890-=??qwertyuiop[]??asdfghjkl;'`??zxcvbnm,./";
    MAP.get(make as usize).copied().unwrap_or(b'?')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn letter_map_covers_printable_primary_keys() {
        assert_eq!(scancode_letter(0x10), b'q');
        assert_eq!(scancode_letter(0x1E), b'a');
        assert_eq!(scancode_letter(0x2C), b'z');
        assert_eq!(scancode_letter(0x39), b' ');
    }
}
