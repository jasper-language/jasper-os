//! Jasper-OS native command line.
//!
//! The process consumes only the versioned native terminal interface. It is
//! deliberately small: no Linux ABI, PTY, shell language, or privilege model is
//! involved. The first slice supports `help`, `echo <text>`, and `exit`.

#![no_std]
#![no_main]

use jasper_rt::{entry, ids, sys};
use kernel_core::terminal_editor::{EditEvent, LineEditor};

const PROMPT: &[u8] = b"jasper> ";
const HELP: &[u8] = b"commands: help, echo <text>, exit\n";

fn write(bytes: &[u8]) -> bool {
    let result = unsafe {
        sys::call3(
            ids::SYSTEM_TERMINAL_WRITE,
            bytes.as_ptr() as u64,
            bytes.len() as u64,
            0,
        )
    };
    result == bytes.len() as i64
}

fn read_byte() -> Result<u8, ()> {
    let mut byte = 0u8;
    let count = unsafe {
        sys::call3(
            ids::SYSTEM_TERMINAL_READ,
            (&mut byte as *mut u8) as u64,
            1,
            0,
        )
    };
    match count {
        1 => Ok(byte),
        0 => Err(()),
        _ => Err(()),
    }
}

fn redraw(editor: &LineEditor<256, 16, 256>) -> bool {
    if !write(b"\r") || !write(PROMPT) {
        return false;
    }
    let line = editor.line();
    line.is_empty() || write(line)
}

fn write_echo(text: &[u8]) -> bool {
    const PREFIX: &[u8] = b"native-echo=";
    const SUFFIX: &[u8] = b"\nnative-echo-ok\n";
    let mut output = [0u8; 300];
    let length = PREFIX.len() + text.len() + SUFFIX.len();
    if text.len() > 256 || length > output.len() {
        return false;
    }
    output[..PREFIX.len()].copy_from_slice(PREFIX);
    output[PREFIX.len()..PREFIX.len() + text.len()].copy_from_slice(text);
    output[PREFIX.len() + text.len()..length].copy_from_slice(SUFFIX);
    write(&output[..length])
}

fn main(_: u64, _: u64) -> i32 {
    if !write(b"Jasper-OS native CLI\n") {
        return 1;
    }
    let mut editor = LineEditor::<256, 16, 256>::new();
    loop {
        if !write(PROMPT) {
            return 1;
        }
        editor.begin_line();
        loop {
            let byte = match read_byte() {
                Ok(byte) => byte,
                Err(()) => {
                    let _ = write(b"native-bye\n");
                    return 0;
                }
            };
            match editor.input(byte) {
                EditEvent::Pending => {}
                EditEvent::Rejected => {
                    if !write(b"\x08 \x08") {
                        return 3;
                    }
                }
                EditEvent::Redraw => {
                    if !redraw(&editor) {
                        return 3;
                    }
                }
                EditEvent::Cancel => {
                    if !write(b"^C\n") {
                        return 3;
                    }
                    break;
                }
                EditEvent::Eof => {
                    if !write(b"native-bye\n") {
                        return 3;
                    }
                    return 0;
                }
                EditEvent::Submit => break,
            }
        }
        let command = editor.line();
        if command == b"help" {
            if !write(HELP) || !write(b"native-help-ok\n") {
                return 3;
            }
        } else if command == b"exit" {
            if !write(b"native-bye\n") {
                return 3;
            }
            return 0;
        } else if let Some(text) = command.strip_prefix(b"echo ") {
            if !write_echo(text) {
                return 3;
            }
        } else if command.is_empty() {
            editor.finish_submit();
            continue;
        } else {
            if !write(b"unknown command; use help\n") {
                return 3;
            }
        }
        editor.finish_submit();
    }
}

entry!(main);
