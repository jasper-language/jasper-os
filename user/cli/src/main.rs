//! Jasper-OS native command line.
//!
//! The process consumes only the versioned native terminal interface. It is
//! deliberately small: no Linux ABI, PTY, shell language, or privilege model is
//! involved. The first slice supports `help`, `echo <text>`, and `exit`.

#![no_std]
#![no_main]

use jasper_rt::{entry, ids, sys};

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

fn read_line(buffer: &mut [u8]) -> Option<usize> {
    let mut used = 0usize;
    while used < buffer.len() {
        let count = unsafe {
            sys::call3(
                ids::SYSTEM_TERMINAL_READ,
                buffer[used..].as_mut_ptr() as u64,
                1,
                0,
            )
        };
        if count < 0 {
            return None;
        }
        if count == 0 {
            return Some(used);
        }
        if count != 1 {
            return None;
        }
        used += 1;
        if buffer[used - 1] == b'\n' {
            return Some(used);
        }
    }
    Some(used)
}

fn trimmed(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    while end != 0 && matches!(line[end - 1], b'\r' | b'\n') {
        end -= 1;
    }
    &line[..end]
}

fn main(_: u64, _: u64) -> i32 {
    if !write(b"Jasper-OS native CLI\n") {
        return 1;
    }
    let mut buffer = [0u8; 256];
    loop {
        if !write(PROMPT) {
            return 1;
        }
        let count = match read_line(&mut buffer) {
            Some(count) => count,
            None => {
                let _ = write(b"terminal read failed\n");
                return 2;
            }
        };
        if count == 0 {
            let _ = write(b"native-bye\n");
            return 0;
        }
        let command = trimmed(&buffer[..count]);
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
            if !write(b"native-echo=")
                || !write(text)
                || !write(b"\n")
                || !write(b"native-echo-ok\n")
            {
                return 3;
            }
        } else if command.is_empty() {
            continue;
        } else {
            if !write(b"unknown command; use help\n") {
                return 3;
            }
        }
    }
}

entry!(main);
