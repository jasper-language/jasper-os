//! Jasper-OS native command line.
//!
//! The process consumes only the versioned native terminal interface. It is
//! deliberately small: no Linux ABI, PTY, shell language, or privilege model is
//! involved. The first slice supports `help`, `echo <text>`, and `exit`.

#![no_std]
#![no_main]

use jasper_rt::{entry, ids, sys};
use kernel_core::jucs::{self, Command, Form, Invocation};
use kernel_core::terminal_editor::{EditEvent, LineEditor};
use kernel_core::update_service::{StatusRequest, StatusResponse, RESPONSE_BYTES, SCOPE_PLATFORM};
use kernel_core::update_status::{UpdateStatus, NO_SLOT};

const PROMPT: &[u8] = b"jasper> ";
const HELP: &[u8] = b"commands: help, echo <text>, system update status [--json], exit\n";

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

struct FixedText {
    bytes: [u8; 1280],
    len: usize,
}

impl FixedText {
    const fn new() -> Self {
        Self {
            bytes: [0; 1280],
            len: 0,
        }
    }

    fn push(&mut self, text: &[u8]) -> bool {
        let Some(end) = self.len.checked_add(text.len()) else {
            return false;
        };
        if end > self.bytes.len() {
            return false;
        }
        self.bytes[self.len..end].copy_from_slice(text);
        self.len = end;
        true
    }

    fn push_u64(&mut self, mut value: u64) -> bool {
        let mut digits = [0u8; 20];
        let mut at = digits.len();
        loop {
            at -= 1;
            digits[at] = b'0' + (value % 10) as u8;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        self.push(&digits[at..])
    }

    fn push_i64(&mut self, value: i64) -> bool {
        if value < 0 {
            self.push(b"-") && self.push_u64(value.unsigned_abs())
        } else {
            self.push_u64(value as u64)
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn push_hex(&mut self, bytes: &[u8]) -> bool {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in bytes {
            if !self.push(&[HEX[(byte >> 4) as usize], HEX[(byte & 0xf) as usize]]) {
                return false;
            }
        }
        true
    }
}

fn slot_name(slot: u8) -> &'static [u8] {
    match slot {
        0 => b"A",
        1 => b"B",
        _ => b"none",
    }
}

fn state_name(state: u8) -> &'static [u8] {
    match state {
        0 => b"empty",
        1 => b"candidate",
        2 => b"confirmed",
        3 => b"failed",
        _ => b"unknown",
    }
}

fn dispatch_jucs(invocation: Invocation, request_id: u64) -> bool {
    match (invocation.command, invocation.form) {
        (_, Form::Help) => write(jucs::UPDATE_STATUS_HELP.as_bytes()),
        (_, Form::Schema) => write(jucs::UPDATE_STATUS_SCHEMA.as_bytes()),
        (Command::UpdateStatus, Form::Invoke) => write_update_status(request_id, false),
        (Command::UpdateStatus, Form::Json) => write_update_status(request_id, true),
    }
}

fn write_update_error(code: i64, json: bool) -> bool {
    let mut output = FixedText::new();
    let ok = if json {
        output.push(b"{\"schema\":\"jucs.result/1\",\"command\":\"system.update.status\",\"status\":\"error\",\"code\":")
            && output.push_i64(code)
            && output.push(b"}\n")
    } else {
        output.push(b"jucs-error command=system.update.status code=")
            && output.push_i64(code)
            && output.push(b"\nsystem-update-failed\n")
    };
    ok && write(output.as_bytes())
}

fn write_update_status(request_id: u64, json: bool) -> bool {
    let request = StatusRequest {
        request_id,
        expected_generation: 0,
        scope: SCOPE_PLATFORM,
    }
    .encode();
    let mut output = [0u8; RESPONSE_BYTES];
    let result = unsafe {
        sys::call3(
            ids::SYSTEM_UPDATE_STATUS_QUERY,
            request.as_ptr() as u64,
            output.as_mut_ptr() as u64,
            output.len() as u64,
        )
    };
    if result != RESPONSE_BYTES as i64 {
        return write_update_error(if result < 0 { -result } else { result }, json);
    }
    let Some(response) = StatusResponse::decode(&output) else {
        return write(if json {
            b"{\"schema\":\"jucs.result/1\",\"command\":\"system.update.status\",\"status\":\"error\",\"code\":\"protocol\"}\n"
        } else {
            b"jucs-error command=system.update.status code=protocol\n"
        });
    };
    if response.authorization.request_id != request_id {
        return write(if json {
            b"{\"schema\":\"jucs.result/1\",\"command\":\"system.update.status\",\"status\":\"error\",\"code\":\"response_request\"}\n"
        } else {
            b"jucs-error command=system.update.status code=response_request\n"
        });
    }
    let status: UpdateStatus = response.status;
    if status.candidate_slot == NO_SLOT && status.candidate_release != 0 {
        return write(if json {
            b"{\"schema\":\"jucs.result/1\",\"command\":\"system.update.status\",\"status\":\"error\",\"code\":\"protocol\"}\n"
        } else {
            b"jucs-error command=system.update.status code=protocol\n"
        });
    }
    if json {
        return write_update_status_json(status, response.authorization.tenant, request_id);
    }
    let mut line = FixedText::new();
    let valid = line.push(b"system-update status=ok command=system.update.status generation=")
        && line.push_u64(status.service_generation)
        && line.push(b" transaction=")
        && line.push_u64(status.transaction_id)
        && line.push(b" active=")
        && line.push(slot_name(status.active_slot))
        && line.push(b" state=")
        && line.push(state_name(status.active_state))
        && line.push(b" release=")
        && line.push_u64(status.active_release)
        && line.push(b" attempts=")
        && line.push_u64(status.active_attempts as u64)
        && line.push(b" candidate=")
        && line.push(slot_name(status.candidate_slot))
        && line.push(b" candidate_release=")
        && line.push_u64(status.candidate_release)
        && line.push(b" rollback_floor=")
        && line.push_u64(status.rollback_floor)
        && line.push(b" security_epoch=")
        && line.push_u64(status.security_epoch)
        && line.push(b" schema=")
        && line.push_u64(status.data_schema_min as u64)
        && line.push(b"..")
        && line.push_u64(status.data_schema_max as u64)
        && line.push(b" caller=")
        && line.push_u64(status.caller_subject)
        && line.push(b" domain=")
        && line.push_u64(status.caller_domain as u64)
        && line.push(b" tenant=")
        && line.push_u64(response.authorization.tenant)
        && line.push(b" request=")
        && line.push_u64(response.authorization.request_id)
        && line.push(b"\nsystem-update-ok\n");
    if !valid {
        return false;
    }
    write(line.as_bytes())
}

fn write_update_status_json(status: UpdateStatus, tenant: u64, request_id: u64) -> bool {
    let mut line = FixedText::new();
    let mut ok = line.push(
        b"{\"schema\":\"service.update.status/1\",\"command\":\"system.update.status\",\"status\":\"ok\",\"generation\":",
    );
    ok &= line.push_u64(status.service_generation);
    ok &= line.push(b",\"transaction\":");
    ok &= line.push_u64(status.transaction_id);
    ok &= line.push(b",\"active\":{\"slot\":\"");
    ok &= line.push(slot_name(status.active_slot));
    ok &= line.push(b"\",\"state\":\"");
    ok &= line.push(state_name(status.active_state));
    ok &= line.push(b"\",\"release\":");
    ok &= line.push_u64(status.active_release);
    ok &= line.push(b",\"attempts\":");
    ok &= line.push_u64(status.active_attempts as u64);
    ok &= line.push(b",\"digest\":\"");
    ok &= line.push_hex(&status.active_digest);
    ok &= line.push(b"\"},\"candidate\":");
    if status.candidate_slot == NO_SLOT {
        ok &= line.push(b"null");
    } else {
        ok &= line.push(b"{\"slot\":\"");
        ok &= line.push(slot_name(status.candidate_slot));
        ok &= line.push(b"\",\"state\":\"");
        ok &= line.push(state_name(status.candidate_state));
        ok &= line.push(b"\",\"release\":");
        ok &= line.push_u64(status.candidate_release);
        ok &= line.push(b",\"attempts\":");
        ok &= line.push_u64(status.candidate_attempts as u64);
        ok &= line.push(b",\"digest\":\"");
        ok &= line.push_hex(&status.candidate_digest);
        ok &= line.push(b"\"}");
    }
    ok &= line.push(b",\"rollback_floor\":");
    ok &= line.push_u64(status.rollback_floor);
    ok &= line.push(b",\"security_epoch\":");
    ok &= line.push_u64(status.security_epoch);
    ok &= line.push(b",\"data_schema\":{\"min\":");
    ok &= line.push_u64(status.data_schema_min as u64);
    ok &= line.push(b",\"max\":");
    ok &= line.push_u64(status.data_schema_max as u64);
    ok &= line.push(b"},\"caller\":{\"subject\":");
    ok &= line.push_u64(status.caller_subject);
    ok &= line.push(b",\"domain\":");
    ok &= line.push_u64(status.caller_domain as u64);
    ok &= line.push(b",\"tenant\":");
    ok &= line.push_u64(tenant);
    ok &= line.push(b"},\"request\":");
    ok &= line.push_u64(request_id);
    ok &= line.push(b"}\n");
    ok && write(line.as_bytes())
}

fn write_jucs_parse_error(name: &str) -> bool {
    let mut output = FixedText::new();
    output.push(b"jucs-error command=system.update.status code=")
        && output.push(name.as_bytes())
        && output.push(b"\n")
        && write(output.as_bytes())
}

fn main(_: u64, _: u64) -> i32 {
    if !write(b"Jasper-OS native CLI\n") {
        return 1;
    }
    let mut editor = LineEditor::<256, 16, 256>::new();
    let mut next_status_request = 1u64;
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
        if command.starts_with(b"system update ")
            || command.starts_with(b"jucs ")
            || command.starts_with(b"jasper system ")
        {
            match jucs::parse(command) {
                Ok(invocation) => {
                    let request_id = next_status_request;
                    next_status_request = next_status_request.wrapping_add(1).max(1);
                    if !dispatch_jucs(invocation, request_id) {
                        return 3;
                    }
                }
                Err(error) if !write_jucs_parse_error(error.name()) => return 3,
                Err(_) => {}
            }
        } else if command == b"help" {
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
