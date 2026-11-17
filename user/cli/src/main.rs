//! Jasper-OS native command line.
//!
//! The process consumes only the versioned native terminal interface. It is
//! deliberately small: no Linux ABI, PTY, shell language, or privilege model is
//! involved. The first slice supports `help`, `echo <text>`, and `exit`.

#![no_std]
#![no_main]

use jasper_rt::update::{
    NativeUpdateAuditTransport, NativeUpdateListTransport, NativeUpdateTransport,
};
use jasper_rt::{entry, ids, sys};
use kernel_core::jucs::{self, Command, Form, Invocation};
use kernel_core::terminal_editor::{EditEvent, LineEditor};
use kernel_core::update_agent::{AgentError, UpdateAgent, ACTION_JSON_BYTES, STATUS_JSON_BYTES};
use kernel_core::update_audit::{encode_audit_json, UpdateAuditClient, AUDIT_JSON_BYTES};
use kernel_core::update_client::{ClientError, UpdateClient};
use kernel_core::update_list_agent::{
    AgentListError, UpdateListAgent, UpdateListClient, LIST_JSON_BYTES,
};
use kernel_core::update_status::UpdateStatus;

const PROMPT: &[u8] = b"jasper> ";
const HELP: &[u8] =
    b"commands: help, echo <text>, system update status|recover|archive|list|audit [--json], exit\n";

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

fn terminal_name(stage: u8) -> &'static [u8] {
    match stage {
        0 => b"none",
        7 => b"complete",
        10 => b"rolled_back",
        _ => b"unknown",
    }
}

fn take_request(next: &mut u64) -> u64 {
    let request_id = *next;
    *next = (*next).wrapping_add(1).max(1);
    request_id
}

fn dispatch_jucs(invocation: Invocation, next_request: &mut u64) -> bool {
    match (invocation.command, invocation.form) {
        (Command::UpdateStatus, Form::Help) => write(jucs::UPDATE_STATUS_HELP.as_bytes()),
        (Command::UpdateStatus, Form::Schema) => write(jucs::UPDATE_STATUS_SCHEMA.as_bytes()),
        (Command::UpdateStatus, Form::Invoke) => {
            write_update_status(take_request(next_request), false)
        }
        (Command::UpdateStatus, Form::Json) => {
            write_update_status(take_request(next_request), true)
        }
        (Command::UpdateRecover, Form::Help) => write(jucs::UPDATE_RECOVER_HELP.as_bytes()),
        (Command::UpdateRecover, Form::Schema) => write(jucs::UPDATE_RECOVER_SCHEMA.as_bytes()),
        (Command::UpdateRecover, Form::Invoke) => {
            let status_request = take_request(next_request);
            let action_request = take_request(next_request);
            write_update_recovery(status_request, action_request, false)
        }
        (Command::UpdateRecover, Form::Json) => {
            let status_request = take_request(next_request);
            let action_request = take_request(next_request);
            write_update_recovery(status_request, action_request, true)
        }
        (Command::UpdateArchive, Form::Help) => write(jucs::UPDATE_ARCHIVE_HELP.as_bytes()),
        (Command::UpdateArchive, Form::Schema) => write(jucs::UPDATE_ARCHIVE_SCHEMA.as_bytes()),
        (Command::UpdateArchive, Form::Invoke) => {
            let status_request = take_request(next_request);
            let action_request = take_request(next_request);
            write_update_archive(status_request, action_request, false)
        }
        (Command::UpdateArchive, Form::Json) => {
            let status_request = take_request(next_request);
            let action_request = take_request(next_request);
            write_update_archive(status_request, action_request, true)
        }
        (Command::UpdateList, Form::Help) => write(jucs::UPDATE_LIST_HELP.as_bytes()),
        (Command::UpdateList, Form::Schema) => write(jucs::UPDATE_LIST_SCHEMA.as_bytes()),
        (Command::UpdateList, Form::Invoke) => write_update_list(take_request(next_request), false),
        (Command::UpdateList, Form::Json) => write_update_list(take_request(next_request), true),
        (Command::UpdateAudit, Form::Help) => write(jucs::UPDATE_AUDIT_HELP.as_bytes()),
        (Command::UpdateAudit, Form::Schema) => write(jucs::UPDATE_AUDIT_SCHEMA.as_bytes()),
        (Command::UpdateAudit, Form::Invoke) => {
            write_update_audit(take_request(next_request), false)
        }
        (Command::UpdateAudit, Form::Json) => write_update_audit(take_request(next_request), true),
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
    if json {
        let mut agent = UpdateAgent::new(NativeUpdateTransport);
        let mut output = [0u8; STATUS_JSON_BYTES];
        return match agent.status_json(request_id, 0, &mut output) {
            Ok(length) => write(&output[..length]),
            Err(error) => write_update_error(agent_error_code(error), true),
        };
    }
    let mut client = UpdateClient::new(NativeUpdateTransport);
    let response = match client.status(request_id, 0) {
        Ok(response) => response,
        Err(error) => return write_update_error(client_error_code(error), json),
    };
    let status: UpdateStatus = response.status;
    let mut line = FixedText::new();
    let valid = line.push(b"system-update status=ok command=system.update.status generation=")
        && line.push_u64(status.service_generation)
        && line.push(b" transaction=")
        && line.push_u64(status.transaction_id)
        && line.push(b" terminal=")
        && line.push(terminal_name(status.terminal_stage))
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

fn write_update_recovery(status_request_id: u64, action_request_id: u64, json: bool) -> bool {
    if json {
        let mut agent = UpdateAgent::new(NativeUpdateTransport);
        let mut output = [0u8; ACTION_JSON_BYTES];
        return match agent.recover_json(status_request_id, action_request_id, &mut output) {
            Ok(length) => write(&output[..length]),
            Err(error) => write_recovery_error(agent_error_code(error), true),
        };
    }
    let mut client = UpdateClient::new(NativeUpdateTransport);
    let response = match client.recover(status_request_id, action_request_id) {
        Ok(response) => response,
        Err(error) => return write_recovery_error(client_error_code(error), json),
    };
    let mut line = FixedText::new();
    let ok = line
        .push(b"system-update result=ok command=system.update.recover action=recover generation=")
        && line.push_u64(response.generation)
        && line.push(b" transaction=")
        && line.push_u64(response.transaction_id)
        && line.push(b" recovery_required=")
        && line.push(if response.recovery_required {
            b"true"
        } else {
            b"false"
        })
        && line.push(b" tenant=")
        && line.push_u64(response.tenant)
        && line.push(b" request=")
        && line.push_u64(response.request_id)
        && line.push(b"\nsystem-update-ok\n");
    ok && write(line.as_bytes())
}

fn write_recovery_error(code: i64, json: bool) -> bool {
    let mut output = FixedText::new();
    let ok = if json {
        output.push(
            b"{\"schema\":\"jucs.result/1\",\"command\":\"system.update.recover\",\"status\":\"error\",\"code\":",
        ) && output.push_i64(code)
            && output.push(b"}\n")
    } else {
        output.push(b"jucs-error command=system.update.recover code=")
            && output.push_i64(code)
            && output.push(b"\nsystem-update-failed\n")
    };
    ok && write(output.as_bytes())
}

fn write_update_archive(status_request_id: u64, action_request_id: u64, json: bool) -> bool {
    if json {
        let mut agent = UpdateAgent::new(NativeUpdateTransport);
        let mut output = [0u8; ACTION_JSON_BYTES];
        return match agent.archive_json(status_request_id, action_request_id, &mut output) {
            Ok(length) => write(&output[..length]),
            Err(error) => write_archive_error(agent_error_code(error), true),
        };
    }
    let mut client = UpdateClient::new(NativeUpdateTransport);
    let response = match client.archive(status_request_id, action_request_id) {
        Ok(response) => response,
        Err(error) => return write_archive_error(client_error_code(error), json),
    };
    let mut line = FixedText::new();
    let ok = line
        .push(b"system-update result=ok command=system.update.archive action=archive generation=")
        && line.push_u64(response.generation)
        && line.push(b" transaction=")
        && line.push_u64(response.transaction_id)
        && line.push(b" archived=")
        && line.push(if response.archived { b"true" } else { b"false" })
        && line.push(b" tenant=")
        && line.push_u64(response.tenant)
        && line.push(b" request=")
        && line.push_u64(response.request_id)
        && line.push(b"\nsystem-update-ok\n");
    ok && write(line.as_bytes())
}

fn write_archive_error(code: i64, json: bool) -> bool {
    let mut output = FixedText::new();
    let ok = if json {
        output.push(
            b"{\"schema\":\"jucs.result/1\",\"command\":\"system.update.archive\",\"status\":\"error\",\"code\":",
        ) && output.push_i64(code)
            && output.push(b"}\n")
    } else {
        output.push(b"jucs-error command=system.update.archive code=")
            && output.push_i64(code)
            && output.push(b"\nsystem-update-failed\n")
    };
    ok && write(output.as_bytes())
}

fn write_update_list(request_id: u64, json: bool) -> bool {
    if json {
        let mut agent = UpdateListAgent::new(NativeUpdateListTransport);
        let mut output = [0u8; LIST_JSON_BYTES];
        return match agent.list_json(request_id, &mut output) {
            Ok(length) => write(&output[..length]),
            Err(error) => write_list_error(agent_list_error_code(error), true),
        };
    }
    let mut client = UpdateListClient::new(NativeUpdateListTransport);
    let response = match client.list(request_id) {
        Ok(response) => response,
        Err(error) => return write_list_error(client_error_code(error), json),
    };
    for index in 0..response.len() {
        let Some(record) = response.record(index) else {
            return false;
        };
        let mut line = FixedText::new();
        let scope = scope_name(record.scope);
        let ok = line.push(b"system-update-update installation=")
            && line.push_u64(record.installation.to_raw())
            && line.push(b" package=")
            && line.push_u64(record.package.to_raw())
            && line.push(b" app_id=")
            && line.push_u64(record.app_id)
            && line.push(b" publisher=")
            && line.push_u64(record.publisher)
            && line.push(b" version=")
            && line.push_u64(u64::from(record.version))
            && line.push(b" scope=")
            && line.push(scope.0)
            && line.push(b":")
            && line.push_u64(scope.1)
            && line.push(b" source=")
            && line.push(source_name(record.source))
            && line.push(b" enabled=")
            && line.push(if record.enabled { b"true" } else { b"false" })
            && line.push(b"\n");
        if !ok || !write(line.as_bytes()) {
            return false;
        }
    }
    let mut summary = FixedText::new();
    let ok = summary.push(b"system-update list=ok command=system.update.list count=")
        && summary.push_u64(response.len() as u64)
        && summary.push(b" request=")
        && summary.push_u64(response.request_id())
        && summary.push(b"\nsystem-update-ok\n");
    ok && write(summary.as_bytes())
}

fn write_update_audit(request_id: u64, json: bool) -> bool {
    let mut client = UpdateAuditClient::new(NativeUpdateAuditTransport);
    let response = match client.query(request_id, 0) {
        Ok(response) => response,
        Err(error) => return write_audit_error(client_error_code(error), json),
    };
    if json {
        let mut output = [0u8; AUDIT_JSON_BYTES];
        return match encode_audit_json(response, &mut output) {
            Ok(length) => write(&output[..length]),
            Err(error) => write_audit_error(client_error_code(error), true),
        };
    }
    let mut line = FixedText::new();
    let mut ok = line.push(b"system-update audit=ok command=system.update.audit request=");
    ok &= line.push_u64(request_id);
    ok &= line.push(b" available=");
    ok &= line.push(if response.available {
        b"true"
    } else {
        b"false"
    });
    if response.available {
        ok &= line.push(b" sequence=");
        ok &= line.push_u64(response.archive_sequence);
        ok &= line.push(b" transaction=");
        ok &= line.push_u64(response.transaction_id);
        ok &= line.push(b" terminal=");
        ok &= line.push(match response.terminal_stage {
            7 => b"complete".as_slice(),
            10 => b"rolled_back".as_slice(),
            _ => b"unknown".as_slice(),
        });
    }
    ok &= line.push(b"\nsystem-update-ok\n");
    ok && write(line.as_bytes())
}

fn write_audit_error(code: i64, json: bool) -> bool {
    let mut output = FixedText::new();
    let ok = if json {
        output.push(
            b"{\"schema\":\"jucs.result/1\",\"command\":\"system.update.audit\",\"status\":\"error\",\"code\":",
        ) && output.push_i64(code)
            && output.push(b"}\n")
    } else {
        output.push(b"jucs-error command=system.update.audit code=")
            && output.push_i64(code)
            && output.push(b"\nsystem-update-failed\n")
    };
    ok && write(output.as_bytes())
}

fn write_list_error(code: i64, json: bool) -> bool {
    let mut output = FixedText::new();
    let ok = if json {
        output.push(
            b"{\"schema\":\"jucs.result/1\",\"command\":\"system.update.list\",\"status\":\"error\",\"code\":",
        ) && output.push_i64(code)
            && output.push(b"}\n")
    } else {
        output.push(b"jucs-error command=system.update.list code=")
            && output.push_i64(code)
            && output.push(b"\nsystem-update-failed\n")
    };
    ok && write(output.as_bytes())
}

fn scope_name(scope: kernel_core::native_install::OwnerScope) -> (&'static [u8], u64) {
    use kernel_core::native_install::OwnerScope;
    match scope {
        OwnerScope::System => (b"system", 0),
        OwnerScope::Device(id) => (b"device", id),
        OwnerScope::User(id) => (b"user", id),
        OwnerScope::Group(id) => (b"group", id),
        OwnerScope::Tenant(id) => (b"tenant", id),
        OwnerScope::Workload(id) => (b"workload", id),
    }
}

fn source_name(source: kernel_core::native_install::PackageSource) -> &'static [u8] {
    use kernel_core::native_install::PackageSource;
    match source {
        PackageSource::SystemBuiltin => b"system_builtin",
        PackageSource::Store => b"store",
        PackageSource::UserImport => b"user_import",
        PackageSource::Enterprise => b"enterprise",
        PackageSource::Developer => b"developer",
    }
}

fn client_error_code(error: ClientError) -> i64 {
    match error {
        ClientError::Transport(code) => code,
        ClientError::Protocol => ids::SYSTEM_UPDATE_ERROR_PROTOCOL as i64,
        ClientError::IdentityMismatch => ids::SYSTEM_UPDATE_ERROR_TENANT_SCOPE as i64,
        ClientError::RequestMismatch | ClientError::BindingMismatch => {
            ids::SYSTEM_UPDATE_ERROR_TRANSACTION_MISMATCH as i64
        }
    }
}

fn agent_error_code(error: AgentError) -> i64 {
    match error {
        AgentError::Client(error) => client_error_code(error),
        AgentError::BufferTooSmall => ids::SYSTEM_UPDATE_ERROR_BUFFER_TOO_SMALL as i64,
    }
}

fn agent_list_error_code(error: AgentListError) -> i64 {
    match error {
        AgentListError::Client(error) => client_error_code(error),
        AgentListError::BufferTooSmall => ids::SYSTEM_UPDATE_ERROR_BUFFER_TOO_SMALL as i64,
    }
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
                    if !dispatch_jucs(invocation, &mut next_status_request) {
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
