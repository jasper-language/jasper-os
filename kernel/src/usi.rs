//! USI-1 read-only service queries.

use alloc::vec::Vec;

use kernel_core::assembly::{Health, State};
use kernel_core::usi;
use kernel_core::usi_request::Begin;

use crate::mm::user::copy_to_user;
use crate::syscall::table::{
    SYSTEM_ERROR_INVALID_ARGUMENT, SYSTEM_ERROR_QUOTA_EXCEEDED, SYSTEM_USI_ERROR_REQUEST_ID,
};
use crate::syscall::{err, user_ptr_err};
use crate::{assembly, proc, profile, sched};

struct RequestGuard {
    pid: kernel_core::objtable::ObjId,
    request_id: u64,
    service: u16,
    slot: Option<usize>,
}

impl RequestGuard {
    fn begin(request_id: u64, service: usi::Service) -> Result<Self, i64> {
        if request_id == 0 {
            return Err(err(SYSTEM_USI_ERROR_REQUEST_ID));
        }
        let pid = proc::current_process().ok_or_else(|| err(SYSTEM_ERROR_INVALID_ARGUMENT))?;
        let service_id = service as u16;
        let slot = match proc::begin_usi_request(pid, request_id, service_id) {
            Ok(Begin::New(slot)) => Some(slot),
            Ok(Begin::Retry) => None,
            Ok(Begin::Busy | Begin::Conflict) => {
                return Err(err(SYSTEM_USI_ERROR_REQUEST_ID));
            }
            Ok(Begin::Exhausted) => return Err(err(SYSTEM_ERROR_QUOTA_EXCEEDED)),
            Err(_) => return Err(err(SYSTEM_ERROR_INVALID_ARGUMENT)),
        };
        Ok(Self {
            pid,
            request_id,
            service: service_id,
            slot,
        })
    }

    fn complete(&mut self) {
        if let Some(slot) = self.slot.take() {
            proc::complete_usi_request(self.pid, slot, self.request_id, self.service);
        }
    }
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        if let Some(slot) = self.slot.take() {
            proc::abort_usi_request(self.pid, slot, self.request_id, self.service);
        }
    }
}

fn respond(
    request_id: u64,
    service: usi::Service,
    records: u32,
    payload: &[u8],
    ptr: u64,
    cap: u64,
    request: &mut RequestGuard,
) -> i64 {
    if request_id == 0 {
        return err(SYSTEM_USI_ERROR_REQUEST_ID);
    }
    request.complete();
    let Ok(capacity) = usize::try_from(cap) else {
        return err(SYSTEM_ERROR_INVALID_ARGUMENT);
    };
    let required = match usi::HEADER_BYTES.checked_add(payload.len()) {
        Some(value) => value,
        None => return err(SYSTEM_ERROR_INVALID_ARGUMENT),
    };
    if capacity < required {
        return required as i64;
    }
    let mut bytes = Vec::with_capacity(required);
    bytes.extend_from_slice(
        &usi::Header::new(
            request_id,
            service,
            payload.len() as u32,
            records,
        )
        .encode(),
    );
    bytes.extend_from_slice(payload);
    if let Err(error) = copy_to_user(ptr, &bytes, required) {
        return user_ptr_err(error);
    }
    required as i64
}

pub fn info_get(request_id: u64, ptr: u64, cap: u64) -> i64 {
    let mut request = match RequestGuard::begin(request_id, usi::Service::Info) {
        Ok(request) => request,
        Err(error) => return error,
    };
    let snapshot = proc::process_snapshot();
    let modules = assembly::statuses().modules().count();
    let resolved = match profile::resolved() {
        Some(value) => value,
        None => return err(SYSTEM_ERROR_INVALID_ARGUMENT),
    };
    let profile_name = profile::ACTIVE.name.as_bytes();
    let copy_len = profile_name.len().min(usi::MAX_PROFILE_NAME);
    let mut profile_bytes = [0u8; usi::MAX_PROFILE_NAME];
    profile_bytes[..copy_len].copy_from_slice(&profile_name[..copy_len]);
    let info = usi::Info {
        abi: kernel_core::abi_version::NATIVE.packed(),
        online_cpus: sched::online_cpus().len().min(u16::MAX as usize) as u16,
        modules: modules.min(u16::MAX as usize) as u16,
        processes: snapshot.len().min(u16::MAX as usize) as u16,
        capabilities: resolved.capabilities().len().min(u16::MAX as usize) as u16,
        profile_name_len: copy_len as u16,
        profile_name: profile_bytes,
    };
    respond(
        request_id,
        usi::Service::Info,
        1,
        &info.encode(),
        ptr,
        cap,
        &mut request,
    )
}

pub fn process_list(request_id: u64, ptr: u64, cap: u64) -> i64 {
    let mut request = match RequestGuard::begin(request_id, usi::Service::ProcessList) {
        Ok(request) => request,
        Err(error) => return error,
    };
    let snapshot = proc::process_snapshot();
    let mut payload = Vec::with_capacity(snapshot.len() * usi::PROCESS_BYTES);
    for process in &snapshot {
        payload.extend_from_slice(&process.encode());
    }
    respond(
        request_id,
        usi::Service::ProcessList,
        snapshot.len() as u32,
        &payload,
        ptr,
        cap,
        &mut request,
    )
}

pub fn module_list(request_id: u64, ptr: u64, cap: u64) -> i64 {
    module_records(request_id, usi::Service::ModuleList, ptr, cap)
}

pub fn module_lifecycle(request_id: u64, ptr: u64, cap: u64) -> i64 {
    module_records(request_id, usi::Service::ModuleLifecycle, ptr, cap)
}

fn module_records(
    request_id: u64,
    service: usi::Service,
    ptr: u64,
    cap: u64,
) -> i64 {
    let mut request = match RequestGuard::begin(request_id, service) {
        Ok(request) => request,
        Err(error) => return error,
    };
    let statuses = assembly::statuses();
    let mut payload = Vec::new();
    let mut records = 0u32;
    for (order, module) in statuses.modules().enumerate() {
        let Some(record) = module_record(module, order) else {
            return err(SYSTEM_ERROR_INVALID_ARGUMENT);
        };
        payload.extend_from_slice(&record.encode());
        records += 1;
    }
    respond(
        request_id,
        service,
        records,
        &payload,
        ptr,
        cap,
        &mut request,
    )
}

fn module_record(module: assembly::ModuleStatus, order: usize) -> Option<usi::Module> {
    usi::Module::from_parts(
        module.name,
        module.version,
        order as u16,
        state_code(module.state),
        health_code(module.health),
        health_code(module.effective_health),
        module.available,
    )
}

const fn state_code(state: State) -> u8 {
    match state {
        State::Declared => 0,
        State::Blocked => 1,
        State::Initializing => 2,
        State::Ready => 3,
        State::Failed => 4,
        State::Stopped => 5,
    }
}

const fn health_code(health: Health) -> u8 {
    match health {
        Health::Unknown => 0,
        Health::Healthy => 1,
        Health::Degraded => 2,
        Health::Unhealthy => 3,
    }
}
