#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use jasper_rt::sys;
use jasper_rt::{entry, ids, println};
use kernel_core::usi;

entry!(main);

static NEXT_REQUEST: AtomicU32 = AtomicU32::new(1);

fn request_id() -> u64 {
    u64::from(NEXT_REQUEST.fetch_add(1, Ordering::Relaxed))
}

#[derive(Debug)]
struct Snapshot {
    info: usi::Info,
    processes: Vec<usi::Process>,
    modules: Vec<usi::Module>,
    lifecycle: Vec<usi::Module>,
    now: u64,
    request_ids: Vec<u64>,
}

fn query(id: u64, service: usi::Service, req: u64) -> Result<(usi::Header, Vec<u8>), i64> {
    let mut capacity = 256usize;
    loop {
        let mut buffer = vec![0u8; capacity];
        // SAFETY: the kernel validates the complete caller buffer before writing.
        let result = unsafe {
            sys::call3(
                id,
                req,
                buffer.as_mut_ptr() as u64,
                buffer.len() as u64,
            )
        };
        if result < 0 {
            return Err(result);
        }
        let required = result as usize;
        if required > buffer.len() {
            capacity = required;
            continue;
        }
        buffer.truncate(required);
        if buffer.len() < usi::HEADER_BYTES {
            return Err(-(ids::SYSTEM_USI_ERROR_SCHEMA as i64));
        }
        let mut raw = [0u8; usi::HEADER_BYTES];
        raw.copy_from_slice(&buffer[..usi::HEADER_BYTES]);
        let Some(header) = usi::Header::decode(&raw) else {
            return Err(-(ids::SYSTEM_USI_ERROR_SCHEMA as i64));
        };
        if header.service != service || header.request_id != req {
            return Err(-(ids::SYSTEM_USI_ERROR_REQUEST_ID as i64));
        }
        return Ok((header, buffer[usi::HEADER_BYTES..].to_vec()));
    }
}

fn decode_info(payload: &[u8]) -> Option<usi::Info> {
    let raw: &[u8; usi::INFO_BYTES] = payload.try_into().ok()?;
    usi::Info::decode(raw)
}

fn decode_processes(payload: &[u8]) -> Option<Vec<usi::Process>> {
    if payload.len() % usi::PROCESS_BYTES != 0 {
        return None;
    }
    let mut out = Vec::new();
    for bytes in payload.chunks_exact(usi::PROCESS_BYTES) {
        out.push(usi::Process::decode(bytes.try_into().ok()?)?);
    }
    Some(out)
}

fn decode_modules(payload: &[u8]) -> Option<Vec<usi::Module>> {
    if payload.len() % usi::MODULE_BYTES != 0 {
        return None;
    }
    let mut out = Vec::new();
    for bytes in payload.chunks_exact(usi::MODULE_BYTES) {
        out.push(usi::Module::decode(bytes.try_into().ok()?)?);
    }
    Some(out)
}

fn snapshot() -> Result<Snapshot, i64> {
    let mut request_ids = Vec::new();

    let req = request_id();
    request_ids.push(req);
    let (_, payload) = query(ids::SYSTEM_INFO_GET, usi::Service::Info, req)?;
    let info = decode_info(&payload).ok_or(-(ids::SYSTEM_USI_ERROR_SCHEMA as i64))?;

    let req = request_id();
    request_ids.push(req);
    let (_, payload) = query(ids::SYSTEM_PROCESS_LIST, usi::Service::ProcessList, req)?;
    let processes = decode_processes(&payload).ok_or(-(ids::SYSTEM_USI_ERROR_SCHEMA as i64))?;

    let req = request_id();
    request_ids.push(req);
    let (_, payload) = query(ids::SYSTEM_MODULE_LIST, usi::Service::ModuleList, req)?;
    let modules = decode_modules(&payload).ok_or(-(ids::SYSTEM_USI_ERROR_SCHEMA as i64))?;

    let req = request_id();
    request_ids.push(req);
    let (_, payload) =
        query(ids::SYSTEM_MODULE_LIFECYCLE_GET, usi::Service::ModuleLifecycle, req)?;
    let lifecycle = decode_modules(&payload).ok_or(-(ids::SYSTEM_USI_ERROR_SCHEMA as i64))?;

    let req = request_id();
    request_ids.push(req);
    let now = jasper_rt::time::now();

    Ok(Snapshot {
        info,
        processes,
        modules,
        lifecycle,
        now,
        request_ids,
    })
}

fn snapshot_key(s: &Snapshot) -> String {
    let profile = core::str::from_utf8(s.info.profile_name()).unwrap_or("?");
    format!(
        "abi={}.{}.{}:profile={}:modules={}:processes={}",
        (s.info.abi >> 32) as u16,
        ((s.info.abi >> 16) & 0xffff) as u16,
        (s.info.abi & 0xffff) as u16,
        profile,
        s.modules.len(),
        s.processes.len()
    )
}

fn render_human(s: &Snapshot) {
    println!(
        "usi: mode=human snapshot={} time={} requests={},{},{},{},{}",
        snapshot_key(s),
        s.now,
        s.request_ids[0],
        s.request_ids[1],
        s.request_ids[2],
        s.request_ids[3],
        s.request_ids[4]
    );
    println!(
        "usi: info profile={} online_cpus={} modules={} processes={} capabilities={}",
        core::str::from_utf8(s.info.profile_name()).unwrap_or("?"),
        s.info.online_cpus,
        s.info.modules,
        s.info.processes,
        s.info.capabilities
    );
    for process in &s.processes {
        println!(
            "usi: process pid={} app={} state={} threads={}/{}",
            process.pid,
            process.app,
            process.state,
            process.threads_live,
            process.threads_total
        );
    }
    for module in &s.lifecycle {
        println!(
            "usi: module name={} version={} state={} health={} effective={} available={}",
            core::str::from_utf8(module.name()).unwrap_or("?"),
            core::str::from_utf8(module.version()).unwrap_or("?"),
            module.state,
            module.health,
            module.effective_health,
            module.available != 0
        );
    }
}

fn render_json(s: &Snapshot) {
    let modules: Vec<String> = s
        .lifecycle
        .iter()
        .map(|module| {
            format!(
                "{{\"name\":\"{}\",\"version\":\"{}\",\"state\":{},\"health\":{},\"effective\":{},\"available\":{}}}",
                core::str::from_utf8(module.name()).unwrap_or("?"),
                core::str::from_utf8(module.version()).unwrap_or("?"),
                module.state,
                module.health,
                module.effective_health,
                module.available != 0
            )
        })
        .collect();
    let processes: Vec<String> = s
        .processes
        .iter()
        .map(|process| {
            format!(
                "{{\"pid\":{},\"app\":{},\"state\":{},\"threads_live\":{},\"threads_total\":{},\"exit_code\":{}}}",
                process.pid,
                process.app,
                process.state,
                process.threads_live,
                process.threads_total,
                process.exit_code
            )
        })
        .collect();
    println!(
        "usi: mode=json {{\"schema\":\"usi.v1\",\"snapshot\":\"{}\",\"time\":{},\"request_ids\":[{},{},{},{},{}],\"profile\":\"{}\",\"online_cpus\":{},\"capabilities\":{},\"processes\":[{}],\"modules\":[{}]}}",
        snapshot_key(s),
        s.now,
        s.request_ids[0],
        s.request_ids[1],
        s.request_ids[2],
        s.request_ids[3],
        s.request_ids[4],
        core::str::from_utf8(s.info.profile_name()).unwrap_or("?"),
        s.info.online_cpus,
        s.info.capabilities,
        processes.join(","),
        modules.join(",")
    );
}

fn denied() -> i32 {
    let calls = [
        (ids::SYSTEM_INFO_GET, usi::Service::Info),
        (ids::SYSTEM_PROCESS_LIST, usi::Service::ProcessList),
        (ids::SYSTEM_MODULE_LIST, usi::Service::ModuleList),
        (ids::SYSTEM_MODULE_LIFECYCLE_GET, usi::Service::ModuleLifecycle),
    ];
    let mut all = true;
    for (index, (id, _)) in calls.iter().enumerate() {
        // SAFETY: an unauthorized syscall is rejected before pointer validation.
        let result = unsafe { sys::call3(*id, request_id(), 0, 0) };
        let expected = -(ids::SYSTEM_ERROR_RIGHTS_DENIED as i64);
        all &= result == expected;
        println!("usi: denied index={} result={}", index, result);
    }
    // SAFETY: same rights gate applies to the existing time service.
    let time = unsafe { sys::call3(ids::SYSTEM_TIME_NOW, 0, 0, 0) };
    all &= time == -(ids::SYSTEM_ERROR_RIGHTS_DENIED as i64);
    println!(
        "usi: mode=denied all_denied={} time={}",
        all,
        time
    );
    if all { 0 } else { 9 }
}

fn module_available(name: &str) -> Result<bool, i64> {
    let s = snapshot()?;
    let module = s
        .lifecycle
        .iter()
        .find(|module| module.name() == name.as_bytes())
        .ok_or(-(ids::SYSTEM_USI_ERROR_SCHEMA as i64))?;
    Ok(module.available != 0)
}

fn idempotent_requests() -> i32 {
    let req = request_id();
    let first = query(ids::SYSTEM_INFO_GET, usi::Service::Info, req);
    let retry = query(ids::SYSTEM_INFO_GET, usi::Service::Info, req);
    let conflict = query(ids::SYSTEM_MODULE_LIST, usi::Service::ModuleList, req);
    let invalid = query(ids::SYSTEM_INFO_GET, usi::Service::Info, 0);
    let conflict_code = conflict.as_ref().err().copied().unwrap_or(0);
    let invalid_code = invalid.as_ref().err().copied().unwrap_or(0);
    let ok = first.is_ok()
        && retry.is_ok()
        && conflict == Err(-(ids::SYSTEM_USI_ERROR_REQUEST_ID as i64))
        && invalid == Err(-(ids::SYSTEM_USI_ERROR_REQUEST_ID as i64));
    println!(
        "usi: mode=idempotent retry={} conflict={} invalid={} ok={}",
        retry.is_ok(),
        conflict_code,
        invalid_code,
        ok
    );
    if ok { 0 } else { 8 }
}

fn capability_source() -> i32 {
    let mut source = [0u8; 24];
    source[0..2].copy_from_slice(&1u16.to_le_bytes());
    source[2..4].copy_from_slice(&24u16.to_le_bytes());
    source[4..8].copy_from_slice(&4u32.to_le_bytes());
    // SAFETY: source is a versioned 24-byte descriptor with kind=capability catalog.
    let source_handle = unsafe {
        sys::call3(
            ids::SYSTEM_EVENT_SOURCE_CREATE,
            source.as_ptr() as u64,
            0,
            0,
        )
    };
    if source_handle <= 0 {
        println!("usi: mode=capability source_error={}", source_handle);
        return 9;
    }

    let mut subscribe = [0u8; 32];
    subscribe[0..2].copy_from_slice(&1u16.to_le_bytes());
    subscribe[2..4].copy_from_slice(&32u16.to_le_bytes());
    subscribe[4..8].copy_from_slice(&1u32.to_le_bytes()); // State policy.
    subscribe[8..12].copy_from_slice(&16u32.to_le_bytes());
    // SAFETY: subscribe points at a writable 32-byte descriptor plus 16-byte snapshot.
    let sub_handle = unsafe {
        sys::call3(
            ids::SYSTEM_EVENT_SUBSCRIPTION_CREATE,
            source_handle as u64,
            subscribe.as_mut_ptr() as u64,
            0,
        )
    };
    if sub_handle <= 0 {
        let _ = unsafe {
            sys::call3(
                ids::SYSTEM_HANDLE_CLOSE,
                source_handle as u64,
                0,
                0,
            )
        };
        println!("usi: mode=capability subscription_error={}", sub_handle);
        return 10;
    }
    let mut version = [0u8; 8];
    version.copy_from_slice(&subscribe[16..24]);
    let mut mask = [0u8; 8];
    mask.copy_from_slice(&subscribe[24..32]);
    let version = u64::from_le_bytes(version);
    let mask = u64::from_le_bytes(mask);
    let _ = unsafe {
        sys::call3(ids::SYSTEM_HANDLE_CLOSE, sub_handle as u64, 0, 0)
    };
    let _ = unsafe {
        sys::call3(
            ids::SYSTEM_HANDLE_CLOSE,
            source_handle as u64,
            0,
            0,
        )
    };
    println!(
        "usi: mode=capability source=true subscription=true version={} mask={:#x}",
        version, mask
    );
    0
}

fn main(mode: u64, _: u64) -> i32 {
    match mode {
        0 => match snapshot() {
            Ok(s) => {
                render_human(&s);
                0
            }
            Err(error) => {
                println!("usi: mode=human error={}", error);
                1
            }
        },
        1 => match snapshot() {
            Ok(s) => {
                render_json(&s);
                0
            }
            Err(error) => {
                println!("usi: mode=json error={}", error);
                1
            }
        },
        2 => denied(),
        3 => match module_available("devices") {
            Ok(available) => {
                println!("usi: mode=degraded devices_available={}", available);
                if available { 3 } else { 0 }
            }
            Err(error) => {
                println!("usi: mode=degraded error={}", error);
                4
            }
        },
        4 => match module_available("devices") {
            Ok(available) => {
                println!("usi: mode=restored devices_available={}", available);
                if available { 0 } else { 5 }
            }
            Err(error) => {
                println!("usi: mode=restored error={}", error);
                6
            }
        },
        5 => idempotent_requests(),
        6 => capability_source(),
        _ => 7,
    }
}
