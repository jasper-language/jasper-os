//! Real UI Service process launch and fail-closed acceptance.
//!
//! This drill embeds the independent `user/ui-service` ELF, creates a real
//! Channel pair between a host process and the service process, queues one
//! versioned JSUI scene request, and schedules the service through CPL3. The
//! pinned engine is still not buildable for Jasper-OS, so success means the
//! service emitted the versioned engine-unavailable error and exited 69. It
//! never treats that blocker as a rendered frame or UI-OS-1 completion.
//!
//! 本演练装载真实的 `user/ui-service` ELF，建立宿主与服务进程之间的 Channel，
//! 投递一条 JSUI 场景请求并在 CPL3 调度服务。固定 Engine 仍不能构建 Jasper-OS
//! 目标，因此通过条件是服务真实返回 engine-unavailable 错误帧并以 69 退出；
//! 绝不把该阻塞状态冒充渲染帧或 UI-OS-1 完成。

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::frame::FRAME_SIZE;
use kernel_core::paging::MapFlags;
use kernel_core::ui_protocol::{decode_ui_frame, encode_ui_frame, UiFrameHeader, UiFrameKind};
use kernel_core::ui_service::{UiClientKey, UI_ERROR_ENGINE_UNAVAILABLE};

use crate::proc::{self, ProcState};
use crate::syscall::{table as abi, SyscallSet};
use crate::{arch, ipc, kobj, kprintln, sched};

static USER_UI_SERVICE: &[u8] = include_bytes!(env!("JSR_USER_UI_SERVICE"));

const STACK_TOP_OFF: u64 = 0xC0_0000;
const STACK_PAGES: u64 = 4;
const REQUEST_PAYLOAD: &[u8] = b"jasper-ui-process-probe-v1";
const SERVICE_EXIT: i64 = 69;

static CHECKS: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);

fn check(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-UI-PROCESS-FAIL] {}", what);
    }
}

/// Failed UI process assertions.
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

fn host_calls() -> SyscallSet {
    SyscallSet::of(&[abi::SYSTEM_CHANNEL_SEND, abi::SYSTEM_CHANNEL_RECV])
}

fn service_calls() -> SyscallSet {
    SyscallSet::of(&[
        abi::SYSTEM_CONSOLE_WRITE,
        abi::SYSTEM_MEMORY_MAP,
        abi::SYSTEM_CHANNEL_SEND,
        abi::SYSTEM_CHANNEL_RECV,
        abi::SYSTEM_HANDLE_CLOSE,
        abi::SYSTEM_PROCESS_EXIT,
    ])
}

fn request_header(client: UiClientKey) -> UiFrameHeader {
    UiFrameHeader {
        kind: UiFrameKind::Scene,
        flags: 0,
        client,
        request_id: 11,
        sequence: 1,
        payload_bytes: REQUEST_PAYLOAD.len() as u32,
    }
}

fn launch_service(pid: kernel_core::objtable::ObjId, channel: u64) -> bool {
    let base = arch::USER_WINDOW.0;
    let entry = match proc::load_elf(pid, USER_UI_SERVICE) {
        Ok(entry) => entry,
        Err(_) => return false,
    };
    for page in 1..=STACK_PAGES {
        if proc::map_new(
            pid,
            base + STACK_TOP_OFF - page * FRAME_SIZE,
            MapFlags::USER | MapFlags::WRITE,
        )
        .is_err()
        {
            return false;
        }
    }
    proc::spawn_thread(pid, "ui-service", entry, base + STACK_TOP_OFF, channel, 0).is_ok()
}

/// Initialize enough monotonic kernel heap capacity for the bounded request and
/// response records before taking the reclamation baseline. The heap
/// intentionally does not shrink; this does not create or retain process
/// objects, so a real process/Channel leak cannot be hidden by the warm-up.
fn warm_heap() {
    let mut bytes = alloc::vec![0u8; 128 * 1024];
    bytes[0] = 1;
    let end = bytes.len() - 1;
    bytes[end] = 1;
    core::hint::black_box(bytes);
}

/// Launch the real UI Service, verify its versioned failure response and audit
/// complete Channel/process/frame reclamation.
pub fn run() -> u32 {
    warm_heap();
    let before = crate::baseline::baseline();
    let queued_before = ipc::queued_total();
    let host = proc::create("ui-process-host", host_calls());
    let service = proc::create("ui-service", service_calls());
    let (Ok(host), Ok(service)) = (host, service) else {
        check(false, "UI host/service process creation failed");
        return failed();
    };
    let Ok((host_endpoint, service_endpoint)) = ipc::create_pair(host, service) else {
        check(false, "UI Channel pair creation failed");
        let _ = proc::exit_idle(host, -1);
        let _ = proc::exit_idle(service, -1);
        proc::reap(host);
        proc::reap(service);
        kobj::run_cleanup(usize::MAX);
        check(
            crate::baseline::baseline() == before,
            "failed launch leaked resources",
        );
        return failed();
    };

    let client = UiClientKey::from_raw((7u64 << 16) | 3).expect("nonzero UI client");
    let header = request_header(client);
    let mut request = [0u8; 128];
    let request_len =
        encode_ui_frame(header, REQUEST_PAYLOAD, &mut request).expect("bounded UI process request");
    let sent = kobj::with(|table| {
        ipc::send_in(
            table,
            host,
            host_endpoint,
            request[..request_len].to_vec(),
            &[],
        )
    });
    check(
        sent == request_len as i64,
        "host request was not queued on the service endpoint",
    );
    check(
        ipc::queued(service, service_endpoint) == Some(1),
        "service endpoint did not receive exactly one request",
    );

    let started = launch_service(service, service_endpoint.raw());
    check(started, "UI Service ELF did not launch");
    if started {
        sched::run();
    }
    let state = proc::state(service);
    check(
        state == Some(ProcState::Exited { code: SERVICE_EXIT }),
        "UI Service did not return engine-unavailable exit code 69",
    );

    let response_bytes = ipc::queued_body(host, host_endpoint, 256);
    let response_ok = response_bytes.as_deref().is_some_and(|bytes| {
        decode_ui_frame(bytes).is_ok_and(|frame| {
            frame.header.kind == UiFrameKind::Error
                && frame.header.flags == 0
                && frame.header.client == client
                && frame.header.request_id == header.request_id
                && frame.header.sequence == header.sequence
                && frame.payload == UI_ERROR_ENGINE_UNAVAILABLE.as_bytes()
        })
    });
    check(
        response_ok,
        "versioned engine-unavailable response was not delivered",
    );
    check(
        ipc::queued(host, host_endpoint) == Some(1),
        "host endpoint did not retain the service response",
    );

    let host_exit = proc::exit_idle(host, 0);
    let service_reaped = proc::reap(service).is_some();
    let host_reaped = proc::reap(host).is_some();
    kobj::run_cleanup(usize::MAX);
    let after = crate::baseline::baseline();
    let resources = after == before && ipc::queued_total() == queued_before;
    kprintln!(
        "[JSR-UI-PROCESS-BASELINE] before={:?} after={:?} queued={}/{}",
        before,
        after,
        queued_before,
        ipc::queued_total()
    );
    check(host_exit, "UI host process did not enter exited");
    check(
        service_reaped && host_reaped,
        "UI processes were not reaped",
    );
    check(
        resources,
        "UI Channel/process resources did not return to baseline",
    );

    // Reaching this marker proves the serial Console remains available after
    // the failed service process and all of its objects were reclaimed.
    kprintln!(
        "[JSR-UI-PROCESS] started={} channel=true request_queued={} blocked=true exit={} response={} terminal_alive=true resources={} checks={} failed={}",
        started,
        sent == request_len as i64,
        SERVICE_EXIT,
        response_ok,
        resources,
        CHECKS.load(Ordering::Relaxed),
        failed()
    );
    failed()
}
