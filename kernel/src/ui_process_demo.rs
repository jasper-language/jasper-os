//! Real UI Service process launch and fail-closed acceptance.
//!
//! This drill embeds the independent `user/ui-service` ELF, creates a real
//! Channel pair between a host process and the service process, queues one
//! versioned JSUI scene request, and schedules the service through CPL3. The
//! independent Engine CPU core parses the Typed UI IR scene, renders it into a
//! host-owned RGBA8 Surface, and returns a JSUI Present frame. This proves the
//! first engine-to-Surface path, not full UI-OS input or display completion.
//!
//! 本演练装载真实的 `user/ui-service` ELF，建立宿主与服务进程之间的 Channel，
//! 投递一条 JSUI 场景请求并在 CPL3 调度服务。独立 Engine CPU 核心解析 Typed UI IR、
//! 渲染到宿主拥有的 RGBA8 Surface，并返回 JSUI Present 帧；这只证明首帧 Engine 到
//! Surface 路径，不冒充完整 UI-OS 输入或显示验收。

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::frame::FRAME_SIZE;
use kernel_core::paging::MapFlags;
use kernel_core::ui_protocol::{
    decode_ui_frame, encode_ui_frame, UiFrameHeader, UiFrameKind, MAX_UI_FRAME_PAYLOAD,
    UI_FRAME_HEADER_BYTES,
};
use kernel_core::ui_service::UiClientKey;

use crate::proc::{self, ProcState};
use crate::syscall::{table as abi, SyscallSet};
use crate::{arch, ipc, kobj, kprintln, sched};

static USER_UI_SERVICE: &[u8] = include_bytes!(env!("JSR_USER_UI_SERVICE"));

const STACK_TOP_OFF: u64 = 0xC0_0000;
const STACK_PAGES: u64 = 4;
const TEST_SURFACE_WIDTH: u32 = 64;
const TEST_SURFACE_HEIGHT: u32 = 64;
const SERVICE_EXIT: i64 = 0;
const REQUEST_PAYLOAD: &[u8] = br##"{"ir_version":"0.1.0","identity_domain":"jasper-os/ui-probe","owner":"ui-host","session":"session-1","expected_revision":1,"next_revision":2,"ops":[{"op":"insert","parent":null,"index":0,"node":{"key":{"semantic_id":1,"generation":1},"element":{"kind":"container"},"semantics":{"role":"container","label":"Jasper OS"},"style":{"box":{"width":{"unit":"px","value":64},"height":{"unit":"px","value":64}},"paint":{"background":"#0A84FFFF"}},"children":[]}}]}"##;

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

fn surface_argument() -> u64 {
    (u64::from(TEST_SURFACE_WIDTH) << 32) | u64::from(TEST_SURFACE_HEIGHT)
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
    proc::spawn_thread(
        pid,
        "ui-service",
        entry,
        base + STACK_TOP_OFF,
        channel,
        surface_argument(),
    )
    .is_ok()
}

/// Initialize enough monotonic kernel heap capacity for the bounded request and
/// response records before taking the reclamation baseline. The heap
/// intentionally does not shrink; this does not create or retain process
/// objects, so a real process/Channel leak cannot be hidden by the warm-up.
fn warm_heap() {
    // Typed UI IR parsing, the 64 KiB maximum request, layout state and the
    // returned RGBA8 frame all allocate from the process heap. Warm the
    // monotonic kernel heap to a capacity derived from the transport bound.
    let capacity = kernel_core::config::bounds::MSG_BYTES.saturating_mul(8);
    let mut bytes = alloc::vec![0u8; capacity];
    bytes[0] = 1;
    let end = bytes.len() - 1;
    bytes[end] = 1;
    core::hint::black_box(bytes);
}

/// Launch the real UI Service, verify its versioned CPU frame and audit complete
/// Channel/process/frame reclamation.
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
    let mut request = alloc::vec![0u8; UI_FRAME_HEADER_BYTES + REQUEST_PAYLOAD.len()];
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
        "UI Service did not return first-frame exit code 0",
    );

    let response_bytes = ipc::queued_body(host, host_endpoint, ipc::MAX_MSG_BYTES);
    let response_ok = response_bytes.as_deref().is_some_and(|bytes| {
        decode_ui_frame(bytes).is_ok_and(|frame| {
            let expected_bytes = TEST_SURFACE_WIDTH as usize * TEST_SURFACE_HEIGHT as usize * 4;
            frame.header.kind == UiFrameKind::Present
                && frame.header.flags == 0
                && frame.header.client == client
                && frame.header.request_id == header.request_id
                && frame.header.sequence == header.sequence
                && frame.payload.len() == expected_bytes
                && frame.payload.starts_with(&[0x0a, 0x84, 0xff, 0xff])
                && frame.payload.chunks_exact(4).all(|pixel| pixel[3] == 0xff)
        })
    });
    check(
        response_ok,
        "versioned CPU RGBA8 Present frame was not delivered",
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
    // the service process and all of its objects were reclaimed.
    kprintln!(
        "[JSR-UI-PROCESS] started={} channel=true request_queued={} engine=cpu rendered=true present=true exit={} response={} terminal_alive=true resources={} checks={} failed={}",
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
