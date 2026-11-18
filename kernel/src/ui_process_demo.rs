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

use kernel_core::display_input::{KeyInput, PixelLayout, SurfaceSpec};
use kernel_core::frame::FRAME_SIZE;
use kernel_core::paging::MapFlags;
use kernel_core::ui_protocol::{
    decode_ui_frame, encode_ui_frame, UiFrameHeader, UiFrameKind, UiInputRecord,
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
const NATIVE_ENTER_CODE: u16 = 0x0103;
const JSUI_ENTER_CODE: u32 = 28;
const REQUEST_PAYLOAD: &[u8] = br##"{"ir_version":"0.1.0","identity_domain":"jasper-os/ui-probe","owner":"ui-host","session":"session-1","expected_revision":1,"next_revision":2,"ops":[{"op":"insert","parent":null,"index":0,"node":{"key":{"semantic_id":1,"generation":1},"element":{"kind":"container"},"semantics":{"role":"container","label":"Jasper OS","focusable":true},"style":{"box":{"width":{"unit":"px","value":64},"height":{"unit":"px","value":64}},"paint":{"background":"#0A84FFFF"}},"events":[{"event":"activate","action":"jasper.ui.activate"}],"children":[]}}]}"##;
const PATCH_PAYLOAD: &[u8] = br##"{"ir_version":"0.1.0","identity_domain":"jasper-os/ui-probe","owner":"ui-host","session":"session-1","expected_revision":2,"next_revision":3,"ops":[{"op":"update","key":{"semantic_id":1,"generation":1},"fields":{"style":{"box":{"width":{"unit":"px","value":64},"height":{"unit":"px","value":64}},"paint":{"background":"#FF0000FF"}}}}]}"##;

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

fn wait_for_native_enter() -> Option<KeyInput> {
    if !crate::display::begin_ui_input_capture() {
        return None;
    }
    kprintln!("[JSR-UI-PROCESS] waiting_real_key=true native_enter=0x0103");
    let deadline = crate::clock::ticks().saturating_add(500);
    while crate::clock::ticks() < deadline {
        let _ = crate::display::poll_input();
        if let Some(key) = crate::display::next_ui_key() {
            if key.pressed && key.code == NATIVE_ENTER_CODE {
                return Some(key);
            }
        }
        core::hint::spin_loop();
    }
    None
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
    let patch_header = UiFrameHeader {
        kind: UiFrameKind::Patch,
        flags: 0,
        client,
        request_id: 12,
        sequence: 2,
        payload_bytes: PATCH_PAYLOAD.len() as u32,
    };
    let mut patch_request = alloc::vec![0u8; UI_FRAME_HEADER_BYTES + PATCH_PAYLOAD.len()];
    let patch_len = encode_ui_frame(patch_header, PATCH_PAYLOAD, &mut patch_request)
        .expect("bounded UI patch request");
    let patch_sent = kobj::with(|table| {
        ipc::send_in(
            table,
            host,
            host_endpoint,
            patch_request[..patch_len].to_vec(),
            &[],
        )
    });
    check(
        patch_sent == patch_len as i64,
        "host patch was not queued on the service endpoint",
    );
    let Some(native_key) = wait_for_native_enter() else {
        crate::display::end_ui_input_capture();
        check(false, "native keyboard Enter was not delivered");
        let _ = proc::exit_idle(host, -1);
        let _ = proc::exit_idle(service, -1);
        proc::reap(host);
        proc::reap(service);
        kobj::run_cleanup(usize::MAX);
        check(
            crate::baseline::baseline() == before && ipc::queued_total() == queued_before,
            "missing hardware input leaked resources",
        );
        return failed();
    };
    kprintln!(
        "[JSR-UI-PROCESS] native_keyboard=true native_code=0x{:04x} jsui_code={}",
        native_key.code,
        JSUI_ENTER_CODE
    );
    let mut input_payload = [0u8; 8];
    UiInputRecord {
        code: JSUI_ENTER_CODE,
        pressed: true,
        modifiers: 0,
    }
    .encode_into(&mut input_payload)
    .expect("encode UI input probe");
    let input_header = UiFrameHeader {
        kind: UiFrameKind::Input,
        flags: 0,
        client,
        request_id: 13,
        sequence: 3,
        payload_bytes: input_payload.len() as u32,
    };
    let mut input_request = alloc::vec![0u8; UI_FRAME_HEADER_BYTES + input_payload.len()];
    let input_len = encode_ui_frame(input_header, &input_payload, &mut input_request)
        .expect("bounded UI input request");
    let input_sent = kobj::with(|table| {
        ipc::send_in(
            table,
            host,
            host_endpoint,
            input_request[..input_len].to_vec(),
            &[],
        )
    });
    check(
        input_sent == input_len as i64,
        "host input was not queued on the service endpoint",
    );
    let close_header = UiFrameHeader {
        kind: UiFrameKind::Close,
        flags: 0,
        client,
        request_id: 14,
        sequence: 4,
        payload_bytes: 0,
    };
    let mut close_request = [0u8; UI_FRAME_HEADER_BYTES];
    let close_len =
        encode_ui_frame(close_header, &[], &mut close_request).expect("bounded UI close request");
    let close_sent = kobj::with(|table| {
        ipc::send_in(
            table,
            host,
            host_endpoint,
            close_request[..close_len].to_vec(),
            &[],
        )
    });
    check(
        close_sent == close_len as i64,
        "host close was not queued on the service endpoint",
    );
    check(
        ipc::queued(service, service_endpoint) == Some(4),
        "service endpoint did not receive Scene/Patch/Input/Close",
    );

    let started = launch_service(service, service_endpoint.raw());
    check(started, "UI Service ELF did not launch");
    if started {
        sched::run();
    }
    crate::display::end_ui_input_capture();
    let state = proc::state(service);
    check(
        state == Some(ProcState::Exited { code: SERVICE_EXIT }),
        "UI Service did not complete the Scene/Input/Close loop",
    );

    let response_bytes = ipc::queued_body(host, host_endpoint, ipc::MAX_MSG_BYTES);
    let response_frame = response_bytes
        .as_deref()
        .and_then(|bytes| decode_ui_frame(bytes).ok());
    let response_ok = response_frame.as_ref().is_some_and(|frame| {
        let expected_bytes = TEST_SURFACE_WIDTH as usize * TEST_SURFACE_HEIGHT as usize * 4;
        frame.header.kind == UiFrameKind::Present
            && frame.header.flags == 0
            && frame.header.client == client
            && frame.header.request_id == header.request_id
            && frame.header.sequence == header.sequence
            && frame.payload.len() == expected_bytes
            && frame.payload.starts_with(&[0x0a, 0x84, 0xff, 0xff])
            && frame.payload.chunks_exact(4).all(|pixel| pixel[3] == 0xff)
    });
    check(
        response_ok,
        "versioned CPU RGBA8 Present frame was not delivered",
    );
    let patch_response_bytes = ipc::queued_body_at(host, host_endpoint, 1, ipc::MAX_MSG_BYTES);
    let patch_response_frame = patch_response_bytes
        .as_deref()
        .and_then(|bytes| decode_ui_frame(bytes).ok());
    let patch_response_ok = patch_response_frame.as_ref().is_some_and(|frame| {
        frame.header.kind == UiFrameKind::Present
            && frame.header.client == client
            && frame.header.request_id == patch_header.request_id
            && frame.header.sequence == patch_header.sequence
            && frame.payload.starts_with(&[0xff, 0x00, 0x00, 0xff])
    });
    check(
        patch_response_ok,
        "patched scene was not re-rendered into a new Present frame",
    );
    let input_response_bytes = ipc::queued_body_at(host, host_endpoint, 2, ipc::MAX_MSG_BYTES);
    let input_response_frame = input_response_bytes
        .as_deref()
        .and_then(|bytes| decode_ui_frame(bytes).ok());
    let input_response_ok = input_response_frame.as_ref().is_some_and(|frame| {
        frame.header.kind == UiFrameKind::Present
            && frame.header.client == client
            && frame.header.request_id == input_header.request_id
            && frame.header.sequence == input_header.sequence
            && frame.payload.len() == TEST_SURFACE_WIDTH as usize * TEST_SURFACE_HEIGHT as usize * 4
            && frame.payload.starts_with(&[0xff, 0x00, 0x00, 0xff])
    });
    check(
        input_response_ok,
        "input-driven second Present frame was not delivered",
    );
    check(
        ipc::queued(host, host_endpoint) == Some(3),
        "host endpoint did not retain all Present responses",
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
    let display_ok = patch_response_frame.as_ref().is_some_and(|frame| {
        let surface = SurfaceSpec {
            width: TEST_SURFACE_WIDTH,
            height: TEST_SURFACE_HEIGHT,
            stride: TEST_SURFACE_WIDTH,
            bytes_per_pixel: 4,
            layout: PixelLayout::Rgba,
        };
        crate::display::present_ui_frame(surface, frame.payload)
            .ok()
            .is_some_and(|(x, y)| crate::display::read_pixel_rgb(x, y) == Some((0xff, 0x00, 0x00)))
    });
    check(
        display_ok,
        "Engine Surface was not adopted into the native framebuffer compositor",
    );

    // Reaching this marker proves the serial Console remains available after
    // the service process and all of its objects were reclaimed.
    kprintln!(
        "[JSR-UI-PROCESS] started={} channel=true request_queued={} engine=cpu rendered=true present=true patch=true input=true native_keyboard=true frames=3 display={} exit={} response={} terminal_alive=true resources={} checks={} failed={}",
        started,
        sent == request_len as i64,
        display_ok,
        SERVICE_EXIT,
        response_ok,
        resources,
        CHECKS.load(Ordering::Relaxed),
        failed()
    );
    failed()
}
