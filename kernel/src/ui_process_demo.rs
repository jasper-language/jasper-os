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

use kernel_core::authz::{AccessScope, Decision, Effect, Operation, Reason, AUTHZ_FORMAT_VERSION};
use kernel_core::display_input::{KeyInput, PixelLayout, SurfaceSpec};
use kernel_core::frame::FRAME_SIZE;
use kernel_core::paging::MapFlags;
use kernel_core::ui_policy::UiDeviceCapabilities;
use kernel_core::ui_protocol::{
    decode_ui_frame, encode_ui_frame, UiFrameHeader, UiFrameKind, UiInputRecord,
    UI_FRAME_HEADER_BYTES,
};
use kernel_core::ui_service::{UiCapability, UiClientKey};
use kernel_core::ui_session::{
    UiInputEnvelope, UiSceneFacts, UiSessionKind, UiSessionRegistry, UiSessionScope,
};

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
const PEER_REQUEST_PAYLOAD: &[u8] = br##"{"ir_version":"0.1.0","identity_domain":"jasper-os/ui-probe","owner":"ui-peer","session":"session-peer","expected_revision":1,"next_revision":2,"ops":[{"op":"insert","parent":null,"index":0,"node":{"key":{"semantic_id":2,"generation":1},"element":{"kind":"container"},"semantics":{"role":"container","label":"Jasper Peer","focusable":false},"style":{"box":{"width":{"unit":"px","value":64},"height":{"unit":"px","value":64}},"paint":{"background":"#00FF00FF"}},"events":[],"children":[]}}]}"##;

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

fn session_scope(session_id: u64) -> UiSessionScope {
    UiSessionScope {
        user: 1,
        tenant: 1,
        session: session_id,
        display_seat: 1,
        input_seat: 1,
    }
}

fn pep_capability(
    subject: u64,
    scope: UiSessionScope,
    operation: Operation,
) -> Option<UiCapability> {
    let decision = Decision {
        format_version: AUTHZ_FORMAT_VERSION,
        issuer: kernel_core::authz::KERNEL_PEP_ISSUER,
        subject,
        executor_object: subject,
        executor_generation: 1,
        tenant: scope.tenant,
        domain: 1,
        operation,
        scope: AccessScope::User(scope.user),
        effect: if operation == Operation::ServiceUiInputRead {
            Effect::Read
        } else {
            Effect::Write
        },
        policy_epoch: 1,
        revocation_generation: Some(0),
        allowed: true,
        reason: Reason::Allowed,
    };
    UiCapability::from_decision(decision, operation).ok()
}

fn test_surface() -> SurfaceSpec {
    SurfaceSpec {
        width: TEST_SURFACE_WIDTH,
        height: TEST_SURFACE_HEIGHT,
        stride: TEST_SURFACE_WIDTH,
        bytes_per_pixel: 4,
        layout: PixelLayout::Rgba,
    }
}

fn ui_capabilities() -> UiDeviceCapabilities {
    UiDeviceCapabilities {
        display: true,
        keyboard: true,
        pointer: false,
        touch: false,
        split_layouts: false,
        multi_window: false,
        background_grants: true,
    }
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

fn run_round(round: u32) -> bool {
    let before = crate::baseline::baseline();
    let queued_before = ipc::queued_total();
    let host = proc::create("ui-process-host", host_calls());
    let service = proc::create("ui-service", service_calls());
    let peer = proc::create("ui-peer", service_calls());
    let (Ok(host), Ok(service), Ok(peer)) = (host, service, peer) else {
        check(false, "UI host/service process creation failed");
        return false;
    };
    let Ok((host_endpoint, service_endpoint)) = ipc::create_pair(host, service) else {
        check(false, "UI Channel pair creation failed");
        for process in [host, service, peer] {
            let _ = proc::exit_idle(process, -1);
            proc::reap(process);
        }
        kobj::run_cleanup(usize::MAX);
        check(
            crate::baseline::baseline() == before,
            "failed launch leaked resources",
        );
        return false;
    };
    let Ok((peer_host_endpoint, peer_service_endpoint)) = ipc::create_pair(host, peer) else {
        check(false, "UI peer Channel pair creation failed");
        for process in [host, service, peer] {
            let _ = proc::exit_idle(process, -1);
            proc::reap(process);
        }
        kobj::run_cleanup(usize::MAX);
        check(
            crate::baseline::baseline() == before,
            "failed peer launch leaked resources",
        );
        return false;
    };

    let subject = service.raw();
    let peer_subject = peer.raw();
    let scope = session_scope(u64::from(round) + 1);
    let peer_scope = session_scope(100 + u64::from(round));
    let mut sessions = UiSessionRegistry::<2>::new();
    let Some(create_capability) = pep_capability(subject, scope, Operation::ServiceUiSessionCreate)
    else {
        check(false, "UI session create capability was not admitted");
        return false;
    };
    let Ok((initial_key, _)) = sessions.open(
        subject,
        scope,
        UiSessionKind::Remote,
        ui_capabilities(),
        Some(test_surface()),
        create_capability,
    ) else {
        check(false, "UI session was not admitted");
        return false;
    };
    check(
        sessions.disconnect(subject, initial_key).is_ok(),
        "remote UI session did not disconnect",
    );
    let Some(recovery_capability) =
        pep_capability(subject, scope, Operation::ServiceUiSessionCreate)
    else {
        check(false, "UI recovery capability was not admitted");
        return false;
    };
    let Ok((session_key, input_generation)) =
        sessions.recover(subject, scope, initial_key, recovery_capability)
    else {
        check(false, "remote UI session did not recover explicitly");
        return false;
    };
    check(
        sessions.surface_for(subject, initial_key).is_err(),
        "old remote UI session generation survived recovery",
    );
    let scene_ok = sessions
        .set_scene(
            subject,
            scope,
            session_key,
            UiSceneFacts {
                visible: true,
                rendering: true,
            },
        )
        .is_ok();
    check(scene_ok, "UI session Scene facts were not admitted");
    let Some(focus_capability) = pep_capability(subject, scope, Operation::ServiceUiFocusSet)
    else {
        check(false, "UI focus capability was not admitted");
        return false;
    };
    let focus_ok = sessions
        .focus(subject, scope, session_key, true, focus_capability)
        .is_ok();
    check(focus_ok, "UI session did not acquire focus");
    let input_capability =
        pep_capability(subject, scope, Operation::ServiceUiInputRead).expect("UI input capability");
    let Some(peer_create_capability) =
        pep_capability(peer_subject, peer_scope, Operation::ServiceUiSessionCreate)
    else {
        check(false, "peer UI session capability was not admitted");
        return false;
    };
    let Ok((peer_key, _)) = sessions.open(
        peer_subject,
        peer_scope,
        UiSessionKind::Remote,
        ui_capabilities(),
        Some(test_surface()),
        peer_create_capability,
    ) else {
        check(false, "peer UI session was not admitted");
        return false;
    };
    let hidden_scene = UiSceneFacts {
        visible: false,
        rendering: true,
    };
    let peer_ordinary_background_rejected = sessions
        .set_scene(peer_subject, peer_scope, peer_key, hidden_scene)
        .is_err();
    check(
        peer_ordinary_background_rejected,
        "peer rendering without a background grant was accepted",
    );
    let Some(peer_present_capability) =
        pep_capability(peer_subject, peer_scope, Operation::ServiceUiFramePresent)
    else {
        check(false, "peer background capability was not admitted");
        return false;
    };
    let peer_background_ok = sessions
        .grant_background(peer_subject, peer_scope, peer_key, peer_present_capability)
        .and_then(|_| sessions.set_scene(peer_subject, peer_scope, peer_key, hidden_scene))
        .is_ok();
    check(
        peer_background_ok,
        "authorized peer background rendering was not admitted",
    );
    let peer_client = UiClientKey::from_raw(peer_key.raw()).expect("nonzero peer UI client");
    let client = UiClientKey::from_raw(session_key.raw()).expect("nonzero UI client");
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
        for process in [host, service, peer] {
            let _ = proc::exit_idle(process, -1);
            proc::reap(process);
        }
        kobj::run_cleanup(usize::MAX);
        check(
            crate::baseline::baseline() == before && ipc::queued_total() == queued_before,
            "missing hardware input leaked resources",
        );
        return false;
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
        modifiers: native_key.modifiers,
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
    let input_envelope = UiInputEnvelope {
        key: session_key,
        input_generation,
        sequence: 1,
        code: JSUI_ENTER_CODE,
        pressed: true,
        modifiers: u32::from(native_key.modifiers),
    };
    let input_ok = sessions
        .input(subject, scope, input_envelope, input_capability)
        .is_ok();
    check(input_ok, "focused UI session did not admit native input");
    let replay_rejected = sessions
        .input(subject, scope, input_envelope, input_capability)
        .is_err();
    check(replay_rejected, "replayed UI session input was accepted");
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
    let peer_header = UiFrameHeader {
        kind: UiFrameKind::Scene,
        flags: 0,
        client: peer_client,
        request_id: 21,
        sequence: 1,
        payload_bytes: PEER_REQUEST_PAYLOAD.len() as u32,
    };
    let mut peer_request = alloc::vec![0u8; UI_FRAME_HEADER_BYTES + PEER_REQUEST_PAYLOAD.len()];
    let peer_request_len = encode_ui_frame(peer_header, PEER_REQUEST_PAYLOAD, &mut peer_request)
        .expect("bounded peer UI request");
    let peer_sent = kobj::with(|table| {
        ipc::send_in(
            table,
            host,
            peer_host_endpoint,
            peer_request[..peer_request_len].to_vec(),
            &[],
        )
    });
    check(
        peer_sent == peer_request_len as i64,
        "peer request was not queued",
    );
    let peer_failure_header = UiFrameHeader {
        kind: UiFrameKind::Present,
        flags: 0,
        client: peer_client,
        request_id: 22,
        sequence: 2,
        payload_bytes: 0,
    };
    let mut peer_failure_request = [0u8; UI_FRAME_HEADER_BYTES];
    let peer_failure_len = encode_ui_frame(peer_failure_header, &[], &mut peer_failure_request)
        .expect("bounded peer failure request");
    let peer_failure_sent = kobj::with(|table| {
        ipc::send_in(
            table,
            host,
            peer_host_endpoint,
            peer_failure_request[..peer_failure_len].to_vec(),
            &[],
        )
    });
    check(
        peer_failure_sent == peer_failure_len as i64,
        "peer failure request was not queued",
    );
    check(
        ipc::queued(service, service_endpoint) == Some(4),
        "service endpoint did not receive Scene/Patch/Input/Close",
    );
    check(
        ipc::queued(peer, peer_service_endpoint) == Some(2),
        "peer endpoint did not receive Scene/Close",
    );

    let started = launch_service(service, service_endpoint.raw());
    let peer_started = started && launch_service(peer, peer_service_endpoint.raw());
    check(started, "UI Service ELF did not launch");
    check(peer_started, "peer UI Service ELF did not launch");
    if peer_started {
        sched::run();
    }
    check(
        sessions.close(subject, session_key).is_ok(),
        "UI session did not close",
    );
    crate::display::end_ui_input_capture();
    let state = proc::state(service);
    check(
        state == Some(ProcState::Exited { code: SERVICE_EXIT }),
        "UI Service did not complete the Scene/Input/Close loop",
    );
    let peer_state = proc::state(peer);
    check(
        peer_state == Some(ProcState::Exited { code: 65 }),
        "peer UI Service did not terminate through the protocol failure path",
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
    let peer_response_bytes = ipc::queued_body(host, peer_host_endpoint, ipc::MAX_MSG_BYTES);
    let peer_response_frame = peer_response_bytes
        .as_deref()
        .and_then(|bytes| decode_ui_frame(bytes).ok());
    let peer_response_ok = peer_response_frame.as_ref().is_some_and(|frame| {
        frame.header.kind == UiFrameKind::Present
            && frame.header.client == peer_client
            && frame.header.request_id == peer_header.request_id
            && frame.header.sequence == peer_header.sequence
            && frame.payload.starts_with(&[0x00, 0xff, 0x00, 0xff])
    });
    check(
        peer_response_ok,
        "resident peer UI Service did not deliver its background Present frame",
    );
    let peer_error_bytes = ipc::queued_body_at(host, peer_host_endpoint, 1, ipc::MAX_MSG_BYTES);
    let peer_error_frame = peer_error_bytes
        .as_deref()
        .and_then(|bytes| decode_ui_frame(bytes).ok());
    let peer_error_ok = peer_error_frame.as_ref().is_some_and(|frame| {
        frame.header.kind == UiFrameKind::Error
            && frame.header.client == peer_client
            && frame.header.request_id == peer_failure_header.request_id
            && frame.header.sequence == peer_failure_header.sequence
    });
    check(
        peer_error_ok,
        "peer UI Service did not emit its terminal Error frame",
    );
    let background_revoked = sessions
        .revoke_background(peer_subject, peer_scope, peer_key)
        .and_then(|_| sessions.set_scene(peer_subject, peer_scope, peer_key, hidden_scene))
        .is_err();
    check(
        background_revoked,
        "revoked peer background rendering was accepted",
    );
    let peer_close_ok = sessions.close(peer_subject, peer_key).is_ok();
    check(peer_close_ok, "peer UI session did not close");
    check(
        ipc::queued(host, peer_host_endpoint) == Some(2),
        "peer host endpoint did not retain Present and terminal Error responses",
    );
    check(
        peer_response_ok && peer_error_ok,
        "peer UI Service did not complete present then terminal failure",
    );

    let host_exit = proc::exit_idle(host, 0);
    let service_reaped = proc::reap(service).is_some();
    let peer_reaped = proc::reap(peer).is_some();
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
        service_reaped && peer_reaped && host_reaped,
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
    let session_isolation = scene_ok && focus_ok && input_ok && replay_rejected;
    check(
        session_isolation,
        "CPL3 UI session isolation did not complete",
    );
    kprintln!(
        "[JSR-UI-SESSION-ISOLATION] round={} remote_channel=true session_key=true scope=true recovered=true scene=true focus=true input_capability=true replay_rejected={} failed={}",
        round,
        replay_rejected,
        failed()
    );
    let mobile_ok = session_isolation
        && peer_response_ok
        && peer_ordinary_background_rejected
        && peer_background_ok
        && background_revoked
        && peer_error_ok
        && peer_close_ok
        && resources;
    check(mobile_ok, "two-process mobile foreground policy failed");
    kprintln!(
        "[JSR-UI-MOBILE] round={} primary_focus=true primary_input=true peer_resident=true peer_present={} ordinary_background_rejected={} background_grant={} background_revoked={} peer_failed=true resources={} failed={}",
        round,
        peer_response_ok,
        peer_ordinary_background_rejected,
        peer_background_ok,
        background_revoked,
        resources,
        failed()
    );

    // Reaching this marker proves the serial Console remains available after
    // the service process and all of its objects were reclaimed.
    kprintln!(
        "[JSR-UI-SESSION] round={} started={} channel=true request_queued={} engine=cpu rendered=true present=true patch=true input=true native_keyboard=true frames=3 display={} exit={} response={} terminal_alive=true resources={} checks={} failed={}",
        round,
        started,
        sent == request_len as i64,
        display_ok,
        SERVICE_EXIT,
        response_ok,
        resources,
        CHECKS.load(Ordering::Relaxed),
        failed()
    );
    failed() == 0
}

/// Launch two independent UI Services in sequence and verify complete teardown
/// between sessions.
pub fn run() -> u32 {
    warm_heap();
    let queued_before = ipc::queued_total();
    let mut rounds = 0u32;
    while rounds < 2 && run_round(rounds) {
        rounds += 1;
    }
    // Each round checks its own object/frame baseline. The monotonic kernel
    // heap may retain first-use capacity after round zero, so the restart gate
    // compares the second round against its own baseline rather than pretending
    // that heap capacity is a reclaimable process resource.
    let resources = rounds == 2 && ipc::queued_total() == queued_before;
    check(
        resources,
        "UI Service restart did not return to the global baseline",
    );
    kprintln!(
        "[JSR-UI-PROCESS] rounds=2 started=true channel=true request_queued=true engine=cpu rendered=true present=true patch=true input=true native_keyboard=true frames=6 display=true exit=0 response=true terminal_alive=true restart=true resources={} checks={} failed={}",
        resources,
        CHECKS.load(Ordering::Relaxed),
        failed()
    );
    failed()
}
