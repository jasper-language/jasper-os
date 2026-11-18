//! UI Service process skeleton for Jasper-OS.
//!
//! The process accepts a pre-opened native Channel handle from its launcher.
//! With `native-engine-core` it renders one Typed UI IR scene through the real
//! pinned Engine CPU core and returns an RGBA8 Present frame. Builds without
//! that feature fail closed instead of emitting a synthetic frame.
//!
//! UI Service 进程通过启动者预先打开的 Jasper Channel 接收场景；开启
//! `native-engine-core` 时由固定 Engine CPU 核心渲染 RGBA8 Present 帧，未开启时
//! 明确失败关闭，不输出伪造帧或宿主回环成功。

#![no_std]
#![no_main]

extern crate alloc;

#[cfg(feature = "native-engine-core")]
use alloc::vec;
use jasper_rt::{entry, println, Handle};
#[cfg(feature = "native-engine-core")]
use jasper_ui_service::HostError;
use jasper_ui_service::NativeUiEndpoint;
#[cfg(feature = "native-engine-core")]
use jasper_ui_service::{CpuEngineHost, CpuFrame};
#[cfg(not(feature = "native-engine-core"))]
use jasper_ui_service::{EngineHost, EngineState, UnavailableEngine};
#[cfg(feature = "native-engine-core")]
use kernel_core::display_input::{PixelLayout, SurfaceSpec};
#[cfg(feature = "native-engine-core")]
use kernel_core::ui_protocol::MAX_UI_FRAME_PAYLOAD;
use kernel_core::ui_protocol::{UiFrameHeader, UiFrameKind};
#[cfg(not(feature = "native-engine-core"))]
use kernel_core::ui_service::UI_ERROR_ENGINE_UNAVAILABLE;

entry!(main);

fn fail_response(
    endpoint: &NativeUiEndpoint,
    request: UiFrameHeader,
    detail: &str,
    exit: i32,
) -> i32 {
    let response = UiFrameHeader {
        kind: UiFrameKind::Error,
        flags: 0,
        client: request.client,
        request_id: request.request_id,
        sequence: request.sequence,
        payload_bytes: detail.len() as u32,
    };
    if endpoint.send_frame(response, detail.as_bytes()).is_err() {
        return 70;
    }
    exit
}

#[cfg(feature = "native-engine-core")]
fn surface_from_argument(value: u64) -> Option<SurfaceSpec> {
    let width = u32::try_from(value >> 32).ok()?;
    let height = u32::try_from(value & u64::from(u32::MAX)).ok()?;
    let surface = SurfaceSpec {
        width,
        height,
        stride: width,
        bytes_per_pixel: 4,
        layout: PixelLayout::Rgba,
    };
    let bytes = surface.validate().ok()?;
    if bytes > jasper_ui_service::MAX_NATIVE_UI_FRAME_PAYLOAD as u64 {
        return None;
    }
    Some(surface)
}

#[cfg(feature = "native-engine-core")]
fn run_cpu_engine(
    endpoint: NativeUiEndpoint,
    surface: SurfaceSpec,
    request: kernel_core::ui_protocol::UiFrame<'_>,
) -> i32 {
    let engine = match CpuEngineHost::new(surface.width, surface.height) {
        Ok(engine) => engine,
        Err(error) => {
            return fail_response(&endpoint, request.header, error.name(), 72);
        }
    };
    let mut host = match jasper_ui_service::UiHost::new(engine, surface, 1) {
        Ok(host) => host,
        Err(error) => {
            return fail_response(&endpoint, request.header, error.name(), 72);
        }
    };
    let scene_version = match host.set_scene(request.payload) {
        Ok(version) => version,
        Err(error) => {
            return fail_response(&endpoint, request.header, error.name(), 69);
        }
    };
    let expected = match surface.validate() {
        Ok(bytes) => bytes as usize,
        Err(_) => {
            return fail_response(
                &endpoint,
                request.header,
                HostError::InvalidSurface.name(),
                72,
            )
        }
    };
    let mut frame = match CpuFrame::new(
        surface,
        1,
        scene_version,
        u64::from(request.header.sequence),
        vec![0; expected],
    ) {
        Ok(frame) => frame,
        Err(error) => {
            return fail_response(&endpoint, request.header, error.name(), 72);
        }
    };
    if let Err(error) = host.render(&mut frame) {
        return fail_response(&endpoint, request.header, error.name(), 69);
    }
    let response = UiFrameHeader {
        kind: UiFrameKind::Present,
        flags: 0,
        client: request.header.client,
        request_id: request.header.request_id,
        sequence: request.header.sequence,
        payload_bytes: frame.pixels().len() as u32,
    };
    if endpoint.send_frame(response, frame.pixels()).is_err() {
        return 70;
    }
    println!(
        "ui-service: presented {}x{} bytes={} sequence={}",
        surface.width,
        surface.height,
        frame.pixels().len(),
        frame.sequence()
    );
    0
}

fn main(channel_handle: u64, surface_argument: u64) -> i32 {
    if channel_handle == 0 {
        println!("ui-service: refuse reason=missing-channel");
        return 64;
    }
    // SAFETY: the launcher transfers one Channel handle as main's first
    // argument; no other owner exists in this process.
    let endpoint = NativeUiEndpoint::from_handle(unsafe { Handle::from_raw(channel_handle) });

    #[cfg(feature = "native-engine-core")]
    {
        println!("ui-service: ready protocol=1 engine=cpu-ready");
        let surface = match surface_from_argument(surface_argument) {
            Some(surface) => surface,
            None => {
                println!("ui-service: refuse reason=invalid-surface");
                return 72;
            }
        };
        let mut request_bytes = vec![0u8; MAX_UI_FRAME_PAYLOAD];
        let request = match endpoint.receive_frame(&mut request_bytes) {
            Ok(frame) if frame.header.kind == UiFrameKind::Scene => frame,
            Ok(_) => {
                println!("ui-service: refuse reason=invalid-frame-kind");
                return 65;
            }
            Err(error) => {
                println!("ui-service: refuse reason={}", error.name());
                return 68;
            }
        };
        return run_cpu_engine(endpoint, surface, request);
    }

    #[cfg(not(feature = "native-engine-core"))]
    let engine = UnavailableEngine;
    #[cfg(not(feature = "native-engine-core"))]
    {
        let _ = surface_argument;
        println!(
            "ui-service: ready protocol=1 engine={}",
            match engine.state() {
                EngineState::BlockedNoStd => "blocked-no-std",
                EngineState::CpuReady => "cpu-ready",
                EngineState::GpuReady => "gpu-ready",
            }
        );
        // The launcher sends one versioned scene request. Report the exact blocker
        // in a versioned error frame and never synthesize a successful scene.
        let mut request_bytes = [0u8; 512];
        let request = match endpoint.receive_frame(&mut request_bytes) {
            Ok(frame) if frame.header.kind == UiFrameKind::Scene => frame,
            Ok(_) => {
                println!("ui-service: refuse reason=invalid-frame-kind");
                return 65;
            }
            Err(error) => {
                println!("ui-service: refuse reason={}", error.name());
                return 68;
            }
        };
        return fail_response(&endpoint, request.header, UI_ERROR_ENGINE_UNAVAILABLE, 69);
    }
}
