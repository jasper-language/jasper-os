//! UI Service process skeleton for Jasper-OS.
//!
//! The process accepts a pre-opened native Channel handle from its launcher.
//! It fails closed while the pinned engine has no Jasper-OS target build; no
//! synthetic frame or host loopback success is emitted.
//!
//! UI Service 进程骨架通过启动者预先打开的 Jasper Channel 接收场景；固定引擎尚未
//! 具备 Jasper-OS 目标构建时明确失败关闭，不输出伪造帧或宿主回环成功。

#![no_std]
#![no_main]

use jasper_rt::{entry, println, Handle};
use jasper_ui_service::{EngineHost, EngineState, NativeUiEndpoint, UnavailableEngine};
use kernel_core::ui_protocol::{UiFrameHeader, UiFrameKind};
use kernel_core::ui_service::UI_ERROR_ENGINE_UNAVAILABLE;

entry!(main);

fn main(channel_handle: u64, _: u64) -> i32 {
    if channel_handle == 0 {
        println!("ui-service: refuse reason=missing-channel");
        return 64;
    }
    // SAFETY: the launcher transfers one Channel handle as main's first
    // argument; no other owner exists in this process.
    let endpoint = NativeUiEndpoint::from_handle(unsafe { Handle::from_raw(channel_handle) });
    let engine = UnavailableEngine;
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
    let response = UiFrameHeader {
        kind: UiFrameKind::Error,
        flags: 0,
        client: request.header.client,
        request_id: request.header.request_id,
        sequence: request.header.sequence,
        payload_bytes: UI_ERROR_ENGINE_UNAVAILABLE.len() as u32,
    };
    let mut response_bytes = [0u8; 128];
    if let Err(error) = endpoint.send_frame_into(
        response,
        UI_ERROR_ENGINE_UNAVAILABLE.as_bytes(),
        &mut response_bytes,
    ) {
        println!("ui-service: refuse reason={}", error.name());
        return 70;
    }
    69
}
