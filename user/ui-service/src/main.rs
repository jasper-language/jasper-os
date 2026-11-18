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
    // A broker probe may send a zero-length readiness request. We only report
    // the exact blocker and never synthesize a scene/frame completion.
    let mut request = [0u8; 256];
    match endpoint.receive(&mut request) {
        Ok(_) => {
            let _ = endpoint.send(b"service.ui.error.engine_unavailable");
            69
        }
        Err(error) => {
            println!("ui-service: refuse reason={}", error.name());
            69
        }
    }
}
