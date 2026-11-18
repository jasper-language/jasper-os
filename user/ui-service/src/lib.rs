//! Jasper-OS host boundary for the pinned Jasper UI Engine.
//!
//! This crate owns no renderer or window policy. It validates the host surface,
//! engine state, input and output generations around an engine supplied by the
//! independent `jasper-ui-engine` repository. The current pinned engine target
//! is blocked on `std`; this adapter therefore reports that state instead of
//! fabricating a successful frame.
//!
//! 本 crate 是固定版本 Jasper UI Engine 的 Jasper-OS 宿主边界；不拥有渲染器或窗口
//! 策略。当前固定引擎尚未完成 `no_std` 目标构建，因此适配器必须明确返回阻塞状态，
//! 不能伪造成功帧。

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use kernel_core::display_input::{DisplayInputError, KeyInput, SurfaceSpec};
#[cfg(feature = "native-transport")]
use kernel_core::ui_protocol::{decode_ui_frame, encode_ui_frame, UiFrame, UiFrameHeader};
use kernel_core::ui_service::UI_SERVICE_PROTOCOL_VERSION;

/// UI Engine revision currently recorded by `ui-engine.lock.toml`.
pub const PINNED_ENGINE_COMMIT: &str = "4194117011f13fdc063977683162fd5a145c85d7";

/// Build-time engine availability. The independent engine repository must
/// provide a target-buildable core before this changes to `CpuReady`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineState {
    BlockedNoStd,
    CpuReady,
    GpuReady,
}

/// Host-side engine operations. The implementation is supplied by the engine
/// adapter once a `no_std + alloc` engine core is available.
pub trait EngineHost {
    fn state(&self) -> EngineState;

    /// Replace the host-neutral scene or UI batch. The payload interpretation
    /// belongs to the engine and its versioned UI contract.
    fn set_scene(&mut self, scene: &[u8]) -> Result<(), HostError>;

    /// Render into a host-owned frame buffer. The host owns allocation,
    /// capability checks and presentation; the engine only fills pixels.
    fn render_cpu(&mut self, scene_version: u64, pixels: &mut [u8]) -> Result<(), HostError>;
}

/// Explicit adapter used until the pinned engine can be built for Jasper-OS.
#[derive(Debug, Default)]
pub struct UnavailableEngine;

impl EngineHost for UnavailableEngine {
    fn state(&self) -> EngineState {
        EngineState::BlockedNoStd
    }

    fn set_scene(&mut self, _scene: &[u8]) -> Result<(), HostError> {
        Err(HostError::EngineUnavailable)
    }

    fn render_cpu(&mut self, _scene_version: u64, _pixels: &mut [u8]) -> Result<(), HostError> {
        Err(HostError::EngineUnavailable)
    }
}

/// Stable host errors, independent of engine-internal Rust errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostError {
    EngineUnavailable,
    InvalidSurface,
    InvalidFrame,
    InvalidSequence,
    StaleGeneration,
    SurfaceRetired,
    InputUnavailable,
}

impl HostError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::EngineUnavailable => "service.ui.error.engine_unavailable",
            Self::InvalidSurface => "service.ui.error.invalid_surface",
            Self::InvalidFrame => "service.ui.error.invalid_frame",
            Self::InvalidSequence => "service.ui.error.invalid_sequence",
            Self::StaleGeneration => "service.ui.error.stale_generation",
            Self::SurfaceRetired => "service.ui.error.surface_retired",
            Self::InputUnavailable => "service.ui.error.input_unavailable",
        }
    }
}

/// A host-owned CPU frame with one Surface generation and monotonic sequence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CpuFrame {
    surface: SurfaceSpec,
    surface_generation: u64,
    scene_version: u64,
    sequence: u64,
    bytes: Vec<u8>,
}

impl CpuFrame {
    pub fn new(
        surface: SurfaceSpec,
        surface_generation: u64,
        scene_version: u64,
        sequence: u64,
        bytes: Vec<u8>,
    ) -> Result<Self, HostError> {
        let expected = surface.validate().map_err(|_| HostError::InvalidSurface)?;
        if surface.layout != kernel_core::display_input::PixelLayout::Rgba
            || surface.bytes_per_pixel != 4
            || surface_generation == 0
            || scene_version == 0
            || sequence == 0
            || expected != bytes.len() as u64
        {
            return Err(HostError::InvalidFrame);
        }
        Ok(Self {
            surface,
            surface_generation,
            scene_version,
            sequence,
            bytes,
        })
    }

    pub const fn surface(&self) -> SurfaceSpec {
        self.surface
    }

    pub const fn surface_generation(&self) -> u64 {
        self.surface_generation
    }

    pub const fn scene_version(&self) -> u64 {
        self.scene_version
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn pixels(&self) -> &[u8] {
        &self.bytes
    }
}

/// Host state that binds engine rendering to one active Surface generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SurfaceBinding {
    surface: SurfaceSpec,
    generation: u64,
    last_sequence: u64,
}

impl SurfaceBinding {
    pub fn new(surface: SurfaceSpec, generation: u64) -> Result<Self, HostError> {
        surface.validate().map_err(|_| HostError::InvalidSurface)?;
        if generation == 0 {
            return Err(HostError::InvalidFrame);
        }
        Ok(Self {
            surface,
            generation,
            last_sequence: 0,
        })
    }

    /// Validate a frame without publishing its sequence.
    pub fn validate(&self, frame: &CpuFrame) -> Result<(), HostError> {
        if frame.surface != self.surface || frame.surface_generation != self.generation {
            return Err(HostError::StaleGeneration);
        }
        if frame.sequence <= self.last_sequence {
            return Err(HostError::InvalidSequence);
        }
        Ok(())
    }

    /// Adopt a frame only when its Surface and monotonic sequence match.
    pub fn adopt(&mut self, frame: &CpuFrame) -> Result<u64, HostError> {
        self.validate(frame)?;
        self.last_sequence = frame.sequence;
        Ok(frame.sequence)
    }
}

/// One host-side engine session. It deliberately has no window or GPU policy.
pub struct UiHost<E: EngineHost> {
    engine: E,
    surface: SurfaceBinding,
    scene_version: u64,
}

impl<E: EngineHost> UiHost<E> {
    pub fn new(
        engine: E,
        surface: SurfaceSpec,
        surface_generation: u64,
    ) -> Result<Self, HostError> {
        Ok(Self {
            engine,
            surface: SurfaceBinding::new(surface, surface_generation)?,
            scene_version: 0,
        })
    }

    pub fn protocol_version(&self) -> u16 {
        UI_SERVICE_PROTOCOL_VERSION
    }

    pub fn engine_state(&self) -> EngineState {
        self.engine.state()
    }

    pub fn set_scene(&mut self, scene: &[u8]) -> Result<u64, HostError> {
        self.engine.set_scene(scene)?;
        self.scene_version = self
            .scene_version
            .checked_add(1)
            .ok_or(HostError::InvalidSequence)?;
        Ok(self.scene_version)
    }

    pub fn render(&mut self, frame: &mut CpuFrame) -> Result<u64, HostError> {
        if frame.surface != self.surface.surface {
            return Err(HostError::InvalidSurface);
        }
        self.surface.validate(frame)?;
        self.engine
            .render_cpu(self.scene_version, &mut frame.bytes)?;
        self.surface.adopt(frame)
    }
}

/// Native Channel transport adapter. Payload syntax belongs to the versioned
/// UI service contract; this wrapper only preserves real endpoint ownership.
#[cfg(feature = "native-transport")]
pub struct NativeUiEndpoint {
    channel: jasper_rt::channel::Channel,
}

#[cfg(feature = "native-transport")]
impl NativeUiEndpoint {
    pub fn from_handle(handle: jasper_rt::Handle) -> Self {
        Self {
            channel: jasper_rt::channel::Channel::from_handle(handle),
        }
    }

    pub fn receive(&self, buffer: &mut [u8]) -> Result<usize, HostError> {
        self.channel
            .recv(buffer)
            .map(|message| message.len)
            .map_err(|_| HostError::InputUnavailable)
    }

    pub fn send(&self, bytes: &[u8]) -> Result<(), HostError> {
        self.channel
            .send(bytes)
            .map_err(|_| HostError::InputUnavailable)
    }

    /// Receive and validate one versioned UI protocol frame.
    pub fn receive_frame<'a>(&self, buffer: &'a mut [u8]) -> Result<UiFrame<'a>, HostError> {
        let len = self.receive(buffer)?;
        decode_ui_frame(&buffer[..len]).map_err(|_| HostError::InvalidFrame)
    }

    /// Encode and send one versioned UI protocol frame over the native Channel.
    pub fn send_frame(&self, header: UiFrameHeader, payload: &[u8]) -> Result<(), HostError> {
        if payload.len() > kernel_core::ui_protocol::MAX_UI_FRAME_PAYLOAD {
            return Err(HostError::InvalidFrame);
        }
        let mut encoded = alloc::vec![
            0u8;
            kernel_core::ui_protocol::UI_FRAME_HEADER_BYTES + payload.len()
        ];
        let len = encode_ui_frame(header, payload, &mut encoded)
            .map_err(|_| HostError::InvalidFrame)?;
        self.send(&encoded[..len])
    }
}

/// Surface errors are kept in the host namespace rather than exposed as UI
/// Engine internals.
pub fn surface_error(_error: DisplayInputError) -> HostError {
    HostError::InvalidSurface
}

/// Input normalization belongs to the host; the engine receives only admitted
/// logical events.
pub fn admit_key(_key: KeyInput) -> Result<KeyInput, HostError> {
    Err(HostError::InputUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use kernel_core::display_input::PixelLayout;

    const SURFACE: SurfaceSpec = SurfaceSpec {
        width: 4,
        height: 3,
        stride: 4,
        bytes_per_pixel: 4,
        layout: PixelLayout::Rgba,
    };

    #[test]
    fn frame_requires_exact_surface_extent_and_monotonic_generation() {
        assert!(CpuFrame::new(SURFACE, 1, 1, 1, vec![0; 47]).is_err());
        assert!(CpuFrame::new(
            SurfaceSpec {
                layout: PixelLayout::Bgr,
                ..SURFACE
            },
            1,
            1,
            1,
            vec![0; 48],
        )
        .is_err());
        let frame = CpuFrame::new(SURFACE, 1, 1, 1, vec![0; 48]).unwrap();
        let mut binding = SurfaceBinding::new(SURFACE, 1).unwrap();
        assert_eq!(binding.adopt(&frame), Ok(1));
        assert_eq!(binding.adopt(&frame), Err(HostError::InvalidSequence));
    }

    #[test]
    fn unavailable_engine_cannot_publish_a_frame() {
        let mut host = UiHost::new(UnavailableEngine, SURFACE, 1).unwrap();
        assert_eq!(host.engine_state(), EngineState::BlockedNoStd);
        assert_eq!(host.set_scene(b"scene"), Err(HostError::EngineUnavailable));
        let mut frame = CpuFrame::new(SURFACE, 1, 1, 1, vec![0; 48]).unwrap();
        assert_eq!(host.render(&mut frame), Err(HostError::EngineUnavailable));
    }

    #[derive(Default)]
    struct CountingEngine {
        renders: u32,
    }

    impl EngineHost for CountingEngine {
        fn state(&self) -> EngineState {
            EngineState::CpuReady
        }

        fn set_scene(&mut self, _scene: &[u8]) -> Result<(), HostError> {
            Ok(())
        }

        fn render_cpu(
            &mut self,
            _scene_version: u64,
            pixels: &mut [u8],
        ) -> Result<(), HostError> {
            self.renders = self.renders.saturating_add(1);
            pixels.fill(0x7f);
            Ok(())
        }
    }

    #[test]
    fn stale_sequence_is_rejected_before_engine_rendering() {
        let mut host = UiHost::new(CountingEngine::default(), SURFACE, 1).unwrap();
        let mut first = CpuFrame::new(SURFACE, 1, 1, 1, vec![0; 48]).unwrap();
        assert_eq!(host.render(&mut first), Ok(1));
        assert_eq!(host.engine.renders, 1);
        let mut stale = CpuFrame::new(SURFACE, 1, 1, 1, vec![0; 48]).unwrap();
        assert_eq!(host.render(&mut stale), Err(HostError::InvalidSequence));
        assert_eq!(host.engine.renders, 1);
        assert_eq!(stale.pixels(), &[0; 48]);
    }
}
