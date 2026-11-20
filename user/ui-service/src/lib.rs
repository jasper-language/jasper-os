//! Jasper-OS host boundary for the pinned Jasper UI Engine.
//!
//! This crate owns no renderer or window policy. It validates the host surface,
//! engine state, input and output generations around an engine supplied by the
//! independent `jasper-ui-engine` repository. The `native-engine-core` feature
//! selects its real `no_std + alloc` CPU core; builds without that feature keep
//! an explicit unavailable adapter rather than fabricating a successful frame.
//!
//! 本 crate 是固定版本 Jasper UI Engine 的 Jasper-OS 宿主边界；不拥有渲染器或窗口
//! 策略。`native-engine-core` 选择真实 `no_std + alloc` CPU 核心；未开启该特性时
//! 明确返回不可用状态，不能伪造成功帧。

#![no_std]

extern crate alloc;

#[cfg(feature = "native-engine-core")]
use alloc::boxed::Box;
use alloc::vec::Vec;
#[cfg(feature = "native-engine-core")]
use jasper_ui_engine::{
    core_renderer::CoreRgbaRenderer,
    geometry::Size,
    scene::Node,
    ui_ir::{
        NativeActivationSource, NativeUiDocument, UiEventContext, UiEventKind, UiFrame as IrFrame,
        UiPermission, UiPermissionContext,
    },
    SimpleTextEngine,
};
use kernel_core::display_input::{DisplayInputError, KeyInput, SurfaceSpec};
pub use kernel_core::ui_policy::{
    UiDeviceCapabilities, UiPolicyError, UiPolicySnapshot, InteractionProfile, ProfileDecision,
};
#[cfg(feature = "native-transport")]
use kernel_core::ui_protocol::{decode_ui_frame, encode_ui_frame, UiFrame, UiFrameHeader};
use kernel_core::ui_service::{UI_ERROR_ENGINE_UNAVAILABLE, UI_SERVICE_PROTOCOL_VERSION};

/// UI Engine revision currently recorded by `ui-engine.lock.toml`.
pub const PINNED_ENGINE_COMMIT: &str = "8adb6d4432c8385250192304eef04a07b22594d2";
/// Largest JSUI payload that fits one Jasper native Channel message.
pub fn max_native_ui_frame_payload() -> usize {
    kernel_core::config::bounds::MSG_BYTES
        .saturating_sub(kernel_core::ui_protocol::UI_FRAME_HEADER_BYTES)
}

/// Build-time engine availability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineState {
    BlockedNoStd,
    CpuReady,
    GpuReady,
}

/// Host-side engine operations supplied by either the CPU core adapter or an
/// explicit fail-closed adapter.
pub trait EngineHost {
    fn state(&self) -> EngineState;

    /// Replace the host-neutral scene or UI batch. The payload interpretation
    /// belongs to the engine and its versioned UI contract.
    fn set_scene(&mut self, scene: &[u8]) -> Result<(), HostError>;

    /// Render into a host-owned frame buffer. The host owns allocation,
    /// capability checks and presentation; the engine only fills pixels.
    fn render_cpu(&mut self, scene_version: u64, pixels: &mut [u8]) -> Result<(), HostError>;
}

/// Explicit adapter for builds that intentionally omit the Engine CPU core.
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

/// Real Jasper UI Engine CPU core over an OS-owned RGBA8 surface.
///
/// The engine owns scene layout and paint state; Jasper-OS owns allocation,
/// Surface lifecycle, Channel transport and presentation.
///
/// 真实 Jasper UI Engine CPU 核心运行在 Jasper-OS 拥有的 RGBA8 Surface 上；
/// 引擎负责场景布局与绘制，Jasper-OS 负责分配、Surface 生命周期、Channel 和呈现。
#[cfg(feature = "native-engine-core")]
pub struct CpuEngineHost {
    document: Option<NativeUiDocument>,
    width: u32,
    height: u32,
}

#[cfg(feature = "native-engine-core")]
impl CpuEngineHost {
    pub fn new(width: u32, height: u32) -> Result<Self, HostError> {
        if width == 0 || height == 0 {
            return Err(HostError::InvalidSurface);
        }
        Ok(Self {
            document: None,
            width,
            height,
        })
    }

    /// Admit an Enter key against the first current activation binding. This is
    /// the bounded single-focus acceptance path, not a general focus stack.
    pub fn input_key(
        &mut self,
        code: u32,
        pressed: bool,
        _modifiers: u8,
    ) -> Result<bool, HostError> {
        if !pressed || code != 28 {
            return Ok(false);
        }
        let document = self.document.as_ref().ok_or(HostError::InvalidSequence)?;
        let target = first_activation_target(document).ok_or(HostError::InputUnavailable)?;
        let node = document
            .node_for_key(target)
            .ok_or(HostError::InvalidSequence)?;
        let context = UiEventContext {
            target,
            identity_domain: document.identity_domain().into(),
            owner: document.owner().into(),
            session: document.session().into(),
            frame_revision: document.revision(),
            permission_context: UiPermissionContext::new(
                "jasper-os-ui-host",
                [UiPermission::Activate],
            ),
        };
        document
            .admit_activation(&context, node, NativeActivationSource::Keyboard)
            .map(|_| true)
            .map_err(|_| HostError::InputUnavailable)
    }
}

#[cfg(feature = "native-engine-core")]
fn first_activation_target(document: &NativeUiDocument) -> Option<jasper_ui_engine::ui_ir::UiKey> {
    fn visit(document: &NativeUiDocument, node: &Node) -> Option<jasper_ui_engine::ui_ir::UiKey> {
        if let Some(key) = document.key_for_node(node.id) {
            if document.event_binding(key, UiEventKind::Activate).is_some() {
                return Some(key);
            }
        }
        node.children
            .iter()
            .find_map(|child| visit(document, child))
    }
    visit(document, &document.scene().root)
}

#[cfg(feature = "native-engine-core")]
impl EngineHost for CpuEngineHost {
    fn state(&self) -> EngineState {
        EngineState::CpuReady
    }

    fn set_scene(&mut self, scene: &[u8]) -> Result<(), HostError> {
        let frame = IrFrame::from_json_slice(scene).map_err(|_| HostError::InvalidFrame)?;
        if frame.expected_revision == 1 {
            self.document =
                Some(NativeUiDocument::from_frame(&frame).map_err(|_| HostError::InvalidFrame)?);
        } else {
            self.document
                .as_mut()
                .ok_or(HostError::InvalidSequence)?
                .apply_frame(&frame)
                .map_err(|_| HostError::InvalidFrame)?;
        }
        Ok(())
    }

    fn render_cpu(&mut self, _scene_version: u64, pixels: &mut [u8]) -> Result<(), HostError> {
        let document = self.document.as_ref().ok_or(HostError::InvalidSequence)?;
        let renderer = CoreRgbaRenderer::new(
            Size::new(self.width as f32, self.height as f32),
            Box::new(SimpleTextEngine),
        )
        .with_max_frame_bytes(pixels.len());
        let frame = renderer
            .render(document.scene())
            .map_err(|_| HostError::InvalidFrame)?;
        if frame.width != self.width
            || frame.height != self.height
            || frame.pixels.len() != pixels.len()
        {
            return Err(HostError::InvalidFrame);
        }
        pixels.copy_from_slice(&frame.pixels);
        Ok(())
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
            Self::EngineUnavailable => UI_ERROR_ENGINE_UNAVAILABLE,
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
    policy: Option<UiPolicySnapshot>,
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
            policy: None,
        })
    }

    /// Bind the immutable policy snapshot that admits this host Surface. This
    /// validates the contract epoch/surface binding without changing the
    /// service's existing authorization or display-session authority.
    pub fn bind_policy(&mut self, policy: UiPolicySnapshot) -> Result<(), HostError> {
        if policy.surface != self.surface.surface {
            return Err(HostError::InvalidSurface);
        }
        self.policy = Some(policy);
        Ok(())
    }

    pub const fn policy(&self) -> Option<UiPolicySnapshot> {
        self.policy
    }

    pub fn protocol_version(&self) -> u16 {
        UI_SERVICE_PROTOCOL_VERSION
    }

    pub fn engine_state(&self) -> EngineState {
        self.engine.state()
    }

    pub fn engine_mut(&mut self) -> &mut E {
        &mut self.engine
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
        if payload.len() > max_native_ui_frame_payload() {
            return Err(HostError::InvalidFrame);
        }
        let mut encoded = alloc::vec![
            0u8;
            kernel_core::ui_protocol::UI_FRAME_HEADER_BYTES + payload.len()
        ];
        let len =
            encode_ui_frame(header, payload, &mut encoded).map_err(|_| HostError::InvalidFrame)?;
        self.send(&encoded[..len])
    }

    /// Encode one bounded frame into caller-owned storage and send it without
    /// allocating. The buffer must cover the header and the complete payload.
    pub fn send_frame_into(
        &self,
        header: UiFrameHeader,
        payload: &[u8],
        output: &mut [u8],
    ) -> Result<(), HostError> {
        if payload.len() > max_native_ui_frame_payload() {
            return Err(HostError::InvalidFrame);
        }
        let len = encode_ui_frame(header, payload, output).map_err(|_| HostError::InvalidFrame)?;
        self.send(&output[..len])
    }
}

/// Surface errors are kept in the host namespace rather than exposed as UI
/// Engine internals.
pub fn surface_error(_error: DisplayInputError) -> HostError {
    HostError::InvalidSurface
}

/// Input normalization belongs to the host; the engine receives only admitted
/// logical events. Backend key code zero is reserved and cannot cross the host
/// boundary.
pub fn admit_key(key: KeyInput) -> Result<KeyInput, HostError> {
    if key.code == 0 {
        Err(HostError::InputUnavailable)
    } else {
        Ok(key)
    }
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

    #[test]
    fn host_binds_one_immutable_policy_surface() {
        let mut host = UiHost::new(UnavailableEngine, SURFACE, 1).unwrap();
        let policy = UiPolicySnapshot::new(
            1,
            2,
            3,
            kernel_core::ui_policy::UiPolicyScope {
                user: 1,
                tenant: 1,
                session: 1,
                display_seat: 1,
                input_seat: 1,
            },
            UiDeviceCapabilities {
                display: true,
                keyboard: true,
                pointer: false,
                touch: false,
                split_layouts: false,
                multi_window: false,
                background_grants: false,
            },
            InteractionProfile::SinglePrimary,
            kernel_core::ui_policy::UiBackgroundPolicy::DenyOrdinary,
            SURFACE,
        )
        .unwrap();
        assert_eq!(host.bind_policy(policy), Ok(()));
        assert_eq!(host.policy(), Some(policy));
        let mut wrong = policy;
        wrong.surface.width = 5;
        wrong.surface.stride = 5;
        assert_eq!(host.bind_policy(wrong), Err(HostError::InvalidSurface));
        assert_eq!(host.policy(), Some(policy));
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

        fn render_cpu(&mut self, _scene_version: u64, pixels: &mut [u8]) -> Result<(), HostError> {
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

    #[test]
    fn host_admits_stable_keys_and_rejects_reserved_zero_code() {
        let key = KeyInput {
            code: 30,
            pressed: true,
            modifiers: 1,
        };
        assert_eq!(admit_key(key), Ok(key));
        assert_eq!(
            admit_key(KeyInput { code: 0, ..key }),
            Err(HostError::InputUnavailable)
        );
    }

    #[cfg(feature = "native-engine-core")]
    #[test]
    fn pinned_cpu_engine_renders_typed_ui_ir_into_host_pixels() {
        const ENGINE_SURFACE: SurfaceSpec = SurfaceSpec {
            width: 4,
            height: 4,
            stride: 4,
            bytes_per_pixel: 4,
            layout: PixelLayout::Rgba,
        };
        let scene = br##"{"ir_version":"0.1.0","identity_domain":"jasper-os/ui-test","owner":"test-host","session":"session-1","expected_revision":1,"next_revision":2,"ops":[{"op":"insert","parent":null,"index":0,"node":{"key":{"semantic_id":1,"generation":1},"element":{"kind":"container"},"semantics":{"role":"container","label":"Engine","focusable":true},"style":{"box":{"width":{"unit":"px","value":4},"height":{"unit":"px","value":4}},"paint":{"background":"#0A84FFFF"}},"events":[{"event":"activate","action":"jasper.ui.activate"}],"children":[]}}]}"##;
        let patch = br##"{"ir_version":"0.1.0","identity_domain":"jasper-os/ui-test","owner":"test-host","session":"session-1","expected_revision":2,"next_revision":3,"ops":[{"op":"update","key":{"semantic_id":1,"generation":1},"fields":{"style":{"box":{"width":{"unit":"px","value":4},"height":{"unit":"px","value":4}},"paint":{"background":"#FF0000FF"}}}}]}"##;

        let engine = CpuEngineHost::new(4, 4).unwrap();
        let mut host = UiHost::new(engine, ENGINE_SURFACE, 1).unwrap();
        let scene_version = host.set_scene(scene).unwrap();
        let mut frame = CpuFrame::new(ENGINE_SURFACE, 1, scene_version, 1, vec![0; 64]).unwrap();
        assert_eq!(host.render(&mut frame), Ok(1));
        assert_eq!(&frame.pixels()[..4], &[0x0a, 0x84, 0xff, 0xff]);
        assert!(frame.pixels().chunks_exact(4).all(|pixel| pixel[3] == 0xff));
        let patched_version = host.set_scene(patch).unwrap();
        let mut patched =
            CpuFrame::new(ENGINE_SURFACE, 1, patched_version, 2, vec![0; 64]).unwrap();
        assert_eq!(host.render(&mut patched), Ok(2));
        assert_eq!(&patched.pixels()[..4], &[0xff, 0x00, 0x00, 0xff]);
        assert_eq!(host.engine_mut().input_key(28, true, 0), Ok(true));
    }
}
