//! Bounded native display and input session contract.
//!
//! Responsibility: describe one visible framebuffer surface and one bounded
//! keyboard event queue, with failure-atomic presentation and one terminal
//! state. The module contains no compositor, PTY, Linux input, or GPU command
//! execution semantics.
//!
//! 原生显示与输入会话的有界机制。负责一个可见 surface、一个有界键盘事件
//! 队列、失败原子的帧提交和唯一终态；不包含 compositor、PTY、Linux 输入
//! 或 GPU 命令执行语义。

#[cfg(any(test, feature = "display-dynamic"))]
use alloc::collections::VecDeque;

/// Pixel layout exposed by a display backend.
///
/// 显示后端暴露的像素布局。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PixelLayout {
    Rgb,
    Bgr,
    Gray,
}

/// Display backend selected from probed capabilities.
///
/// 根据能力探测选择的显示后端。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisplayBackend {
    Framebuffer,
    VirtioGpu2d,
}

/// Validated visible surface geometry.
///
/// 校验后的可见 surface 几何。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SurfaceSpec {
    pub width: u32,
    pub height: u32,
    /// Pixels between the starts of adjacent rows.
    pub stride: u32,
    pub bytes_per_pixel: u8,
    pub layout: PixelLayout,
}

impl SurfaceSpec {
    /// Validate geometry and return the exact byte length expected by one frame.
    ///
    /// 校验几何并返回一帧必须具有的精确字节数。
    pub fn validate(self) -> Result<u64, DisplayInputError> {
        if self.width == 0
            || self.height == 0
            || self.stride < self.width
            || self.bytes_per_pixel == 0
            || self.bytes_per_pixel > 4
        {
            return Err(DisplayInputError::InvalidSurface);
        }
        let required = u64::from(self.stride)
            .checked_mul(u64::from(self.height))
            .and_then(|bytes| bytes.checked_mul(u64::from(self.bytes_per_pixel)))
            .ok_or(DisplayInputError::InvalidSurface)?;
        if required == 0 || required > usize::MAX as u64 {
            return Err(DisplayInputError::InvalidSurface);
        }
        Ok(required)
    }
}

/// Hardware or firmware facts used to open a native display/input session.
///
/// 打开原生显示/输入会话所需的硬件或固件事实。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisplayCapabilities {
    pub backend: Option<DisplayBackend>,
    pub surface: Option<SurfaceSpec>,
    /// A genuine keyboard event source is present and initialized.
    pub keyboard: bool,
}

impl DisplayCapabilities {
    /// Unsupported capabilities indistinguishable from absent hardware.
    ///
    /// 与硬件缺失无法区分的未支持能力。
    pub const UNSUPPORTED: Self = Self {
        backend: None,
        surface: None,
        keyboard: false,
    };
}

/// Stable display/input errors.
///
/// 稳定的显示/输入错误。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisplayInputError {
    Unsupported,
    InvalidSurface,
    InvalidFrame,
    Busy,
    StaleTicket,
    QueueFull,
    QueueEmpty,
    Closed,
    Failed,
}

impl DisplayInputError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unsupported => "system.display.error.unsupported",
            Self::InvalidSurface => "system.display.error.invalid_surface",
            Self::InvalidFrame => "system.display.error.invalid_frame",
            Self::Busy => "system.display.error.busy",
            Self::StaleTicket => "system.display.error.stale_ticket",
            Self::QueueFull => "system.input.error.queue_full",
            Self::QueueEmpty => "system.input.error.queue_empty",
            Self::Closed => "system.display.error.closed",
            Self::Failed => "system.display.error.failed",
        }
    }
}

/// One key transition from the native input backend.
///
/// 原生输入后端产生的一次按键状态变化。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyInput {
    /// Backend-stable key code, not a Linux input event code.
    pub code: u16,
    pub pressed: bool,
    pub modifiers: u8,
}

/// Derive a keyboard queue from presentment demand and admitted memory.
pub fn plan_key_queue_capacity(surface_bytes: u64, memory_budget: u64) -> Option<usize> {
    let event_bytes = core::mem::size_of::<KeyInput>() as u64;
    if event_bytes == 0 || memory_budget < event_bytes {
        return None;
    }
    // Issue #33 HC-22 policy: input metadata may consume at most 1/1024 of the
    // admitted memory. One event of demand is admitted per 4 KiB of surface.
    let policy_bytes = (memory_budget / 1024).max(event_bytes);
    let budget_events = usize::try_from(policy_bytes / event_bytes).ok()?;
    let demand = usize::try_from((surface_bytes / 4096).max(1)).ok()?;
    Some(demand.min(budget_events))
}

/// Session lifecycle state.
///
/// 会话生命周期状态。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisplaySessionState {
    Open,
    Closed,
    Failed,
}

/// Permission to commit exactly one validated frame.
///
/// 恰好提交一帧的许可票据。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameTicket {
    sequence: u64,
    bytes: u64,
}

/// Native display/input session with a fixed keyboard queue.
///
/// 具有固定容量键盘队列的原生显示/输入会话。
pub struct DisplayInputSession<const KEYS: usize> {
    backend: DisplayBackend,
    surface: SurfaceSpec,
    surface_bytes: u64,
    keyboard: bool,
    keys: [Option<KeyInput>; KEYS],
    key_head: usize,
    key_len: usize,
    state: DisplaySessionState,
    pending: Option<FrameTicket>,
    next_ticket: u64,
    frames: u64,
    dropped_keys: u64,
}

impl<const KEYS: usize> DisplayInputSession<KEYS> {
    /// Open a display session; input operations fail closed when no keyboard exists.
    ///
    /// 打开显示会话；没有真实键盘来源时输入操作明确失败关闭。
    pub fn open(capabilities: DisplayCapabilities) -> Result<Self, DisplayInputError> {
        let backend = capabilities.backend.ok_or(DisplayInputError::Unsupported)?;
        let surface = capabilities.surface.ok_or(DisplayInputError::Unsupported)?;
        let surface_bytes = surface.validate()?;
        if KEYS == 0 {
            return Err(DisplayInputError::Unsupported);
        }
        Ok(Self {
            backend,
            surface,
            surface_bytes,
            keyboard: capabilities.keyboard,
            keys: [None; KEYS],
            key_head: 0,
            key_len: 0,
            state: DisplaySessionState::Open,
            pending: None,
            next_ticket: 1,
            frames: 0,
            dropped_keys: 0,
        })
    }

    pub const fn backend(&self) -> DisplayBackend {
        self.backend
    }

    pub const fn surface(&self) -> SurfaceSpec {
        self.surface
    }

    pub const fn state(&self) -> DisplaySessionState {
        self.state
    }

    pub const fn frames(&self) -> u64 {
        self.frames
    }

    pub const fn pending_keys(&self) -> usize {
        self.key_len
    }

    pub const fn dropped_keys(&self) -> u64 {
        self.dropped_keys
    }

    pub const fn keyboard_available(&self) -> bool {
        self.keyboard
    }

    /// Queue one key event without overwriting older input.
    ///
    /// 追加一个键盘事件，不覆盖更早的输入。
    pub fn push_key(&mut self, key: KeyInput) -> Result<(), DisplayInputError> {
        self.ensure_open()?;
        self.ensure_keyboard()?;
        if self.key_len == KEYS {
            self.dropped_keys = self.dropped_keys.saturating_add(1);
            return Err(DisplayInputError::QueueFull);
        }
        let tail = (self.key_head + self.key_len) % KEYS;
        self.keys[tail] = Some(key);
        self.key_len += 1;
        Ok(())
    }

    /// Remove the oldest key event.
    ///
    /// 取出最早的键盘事件。
    pub fn pop_key(&mut self) -> Result<KeyInput, DisplayInputError> {
        self.ensure_open()?;
        self.ensure_keyboard()?;
        if self.key_len == 0 {
            return Err(DisplayInputError::QueueEmpty);
        }
        let key = self.keys[self.key_head]
            .take()
            .ok_or(DisplayInputError::QueueEmpty)?;
        self.key_head = (self.key_head + 1) % KEYS;
        self.key_len -= 1;
        Ok(key)
    }

    /// Validate a frame and reserve the only commit ticket.
    ///
    /// 校验整帧并预留唯一提交票据。
    pub fn prepare_frame(&mut self, bytes: u64) -> Result<FrameTicket, DisplayInputError> {
        self.ensure_open()?;
        if bytes != self.surface_bytes {
            return Err(DisplayInputError::InvalidFrame);
        }
        if self.pending.is_some() {
            return Err(DisplayInputError::Busy);
        }
        let sequence = self.next_ticket;
        self.next_ticket = sequence.checked_add(1).ok_or(DisplayInputError::Failed)?;
        let ticket = FrameTicket { sequence, bytes };
        self.pending = Some(ticket);
        Ok(ticket)
    }

    /// Commit a prepared frame after the backend write succeeded.
    ///
    /// 后端写入成功后提交已准备的帧。
    pub fn commit_frame(&mut self, ticket: FrameTicket) -> Result<u64, DisplayInputError> {
        self.ensure_open()?;
        if ticket.bytes != self.surface_bytes || self.pending != Some(ticket) {
            return Err(DisplayInputError::StaleTicket);
        }
        self.pending = None;
        self.frames = self.frames.saturating_add(1);
        Ok(self.frames)
    }

    /// Abort a prepared frame without counting it.
    ///
    /// 放弃已准备的帧，不增加提交计数。
    pub fn abort_frame(&mut self, ticket: FrameTicket) -> Result<(), DisplayInputError> {
        self.ensure_open()?;
        if self.pending != Some(ticket) {
            return Err(DisplayInputError::StaleTicket);
        }
        self.pending = None;
        Ok(())
    }

    /// Commit the unique normal close.
    ///
    /// 提交唯一的正常关闭状态。
    pub fn close(&mut self) -> Result<(), DisplayInputError> {
        match self.state {
            DisplaySessionState::Open => {
                self.pending = None;
                self.state = DisplaySessionState::Closed;
                Ok(())
            }
            DisplaySessionState::Closed => Ok(()),
            DisplaySessionState::Failed => Err(DisplayInputError::Failed),
        }
    }

    /// Commit the unique failure state.
    ///
    /// 提交唯一的失败状态。
    pub fn fail(&mut self) -> Result<(), DisplayInputError> {
        match self.state {
            DisplaySessionState::Open => {
                self.pending = None;
                self.state = DisplaySessionState::Failed;
                Ok(())
            }
            DisplaySessionState::Failed => Ok(()),
            DisplaySessionState::Closed => Err(DisplayInputError::Closed),
        }
    }

    fn ensure_open(&self) -> Result<(), DisplayInputError> {
        match self.state {
            DisplaySessionState::Open => Ok(()),
            DisplaySessionState::Closed => Err(DisplayInputError::Closed),
            DisplaySessionState::Failed => Err(DisplayInputError::Failed),
        }
    }

    fn ensure_keyboard(&self) -> Result<(), DisplayInputError> {
        if self.keyboard {
            Ok(())
        } else {
            Err(DisplayInputError::Unsupported)
        }
    }
}

/// Native display session whose keyboard queue is allocated at runtime.
#[cfg(any(test, feature = "display-dynamic"))]
pub struct DynamicDisplayInputSession {
    backend: DisplayBackend,
    surface: SurfaceSpec,
    surface_bytes: u64,
    keyboard: bool,
    keys: VecDeque<KeyInput>,
    key_capacity: usize,
    state: DisplaySessionState,
    pending: Option<FrameTicket>,
    next_ticket: u64,
    frames: u64,
    dropped_keys: u64,
}

#[cfg(any(test, feature = "display-dynamic"))]
impl DynamicDisplayInputSession {
    pub fn open(
        capabilities: DisplayCapabilities,
        key_capacity: usize,
    ) -> Result<Self, DisplayInputError> {
        let backend = capabilities.backend.ok_or(DisplayInputError::Unsupported)?;
        let surface = capabilities.surface.ok_or(DisplayInputError::Unsupported)?;
        let surface_bytes = surface.validate()?;
        if key_capacity == 0 {
            return Err(DisplayInputError::Unsupported);
        }
        let mut keys = VecDeque::new();
        keys.try_reserve_exact(key_capacity)
            .map_err(|_| DisplayInputError::Failed)?;
        Ok(Self {
            backend,
            surface,
            surface_bytes,
            keyboard: capabilities.keyboard,
            keys,
            key_capacity,
            state: DisplaySessionState::Open,
            pending: None,
            next_ticket: 1,
            frames: 0,
            dropped_keys: 0,
        })
    }

    pub const fn backend(&self) -> DisplayBackend {
        self.backend
    }

    pub const fn surface(&self) -> SurfaceSpec {
        self.surface
    }

    pub const fn state(&self) -> DisplaySessionState {
        self.state
    }

    pub const fn frames(&self) -> u64 {
        self.frames
    }

    pub fn pending_keys(&self) -> usize {
        self.keys.len()
    }

    pub const fn key_capacity(&self) -> usize {
        self.key_capacity
    }

    pub const fn dropped_keys(&self) -> u64 {
        self.dropped_keys
    }

    pub const fn keyboard_available(&self) -> bool {
        self.keyboard
    }

    pub fn push_key(&mut self, key: KeyInput) -> Result<(), DisplayInputError> {
        self.ensure_open()?;
        self.ensure_keyboard()?;
        if self.keys.len() == self.key_capacity {
            self.dropped_keys = self.dropped_keys.saturating_add(1);
            return Err(DisplayInputError::QueueFull);
        }
        self.keys.push_back(key);
        Ok(())
    }

    pub fn pop_key(&mut self) -> Result<KeyInput, DisplayInputError> {
        self.ensure_open()?;
        self.ensure_keyboard()?;
        self.keys
            .pop_front()
            .ok_or(DisplayInputError::QueueEmpty)
    }

    pub fn prepare_frame(&mut self, bytes: u64) -> Result<FrameTicket, DisplayInputError> {
        self.ensure_open()?;
        if bytes != self.surface_bytes {
            return Err(DisplayInputError::InvalidFrame);
        }
        if self.pending.is_some() {
            return Err(DisplayInputError::Busy);
        }
        let sequence = self.next_ticket;
        self.next_ticket = sequence.checked_add(1).ok_or(DisplayInputError::Failed)?;
        let ticket = FrameTicket { sequence, bytes };
        self.pending = Some(ticket);
        Ok(ticket)
    }

    pub fn commit_frame(&mut self, ticket: FrameTicket) -> Result<u64, DisplayInputError> {
        self.ensure_open()?;
        if ticket.bytes != self.surface_bytes || self.pending != Some(ticket) {
            return Err(DisplayInputError::StaleTicket);
        }
        self.pending = None;
        self.frames = self.frames.saturating_add(1);
        Ok(self.frames)
    }

    pub fn abort_frame(&mut self, ticket: FrameTicket) -> Result<(), DisplayInputError> {
        self.ensure_open()?;
        if self.pending != Some(ticket) {
            return Err(DisplayInputError::StaleTicket);
        }
        self.pending = None;
        Ok(())
    }

    pub fn close(&mut self) -> Result<(), DisplayInputError> {
        match self.state {
            DisplaySessionState::Open => {
                self.pending = None;
                self.state = DisplaySessionState::Closed;
                Ok(())
            }
            DisplaySessionState::Closed => Ok(()),
            DisplaySessionState::Failed => Err(DisplayInputError::Failed),
        }
    }

    pub fn fail(&mut self) -> Result<(), DisplayInputError> {
        match self.state {
            DisplaySessionState::Open => {
                self.pending = None;
                self.state = DisplaySessionState::Failed;
                Ok(())
            }
            DisplaySessionState::Failed => Ok(()),
            DisplaySessionState::Closed => Err(DisplayInputError::Closed),
        }
    }

    fn ensure_open(&self) -> Result<(), DisplayInputError> {
        match self.state {
            DisplaySessionState::Open => Ok(()),
            DisplaySessionState::Closed => Err(DisplayInputError::Closed),
            DisplaySessionState::Failed => Err(DisplayInputError::Failed),
        }
    }

    fn ensure_keyboard(&self) -> Result<(), DisplayInputError> {
        if self.keyboard {
            Ok(())
        } else {
            Err(DisplayInputError::Unsupported)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SURFACE: SurfaceSpec = SurfaceSpec {
        width: 8,
        height: 4,
        stride: 10,
        bytes_per_pixel: 4,
        layout: PixelLayout::Bgr,
    };

    fn capabilities() -> DisplayCapabilities {
        DisplayCapabilities {
            backend: Some(DisplayBackend::Framebuffer),
            surface: Some(SURFACE),
            keyboard: true,
        }
    }

    #[test]
    fn surface_geometry_is_strict_and_overflow_safe() {
        assert_eq!(SURFACE.validate(), Ok(160));
        assert_eq!(
            SurfaceSpec {
                stride: 7,
                ..SURFACE
            }
            .validate(),
            Err(DisplayInputError::InvalidSurface)
        );
        let wide = SurfaceSpec {
            width: 8192,
            height: 1,
            stride: 8192,
            ..SURFACE
        };
        assert_eq!(wide.validate(), Ok(8192 * 4));
        let large = SurfaceSpec {
            width: 8193,
            height: 8192,
            stride: 8193,
            ..SURFACE
        };
        assert_eq!(large.validate(), Ok(8193 * 8192 * 4));
        assert_eq!(
            SurfaceSpec {
                stride: u32::MAX,
                height: u32::MAX,
                ..SURFACE
            }
            .validate(),
            Err(DisplayInputError::InvalidSurface)
        );
    }

    #[test]
    fn missing_display_is_unsupported_and_missing_keyboard_fails_closed() {
        assert_eq!(
            DisplayInputSession::<4>::open(DisplayCapabilities::UNSUPPORTED).err(),
            Some(DisplayInputError::Unsupported)
        );
        let mut no_keyboard = DisplayInputSession::<4>::open(DisplayCapabilities {
            keyboard: false,
            ..capabilities()
        })
        .unwrap();
        assert_eq!(no_keyboard.prepare_frame(160).is_ok(), true);
        assert_eq!(
            no_keyboard.push_key(KeyInput {
                code: 1,
                pressed: true,
                modifiers: 0
            }),
            Err(DisplayInputError::Unsupported)
        );
        assert_eq!(no_keyboard.pop_key(), Err(DisplayInputError::Unsupported));
        assert_eq!(
            DisplayInputSession::<0>::open(capabilities()).err(),
            Some(DisplayInputError::Unsupported)
        );
    }

    #[test]
    fn keyboard_queue_wraps_and_overflow_never_overwrites() {
        let mut session = DisplayInputSession::<2>::open(capabilities()).unwrap();
        let first = KeyInput {
            code: 1,
            pressed: true,
            modifiers: 0,
        };
        let second = KeyInput {
            code: 2,
            pressed: true,
            modifiers: 0,
        };
        session.push_key(first).unwrap();
        assert_eq!(session.push_key(second), Ok(()));
        assert_eq!(
            session.push_key(KeyInput {
                code: 3,
                pressed: true,
                modifiers: 0
            }),
            Err(DisplayInputError::QueueFull)
        );
        assert_eq!(session.pop_key(), Ok(first));
        session
            .push_key(KeyInput {
                code: 3,
                pressed: true,
                modifiers: 0,
            })
            .unwrap();
        assert_eq!(session.pop_key(), Ok(second));
        assert_eq!(
            session.pop_key(),
            Ok(KeyInput {
                code: 3,
                pressed: true,
                modifiers: 0
            })
        );
        assert_eq!(session.dropped_keys(), 1);
    }

    #[test]
    fn frame_preparation_is_atomic_and_exact() {
        let mut session = DisplayInputSession::<2>::open(capabilities()).unwrap();
        assert_eq!(
            session.prepare_frame(159),
            Err(DisplayInputError::InvalidFrame)
        );
        let ticket = session.prepare_frame(160).unwrap();
        assert_eq!(session.prepare_frame(160), Err(DisplayInputError::Busy));
        assert_eq!(session.frames(), 0);
        assert_eq!(session.commit_frame(ticket), Ok(1));
        assert_eq!(
            session.commit_frame(ticket),
            Err(DisplayInputError::StaleTicket)
        );
    }

    #[test]
    fn aborted_frame_does_not_publish_or_revive_ticket() {
        let mut session = DisplayInputSession::<2>::open(capabilities()).unwrap();
        let ticket = session.prepare_frame(160).unwrap();
        session.abort_frame(ticket).unwrap();
        assert_eq!(session.frames(), 0);
        assert_eq!(
            session.commit_frame(ticket),
            Err(DisplayInputError::StaleTicket)
        );
        let replacement = session.prepare_frame(160).unwrap();
        assert_ne!(replacement, ticket);
        assert_eq!(session.commit_frame(replacement), Ok(1));
    }

    #[test]
    fn terminal_states_are_unique_and_old_operations_fail_closed() {
        let mut closed = DisplayInputSession::<2>::open(capabilities()).unwrap();
        closed.close().unwrap();
        closed.close().unwrap();
        assert_eq!(closed.state(), DisplaySessionState::Closed);
        assert_eq!(closed.fail(), Err(DisplayInputError::Closed));
        assert_eq!(
            closed.push_key(KeyInput {
                code: 1,
                pressed: true,
                modifiers: 0
            }),
            Err(DisplayInputError::Closed)
        );
        assert_eq!(closed.prepare_frame(160), Err(DisplayInputError::Closed));

        let mut failed = DisplayInputSession::<2>::open(capabilities()).unwrap();
        failed.fail().unwrap();
        failed.fail().unwrap();
        assert_eq!(failed.state(), DisplaySessionState::Failed);
        assert_eq!(failed.close(), Err(DisplayInputError::Failed));
        assert_eq!(failed.pop_key(), Err(DisplayInputError::Failed));
    }

    #[test]
    fn dynamic_key_capacity_follows_surface_and_memory_budget() {
        let tiny = plan_key_queue_capacity(160, 64).unwrap();
        let standard = plan_key_queue_capacity(1280 * 720 * 3, 128 * 1024 * 1024).unwrap();
        assert_eq!(tiny, 1);
        assert_eq!(standard, (1280 * 720 * 3) / 4096);
        assert!(plan_key_queue_capacity(160, 0).is_none());
    }

    #[test]
    fn dynamic_session_preserves_fifo_and_rejects_overflow() {
        let mut session = DynamicDisplayInputSession::open(capabilities(), 2).unwrap();
        let key = |code| KeyInput {
            code,
            pressed: true,
            modifiers: 0,
        };
        session.push_key(key(1)).unwrap();
        session.push_key(key(2)).unwrap();
        assert_eq!(session.push_key(key(3)), Err(DisplayInputError::QueueFull));
        assert_eq!(session.pop_key(), Ok(key(1)));
        session.push_key(key(3)).unwrap();
        assert_eq!(session.pop_key(), Ok(key(2)));
        assert_eq!(session.pop_key(), Ok(key(3)));
        assert_eq!(session.pop_key(), Err(DisplayInputError::QueueEmpty));
        assert_eq!(session.dropped_keys(), 1);
    }
}
