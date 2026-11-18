//! Backend-neutral system UI service contract over existing display resources.
//!
//! This module composes the existing display/input session, compositor, frame
//! tickets and unified authorization decision. It contains no window server,
//! GPU API, renderer, Terminal command execution or second permission authority.
//! `service.ui.*` names are logical service operations; this module registers no
//! new kernel syscall IDs.
//!
//! 本模块在既有显示/输入会话、compositor、帧票据与统一授权决策之上组合系统 UI
//! 服务契约。它不包含窗口服务实现、GPU API、渲染器、Terminal 命令执行或第二套
//! 权限权威；`service.ui.*` 是逻辑服务操作，本模块不登记新的内核 syscall ID。

use crate::authz::{self, AccessScope, Decision, Effect, Operation};
use crate::display_compositor::{
    CompositionStats, Compositor, CompositorError, DamageRect, LayerKey, LayerPixels, LayerSpec,
};
use crate::display_input::{
    plan_key_queue_capacity, DisplayCapabilities, DisplayInputError, DisplayInputSession,
    FrameTicket, KeyInput, SurfaceSpec,
};

/// Logical UI service contract version. This is not a kernel ABI ID.
pub const UI_SERVICE_PROTOCOL_VERSION: u16 = 1;

/// Stable service-level UI error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UiServiceError {
    AuthorizationDenied,
    WrongOperation,
    InvalidOwner,
    InvalidScope,
    Capacity,
    StaleClient,
    NotFocused,
    NoPendingFrame,
    Display(DisplayInputError),
    Compositor(CompositorError),
    Closed,
    Failed,
}

impl UiServiceError {
    /// Stable logical namespace error, not a registered syscall errno.
    pub const fn name(self) -> &'static str {
        match self {
            Self::AuthorizationDenied => "service.ui.error.authorization",
            Self::WrongOperation => "service.ui.error.operation",
            Self::InvalidOwner => "service.ui.error.owner",
            Self::InvalidScope => "service.ui.error.scope",
            Self::Capacity => "service.ui.error.capacity",
            Self::StaleClient => "service.ui.error.stale_client",
            Self::NotFocused => "service.ui.error.not_focused",
            Self::NoPendingFrame => "service.ui.error.no_pending_frame",
            Self::Display(_) => "service.ui.error.display",
            Self::Compositor(_) => "service.ui.error.compositor",
            Self::Closed => "service.ui.error.closed",
            Self::Failed => "service.ui.error.failed",
        }
    }
}

/// Exact operation capability recovered from the shared authorization decision.
///
/// 从共享授权决策中恢复的精确操作能力；调用者不能提供布尔值伪造准入。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UiCapability {
    decision: Decision,
    operation: Operation,
}

impl UiCapability {
    pub fn from_decision(decision: Decision, operation: Operation) -> Result<Self, UiServiceError> {
        if decision.format_version != authz::AUTHZ_FORMAT_VERSION
            || decision.operation != operation
            || decision.effect != operation_effect(operation)
        {
            return Err(UiServiceError::WrongOperation);
        }
        if !decision.admitted() {
            return Err(UiServiceError::AuthorizationDenied);
        }
        Ok(Self {
            decision,
            operation,
        })
    }

    pub const fn operation(self) -> Operation {
        self.operation
    }

    pub const fn decision(self) -> Decision {
        self.decision
    }
}

const fn operation_effect(operation: Operation) -> Effect {
    match operation {
        Operation::ServiceUiInputRead => Effect::Read,
        Operation::ServiceUiSessionCreate
        | Operation::ServiceUiSessionClose
        | Operation::ServiceUiFocusSet
        | Operation::ServiceUiFramePresent => Effect::Write,
        _ => Effect::Read,
    }
}

/// Stable client identity. A closed slot never revives this token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UiClientKey {
    slot: u16,
    generation: u32,
}

impl UiClientKey {
    pub const fn to_raw(self) -> u64 {
        ((self.generation as u64) << 16) | self.slot as u64
    }

    pub const fn from_raw(raw: u64) -> Option<Self> {
        if raw >> 48 != 0 || (raw >> 16) as u32 == 0 {
            return None;
        }
        Some(Self {
            slot: raw as u16,
            generation: (raw >> 16) as u32,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Client {
    key: UiClientKey,
    owner: u64,
    scope: AccessScope,
    layer: LayerKey,
}

/// Bounded UI service state over one admitted display/input session.
///
/// 在已准入显示/输入会话之上的有界 UI 服务状态。
pub struct UiService<const CLIENTS: usize, const LAYERS: usize, const KEYS: usize> {
    display: DisplayInputSession<KEYS>,
    compositor: Compositor<LAYERS>,
    clients: [Option<Client>; CLIENTS],
    generations: [u32; CLIENTS],
    focus: Option<UiClientKey>,
    pending_frame: Option<(UiClientKey, FrameTicket)>,
}

impl<const CLIENTS: usize, const LAYERS: usize, const KEYS: usize>
    UiService<CLIENTS, LAYERS, KEYS>
{
    /// Open over real display capabilities and an admitted input-memory budget.
    pub fn open(
        capabilities: DisplayCapabilities,
        memory_budget: u64,
    ) -> Result<Self, UiServiceError> {
        let surface = capabilities
            .surface
            .ok_or(UiServiceError::Display(DisplayInputError::Unsupported))?;
        let surface_bytes = surface.validate().map_err(UiServiceError::Display)?;
        let planned = plan_key_queue_capacity(surface_bytes, memory_budget)
            .ok_or(UiServiceError::Capacity)?;
        if CLIENTS == 0 || LAYERS == 0 || KEYS == 0 || KEYS > planned {
            return Err(UiServiceError::Capacity);
        }
        let display = DisplayInputSession::open(capabilities).map_err(UiServiceError::Display)?;
        Ok(Self {
            display,
            compositor: Compositor::new(),
            clients: [None; CLIENTS],
            generations: [0; CLIENTS],
            focus: None,
            pending_frame: None,
        })
    }

    pub const fn surface(&self) -> SurfaceSpec {
        self.display.surface()
    }

    pub fn client_count(&self) -> usize {
        self.clients.iter().flatten().count()
    }

    pub const fn focused(&self) -> Option<UiClientKey> {
        self.focus
    }

    /// Admit one application surface through an exact shared decision.
    pub fn create_client(
        &mut self,
        owner: u64,
        scope: AccessScope,
        layer: LayerSpec,
        capability: UiCapability,
    ) -> Result<UiClientKey, UiServiceError> {
        self.ensure_open()?;
        require_operation(capability, Operation::ServiceUiSessionCreate)?;
        if owner == 0 || capability.decision().subject != owner {
            return Err(UiServiceError::InvalidOwner);
        }
        if capability.decision().scope != scope || !valid_client_scope(scope) {
            return Err(UiServiceError::InvalidScope);
        }
        let slot = self
            .clients
            .iter()
            .position(Option::is_none)
            .ok_or(UiServiceError::Capacity)?;
        if slot > u16::MAX as usize {
            return Err(UiServiceError::Capacity);
        }
        let generation = self.generations[slot]
            .checked_add(1)
            .ok_or(UiServiceError::Capacity)?;
        let layer = self
            .compositor
            .create(layer)
            .map_err(UiServiceError::Compositor)?;
        self.generations[slot] = generation;
        let key = UiClientKey {
            slot: slot as u16,
            generation,
        };
        self.clients[slot] = Some(Client {
            key,
            owner,
            scope,
            layer,
        });
        Ok(key)
    }

    /// Move focus to one admitted client.
    pub fn set_focus(
        &mut self,
        client: UiClientKey,
        capability: UiCapability,
    ) -> Result<(), UiServiceError> {
        self.ensure_open()?;
        require_operation(capability, Operation::ServiceUiFocusSet)?;
        let record = self.client(client)?;
        require_owner_scope(record, capability)?;
        self.focus = Some(client);
        Ok(())
    }

    /// Queue a native keyboard event for the focused client.
    pub fn push_key(&mut self, key: KeyInput) -> Result<(), UiServiceError> {
        self.ensure_open()?;
        self.focus.ok_or(UiServiceError::NotFocused)?;
        self.display.push_key(key).map_err(UiServiceError::Display)
    }

    /// Read one event only through the focused client's exact capability.
    pub fn read_input(
        &mut self,
        client: UiClientKey,
        capability: UiCapability,
    ) -> Result<KeyInput, UiServiceError> {
        self.ensure_open()?;
        require_operation(capability, Operation::ServiceUiInputRead)?;
        let record = self.client(client)?;
        require_owner_scope(record, capability)?;
        if self.focus != Some(client) {
            return Err(UiServiceError::NotFocused);
        }
        self.display.pop_key().map_err(UiServiceError::Display)
    }

    /// Reserve one frame for a specific client; another client cannot steal it.
    pub fn prepare_frame(
        &mut self,
        client: UiClientKey,
        bytes: u64,
        capability: UiCapability,
    ) -> Result<FrameTicket, UiServiceError> {
        self.ensure_open()?;
        require_operation(capability, Operation::ServiceUiFramePresent)?;
        let record = self.client(client)?;
        require_owner_scope(record, capability)?;
        if self.pending_frame.is_some() {
            return Err(UiServiceError::Display(DisplayInputError::Busy));
        }
        let ticket = self
            .display
            .prepare_frame(bytes)
            .map_err(UiServiceError::Display)?;
        self.pending_frame = Some((client, ticket));
        Ok(ticket)
    }

    /// Commit the exact frame that the same client prepared.
    pub fn commit_frame(
        &mut self,
        client: UiClientKey,
        ticket: FrameTicket,
        capability: UiCapability,
    ) -> Result<u64, UiServiceError> {
        self.ensure_open()?;
        require_operation(capability, Operation::ServiceUiFramePresent)?;
        let record = self.client(client)?;
        require_owner_scope(record, capability)?;
        if self.pending_frame != Some((client, ticket)) {
            return Err(UiServiceError::NoPendingFrame);
        }
        let frame = self
            .display
            .commit_frame(ticket)
            .map_err(UiServiceError::Display)?;
        self.pending_frame = None;
        Ok(frame)
    }

    /// Close one client and destroy only its layer.
    pub fn close_client(
        &mut self,
        client: UiClientKey,
        capability: UiCapability,
    ) -> Result<(), UiServiceError> {
        self.ensure_open()?;
        require_operation(capability, Operation::ServiceUiSessionClose)?;
        let record = self.client(client)?;
        require_owner_scope(record, capability)?;
        self.compositor
            .destroy(record.layer)
            .map_err(UiServiceError::Compositor)?;
        if self.pending_frame.is_some_and(|(owner, _)| owner == client) {
            self.pending_frame = None;
        }
        self.clients[client.slot as usize] = None;
        if self.focus == Some(client) {
            self.focus = None;
        }
        Ok(())
    }

    /// Compose admitted layers through the existing bounded compositor.
    pub fn compose(
        &self,
        frame_bytes: &mut [u8],
        pixels: &[LayerPixels<'_>],
    ) -> Result<CompositionStats, UiServiceError> {
        self.ensure_open()?;
        self.compositor
            .compose(self.surface(), frame_bytes, pixels)
            .map_err(UiServiceError::Compositor)
    }

    /// Compose a damage region while retaining the base frame outside it.
    pub fn compose_retained(
        &self,
        frame_bytes: &mut [u8],
        base_bytes: &[u8],
        pixels: &[LayerPixels<'_>],
        damage: DamageRect,
    ) -> Result<CompositionStats, UiServiceError> {
        self.ensure_open()?;
        self.compositor
            .compose_retained(self.surface(), frame_bytes, base_bytes, pixels, damage)
            .map_err(UiServiceError::Compositor)
    }

    /// Commit the unique failed terminal and invalidate all live client tokens.
    pub fn fail(&mut self) -> Result<(), UiServiceError> {
        let display =
            if self.display.state() == crate::display_input::DisplaySessionState::Failed {
                Ok(())
            } else {
                self.display.fail()
            };
        let compositor =
            if self.compositor.state() == crate::display_compositor::CompositorState::Failed {
                Ok(())
            } else {
                self.compositor.fail()
            };
        self.clients.fill(None);
        self.focus = None;
        self.pending_frame = None;
        display.map_err(UiServiceError::Display)?;
        compositor.map_err(UiServiceError::Compositor)
    }

    fn client(&self, key: UiClientKey) -> Result<Client, UiServiceError> {
        self.clients
            .get(key.slot as usize)
            .and_then(Option::as_ref)
            .copied()
            .filter(|client| client.key == key)
            .ok_or(UiServiceError::StaleClient)
    }

    fn ensure_open(&self) -> Result<(), UiServiceError> {
        match self.display.state() {
            crate::display_input::DisplaySessionState::Open => Ok(()),
            crate::display_input::DisplaySessionState::Closed => Err(UiServiceError::Closed),
            crate::display_input::DisplaySessionState::Failed => Err(UiServiceError::Failed),
        }
    }
}

fn valid_client_scope(scope: AccessScope) -> bool {
    matches!(
        scope,
        AccessScope::User(_)
            | AccessScope::Group(_)
            | AccessScope::Tenant(_)
            | AccessScope::Workload(_)
            | AccessScope::Service(_)
    ) && scope.is_valid()
}

fn require_operation(capability: UiCapability, operation: Operation) -> Result<(), UiServiceError> {
    (capability.operation == operation)
        .then_some(())
        .ok_or(UiServiceError::WrongOperation)
}

fn require_owner_scope(client: Client, capability: UiCapability) -> Result<(), UiServiceError> {
    let decision = capability.decision;
    if decision.subject != client.owner {
        return Err(UiServiceError::InvalidOwner);
    }
    if decision.scope != client.scope {
        return Err(UiServiceError::InvalidScope);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::display_input::{DisplayBackend, PixelLayout};

    const SURFACE: SurfaceSpec = SurfaceSpec {
        width: 64,
        height: 32,
        stride: 64,
        bytes_per_pixel: 4,
        layout: PixelLayout::Bgr,
    };
    const CAPS: DisplayCapabilities = DisplayCapabilities {
        backend: Some(DisplayBackend::Framebuffer),
        surface: Some(SURFACE),
        keyboard: true,
    };

    fn decision(subject: u64, scope: AccessScope, operation: Operation, allowed: bool) -> Decision {
        Decision {
            format_version: authz::AUTHZ_FORMAT_VERSION,
            issuer: authz::KERNEL_PEP_ISSUER,
            subject,
            executor_object: subject,
            executor_generation: 1,
            tenant: 7,
            domain: 1,
            operation,
            scope,
            effect: operation_effect(operation),
            policy_epoch: 1,
            revocation_generation: Some(1),
            allowed,
            reason: if allowed {
                authz::Reason::Allowed
            } else {
                authz::Reason::MissingCapability
            },
        }
    }

    fn capability(subject: u64, scope: AccessScope, operation: Operation) -> UiCapability {
        UiCapability::from_decision(decision(subject, scope, operation, true), operation).unwrap()
    }

    fn layer(z: u16) -> LayerSpec {
        LayerSpec {
            surface: SURFACE,
            x: 0,
            y: 0,
            z_order: z,
            visible: true,
            opacity: 255,
        }
    }

    #[test]
    fn two_clients_are_focus_and_generation_isolated() {
        let mut ui = UiService::<2, 2, 2>::open(CAPS, 1024 * 1024).unwrap();
        let first_scope = AccessScope::Workload(10);
        let second_scope = AccessScope::Workload(11);
        let first = ui
            .create_client(
                10,
                first_scope,
                layer(1),
                capability(10, first_scope, Operation::ServiceUiSessionCreate),
            )
            .unwrap();
        let second = ui
            .create_client(
                11,
                second_scope,
                layer(2),
                capability(11, second_scope, Operation::ServiceUiSessionCreate),
            )
            .unwrap();
        ui.set_focus(
            first,
            capability(10, first_scope, Operation::ServiceUiFocusSet),
        )
        .unwrap();
        ui.push_key(KeyInput {
            code: 30,
            pressed: true,
            modifiers: 0,
        })
        .unwrap();
        assert_eq!(
            ui.read_input(
                second,
                capability(11, second_scope, Operation::ServiceUiInputRead)
            ),
            Err(UiServiceError::NotFocused)
        );
        assert_eq!(
            ui.read_input(
                first,
                capability(11, second_scope, Operation::ServiceUiInputRead)
            ),
            Err(UiServiceError::InvalidOwner)
        );
        assert_eq!(
            ui.read_input(
                first,
                capability(10, first_scope, Operation::ServiceUiInputRead)
            ),
            Ok(KeyInput {
                code: 30,
                pressed: true,
                modifiers: 0
            })
        );
        let bytes = SURFACE.validate().unwrap();
        let ticket = ui
            .prepare_frame(
                first,
                bytes,
                capability(10, first_scope, Operation::ServiceUiFramePresent),
            )
            .unwrap();
        assert_eq!(
            ui.commit_frame(
                second,
                ticket,
                capability(11, second_scope, Operation::ServiceUiFramePresent)
            ),
            Err(UiServiceError::NoPendingFrame)
        );
        assert_eq!(
            ui.commit_frame(
                first,
                ticket,
                capability(10, first_scope, Operation::ServiceUiFramePresent)
            ),
            Ok(1)
        );
    }

    #[test]
    fn denied_or_wrong_operation_cannot_mint_ui_capability() {
        let scope = AccessScope::Workload(10);
        assert_eq!(
            UiCapability::from_decision(
                decision(10, scope, Operation::ServiceUiSessionCreate, false),
                Operation::ServiceUiSessionCreate
            ),
            Err(UiServiceError::AuthorizationDenied)
        );
        assert_eq!(
            UiCapability::from_decision(
                decision(10, scope, Operation::ServiceUiInputRead, true),
                Operation::ServiceUiSessionCreate
            ),
            Err(UiServiceError::WrongOperation)
        );
    }

    #[test]
    fn close_reuses_slot_with_new_generation_and_service_failure_invalidates_clients() {
        let mut ui = UiService::<1, 1, 2>::open(CAPS, 1024 * 1024).unwrap();
        let scope = AccessScope::Workload(10);
        let first = ui
            .create_client(
                10,
                scope,
                layer(1),
                capability(10, scope, Operation::ServiceUiSessionCreate),
            )
            .unwrap();
        ui.close_client(
            first,
            capability(10, scope, Operation::ServiceUiSessionClose),
        )
        .unwrap();
        let second = ui
            .create_client(
                10,
                scope,
                layer(1),
                capability(10, scope, Operation::ServiceUiSessionCreate),
            )
            .unwrap();
        assert_ne!(first.to_raw(), second.to_raw());
        ui.fail().unwrap();
        assert_eq!(ui.fail(), Ok(()));
        assert_eq!(
            ui.set_focus(second, capability(10, scope, Operation::ServiceUiFocusSet)),
            Err(UiServiceError::Failed)
        );
        assert_eq!(ui.client_count(), 0);
    }
}
