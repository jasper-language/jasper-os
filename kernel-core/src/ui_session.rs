//! Authenticated local/remote UI session isolation contract.
//!
//! Session keys are disposable scalar identities, never native Handles. The
//! module binds a session to one authenticated subject and display/input scope,
//! rejects stale or replayed input, recovers a disconnected remote session with
//! a new generation, and degrades explicitly when no display is available.

use crate::authz::{AccessScope, Operation};
use crate::display_input::SurfaceSpec;
use crate::ui_policy::UiDeviceCapabilities;
use crate::ui_service::{UiCapability, UiServiceError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiSessionKind {
    Local,
    Remote,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiRenderMode {
    Ui,
    Headless,
    Console,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UiSessionScope {
    pub user: u64,
    pub tenant: u64,
    pub session: u64,
    pub display_seat: u32,
    pub input_seat: u32,
}

impl UiSessionScope {
    pub const fn is_valid(self) -> bool {
        self.user != 0
            && self.tenant != 0
            && self.session != 0
            && self.display_seat != 0
            && self.input_seat != 0
    }

    fn same_seat(self, other: Self) -> bool {
        self.display_seat == other.display_seat && self.input_seat == other.input_seat
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UiSessionKey {
    slot: u16,
    generation: u32,
}

impl UiSessionKey {
    pub const fn raw(self) -> u64 {
        ((self.generation as u64) << 16) | self.slot as u64
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiSessionState {
    Active,
    Disconnected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UiSceneFacts {
    pub visible: bool,
    pub rendering: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UiInputEnvelope {
    pub key: UiSessionKey,
    pub input_generation: u64,
    pub sequence: u64,
    pub code: u32,
    pub pressed: bool,
    pub modifiers: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiSessionError {
    InvalidScope,
    Authorization,
    Capacity,
    GenerationExhausted,
    UnknownSession,
    StaleSession,
    CrossUserSeat,
    CrossUserSurface,
    NotFocused,
    Replay,
    StaleInput,
    OrdinaryBackground,
    NotRemote,
    NotDisconnected,
    RecoveryConflict,
    InvalidSurface,
    Closed,
}

#[derive(Debug, Clone, Copy)]
struct Session {
    key: UiSessionKey,
    subject: u64,
    scope: UiSessionScope,
    kind: UiSessionKind,
    state: UiSessionState,
    surface: Option<SurfaceSpec>,
    input_generation: u64,
    last_input_sequence: u64,
    scene: UiSceneFacts,
    background_grant: bool,
}

pub struct UiSessionRegistry<const N: usize> {
    sessions: [Option<Session>; N],
    generations: [u32; N],
    focus: Option<UiSessionKey>,
    focus_subject: u64,
}

impl<const N: usize> UiSessionRegistry<N> {
    pub const fn new() -> Self {
        Self {
            sessions: [None; N],
            generations: [0; N],
            focus: None,
            focus_subject: 0,
        }
    }

    pub fn open(
        &mut self,
        subject: u64,
        scope: UiSessionScope,
        kind: UiSessionKind,
        capabilities: UiDeviceCapabilities,
        surface: Option<SurfaceSpec>,
        capability: UiCapability,
    ) -> Result<(UiSessionKey, UiRenderMode), UiSessionError> {
        authorize(
            capability,
            subject,
            scope,
            Operation::ServiceUiSessionCreate,
        )?;
        if !scope.is_valid() {
            return Err(UiSessionError::InvalidScope);
        }
        let mode = choose_mode(capabilities);
        if mode == UiRenderMode::Ui {
            let surface = surface.ok_or(UiSessionError::InvalidSurface)?;
            surface
                .validate()
                .map_err(|_| UiSessionError::InvalidSurface)?;
        }
        if self.sessions.iter().flatten().any(|session| {
            session.state == UiSessionState::Active
                && session.scope.same_seat(scope)
                && session.subject != subject
        }) {
            return Err(UiSessionError::CrossUserSeat);
        }
        let slot = self
            .sessions
            .iter()
            .position(Option::is_none)
            .ok_or(UiSessionError::Capacity)?;
        let generation = self.generations[slot]
            .checked_add(1)
            .ok_or(UiSessionError::GenerationExhausted)?;
        let key = UiSessionKey {
            slot: u16::try_from(slot).map_err(|_| UiSessionError::Capacity)?,
            generation,
        };
        self.generations[slot] = generation;
        self.sessions[slot] = Some(Session {
            key,
            subject,
            scope,
            kind,
            state: UiSessionState::Active,
            surface: (mode == UiRenderMode::Ui).then_some(surface).flatten(),
            input_generation: 1,
            last_input_sequence: 0,
            scene: UiSceneFacts {
                visible: false,
                rendering: false,
            },
            background_grant: false,
        });
        Ok((key, mode))
    }

    pub fn focus(
        &mut self,
        subject: u64,
        scope: UiSessionScope,
        key: UiSessionKey,
        visible: bool,
        capability: UiCapability,
    ) -> Result<(), UiSessionError> {
        authorize(capability, subject, scope, Operation::ServiceUiFocusSet)?;
        let session = self.active(subject, scope, key)?;
        if !visible {
            return Err(UiSessionError::NotFocused);
        }
        if let Some(current) = self.focus.filter(|current| *current != key) {
            if self.focus_subject != subject {
                return Err(UiSessionError::CrossUserSurface);
            }
            if let Some(current) = self.find(current) {
                let _ = session;
                if current.scope.user != subject {
                    return Err(UiSessionError::CrossUserSurface);
                }
            }
        }
        self.focus = Some(key);
        self.focus_subject = subject;
        Ok(())
    }

    pub fn set_scene(
        &mut self,
        subject: u64,
        scope: UiSessionScope,
        key: UiSessionKey,
        scene: UiSceneFacts,
    ) -> Result<(), UiSessionError> {
        let background_grant = self.active(subject, scope, key)?.background_grant;
        if scene.rendering && !scene.visible && !background_grant {
            return Err(UiSessionError::OrdinaryBackground);
        }
        let session = self.active_mut(subject, scope, key)?;
        session.scene = scene;
        Ok(())
    }

    pub fn grant_background(
        &mut self,
        subject: u64,
        scope: UiSessionScope,
        key: UiSessionKey,
        capability: UiCapability,
    ) -> Result<(), UiSessionError> {
        authorize(capability, subject, scope, Operation::ServiceUiFramePresent)?;
        self.active_mut(subject, scope, key)?.background_grant = true;
        Ok(())
    }

    pub fn revoke_background(
        &mut self,
        subject: u64,
        scope: UiSessionScope,
        key: UiSessionKey,
    ) -> Result<(), UiSessionError> {
        let session = self.active_mut(subject, scope, key)?;
        session.background_grant = false;
        if session.scene.rendering && !session.scene.visible {
            session.scene.rendering = false;
        }
        Ok(())
    }

    pub fn input(
        &mut self,
        subject: u64,
        scope: UiSessionScope,
        input: UiInputEnvelope,
        capability: UiCapability,
    ) -> Result<(), UiSessionError> {
        authorize(capability, subject, scope, Operation::ServiceUiInputRead)?;
        let _ = self.active(subject, scope, input.key)?;
        if self.focus != Some(input.key) || self.focus_subject != subject {
            return Err(UiSessionError::NotFocused);
        }
        let session = self.active_mut(subject, scope, input.key)?;
        if input.input_generation != session.input_generation {
            return Err(UiSessionError::StaleInput);
        }
        if input.sequence <= session.last_input_sequence {
            return Err(UiSessionError::Replay);
        }
        session.last_input_sequence = input.sequence;
        let _ = (input.code, input.pressed, input.modifiers);
        Ok(())
    }

    pub fn surface_for(
        &self,
        subject: u64,
        key: UiSessionKey,
    ) -> Result<SurfaceSpec, UiSessionError> {
        let session = self.find(key).ok_or(UiSessionError::UnknownSession)?;
        if session.state != UiSessionState::Active {
            return Err(UiSessionError::Closed);
        }
        if session.subject != subject {
            return Err(UiSessionError::CrossUserSurface);
        }
        session.surface.ok_or(UiSessionError::InvalidSurface)
    }

    pub fn disconnect(&mut self, subject: u64, key: UiSessionKey) -> Result<(), UiSessionError> {
        let session = self.find_mut(key).ok_or(UiSessionError::UnknownSession)?;
        if session.subject != subject || session.state != UiSessionState::Active {
            return Err(UiSessionError::StaleSession);
        }
        if session.kind != UiSessionKind::Remote {
            return Err(UiSessionError::NotRemote);
        }
        session.state = UiSessionState::Disconnected;
        if self.focus == Some(key) {
            self.focus = None;
            self.focus_subject = 0;
        }
        Ok(())
    }

    pub fn recover(
        &mut self,
        subject: u64,
        scope: UiSessionScope,
        old: UiSessionKey,
        capability: UiCapability,
    ) -> Result<(UiSessionKey, u64), UiSessionError> {
        authorize(
            capability,
            subject,
            scope,
            Operation::ServiceUiSessionCreate,
        )?;
        let session = self.find(old).ok_or(UiSessionError::UnknownSession)?;
        if session.subject != subject || session.scope != scope {
            return Err(UiSessionError::RecoveryConflict);
        }
        if session.state != UiSessionState::Disconnected {
            return Err(UiSessionError::NotDisconnected);
        }
        let slot = old.slot as usize;
        let generation = self.generations[slot]
            .checked_add(1)
            .ok_or(UiSessionError::GenerationExhausted)?;
        let key = UiSessionKey {
            slot: old.slot,
            generation,
        };
        let input_generation = session
            .input_generation
            .checked_add(1)
            .ok_or(UiSessionError::GenerationExhausted)?;
        self.generations[slot] = generation;
        let session = self.sessions[slot]
            .as_mut()
            .ok_or(UiSessionError::UnknownSession)?;
        session.key = key;
        session.state = UiSessionState::Active;
        session.input_generation = input_generation;
        session.last_input_sequence = 0;
        session.scene = UiSceneFacts {
            visible: false,
            rendering: false,
        };
        Ok((key, input_generation))
    }

    pub fn close(&mut self, subject: u64, key: UiSessionKey) -> Result<(), UiSessionError> {
        let session = self.find(key).ok_or(UiSessionError::UnknownSession)?;
        if session.subject != subject {
            return Err(UiSessionError::StaleSession);
        }
        if self.focus == Some(key) {
            self.focus = None;
            self.focus_subject = 0;
        }
        self.sessions[key.slot as usize] = None;
        Ok(())
    }

    pub const fn focused(&self) -> Option<UiSessionKey> {
        self.focus
    }

    fn active(
        &self,
        subject: u64,
        scope: UiSessionScope,
        key: UiSessionKey,
    ) -> Result<&Session, UiSessionError> {
        let session = self.find(key).ok_or(UiSessionError::UnknownSession)?;
        if session.subject != subject || session.scope != scope {
            return Err(UiSessionError::CrossUserSurface);
        }
        if session.state != UiSessionState::Active {
            return Err(UiSessionError::StaleSession);
        }
        Ok(session)
    }

    fn active_mut(
        &mut self,
        subject: u64,
        scope: UiSessionScope,
        key: UiSessionKey,
    ) -> Result<&mut Session, UiSessionError> {
        let session = self.find_mut(key).ok_or(UiSessionError::UnknownSession)?;
        if session.subject != subject || session.scope != scope {
            return Err(UiSessionError::CrossUserSurface);
        }
        if session.state != UiSessionState::Active {
            return Err(UiSessionError::StaleSession);
        }
        Ok(session)
    }

    fn find(&self, key: UiSessionKey) -> Option<&Session> {
        self.sessions
            .get(key.slot as usize)
            .and_then(Option::as_ref)
            .filter(|session| session.key == key)
    }

    fn find_mut(&mut self, key: UiSessionKey) -> Option<&mut Session> {
        self.sessions
            .get_mut(key.slot as usize)
            .and_then(Option::as_mut)
            .filter(|session| session.key == key)
    }
}

impl<const N: usize> Default for UiSessionRegistry<N> {
    fn default() -> Self {
        Self::new()
    }
}

fn choose_mode(capabilities: UiDeviceCapabilities) -> UiRenderMode {
    if capabilities.display {
        UiRenderMode::Ui
    } else if capabilities.keyboard || capabilities.pointer || capabilities.touch {
        UiRenderMode::Headless
    } else {
        UiRenderMode::Console
    }
}

fn authorize(
    capability: UiCapability,
    subject: u64,
    scope: UiSessionScope,
    operation: Operation,
) -> Result<(), UiSessionError> {
    let decision = capability.decision();
    if capability.operation() != operation
        || decision.subject != subject
        || decision.scope != AccessScope::User(scope.user)
        || decision.tenant != scope.tenant
    {
        return Err(UiSessionError::Authorization);
    }
    Ok(())
}

impl From<UiServiceError> for UiSessionError {
    fn from(_: UiServiceError) -> Self {
        Self::Authorization
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::{Decision, Effect, Reason, AUTHZ_FORMAT_VERSION};

    const SURFACE: SurfaceSpec = SurfaceSpec {
        width: 64,
        height: 64,
        stride: 64,
        bytes_per_pixel: 4,
        layout: crate::display_input::PixelLayout::Rgba,
    };

    fn scope(user: u64, session: u64, seat: u32) -> UiSessionScope {
        UiSessionScope {
            user,
            tenant: 1,
            session,
            display_seat: seat,
            input_seat: seat,
        }
    }

    fn decision(subject: u64, scope: UiSessionScope, operation: Operation) -> Decision {
        Decision {
            format_version: AUTHZ_FORMAT_VERSION,
            issuer: crate::authz::KERNEL_PEP_ISSUER,
            subject,
            executor_object: subject,
            executor_generation: 1,
            tenant: scope.tenant,
            domain: 1,
            operation,
            effect: match operation {
                Operation::ServiceUiInputRead => Effect::Read,
                _ => Effect::Write,
            },
            scope: AccessScope::User(scope.user),
            policy_epoch: 1,
            revocation_generation: Some(0),
            allowed: true,
            reason: Reason::Allowed,
        }
    }

    fn capability(subject: u64, scope: UiSessionScope, operation: Operation) -> UiCapability {
        UiCapability::from_decision(decision(subject, scope, operation), operation).unwrap()
    }

    fn capabilities(display: bool) -> UiDeviceCapabilities {
        UiDeviceCapabilities {
            display,
            keyboard: true,
            pointer: false,
            touch: false,
            split_layouts: false,
            multi_window: false,
            background_grants: true,
        }
    }

    #[test]
    fn scopes_focus_and_surfaces_are_cross_user_isolated() {
        let mut registry: UiSessionRegistry<2> = UiSessionRegistry::new();
        let first = scope(10, 1, 1);
        let second = scope(11, 2, 1);
        let (first_key, _) = registry
            .open(
                10,
                first,
                UiSessionKind::Local,
                capabilities(true),
                Some(SURFACE),
                capability(10, first, Operation::ServiceUiSessionCreate),
            )
            .unwrap();
        assert_eq!(
            registry.open(
                11,
                second,
                UiSessionKind::Remote,
                capabilities(true),
                Some(SURFACE),
                capability(11, second, Operation::ServiceUiSessionCreate),
            ),
            Err(UiSessionError::CrossUserSeat)
        );
        registry
            .focus(
                10,
                first,
                first_key,
                true,
                capability(10, first, Operation::ServiceUiFocusSet),
            )
            .unwrap();
        assert_eq!(
            registry.surface_for(11, first_key),
            Err(UiSessionError::CrossUserSurface)
        );
    }

    #[test]
    fn input_requires_focus_and_rejects_stale_or_replayed_sequences() {
        let mut registry: UiSessionRegistry<1> = UiSessionRegistry::new();
        let s = scope(10, 1, 1);
        let (key, _) = registry
            .open(
                10,
                s,
                UiSessionKind::Remote,
                capabilities(true),
                Some(SURFACE),
                capability(10, s, Operation::ServiceUiSessionCreate),
            )
            .unwrap();
        let input = UiInputEnvelope {
            key,
            input_generation: 1,
            sequence: 1,
            code: 28,
            pressed: true,
            modifiers: 0,
        };
        assert_eq!(
            registry.input(
                10,
                s,
                input,
                capability(10, s, Operation::ServiceUiInputRead)
            ),
            Err(UiSessionError::NotFocused)
        );
        registry
            .set_scene(
                10,
                s,
                key,
                UiSceneFacts {
                    visible: true,
                    rendering: true,
                },
            )
            .unwrap();
        registry
            .focus(
                10,
                s,
                key,
                true,
                capability(10, s, Operation::ServiceUiFocusSet),
            )
            .unwrap();
        assert_eq!(
            registry.input(
                10,
                s,
                input,
                capability(10, s, Operation::ServiceUiInputRead)
            ),
            Ok(())
        );
        assert_eq!(
            registry.input(
                10,
                s,
                input,
                capability(10, s, Operation::ServiceUiInputRead)
            ),
            Err(UiSessionError::Replay)
        );
        assert_eq!(
            registry.input(
                10,
                s,
                UiInputEnvelope {
                    input_generation: 0,
                    sequence: 2,
                    ..input
                },
                capability(10, s, Operation::ServiceUiInputRead)
            ),
            Err(UiSessionError::StaleInput)
        );
    }

    #[test]
    fn remote_disconnect_requires_explicit_generation_recovery() {
        let mut registry: UiSessionRegistry<1> = UiSessionRegistry::new();
        let s = scope(10, 1, 1);
        let (old, _) = registry
            .open(
                10,
                s,
                UiSessionKind::Remote,
                capabilities(true),
                Some(SURFACE),
                capability(10, s, Operation::ServiceUiSessionCreate),
            )
            .unwrap();
        registry.disconnect(10, old).unwrap();
        assert_eq!(
            registry.disconnect(10, old),
            Err(UiSessionError::StaleSession)
        );
        let (new, input_generation) = registry
            .recover(
                10,
                s,
                old,
                capability(10, s, Operation::ServiceUiSessionCreate),
            )
            .unwrap();
        assert_ne!(old, new);
        assert_eq!(input_generation, 2);
        assert_eq!(
            registry.input(
                10,
                s,
                UiInputEnvelope {
                    key: old,
                    input_generation: 1,
                    sequence: 1,
                    code: 28,
                    pressed: true,
                    modifiers: 0,
                },
                capability(10, s, Operation::ServiceUiInputRead)
            ),
            Err(UiSessionError::UnknownSession)
        );
    }

    #[test]
    fn no_gui_profiles_degrade_to_headless_or_console() {
        let mut registry: UiSessionRegistry<2> = UiSessionRegistry::new();
        let headless = scope(10, 1, 1);
        let console = scope(11, 2, 2);
        assert_eq!(
            registry
                .open(
                    10,
                    headless,
                    UiSessionKind::Remote,
                    capabilities(false),
                    None,
                    capability(10, headless, Operation::ServiceUiSessionCreate),
                )
                .unwrap()
                .1,
            UiRenderMode::Headless
        );
        let mut no_input = capabilities(false);
        no_input.keyboard = false;
        assert_eq!(
            registry
                .open(
                    11,
                    console,
                    UiSessionKind::Local,
                    no_input,
                    None,
                    capability(11, console, Operation::ServiceUiSessionCreate),
                )
                .unwrap()
                .1,
            UiRenderMode::Console
        );
    }

    #[test]
    fn invisible_rendering_requires_an_explicit_background_capability() {
        let mut registry: UiSessionRegistry<1> = UiSessionRegistry::new();
        let s = scope(10, 1, 1);
        let (key, _) = registry
            .open(
                10,
                s,
                UiSessionKind::Local,
                capabilities(true),
                Some(SURFACE),
                capability(10, s, Operation::ServiceUiSessionCreate),
            )
            .unwrap();
        let hidden = UiSceneFacts {
            visible: false,
            rendering: true,
        };
        assert_eq!(
            registry.set_scene(10, s, key, hidden),
            Err(UiSessionError::OrdinaryBackground)
        );
        registry
            .grant_background(
                10,
                s,
                key,
                capability(10, s, Operation::ServiceUiFramePresent),
            )
            .unwrap();
        assert_eq!(registry.set_scene(10, s, key, hidden), Ok(()));
        registry.revoke_background(10, s, key).unwrap();
        assert_eq!(
            registry.set_scene(10, s, key, hidden),
            Err(UiSessionError::OrdinaryBackground)
        );
    }

    #[test]
    fn close_reuses_a_slot_only_with_a_new_generation() {
        let mut registry: UiSessionRegistry<1> = UiSessionRegistry::new();
        let s = scope(10, 1, 1);
        let (old, _) = registry
            .open(
                10,
                s,
                UiSessionKind::Local,
                capabilities(true),
                Some(SURFACE),
                capability(10, s, Operation::ServiceUiSessionCreate),
            )
            .unwrap();
        registry.close(10, old).unwrap();
        let (new, _) = registry
            .open(
                10,
                s,
                UiSessionKind::Local,
                capabilities(true),
                Some(SURFACE),
                capability(10, s, Operation::ServiceUiSessionCreate),
            )
            .unwrap();
        assert_ne!(old, new);
        assert_eq!(
            registry.surface_for(10, old),
            Err(UiSessionError::UnknownSession)
        );
        assert_eq!(registry.surface_for(10, new), Ok(SURFACE));
    }
}
