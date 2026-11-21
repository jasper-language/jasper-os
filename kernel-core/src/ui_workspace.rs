//! Atomic multi-window layout and display-capability migration.
//!
//! The workspace is a policy/service contract: it plans Scene viewports and
//! commits all Surface/input generation changes together. It does not own a
//! framebuffer, compositor or authorization authority.

use crate::authz::AccessScope;
use crate::display_input::SurfaceSpec;
use crate::ui_policy::{
    select_interaction_profile, InteractionProfile, ProfileDecision, UiDeviceCapabilities,
    UiPolicyScope,
};
use crate::ui_service::UiCapability;
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiLayoutMode {
    Single,
    Split,
    MultiWindow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UiViewport {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UiCapabilityEvent {
    pub capability_epoch: u64,
    pub policy_epoch: u64,
    pub revocation_epoch: u64,
    pub capabilities: UiDeviceCapabilities,
    pub surface: SurfaceSpec,
    pub dpi_x: u32,
    pub dpi_y: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SceneBinding {
    slot: u16,
    scene_generation: u32,
    surface_generation: u64,
    input_generation: u64,
    frame_sequence: u64,
    input_sequence: u64,
    viewport: UiViewport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiWorkspaceError {
    Invalid,
    Capacity,
    Unsupported,
    Authorization,
    Budget,
    StaleCapability,
    StalePolicy,
    StaleRevocation,
    StaleScene,
    StaleSurface,
    StaleInput,
    ReplayFrame,
    ReplayInput,
}

pub struct UiWorkspace<const N: usize> {
    subject: u64,
    scope: UiPolicyScope,
    mode: UiLayoutMode,
    capabilities: UiDeviceCapabilities,
    surface: SurfaceSpec,
    dpi_x: u32,
    dpi_y: u32,
    capability_epoch: u64,
    policy_epoch: u64,
    revocation_epoch: u64,
    scenes: [Option<SceneBinding>; N],
}

impl<const N: usize> UiWorkspace<N> {
    pub fn new(
        subject: u64,
        scope: UiPolicyScope,
        capabilities: UiDeviceCapabilities,
        surface: SurfaceSpec,
        dpi_x: u32,
        dpi_y: u32,
        scene_generations: &[u32],
    ) -> Result<Self, UiWorkspaceError> {
        if subject == 0
            || !scope.is_valid()
            || !capabilities.display
            || dpi_x == 0
            || dpi_y == 0
            || scene_generations.is_empty()
            || scene_generations.len() > N
        {
            return Err(UiWorkspaceError::Invalid);
        }
        surface.validate().map_err(|_| UiWorkspaceError::Invalid)?;
        let mode = match scene_generations.len() {
            1 => UiLayoutMode::Single,
            2 if capabilities.split_layouts => UiLayoutMode::Split,
            count if capabilities.multi_window && count <= N => UiLayoutMode::MultiWindow,
            _ => return Err(UiWorkspaceError::Unsupported),
        };
        let viewports = plan_viewports(mode, surface, scene_generations.len(), 500)?;
        let mut scenes = [None; N];
        for (slot, generation) in scene_generations.iter().copied().enumerate() {
            if generation == 0 {
                return Err(UiWorkspaceError::Invalid);
            }
            scenes[slot] = Some(SceneBinding {
                slot: u16::try_from(slot).map_err(|_| UiWorkspaceError::Capacity)?,
                scene_generation: generation,
                surface_generation: 1,
                input_generation: 1,
                frame_sequence: 0,
                input_sequence: 0,
                viewport: viewports[slot],
            });
        }
        Ok(Self {
            subject,
            scope,
            mode,
            capabilities,
            surface,
            dpi_x,
            dpi_y,
            capability_epoch: 1,
            policy_epoch: 1,
            revocation_epoch: 0,
            scenes,
        })
    }

    pub const fn mode(&self) -> UiLayoutMode {
        self.mode
    }

    pub const fn surface(&self) -> SurfaceSpec {
        self.surface
    }

    pub fn viewport(&self, slot: u16, scene_generation: u32) -> Option<UiViewport> {
        self.scenes
            .get(slot as usize)
            .and_then(Option::as_ref)
            .filter(|scene| scene.scene_generation == scene_generation)
            .map(|scene| scene.viewport)
    }

    pub fn reconfigure(
        &mut self,
        event: UiCapabilityEvent,
        requested: InteractionProfile,
        primary_permille: u16,
        memory_budget: u64,
        capability: UiCapability,
    ) -> Result<UiLayoutMode, UiWorkspaceError> {
        if event.capability_epoch <= self.capability_epoch {
            return Err(UiWorkspaceError::StaleCapability);
        }
        if event.policy_epoch <= self.policy_epoch {
            return Err(UiWorkspaceError::StalePolicy);
        }
        if event.revocation_epoch < self.revocation_epoch {
            return Err(UiWorkspaceError::StaleRevocation);
        }
        if event.dpi_x == 0 || event.dpi_y == 0 {
            return Err(UiWorkspaceError::Invalid);
        }
        let decision = capability.decision();
        if decision.subject != self.subject
            || decision.scope != AccessScope::User(u64::from(self.scope.user))
            || decision.tenant != u64::from(self.scope.tenant)
            || decision.policy_epoch != event.policy_epoch
            || decision.revocation_generation != u32::try_from(event.revocation_epoch).ok()
        {
            return Err(UiWorkspaceError::Authorization);
        }
        if capability.operation() != crate::authz::Operation::ServiceUiFramePresent {
            return Err(UiWorkspaceError::Authorization);
        }
        let profile = match select_interaction_profile(event.capabilities, requested) {
            ProfileDecision::Selected(profile) | ProfileDecision::Degraded(profile) => profile,
            ProfileDecision::Unsupported => return Err(UiWorkspaceError::Unsupported),
        };
        let mode = match profile {
            InteractionProfile::SinglePrimary => UiLayoutMode::Single,
            InteractionProfile::Split => UiLayoutMode::Split,
            InteractionProfile::MultiWindow => UiLayoutMode::MultiWindow,
        };
        let active = self.scenes.iter().flatten().count();
        if active == 0
            || (mode == UiLayoutMode::Single && active != 1)
            || (mode == UiLayoutMode::Split && active != 2)
        {
            return Err(UiWorkspaceError::Unsupported);
        }
        if primary_permille == 0 || primary_permille >= 1000 {
            return Err(UiWorkspaceError::Invalid);
        }
        let surface_bytes = event
            .surface
            .validate()
            .map_err(|_| UiWorkspaceError::Invalid)?;
        let total = surface_bytes
            .checked_mul(active as u64)
            .ok_or(UiWorkspaceError::Budget)?;
        if total > memory_budget {
            return Err(UiWorkspaceError::Budget);
        }
        let viewports = plan_viewports(mode, event.surface, active, primary_permille)?;
        let mut next = self.scenes;
        let mut viewport = 0;
        for scene in next.iter_mut().flatten() {
            scene.surface_generation = scene
                .surface_generation
                .checked_add(1)
                .ok_or(UiWorkspaceError::StaleSurface)?;
            scene.input_generation = scene
                .input_generation
                .checked_add(1)
                .ok_or(UiWorkspaceError::StaleInput)?;
            scene.viewport = viewports[viewport];
            viewport += 1;
        }
        self.mode = mode;
        self.capabilities = event.capabilities;
        self.surface = event.surface;
        self.dpi_x = event.dpi_x;
        self.dpi_y = event.dpi_y;
        self.capability_epoch = event.capability_epoch;
        self.policy_epoch = event.policy_epoch;
        self.revocation_epoch = event.revocation_epoch;
        self.scenes = next;
        Ok(mode)
    }

    pub fn frame(
        &mut self,
        slot: u16,
        scene_generation: u32,
        surface_generation: u64,
        sequence: u64,
    ) -> Result<UiViewport, UiWorkspaceError> {
        let scene = self
            .scenes
            .get_mut(slot as usize)
            .and_then(Option::as_mut)
            .filter(|scene| scene.scene_generation == scene_generation)
            .ok_or(UiWorkspaceError::StaleScene)?;
        if surface_generation != scene.surface_generation {
            return Err(UiWorkspaceError::StaleSurface);
        }
        if sequence <= scene.frame_sequence {
            return Err(UiWorkspaceError::ReplayFrame);
        }
        scene.frame_sequence = sequence;
        Ok(scene.viewport)
    }

    pub fn input(
        &mut self,
        slot: u16,
        scene_generation: u32,
        input_generation: u64,
        sequence: u64,
    ) -> Result<UiViewport, UiWorkspaceError> {
        let scene = self
            .scenes
            .get_mut(slot as usize)
            .and_then(Option::as_mut)
            .filter(|scene| scene.scene_generation == scene_generation)
            .ok_or(UiWorkspaceError::StaleScene)?;
        if input_generation != scene.input_generation {
            return Err(UiWorkspaceError::StaleInput);
        }
        if sequence <= scene.input_sequence {
            return Err(UiWorkspaceError::ReplayInput);
        }
        scene.input_sequence = sequence;
        Ok(scene.viewport)
    }
}

fn plan_viewports(
    mode: UiLayoutMode,
    surface: SurfaceSpec,
    count: usize,
    primary_permille: u16,
) -> Result<Vec<UiViewport>, UiWorkspaceError> {
    if count == 0 {
        return Err(UiWorkspaceError::Invalid);
    }
    let mut out = Vec::new();
    out.try_reserve_exact(count)
        .map_err(|_| UiWorkspaceError::Capacity)?;
    match mode {
        UiLayoutMode::Single => out.push(UiViewport {
            x: 0,
            y: 0,
            width: surface.width,
            height: surface.height,
        }),
        UiLayoutMode::Split => {
            if count != 2 || primary_permille == 0 || primary_permille >= 1000 {
                return Err(UiWorkspaceError::Invalid);
            }
            let primary = surface.width as u64 * u64::from(primary_permille) / 1000;
            let primary = u32::try_from(primary).map_err(|_| UiWorkspaceError::Invalid)?;
            if primary == 0 || primary >= surface.width {
                return Err(UiWorkspaceError::Invalid);
            }
            out.push(UiViewport {
                x: 0,
                y: 0,
                width: primary,
                height: surface.height,
            });
            out.push(UiViewport {
                x: primary,
                y: 0,
                width: surface.width - primary,
                height: surface.height,
            });
        }
        UiLayoutMode::MultiWindow => {
            let columns = integer_sqrt(count);
            let rows = count.div_ceil(columns);
            for index in 0..count {
                let column = index % columns;
                let row = index / columns;
                let x = surface.width as u64 * column as u64 / columns as u64;
                let next_x = surface.width as u64 * (column as u64 + 1) / columns as u64;
                let y = surface.height as u64 * row as u64 / rows as u64;
                let next_y = surface.height as u64 * (row as u64 + 1) / rows as u64;
                out.push(UiViewport {
                    x: u32::try_from(x).map_err(|_| UiWorkspaceError::Invalid)?,
                    y: u32::try_from(y).map_err(|_| UiWorkspaceError::Invalid)?,
                    width: u32::try_from(next_x - x).map_err(|_| UiWorkspaceError::Invalid)?,
                    height: u32::try_from(next_y - y).map_err(|_| UiWorkspaceError::Invalid)?,
                });
            }
        }
    }
    Ok(out)
}

fn integer_sqrt(value: usize) -> usize {
    let mut root = 1usize;
    while (root + 1).saturating_mul(root + 1) <= value {
        root += 1;
    }
    root
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::{Decision, Effect, Operation, Reason, AUTHZ_FORMAT_VERSION};
    use crate::ui_service::UiCapability;

    const SURFACE: SurfaceSpec = SurfaceSpec {
        width: 800,
        height: 600,
        stride: 800,
        bytes_per_pixel: 4,
        layout: crate::display_input::PixelLayout::Rgba,
    };

    fn scope() -> UiPolicyScope {
        UiPolicyScope {
            user: 1,
            tenant: 1,
            session: 1,
            display_seat: 1,
            input_seat: 1,
        }
    }

    fn capabilities(multi_window: bool, split: bool) -> UiDeviceCapabilities {
        UiDeviceCapabilities {
            display: true,
            keyboard: true,
            pointer: false,
            touch: true,
            split_layouts: split,
            multi_window,
            background_grants: true,
        }
    }

    fn capability(epoch: u64, revocation: u32) -> UiCapability {
        let operation = Operation::ServiceUiFramePresent;
        UiCapability::from_decision(
            Decision {
                format_version: AUTHZ_FORMAT_VERSION,
                issuer: crate::authz::KERNEL_PEP_ISSUER,
                subject: 1,
                executor_object: 1,
                executor_generation: 1,
                tenant: 1,
                domain: 1,
                operation,
                scope: AccessScope::User(1),
                effect: Effect::Write,
                policy_epoch: epoch,
                revocation_generation: Some(revocation),
                allowed: true,
                reason: Reason::Allowed,
            },
            operation,
        )
        .unwrap()
    }

    fn event(epoch: u64) -> UiCapabilityEvent {
        UiCapabilityEvent {
            capability_epoch: epoch + 10,
            policy_epoch: epoch,
            revocation_epoch: u64::from(epoch as u32),
            capabilities: capabilities(true, true),
            surface: SURFACE,
            dpi_x: 320,
            dpi_y: 320,
        }
    }

    #[test]
    fn split_and_multi_layouts_cover_the_surface_without_overlap() {
        let mut workspace = UiWorkspace::<4>::new(
            1,
            scope(),
            capabilities(false, true),
            SURFACE,
            320,
            320,
            &[1, 1],
        )
        .unwrap();
        assert_eq!(
            workspace.reconfigure(
                event(2),
                InteractionProfile::Split,
                600,
                u64::MAX,
                capability(2, 2)
            ),
            Ok(UiLayoutMode::Split)
        );
        let first = workspace.viewport(0, 1).unwrap();
        let second = workspace.viewport(1, 1).unwrap();
        assert_eq!(first.width + second.width, SURFACE.width);
        assert_eq!(second.x, first.width);
        assert_eq!(first.height, SURFACE.height);
        assert_eq!(second.height, SURFACE.height);
    }

    #[test]
    fn migration_rotates_frame_and_input_generations_atomically() {
        let mut workspace = UiWorkspace::<2>::new(
            1,
            scope(),
            capabilities(false, true),
            SURFACE,
            320,
            320,
            &[1, 1],
        )
        .unwrap();
        workspace.frame(0, 1, 1, 1).unwrap();
        workspace.input(0, 1, 1, 1).unwrap();
        workspace
            .reconfigure(
                event(2),
                InteractionProfile::Split,
                500,
                u64::MAX,
                capability(2, 2),
            )
            .unwrap();
        assert_eq!(
            workspace.frame(0, 1, 1, 2),
            Err(UiWorkspaceError::StaleSurface)
        );
        assert_eq!(
            workspace.input(0, 1, 1, 2),
            Err(UiWorkspaceError::StaleInput)
        );
        assert!(workspace.frame(0, 1, 2, 2).is_ok());
        assert!(workspace.input(0, 1, 2, 2).is_ok());
    }

    #[test]
    fn budget_or_authorization_failure_leaves_old_binding_unchanged() {
        let mut workspace = UiWorkspace::<2>::new(
            1,
            scope(),
            capabilities(false, true),
            SURFACE,
            320,
            320,
            &[1, 1],
        )
        .unwrap();
        assert_eq!(
            workspace.reconfigure(
                event(2),
                InteractionProfile::Split,
                500,
                1,
                capability(2, 2)
            ),
            Err(UiWorkspaceError::Budget)
        );
        assert_eq!(workspace.surface(), SURFACE);
        assert_eq!(
            workspace.frame(0, 1, 1, 1),
            Ok(UiViewport {
                x: 0,
                y: 0,
                width: SURFACE.width / 2,
                height: SURFACE.height,
            })
        );
        assert_eq!(
            workspace.reconfigure(
                event(2),
                InteractionProfile::Split,
                500,
                u64::MAX,
                capability(9, 9)
            ),
            Err(UiWorkspaceError::Authorization)
        );
    }

    #[test]
    fn capability_degradation_is_explicit_and_stale_events_are_rejected() {
        let mut workspace = UiWorkspace::<2>::new(
            1,
            scope(),
            capabilities(false, true),
            SURFACE,
            320,
            320,
            &[1, 1],
        )
        .unwrap();
        let mut degraded = event(2);
        degraded.capabilities.multi_window = false;
        assert_eq!(
            workspace.reconfigure(
                degraded,
                InteractionProfile::MultiWindow,
                500,
                u64::MAX,
                capability(2, 2)
            ),
            Ok(UiLayoutMode::Split)
        );
        assert_eq!(
            workspace.reconfigure(
                event(2),
                InteractionProfile::Split,
                500,
                u64::MAX,
                capability(2, 2)
            ),
            Err(UiWorkspaceError::StaleCapability)
        );
    }
}
