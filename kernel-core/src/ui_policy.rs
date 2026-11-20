//! Versioned UI capability, interaction-profile and Scene lifecycle contract.
//!
//! This module carries facts and validates state transitions. It does not own
//! authorization, display sessions, input routing, rendering or window policy.

use crate::display_input::{PixelLayout, SurfaceSpec};

pub const UI_POLICY_SCHEMA_VERSION: u16 = 1;
pub const UI_POLICY_SNAPSHOT_BYTES: usize = 80;
const UI_POLICY_MAGIC: [u8; 4] = *b"JSUP";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UiDeviceCapabilities {
    pub display: bool,
    pub keyboard: bool,
    pub pointer: bool,
    pub touch: bool,
    pub split_layouts: bool,
    pub multi_window: bool,
    pub background_grants: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InteractionProfile {
    SinglePrimary = 1,
    Split = 2,
    MultiWindow = 3,
}

impl InteractionProfile {
    pub const fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::SinglePrimary),
            2 => Some(Self::Split),
            3 => Some(Self::MultiWindow),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileDecision {
    Selected(InteractionProfile),
    Degraded(InteractionProfile),
    Unsupported,
}

/// Select a profile from observed capabilities and a product preference.
/// No device name or model string participates in this decision.
pub fn select_interaction_profile(
    capabilities: UiDeviceCapabilities,
    requested: InteractionProfile,
) -> ProfileDecision {
    if !capabilities.display {
        return ProfileDecision::Unsupported;
    }
    match requested {
        InteractionProfile::MultiWindow if capabilities.multi_window => {
            ProfileDecision::Selected(requested)
        }
        InteractionProfile::MultiWindow if capabilities.split_layouts => {
            ProfileDecision::Degraded(InteractionProfile::Split)
        }
        InteractionProfile::MultiWindow => {
            ProfileDecision::Degraded(InteractionProfile::SinglePrimary)
        }
        InteractionProfile::Split
            if capabilities.split_layouts && (capabilities.pointer || capabilities.touch) =>
        {
            ProfileDecision::Selected(requested)
        }
        InteractionProfile::Split => ProfileDecision::Degraded(InteractionProfile::SinglePrimary),
        InteractionProfile::SinglePrimary => ProfileDecision::Selected(requested),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UiBackgroundPolicy {
    DenyOrdinary = 1,
    RequireGrant = 2,
}

impl UiBackgroundPolicy {
    pub const fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::DenyOrdinary),
            2 => Some(Self::RequireGrant),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UiPolicyScope {
    pub user: u32,
    pub tenant: u32,
    pub session: u64,
    pub display_seat: u32,
    pub input_seat: u32,
}

impl UiPolicyScope {
    pub const fn is_valid(self) -> bool {
        self.session != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UiPolicySnapshot {
    pub capability_epoch: u64,
    pub policy_epoch: u64,
    pub revocation_epoch: u64,
    pub scope: UiPolicyScope,
    pub capabilities: UiDeviceCapabilities,
    pub profile: InteractionProfile,
    pub background: UiBackgroundPolicy,
    pub surface: SurfaceSpec,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UiPolicyError {
    UnsupportedVersion,
    MalformedRecord,
    InvalidEpoch,
    InvalidScope,
    InvalidSurface,
    IncompatibleProfile,
    InvalidCapabilities,
    StaleCapabilityEpoch,
    StalePolicyEpoch,
    StaleRevocationEpoch,
    StaleSceneGeneration,
    StaleSurfaceGeneration,
    FocusConflict,
    InvisibleFocus,
    UnauthorizedBackground,
    AuthorizationDenied,
    AuthorizationEpoch,
    InvalidTransaction,
    Closed,
}

impl UiPolicyError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::UnsupportedVersion => "system.ui.policy.error.unsupported_version",
            Self::MalformedRecord => "system.ui.policy.error.malformed",
            Self::InvalidEpoch => "system.ui.policy.error.epoch",
            Self::InvalidScope => "system.ui.policy.error.scope",
            Self::InvalidSurface => "system.ui.policy.error.surface",
            Self::IncompatibleProfile => "system.ui.policy.error.profile",
            Self::InvalidCapabilities => "system.ui.policy.error.capabilities",
            Self::StaleCapabilityEpoch => "system.ui.policy.error.stale_capability",
            Self::StalePolicyEpoch => "system.ui.policy.error.stale_policy",
            Self::StaleRevocationEpoch => "system.ui.policy.error.stale_revocation",
            Self::StaleSceneGeneration => "system.ui.policy.error.stale_scene",
            Self::StaleSurfaceGeneration => "system.ui.policy.error.stale_surface",
            Self::FocusConflict => "system.ui.policy.error.focus_conflict",
            Self::InvisibleFocus => "system.ui.policy.error.invisible_focus",
            Self::UnauthorizedBackground => "system.ui.policy.error.background",
            Self::AuthorizationDenied => "system.ui.policy.error.authorization_denied",
            Self::AuthorizationEpoch => "system.ui.policy.error.authorization_epoch",
            Self::InvalidTransaction => "system.ui.policy.error.transaction",
            Self::Closed => "system.ui.policy.error.closed",
        }
    }
}

impl UiPolicySnapshot {
    pub fn new(
        capability_epoch: u64,
        policy_epoch: u64,
        revocation_epoch: u64,
        scope: UiPolicyScope,
        capabilities: UiDeviceCapabilities,
        profile: InteractionProfile,
        background: UiBackgroundPolicy,
        surface: SurfaceSpec,
    ) -> Result<Self, UiPolicyError> {
        if capability_epoch == 0 || policy_epoch == 0 {
            return Err(UiPolicyError::InvalidEpoch);
        }
        if !scope.is_valid() {
            return Err(UiPolicyError::InvalidScope);
        }
        surface
            .validate()
            .map_err(|_| UiPolicyError::InvalidSurface)?;
        if !capabilities.display
            || (profile != InteractionProfile::SinglePrimary
                && !capabilities.split_layouts
                && !capabilities.multi_window)
            || (profile == InteractionProfile::Split
                && (!capabilities.split_layouts || (!capabilities.pointer && !capabilities.touch)))
            || (profile == InteractionProfile::MultiWindow && !capabilities.multi_window)
        {
            return Err(UiPolicyError::IncompatibleProfile);
        }
        if background == UiBackgroundPolicy::RequireGrant && !capabilities.background_grants {
            return Err(UiPolicyError::InvalidCapabilities);
        }
        Ok(Self {
            capability_epoch,
            policy_epoch,
            revocation_epoch,
            scope,
            capabilities,
            profile,
            background,
            surface,
        })
    }

    pub fn encode(self, output: &mut [u8]) -> Result<usize, UiPolicyError> {
        if output.len() < UI_POLICY_SNAPSHOT_BYTES {
            return Err(UiPolicyError::MalformedRecord);
        }
        output[..UI_POLICY_SNAPSHOT_BYTES].fill(0);
        output[..4].copy_from_slice(&UI_POLICY_MAGIC);
        put_u16(output, 4, UI_POLICY_SCHEMA_VERSION);
        put_u16(output, 6, UI_POLICY_SNAPSHOT_BYTES as u16);
        put_u64(output, 8, self.capability_epoch);
        put_u64(output, 16, self.policy_epoch);
        put_u64(output, 24, self.revocation_epoch);
        put_u32(output, 32, self.scope.user);
        put_u32(output, 36, self.scope.tenant);
        put_u64(output, 40, self.scope.session);
        put_u32(output, 48, self.scope.display_seat);
        put_u32(output, 52, self.scope.input_seat);
        output[56] = self.profile as u8;
        output[57] = self.background as u8;
        put_u16(output, 58, capability_bits(self.capabilities));
        put_u32(output, 60, self.surface.width);
        put_u32(output, 64, self.surface.height);
        put_u32(output, 68, self.surface.stride);
        output[72] = self.surface.bytes_per_pixel;
        output[73] = pixel_layout_raw(self.surface.layout);
        Ok(UI_POLICY_SNAPSHOT_BYTES)
    }

    pub fn decode(input: &[u8]) -> Result<Self, UiPolicyError> {
        if input.len() != UI_POLICY_SNAPSHOT_BYTES {
            return Err(UiPolicyError::MalformedRecord);
        }
        if input[..4] != UI_POLICY_MAGIC || get_u16(input, 6) as usize != input.len() {
            return Err(UiPolicyError::MalformedRecord);
        }
        if get_u16(input, 4) != UI_POLICY_SCHEMA_VERSION {
            return Err(UiPolicyError::UnsupportedVersion);
        }
        if input[74..].iter().any(|byte| *byte != 0) {
            return Err(UiPolicyError::MalformedRecord);
        }
        let profile =
            InteractionProfile::from_raw(input[56]).ok_or(UiPolicyError::IncompatibleProfile)?;
        let background =
            UiBackgroundPolicy::from_raw(input[57]).ok_or(UiPolicyError::InvalidCapabilities)?;
        let capabilities =
            capability_from_bits(get_u16(input, 58)).ok_or(UiPolicyError::InvalidCapabilities)?;
        let layout = pixel_layout_from_raw(input[73]).ok_or(UiPolicyError::InvalidSurface)?;
        Self::new(
            get_u64(input, 8),
            get_u64(input, 16),
            get_u64(input, 24),
            UiPolicyScope {
                user: get_u32(input, 32),
                tenant: get_u32(input, 36),
                session: get_u64(input, 40),
                display_seat: get_u32(input, 48),
                input_seat: get_u32(input, 52),
            },
            capabilities,
            profile,
            background,
            SurfaceSpec {
                width: get_u32(input, 60),
                height: get_u32(input, 64),
                stride: get_u32(input, 68),
                bytes_per_pixel: input[72],
                layout,
            },
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UiSceneKey {
    pub slot: u16,
    pub generation: u32,
}

impl UiSceneKey {
    pub const fn is_valid(self) -> bool {
        self.generation != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UiSceneFacts {
    pub visible: bool,
    pub focused: bool,
    pub rendering: bool,
    pub background_grant: bool,
}

impl UiSceneFacts {
    fn validate(self, policy: UiPolicySnapshot) -> Result<(), UiPolicyError> {
        if self.focused && !self.visible {
            return Err(UiPolicyError::InvisibleFocus);
        }
        if self.background_grant
            && policy.background == UiBackgroundPolicy::DenyOrdinary
        {
            return Err(UiPolicyError::UnauthorizedBackground);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UiSceneState {
    pub key: UiSceneKey,
    pub scope: UiPolicyScope,
    pub surface: SurfaceSpec,
    pub surface_generation: u64,
    pub input_generation: u64,
    pub capability_epoch: u64,
    pub policy_epoch: u64,
    pub revocation_epoch: u64,
    pub facts: UiSceneFacts,
}

impl UiSceneState {
    pub fn new(
        key: UiSceneKey,
        surface_generation: u64,
        facts: UiSceneFacts,
        policy: UiPolicySnapshot,
    ) -> Result<Self, UiPolicyError> {
        if !key.is_valid() || surface_generation == 0 {
            return Err(UiPolicyError::StaleSceneGeneration);
        }
        policy
            .surface
            .validate()
            .map_err(|_| UiPolicyError::InvalidSurface)?;
        facts.validate(policy)?;
        Ok(Self {
            key,
            scope: policy.scope,
            surface: policy.surface,
            surface_generation,
            input_generation: 1,
            capability_epoch: policy.capability_epoch,
            policy_epoch: policy.policy_epoch,
            revocation_epoch: policy.revocation_epoch,
            facts,
        })
    }

    pub fn update_facts(
        mut self,
        facts: UiSceneFacts,
        policy: UiPolicySnapshot,
        currently_focused: Option<UiSceneKey>,
    ) -> Result<Self, UiPolicyError> {
        self.check_policy(policy)?;
        if self.scope != policy.scope {
            return Err(UiPolicyError::InvalidScope);
        }
        if facts.focused
            && currently_focused.is_some_and(|focused| focused != self.key)
        {
            return Err(UiPolicyError::FocusConflict);
        }
        facts.validate(policy)?;
        self.facts = facts;
        Ok(self)
    }

    fn check_policy(&self, policy: UiPolicySnapshot) -> Result<(), UiPolicyError> {
        if self.capability_epoch != policy.capability_epoch {
            return Err(UiPolicyError::StaleCapabilityEpoch);
        }
        if self.policy_epoch != policy.policy_epoch {
            return Err(UiPolicyError::StalePolicyEpoch);
        }
        if self.revocation_epoch != policy.revocation_epoch {
            return Err(UiPolicyError::StaleRevocationEpoch);
        }
        Ok(())
    }
}

/// Receipt supplied by the one unified PEP/authorization path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UiPolicyAuthorization {
    pub decision_id: u64,
    pub policy_epoch: u64,
    pub allowed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SurfaceMigration {
    transaction_id: u64,
    scene_key: UiSceneKey,
    scope: UiPolicyScope,
    expected_scene_generation: u32,
    from_surface_generation: u64,
    target_surface_generation: u64,
    target_input_generation: u64,
    new_surface: SurfaceSpec,
    capability_epoch: u64,
    policy_epoch: u64,
    revocation_epoch: u64,
    facts: UiSceneFacts,
}

impl SurfaceMigration {
    pub fn begin(
        transaction_id: u64,
        scene: UiSceneState,
        policy: UiPolicySnapshot,
        new_surface: SurfaceSpec,
        target_surface_generation: u64,
    ) -> Result<Self, UiPolicyError> {
        if transaction_id == 0 {
            return Err(UiPolicyError::InvalidTransaction);
        }
        scene.check_policy(policy)?;
        if scene.scope != policy.scope {
            return Err(UiPolicyError::InvalidScope);
        }
        new_surface
            .validate()
            .map_err(|_| UiPolicyError::InvalidSurface)?;
        if target_surface_generation <= scene.surface_generation {
            return Err(UiPolicyError::StaleSurfaceGeneration);
        }
        let expected_scene_generation = scene
            .key
            .generation
            .checked_add(1)
            .ok_or(UiPolicyError::StaleSceneGeneration)?;
        let target_input_generation = scene
            .input_generation
            .checked_add(1)
            .ok_or(UiPolicyError::StaleSceneGeneration)?;
        Ok(Self {
            transaction_id,
            scene_key: scene.key,
            scope: scene.scope,
            expected_scene_generation,
            from_surface_generation: scene.surface_generation,
            target_surface_generation,
            target_input_generation,
            new_surface,
            capability_epoch: policy.capability_epoch,
            policy_epoch: policy.policy_epoch,
            revocation_epoch: policy.revocation_epoch,
            facts: scene.facts,
        })
    }

    pub fn commit(
        self,
        scene: UiSceneState,
        policy: UiPolicySnapshot,
        authorization: UiPolicyAuthorization,
    ) -> Result<UiSceneState, UiPolicyError> {
        if !authorization.allowed {
            return Err(UiPolicyError::AuthorizationDenied);
        }
        if authorization.decision_id == 0 || authorization.policy_epoch != policy.policy_epoch {
            return Err(UiPolicyError::AuthorizationEpoch);
        }
        if scene.key != self.scene_key
            || scene.key.generation != self.expected_scene_generation.saturating_sub(1)
            || scene.surface_generation != self.from_surface_generation
        {
            return Err(UiPolicyError::StaleSceneGeneration);
        }
        if scene.scope != self.scope || policy.scope != self.scope {
            return Err(UiPolicyError::InvalidScope);
        }
        if scene.capability_epoch != self.capability_epoch
            || policy.capability_epoch != self.capability_epoch
        {
            return Err(UiPolicyError::StaleCapabilityEpoch);
        }
        if scene.policy_epoch != self.policy_epoch || policy.policy_epoch != self.policy_epoch {
            return Err(UiPolicyError::StalePolicyEpoch);
        }
        if scene.revocation_epoch != self.revocation_epoch
            || policy.revocation_epoch != self.revocation_epoch
        {
            return Err(UiPolicyError::StaleRevocationEpoch);
        }
        Ok(UiSceneState {
            key: UiSceneKey {
                slot: self.scene_key.slot,
                generation: self.expected_scene_generation,
            },
            scope: self.scope,
            surface: self.new_surface,
            surface_generation: self.target_surface_generation,
            input_generation: self.target_input_generation,
            capability_epoch: self.capability_epoch,
            policy_epoch: self.policy_epoch,
            revocation_epoch: self.revocation_epoch,
            facts: self.facts,
        })
    }

    pub fn rollback(self) -> MigrationRollback {
        MigrationRollback {
            transaction_id: self.transaction_id,
            scene_key: self.scene_key,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MigrationRollback {
    pub transaction_id: u64,
    pub scene_key: UiSceneKey,
}

fn capability_bits(capabilities: UiDeviceCapabilities) -> u16 {
    u16::from(capabilities.display)
        | (u16::from(capabilities.keyboard) << 1)
        | (u16::from(capabilities.pointer) << 2)
        | (u16::from(capabilities.touch) << 3)
        | (u16::from(capabilities.split_layouts) << 4)
        | (u16::from(capabilities.multi_window) << 5)
        | (u16::from(capabilities.background_grants) << 6)
}

fn capability_from_bits(bits: u16) -> Option<UiDeviceCapabilities> {
    if bits & !0x7f != 0 {
        return None;
    }
    Some(UiDeviceCapabilities {
        display: bits & 1 != 0,
        keyboard: bits & 2 != 0,
        pointer: bits & 4 != 0,
        touch: bits & 8 != 0,
        split_layouts: bits & 16 != 0,
        multi_window: bits & 32 != 0,
        background_grants: bits & 64 != 0,
    })
}

fn pixel_layout_raw(layout: PixelLayout) -> u8 {
    match layout {
        PixelLayout::Rgb => 1,
        PixelLayout::Bgr => 2,
        PixelLayout::Rgba => 3,
        PixelLayout::Gray => 4,
    }
}

fn pixel_layout_from_raw(raw: u8) -> Option<PixelLayout> {
    match raw {
        1 => Some(PixelLayout::Rgb),
        2 => Some(PixelLayout::Bgr),
        3 => Some(PixelLayout::Rgba),
        4 => Some(PixelLayout::Gray),
        _ => None,
    }
}

fn put_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn get_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(input[offset..offset + 2].try_into().expect("checked record width"))
}

fn get_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(input[offset..offset + 4].try_into().expect("checked record width"))
}

fn get_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(input[offset..offset + 8].try_into().expect("checked record width"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SURFACE: SurfaceSpec = SurfaceSpec {
        width: 1280,
        height: 800,
        stride: 1280,
        bytes_per_pixel: 4,
        layout: PixelLayout::Rgba,
    };

    fn capabilities() -> UiDeviceCapabilities {
        UiDeviceCapabilities {
            display: true,
            keyboard: true,
            pointer: true,
            touch: true,
            split_layouts: true,
            multi_window: false,
            background_grants: true,
        }
    }

    fn policy() -> UiPolicySnapshot {
        UiPolicySnapshot::new(
            7,
            11,
            13,
            UiPolicyScope {
                user: 4,
                tenant: 2,
                session: 9,
                display_seat: 1,
                input_seat: 3,
            },
            capabilities(),
            InteractionProfile::Split,
            UiBackgroundPolicy::RequireGrant,
            SURFACE,
        )
        .unwrap()
    }

    fn scene() -> UiSceneState {
        UiSceneState::new(
            UiSceneKey {
                slot: 1,
                generation: 5,
            },
            8,
            UiSceneFacts {
                visible: true,
                focused: true,
                rendering: true,
                background_grant: false,
            },
            policy(),
        )
        .unwrap()
    }

    #[test]
    fn profile_selection_uses_capabilities_not_device_names() {
        assert_eq!(
            select_interaction_profile(capabilities(), InteractionProfile::MultiWindow),
            ProfileDecision::Degraded(InteractionProfile::Split)
        );
        assert_eq!(
            select_interaction_profile(
                UiDeviceCapabilities {
                    display: false,
                    keyboard: false,
                    pointer: false,
                    touch: false,
                    split_layouts: false,
                    multi_window: false,
                    background_grants: false,
                },
                InteractionProfile::SinglePrimary,
            ),
            ProfileDecision::Unsupported
        );
    }

    #[test]
    fn snapshot_roundtrips_and_rejects_decode_negatives() {
        let policy = policy();
        let mut bytes = [0u8; UI_POLICY_SNAPSHOT_BYTES];
        assert_eq!(policy.encode(&mut bytes), Ok(UI_POLICY_SNAPSHOT_BYTES));
        assert_eq!(UiPolicySnapshot::decode(&bytes), Ok(policy));

        let mut wrong_version = bytes;
        put_u16(&mut wrong_version, 4, 2);
        assert_eq!(
            UiPolicySnapshot::decode(&wrong_version),
            Err(UiPolicyError::UnsupportedVersion)
        );
        let mut reserved = bytes;
        reserved[79] = 1;
        assert_eq!(
            UiPolicySnapshot::decode(&reserved),
            Err(UiPolicyError::MalformedRecord)
        );
        assert_eq!(
            UiPolicySnapshot::decode(&bytes[..79]),
            Err(UiPolicyError::MalformedRecord)
        );
    }

    #[test]
    fn scene_focus_and_background_facts_remain_independent_but_fail_closed() {
        let policy = policy();
        assert_eq!(
            UiSceneState::new(
                UiSceneKey {
                    slot: 1,
                    generation: 1,
                },
                1,
                UiSceneFacts {
                    visible: false,
                    focused: true,
                    rendering: false,
                    background_grant: false,
                },
                policy,
            )
            .unwrap_err(),
            UiPolicyError::InvisibleFocus
        );
        assert_eq!(
            scene()
                .update_facts(
                    UiSceneFacts {
                        visible: false,
                        focused: false,
                        rendering: true,
                        background_grant: false,
                    },
                    policy,
                    None,
                )
                .unwrap()
                .facts
                .rendering,
            true
        );
        assert_eq!(
            scene()
                .update_facts(
                    scene().facts,
                    policy,
                    Some(UiSceneKey {
                        slot: 2,
                        generation: 1,
                    }),
                )
                .unwrap_err(),
            UiPolicyError::FocusConflict
        );
    }

    #[test]
    fn surface_migration_is_generation_safe_and_epoch_bound() {
        let policy = policy();
        let scene = scene();
        let new_surface = SurfaceSpec {
            width: 1920,
            stride: 1920,
            ..SURFACE
        };
        let migration = SurfaceMigration::begin(41, scene, policy, new_surface, 9).unwrap();
        let auth = UiPolicyAuthorization {
            decision_id: 88,
            policy_epoch: policy.policy_epoch,
            allowed: true,
        };
        let committed = migration.commit(scene, policy, auth).unwrap();
        assert_eq!(committed.key.generation, 6);
        assert_eq!(committed.surface_generation, 9);
        assert_eq!(committed.input_generation, 2);
        assert_eq!(committed.surface.width, 1920);

        let migration = SurfaceMigration::begin(42, scene, policy, new_surface, 9).unwrap();
        assert_eq!(
            migration
                .commit(
                    committed,
                    policy,
                    UiPolicyAuthorization {
                        decision_id: 89,
                        policy_epoch: policy.policy_epoch,
                        allowed: true,
                    },
                )
                .unwrap_err(),
            UiPolicyError::StaleSceneGeneration
        );
        assert_eq!(
            SurfaceMigration::begin(43, scene, policy, new_surface, 8).unwrap_err(),
            UiPolicyError::StaleSurfaceGeneration
        );
        let rolled_back = SurfaceMigration::begin(44, scene, policy, new_surface, 9)
            .unwrap()
            .rollback();
        assert_eq!(rolled_back.transaction_id, 44);
        assert_eq!(rolled_back.scene_key, scene.key);
    }

    #[test]
    fn migration_rejects_stale_revocation_and_authorization_epochs() {
        let policy = policy();
        let scene = scene();
        let new_surface = SurfaceSpec {
            width: 1024,
            ..SURFACE
        };
        let migration = SurfaceMigration::begin(51, scene, policy, new_surface, 9).unwrap();
        let mut changed = policy;
        changed.revocation_epoch += 1;
        assert_eq!(
            migration
                .commit(
                    scene,
                    changed,
                    UiPolicyAuthorization {
                        decision_id: 90,
                        policy_epoch: changed.policy_epoch,
                        allowed: true,
                    },
                )
                .unwrap_err(),
            UiPolicyError::StaleRevocationEpoch
        );
        let migration = SurfaceMigration::begin(52, scene, policy, new_surface, 9).unwrap();
        assert_eq!(
            migration
                .commit(
                    scene,
                    policy,
                    UiPolicyAuthorization {
                        decision_id: 91,
                        policy_epoch: policy.policy_epoch + 1,
                        allowed: true,
                    },
                )
                .unwrap_err(),
            UiPolicyError::AuthorizationEpoch
        );

        let migration = SurfaceMigration::begin(53, scene, policy, new_surface, 9).unwrap();
        let mut changed_scope = policy;
        changed_scope.scope.session += 1;
        assert_eq!(
            migration
                .commit(
                    scene,
                    changed_scope,
                    UiPolicyAuthorization {
                        decision_id: 92,
                        policy_epoch: changed_scope.policy_epoch,
                        allowed: true,
                    },
                )
                .unwrap_err(),
            UiPolicyError::InvalidScope
        );
    }
}
