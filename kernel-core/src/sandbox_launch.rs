//! Bounded Sandbox launch-plan composition.
//!
//! A launch plan references authoritative Workload, Sandbox, image, volume,
//! network and device objects. It never derives authority from a logical path.
//! Path-shaped mount views are produced on demand for presentation only.
//!
//! 有界 Sandbox 启动计划。计划只引用权威 Workload、Sandbox、镜像、卷、网络和
//! 设备对象，不把逻辑路径当授权依据；挂载路径只按需派生用于展示。

use crate::sandbox::{SandboxError, SandboxKey, SandboxTable};
use crate::sandbox_image::{
    ContentDigest, ImageKey, SandboxStorageError, SandboxStorageTable, VolumeKey,
};
use crate::security_domain::DomainKey;
use crate::workload::{
    IoRateLimits, ResourceLimits, WorkloadError, WorkloadKey, WorkloadState, WorkloadTable,
};

pub const MAX_DEVICE_GRANTS: usize = 16;
pub const MAX_DATA_SCOPES: usize = 16;
pub const MAX_VIEW_PATH: usize = 64;

/// A compact capability set. Capabilities are explicit identifiers, never
/// paths, AppIDs, UIDs or installation sources.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CapabilitySet(u64);

impl CapabilitySet {
    pub const NONE: Self = Self(0);
    pub const EXECUTE: Self = Self(1 << 0);
    pub const NETWORK: Self = Self(1 << 1);
    pub const DEVICE: Self = Self(1 << 2);
    pub const DATA_READ: Self = Self(1 << 3);
    pub const DATA_WRITE: Self = Self(1 << 4);
    pub const ALL: Self = Self((1 << 5) - 1);

    pub const fn new(raw: u64) -> Option<Self> {
        if raw & !Self::ALL.0 == 0 {
            Some(Self(raw))
        } else {
            None
        }
    }

    pub const fn raw(self) -> u64 {
        self.0
    }

    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn attenuates(self, parent: Self) -> bool {
        self.0 & !parent.0 == 0
    }
}

/// Opaque NET policy identity. NET remains the sole network-policy authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkPolicyRef {
    pub policy: u64,
    pub generation: u32,
}

impl NetworkPolicyRef {
    const fn is_valid(self) -> bool {
        self.policy != 0 && self.generation != 0
    }
}

/// One device or accelerator grant, already issued by the device authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceGrant {
    pub object: u64,
    pub generation: u32,
    pub rights: u32,
    pub owner: DomainKey,
    pub grantee: DomainKey,
}

/// One read-only or writable data scope. Data owner and runtime principal are
/// distinct facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataScopeGrant {
    pub object: u64,
    pub generation: u32,
    pub owner: DomainKey,
    pub grantee: DomainKey,
    pub writable: bool,
}

/// Requested launch resources. They must attenuate the root Workload limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaunchResources {
    pub limits: ResourceLimits,
    pub io_rate: Option<IoRateLimits>,
}

/// All borrowed inputs needed to create one immutable launch plan.
#[derive(Clone, Copy)]
pub struct LaunchSpec<'a> {
    pub sandbox: SandboxKey,
    pub root: WorkloadKey,
    pub image: ImageKey,
    pub volume: Option<VolumeKey>,
    pub root_capabilities: CapabilitySet,
    pub capabilities: CapabilitySet,
    pub resources: LaunchResources,
    pub network_policy: Option<NetworkPolicyRef>,
    pub devices: &'a [DeviceGrant],
    pub data: &'a [DataScopeGrant],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaunchPlanKey {
    slot: u16,
    generation: u32,
}

impl LaunchPlanKey {
    pub const fn to_raw(self) -> u64 {
        ((self.generation as u64) << 16) | self.slot as u64
    }

    pub const fn from_raw(raw: u64) -> Option<Self> {
        if raw == 0 || raw >> 48 != 0 || (raw >> 16) as u32 == 0 {
            return None;
        }
        Some(Self {
            slot: raw as u16,
            generation: (raw >> 16) as u32,
        })
    }
}

/// Immutable, bounded facts admitted for one Sandbox start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaunchPlanSnapshot {
    pub key: LaunchPlanKey,
    pub sandbox: SandboxKey,
    pub root: WorkloadKey,
    pub image: ImageKey,
    pub image_content: ContentDigest,
    pub volume: Option<VolumeKey>,
    pub capabilities: CapabilitySet,
    pub resources: LaunchResources,
    pub network_policy: Option<NetworkPolicyRef>,
    pub devices: u16,
    pub data_scopes: u16,
    pub data_writable_mask: u16,
}

#[derive(Clone, Copy)]
struct Record {
    key: LaunchPlanKey,
    domain: DomainKey,
    plan: LaunchPlanSnapshot,
    devices: [Option<DeviceGrant>; MAX_DEVICE_GRANTS],
    data: [Option<DataScopeGrant>; MAX_DATA_SCOPES],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaunchError {
    InvalidDomain,
    InvalidSandbox,
    InvalidRoot,
    NotRunning,
    Ownership,
    InvalidLimit,
    Capability,
    InvalidNetwork,
    InvalidDevice,
    InvalidData,
    DuplicateGrant,
    Capacity,
    IdExhausted,
    InvalidView,
    Sandbox(SandboxError),
    Workload(WorkloadError),
    Storage(SandboxStorageError),
}

impl LaunchError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidDomain => "system.sandbox.launch.error.domain",
            Self::InvalidSandbox => "system.sandbox.launch.error.sandbox",
            Self::InvalidRoot => "system.sandbox.launch.error.root",
            Self::NotRunning => "system.sandbox.launch.error.not_running",
            Self::Ownership => "system.sandbox.launch.error.ownership",
            Self::InvalidLimit => "system.sandbox.launch.error.limit",
            Self::Capability => "system.sandbox.launch.error.capability",
            Self::InvalidNetwork => "system.sandbox.launch.error.network",
            Self::InvalidDevice => "system.sandbox.launch.error.device",
            Self::InvalidData => "system.sandbox.launch.error.data",
            Self::DuplicateGrant => "system.sandbox.launch.error.duplicate",
            Self::Capacity => "system.sandbox.launch.error.capacity",
            Self::IdExhausted => "system.sandbox.launch.error.ids_exhausted",
            Self::InvalidView => "system.sandbox.launch.error.view",
            Self::Sandbox(error) => error.name(),
            Self::Workload(error) => error.name(),
            Self::Storage(error) => error.name(),
        }
    }
}

impl From<SandboxError> for LaunchError {
    fn from(error: SandboxError) -> Self {
        Self::Sandbox(error)
    }
}

impl From<WorkloadError> for LaunchError {
    fn from(error: WorkloadError) -> Self {
        Self::Workload(error)
    }
}

impl From<SandboxStorageError> for LaunchError {
    fn from(error: SandboxStorageError) -> Self {
        Self::Storage(error)
    }
}

/// Fixed-capacity launch-plan table. Admission validates every referenced
/// fact before writing the first plan byte.
pub struct SandboxLaunchTable<const N: usize> {
    slots: [Option<Record>; N],
    generations: [u32; N],
}

impl<const N: usize> SandboxLaunchTable<N> {
    pub const fn new() -> Self {
        Self {
            slots: [None; N],
            generations: [0; N],
        }
    }

    pub fn create<
        const W: usize,
        const S: usize,
        const I: usize,
        const L: usize,
        const V: usize,
    >(
        &mut self,
        domain: DomainKey,
        workloads: &WorkloadTable<W>,
        sandboxes: &SandboxTable<S>,
        storage: &SandboxStorageTable<I, L, V>,
        spec: LaunchSpec<'_>,
    ) -> Result<LaunchPlanKey, LaunchError> {
        if !domain.is_valid() {
            return Err(LaunchError::InvalidDomain);
        }
        let sandbox = sandboxes.snapshot_in_domain(workloads, domain, spec.sandbox)?;
        if sandbox.root != spec.root {
            return Err(LaunchError::InvalidRoot);
        }
        let workload = workloads.snapshot(spec.root)?;
        if workload.domain != domain
            || workload.parent.is_some()
            || workload.state != WorkloadState::Running
            || sandbox.state != WorkloadState::Running
        {
            return Err(LaunchError::NotRunning);
        }
        spec.resources
            .limits
            .validate()
            .map_err(|_| LaunchError::InvalidLimit)?;
        if !attenuates_limits(spec.resources.limits, workload.limits) {
            return Err(LaunchError::InvalidLimit);
        }
        let image = storage.image(domain, spec.sandbox, spec.image)?;
        if let Some(volume) = spec.volume {
            let volume = storage.volume(domain, spec.sandbox, volume)?;
            if volume.image != spec.image {
                return Err(LaunchError::Ownership);
            }
        }
        if !spec.capabilities.attenuates(spec.root_capabilities) {
            return Err(LaunchError::Capability);
        }
        if !spec.capabilities.contains(CapabilitySet::EXECUTE)
            || (spec.volume.is_some() && !spec.capabilities.contains(CapabilitySet::DATA_WRITE))
        {
            return Err(LaunchError::Capability);
        }
        validate_rate(
            workloads.io_rate_snapshot(spec.root)?,
            spec.resources.io_rate,
        )?;
        if spec.capabilities.contains(CapabilitySet::NETWORK) != spec.network_policy.is_some()
            || spec.network_policy.is_some_and(|policy| !policy.is_valid())
        {
            return Err(LaunchError::InvalidNetwork);
        }
        validate_devices(domain, spec.capabilities, spec.devices)?;
        validate_data(domain, spec.capabilities, spec.data)?;
        let (slot, generation) = self.vacant()?;
        let key = LaunchPlanKey {
            slot: slot as u16,
            generation,
        };
        let mut devices = [None; MAX_DEVICE_GRANTS];
        let mut data = [None; MAX_DATA_SCOPES];
        for (target, source) in devices.iter_mut().zip(spec.devices.iter().copied()) {
            *target = Some(source);
        }
        for (target, source) in data.iter_mut().zip(spec.data.iter().copied()) {
            *target = Some(source);
        }
        let plan = LaunchPlanSnapshot {
            key,
            sandbox: spec.sandbox,
            root: spec.root,
            image: spec.image,
            image_content: image.image.content,
            volume: spec.volume,
            capabilities: spec.capabilities,
            resources: spec.resources,
            network_policy: spec.network_policy,
            devices: spec.devices.len() as u16,
            data_scopes: spec.data.len() as u16,
            data_writable_mask: spec
                .data
                .iter()
                .enumerate()
                .fold(0u16, |mask, (index, grant)| {
                    if grant.writable {
                        mask | (1u16 << index)
                    } else {
                        mask
                    }
                }),
        };
        self.generations[slot] = generation;
        self.slots[slot] = Some(Record {
            key,
            domain,
            plan,
            devices,
            data,
        });
        Ok(key)
    }

    pub fn plan(
        &self,
        domain: DomainKey,
        key: LaunchPlanKey,
    ) -> Result<LaunchPlanSnapshot, LaunchError> {
        self.record(domain, key).map(|record| record.plan)
    }

    pub fn count(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    pub fn device(
        &self,
        domain: DomainKey,
        key: LaunchPlanKey,
        index: u16,
    ) -> Result<DeviceGrant, LaunchError> {
        let record = self.record(domain, key)?;
        if index >= record.plan.devices {
            return Err(LaunchError::InvalidDevice);
        }
        record.devices[index as usize].ok_or(LaunchError::InvalidDevice)
    }

    pub fn data_scope(
        &self,
        domain: DomainKey,
        key: LaunchPlanKey,
        index: u16,
    ) -> Result<DataScopeGrant, LaunchError> {
        let record = self.record(domain, key)?;
        if index >= record.plan.data_scopes {
            return Err(LaunchError::InvalidData);
        }
        record.data[index as usize].ok_or(LaunchError::InvalidData)
    }

    pub fn destroy(&mut self, domain: DomainKey, key: LaunchPlanKey) -> Result<(), LaunchError> {
        let _ = self.record(domain, key)?;
        self.slots[key.slot as usize] = None;
        Ok(())
    }

    fn record(&self, domain: DomainKey, key: LaunchPlanKey) -> Result<Record, LaunchError> {
        self.slots
            .get(key.slot as usize)
            .and_then(|record| *record)
            .filter(|record| record.key == key && record.domain == domain)
            .ok_or(LaunchError::InvalidSandbox)
    }

    fn vacant(&self) -> Result<(usize, u32), LaunchError> {
        let slot = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(LaunchError::Capacity)?;
        if slot > u16::MAX as usize {
            return Err(LaunchError::Capacity);
        }
        let generation = self.generations[slot]
            .checked_add(1)
            .ok_or(LaunchError::IdExhausted)?;
        Ok((slot, generation))
    }
}

impl<const N: usize> Default for SandboxLaunchTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

fn attenuates_limits(child: ResourceLimits, parent: ResourceLimits) -> bool {
    child.cpu_permille <= parent.cpu_permille
        && child.memory_bytes <= parent.memory_bytes
        && child.threads <= parent.threads
        && child.ring_entries <= parent.ring_entries
        && child.io_bytes <= parent.io_bytes
        && child.io_ops <= parent.io_ops
}

fn validate_rate(
    parent: crate::workload::IoRateSnapshot,
    child: Option<IoRateLimits>,
) -> Result<(), LaunchError> {
    match (parent.limits, child) {
        (Some(parent), Some(child))
            if child.validate().is_ok()
                && child.bytes_per_window <= parent.bytes_per_window
                && child.ops_per_window <= parent.ops_per_window
                && child.window_ns >= parent.window_ns =>
        {
            Ok(())
        }
        (Some(_), _) => Err(LaunchError::InvalidLimit),
        (None, Some(child)) if child.validate().is_ok() => Ok(()),
        (None, None) => Ok(()),
        (None, Some(_)) => Err(LaunchError::InvalidLimit),
    }
}

fn validate_devices(
    domain: DomainKey,
    capabilities: CapabilitySet,
    grants: &[DeviceGrant],
) -> Result<(), LaunchError> {
    if grants.len() > MAX_DEVICE_GRANTS
        || (!grants.is_empty() && !capabilities.contains(CapabilitySet::DEVICE))
    {
        return Err(LaunchError::InvalidDevice);
    }
    for (index, grant) in grants.iter().copied().enumerate() {
        if grant.object == 0
            || grant.generation == 0
            || grant.rights == 0
            || !grant.owner.is_valid()
            || grant.grantee != domain
        {
            return Err(LaunchError::InvalidDevice);
        }
        if grants[..index]
            .iter()
            .any(|existing| existing.object == grant.object)
        {
            return Err(LaunchError::DuplicateGrant);
        }
    }
    Ok(())
}

fn validate_data(
    domain: DomainKey,
    capabilities: CapabilitySet,
    grants: &[DataScopeGrant],
) -> Result<(), LaunchError> {
    if grants.len() > MAX_DATA_SCOPES {
        return Err(LaunchError::InvalidData);
    }
    for (index, grant) in grants.iter().copied().enumerate() {
        let required = if grant.writable {
            CapabilitySet::DATA_WRITE
        } else {
            CapabilitySet::DATA_READ
        };
        if grant.object == 0
            || grant.generation == 0
            || !grant.owner.is_valid()
            || grant.grantee != domain
            || !capabilities.contains(required)
        {
            return Err(LaunchError::InvalidData);
        }
        if grants[..index]
            .iter()
            .any(|existing| existing.object == grant.object)
        {
            return Err(LaunchError::DuplicateGrant);
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViewSource {
    ImageRoot(ImageKey),
    WritableVolume(VolumeKey),
    Data { index: u16, writable: bool },
}

/// Presentation-only mount view. It has no method that grants access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogicalMountView {
    pub source: ViewSource,
    pub writable: bool,
    target: [u8; MAX_VIEW_PATH],
    target_len: u8,
}

impl LogicalMountView {
    pub fn target(&self) -> &[u8] {
        &self.target[..self.target_len as usize]
    }
}

/// Derive a bounded display path without mutating the launch plan or granting
/// any capability.
pub fn derive_mount_view(
    plan: LaunchPlanSnapshot,
    source: ViewSource,
    target: &[u8],
) -> Result<LogicalMountView, LaunchError> {
    if target.is_empty()
        || target.len() > MAX_VIEW_PATH
        || target[0] != b'/'
        || target.contains(&0)
        || target.split(|byte| *byte == b'/').any(|part| part == b"..")
    {
        return Err(LaunchError::InvalidView);
    }
    let writable = match source {
        ViewSource::ImageRoot(image) if image == plan.image => false,
        ViewSource::WritableVolume(volume) if plan.volume == Some(volume) => true,
        ViewSource::Data { index, writable }
            if index < plan.data_scopes
                && ((plan.data_writable_mask >> index) & 1 != 0) == writable =>
        {
            writable
        }
        _ => return Err(LaunchError::InvalidView),
    };
    let mut stored = [0u8; MAX_VIEW_PATH];
    stored[..target.len()].copy_from_slice(target);
    Ok(LogicalMountView {
        source,
        writable,
        target: stored,
        target_len: target.len() as u8,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::SandboxTable;
    use crate::sandbox_image::{
        ContentDigest, ImageLayerSpec, ImageSpec, ImageVersion, SignedImage,
    };
    use crate::workload::{ResourceLimits, WorkloadTable};

    const DOMAIN: DomainKey = DomainKey {
        id: 41,
        generation: 3,
    };
    const OTHER_DOMAIN: DomainKey = DomainKey {
        id: 77,
        generation: 1,
    };

    fn digest(byte: u8) -> ContentDigest {
        ContentDigest::new([byte; 32]).unwrap()
    }

    fn limits() -> ResourceLimits {
        ResourceLimits {
            cpu_permille: 500,
            memory_bytes: 64 * 1024,
            threads: 4,
            ring_entries: 4,
            io_bytes: 64 * 1024,
            io_ops: 32,
        }
    }

    fn image_spec(version: u16) -> ImageSpec {
        ImageSpec {
            image: SignedImage {
                content: digest(version as u8),
                signer: 7,
                signature: digest(0x80 | version as u8),
                version: ImageVersion {
                    major: version,
                    minor: 0,
                    patch: 0,
                },
            },
            rootfs_bytes: 12,
            writable_bytes: 32 * 1024,
            max_volumes: 2,
        }
    }

    fn layers() -> [ImageLayerSpec; 2] {
        [
            ImageLayerSpec {
                content: digest(0x31),
                bytes: 5,
            },
            ImageLayerSpec {
                content: digest(0x32),
                bytes: 7,
            },
        ]
    }

    fn capabilities() -> CapabilitySet {
        CapabilitySet::EXECUTE
            .union(CapabilitySet::NETWORK)
            .union(CapabilitySet::DEVICE)
            .union(CapabilitySet::DATA_READ)
            .union(CapabilitySet::DATA_WRITE)
    }

    fn fixture() -> (
        WorkloadTable<2>,
        SandboxTable<1>,
        SandboxStorageTable<2, 4, 2>,
        SandboxKey,
        WorkloadKey,
        ImageKey,
        VolumeKey,
        ImageKey,
    ) {
        let mut workloads = WorkloadTable::<2>::new();
        let mut sandboxes = SandboxTable::<1>::new();
        let sandbox = sandboxes.create(&mut workloads, DOMAIN, limits()).unwrap();
        sandboxes.mark_ready(&mut workloads, sandbox).unwrap();
        sandboxes.start(&mut workloads, sandbox).unwrap();
        let root = sandboxes.root_snapshot(&workloads, sandbox).unwrap().key;
        let mut storage = SandboxStorageTable::<2, 4, 2>::new();
        let image = storage
            .add_image(DOMAIN, sandbox, image_spec(1), &layers())
            .unwrap();
        let volume = storage
            .create_volume(DOMAIN, sandbox, image, 16 * 1024)
            .unwrap();
        let other_image = storage
            .add_image(DOMAIN, sandbox, image_spec(2), &layers())
            .unwrap();
        (
            workloads,
            sandboxes,
            storage,
            sandbox,
            root,
            image,
            volume,
            other_image,
        )
    }

    fn launch_spec<'a>(
        sandbox: SandboxKey,
        root: WorkloadKey,
        image: ImageKey,
        volume: Option<VolumeKey>,
        devices: &'a [DeviceGrant],
        data: &'a [DataScopeGrant],
    ) -> LaunchSpec<'a> {
        LaunchSpec {
            sandbox,
            root,
            image,
            volume,
            root_capabilities: CapabilitySet::ALL,
            capabilities: capabilities(),
            resources: LaunchResources {
                limits: limits(),
                io_rate: Some(IoRateLimits {
                    bytes_per_window: 4096,
                    ops_per_window: 8,
                    window_ns: 1_000_000,
                }),
            },
            network_policy: Some(NetworkPolicyRef {
                policy: 17,
                generation: 2,
            }),
            devices,
            data,
        }
    }

    #[test]
    fn valid_plan_combines_references_without_copying_authority() {
        let (workloads, sandboxes, storage, sandbox, root, image, volume, _) = fixture();
        let devices = [DeviceGrant {
            object: 0x500,
            generation: 2,
            rights: 3,
            owner: OTHER_DOMAIN,
            grantee: DOMAIN,
        }];
        let data = [
            DataScopeGrant {
                object: 0x600,
                generation: 1,
                owner: DOMAIN,
                grantee: DOMAIN,
                writable: false,
            },
            DataScopeGrant {
                object: 0x601,
                generation: 4,
                owner: DOMAIN,
                grantee: DOMAIN,
                writable: true,
            },
        ];
        let spec = launch_spec(sandbox, root, image, Some(volume), &devices, &data);
        let mut plans = SandboxLaunchTable::<1>::new();
        let key = plans
            .create(DOMAIN, &workloads, &sandboxes, &storage, spec)
            .unwrap();
        let plan = plans.plan(DOMAIN, key).unwrap();
        assert_eq!(plan.sandbox, sandbox);
        assert_eq!(plan.root, root);
        assert_eq!(plan.image, image);
        assert_eq!(plan.volume, Some(volume));
        assert_eq!(plan.devices, 1);
        assert_eq!(plan.data_scopes, 2);
        assert_eq!(plan.data_writable_mask, 2);
        assert_eq!(plans.device(DOMAIN, key, 0).unwrap(), devices[0]);
        assert_eq!(plans.data_scope(DOMAIN, key, 0).unwrap(), data[0]);
        assert_eq!(
            plans.plan(
                DomainKey {
                    id: 99,
                    generation: 1,
                },
                key,
            ),
            Err(LaunchError::InvalidSandbox)
        );
    }

    #[test]
    fn image_and_volume_ownership_is_checked_before_admission() {
        let (workloads, sandboxes, mut storage, sandbox, root, image, _, other_image) = fixture();
        let other_volume = storage
            .create_volume(DOMAIN, sandbox, other_image, 8 * 1024)
            .unwrap();
        let spec = launch_spec(sandbox, root, image, Some(other_volume), &[], &[]);
        let mut plans = SandboxLaunchTable::<1>::new();
        assert_eq!(
            plans.create(DOMAIN, &workloads, &sandboxes, &storage, spec),
            Err(LaunchError::Ownership)
        );
        assert_eq!(plans.count(), 0);
    }

    #[test]
    fn resource_and_capability_escalation_are_failure_atomic() {
        let (workloads, sandboxes, storage, sandbox, root, image, volume, _) = fixture();
        let mut plans = SandboxLaunchTable::<1>::new();
        let good = launch_spec(sandbox, root, image, Some(volume), &[], &[]);
        let key = plans
            .create(DOMAIN, &workloads, &sandboxes, &storage, good)
            .unwrap();
        assert_eq!(plans.count(), 1);

        let mut too_large = good;
        too_large.resources.limits.memory_bytes *= 2;
        assert_eq!(
            plans.create(DOMAIN, &workloads, &sandboxes, &storage, too_large),
            Err(LaunchError::InvalidLimit)
        );

        let mut capability_escalation = good;
        capability_escalation.root_capabilities = CapabilitySet::DATA_READ;
        assert_eq!(
            plans.create(
                DOMAIN,
                &workloads,
                &sandboxes,
                &storage,
                capability_escalation,
            ),
            Err(LaunchError::Capability)
        );
        assert_eq!(plans.count(), 1);
        assert_eq!(plans.plan(DOMAIN, key).unwrap().root, root);
    }

    #[test]
    fn device_data_and_network_grants_are_checked_and_duplicate_free() {
        let (workloads, sandboxes, storage, sandbox, root, image, volume, _) = fixture();
        let mut plans = SandboxLaunchTable::<1>::new();
        let bad_device = [DeviceGrant {
            object: 0x701,
            generation: 1,
            rights: 1,
            owner: OTHER_DOMAIN,
            grantee: OTHER_DOMAIN,
        }];
        assert_eq!(
            plans.create(
                DOMAIN,
                &workloads,
                &sandboxes,
                &storage,
                launch_spec(sandbox, root, image, Some(volume), &bad_device, &[],),
            ),
            Err(LaunchError::InvalidDevice)
        );

        let duplicate = [
            DeviceGrant {
                object: 0x702,
                generation: 1,
                rights: 1,
                owner: DOMAIN,
                grantee: DOMAIN,
            },
            DeviceGrant {
                object: 0x702,
                generation: 2,
                rights: 1,
                owner: DOMAIN,
                grantee: DOMAIN,
            },
        ];
        assert_eq!(
            plans.create(
                DOMAIN,
                &workloads,
                &sandboxes,
                &storage,
                launch_spec(sandbox, root, image, Some(volume), &duplicate, &[]),
            ),
            Err(LaunchError::DuplicateGrant)
        );

        let writable_without_capability = [DataScopeGrant {
            object: 0x703,
            generation: 1,
            owner: DOMAIN,
            grantee: DOMAIN,
            writable: true,
        }];
        let mut no_write = launch_spec(
            sandbox,
            root,
            image,
            None,
            &[],
            &writable_without_capability,
        );
        no_write.capabilities = CapabilitySet::EXECUTE.union(CapabilitySet::DATA_READ);
        no_write.root_capabilities = CapabilitySet::ALL;
        no_write.network_policy = None;
        assert_eq!(
            plans.create(DOMAIN, &workloads, &sandboxes, &storage, no_write),
            Err(LaunchError::InvalidData)
        );

        let mut no_network = launch_spec(sandbox, root, image, None, &[], &[]);
        no_network.capabilities = CapabilitySet::EXECUTE;
        assert_eq!(
            plans.create(DOMAIN, &workloads, &sandboxes, &storage, no_network),
            Err(LaunchError::InvalidNetwork)
        );

        let mut network_without_policy = launch_spec(sandbox, root, image, Some(volume), &[], &[]);
        network_without_policy.network_policy = None;
        assert_eq!(
            plans.create(
                DOMAIN,
                &workloads,
                &sandboxes,
                &storage,
                network_without_policy,
            ),
            Err(LaunchError::InvalidNetwork)
        );

        let mut volume_without_write = launch_spec(sandbox, root, image, Some(volume), &[], &[]);
        volume_without_write.capabilities = CapabilitySet::EXECUTE
            .union(CapabilitySet::NETWORK)
            .union(CapabilitySet::DATA_READ);
        assert_eq!(
            plans.create(
                DOMAIN,
                &workloads,
                &sandboxes,
                &storage,
                volume_without_write,
            ),
            Err(LaunchError::Capability)
        );
        assert_eq!(plans.count(), 0);
    }

    #[test]
    fn logical_views_are_derived_and_cannot_change_launch_authority() {
        let (workloads, sandboxes, storage, sandbox, root, image, volume, _) = fixture();
        let mut plans = SandboxLaunchTable::<1>::new();
        let key = plans
            .create(
                DOMAIN,
                &workloads,
                &sandboxes,
                &storage,
                launch_spec(sandbox, root, image, Some(volume), &[], &[]),
            )
            .unwrap();
        let before = plans.plan(DOMAIN, key).unwrap();
        let image_view = derive_mount_view(before, ViewSource::ImageRoot(image), b"/app").unwrap();
        assert_eq!(image_view.target(), b"/app");
        assert!(!image_view.writable);
        let volume_view =
            derive_mount_view(before, ViewSource::WritableVolume(volume), b"/data").unwrap();
        assert!(volume_view.writable);
        assert_eq!(plans.plan(DOMAIN, key).unwrap(), before);
        assert_eq!(
            derive_mount_view(before, ViewSource::ImageRoot(image), b"/../etc"),
            Err(LaunchError::InvalidView)
        );
        assert_eq!(
            derive_mount_view(
                before,
                ViewSource::Data {
                    index: 0,
                    writable: false,
                },
                b"/data",
            ),
            Err(LaunchError::InvalidView)
        );
    }

    #[test]
    fn plans_are_capacity_bounded_and_old_keys_never_revive() {
        let (workloads, sandboxes, storage, sandbox, root, image, volume, _) = fixture();
        let mut plans = SandboxLaunchTable::<1>::new();
        let spec = launch_spec(sandbox, root, image, Some(volume), &[], &[]);
        let old = plans
            .create(DOMAIN, &workloads, &sandboxes, &storage, spec)
            .unwrap();
        assert_eq!(
            plans.create(DOMAIN, &workloads, &sandboxes, &storage, spec),
            Err(LaunchError::Capacity)
        );
        plans.destroy(DOMAIN, old).unwrap();
        let new = plans
            .create(DOMAIN, &workloads, &sandboxes, &storage, spec)
            .unwrap();
        assert_ne!(old, new);
        assert_eq!(plans.plan(DOMAIN, old), Err(LaunchError::InvalidSandbox));
    }
}
