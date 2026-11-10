//! Bounded Linux graphics service over Jasper GPU queue and Memory capabilities.
//!
//! 职责：把 Vulkan 兼容请求映射到 HWV-7 GPU 队列、Memory capability、WSI
//! 和世代化同步对象。边界：不执行 Vulkan 命令、不映射真实设备页、不伪造
//! 设备 completion。
//! Responsibility: map Linux graphics resource requests onto Jasper mechanisms.

use kernel_core::dma_quiesce::ResetOutcome;
use kernel_core::hwv7::{
    GpuBackend, GpuError, GpuIdentity, GpuQueue, CANCEL, CONTROL, MAP_DEVICE, QUEUE_CAPACITY,
    SUBMIT,
};
use kernel_core::memory_capability::{
    BackingIdentity, MemoryCapabilityTable, MemoryCapabilityUse, MemoryRights,
};
use kernel_core::security_domain::DomainKey;

use crate::sync::{
    Fence, FenceStatus, Semaphore, SyncError, TimelineSemaphore, TimelineStatus,
};
use crate::vulkan::{
    CapabilityReport, DeviceCapabilities, VulkanProfile, WsiCapabilityReport, WsiSystem,
};
use crate::wsi::{
    InputEvent, InputValue, PixelFormat, SurfaceCaps, SurfaceId, WindowGeometry, WindowId, Wsi,
    WsiError,
};

pub const MAX_IMPORTS: usize = 32;
pub const MAX_SYNC_OBJECTS: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GraphicsLimit {
    pub max_buffer_bytes: u64,
    pub total_buffer_bytes: u64,
    pub max_image_bytes: u64,
    pub total_image_bytes: u64,
}

impl GraphicsLimit {
    pub fn validate(self) -> Result<Self, GraphicsError> {
        if self.max_buffer_bytes == 0
            || self.max_image_bytes == 0
            || self.total_buffer_bytes < self.max_buffer_bytes
            || self.total_image_bytes < self.max_image_bytes
        {
            return Err(GraphicsError::InvalidLimit);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraphicsError {
    InvalidIdentity,
    InvalidLimit,
    RightsDenied,
    CapabilityStale,
    CapabilityDenied,
    InvalidBuffer,
    InvalidImage,
    InvalidWork,
    Capacity,
    Quota,
    StaleGeneration,
    Busy,
    NotFound,
    Queue(GpuError),
    Sync(SyncError),
    Wsi(WsiError),
    Quarantined,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryHandle {
    pub capability: u64,
    pub epoch: u32,
    pub backing: BackingIdentity,
    pub rights: MemoryRights,
}

impl MemoryHandle {
    fn from_use(usage: MemoryCapabilityUse) -> Self {
        Self {
            capability: usage.capability,
            epoch: usage.epoch,
            backing: usage.backing,
            rights: usage.rights,
        }
    }

    fn as_use(self) -> MemoryCapabilityUse {
        MemoryCapabilityUse {
            capability: self.capability,
            epoch: self.epoch,
            backing: self.backing,
            rights: self.rights,
        }
    }
}

/// Linux GPU access requested for one imported memory range.
///
/// Linux 图形工作对一段导入内存请求的访问方向。导入时授予的能力必须覆盖导入方向，
/// 每次提交又必须覆盖该工作包声明的方向，不能借一次只读导入执行写工作。
/// Access granted at import time and requested by each work packet are both checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraphicsMemoryAccess {
    ReadOnly,
    ReadWrite,
}

impl GraphicsMemoryAccess {
    const fn required_rights(self) -> MemoryRights {
        match self {
            Self::ReadOnly => MemoryRights::READ,
            Self::ReadWrite => MemoryRights::READ.union(MemoryRights::WRITE),
        }
    }

    const fn contains(self, requested: Self) -> bool {
        matches!(
            (self, requested),
            (Self::ReadWrite, _) | (Self::ReadOnly, Self::ReadOnly)
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BufferImport {
    pub backing_start: u64,
    pub size: u64,
    pub alignment: u64,
    pub access: GraphicsMemoryAccess,
    /// 由受信 DMA/IOMMU 后端签发的 opaque 设备范围标识。
    ///
    /// Opaque device-range identity issued by the trusted DMA/IOMMU backend. It is not a
    /// caller-selected physical or I/O virtual address and cannot be used as a raw mapping.
    pub opaque_device_range: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImportedBuffer {
    pub memory: MemoryHandle,
    pub descriptor: BufferImport,
    active: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageImport {
    pub backing_start: u64,
    pub size: u64,
    pub alignment: u64,
    pub access: GraphicsMemoryAccess,
    pub width: u32,
    pub height: u32,
    pub format: PixelFormat,
    /// 由受信 DMA/IOMMU 后端签发的 opaque 设备范围标识。
    ///
    /// Opaque device-range identity issued by the trusted DMA/IOMMU backend.
    pub opaque_device_range: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImportedImage {
    pub memory: MemoryHandle,
    pub descriptor: ImageImport,
    active: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueuePacket {
    pub op: u32,
    pub work_units: u32,
    pub buffer: Option<MemoryHandle>,
    pub image: Option<MemoryHandle>,
    pub buffer_access: Option<GraphicsMemoryAccess>,
    pub image_access: Option<GraphicsMemoryAccess>,
    pub fence: Option<u64>,
    pub timeline: Option<(u64, u64)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrimitiveTopology {
    PointList,
    LineList,
    TriangleList,
    TriangleStrip,
    PatchList,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaceCullMode {
    None,
    Front,
    Back,
    FrontAndBack,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Work {
    request: u64,
    fence: Option<u64>,
    timeline: Option<(u64, u64)>,
    buffer: Option<MemoryHandle>,
    image: Option<MemoryHandle>,
}

/// Linux graphics compatibility service bound to one Jasper GPU queue generation.
///
/// 绑定一个 Jasper GPU 队列世代的 Linux 图形兼容服务。所有 import 在使用前
/// 重新校验 Memory capability，撤销后的 token 不会被缓存绕过。
pub struct GraphicsService<const W: usize, const S: usize> {
    caps: DeviceCapabilities,
    queue: GpuQueue,
    available_rights: u32,
    limits: GraphicsLimit,
    buffers: [Option<ImportedBuffer>; MAX_IMPORTS],
    images: [Option<ImportedImage>; MAX_IMPORTS],
    work: [Option<Work>; QUEUE_CAPACITY],
    fences: [Option<Fence>; MAX_SYNC_OBJECTS],
    semaphores: [Option<Semaphore>; MAX_SYNC_OBJECTS],
    timelines: [Option<TimelineSemaphore>; MAX_SYNC_OBJECTS],
    next_sync: u64,
    wsi: Wsi<W, S>,
    buffer_bytes: u64,
    image_bytes: u64,
    active: bool,
}

impl<const W: usize, const S: usize> GraphicsService<W, S> {
    pub fn new(
        caps: DeviceCapabilities,
        identity: GpuIdentity,
        available_rights: u32,
        iommu: Option<DomainKey>,
        limits: GraphicsLimit,
    ) -> Result<Self, GraphicsError> {
        let required = SUBMIT | CANCEL | CONTROL | MAP_DEVICE;
        if available_rights & required != required {
            return Err(GraphicsError::RightsDenied);
        }
        let limits = limits.validate()?;
        let queue = GpuQueue::bind(identity, caps.backend(), iommu).map_err(GraphicsError::Queue)?;
        Ok(Self {
            caps,
            queue,
            available_rights,
            limits,
            buffers: [None; MAX_IMPORTS],
            images: [None; MAX_IMPORTS],
            work: [None; QUEUE_CAPACITY],
            fences: [None; MAX_SYNC_OBJECTS],
            semaphores: [None; MAX_SYNC_OBJECTS],
            timelines: [None; MAX_SYNC_OBJECTS],
            next_sync: 1,
            wsi: Wsi::new(),
            buffer_bytes: 0,
            image_bytes: 0,
            active: true,
        })
    }

    pub fn capabilities(&self) -> &DeviceCapabilities {
        &self.caps
    }

    pub fn backend(&self) -> GpuBackend {
        self.queue.backend()
    }

    pub fn identity(&self) -> GpuIdentity {
        self.queue.identity()
    }

    pub fn generation(&self) -> u32 {
        self.queue.identity().generation
    }

    pub fn validate_profile(&self, profile: VulkanProfile) -> CapabilityReport {
        self.caps.validate_profile(profile)
    }

    pub fn validate_wsi(&self, system: WsiSystem) -> WsiCapabilityReport {
        self.caps.validate_wsi(system)
    }

    pub fn imported_buffer_bytes(&self) -> u64 {
        self.buffer_bytes
    }

    pub fn imported_image_bytes(&self) -> u64 {
        self.image_bytes
    }

    pub fn create_fence(&mut self, initially_signaled: bool) -> Result<u64, GraphicsError> {
        let generation = self.generation();
        let slot = self
            .fences
            .iter()
            .position(Option::is_none)
            .ok_or(GraphicsError::Capacity)?;
        let id = self.allocate_sync_id()?;
        self.fences[slot] =
            Some(Fence::new(id, generation, initially_signaled).map_err(GraphicsError::Sync)?);
        Ok(id)
    }

    pub fn fence_status(&self, id: u64) -> Result<FenceStatus, GraphicsError> {
        self.fence(id).map(|fence| fence.status())
    }

    pub fn reset_fence(&mut self, id: u64) -> Result<(), GraphicsError> {
        let generation = self.generation();
        let slot = self
            .fences
            .iter()
            .position(|fence| fence.is_some_and(|value| value.id() == id))
            .ok_or(GraphicsError::NotFound)?;
        self.fences[slot]
            .as_mut()
            .ok_or(GraphicsError::NotFound)?
            .reset(generation)
            .map_err(GraphicsError::Sync)
    }

    pub fn create_semaphore(&mut self) -> Result<u64, GraphicsError> {
        let generation = self.generation();
        let slot = self
            .semaphores
            .iter()
            .position(Option::is_none)
            .ok_or(GraphicsError::Capacity)?;
        let id = self.allocate_sync_id()?;
        self.semaphores[slot] =
            Some(Semaphore::new(id, generation).map_err(GraphicsError::Sync)?);
        Ok(id)
    }

    pub fn destroy_fence(&mut self, id: u64) -> Result<(), GraphicsError> {
        if self
            .work
            .iter()
            .flatten()
            .any(|work| work.fence == Some(id))
        {
            return Err(GraphicsError::Busy);
        }
        let slot = self
            .fences
            .iter()
            .position(|fence| fence.is_some_and(|value| value.id() == id))
            .ok_or(GraphicsError::NotFound)?;
        self.fences[slot] = None;
        Ok(())
    }

    pub fn destroy_semaphore(&mut self, id: u64) -> Result<(), GraphicsError> {
        let slot = self
            .semaphores
            .iter()
            .position(|semaphore| semaphore.is_some_and(|value| value.id() == id))
            .ok_or(GraphicsError::NotFound)?;
        self.semaphores[slot] = None;
        Ok(())
    }

    pub fn destroy_timeline(&mut self, id: u64) -> Result<(), GraphicsError> {
        if self
            .work
            .iter()
            .flatten()
            .any(|work| work.timeline.is_some_and(|(timeline, _)| timeline == id))
        {
            return Err(GraphicsError::Busy);
        }
        let slot = self
            .timelines
            .iter()
            .position(|timeline| timeline.is_some_and(|value| value.id() == id))
            .ok_or(GraphicsError::NotFound)?;
        self.timelines[slot] = None;
        Ok(())
    }

    pub fn signal_semaphore(&mut self, id: u64) -> Result<(), GraphicsError> {
        let generation = self.generation();
        let slot = self
            .semaphores
            .iter()
            .position(|semaphore| semaphore.is_some_and(|value| value.id() == id))
            .ok_or(GraphicsError::NotFound)?;
        self.semaphores[slot]
            .as_mut()
            .ok_or(GraphicsError::NotFound)?
            .signal(generation)
            .map_err(GraphicsError::Sync)
    }

    pub fn wait_semaphore(&mut self, id: u64) -> Result<(), GraphicsError> {
        let generation = self.generation();
        let slot = self
            .semaphores
            .iter()
            .position(|semaphore| semaphore.is_some_and(|value| value.id() == id))
            .ok_or(GraphicsError::NotFound)?;
        self.semaphores[slot]
            .as_mut()
            .ok_or(GraphicsError::NotFound)?
            .wait(generation)
            .map(|_| ())
            .map_err(GraphicsError::Sync)
    }

    pub fn create_timeline(&mut self, initial_value: u64) -> Result<u64, GraphicsError> {
        let generation = self.generation();
        let slot = self
            .timelines
            .iter()
            .position(Option::is_none)
            .ok_or(GraphicsError::Capacity)?;
        let id = self.allocate_sync_id()?;
        self.timelines[slot] = Some(
            TimelineSemaphore::new(id, generation, initial_value).map_err(GraphicsError::Sync)?,
        );
        Ok(id)
    }

    pub fn signal_timeline(&mut self, id: u64, value: u64) -> Result<u64, GraphicsError> {
        let generation = self.generation();
        let slot = self
            .timelines
            .iter()
            .position(|timeline| timeline.is_some_and(|value| value.id() == id))
            .ok_or(GraphicsError::NotFound)?;
        self.timelines[slot]
            .as_mut()
            .ok_or(GraphicsError::NotFound)?
            .signal(generation, value)
            .map_err(GraphicsError::Sync)
    }

    pub fn wait_timeline(&self, id: u64, value: u64) -> Result<TimelineStatus, GraphicsError> {
        let generation = self.generation();
        let timeline = self
            .timelines
            .iter()
            .flatten()
            .find(|timeline| timeline.id() == id)
            .ok_or(GraphicsError::NotFound)?;
        timeline
            .wait(generation, value)
            .map_err(GraphicsError::Sync)
    }

    pub fn import_buffer<const C: usize>(
        &mut self,
        table: &MemoryCapabilityTable<C>,
        token: MemoryCapabilityUse,
        descriptor: BufferImport,
    ) -> Result<MemoryHandle, GraphicsError> {
        let generation = self.generation();
        self.require_generation(generation)?;
        if descriptor.size == 0
            || descriptor.alignment == 0
            || !descriptor.alignment.is_power_of_two()
            || descriptor.size > self.limits.max_buffer_bytes
            || descriptor.opaque_device_range == 0
            || !descriptor
                .opaque_device_range
                .is_multiple_of(descriptor.alignment)
        {
            return Err(GraphicsError::InvalidBuffer);
        }
        if self.device_range_overlaps(descriptor.opaque_device_range, descriptor.size) {
            return Err(GraphicsError::Busy);
        }
        let checked = validate_capability_use(
            table,
            token,
            descriptor.backing_start,
            descriptor.size,
            descriptor.access.required_rights(),
        )?;
        let total = self
            .buffer_bytes
            .checked_add(descriptor.size)
            .ok_or(GraphicsError::Quota)?;
        if total > self.limits.total_buffer_bytes {
            return Err(GraphicsError::Quota);
        }
        let duplicate = self.buffers.iter().flatten().any(|buffer| {
            buffer.active && buffer.memory.backing == checked.backing
        });
        if duplicate {
            return Err(GraphicsError::Busy);
        }
        let slot = self
            .buffers
            .iter()
            .position(Option::is_none)
            .ok_or(GraphicsError::Capacity)?;
        let memory = MemoryHandle::from_use(checked);
        self.buffers[slot] = Some(ImportedBuffer {
            memory,
            descriptor,
            active: true,
        });
        self.buffer_bytes = total;
        Ok(memory)
    }

    pub fn import_image<const C: usize>(
        &mut self,
        table: &MemoryCapabilityTable<C>,
        token: MemoryCapabilityUse,
        descriptor: ImageImport,
    ) -> Result<MemoryHandle, GraphicsError> {
        let generation = self.generation();
        self.require_generation(generation)?;
        let required_image_bytes = u64::from(descriptor.width)
            .checked_mul(u64::from(descriptor.height))
            .and_then(|pixels| pixels.checked_mul(4))
            .ok_or(GraphicsError::InvalidImage)?;
        if descriptor.width == 0
            || descriptor.height == 0
            || descriptor.alignment == 0
            || !descriptor.alignment.is_power_of_two()
            || descriptor.width > 16_384
            || descriptor.height > 16_384
            || descriptor.size < required_image_bytes
            || descriptor.size > self.limits.max_image_bytes
            || descriptor.opaque_device_range == 0
            || !descriptor
                .opaque_device_range
                .is_multiple_of(descriptor.alignment)
        {
            return Err(GraphicsError::InvalidImage);
        }
        if self.device_range_overlaps(descriptor.opaque_device_range, descriptor.size) {
            return Err(GraphicsError::Busy);
        }
        let checked = validate_capability_use(
            table,
            token,
            descriptor.backing_start,
            descriptor.size,
            descriptor.access.required_rights(),
        )?;
        let total = self
            .image_bytes
            .checked_add(descriptor.size)
            .ok_or(GraphicsError::Quota)?;
        if total > self.limits.total_image_bytes {
            return Err(GraphicsError::Quota);
        }
        let duplicate = self.images.iter().flatten().any(|image| {
            image.active && image.memory.backing == checked.backing
        });
        if duplicate {
            return Err(GraphicsError::Busy);
        }
        let slot = self
            .images
            .iter()
            .position(Option::is_none)
            .ok_or(GraphicsError::Capacity)?;
        let memory = MemoryHandle::from_use(checked);
        self.images[slot] = Some(ImportedImage {
            memory,
            descriptor,
            active: true,
        });
        self.image_bytes = total;
        Ok(memory)
    }

    /// Revokes one graphics import while preserving external Memory ownership.
    ///
    /// 撤销一个图形导入，但不销毁外部 Memory capability；仍有在飞工作时拒绝。
    pub fn revoke_import(&mut self, memory: MemoryHandle) -> Result<(), GraphicsError> {
        if self.work.iter().flatten().any(|work| {
            work.buffer == Some(memory) || work.image == Some(memory)
        }) {
            return Err(GraphicsError::Busy);
        }
        if let Some(slot) = self.buffers.iter().position(|buffer| {
            buffer.is_some_and(|buffer| buffer.active && buffer.memory == memory)
        }) {
            let buffer = self.buffers[slot].take().ok_or(GraphicsError::NotFound)?;
            self.buffer_bytes = self
                .buffer_bytes
                .checked_sub(buffer.descriptor.size)
                .ok_or(GraphicsError::InvalidLimit)?;
            return Ok(());
        }
        if let Some(slot) = self.images.iter().position(|image| {
            image.is_some_and(|image| image.active && image.memory == memory)
        }) {
            let image = self.images[slot].take().ok_or(GraphicsError::NotFound)?;
            self.image_bytes = self
                .image_bytes
                .checked_sub(image.descriptor.size)
                .ok_or(GraphicsError::InvalidLimit)?;
            return Ok(());
        }
        Err(GraphicsError::NotFound)
    }

    /// Submits one device-work packet and validates every imported memory token.
    ///
    /// 提交一个设备工作包并重新验证所有导入内存；门铃不产生 completion。
    pub fn submit<const C: usize>(
        &mut self,
        table: &MemoryCapabilityTable<C>,
        packet: QueuePacket,
    ) -> Result<u64, GraphicsError> {
        if !self.active {
            return Err(GraphicsError::Quarantined);
        }
        if packet.op == 0 || packet.work_units == 0 {
            return Err(GraphicsError::InvalidWork);
        }
        match (packet.buffer, packet.buffer_access) {
            (None, None) => {}
            (Some(buffer), Some(access)) => {
                let imported = self.require_active_buffer(buffer)?;
                if !imported.descriptor.access.contains(access) {
                    return Err(GraphicsError::RightsDenied);
                }
                table
                    .validate(buffer.as_use())
                    .map_err(map_capability_error)?;
            }
            _ => return Err(GraphicsError::InvalidWork),
        }
        match (packet.image, packet.image_access) {
            (None, None) => {}
            (Some(image), Some(access)) => {
                let imported = self.require_active_image(image)?;
                if !imported.descriptor.access.contains(access) {
                    return Err(GraphicsError::RightsDenied);
                }
                table
                    .validate(image.as_use())
                    .map_err(map_capability_error)?;
            }
            _ => return Err(GraphicsError::InvalidWork),
        }
        if let Some(id) = packet.fence {
            self.validate_fence_submission(id)?;
        }
        if let Some((id, value)) = packet.timeline {
            self.validate_timeline_submission(id, value)?;
        }
        let slot = self
            .work
            .iter()
            .position(Option::is_none)
            .ok_or(GraphicsError::Capacity)?;
        let generation = self.generation();
        let request = self
            .queue
            .submit(generation, self.available_rights, packet.work_units)
            .map_err(GraphicsError::Queue)?;
        if let Err(error) = self.queue.start(request) {
            let _ = self
                .queue
                .cancel(generation, request, self.available_rights);
            return Err(GraphicsError::Queue(error));
        }
        if let Err(error) = self.queue.ring_doorbell(generation) {
            let _ = self
                .queue
                .cancel(generation, request, self.available_rights);
            return Err(GraphicsError::Queue(error));
        }
        self.work[slot] = Some(Work {
            request,
            fence: packet.fence,
            timeline: packet.timeline,
            buffer: packet.buffer,
            image: packet.image,
        });
        Ok(request)
    }

    /// Delivers a real backend completion and signals dependent synchronization.
    ///
    /// 交付真实后端 completion，并触发依赖的 fence/timeline。
    pub fn complete(&mut self, request: u64, success: bool) -> Result<u64, GraphicsError> {
        let slot = self
            .work
            .iter()
            .position(|work| work.is_some_and(|work| work.request == request))
            .ok_or(GraphicsError::NotFound)?;
        let completion = self
            .queue
            .complete(request, success)
            .map_err(GraphicsError::Queue)?;
        let work = self.work[slot].take().ok_or(GraphicsError::NotFound)?;
        if let Err(error) = self.signal_work_sync(work) {
            self.active = false;
            self.revoke_all_owned();
            return Err(error);
        }
        Ok(completion.sequence)
    }

    pub fn cancel(&mut self, request: u64) -> Result<u64, GraphicsError> {
        let generation = self.generation();
        let slot = self
            .work
            .iter()
            .position(|work| work.is_some_and(|work| work.request == request))
            .ok_or(GraphicsError::NotFound)?;
        let completion = self
            .queue
            .cancel(generation, request, self.available_rights)
            .map_err(GraphicsError::Queue)?;
        let work = self.work[slot].take().ok_or(GraphicsError::NotFound)?;
        if let Err(error) = self.signal_work_sync(work) {
            self.active = false;
            self.revoke_all_owned();
            return Err(error);
        }
        Ok(completion.sequence)
    }

    pub fn pop_completion(&mut self) -> Option<kernel_core::hwv7::Completion> {
        self.queue.pop_completion()
    }

    /// Resets the GPU generation and revokes every graphics-owned device resource.
    ///
    /// 复位 GPU 世代并撤销全部图形设备资源；无法确认静默时进入永久隔离。
    pub fn reset(
        &mut self,
        outcome: ResetOutcome,
        bus_master: Option<bool>,
    ) -> Result<GpuIdentity, GraphicsError> {
        let generation = self.generation();
        let identity = match self
            .queue
            .reset(generation, outcome, bus_master)
            .map_err(GraphicsError::Queue)
        {
            Ok(identity) => identity,
            Err(error) => {
                self.active = false;
                self.revoke_all_owned();
                return if error == GraphicsError::Queue(GpuError::ResetUnsafe) {
                    Err(GraphicsError::Quarantined)
                } else {
                    Err(error)
                };
            }
        };
        self.revoke_all_owned();
        Ok(identity)
    }

    pub fn register_window(
        &mut self,
        window: WindowId,
        geometry: WindowGeometry,
    ) -> Result<u32, GraphicsError> {
        self.wsi
            .register_window(window, geometry)
            .map_err(GraphicsError::Wsi)
    }

    pub fn create_surface(
        &mut self,
        surface: SurfaceId,
        window: WindowId,
        caps: SurfaceCaps,
    ) -> Result<u32, GraphicsError> {
        self.wsi
            .create_surface(surface, window, caps)
            .map_err(GraphicsError::Wsi)
    }

    pub fn acquire_image(
        &mut self,
        surface: SurfaceId,
        generation: u32,
    ) -> Result<u32, GraphicsError> {
        self.wsi
            .acquire_image(surface, generation)
            .map_err(GraphicsError::Wsi)
    }

    pub fn present_image(
        &mut self,
        surface: SurfaceId,
        generation: u32,
        image: u32,
    ) -> Result<(), GraphicsError> {
        self.wsi
            .present_image(surface, generation, image)
            .map_err(GraphicsError::Wsi)
    }

    pub fn push_input(
        &mut self,
        window: WindowId,
        generation: u32,
        value: InputValue,
    ) -> Result<u64, GraphicsError> {
        self.wsi
            .push_input(window, generation, value)
            .map_err(GraphicsError::Wsi)
    }

    pub fn pop_input(&mut self) -> Option<InputEvent> {
        self.wsi.pop_input()
    }

    fn allocate_sync_id(&mut self) -> Result<u64, GraphicsError> {
        let id = self.next_sync;
        self.next_sync = id.checked_add(1).ok_or(GraphicsError::Capacity)?;
        Ok(id)
    }

    fn fence(&self, id: u64) -> Result<Fence, GraphicsError> {
        self.fences
            .iter()
            .flatten()
            .find(|fence| fence.id() == id)
            .copied()
            .ok_or(GraphicsError::NotFound)
    }

    fn timeline(&self, id: u64) -> Result<TimelineSemaphore, GraphicsError> {
        self.timelines
            .iter()
            .flatten()
            .find(|timeline| timeline.id() == id)
            .copied()
            .ok_or(GraphicsError::NotFound)
    }

    fn require_generation(&self, generation: u32) -> Result<(), GraphicsError> {
        if !self.active {
            Err(GraphicsError::Quarantined)
        } else if generation != self.queue.identity().generation {
            Err(GraphicsError::StaleGeneration)
        } else {
            Ok(())
        }
    }

    fn require_active_buffer(&self, memory: MemoryHandle) -> Result<ImportedBuffer, GraphicsError> {
        self.buffers
            .iter()
            .flatten()
            .find(|buffer| buffer.active && buffer.memory == memory)
            .copied()
            .ok_or(GraphicsError::InvalidBuffer)
    }

    fn require_active_image(&self, memory: MemoryHandle) -> Result<ImportedImage, GraphicsError> {
        self.images
            .iter()
            .flatten()
            .find(|image| image.active && image.memory == memory)
            .copied()
            .ok_or(GraphicsError::InvalidImage)
    }

    fn validate_fence_submission(&self, id: u64) -> Result<(), GraphicsError> {
        let fence = self.fence(id)?;
        if fence.status() == FenceStatus::Signaled {
            return Err(GraphicsError::Sync(SyncError::InvalidState));
        }
        if self
            .work
            .iter()
            .flatten()
            .any(|work| work.fence == Some(id))
        {
            return Err(GraphicsError::Busy);
        }
        Ok(())
    }

    fn validate_timeline_submission(&self, id: u64, value: u64) -> Result<(), GraphicsError> {
        let generation = self.generation();
        let timeline = self.timeline(id)?;
        timeline
            .wait(generation, value)
            .map_err(GraphicsError::Sync)?;
        if timeline.generation() != generation || value <= timeline.value() {
            return Err(GraphicsError::Sync(SyncError::NonMonotonic));
        }
        if self.work.iter().flatten().any(|work| {
            work.timeline
                .is_some_and(|(pending_id, pending_value)| {
                    pending_id == id && pending_value >= value
                })
        }) {
            return Err(GraphicsError::Sync(SyncError::NonMonotonic));
        }
        Ok(())
    }

    fn signal_work_sync(&mut self, work: Work) -> Result<(), GraphicsError> {
        let generation = self.generation();
        if let Some(fence) = work.fence {
            let slot = self
                .fences
                .iter()
                .position(|value| value.is_some_and(|value| value.id() == fence))
                .ok_or(GraphicsError::NotFound)?;
            self.fences[slot]
                .as_mut()
                .ok_or(GraphicsError::NotFound)?
                .signal(generation)
                .map_err(GraphicsError::Sync)?;
        }
        if let Some((timeline, value)) = work.timeline {
            let slot = self
                .timelines
                .iter()
                .position(|entry| entry.is_some_and(|entry| entry.id() == timeline))
                .ok_or(GraphicsError::NotFound)?;
            self.timelines[slot]
                .as_mut()
                .ok_or(GraphicsError::NotFound)?
                .satisfy_completion(generation, value)
                .map_err(GraphicsError::Sync)?;
        }
        Ok(())
    }

    fn revoke_all_owned(&mut self) {
        self.buffers.fill(None);
        self.images.fill(None);
        self.work.fill(None);
        self.fences.fill(None);
        self.semaphores.fill(None);
        self.timelines.fill(None);
        self.buffer_bytes = 0;
        self.image_bytes = 0;
    }

    fn device_range_overlaps(&self, address: u64, size: u64) -> bool {
        let Some(end) = address.checked_add(size) else {
            return true;
        };
        self.buffers.iter().flatten().any(|buffer| {
            buffer.active
                && ranges_overlap(
                    address,
                    end,
                    buffer.descriptor.opaque_device_range,
                    buffer.descriptor.size,
                )
        }) || self.images.iter().flatten().any(|image| {
            image.active
                && ranges_overlap(
                    address,
                    end,
                    image.descriptor.opaque_device_range,
                    image.descriptor.size,
                )
        })
    }
}

fn ranges_overlap(start: u64, end: u64, other_start: u64, other_size: u64) -> bool {
    other_start
        .checked_add(other_size)
        .is_none_or(|other_end| start < other_end && other_start < end)
}

fn validate_capability_use<const C: usize>(
    table: &MemoryCapabilityTable<C>,
    token: MemoryCapabilityUse,
    start: u64,
    size: u64,
    required: MemoryRights,
) -> Result<MemoryCapabilityUse, GraphicsError> {
    // 先验证调用者实际持有的 capability/epoch，再重新解析范围。
    // Validate the caller-held capability and epoch before resolving the range again.
    table.validate(token).map_err(map_capability_error)?;
    if !token.rights.contains(required) {
        return Err(GraphicsError::CapabilityDenied);
    }
    let checked = table
        .check(start, size, required, Some(token.backing))
        .map_err(map_capability_error)?;
    if checked.capability != token.capability
        || checked.epoch != token.epoch
        || checked.backing != token.backing
        || checked.rights != required
    {
        return Err(GraphicsError::CapabilityStale);
    }
    Ok(checked)
}

fn map_capability_error(
    error: kernel_core::memory_capability::MemoryCapabilityError,
) -> GraphicsError {
    use kernel_core::memory_capability::MemoryCapabilityError;
    match error {
        MemoryCapabilityError::Revoked => GraphicsError::CapabilityStale,
        MemoryCapabilityError::StaleIdentity
        | MemoryCapabilityError::InvalidCapability
        | MemoryCapabilityError::Unmapped => GraphicsError::CapabilityStale,
        MemoryCapabilityError::RightsDenied | MemoryCapabilityError::InvalidRange => {
            GraphicsError::CapabilityDenied
        }
        _ => GraphicsError::CapabilityDenied,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use kernel_core::hwv7::COMPLETION_CAPACITY;
    use kernel_core::memory_capability::{
        BackingIdentity, MemoryCapabilityTable, MemoryKind, MemoryRights,
    };

    fn capabilities() -> DeviceCapabilities {
        DeviceCapabilities::new(
            GpuBackend::VirtioGpu,
            ash::vk::make_api_version(0, 1, 3, 0),
            1,
            alloc::string::String::from("Jasper graphics test"),
            vec!["VK_KHR_surface", "VK_KHR_xcb_surface"],
            vec![
                "VK_KHR_swapchain",
                "VK_KHR_maintenance1",
                "VK_KHR_shader_draw_parameters",
                "VK_KHR_draw_indirect_count",
            ],
        )
        .unwrap()
    }

    fn test_service() -> GraphicsService<2, 2> {
        GraphicsService::new(
            capabilities(),
            GpuIdentity {
                object: 11,
                generation: 1,
            },
            SUBMIT | CANCEL | CONTROL | MAP_DEVICE,
            None,
            GraphicsLimit {
                max_buffer_bytes: 1 << 20,
                total_buffer_bytes: 1 << 21,
                max_image_bytes: 1 << 22,
                total_image_bytes: 1 << 23,
            },
        )
        .unwrap()
    }

    fn memory<const N: usize>(table: &mut MemoryCapabilityTable<N>) -> MemoryCapabilityUse {
        table
            .grant(
                0x10_000,
                4,
                MemoryRights::READ.union(MemoryRights::WRITE),
                MemoryKind::Shared,
                BackingIdentity::new(7, 1).unwrap(),
            )
            .unwrap();
        table
            .check(
                0x10_000,
                4 * 4096,
                MemoryRights::READ.union(MemoryRights::WRITE),
                None,
            )
            .unwrap()
    }

    #[test]
    fn imported_memory_submit_completion_and_sync_roundtrip() {
        let mut table = MemoryCapabilityTable::<4>::new();
        let token = memory(&mut table);
        let mut service = test_service();
        let buffer = service
            .import_buffer(
                &table,
                token,
                BufferImport {
                    backing_start: 0x10_000,
                    size: 4096,
                    alignment: 256,
                    access: GraphicsMemoryAccess::ReadWrite,
                    opaque_device_range: 0x20_000,
                },
            )
            .unwrap();
        let fence = service.create_fence(false).unwrap();
        let timeline = service.create_timeline(0).unwrap();
        let request = service
            .submit(
                &table,
                QueuePacket {
                    op: 7,
                    work_units: 4,
                    buffer: Some(buffer),
                    image: None,
                    buffer_access: Some(GraphicsMemoryAccess::ReadWrite),
                    image_access: None,
                    fence: Some(fence),
                    timeline: Some((timeline, 3)),
                },
            )
            .unwrap();
        assert_eq!(service.fence_status(fence), Ok(FenceStatus::Unsignaled));
        assert!(service.pop_completion().is_none());
        assert_eq!(service.complete(request, true), Ok(1));
        assert_eq!(service.fence_status(fence), Ok(FenceStatus::Signaled));
        assert_eq!(service.wait_timeline(timeline, 3), Ok(TimelineStatus::Ready));
        assert_eq!(
            service.pop_completion().unwrap().request,
            request
        );
        service.revoke_import(buffer).unwrap();
        assert_eq!(service.imported_buffer_bytes(), 0);
    }

    #[test]
    fn revoked_capability_and_missing_rights_fail_without_submit() {
        let mut table = MemoryCapabilityTable::<4>::new();
        let token = memory(&mut table);
        let mut service = test_service();
        let buffer = service
            .import_buffer(
                &table,
                token,
                BufferImport {
                    backing_start: 0x10_000,
                    size: 4096,
                    alignment: 256,
                    access: GraphicsMemoryAccess::ReadWrite,
                    opaque_device_range: 0x20_000,
                },
            )
            .unwrap();
        table.revoke_range(0x10_000, 4).unwrap();
        assert_eq!(
            service.submit(
                &table,
                QueuePacket {
                    op: 1,
                    work_units: 1,
                    buffer: Some(buffer),
                    image: None,
                    buffer_access: Some(GraphicsMemoryAccess::ReadWrite),
                    image_access: None,
                    fence: None,
                    timeline: None,
                }
            ),
            Err(GraphicsError::CapabilityStale)
        );
        assert!(service.pop_completion().is_none());
    }

    #[test]
    fn stale_or_forged_capability_token_cannot_use_replacement_backing_capability() {
        let mut table = MemoryCapabilityTable::<4>::new();
        let old = memory(&mut table);
        table.revoke_range(0x10_000, 4).unwrap();
        table
            .grant(
                0x10_000,
                4,
                MemoryRights::READ.union(MemoryRights::WRITE),
                MemoryKind::Shared,
                BackingIdentity::new(7, 1).unwrap(),
            )
            .unwrap();
        let replacement = table
            .check(
                0x10_000,
                4 * 4096,
                MemoryRights::READ.union(MemoryRights::WRITE),
                None,
            )
            .unwrap();
        assert_ne!(old.capability, replacement.capability);

        let descriptor = BufferImport {
            backing_start: 0x10_000,
            size: 4096,
            alignment: 256,
            access: GraphicsMemoryAccess::ReadWrite,
            opaque_device_range: 0x20_000,
        };
        let mut service = test_service();
        assert_eq!(
            service.import_buffer(&table, old, descriptor),
            Err(GraphicsError::CapabilityStale)
        );
        assert_eq!(service.imported_buffer_bytes(), 0);

        let mut forged = replacement;
        forged.capability = forged.capability.saturating_add(1);
        assert_eq!(
            service.import_buffer(&table, forged, descriptor),
            Err(GraphicsError::CapabilityStale)
        );
        assert_eq!(service.imported_buffer_bytes(), 0);
        assert!(service.import_buffer(&table, replacement, descriptor).is_ok());
    }

    #[test]
    fn read_only_import_rejects_gpu_write_work_without_submission() {
        let mut table = MemoryCapabilityTable::<4>::new();
        table
            .grant(
                0x30_000,
                1,
                MemoryRights::READ.union(MemoryRights::WRITE),
                MemoryKind::Shared,
                BackingIdentity::new(9, 1).unwrap(),
            )
            .unwrap();
        let token = table
            .check(
                0x30_000,
                4096,
                MemoryRights::READ.union(MemoryRights::WRITE),
                None,
            )
            .unwrap();
        let mut service = test_service();
        let image = service
            .import_image(
                &table,
                token,
                ImageImport {
                    backing_start: 0x30_000,
                    size: 4096,
                    alignment: 256,
                    access: GraphicsMemoryAccess::ReadOnly,
                    width: 32,
                    height: 32,
                    format: PixelFormat::B8g8r8a8Srgb,
                    opaque_device_range: 0x60_000,
                },
            )
            .unwrap();
        assert_eq!(
            service.submit(
                &table,
                QueuePacket {
                    op: 1,
                    work_units: 1,
                    buffer: None,
                    image: Some(image),
                    buffer_access: None,
                    image_access: Some(GraphicsMemoryAccess::ReadWrite),
                    fence: None,
                    timeline: None,
                }
            ),
            Err(GraphicsError::RightsDenied)
        );
        assert!(service.pop_completion().is_none());
        service
            .submit(
                &table,
                QueuePacket {
                    op: 1,
                    work_units: 1,
                    buffer: None,
                    image: Some(image),
                    buffer_access: None,
                    image_access: Some(GraphicsMemoryAccess::ReadOnly),
                    fence: None,
                    timeline: None,
                },
            )
            .unwrap();
    }

    #[test]
    fn sync_preflight_rejects_bad_timeline_and_fence_reuse_before_effects() {
        let mut table = MemoryCapabilityTable::<4>::new();
        let token = memory(&mut table);
        let mut service = test_service();
        let buffer = service
            .import_buffer(
                &table,
                token,
                BufferImport {
                    backing_start: 0x10_000,
                    size: 4096,
                    alignment: 256,
                    access: GraphicsMemoryAccess::ReadWrite,
                    opaque_device_range: 0x20_000,
                },
            )
            .unwrap();
        let fence = service.create_fence(false).unwrap();
        let timeline = service.create_timeline(5).unwrap();
        let packet = |value| QueuePacket {
            op: 1,
            work_units: 1,
            buffer: Some(buffer),
            image: None,
            buffer_access: Some(GraphicsMemoryAccess::ReadWrite),
            image_access: None,
            fence: Some(fence),
            timeline: Some((timeline, value)),
        };
        assert_eq!(
            service.submit(&table, packet(5)),
            Err(GraphicsError::Sync(SyncError::NonMonotonic))
        );
        assert_eq!(service.fence_status(fence), Ok(FenceStatus::Unsignaled));
        assert!(service.pop_completion().is_none());

        let request = service.submit(&table, packet(6)).unwrap();
        assert_eq!(
            service.submit(&table, packet(7)),
            Err(GraphicsError::Busy),
            "one fence cannot be attached to two unresolved submissions"
        );
        assert_eq!(service.complete(request, true), Ok(1));
        assert_eq!(service.fence_status(fence), Ok(FenceStatus::Signaled));
        assert_eq!(service.wait_timeline(timeline, 6), Ok(TimelineStatus::Ready));
    }

    #[test]
    fn reset_with_pending_work_revokes_sync_and_import_state() {
        let mut table = MemoryCapabilityTable::<4>::new();
        let token = memory(&mut table);
        let mut service = test_service();
        let buffer = service
            .import_buffer(
                &table,
                token,
                BufferImport {
                    backing_start: 0x10_000,
                    size: 4096,
                    alignment: 256,
                    access: GraphicsMemoryAccess::ReadWrite,
                    opaque_device_range: 0x20_000,
                },
            )
            .unwrap();
        let fence = service.create_fence(false).unwrap();
        let timeline = service.create_timeline(0).unwrap();
        let request = service
            .submit(
                &table,
                QueuePacket {
                    op: 1,
                    work_units: 1,
                    buffer: Some(buffer),
                    image: None,
                    buffer_access: Some(GraphicsMemoryAccess::ReadWrite),
                    image_access: None,
                    fence: Some(fence),
                    timeline: Some((timeline, 1)),
                },
            )
            .unwrap();
        service.reset(ResetOutcome::Done, None).unwrap();
        assert_eq!(service.imported_buffer_bytes(), 0);
        assert_eq!(service.complete(request, true), Err(GraphicsError::NotFound));
        assert_eq!(service.fence_status(fence), Err(GraphicsError::NotFound));
        assert_eq!(
            service.wait_timeline(timeline, 0),
            Err(GraphicsError::NotFound)
        );
    }

    #[test]
    fn reset_revokes_imports_and_quarantine_rejects_new_work() {
        let mut table = MemoryCapabilityTable::<4>::new();
        let token = memory(&mut table);
        let mut service = test_service();
        service
            .import_buffer(
                &table,
                token,
                BufferImport {
                    backing_start: 0x10_000,
                    size: 4096,
                    alignment: 256,
                    access: GraphicsMemoryAccess::ReadWrite,
                    opaque_device_range: 0x20_000,
                },
            )
            .unwrap();
        let identity = service.reset(ResetOutcome::Done, None).unwrap();
        assert_eq!(identity.generation, 2);
        assert_eq!(service.imported_buffer_bytes(), 0);

        let mut quarantined = test_service();
        assert_eq!(
            quarantined.reset(ResetOutcome::TimedOut, Some(true)),
            Err(GraphicsError::Quarantined)
        );
        assert_eq!(
            quarantined.submit(
                &table,
                QueuePacket {
                    op: 1,
                    work_units: 1,
                    buffer: None,
                    image: None,
                    buffer_access: None,
                    image_access: None,
                    fence: None,
                    timeline: None,
                }
            ),
            Err(GraphicsError::Quarantined)
        );
    }

    #[test]
    fn wsi_and_input_share_the_service_boundary() {
        let mut service = test_service();
        let window = WindowId::new(1).unwrap();
        let surface = SurfaceId::new(2).unwrap();
        assert_eq!(
            service.register_window(
                window,
                WindowGeometry {
                    width: 800,
                    height: 600,
                    scale_milli: 1000,
                }
            ),
            Ok(1)
        );
        service
            .create_surface(
                surface,
                window,
                SurfaceCaps {
                    formats: vec![PixelFormat::B8g8r8a8Srgb],
                    present_modes: vec![crate::wsi::PresentMode::Fifo],
                    min_images: 2,
                    max_images: 2,
                },
            )
            .unwrap();
        assert_eq!(service.acquire_image(surface, 1), Ok(0));
        service.present_image(surface, 1, 0).unwrap();
        service
            .push_input(
                window,
                1,
                InputValue::PointerMove {
                    x_milli: 12_000,
                    y_milli: 3_000,
                },
            )
            .unwrap();
        assert_eq!(
            service.pop_input().unwrap().value,
            InputValue::PointerMove {
                x_milli: 12_000,
                y_milli: 3_000,
            }
        );
    }

    #[test]
    fn queue_and_completion_capacities_are_finite() {
        assert_eq!(QUEUE_CAPACITY, COMPLETION_CAPACITY);
        assert_eq!(MAX_IMPORTS, MAX_SYNC_OBJECTS);
    }

    #[test]
    fn image_import_quotas_alignment_and_device_ranges_fail_closed() {
        let mut table = MemoryCapabilityTable::<4>::new();
        table
            .grant(
                0x20_000,
                2,
                MemoryRights::READ,
                MemoryKind::Shared,
                BackingIdentity::new(8, 1).unwrap(),
            )
            .unwrap();
        let image_token = table
            .check(0x20_000, 2 * 4096, MemoryRights::READ, None)
            .unwrap();
        let mut service = test_service();
        let image = service
            .import_image(
                &table,
                image_token,
                ImageImport {
                    backing_start: 0x20_000,
                    size: 4096,
                    alignment: 256,
                    access: GraphicsMemoryAccess::ReadOnly,
                    width: 32,
                    height: 32,
                    format: PixelFormat::B8g8r8a8Srgb,
                    opaque_device_range: 0x40_000,
                },
            )
            .unwrap();
        assert_eq!(service.imported_image_bytes(), 4096);

        let buffer_token = table
            .check(0x20_000, 4096, MemoryRights::READ, Some(image.backing))
            .unwrap();
        assert_eq!(
            service.import_buffer(
                &table,
                buffer_token,
                BufferImport {
                    backing_start: 0x20_000,
                    size: 4096,
                    alignment: 256,
                    access: GraphicsMemoryAccess::ReadOnly,
                    opaque_device_range: 0x40_000,
                }
            ),
            Err(GraphicsError::Busy)
        );
        assert_eq!(
            service.import_image(
                &table,
                image_token,
                ImageImport {
                    backing_start: 0x20_000,
                    size: 4096,
                    alignment: 3,
                    access: GraphicsMemoryAccess::ReadOnly,
                    width: 32,
                    height: 32,
                    format: PixelFormat::B8g8r8a8Srgb,
                    opaque_device_range: 0x50_100,
                }
            ),
            Err(GraphicsError::InvalidImage)
        );
        service.revoke_import(image).unwrap();
        assert_eq!(service.imported_image_bytes(), 0);
    }

    #[test]
    fn fence_and_timeline_destruction_releases_slots() {
        let mut service = test_service();
        let fence = service.create_fence(false).unwrap();
        let timeline = service.create_timeline(0).unwrap();
        service.destroy_fence(fence).unwrap();
        service.destroy_timeline(timeline).unwrap();
        assert!(service.create_fence(false).is_ok());
        assert!(service.create_timeline(0).is_ok());
        assert_eq!(service.fence_status(fence), Err(GraphicsError::NotFound));
        assert_eq!(
            service.wait_timeline(timeline, 0),
            Err(GraphicsError::NotFound)
        );
        assert_eq!(
            service.validate_wsi(WsiSystem::Xcb),
            WsiCapabilityReport {
                system: WsiSystem::Xcb,
                complete: true,
                missing: vec![],
            }
        );
    }
}
