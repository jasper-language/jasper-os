//! Linux graphics compatibility service over Jasper GPU and Memory mechanisms.
//!
//! 职责：验证 Vulkan 实例/设备能力、Vulkan WSI 与输入边界、设备内存导入、
//! GPU 提交/完成、fence/semaphore 世代以及 reset/revoke 资源生命周期。
//! 边界：本 crate 不实现 Vulkan 协议、不加载厂商 ICD、不执行像素或 GPU 命令，
//! 也不把策略记录当作真实硬件渲染。
//! Responsibility: fail-closed Linux graphics capability and resource adaptation.

#![no_std]

extern crate alloc;

mod service;
mod sync;
mod vulkan;
mod wsi;

pub use service::{
    BufferImport, FaceCullMode, GraphicsError, GraphicsLimit, GraphicsMemoryAccess, GraphicsService,
    ImageImport, ImportedBuffer, ImportedImage, MemoryHandle, PrimitiveTopology, QueuePacket,
};
pub use sync::{
    Fence, FenceStatus, Semaphore, SemaphoreWait, SyncError, TimelineSemaphore, TimelineStatus,
};
pub use vulkan::{
    dxvk_required_extensions, vkd3d_required_extensions, CapabilityError, CapabilityReport,
    DeviceCapabilities, ExtensionRequirement, InstancePlan, VulkanProfile, WsiCapabilityReport,
    WsiSystem,
};
pub use wsi::{
    InputEvent, InputValue, PixelFormat, PresentMode, SurfaceCaps, SurfaceId, WindowGeometry,
    WindowId, Wsi, WsiError,
};
