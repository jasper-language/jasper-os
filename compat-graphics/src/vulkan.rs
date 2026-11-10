//! Vulkan capability negotiation without loading a vendor ICD.
//!
//! 职责：使用成熟 Vulkan ABI 类型表达实例、设备和扩展能力，并核对 DXVK /
//! VKD3D-Proton 所需能力。边界：不伪造物理设备，不加载 libvulkan 或 ICD。
//! Responsibility: truthful Vulkan capability negotiation and extension accounting.

use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::CStr;
use core::ptr;

use ash::vk;
use kernel_core::hwv7::GpuBackend;

const VK_API_VERSION_1_1: u32 = vk::make_api_version(0, 1, 1, 0);
const VK_API_VERSION_1_2: u32 = vk::make_api_version(0, 1, 2, 0);
const VK_API_VERSION_1_3: u32 = vk::make_api_version(0, 1, 3, 0);

/// One extension required, recommended or forbidden by a compatibility profile.
///
/// 一个兼容配置要求、建议或明确禁止的 Vulkan 扩展。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtensionRequirement {
    pub name: &'static str,
    pub required: bool,
    pub promoted_in: Option<u32>,
}

impl ExtensionRequirement {
    const fn required(name: &'static str) -> Self {
        Self {
            name,
            required: true,
            promoted_in: None,
        }
    }

    const fn required_core(name: &'static str, version: u32) -> Self {
        Self {
            name,
            required: true,
            promoted_in: Some(version),
        }
    }

    const fn recommended(name: &'static str) -> Self {
        Self {
            name,
            required: false,
            promoted_in: None,
        }
    }
}

/// Linux graphics compatibility profiles whose extension needs are tracked separately.
///
/// 分别追踪扩展需求的 Linux 图形兼容配置。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VulkanProfile {
    DxvkD3D9To11,
    Vkd3dProtonD3D12,
}

/// Linux display protocol used by a Vulkan WSI instance.
///
/// Vulkan WSI 实例使用的 Linux 显示协议。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WsiSystem {
    Xlib,
    Xcb,
    Wayland,
}

/// Instance-extension report for one Linux WSI protocol.
///
/// 一种 Linux WSI 协议的实例扩展检查结果。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WsiCapabilityReport {
    pub system: WsiSystem,
    pub complete: bool,
    pub missing: Vec<&'static str>,
}

/// Result of checking one profile against a real capability declaration.
///
/// 对真实能力声明检查一个兼容配置后的结果。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityReport {
    pub profile: VulkanProfile,
    pub complete: bool,
    pub missing_required: Vec<&'static str>,
    pub missing_recommended: Vec<&'static str>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityError {
    InvalidApiVersion,
    DuplicateExtension,
    InvalidExtensionName,
    ProfileIncomplete,
}

/// Vulkan-facing capabilities reported by a Jasper physical-device backend.
///
/// Jasper 物理设备后端报告的 Vulkan 能力。扩展列表必须来自实际设备查询；
/// 调用者不能用策略期望替代 `vkEnumerateDeviceExtensionProperties`。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceCapabilities {
    backend: GpuBackend,
    api_version: u32,
    driver_version: u32,
    device_name: String,
    instance_extensions: Vec<&'static str>,
    device_extensions: Vec<&'static str>,
}

impl DeviceCapabilities {
    /// Creates a capability snapshot from queried runtime values.
    ///
    /// 使用运行时真实查询值创建能力快照；重复、空或含 NUL 的扩展名失败关闭。
    pub fn new(
        backend: GpuBackend,
        api_version: u32,
        driver_version: u32,
        device_name: String,
        instance_extensions: Vec<&'static str>,
        device_extensions: Vec<&'static str>,
    ) -> Result<Self, CapabilityError> {
        if api_version < VK_API_VERSION_1_1 || device_name.is_empty() {
            return Err(CapabilityError::InvalidApiVersion);
        }
        validate_extensions(&instance_extensions)?;
        validate_extensions(&device_extensions)?;
        Ok(Self {
            backend,
            api_version,
            driver_version,
            device_name,
            instance_extensions,
            device_extensions,
        })
    }

    pub const fn backend(&self) -> GpuBackend {
        self.backend
    }

    pub const fn api_version(&self) -> u32 {
        self.api_version
    }

    pub const fn driver_version(&self) -> u32 {
        self.driver_version
    }

    pub fn device_name(&self) -> &str {
        &self.device_name
    }

    pub fn instance_extensions(&self) -> &[&'static str] {
        &self.instance_extensions
    }

    pub fn device_extensions(&self) -> &[&'static str] {
        &self.device_extensions
    }

    /// Checks one profile against core promotion rules and queried extensions.
    ///
    /// 按 Vulkan 核心版本提升规则和设备扩展查询结果检查一个兼容配置。
    pub fn validate_profile(&self, profile: VulkanProfile) -> CapabilityReport {
        let requirements = profile_requirements(profile);
        let mut missing_required = Vec::new();
        let mut missing_recommended = Vec::new();
        for requirement in requirements {
            let promoted = requirement
                .promoted_in
                .is_some_and(|version| self.api_version >= version);
            if promoted || self.device_extensions.contains(&requirement.name) {
                continue;
            }
            if requirement.required {
                missing_required.push(requirement.name);
            } else {
                missing_recommended.push(requirement.name);
            }
        }
        CapabilityReport {
            profile,
            complete: missing_required.is_empty(),
            missing_required,
            missing_recommended,
        }
    }

    /// Checks the instance extensions needed by one Linux display protocol.
    ///
    /// 检查一种 Linux 显示协议所需的 Vulkan 实例扩展。
    pub fn validate_wsi(&self, system: WsiSystem) -> WsiCapabilityReport {
        let requirements = match system {
            WsiSystem::Xlib => &["VK_KHR_surface", "VK_KHR_xlib_surface"][..],
            WsiSystem::Xcb => &["VK_KHR_surface", "VK_KHR_xcb_surface"][..],
            WsiSystem::Wayland => &["VK_KHR_surface", "VK_KHR_wayland_surface"][..],
        };
        let missing = requirements
            .iter()
            .copied()
            .filter(|extension| !self.instance_extensions.contains(extension))
            .collect::<Vec<_>>();
        WsiCapabilityReport {
            system,
            complete: missing.is_empty(),
            missing,
        }
    }

    /// Creates the Vulkan instance description after checking requested extensions.
    ///
    /// 检查请求的实例扩展后生成 Vulkan 实例描述；未报告的扩展拒绝启用。
    pub fn plan_instance(
        &self,
        requested_api_version: u32,
        requested_extensions: &[&'static str],
    ) -> Result<InstancePlan, CapabilityError> {
        if requested_api_version < VK_API_VERSION_1_1 || requested_api_version > self.api_version {
            return Err(CapabilityError::InvalidApiVersion);
        }
        validate_extensions(requested_extensions)?;
        if requested_extensions
            .iter()
            .any(|extension| !self.instance_extensions.contains(extension))
        {
            return Err(CapabilityError::ProfileIncomplete);
        }
        Ok(InstancePlan {
            api_version: requested_api_version,
            enabled_extensions: requested_extensions.to_vec(),
        })
    }
}

/// Validated Vulkan instance plan for the Linux loader.
///
/// 经能力校验的 Linux Vulkan loader 实例计划。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstancePlan {
    api_version: u32,
    enabled_extensions: Vec<&'static str>,
}

impl InstancePlan {
    pub const fn api_version(&self) -> u32 {
        self.api_version
    }

    pub fn enabled_extensions(&self) -> &[&'static str] {
        &self.enabled_extensions
    }

    /// Builds the stable Vulkan `VkApplicationInfo` layout from mature ash definitions.
    ///
    /// 使用成熟 ash 定义构造稳定的 Vulkan `VkApplicationInfo` 布局。
    pub fn application_info(&self) -> vk::ApplicationInfo<'static> {
        const APPLICATION: &CStr = c"Jasper Linux Application";
        const ENGINE: &CStr = c"Jasper Vulkan Compatibility";
        vk::ApplicationInfo {
            s_type: vk::StructureType::APPLICATION_INFO,
            p_next: ptr::null(),
            p_application_name: APPLICATION.as_ptr(),
            application_version: vk::make_api_version(0, 1, 0, 0),
            p_engine_name: ENGINE.as_ptr(),
            engine_version: vk::make_api_version(0, 1, 0, 0),
            api_version: self.api_version,
            _marker: core::marker::PhantomData,
        }
    }
}

fn validate_extensions(extensions: &[&'static str]) -> Result<(), CapabilityError> {
    for (index, extension) in extensions.iter().enumerate() {
        if extension.is_empty() || extension.as_bytes().contains(&0) {
            return Err(CapabilityError::InvalidExtensionName);
        }
        if extensions[..index].contains(extension) {
            return Err(CapabilityError::DuplicateExtension);
        }
    }
    Ok(())
}

/// Required Vulkan device extensions for DXVK Direct3D 9–11.
///
/// DXVK Direct3D 9–11 所需的 Vulkan 设备扩展基线。
pub const fn dxvk_required_extensions() -> &'static [ExtensionRequirement] {
    &DXVK_REQUIRED
}

/// Required Vulkan device extensions for VKD3D-Proton Direct3D 12.
///
/// VKD3D-Proton Direct3D 12 所需的 Vulkan 设备扩展基线。
pub const fn vkd3d_required_extensions() -> &'static [ExtensionRequirement] {
    &VKD3D_REQUIRED
}

fn profile_requirements(profile: VulkanProfile) -> &'static [ExtensionRequirement] {
    match profile {
        VulkanProfile::DxvkD3D9To11 => dxvk_required_extensions(),
        VulkanProfile::Vkd3dProtonD3D12 => vkd3d_required_extensions(),
    }
}

const DXVK_REQUIRED: [ExtensionRequirement; 12] = [
    ExtensionRequirement::required("VK_KHR_swapchain"),
    ExtensionRequirement::required_core("VK_KHR_maintenance1", VK_API_VERSION_1_1),
    ExtensionRequirement::required_core(
        "VK_KHR_sampler_mirror_clamp_to_edge",
        VK_API_VERSION_1_2,
    ),
    ExtensionRequirement::required_core(
        "VK_KHR_shader_draw_parameters",
        VK_API_VERSION_1_1,
    ),
    ExtensionRequirement::required_core("VK_KHR_draw_indirect_count", VK_API_VERSION_1_2),
    ExtensionRequirement::required_core("VK_KHR_descriptor_indexing", VK_API_VERSION_1_2),
    ExtensionRequirement::required_core("VK_KHR_buffer_device_address", VK_API_VERSION_1_2),
    ExtensionRequirement::required_core("VK_KHR_timeline_semaphore", VK_API_VERSION_1_2),
    ExtensionRequirement::required_core("VK_KHR_synchronization2", VK_API_VERSION_1_3),
    ExtensionRequirement::required_core("VK_KHR_dynamic_rendering", VK_API_VERSION_1_3),
    ExtensionRequirement::required_core("VK_KHR_copy_commands2", VK_API_VERSION_1_3),
    ExtensionRequirement::recommended("VK_EXT_custom_border_color"),
];

const VKD3D_REQUIRED: [ExtensionRequirement; 13] = [
    ExtensionRequirement::required("VK_KHR_swapchain"),
    ExtensionRequirement::required_core("VK_KHR_maintenance1", VK_API_VERSION_1_1),
    ExtensionRequirement::required_core(
        "VK_KHR_shader_draw_parameters",
        VK_API_VERSION_1_1,
    ),
    ExtensionRequirement::required_core("VK_KHR_draw_indirect_count", VK_API_VERSION_1_2),
    ExtensionRequirement::required_core("VK_KHR_descriptor_indexing", VK_API_VERSION_1_2),
    ExtensionRequirement::required_core("VK_KHR_buffer_device_address", VK_API_VERSION_1_2),
    ExtensionRequirement::required_core("VK_KHR_timeline_semaphore", VK_API_VERSION_1_2),
    ExtensionRequirement::required_core("VK_KHR_synchronization2", VK_API_VERSION_1_3),
    ExtensionRequirement::required_core("VK_KHR_dynamic_rendering", VK_API_VERSION_1_3),
    ExtensionRequirement::required_core("VK_KHR_copy_commands2", VK_API_VERSION_1_3),
    ExtensionRequirement::required_core("VK_KHR_create_renderpass2", VK_API_VERSION_1_2),
    ExtensionRequirement::required_core("VK_EXT_descriptor_indexing", VK_API_VERSION_1_2),
    ExtensionRequirement::recommended("VK_EXT_robustness2"),
];

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn capabilities(api_version: u32, extensions: Vec<&'static str>) -> DeviceCapabilities {
        DeviceCapabilities::new(
            GpuBackend::VirtioGpu,
            api_version,
            1,
            String::from("Jasper test GPU"),
            vec!["VK_KHR_surface", "VK_KHR_xcb_surface"],
            extensions,
        )
        .unwrap()
    }

    #[test]
    fn profile_reports_missing_required_extensions_without_fake_success() {
        let capabilities = capabilities(VK_API_VERSION_1_1, vec!["VK_KHR_swapchain"]);
        let report = capabilities.validate_profile(VulkanProfile::Vkd3dProtonD3D12);
        assert!(!report.complete);
        assert!(report
            .missing_required
            .contains(&"VK_KHR_timeline_semaphore"));
        assert!(report.missing_recommended.contains(&"VK_EXT_robustness2"));
    }

    #[test]
    fn vulkan_1_3_core_promotions_satisfy_promoted_requirements() {
        let capabilities = capabilities(
            VK_API_VERSION_1_3,
            vec![
                "VK_KHR_swapchain",
                "VK_KHR_maintenance1",
                "VK_KHR_shader_draw_parameters",
                "VK_KHR_draw_indirect_count",
            ],
        );
        let report = capabilities.validate_profile(VulkanProfile::Vkd3dProtonD3D12);
        assert!(report.complete);
        assert!(report.missing_required.is_empty());
    }

    #[test]
    fn instance_plan_rejects_unqueried_extensions_and_builds_ash_layout() {
        let capabilities = capabilities(VK_API_VERSION_1_3, vec![]);
        let plan = capabilities
            .plan_instance(
                VK_API_VERSION_1_3,
                &["VK_KHR_surface", "VK_KHR_xcb_surface"],
            )
            .unwrap();
        let info = plan.application_info();
        assert!(info.s_type == vk::StructureType::APPLICATION_INFO);
        assert_eq!(info.api_version, VK_API_VERSION_1_3);
        assert!(!info.p_application_name.is_null());
        assert_eq!(
            capabilities.plan_instance(VK_API_VERSION_1_3, &["VK_KHR_wayland_surface"]),
            Err(CapabilityError::ProfileIncomplete)
        );
        assert_eq!(
            capabilities.validate_wsi(WsiSystem::Xcb),
            WsiCapabilityReport {
                system: WsiSystem::Xcb,
                complete: true,
                missing: vec![],
            }
        );
        assert!(!capabilities.validate_wsi(WsiSystem::Wayland).complete);
    }

    #[test]
    fn duplicate_empty_and_nul_extensions_fail_closed() {
        assert_eq!(
            DeviceCapabilities::new(
                GpuBackend::VirtioGpu,
                VK_API_VERSION_1_3,
                1,
                String::from("GPU"),
                vec!["VK_KHR_surface", "VK_KHR_surface"],
                vec![],
            ),
            Err(CapabilityError::DuplicateExtension)
        );
        assert_eq!(
            DeviceCapabilities::new(
                GpuBackend::VirtioGpu,
                VK_API_VERSION_1_3,
                1,
                String::from("GPU"),
                vec![""],
                vec![],
            ),
            Err(CapabilityError::InvalidExtensionName)
        );
    }
}
