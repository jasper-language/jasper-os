# Issue #36/#37：GPU ABI 与 UI 服务边界

更新日期：2026-11-17。

## 已确认方向

- Vulkan 是当前唯一官方原生 GPU 图形/计算 API，但它不是内核 GPU 机制的对象模型。
- `system.gpu.*` 只描述真实设备、授权、内存、队列、同步、撤销、复位和审计，不暴露
  `VkInstance`、`VkDevice`、`VkDeviceMemory`、`VkQueue` 等 Vulkan 对象。
- `service.graphics.*` 保持公共图形服务语义；`service.graphics.vulkan.*` 才是 Vulkan
  Loader/ICD 部署、选择、健康、版本和策略治理的专属服务命名域。
- `service.ui.*` 不包含 Vulkan 句柄或后端选择。Jasper UI Engine 必须作为独立用户态
  UI Service 集成，不进入内核，也不因 GPU 后端缺失而替代 CPU/救援 Console。
- Linux `compat-graphics`、DXVK、VKD3D-Proton 和 Metal2Vulkan 属于可选兼容/转换层，
  不升级为 Jasper 原生底层 ABI。

## 当前源码事实

- `kernel-core/src/hwv7.rs` 使用 `GpuBackend`、`GpuIdentity`、`GpuQueue`、
  `GpuRequest`、`Completion` 和 `MemoryTier` 等后端中立类型；当前没有 `Vk*` 类型。
- `compat-graphics` 明确是 Vulkan/Linux/Windows 兼容层，不位于内核 ABI。
- `abi/system-ids.txt` 当前没有登记 `system.gpu.*` 操作，只有通用
  `system.gpu.error.*` 错误名；后续操作必须先完成资源、权属、generation、错误和
  生命周期设计再登记。
- 当前内核和 `kernel-core` 不链接 `ash`、`vulkano`、`wgpu`、Blitz、Vello、Parley、
  Jasper UI Engine 或 Jasper UI Framework。
- Jasper UI Engine 的用户态宿主、真实 IPC、Surface/输入和更新闭环尚未交付；CPU
  compositor/framebuffer 不能冒充正式 UI Service。

## 可执行门禁

`scripts/check-gpu-abi-boundary.py` 在 CI 中验证：

1. `system.gpu.*` 和 `service.ui.*` 操作名不得包含 Vulkan/Vk API 名称；
2. `kernel`、`kernel-core` 的 GPU 相关生产源码不得出现 Vulkan 对象类型；
3. 内核层不得链接 UI Engine、Blitz、Vello、Parley、wgpu 或 Vulkan 高层 API crate；
4. 门禁自身包含泄漏与误报测试。

该门禁只证明当前命名和依赖边界；完整 Vulkan Loader/驱动/WSI、真实 GPU 和 UI Service
端到端仍需 DAG 与硬件证据。Virtio-gpu 2D、CPU 软件绘制、Linux SwiftShader 或宿主
成功都不能替代这些验收。
