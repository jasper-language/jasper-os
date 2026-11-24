# Linux Vulkan 图形兼容状态

更新日期：2026-11-24。

状态：**core-passed**。Vulkan 能力、WSI 状态机、输入、设备内存导入、GPU
提交/完成、fence/timeline 和 reset 已有可执行核心；真实 Linux Vulkan loader +
SwiftShader ICD 的 compute 路径已在 Jasper root 中执行，Metal2Vulkan v0.2.0
render-to-texture 也已在 Mesa lavapipe 上通过精确像素回读。物理 GPU、
硬件 WSI、可见 present 和 DXVK/VKD3D 硬件路径仍未完成。

## 分层边界

- Linux Vulkan/WSI 名称只存在于兼容层，不进入 Jasper 原生内核 ABI；
- Vulkan ABI 类型复用成熟 `ash` 定义；
- GPU 提交复用 `kernel-core::hwv7::GpuQueue` 的请求、completion、世代和撤销规则；
- 窗口、surface、输入、fence、semaphore 和内存导入均使用有界容量与严格世代；
- 软件 Vulkan 结果不能冒充物理 GPU、硬件显示、DMA/IOMMU 或性能证据。

## 已交付核心

- 从运行时查询生成物理设备能力快照，未知扩展、空名称和非法版本失败关闭；
- 检查 Xlib、XCB、Wayland surface 扩展，以及 DXVK/VKD3D 所需能力基线；
- 维护 window/surface/swapchain 图像轮转、resize 撤销和输入世代隔离；
- 验证设备内存 capability、backing、范围、访问方向、地址重叠和配额；
- GPU submit、completion/cancel、binary/timeline semaphore 与 fence 终态一致；
- reset 清空导入、在飞工作、同步和配额；无法证明静默时隔离资源。

## 软件 Vulkan loader/ICD 执行

`scripts/compat-graphics-software-check.sh` 将现有软件 Vulkan 路径固定成可复现
门禁：

- 先校验 upstream Vulkan loader、SwiftShader ICD、compat DSO、AIR fixture 与两个
  upstream `metal2vulkan` 示例的 `SHA256SUMS`；
- 在真实 OVMF/virtio-blk Jasper root userland 中设置
  `VK_DRIVER_FILES`/`VK_ICD_FILENAMES`，运行未修改的 upstream
`compute_dispatch`；
- 成功必须看到 compute 输出 `[0.0, 3.0, 6.0, 9.0]`、进程
  `exit_zero=true`、资源回到基线且没有 panic/ABI fault。

这条软件链证明 `libvulkan.so.1`、软件 ICD、Vulkan command dispatch 和像素读回
中的 compute 路径在 Jasper 中真实执行；SwiftShader 是 CPU 设备，不是物理 GPU
验收。

2026-11-24 的 Metal2Vulkan v0.2.0 验收使用未修改的上游 examples、Linux
Vulkan loader 和 Mesa lavapipe：

```text
device: llvmpipe (LLVM 21.1.8, 256 bits)
output[0..4] = [0.0, 3.0, 6.0, 9.0], ..., output[999] = 2997: as expected
every texel as expected: the top-left quarter drawn, the rest cleared
program=metal2vulkan-render syscalls=3718 exit_zero=true
frames_before=941344 resources=true failed=0
```

该 render 路径真实执行 render pipeline、private texture、clear、draw、
texture-to-buffer copy、fence 和 mapped pixel readback。它不代表可见
swapchain/present、物理 GPU 或硬件显示。证据见
`evidence/compat-metal2vulkan-v020-r21-lavapipe/README.md`。

SwiftShader render 仍有一条独立失败：其 JIT 代码读取已经 `munmap` 的匿名
分配并 page fault。该失败没有被 lavapipe 成功掩盖；两种后端分别记录。

## 验证

```text
cargo test --locked -p jasper-compat-graphics
19 passed; 0 failed

cargo check --locked -p jasper-compat-graphics --target x86_64-unknown-none
PASS

COMPAT_GRAPHICS_CHECK_ONLY=1 bash scripts/compat-graphics-software-check.sh
compat-graphics-software: ASSETS PASS

bash scripts/compat-graphics-software-check.sh
compat-graphics-software: PASS loader=true icd=swiftshader compute=true render=false resources=true hardware_gpu=false
```

机器矩阵见 `verification/linux-graphics-compat.toml`。

## 未完成门

- 物理 GPU 的厂商 ICD、真实 DRM/X11/XCB/Wayland surface 和硬件 presented pixels；
- `metal2vulkan-render` 可见 WSI/present 闭环；
- 真实 GPU 页表、DMA-BUF/FD 导入、IOMMU 激活与 cache 一致性；
- Vulkan command buffer 在物理 GPU 上执行 shader、拷贝和像素校验；
- reset 前后的 FLR、IOMMU、SR-IOV/mdev、DMA/IRQ 静默；
- DXVK/VKD3D-Proton 的物理 GPU、WSI 和 conformance；软件路径由
  `verification/compat-d3d12.toml` 与 WSI 证据独立验收；
- Wine + DXVK/VKD3D-Proton 的真实硬件性能。

因此 `COMPAT-GRAPHICS-1` 保持 `core-passed`。
