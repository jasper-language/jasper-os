# Issue #43：Pixel 6a 驱动兼容层实机清单

更新时间：2026-11-19。

状态：**只完成只读实机盘点与执行边界裁决；尚未完成 Linux/Android 驱动域，也不代表 Pixel 6a 原生驱动、UFS、GPU 或 HAL 已通过。**

## 实机事实

当前连接的实机只读信息：

| 项目 | 实测值 |
| --- | --- |
| 设备 | `Pixel 6a`，代号 `bluejay` |
| SoC/平台 | `gs101` |
| 系统 | Android 16，`BP4A.251205.006/14401865` |
| 内核 | `Linux 6.1.145-android14-11-gc1de4747ac59-ab14219743` |
| ABI | `arm64-v8a` |
| 设备节点 | DRM `card0`、`renderD128`；input `event0..event3` |
| 分区表 | A/B `boot`、`vendor_boot`、`vbmeta`、`dtbo`、`modem` 及 `super`、`userdata` 等 |
| vendor 模块 | `/vendor/lib/modules` 共 323 个 `.ko` |
| vendor HAL 库 | `/vendor/lib64/hw` 共 26 个 `.so` |

已观测到的关键模块包括：

- 显示/GPU/输入：`gs_panel`、`panel_samsung_s6e3fc3_p10`、`panel_common`、
  `mali_kbase`、`mali_pixel`、`abrolhos`、`lwis`、`fps_touch_handler`。
- 存储：`ufs-exynos-gs`、`samsung_iommu`、`samsung_iommu_group`。
- 网络/无线：`bcmdhd4389`、`cfg80211`、`bluetooth`、`hci_uart`。
- 电源/PMIC：多项 `max77779_*`、`slg51000_*`、`s2mpg10/11-*`。

模块存在或处于加载状态只证明库存事实，不证明许可证、源码可得性或可移植性。
实机 `/proc/modules` 中的 `(O)` 表示 out-of-tree，不能据此区分 GPL 源码模块与厂商二进制模块。

## 是否属于“官方开源驱动”

Google 通常发布匹配设备的 GKI 内核、设备内核和一部分厂商模块源码，但一个完整
Pixel 系统还包含厂商 HAL 二进制、签名 vendor 模块、DSP/GPU/基带固件以及
不可再分发的设备数据。因此应逐个模块核对：

1. 对应 build fingerprint 的 AOSP 内核源码分支；
2. 模块许可证与源码可用性；
3. 是否需要匹配的 GKI/KMI、符号版本和签名；
4. 是否有可在兼容环境外合法再分发的 firmware；
5. 是否依赖 Android vendor HAL、Binder 或 Trusty 服务。

不能因为模块来自官方设备镜像，就把它视为可以复制到公开仓库、任意重签名或直接
加载进 Jasper 原生内核的“开源驱动”。

## 可行接入方式

### 1. 隔离 Android/Linux 驱动域

首选路线是在匹配 `6.1.145-android14-11` GKI 的隔离 Linux/Android 驱动域运行
现有 vendor 模块。驱动域使用该设备实际的 `vendor_boot`、模块和 firmware，但
不能自行成为物理设备所有权或 Jasper 授权的事实源。

Jasper Device Broker 只授予驱动域经过验证的 MMIO、IRQ、DMA/IOMMU、设备代际和
生命周期。驱动域崩溃、超时或撤销时，必须先停止新请求、排空在飞请求、静止
DMA/IRQ，再回收资源。

### 2. HAL 只作为用户态兼容服务

`audio.primary.gs101`、`hwcomposer.gs101`、`mali`/gralloc、sensors 等 HAL 是
用户态库，不是 Jasper 内核驱动。它们只能在具备 Binder、HIDL/AIDL、gralloc、
共享内存和设备节点语义的 Android 兼容环境中执行。

当前 `compat-core`/`compat-loader` 提供 Linux 用户态 ELF/进程基础，但尚无完整
Binder、HAL 服务注册、Android 图形缓冲和驱动域接口，因此不能把 HAL `.so`
放进现有兼容层就宣称设备可用。

### 3. Jasper 原生应用路径

Jasper 原生应用只使用 Jasper 原生系统 ABI。驱动域或 Android HAL Adapter 是
现有 Device Service / Driver Host 的后端实现，不新增第二套设备所有权或授权
模型。厂商 ioctl/HAL 私有协议仍由兼容层解释，不能进入 Jasper 原生内核 ABI。

## 启动依赖裁决

Pixel 6a 的 `super`/`userdata` 位于 UFS。UFS 驱动和 `samsung_iommu` 不能被
依赖“系统启动完成后再启动”的 Android 兼容域承担，否则形成启动依赖环。

- Jasper 启动盘和更新写入仍需要原生 UFS、受控早期驱动域或经验证的救援路径。
- 后启动的 Android GKI/vendor 模块可以服务已经启动后的相机、音频、传感器等设备，
  不能自动解除 Pixel 6a UFS/LC-4 阻塞。
- 在没有可靠 IOMMU、reset 和 DMA 静止时，不把块设备直通描述为安全方案。

## 首批兼容后端候选

顺序按启动风险和可验证性排列：

1. **传感器/输入只读 Provider**：使用现有 Android HAL 或隔离驱动域，验证服务死亡、
   取消和权限拒绝，不写启动关键分区。
2. **音频 Provider**：验证 HAL、共享内存缓冲、DMA 在飞与崩溃恢复。
3. **显示/GPU Provider**：验证 DRM/gralloc/composer 链、缓冲区所有权和 reset；
   在此之前 Jasper UI 的兼容后端不能冒充实机显示完成。
4. **UFS/启动链**：单独走原生或早期驱动域路线，不能依赖普通 Android HAL。

## 验收门槛

- 驱动域的 GKI/KMI、build fingerprint、模块签名和 firmware 版本必须可追溯。
- 至少一个真实设备调用链由 Jasper 原生 ABI 发起，经现有 Device Service/Driver Host
  到达 Android/Linux 后端，并返回真实数据或明确不支持。
- 未授权请求、错误代际、服务崩溃、取消、超时、DMA 在飞和设备 reset 均失败关闭。
- 禁用全部兼容后端后，Jasper 原生调度、终端、Device Broker 和 Driver Host 仍运行。
- vendor 二进制和私有 firmware 不进入公开仓库；只登记来源、哈希、许可证与安装步骤。
- QEMU、HAL 加载成功或驱动模块加载成功都不能替代真实设备操作验收。

## 当前结论

可以在 Android/Linux 兼容驱动域中复用 Pixel 6a 的官方 GKI、vendor 模块和 HAL，
但不能把 Android `.ko` 直接加载进 Jasper 原生内核，也不能仅靠安装一个 APK/驱动包
完成兼容。当前仓库尚未实现可运行的驱动域和 Android Binder/HAL 宿主，因此本清单
只是 Issue #43 的真实设备输入与后续实现契约，不是驱动兼容完成证据。
