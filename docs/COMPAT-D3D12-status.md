# COMPAT-D3D-1 D3D12 状态

更新日期：2026-11-23。

状态：**core-passed；D3D12 fixture 已建立，Jasper 运行时尚未通过。**

本切片增加 VKD3D-Proton 3.1 的固定资产边界和 D3D12 离屏 probe，但不把
fixture 可构建、D3D11 通过或 host baseline 当作 D3D12 done。

## 固定基线

- VKD3D-Proton `3.1`，release 归档：
  `vkd3d-proton-3.1.tar.zst`；
- 归档大小 `5665978` bytes，SHA-256
  `b85ea8219b71093a3924913dd7aae6172333dc0c069983ed510816d67f02120b`；
- 上游许可 `LGPL-2.1`，后端为 Vulkan；
- `x64/d3d12.dll` 与 `x64/d3d12core.dll` 的 SHA-256 逐项固定在
  `verification/compat-d3d12.toml`。

`scripts/prepare-vkd3d-proton-tree.sh` 只接受上述归档；下载、摘要或 PE 头不符
都会失败关闭，不会用名称相同但来源不明的 DLL 继续验收。

## Probe 覆盖

`verification/fixtures/windows/d3d12_probe.c` 覆盖：

- `D3D12CreateDevice`；
- direct command queue、command allocator 和 graphics command list；
- default texture render target 与 descriptor heap/RTV；
- resource barrier、clear 和 copy to upload heap；
- fence/event completion；
- mapped readback，要求像素严格为 `32,64,128,255`；
- 成功时只输出 `D3D12_PROBE_OK pixel=32,64,128,255`。

`scripts/build-d3d12-probe.sh` 使用 `x86_64-w64-mingw32-gcc` 严格构建。当前
Jasper bounded user window 还不覆盖 Wine 随机化 PE 基址，因此该切片暂时使用
`--disable-dynamicbase`；这不代表通用 ASLR 已完成。

`scripts/prepare-wine-d3d-staging.py` 现在把固定 VKD3D-Proton DLL、D3D12 probe
和 WSI probe 一起装入独立的 `/opt/wine-devel` root。内核已有独立
`compat-wine-d3d12-verify` feature；对应启动模式为：

```text
ISSUE21_UEFI_MODE=compat-wine-d3d12
```

该模式要求字面量 `D3D12_PROBE_OK`、进程退出零和 `resources=true`。接线完成
不改变下方“尚未运行”的结论。

2026-11-22 已在隔离 Debian bookworm 容器中使用 MinGW-w64 GCC 12.2 实际交叉
编译，产物为 x86-64 PE32+ console executable。该结果仅证明 fixture 可构建。
证据见 `evidence/compat-d3d12-fixture-20261122/README.md`。

2026-11-23 的复现收敛修复：

- staging 最终文件清单加入固定版本的 `libvulkan.so.1`。此前只安装 lavapipe
  ICD 和 ICD JSON，Wine 的 `vulkan_init_once` 会直接报
  `Failed to load libvulkan.so.1`；
- D3D12/D3D11 WSI probe 使用 `--no-insert-timestamp` 构建，消除 PE 时间戳
  导致的不可复现摘要漂移；
- D3D12 probe 的宿主对照和 guest 诊断轮次使用 `--service-child` 直接执行
  离屏路径，以便把图形栈问题与服务桌面初始化问题分开。

同日的宿主对照运行修复了 probe 的 allocator 使用顺序，得到：

```text
D3D12_PROBE_OK pixel=32,64,128,255 observed=32,64,128,255 row_pitch=256
```

该结果证明 fixture、Wine/DXVK/VKD3D 和 lavapipe 在宿主控制路径上可用。

offscreen probe 的启动桌面修正为 Wine 当前桌面，不再强制首次 explorer
服务桌面。宿主仍通过；Jasper guest 在 2 GiB 和 4 GiB 下都越过 explorer
初始化，但 `D3D12CreateDevice` 仍失败为 `E_OUTOFMEMORY`。因此后续问题已经
收敛到 guest 内 D3D12/Vulkan 设备资源准入，而不是服务桌面或 VKD3D API
语义。

Jasper guest 仍为失败：在直接 service-child 诊断轮次中，加载
`d3d12.dll`、`d3d12core.dll`、DXVK 和 lavapipe 后，进程停在 DXVK/Vulkan
设备初始化，触发 12,076-tick deadline，退出码 124。该诊断发生在有意义的
VKD3D API 语义验收之前，不能据此宣称 Linux ABI 语义不一致。
证据见 `evidence/compat-wine-d3d12-r78/README.md`。

服务桌面路径的 guest 日志进一步定位到 PE 重定位不一致：

```text
explorer.exe: dynamic base 140000000 -> 7ff600000000 mapped at 0x300000000
[JSR-USER] task.faulted ... ip=0x7ff600011300 addr=0x7ff600011300
get_desktop_window failed to create desktop window
```

即 `explorer.exe` 的实际映射基址是 `0x300000000`，但服务桌面线程仍从原首选
基址下的入口 `0x7ff600011300` 启动。该失败发生在 PE 重定位/服务桌面入口一致性
验收，而不是 VKD3D 的设备语义；在修复并把错误映射变为 fail-closed 前，D3D12
和可见桌面都不能标为完成。

## 当前证据边界

已通过的是 D3D11 离屏核心：

```text
D3D11_PROBE_OK feature=0xb000 pixel=32,64,128,255
```

尚未运行或通过的是：

- VKD3D-Proton D3D12 probe 在 Jasper UEFI/QEMU 中执行；
- DXGI swapchain、WSI、present 和 presented pixels；
- 桌面窗口、焦点和真实输入；
- D3D12 allocator、fence、worker 和 mapping 的资源回收；
- 物理 GPU、Pixel 6a 和硬件显示验收。

因此 `COMPAT-D3D-1` 继续保持 `core-passed`，`COMPAT-CONFORMANCE-1` 仍不得
据此前移。

## 验证

```text
python3 scripts/check-compat-d3d12.py
bash scripts/prepare-vkd3d-proton-tree.sh
bash scripts/build-d3d12-probe.sh
```

前两项可在 host 上执行；probe 构建需要受信的 x86_64 MinGW 工具链。构建成功只
证明 fixture 可用，不证明 Jasper 中已执行。
