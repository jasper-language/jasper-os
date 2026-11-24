# COMPAT-D3D-1 D3D12 状态

更新日期：2026-11-24。

状态：**core-passed；Jasper/QEMU/lavapipe 的 D3D12 离屏运行时已通过。**

本节点固定 VKD3D-Proton 3.1 资产边界，并已在真实 Jasper Linux ABI 和 Wine
进程内完成 D3D12 离屏渲染、fence 等待、映射回读及稳态资源回收。该结果是
软件 Vulkan（Mesa lavapipe）验收，不把 fixture、D3D11、宿主对照或 QEMU
软件 ICD 当成物理 GPU、D3D12 WSI 或全面 conformance 完成。

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

该模式要求字面量 `D3D12_PROBE_OK`、进程退出零和 `resources=true`。第一次
执行建立 Wine prefix 和 compat cache，第二次执行作为稳态验收。

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

2026-11-24 的 r143 已完成 Jasper guest 运行时验收：

```text
D3D12_PROBE_OK pixel=32,64,128,255 observed=32,64,128,255 row_pitch=256
```

第二次稳态运行结果：

```text
program=compat-wine-d3d12 syscalls=32690 exit_zero=true
frames_before=940409 resources=true failed=0
[JSR-LIFE-HEALTH] result=root_execution_complete
```

此前的 `E_OUTOFMEMORY` 已定位到 Linux compat heap 固定 64 MiB 虚拟窗口。
r143 的 VKD3D 分配越过原窗口后仍由动态 ceiling 接纳：

```text
requested=0x10001458e000 current=0x10001456b000 ceiling=0x100040000000
```

该 ceiling 来自当前进程的 live mapping/reservation，物理帧和进程配额仍由
原有内核准入执行。修复不是 VKD3D 专用旁路。证据见
`evidence/compat-wine-d3d12-r143-steady-state/README.md`。

servicedesktop 启动期间仍有一个 Wine helper 在 PE 首选基址
`0x7ff600003670` 页故障；主 D3D12 probe 随后继续并通过。因此该 helper
问题保留为 Wine 桌面/loader 缺陷，不能用 D3D12 离屏通过来掩盖。

offscreen probe 的启动桌面修正为 Wine 当前桌面，不再强制首次 explorer
服务桌面。宿主仍通过；Jasper guest 在 2 GiB 和 4 GiB 下都越过 explorer
初始化，但 `D3D12CreateDevice` 仍失败为 `E_OUTOFMEMORY`。因此后续问题已经
收敛到 guest 内 D3D12/Vulkan 设备资源准入，而不是服务桌面或 VKD3D API
语义。

后续 r109 在 D3D12 验证环境中禁用 explorer，并把虚拟文件物化从逐页加锁
写改为有界批量写。本轮不再得到先前的 `E_OUTOFMEMORY`，但 Wine 在
headless desktop fallback 后停在等待路径，最终触发 12,076-tick deadline。
由于没有 `D3D12_PROBE_OK` 或 `D3D12_PROBE_FAIL`，本轮仍不是 VKD3D/Vulkan
语义结论。证据见 `evidence/compat-wine-d3d12-r109/README.md`。

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

已通过的是 VKD3D-Proton 3.1 D3D12 离屏运行时：

- default texture、RTV、barrier、clear、copy、fence 和 mapped readback；
- 第二次稳态运行的零物理帧保留和 `resources=true`。

尚未通过的是：

- DXGI swapchain、WSI、present 和 presented pixels；
- 桌面窗口、焦点和真实输入；
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
