# Issue #43：Pixel 6a 驱动支持与再分发矩阵

更新时间：2026-11-20。

状态：**软件治理门已建立，实机模块清单仍未闭合。** 本文件冻结每个驱动的
来源、许可证、firmware 来源、再分发、安全响应和 EOL 审核字段，不宣称任何
vendor 模块已经可以公开再分发或直接加载进 Jasper 原生内核。

## 为什么需要矩阵

“来自 Google 官方设备镜像”不等于源码可用、许可证允许再分发，也不等于可以跨
GKI/KMI 或重签名加载。矩阵必须逐模块回答：

- 对应 build fingerprint 的上游或 device 内核源码 revision；
- 许可证以及是否存在混合或专有部分；
- 是否包含 firmware、DSP、GPU、基带或签名 vendor 负载；
- 是否允许随 Jasper 仓库、测试镜像或刷机包再分发；
- 漏洞响应渠道、固定状态和 end-of-support 判断；
- 当前验证状态；字段不完整时只能保持 `verification-required`。

`verification/issue43-pixel6a-support-matrix.tsv` 是机器检查源。台账现在逐个
覆盖 318 个 vendor kernel module 和 26 个 vendor HAL；从设备清单新增的条目默认
保持 `source=unknown`、`license=unverified`、`redistribution=denied` 和
`verification-required`。检查器同时验证清单覆盖和确定性生成，禁止把
source/license/firmware/security/EOL 未核实的项目标为 `approved`，也禁止
`redistribution=approved` 缺少仓库内证据。首批条目覆盖显示、GPU、UFS/IOMMU、
无线、PMIC、Android HAL 和 modem firmware，用于冻结边界与失败关闭规则。

## 当前缺口

2026-11-21 的实机盘点由
`scripts/collect-issue43-pixel6a-inventory.sh` 生成
`verification/issue43-pixel6a-binary-inventory.tsv`：完整枚举 318 个 vendor
`.ko`、5 个模块加载元数据和 26 个 vendor HAL `.so`，并记录 build fingerprint、
kernel release、可读取项的 SHA-256/大小以及 `/proc/modules` 加载状态。本次
快照中有 313 个模块已加载；仅 4 个文件可由 adb shell 读取。

该生产构建不允许 adb shell 读取多数 vendor 二进制，因此不可读取项明确记为
`unreadable-by-adb-shell`，不得用镜像名称或加载状态推断许可证、源码 revision、
firmware 哈希、签名或再分发权限。当前矩阵已逐项覆盖全部模块与 HAL 名称，但
绝大多数条目仍是未核实占位记录；D12 继续为 `software-contract`，完整 349 项
来源、许可证、漏洞响应和 EOL 审核仍是硬门。

## 校验

```text
python3 scripts/check-issue43-support-matrix.py --self-test
python3 scripts/check-issue43-support-matrix.py
python3 scripts/generate-issue43-support-matrix.py --check
```
