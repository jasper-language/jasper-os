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

`verification/issue43-pixel6a-support-matrix.tsv` 是机器检查源。检查器禁止把
source/license/firmware/security/EOL 未核实的项目标为 `approved`，也禁止
`redistribution=approved` 缺少仓库内证据。首批条目覆盖显示、GPU、UFS/IOMMU、
无线、PMIC、Android HAL 和 modem firmware，用于冻结边界与失败关闭规则。

## 当前缺口

2026-11-19 的实机盘点记录 323 个 vendor `.ko` 和 26 个 vendor HAL `.so`；当前
矩阵只冻结了关键类别，尚未逐模块完成 323 项 source revision、许可证、firmware
哈希、签名、漏洞响应和 EOL 审核。因此 D12 只能从 `missing` 推进为
`software-contract`，不能标记完成。

## 校验

```text
python3 scripts/check-issue43-support-matrix.py --self-test
python3 scripts/check-issue43-support-matrix.py
```
