# Issue #42 机制族审计台账

更新时间：2026-11-21。

状态：**final disposition complete**。25 个机制族全部获得
`implemented-tested` 或 `compat-retained` 最终裁决；不存在 `partial` 或
`research`。详细依据见 `docs/ISSUE-42-FINAL-DISPOSITION.md`。

## 目的

Issue #42 的最终裁决要求停止继续堆叠“优秀机制大全”，改为按固定结构追踪每个
真实差距。本轮将已有的 25 个机制族写入机器可查台账：

- `verification/issue42-mechanism-ledger.tsv`；
- `scripts/check-issue42-mechanism-ledger.py`。

## 台账结构

每行固定记录：

- 外部来源与对应兼容端点；
- 当前 Jasper 原生权威代码；
- 已覆盖能力；
- 覆盖状态：`implemented-tested`、`partial`、`research` 或
  `compat-retained`；
- 分层：`core`、`service`、`runtime`、`compat` 或 `verification`；
- 可点击、必须存在的仓库证据路径；
- 仍未关闭的工程门。

检查器要求 `M01..M25` 全部存在、顺序固定、无空字段、状态/分层值受控，且每个
证据路径当前真实存在。CI 以 `--final` 运行全表检查，额外要求所有机制族均已
最终裁决，且完成行明确声明本机制门已关闭。

## 当前统计

```text
implemented-tested=15
compat-retained=10
partial=0
research=0
total=25
```

`implemented-tested` 只描述 Jasper 原生通用机制，不表示外部兼容协议完整。
`compat-retained` 明确冻结必须留在兼容/服务层的协议。物理设备资格和完整
Activity 运行仍由各自专项持有独立退出门。

## 兼容关闭的 Profile 门

CI 新增 `scripts/check-native-ecosystem.py --dependency-tree`。它分别检查
`no-default-features`、默认和 `production` 三个 kernel 依赖树，要求均不包含
`jasper-compat-core` 或 `jasper-compat-loader`；同时要求 syscall、ELF 和动态
libc 验收特性只在显式启用时引入对应兼容组件。该检查证明构建依赖隔离，不证明
关闭兼容层后的原生 Pager/服务全链路已经运行。

## 最终门禁

- `compat-retained` 不得改成“内核已有同名结构”并据此新增重复原生 ABI；
- `implemented-tested` 行的 `remaining_gate` 必须以 `No Mxx` 开头并明确本机制门
  已关闭；
- 任何新的 `partial`、`research`、缺证据路径或退回未决状态都会使完整 CI 失败；
- Linux 383 个 syscall 枚举映射和 2 个 Jasper 扩展仍只证明分发表完整性，不能
  代替本台账的原生权威、故障语义和证据。
