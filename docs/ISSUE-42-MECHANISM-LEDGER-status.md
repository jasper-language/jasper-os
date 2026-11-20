# Issue #42 机制族审计台账

更新时间：2026-11-20。

状态：**research ledger complete; engineering acceptance remains open**。

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
证据路径当前真实存在。CI 同时运行 self-test 和全表检查，防止后续新增兼容入口
或删除机制族时静默遗漏。

## 当前统计

```text
partial=23
research=1
compat-retained=1
implemented-tested=0
total=25
```

`implemented-tested=0` 是刻意结果：这 25 族都是跨多层、跨生命周期的机制，
不存在仅凭一个内核状态机或一条 QEMU 日志便可标为全量完成的族。

## 不代表完成

- `compat-retained` 表示该语义应永久留在版本化兼容层，例如 POSIX signal frame；
- `research` 表示设计/最低切片已存在，但真实原生消费方、ABI 准入或硬件证据不足，
  当前主要是 M08 Pager；
- `partial` 表示复用已有对象/等待/内存/设备/安全机制取得实质进展，但至少一个
  生产消费链、故障矩阵、跨域恢复或物理设备门仍未关闭；
- Linux 383 个 syscall 枚举映射和 2 个 Jasper 扩展仍只证明分发表完整性，不能
  代替此台账的真实证据。
