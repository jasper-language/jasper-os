# Issue #42 M25：原生 trace 因果关联与丢失账务

更新时间：2026-11-21。

状态：**核心切片完成；M25 仍为 partial。**

## 边界

本切片只增强可丢弃的原生性能/诊断 trace，不创建 ptrace、uprobe 或 ETW
兼容 ABI，也不把 trace 当作安全审计、授权依据或不可丢失事件流。

- `TraceContext` 携带非零 `trace_id`、`span_id` 和可选父 span；
- 零 trace/span 与自父 span 在进入 Tracer 前被拒绝；
- `Tracer::emit_correlated` 将上下文写入普通 `TraceEvent`；
- ring 覆盖与序号耗尽分别累计到 `TraceLossStats`，不会静默消失；
- 安全审计仍由各自 fail-closed 持久链负责，不能复用这些 best-effort 计数。

## 尚未关闭

- Diagnostics Service 导出/查询必须携带同一 correlation ID；
- 受保护 panic/crash 快照与正常 trace 环的隔离和导出协议；
- 真实多进程/多核因果重建，以及 consumer 重启后的关联完整性矩阵。

因此 `verification/issue42-mechanism-ledger.tsv` 的 M25 保持 `partial`。
