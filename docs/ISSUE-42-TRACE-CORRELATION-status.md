# Issue #42 M25：原生 trace 因果关联与丢失账务

更新时间：2026-11-21。

状态：**implemented-tested；M25 退出门已通过。**

## 边界

本切片只增强可丢弃的原生性能/诊断 trace，不创建 ptrace、uprobe 或 ETW
兼容 ABI，也不把 trace 当作安全审计、授权依据或不可丢失事件流。

- `TraceContext` 携带非零 `trace_id`、`span_id` 和可选父 span；
- 零 trace/span 与自父 span 在进入 Tracer 前被拒绝；
- `Tracer::emit_correlated` 将上下文写入普通 `TraceEvent`；
- ring 覆盖与序号耗尽分别累计到 `TraceLossStats`，不会静默消失；
- 安全审计仍由各自 fail-closed 持久链负责，不能复用这些 best-effort 计数。
- 诊断事件 Schema v2 携带可选 `TraceCorrelation`，零 ID、自父 span 和畸形
  presence/保留字节失败关闭；
- 诊断持久化事件从 256 字节扩展到 288 字节；Schema v1 快照仍可读取，首次
  后续提交写入 v2，不需要猜测旧记录中的 correlation；
- USI 诊断契约升级为 v2：查询请求、成功/错误响应头、每个导出事件携带同一
  可选 trace/span/parent identity；
- crash/panic 来源仍使用独立 no-allocate、try-lock emergency ring，和正常
  trace 环隔离；导出阶段通过同一 v2 记录进入受授权诊断查询。

验证：

```text
cargo test --locked -p jasper-lifecycle-model
65 passed; 0 failed

cargo clippy --locked -p jasper-lifecycle-model --all-targets -- -D warnings
PASS

cargo check --locked --target x86_64-unknown-none -p jasper-kernel
PASS

cargo check --locked --target x86_64-unknown-none -p user-usi
PASS

bash scripts/lifecycle-diagnostic-block-check.sh
PASS rounds=2 evidence/lifecycle-diagnostic-block-20261121-043731
```

真实 OVMF/virtio-blk 两轮均 `failed=0 resources=true`；首轮
`events=5 sequence=6 query=4 sources=2`，重启只读来源清零后第二轮
`events=6 sequence=7 query=4 sources=0`，持久事件、隐私门和追加顺序保持。

USI-1 真实 guest 的单核、4 vCPU、8 vCPU 和 q35 ECAM 四条启动路径均执行独立
`usi-diagnostic` 进程并得到：

```text
usi: mode=diagnostic status=0 records=1 accepted=1 sequence=2 generation=1
  correlated=true ok=true
[JSR-USI] summary ... diagnostic=true failed=0 reclaimed=true
```

这证明请求、响应头与持久诊断页共用同一个非零 correlation；不包含物理 UI
或安全审计语义。

## 真实多进程因果重建

公开 `main` 的 `scripts/ui-process-check.sh` 在真实 QEMU 2-vCPU、CPL3
host/ui-service/ui-peer 三进程路径上记录两条独立 trace：

- host 与 service 使用同一 trace，service span 以 host span 为 parent；
- peer 与 peer service 使用独立 trace，并保留对应 parent 关系；
- UI Service 两轮重启后，第一轮与第二轮共 4 条 trace、4 条 parent link
  仍可同时从 trace ring 重建；
- ring overwrite 与 sequence exhaustion 账务均为 0；
- 串口 marker：

```text
[JSR-M25] multiprocess=true multicore=true service_restarts=2 traces=4
  parent_links=4 retained=true ring_losses=0 sequence_losses=0 failed=0
```

因此 `verification/issue42-mechanism-ledger.tsv` 的 M25 升为
`implemented-tested`。该机制仍是可丢弃诊断 trace，不代替安全审计；
Linux ptrace/uprobe/ETW 协议行为继续由兼容层适配，不要求内核复制其接口。
