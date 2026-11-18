# Issue #33/#35 增量阻断与存量审计

`scripts/check-hardcode-gate.py` 是增量审查门，不是“仓库已经没有硬编码”的证明。
它检查本次变更在全部生产 crate、模块、用户运行时和工具代码中新增的 Rust 行；
`--inventory` 另行审计当前树存量，避免把“新增不报”误当成全量清零。
`--inventory-baseline` 用“路径 + 规则 + 规范化源码行”的 SHA-256 多重集与
`docs/hardcode-inventory-baseline.json` 比较；新增指纹失败，消除条目允许基线
自然下降，避免只检查总数时用“删一加一”绕过治理。基线文件只是待分类审计快照，
不表示 437 个命中已经全部证实为缺陷。

覆盖范围包括 `boot-manager`、`compat-*`、`jaso`、`kernel`、`kernel-core`、
`lifecycle-*`、`modules`、`netd`、`tools`、`user`、`xtask` 和 `arch-probes`。

## 阻断规则

- `HC-G1`：新增 `MAX_*`、`DEFAULT_*`、`QEMU_*`、`PIXEL_*` 等固定容量或平台事实；
- `HC-G2`：使用 `.min(MAX_*)` 静默截断硬件发现结果；
- `HC-G3`：通用生产代码新增 QEMU、Pixel 6a 或 qemu-virt 专用分支；
- `HC-G4`：没有独立验证事实却直接写入 `verified`；
- `HC-G5`：任务、对象、环、页帧位图等运行容量直接来自裸数字；
- `HC-G6`：资源尺寸被软件默认值或最大值夹取；
- `HC-G7`：启动、内存、ACPI/FDT、PCI、IRQ、设备或能力发现路径新增
  `unwrap_or` / `unwrap_or_else` 隐藏回退。
- `HC-G8`：新增固定 `*_CAPACITY`、`*_SLOTS`、`*_LINES`、`*_VECTORS` 或
  `*_CPUS` 数值常量。

测试、演练、基准和测试专用工作负载不在生产门禁范围内。规则不按字符串删除数字：
发现路径必须改为运行时事实、显式策略和失败关闭。

## 规范协议常量

PCI、ACPI、FDT、virtio 等规范明确不可变的字段可以保留，但必须在同一行写明来源和
审查理由：

```rust
const MSIX_MAX_ENTRIES: u16 = 2048; // JASPER-HARDCODE-REVIEW: issue=33 source=PCI-SIG-MSI-X reason=11-bit-table-size-field
```

豁免必须同时满足：

- 注释完整匹配 `issue=<n> source=<registered-id> reason=<why>`；
- `source` 在 `docs/hardcode-review-sources.tsv` 登记，并声明相同 issue、来源类别和
  可追踪引用；
- 未登记 source、缺少 reason 或 issue 不匹配都不会豁免。

该注释只表示此值有可审查的规范、策略、运行时事实或测试来源，不表示相关运行时容量
可以继续硬编码。平台适配器中的固定启动协议也必须同样标注，并保持在明确绑定平台的
模块内。

## CI 基线

公开仓库 `ci.yml` 使用 pull request 的 base SHA 或 push 前的 revision 作为增量基线，
先执行脚本自测，再检查实际 diff。新分支或基线为全零时退回 `HEAD^`。缺少可比较提交
会使检查失败，而不是静默跳过。

门禁不能替代 Issue #33 要求的全量登记、双拓扑事实、超限负例和逐子系统修复；
`NO-HARDCODE-1` 仍须在这些证据全部闭环后才能完成。

## 存量审计

```text
python3 scripts/check-hardcode-gate.py --inventory
python3 scripts/check-hardcode-gate.py --inventory --inventory-verbose
python3 scripts/check-hardcode-gate.py --inventory \
  --inventory-baseline docs/hardcode-inventory-baseline.json
python3 scripts/check-hardcode-gate.py --inventory \
  --write-inventory-baseline docs/hardcode-inventory-baseline.json
```

第一条输出当前生产树的规则计数；第二条列出逐文件、逐行证据。存量审计独立于增量
阻断，CI 会同时运行自测、增量门和存量摘要。
