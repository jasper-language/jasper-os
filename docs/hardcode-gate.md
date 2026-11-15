# Issue #33 新增硬编码门禁

`scripts/check-hardcode-gate.py` 是增量审查门，不是“仓库已经没有硬编码”的证明。
它只检查本次变更在 `kernel/` 与 `kernel-core/` 生产代码中新增的行，避免要求一次性
清理所有既有实验/演练常量后才能真正启用 CI。

## 阻断规则

- `HC-G1`：新增 `MAX_*`、`DEFAULT_*`、`QEMU_*`、`PIXEL_*` 等固定容量或平台事实；
- `HC-G2`：使用 `.min(MAX_*)` 静默截断硬件发现结果；
- `HC-G3`：通用生产代码新增 QEMU、Pixel 6a 或 qemu-virt 专用分支；
- `HC-G4`：没有独立验证事实却直接写入 `verified`；
- `HC-G5`：任务、对象、环、页帧位图等运行容量直接来自裸数字；
- `HC-G6`：资源尺寸被软件默认值或最大值夹取；
- `HC-G7`：启动、内存、ACPI/FDT、PCI、IRQ、设备或能力发现路径新增
  `unwrap_or` / `unwrap_or_else` 隐藏回退。

测试、演练、基准和测试专用工作负载不在生产门禁范围内。规则不按字符串删除数字：
发现路径必须改为运行时事实、显式策略和失败关闭。

## 规范协议常量

PCI、ACPI、FDT、virtio 等规范明确不可变的字段可以保留，但必须在同一行写明来源和
审查理由：

```rust
const MSIX_MAX_ENTRIES: u16 = 2048; // JASPER-HARDCODE-REVIEW: issue=33 source=PCI-SIG-MSI-X reason=11-bit-table-size-field
```

该注释只表示此值不是硬件实例事实，不表示相关运行时容量可以继续硬编码。平台适配器
中的固定启动协议也必须同样标注，并保持在明确绑定平台的模块内。

## CI 基线

公开仓库 `ci.yml` 使用 pull request 的 base SHA 或 push 前的 revision 作为增量基线，
先执行脚本自测，再检查实际 diff。新分支或基线为全零时退回 `HEAD^`。缺少可比较提交
会使检查失败，而不是静默跳过。

门禁不能替代 Issue #33 要求的全量登记、双拓扑事实、超限负例和逐子系统修复；
`NO-HARDCODE-1` 仍须在这些证据全部闭环后才能完成。
