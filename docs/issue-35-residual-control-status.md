# Issue #35 剩余控制路径回退切片

更新时间：2026-11-18。

状态：**剩余控制决策回退继续失败关闭；规范默认、诊断显示和明确的 boot-only
默认继续保留。**

## 本切片

- Irq `Spread` 策略在候选集合为空时返回 `IrqError::Offline`，不再把未初始化候选
  默认选择为 CPU 0；`validate` 仍负责给出更具体的 EmptySet/Offline 原因。
- x86_64 GDT/TSS 每核指针通过显式 `Option` 链取得；缺失或空指针统一输出
  `tss_uninitialized` 并停机，不构造空指针语义值继续执行。
- x86_64 PIC master/slave 的非指定 EOI 只在 in-service 位图非空时清除对应线并
  增加计数，空位图不再清除虚构的 7/15 号线。

以下回退经审计保留：

- AArch64/RISC-V 设备 IRQ 0 表示固件中没有该设备，`line_of_id/source` 也拒绝 0；
- PSCI method/FDT compatible/ACPI 设备 name 的文本是诊断显示，不参与设备事实；
- capability 拒绝事件的 `requested=None` 映射为 `Rights::NONE`，用于表达没有请求
  权限，不授予权限；
- lifecycle 候选比较的 `unwrap_or(true)` 是“尚无更优候选”的 Option 比较，不是
  读取失败成功；
- PCI 未初始化空表、boot manager 无 UEFI stdout、键盘未知扫描码和 RISC-V SBI
  错误分类都是显式不可用/显示语义。

## 验证

```text
cargo test -p kernel-core irq -- --nocapture
22 passed; 0 failed

cargo check -p jasper-kernel --target x86_64-unknown-none --no-default-features
PASS

hardcode inventory: findings=365, added=0
hardcode ledger: 286 classified fingerprints; no unclassified baseline entries
```

## 尚未完成

- 需要 x86 GDT/TSS 缺失、IRQ 候选为空和 PIC 异常的 QEMU 故障注入；
- RISC-V SBI 错误码、AArch64 GIC 中断线和真实固件缺失设备矩阵仍未运行；
- FDT/PCI/VMX 剩余候选需由分类账继续逐项绑定规范或消费者证据。
