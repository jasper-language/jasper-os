# Issue #35 发现回退失败关闭切片

更新时间：2026-11-18。

状态：**SMP 固件拓扑未知、页表帧转换失败和 CPU 扩展尺寸转换失败已改为失败
关闭；诊断显示与架构默认保留。**

## 本切片

- `CpuDiscovery` 新增 `inventory_complete`：
  - x86_64 无物理映射、APIC 不可用、MADT 缺失/损坏时不得把引导处理器冒充完整
    SMP 库存；
  - AArch64 未取得固件拓扑或固件报告多核但 PSCI 不支持时失败关闭；
  - RISC-V 无有效 FDT、boot hart 不在 CPU 表、拓扑解析失败或缺少 HSM/IPI 时
    失败关闭；
  - LoongArch 经已解析 FDT 建表，声明完整。
- 统一 SMP 在发布拓扑前检查 `inventory_complete`；引导处理器或任一逻辑核缺少
  hardware ID、每核槽缺失时输出明确 reject 并停止，不再写入 `0`/`u32::MAX`。
- LoongArch 复制固件 CPU 表时，缺失 hardware ID 返回
  `fdt-cpu-identity-missing`，不存 `0`。
- x86_64 地址空间销毁不再把无效页表物理地址转成 frame 0：
  对齐后仍无法构造合法 `PhysFrame` 时保留泄漏事实，不能错误释放低端页帧。
- x86_64 XSAVE 尺寸的 integer conversion 失败直接让 `configure` 返回 false。

## 保留的显式默认与诊断

- boot manager panic handler 在系统表不可用时只跳过控制台输出；
- ACPI/IOAPIC/AArch64/RISC-V 的设备名缺失显示 `none`；
- AArch64/RISC-V 的设备中断号 `0` 表示该设备未出现在固件拓扑中；
- 键盘未知扫描码显示 `?`；
- x86 GDT 每核 TSS 指针缺失后打印 reject 并停机。

这些路径不会生成新的硬件事实或继续执行依赖该事实的控制流。

## 验证

```text
cargo check -p jasper-kernel --target x86_64-unknown-none --no-default-features
PASS

cargo check -p jasper-kernel --target aarch64-unknown-none-softfloat --no-default-features
PASS

cargo check -p jasper-kernel --target riscv64gc-unknown-none-elf --no-default-features
PASS

cargo check -p jasper-kernel --target loongarch64-unknown-none-softfloat --no-default-features
PASS

python3 scripts/check-hardcode-gate.py --inventory \
  --inventory-baseline docs/hardcode-inventory-baseline.json
findings=375, added=0, cleared=8
```

## 尚未完成

- 需要对缺失/损坏 MADT、无效 RISC-V FDT、无 PSCI 多核和每核 identity 缺失逐项做
  真实平台/QEMU 负例启动证据；
- x86 页表物理地址损坏只能通过故障注入证明，正常编译测试不覆盖硬件错误；
- 剩余 `unwrap_or` 仍需按诊断、规范默认和真实控制回退继续分类。
