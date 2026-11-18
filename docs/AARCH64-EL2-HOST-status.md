# AArch64 EL2 resident-host probe

更新时间：2026-11-18。

状态：**proof-only；EL2 驻留、stage-2、最小 VM exit、通用寄存器与基础系统寄存器
vCPU 上下文恢复已验证，Driver VM 未实现**。

## 当前切片

AArch64 入口现在记录 `CurrentEL`。验证构建会在进入 EL2 时安装最小 EL2 向量表，
再按原路径降到 EL1 运行现有内核；EL1 通过固定 HVC 往返验证 EL2 处理域仍驻留。
本验证同时为次核安装同一 EL2 向量表，因此双核 SMP 上线也证明每个 AP 在进入
EL1 前完成 EL2 驻留准备。

验证构建随后通过 EL2 HVC 配置 39-bit IPA、4 KiB granule、level-1 1 GiB block
的 512 GiB 身份映射。该映射只为继续开发 VM exit 和上下文切换提供可用翻译环境：
1 GiB RAM 块使用 Normal 属性，其余块暂用 Device 属性；它不表达最终设备白名单、
最小权限或 IOMMU 隔离。

验证构建还进入一个临时 EL1 测试 guest，并访问 stage-1 已映射但 stage-2 明确拒绝的
2 MiB IPA。EL2 数据异常入口恢复保存的宿主 ELR/SPSR，确认该路径是 stage-2
fault-to-host exit；下一节把该最小世界切换扩展为通用寄存器上下文恢复。

EL2 入口现在使用独立 64 KiB EL2 栈保存完整 x0–x30、SP_EL1、ELR_EL2 和 SPSR_EL2。
测试 guest 使用独立 64 KiB EL1 栈并把全部通用寄存器改写成不同哨兵；stage-2 fault
返回后，宿主 x2–x8、x11–x29、x18 及 x30 返回地址全部恢复，完整内核继续通过。
SP_EL0、TPIDR_EL0、TPIDR_EL1 和 CONTEXTIDR_EL1 也按 vCPU 帧保存；guest 改写后，
宿主哨兵逐项读回一致。

QEMU `virt,virtualization=on` 的真实串口结果：

```text
[JSR-A64-EL] entry=2 execution=1 el2_available=true el2_retained=true
[JSR-A64-EL2] retained=true hvc_round_trip=true stage2_table=true stage2=true
vm_exit=true vcpu_context=true system_context=true driver_vm=false
[JSR-SMP] start present=2 online=2 failed=0 source=fdt.cpus dropped=0 disabled=0
```

该运行退出 35 仅含既有 AArch64 x86-only `pci_failed=3`、`krn0_failed=1` 基线；
没有新增失败。证据见 `evidence/aarch64-el2-systemctx-20261118-r5/`。

## 边界

- 当前证明 BSP/AP 的 EL2 向量驻留、EL1→EL2→EL1 HVC 往返和共享 stage-2
  身份翻译；
- stage-2 除一个负例块外仍是宽松身份映射；已分类最小 stage-2 data abort，但尚未
  实现按 capability 的最小映射、完整 VE/VM exit 分类及 vCPU/IRQ/定时器上下文切换；
- 已保存恢复通用寄存器、SP_EL1、ELR、SPSR 和基础系统寄存器；尚未保存
  FP/SIMD/SVE、GIC/定时器虚拟状态或支持多 vCPU 调度；
- 基础系统寄存器已覆盖 SP_EL0、TPIDR_EL0/EL1 和 CONTEXTIDR_EL1；TTBR/TCR/MAIR、
  VBAR、调试/性能/安全配置等仍未形成完整 vCPU 系统寄存器模型；
- 尚未实现 Device/MMIO/DMA/IOMMU capability 注入或 Linux Driver VM；
- 不改变 LC-4、DC-1 或 Pixel Driver VM 节点状态。

Pixel 6a 当前 stock AVB/PE 载体进入 EL1，无法使用本路径。必须先完成公开、可恢复的
EL2 保留启动链，才能在实物上继续 Driver VM 验收。

## 复现

```text
AARCH64_EL2_OUT="$PWD/evidence/aarch64-el2-systemctx-20261118-r5" \
AARCH64_EL2_TARGET="$PWD/target/aarch64-el2-stage2" \
AARCH64_EL2_QEMU_CPUS=6-7 \
JASPER_BUILD_CPUS=4-5 \
bash scripts/aarch64-el2-retain-check.sh
```
