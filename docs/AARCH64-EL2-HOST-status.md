# AArch64 EL2 resident-host probe

更新时间：2026-11-18。

状态：**proof-only；EL2 驻留、stage-2、最小 VM exit、虚拟 IRQ 注入、
虚拟定时器/VBAR/通用/系统/FP-SIMD vCPU 上下文恢复已验证，Driver VM 未实现**。

## 当前切片

AArch64 入口现在记录 `CurrentEL`。验证构建会在进入 EL2 时安装最小 EL2 向量表，
再按原路径降到 EL1 运行现有内核；EL1 通过固定 HVC 往返验证 EL2 处理域仍驻留。
本验证同时为次核安装同一 EL2 向量表，因此双核 SMP 上线也证明每个 AP 在进入
EL1 前完成 EL2 驻留准备。

验证构建随后通过 EL2 HVC 配置 39-bit IPA 和 4 KiB granule。测试 guest 运行期间，
声明 RAM 所在的 1 GiB 块走第二级表，仅映射与内核映像和 guest 栈相交的 2 MiB
block；其他 RAM 与全部设备 block 均无效。负例 guest 经物理线性映射访问
`0x4fe00000`，`ESR_EL2` 分类为 stage-2 data abort，`HPFAR_EL2` 精确匹配 fault
IPA。退出后 EL2 恢复宿主 RAM/设备映射并执行 stage-2 TLB invalidate，整机继续
运行不会继承测试映射。宿主恢复后的设备 block 仍是宽松映射，尚未由 capability
动态派生，也不构成 IOMMU 隔离。

验证构建还进入一个临时 EL1 测试 guest，并访问 stage-1 已映射但 stage-2 明确拒绝的
2 MiB IPA。EL2 数据异常入口恢复保存的宿主 ELR/SPSR，确认该路径是 stage-2
fault-to-host exit；下一节把该最小世界切换扩展为通用寄存器上下文恢复。

EL2 入口现在使用独立 64 KiB EL2 栈保存完整 x0–x30、SP_EL1、ELR_EL2 和 SPSR_EL2。
测试 guest 使用独立 64 KiB EL1 栈并把全部通用寄存器改写成不同哨兵；stage-2 fault
返回后，宿主 x2–x8、x11–x29、x18 及 x30 返回地址全部恢复，完整内核继续通过。
SP_EL0、TPIDR_EL0、TPIDR_EL1 和 CONTEXTIDR_EL1 也按 vCPU 帧保存；guest 改写后，
宿主哨兵逐项读回一致。

FP/SIMD 上下文同样进入 vCPU 帧：q0–q31、FPCR、FPSR 和 CPACR_EL1 在每次 EL2
入口保存。测试 guest 在启用 CPACR 后写满所有向量寄存器并执行 `fadd`，stage-2
退出后宿主原 FP 状态恢复，CPACR 重新为 0，内核继续禁止隐式 FP 使用。

最小虚拟中断切片通过 `HCR_EL2.VI` 与 `HCR_EL2.IMO` 向 EL1 guest 注入真实
virtual IRQ。guest 的 `VBAR_EL1` 指向独立异常向量，IRQ 入口通过 HVC 回报收到
中断；EL2 仅在收到该回报后清除 VI/IMO，并恢复宿主上下文。该路径不使用软件
篡改 ELR/SPSR 模拟中断到达。

guest 为该 IRQ 路径安装自己的 `VBAR_EL1`。vCPU 帧现在利用原有尾部对齐槽位保存
VBAR，EL2 返回宿主后恢复进入 guest 前的值；探针机械比较返回前后 VBAR，确认
guest 的异常向量状态没有泄漏回内核。

虚拟定时器状态也已进入同一 vCPU 帧：`CNTV_CTL_EL0` 与绝对比较值
`CNTV_CVAL_EL0` 在 EL2 入口保存，guest 改写后由宿主恢复。探针比较前后 CTL/CVAL，
避免把会自然递减的 `CNTV_TVAL_EL0` 视图误当作稳定状态；这证明定时器上下文切换，
不表示 vGIC 定时器中断注入已实现。

QEMU `virt,virtualization=on` 的真实串口结果：

```text
[JSR-A64-EL] entry=2 execution=1 el2_available=true el2_retained=true
[JSR-A64-STAGE2] vm_exit=true hpfar=0x4fe000 stage2_open=true
[JSR-A64-EL2] retained=true hvc_round_trip=true stage2_table=true stage2=true
vm_exit=true virtual_irq=true timer_context=true vbar_context=true vcpu_context=true
system_context=true fp_context=true driver_vm=false
[JSR-SMP] start present=2 online=2 failed=0 source=fdt.cpus dropped=0 disabled=0
```

该运行退出 35 仅含既有 AArch64 x86-only `pci_failed=3`、`krn0_failed=1` 基线；
没有新增失败。证据见 `evidence/aarch64-stage2-minimal-20261118-r11/`。

## 边界

- 当前证明 BSP/AP 的 EL2 向量驻留、EL1→EL2→EL1 HVC 往返和共享 stage-2
  身份翻译；
- 测试 guest 已有阶段化的最小 RAM 映射和显式恢复；宿主运行阶段的大块设备映射
  尚未由 capability 动态派生，完整 VE/VM exit 分类及多 vCPU 调度仍未完成；
- 当前 virtual IRQ 只证明最小 VI 注入与 guest 向量交付；尚未实现 vGIC
  分配/确认/EOI、GIC 虚拟 CPU 接口或定时器中断虚拟化；当前只完成定时器寄存器
  上下文的保存恢复；
- 已保存恢复通用寄存器、SP_EL1、ELR、SPSR、基础系统寄存器和 FP/SIMD；
  尚未保存 SVE、GIC/定时器虚拟状态或支持多 vCPU 调度；
- 基础系统寄存器已覆盖 SP_EL0、TPIDR_EL0/EL1、CONTEXTIDR_EL1 和 VBAR_EL1；
  TTBR/TCR/MAIR、调试/性能/安全配置等仍未形成完整 vCPU 系统寄存器模型；
- 尚未实现 Device/MMIO/DMA/IOMMU capability 注入或 Linux Driver VM；
- 不改变 LC-4、DC-1 或 Pixel Driver VM 节点状态。

Pixel 6a 当前 stock AVB/PE 载体进入 EL1，无法使用本路径。必须先完成公开、可恢复的
EL2 保留启动链，才能在实物上继续 Driver VM 验收。

## 复现

```text
AARCH64_EL2_OUT="$PWD/evidence/aarch64-stage2-minimal-20261118-r11" \
AARCH64_EL2_TARGET="$PWD/target/aarch64-el2-stage2" \
AARCH64_EL2_QEMU_CPUS=6-7 \
JASPER_BUILD_CPUS=4-5 \
bash scripts/aarch64-el2-retain-check.sh
```
