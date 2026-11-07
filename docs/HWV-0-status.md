# HWV-0 硬件虚拟化能力与拒绝契约

更新日期：2026-11-07。

## 定位

HWV-0 只发现和验证能力，不进入 VMX root 或 SVM host 模式，不创建 vCPU、没有 EPT/NPT 表、没有虚拟设备或 IOMMU 后端。后续里程碑不得把本能力探测当作虚拟化实现已经完成。

## 机器可读矩阵

`kernel_core::hwvirt::CAPABILITY_MATRIX` 固定登记 10 项：

| 能力 | 依赖 | 当前语义 |
|---|---|---|
| `vmx` | — | Intel 硬件辅助虚拟化入口 |
| `svm` | — | AMD 硬件辅助虚拟化入口 |
| `ept` | `vmx` | Intel 二级页表 |
| `npt` | `svm` | AMD 二级页表 |
| `iommu` | — | DMA/中断隔离基础 |
| `vtd` | `iommu` | Intel VT-d |
| `amd_vi` | `iommu` | AMD-Vi |
| `interrupt_remapping` | `iommu` | 中断重映射 |
| `x2apic` | — | x2APIC 能力 |
| `posted_interrupts` | — | Posted interrupt 能力 |

未知位不能通过 `Capabilities::from_bits` 混入；没有后端时返回 `NoBackend`，不能铸造空后端。

## 真实探测

x86_64 启动验收读取真实 CPUID：

* CPUID.0 厂商字符串；
* CPUID.1 ECX：VMX、x2APIC；
* CPUID.80000001 ECX：SVM；
* CPUID.8000000A EDX：NPT；
* 仅当 VMX 存在时读取 `IA32_VMX_EPT_VPID_CAP` 的 4 级 EPT 位。

IOMMU/VT-d/AMD-Vi/中断重映射的固件表发现尚未接入，因此在矩阵中保持不可用；这不表示硬件一定没有 IOMMU，只表示 Jasper 当前没有可信发现证据，必须拒绝依赖它的请求。

## 错误语义

* `NoBackend`：厂商与能力组合不能形成 VMX 或 SVM；
* `VendorMismatch`：显式选择的厂商后端与 CPU 厂商不符；
* `Missing(capability)`：请求能力未被真实发现；
* `Dependency { requested, required }`：依赖闭包不完整；
* `UnknownBits`：能力位图含未知位。

任何错误都在选择/准入阶段返回，不会创建对象、映射页、打开设备或进入虚拟化模式。

## 验收

* `kernel-core` 单元测试覆盖矩阵一一对应、Intel/AMD 分流、未知位、无后端、缺能力与依赖；
* x86_64 真实 KVM 启动输出 `[JSR-HWV0]`，拒绝请求必须得到 `iommu`/`dependency`/`rejected`，有完整能力时必须得到 `accepted`；
* `scripts/accept.sh` 的 `HWV-0` 行要求矩阵 10 项、真实探测完成、功能失败为 0；
* AArch64 只验证不破坏编译，不把它记作 HWV-0 通过。
