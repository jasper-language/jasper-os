# Issue #47：CPU 拓扑无预设固定上限

更新时间：2026-11-19。

状态：**阶段 1 进行中；128 槽位仍是已知的过渡实现，不得宣称 Issue #47 完成。**

## 已落地切片

`kernel_core::smp::admit_cpu_inventory` 建立了与当前 `CpuSet` 表示解耦的 CPU
资源准入：

- 输入是固件 `present/disabled`、每颗已启用 CPU 的真实运行成本与当前可用字节；
- 函数没有固定 CPU 数量常量或位图宽度上限；
- disabled 数量非法、没有任何启用 CPU、乘法溢出或完整库存超出预算时显式拒绝；
- 资源不足时拒绝完整拓扑，不静默启动任意子集；
- 单元测试覆盖 1/32/64/128/129/256/1024/4096 个 CPU 与资源不足负例。

SMP 门面在启动 secondary CPUs 前读取真实空闲页帧预算，并按每个 secondary 的
运行时栈成本执行该准入。成功时输出：

```text
[JSR-SMP] admit present=<n> enabled=<n> disabled=<n> per_cpu_bytes=<n>
  required_bytes=<n> available_bytes=<n> source=resource-budget
```

失败时输出结构化 `system.cpu.error.*` 原因并停机。

## 尚未完成

当前生产 `CpuSet` 仍是 128 位静态位图；调度、每核状态、IRQ/MSI、TLB/IPI、
定时器、实时调度、NUMA 和诊断中仍有由该宽度派生的静态数组。因此：

- 不能把 128 改成 256/1024 后声称“动态支持”；
- 不能把本切片中的 4096-CPU 软件准入测试冒充真实内核运行；
- 不能把 `Topology` 的高位库存保留冒充 `CpuSet`/调度器已支持高位 CPU；
- 旧 `u64/u128` affinity ABI 仍需显式失败或版本化替代。

## Issue #47 阶段映射

1. `CPU-DYNAMIC-ADMISSION-1`：消费链、bootstrap 生命周期、锁序和负例审计；
2. `CPU-DYNAMIC-CORE-1`：动态 CPU 身份、拓扑和 `CpuSet` 核心；
3. `CPU-DYNAMIC-CONSUMERS-1`：调度、per-CPU、IRQ/MSI、TLB/IPI、NUMA 和诊断；
4. `CPU-DYNAMIC-ABI-1`：可变长/分页 CPU 枚举与亲和 ABI；
5. `CPU-DYNAMIC-MATRIX-1`：多规模、多 ISA、热插拔和真实可用平台矩阵。

所有阶段必须保持 discovered / supported / admitted / online / rejected 的独立事实，
且任何分配失败、库存不完整或资源不足都必须失败关闭。
