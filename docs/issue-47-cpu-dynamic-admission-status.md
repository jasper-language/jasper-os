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

阶段 2 的可扩展核心已开始：`kernel_core::cpu_bitmap::CpuBitmap` 使用 `Vec<u64>`
按需扩容，支持稀疏高位 CPU、membership、first、union、intersection 和 remove-all，
没有预设 CPU 数量常量。测试覆盖 1/32/64/128/129/256/1024/4096、130 位边界和
分配结构行为。该类型尚未替换生产 `CpuSet`，所以只是阶段 2 进行中的核心，
不是最终动态调度支持。

阶段 3 的第一个生产消费者已迁移：`kernel_core::msi::VectorPool` 在
`cpu-dynamic` 生产构建中使用动态 `CpuBitmap` 和按 CPU index 分配的向量位图
`Vec`，不再包含 `[_; MAX_CPUS]`。测试验证 CPU 129 的稀疏 MSI 向量分配；
无 `cpu-dynamic` 的轻量构建保留 `CpuSet` 兼容路径，避免给不需要堆的用户程序
强加 allocator。调度、per-CPU、IRQ 全局路由和四架构入口仍未迁移。

`ShardRouter` 已移除 `MAX_SHARDS = MAX_CPUS * 4`。分片数量不再间接跟随 128 位
CPU 集合，只有 32 位分片编号这一明确协议表示范围；实际分片数由服务资源准入决定。

IOMMU 中断重映射不再用 `MAX_CPUS` 裁决目标 CPU。它保留 `u8` 路由字段的协议
表示范围，并把 CPU 是否真实存在/在线的权威校验留给 IRQ 与调度层。

ENV-0 CPU 资源 Demand 在生产构建中已改用动态 CPU 亲和集合，不再用 `MAX_CPUS`
判定资源平台合法性；CPU 真实存在/在线仍由统一 CPU runtime registry 校验。

空闲停表的 `StopBoard` 也已迁到动态 CPU 集合：停表成员使用 `CpuBitmap`，起止
时刻表按已准入 CPU 数预分配。调度器在启动 AP 前完成表和扫描暂存区的全有或全无
分配，因此 `stop`、`restart` 和计时器唤醒路径不依赖临时扩容。CPU 129 与 4096
的宿主测试通过；轻量无堆构建仍使用固定兼容路径。

NUMA 节点 CPU 本地域也已改用动态集合，重复 CPU、离线节点和本地优先放置顺序
继续由同一拓扑快照裁决；CPU 4096 的 NUMA 归属已有测试。该迁移不改变页分配器或
迁移策略，后续仍需把调度放置输入 `Candidate::affinity` 从固定集合迁出。

## 尚未完成

当前生产 `CpuSet` 仍是 128 位静态位图；调度、每核状态、IRQ/MSI、TLB/IPI、
定时器、实时调度、NUMA 和诊断中仍有由该宽度派生的静态数组。因此：

- 不能把 128 改成 256/1024 后声称“动态支持”；
- 不能把本切片中的 4096-CPU 软件准入测试冒充真实内核运行；
- 不能把 `Topology` 的高位库存保留冒充 `CpuSet`/调度器已支持高位 CPU；
- 旧 `u64/u128` affinity ABI 仍需显式失败或版本化替代。

## Issue #47 阶段映射

1. `CPU-DYNAMIC-ADMISSION-1`：消费链、bootstrap 生命周期、锁序和负例审计；
2. `CPU-DYNAMIC-CORE-1`：动态 CPU 身份、拓扑和 `CpuSet` 核心（进行中）；
3. `CPU-DYNAMIC-CONSUMERS-1`：调度、per-CPU、IRQ/MSI、TLB/IPI、NUMA 和诊断
   （MSI 向量池已开始迁移）；
4. `CPU-DYNAMIC-ABI-1`：可变长/分页 CPU 枚举与亲和 ABI；
5. `CPU-DYNAMIC-MATRIX-1`：多规模、多 ISA、热插拔和真实可用平台矩阵。

所有阶段必须保持 discovered / supported / admitted / online / rejected 的独立事实，
且任何分配失败、库存不完整或资源不足都必须失败关闭。
