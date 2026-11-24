# Issue 95 SMP 性能专项整改状态

更新时间：2026-11-24。

状态：**通用切换观测与可终止的双任务工作负载已实现并通过同构建 QEMU 的
1/10/1000 次三组验收；AMD 裸机复核待执行。旧裸机结果不进入正式基线。**
本文件不把软件构建、QEMU 或历史单核数字当作 Issue #95 完成证据。

## 正式矩阵组织

正式 `smp-matrix-only` 镜像在同一个内核、同一次启动和同一套指标实现中依次执行：

1. `SMP_SINGLE`：一个在线逻辑 CPU；
2. `SMP_PHYSICAL`：真实拓扑中每个物理核心各选一个在线逻辑 CPU；
3. `SMP_LOGICAL`：全部在线逻辑 CPU。

参与集合来自固件与实际 SMP 上线结果，不按 Ryzen 7 5700X 的 8P/16T
硬编码。正式构建仍为每个参与 CPU、每项指标 100 万有效样本；
`bench-smoke` 只用于开发控制组，并明确输出较低样本数。

每个并行指标现在分别输出 `planned / observed / valid / failed_ops /
incomplete`。多核百分位仍由全部保留原始样本计算，不平均各 CPU 百分位。
`SCHED.CONTEXT_SWITCH` 由两个普通可运行任务的持续让出产生。任务顺序由生产
调度器按运行队列、优先级、亲和性和预算决定；测试只等待该 CPU 完成目标数量
的真实切换，不要求固定的 A→B→A 顺序，也不使用 `n == 2` 或任何固定切换次数
作为成功条件。

每个模式输出 `before / during_raw_retained / after` 三个阶段的内存事实，
包含可用/空闲/已用内存、堆使用、堆峰值、堆空闲与映射量。

## PERF-R01：真实切换完成事实

- `bench-profile` 构建在 `finish_leaf_switch` 的真实交接完成点发布每 CPU
  `SwitchRecord`：切换序号、执行权交接耗时、切出/切入 task ID、slot、
  generation 和切换原因。计划创建、继续同一上下文及失败切换不产生记录。
- 机制记录覆盖主动让出、定时器/优先级切换、阻塞、退出、迁移和进入 boot/idle
  落脚点。普通生产构建不输出逐次文本日志；测试可注册有界样本 sink 消费事件。
- 切换到 boot/idle 时立即完成 cold settlement，避免 tickless AP 在最后任务
  退出后缺少下一次全局事务而无法满足 `workers_settled`。
- 通用工作负载只提供两个同核任务并持续让出；实际完成多少次、切换给哪个任务
  完全由生产调度器决定。每个样本是真实完成的一次执行权交接。
- 独立受控 A→B→A 工作负载只用于 `SCHED.CONTEXT_SWITCH_ROUND_TRIP` 指标，
  不作为调度器正确性或通用切换样本的唯一判据。
- 吞吐量使用真实成功切换数和 release→settle 工作窗口计算；单次切换延迟、
  受控往返延迟与吞吐量分别输出，不以往返的一半或 `dt / n` 冒充单次延迟。

QEMU/OVMF 同构建控制组 `evidence/issue95-general-switch-qemu-20261124-r5`
依次完成 `SMP_SINGLE`、`SMP_PHYSICAL`、`SMP_LOGICAL` 的 1、10、1000 个
真实切换及独立 1000 次受控往返，全部任务身份/序号校验通过，任务退出后
`workers_done`、资源账本和内存均回到预期基线。最终：

```text
SMP CONCURRENT FINAL SINGLE=true PHYSICAL=true LOGICAL=true
FAILED=0 TIMING_FAILED=0 RECLAIMED=true
```

该结果只证明 QEMU 功能与测量链正确；正式物理结论仍必须来自 AMD 裸机。

## PERF-R02：页帧、失败与吞吐口径

- 并发指标新增独立 `FRAME.ALLOC`、`FRAME.FREE` 与
  `FRAME.ALLOC_FREE_PAIR`，不再把分配加释放同时归入两个指标。
- 分配/释放采用受控批量准备与清理；准备和清理不进入目标延迟样本。
- 每 CPU/汇总结果携带 `SUCCESS`、`FAILED` 和有效样本门；任何失败、缺样本或
  未参与 CPU 均使该指标失败，不允许零样本或失败样本产生看似有效的百分位。
- `OPS/S` 以全部 worker 从统一释放屏障到最终收集完成的真实窗口计算，不再
  用已排序延迟之和倒推吞吐；统计/排序耗时单独输出。
- P50/P99/P99.9/P99.99/P99.999/MAX、阈值超时数、每 CPU 百分位和合并原始样本
  百分位同时保留。

## KPR-1：同核主动切换候选快速路径

第一版 `fast-leaf-yield` 候选在真实 4-vCPU QEMU smoke 中命中本地交接后，
出现 `hot=Running/Some(cpu)` 与 `cold=Runnable/None` 状态分叉并 fail-closed
panic。原因是连续主动交接使冷任务表结算落后于下一次本地选择。强制立即结算
后仍可复现，因此该候选实现及 feature 已撤销，没有进入正式物理镜像。

该负例证明“减少一次全局锁获取”不能以削弱唯一任务状态权威为代价。当前正式
路径保留原有全局调度事务；后续需要先把任务身份、on-CPU、迁移和终态结算组合
成可证明的单次提交，再重新建立 A/B 候选。

控制组结果：

- 4P/4T QEMU/OVMF，100,000 样本 smoke；
- 16 个指标 `COMPLETE=true`；
- 每指标每 CPU 成功/失败样本有独立计数；
- 上下文切换 `MISSED=0`，完成计数与有效样本一致；
- 两个模式的帧、对象、pending、pin 均回基线；
- 最终 `FAILED=0 TIMING_FAILED=0 RESOURCES_RECLAIMED=true`；
- 证据：`evidence/issue95-kpr0-control-tcg-20261124-r10`。

## KPR-3：时钟屏障观测

8P/16T 基准开始前执行同屏障 TSC 读取，记录每 CPU 原始时间戳与
`TSC_BARRIER_SKEW_UPPER_NS`。该值是含屏障释放/IPI 延迟的上界，不被冒充为
硬件计数器绝对同步精度。固件 SMI/NMI、PMU 与频率变化仍需后续受控实验。

## 当前证据门

- 旧 QEMU 控制组只覆盖 physical/logical 两组；统一三组控制组正在重跑。
- 旧 AMD 运行没有同镜像单核组，且 `SCHED.CONTEXT_SWITCH` 未完成，因此不得
  与新镜像组合成正式横向基线。
- 正式 100 万样本镜像只有在三组 QEMU smoke 全通过后才会部署到 PXE；
  QEMU 数字不作为物理性能结论。
- 当前样本规模保持每 CPU/指标 100 万，避免在测量纠偏阶段同时改变样本变量。

## 尚未完成

- 控制组/候选组至少三轮同机复测与统计不确定性；
- 页帧/堆锁等待、持有、IRQ-off 与 PMU/cache 竞争归因；
- Per-CPU 页帧缓存、堆尺寸类局部化及压力收缩；
- 物理 SPSC/RT 混合负载、SMT 对照、长时间运行和跨 ISA 回归；
- PERF-R04～R09 中尚未被实测确认或排除的路径。
