# Issue 95 SMP 性能专项整改状态

更新时间：2026-11-24。

状态：**统一三组矩阵实现中；旧 AMD 裸机结果因缺少同镜像单核组且上下文切换未完整，不进入正式基线。**
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
`SCHED.CONTEXT_SWITCH` 的测量任务直接进入原有完整调度事务，而不是调用允许
立即返回的通用 `yield_now` 快路；否则单核实机可能被正常 yield gate 无限抑制。
若仍未发生真实切换，该次尝试不进入样本，重试后只有真实完成的切换才计入
百分位；重试数单独记录。

每个模式输出 `before / during_raw_retained / after` 三个阶段的内存事实，
包含可用/空闲/已用内存、堆使用、堆峰值、堆空闲与映射量。

## PERF-R01：真实切换完成计数

- `bench-profile` 构建在 `Scheduler::finish_switch` 的真实完成点记录每 CPU
  完成计数、最后换下任务槽位与代次。该路径覆盖普通切换、定时器快速路径、
  阻塞、退出及进入空闲落脚点。
- 计划创建、继续同一上下文、`yield` 无对手和失败切换不增加完成计数。
- 单核并发基准改为读取当前 CPU 的完成计数；原先共享的
  `leaf_local_switch_count` 不再作为切换性能样本依据。
- 每 CPU 输出完成切换数、有效样本、未切换数及最后任务身份/代次。

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
