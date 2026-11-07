# issue #2 进度：调度器高精度期限事件增量维护（第一片）

- 日期：2026-10-28
- 分支：`dev/issue2-s1`
- 范围：第一片——期限森林增加「增量同步」原语，`refresh_ns_events()` 改用它：期限没有变化的槽位不再重设堆节点（不再 set + repair）。x86_64 为唯一运行目标；AArch64 只保证能编译。
- 结论：「无变化不应重设堆节点」已满足并有计数证据；全表逐槽检查（扫描本身）仍在，留给第二片的脏集合。

## 1. 本片做了什么

| 项 | 内容 |
|---|---|
| `DeadlineForest::sync` | 输入槽位、代次与目标 `Option<(所有者 CPU, 时刻)>`。现有节点与目标完全相同（同所有者、同时刻、同代次），或两边都不存在 ⇒ 返回 `Unchanged`，不写任何存储；否则恰好做一次 set 或 remove，返回 `Inserted / Rescheduled / Moved / Removed`。现有节点代次不同 ⇒ `Stale`；越界 CPU / 槽位、坏形状 ⇒ 对应错误；所有失败都不改状态。 |
| `SyncStats` | 刷新轮数、sync 次数与各结果计数；不变量 `synced = unchanged + inserted + rescheduled + moved + removed`。 |
| 调度器接入 | `refresh_ns_events()` 每个有生命周期记录的槽位调用一次 `sync`（原来是无条件 `set` 或 `remove`），并累计计数；`sched::ns_sync_stats()` 读出。 |
| 启动自检 | 默认启动在汇总前打印 `[JSR-NS-SYNC] passes=… synced=… unchanged=… writes=… balanced=…`；计数不守恒计为失败（`nssync_failed=1`）。 |

## 2. 前后对照（本片）

| 项 | 改动前 | 改动后 |
|---|---|---|
| 每轮刷新检查的槽位 | 全部有生命周期记录的槽位 | 不变（第二片处理） |
| 有期限但未变化的槽位 | 每轮一次 `set`：写节点 + `repair`（O(log N) 比较/交换） | 一次 `locate` 比较（O(1)），不写存储 |
| 期限变化的槽位 | 一次 `set`（跨核时先移出旧堆） | 相同：恰一次 `set` |
| 无期限的槽位 | 一次 `remove`（不存在时只做定位） | 相同：存在则一次 `remove`，否则 O(1) 返回 |
| 锁区间 | 全局调度锁内 | 不变；锁内工作量减少的是堆写入，不是扫描 |

实测（默认启动、x86_64 单处理器、TCG，定点验收 `accept-20261028-111400`）：

```
[JSR-NS-SYNC] passes=462484 synced=29322113 unchanged=29322112 writes=1 inserted=1 rescheduled=0 moved=0 removed=0 balanced=true
```

- 平均每轮检查约 63.4 个槽位（29322113 / 462484），这就是第二片要去掉的全表扫描。
- 本次运行只有 1 个槽位插入过期限且之后从未移除；改动前它在插入后的每一轮都会被重写并 repair 一次（至多 462484 次），改动后只写了 1 次。
- 这是 TCG 下的计数证据，不是计时证据；锁持有时间与唤醒分位的前后对照见第四片。

## 3. 验证

- 六步链：`VERUS=… bash verification/toolbox/run-deadline-sync-suite.sh`（仅在构建环境中运行），性质登记 DL-SYNC-01、DL-SYNC-02、KRN2-FOREST-02（后者为既有 `set` / `pop_due` 补链）。
- 定点验收：M1.1、M1.2、M1.4、T-2、T-2/计时、SCHED2、SCHED2/计时、POL2 通过（默认启动走高精度路径）。

## 4. 对照 issue 验收条目

| 条目 | 状态 |
|---|---|
| 无变化不应重设堆节点 | 已满足（本片；计数证据见上） |
| 无变化路径不再全量扫表 | 未满足（第二片） |
| 覆盖取消与到期、迁移与到期、退出复用、预算到期等的回归/并发模型 | 部分：森林层的取消、迁移、错代次、到期弹出由差分测试 / Kani / Loom 覆盖；调度器状态迁移层随第二片补 |
| 堆操作数、扫描槽位数的前后比较 | 部分：已有计数接口与一次实测；锁持有时间与唤醒分位待第四片 |
| 时间拆分 deadline→中断进入→取锁→开始唤醒→队列发布→resume | 未开始（第三片） |
| owner-leaf 本地到期快路径评估 | 未开始（第五片） |

## 5. 剩余切片

1. **第二片：脏集合。** 在每个改变期限输入的状态迁移点（sleep/wake、预算变动、迁移、退出、取消、代次复用、CPU 上下线）登记脏槽位；`refresh_ns_events()` 只同步脏槽位，只重算受影响 CPU 的根。用「脏集合 + 定期全表校验（仅验证构建）」证明没有漏登记。
2. **第三片：时间拆分。** 把 `deadline_to_runnable` 拆成 deadline→中断进入→取锁→开始唤醒→队列发布→resume 六个时间点；队列发布点放在 `make_runnable()` 真正发布之后。
3. **第四片：`settle_highres()` 拆分。** 运行中任务的预算结算只处理到期 CPU；非运行态预算补充改为按补充时刻入堆，不再每次全表扫描；给出复杂度与锁区间前后对照（堆操作数、扫描槽位数、锁持有时间、唤醒分位，同口径样本量）。
4. **第五片：owner-leaf 本地到期快路径评估。** 先写清状态归属、发布顺序与冷结算边界，用并发模型证明同一任务不会跨核重复唤醒，再决定是否实现。
5. **第六片：KVM / 裸机对照。** 同计时口径、同观察开销、同 p99/p99.9 样本量；200 μs 是性能目标而非硬实时保证。

## 6. 第二片：脏集合（2026-11-05）

- 分支：`dev/issue2-s2`
- 范围：`refresh_ns_events()` 只同步脏槽位、只重读受影响处理器的根；`settle_highres()` 的全表结算仍在，留给第四片。

| 项 | 内容 |
|---|---|
| `kernel_core::dirty_slots` | 调用方提供存储的位图：标记、查询、按序取走，不分配、不失败；越界标记是空操作。 |
| `TrackedSlots` | 任务表改用它：不实现 `DerefMut`，可变访问（`get_mut`、`IndexMut`、`iter_mut_where`）都先标脏，没有绕开标记的可变入口。代价是偶尔多同步一个其实没变的槽位，同步对它不写堆。 |
| 表外输入 | 任务表之外的变化显式登记：到期弹出节点（`pop_due`）、退出移除（`mark_current_exited`）、启用高精度模式、扩容。 |
| 根 | `ns_root_dirty` 记需要重读的处理器；离线的留到上线。 |
| 校验 | `ns-dirty-audit` 构建每轮刷新后全表比较已发布节点与应发布事件、缓存的根与堆顶，不一致直接恐慌。默认构建只在启动汇总时比较一次。 |

实测（x86_64，TCG，默认单处理器启动，定点 `accept-20261104-203049`）：

```
[JSR-NS-SYNC] passes=485123 synced=44183 unchanged=43927 writes=256 inserted=256 rescheduled=0 moved=0 removed=0 balanced=true audit_mismatch=0 audits=0
```

平均每轮检查约 0.09 个槽位（第一片同口径约 63.4）。这是计数证据，不是计时证据；两次运行的工作负载也不完全相同。校验内核：单处理器 476526 轮、4 处理器 539215 轮、8 处理器 585545 轮，0 不一致。

验收条目「无变化路径不再全量扫表」：`refresh_ns_events()` 已满足；`settle_highres()` 未满足（第四片）。调度器状态迁移层的回归由校验内核覆盖，并发模型没有新增。

### 校验能抓到什么（变异测试）

默认启动的高精度事件很少，只靠它校验不够：删掉到期弹出的根登记也抓不到。所以校验又加了 RT2 专项（高精度睡眠、取消、预算，4 处理器）。

| 删掉的登记 | 默认启动（1、4 处理器） | RT2 专项 | 结论 |
|---|---|---|---|
| 到期弹出后的根 | 未抓到 | 抓到 | 靠 RT2 专项 |
| `IndexMut` 的标脏 | 抓到 | 抓到 | |
| 写入后重读旧所有者的根 | 4 处理器抓到 | 抓到 | |
| 写入后重读新所有者的根 | 抓到 | 抓到 | |
| 到期弹出的槽位 | 未抓到 | 未抓到 | 冗余：睡眠到期经 `make_runnable` 改任务，预算任务每次结算都被可变访问 |
| 退出移除的槽位 | 未抓到 | 未抓到 | 冗余：退出紧接着把状态改成 `Exited` |
| 启用高精度时全部标脏 | 未抓到 | 未抓到 | 启用前断言没有实时任务，高精度睡眠也要先启用，此时没有应发布的事件 |
| `get_mut` 的标脏 | 未抓到 | 未抓到 | **未解释**：`get_mut` 也用于状态迁移，没有逐条查清为什么没有被发现；标脏由类型保证，代码仍在 |

没有被抓到的前三项是根据代码推断的冗余，没有用组合变异证实。

### 验证

- 验证链 `run-dirty-slots-suite.sh`（性质 NS-DIRTY-01）：Verus 19/0 + 负例、Proptest 2、Miri 1、fuzz 100 万 cov349，Loom N/A（全局调度器锁内访问），Kani 发版时验证。接入路径（NS-DIRTY-02）无法独立运行，五步 N/A，替代证据为校验内核。
- 定点 `accept-20261105-140303`：M1.1 / BOOT-STAGE / TIMER-PROGRESS / NS-DIRTY / SCHED1–3 / POL1–3 / DRV2C1 / DRV2C2 PASS。NS-DIRTY：默认启动 passes=494562、synced=43369；校验内核 1 处理器 488459 轮、4 处理器 509772 轮、8 处理器 578019 轮、RT2 专项 21945 轮，0 不一致。
- 定点通过，等批次全量。

## 7. 第三片：deadline 到 resume 时间点拆分（2026-11-06）

- 分支：`dev/issue2-s3`
- 基线：Wave 1 合入后的 `269fb84`
- 范围：只改高精度期限唤醒的诊断路径；`settle_highres()` 全表结算、owner-leaf 到期快路径、KVM/裸机对照、Ring/对象释放和模块装配均不在本片。

### 六个时间点

| 时间点 | 观测位置 | 边界 |
|---|---|---|
| deadline | 睡眠登记的绝对纳秒时刻 | 与其它点同为启动校准后的共享纳秒域 |
| interrupt | Core 本地定时器分发进入高精度路径，在取调度锁之前 | x86_64 架构 EOI 之后；不是硬件向量第一条指令 |
| lock | 现有全局 `KERNEL_SCHED` 锁取得后 | 不新增锁；包含此前的取锁等待 |
| wake | `make_runnable()` 真正开始处理到期任务 | 在删除期限节点之后、改任务状态之前取点 |
| queue publication | `make_runnable()` 内 `queue.enqueue()` 与 `relist()` 都返回后 | 运行队列字段、策略入队状态和运行列表成员均已发布 |
| resume | 恢复执行流上的 Rust 恢复钩子 | 已在 IRQ 屏蔽下，但不是架构返回指令或用户第一条指令 |

`deadline_to_interrupt / lock / wake / runnable` 是从 deadline 起算的累计区间；`deadline_to_runnable` 现在指向真实队列发布，不再指向 `make_runnable()` 入口。`deadline_to_resume` 仍覆盖全部到期唤醒。严格五点分解只接纳共享时钟且顺序有效的定时器事务样本。

对不是由定时器事务发现的到期唤醒，记为 `late_settlement`，仍计入 deadline→runnable 与 deadline→resume，但不伪造 interrupt 点。若定时器入口或取锁先于精确期限（校准/取时间的边界），记为 `early_timer`，同样保留总路径而排除五点分解。`invalid_order` 与 `invalid_resume` 是功能失败，不能用计时豁免。

### 开销与边界

- 观测只在 `krn2-observe` / `krn3-p999-verify` 构建存在；默认构建不取这些额外时钟，也不增加字段写入。
- 每次到期唤醒增加固定数量的共享时钟读数与定长直方图更新；没有分配、没有遍历任务表、没有额外锁。
- 本片没有去除 `settle_highres()` 的结算扫描（第四片），没有实现 fifth owner-leaf 快路径或 KVM/裸机性能对照。
- 共享纳秒跨处理器比较仍是平台校准假设；TCG 数值只作为机制与路径分解证据，不是物理 p99/p99.9 结论。

### 固定证据

- 单元 / Proptest / Miri：`verification/toolbox/run-deadline-phase-suite.sh`，生产 `raw_timing` 5/0；Proptest 3/0（顺序与时钟性质含 512 例）；Miri 1/0。Kani 两个 harness 已留在生产模块，按发版门禁运行。
- 8 核专项：`evidence/issue2/p999-phase2-20261106/krn3-p999-verify.serial`，计划完整、退出 33、资源与列表恢复。
- 定点 accept：`accept-20261106-185207`，M1.1 / TIMER-PROGRESS / NS-DIRTY / M1.4 / SCHED1 / SCHED1-计时 / SCHED2 / SCHED2-计时 PASS；QEMU 37 仅为计时参考项，定点点位不代表全量。

```text
[JSR-WAKE-PHASE] mode=isolated deadline=0us interrupt=10/10/10/6us lock=10/10/10/10us wake=10/10/20/14us runnable=10/20/20/20us resume=20/30/50/48us samples=9890/10000/10000 late=68 early_timer=42 invalid_order=0 invalid_resume=0 queue_publication=after-enqueue-relist clock=shared-ns-serialized
[JSR-WAKE-PHASE] mode=fanout-7 deadline=0us interrupt=10/10/10/5us lock=10/10/10/12us wake=10/10/10/16us runnable=10/10/20/20us resume=20/20/30/79us samples=14297/14336/14336 late=35 early_timer=4 invalid_order=0 invalid_resume=0 queue_publication=after-enqueue-relist clock=shared-ns-serialized
```

输出中的 `samples=严格五点分解/发布/恢复`；`interrupt/lock/wake/runnable/resume` 各组均为 `p50/p99/p99.9/max`，单位 μs。

### 验收条目

| 条目 | 状态 |
|---|---|
| deadline→中断→取锁→开始唤醒→队列发布→resume 六点可观察 | 已完成；严格有序定时器样本与 late/early 边界分别记账 |
| 队列发布点位于 `make_runnable()` 真正发布之后 | 已完成；端点在 `enqueue + relist` 后取得 |
| 不引入无界开销或额外锁区间 | 已满足；观测为定长 O(1)，复用现有全局锁，无新增分配/锁 |
| 单元、属性与定点证据 | 已满足；见上 |
| `settle_highres()` 去全表扫描 | 留第四片 |
| owner-leaf 本地到期快路径 | 留第五片 |
| KVM / 裸机性能对照 | 留第六片 |

## 8. 第四片：`settle_highres()` 拆分与预算事件化（2026-11-06）

- 分支：`dev/issue2-s4`
- 基线：`e31775d`
- 范围：只改高精度 deadline/预算结算路径及其验证；owner-leaf 快路径、KVM/裸机对照、Ring、对象释放和模块装配均不在本片。

### 拆分后的路径

| 路径 | 旧实现 | 新实现 |
|---|---|---|
| 运行中预算 | 每次高精度锁事务检查所有在线 CPU 的当前任务，并逐处理器 `settle` | 每个在线 CPU 只比较下一次检查点；配额耗尽点或周期边界到达时才取可变引用并结算 |
| 切换/阻塞/退出 | 靠稍后的全 CPU 扫描补记 | 在离开处理器 owner 前结算 `ns_at..now`，再推进 `ns_at`；不依赖后续扫描 |
| 非运行预算补充 | 每次扫描全部任务槽位，对每个睡眠/可运行预算任务 `settle(now,now,false)` | 预算 `next` 已进入期限堆；只在该节点的到期事务中补充并重新入堆，不累积错过的周期 |
| 到期事件 | 扫描所有在线 CPU 根后弹出 | 先用缓存根跳过未到期 CPU，只对到期根调用 `pop_due` |

`Budget::running_settle_at(start)` 把运行检查点定义为“配额耗尽点与周期边界中较早者”；剩余为零时只等周期边界。该函数的生产实现、Verus 伴随模型、Proptest、Miri、fuzz 和发版 Kani harness 使用同一语义。所有状态仍由现有全局调度锁串行化，没有新增锁、分配或 Ring/对象生命周期更改。

复杂度从每轮 `O(C + N)`（另加到期堆操作）改为每轮 `O(C + E log N)`，其中 `N` 是任务槽位、`C` 是在线 CPU、`E` 是本次弹出的到期事件；非到期预算任务不访问。切换路径增加一次仅针对带预算 owner 的 O(1) 区间结算。

### 同口径前后对照

计数由同一观测补丁产生，`heap_ops` 定义为期限堆写次数加到期弹出次数；`max_settle_cycles` 是 `settle_highres()` 在调度锁内的最长架构周期数。窗口是完整的 8 核 `krn3-p999` 客户机，固定 10,000 个隔离唤醒、14,336 个七核 fanout 唤醒。

| 8 核 p999 客户机 | 改动前 | 改动后 |
|---|---:|---:|
| 结算调用遍数 | 168,615 | 168,662 |
| CPU 检查数 | 1,348,920 | 1,349,296 |
| 到期 CPU 数 | 24,336 | 24,336 |
| **任务槽位扫描数** | **10,791,360** | **0** |
| 到期事件/弹出数 | 24,336 | 24,336 |
| **堆操作数** | **48,672** | **48,672** |
| `settle_highres()` 最长锁内周期 | 7,914 | 7,035 |
| isolated resume p50/p99/p99.9 | 20/30/40 μs | 20/20/20 μs |
| fanout-7 resume p50/p99/p99.9 | 20/20/40 μs | 20/30/30 μs |

两轮 p999 的唤醒样本量均为 isolated `10,000`（改动前/后严格分解分别为 `9,922` / `10,000`）和 fanout-7 `14,336`（`14,271` / `14,220`）；`invalid_order=0`、`invalid_resume=0`、资源与列表恢复。TCG 周期和微秒值只证明机制与同机对比，不是物理 p99.9。

4 核 `ns-dirty-audit,rt2-verify` 另取固定 RT2 工作负载。基线审计 5,037 轮、改动后 1,510 轮；两者都 `audit_mismatch=0`，目录和退出路径不同使锁事务数不等，因此下表的样本量按实际运行记账：

| 4 核 RT2 | 改动前 | 改动后 |
|---|---:|---:|
| 结算调用遍数 | 5,037 | 1,513 |
| CPU 检查数 | 20,148 | 6,052 |
| 到期事件/堆弹出 | 447 | 78 |
| **任务槽位扫描数** | **322,368** | **0** |
| 运行态预算结算 | 2,210 | 150 |
| 非运行态预算补充 | 2,061 | 52 |
| 堆操作数 | 902 | 164 |
| `settle_highres()` 最长锁内周期 | 132,192 | 103,104 |

改动后 RT2 确实执行了运行态结算和非运行态补充；最长锁内周期不是稳定性能门限，未用于放宽任何功能判据。主要验收事实是旧实现每轮扫描 `N` 个槽位，新实现该计数为 0，同时审计、RT2 功能、资源和列表断言保持通过。

### 验证与边界

- 六步链：`VERUS=… bash verification/toolbox/run-ns-budget-suite.sh`。Verus 11/0 + 负例，kernel-core 3、Proptest 5、Miri 1、fuzz 100 万；Loom N/A（调用方串行化的值类型），Kani 发版时验证。
- 最终 QEMU：串行执行 `scripts/ns-dirty-check.sh`。默认启动 1 核 508,459 轮/508,461 次审计、4 核 522,023/522,025、8 核 563,741/563,743，均为 `audit_mismatch=0`；4 核 RT2 为 1,510/1,515 轮和审计，功能、资源与列表断言全通过。另以相同 8 核 p999 工作负载比较前后。`scripts/ns-dirty-check.sh` 的三个默认客户机现各自经 `/tmp/jasper-os-qemu.lock` 串行。
- 未实现第五片 owner-leaf 本地到期快路径、第六片 KVM/裸机对照；未改 Ring、对象释放或模块装配。
- TCG 不是物理实时保证，跨处理器共享纳秒仍依赖既有平台校准假设。

## 9. 第五片：owner-leaf 本地到期快路径评估（2026-11-07）

- 分支：`dev/issue2-s5`
- 基线：`dc3f7ba`
- 结论：**当前模块化宏内核不实现独立 owner-leaf 发布快路径。** 不是性能目标取消，而是当前状态所有权不允许在“只持本核 leaf 锁”时安全发布唤醒。

### 状态归属与线性化点

| 状态 | 当前唯一权威位置 | 本地快路径若直接读取/修改的风险 |
|---|---|---|
| 期限堆节点与 CPU 根 | 全局 `Scheduler::ns_heap` / `ns_roots` | 不同 CPU 可同时修改同一规范调度器存储 |
| 任务状态、home、等待轮次、TimerId | 全局调度器任务表与 `timer_table` | 读取后迁移可令 owner/代次失效，发布必须与迁移线性化 |
| 运行队列、策略实体、`on_cpu` | 每核 `RunLeaf` | leaf 锁只能排除同核竞争者，不能单独冻结跨核迁移 |
| TimerId 终态 | 全局 `timer_table` | “到期”和“取消/迁移”必须有同一终态裁决点 |
| runnable 发布 | `make_runnable` 更新任务状态、运行队列与运行列表 | 发布前后必须保证旧 owner 不再消费、新 owner 可见唯一节点 |

候选快路径只有在同时满足以下条件时才是函数正确的：事件身份仍为当前 TimerId+generation；任务仍阻塞且 home 与 CPU 根一致；迁移/取消尚未赢得终态；本核持有可阻止所有规范状态写者的许可；runnable 发布完成后才允许另一核消费。前四项不能由单个 `RunLeaf` 锁保证，因此需要取得全局调度器或等价的跨 leaf 排他许可。取得该许可后，路径已不再是与全局控制面并行的“owner-local”路径，而只是把现有全局事务改名并增加旁路。

### 并发反例

新增 `verification/owner_leaf_fast_path.tla`：

- 正模型：17 生成 / 15 可达 / 深度 5；本地读取后必须保持规范串行化，迁移不能与发布交错，`NoStaleWake`、`OwnerMatchesClaim`、`AtMostOneWake` 均成立。
- 反例一：去掉规范串行化，允许本地读取后任务迁移，旧 CPU 仍用旧 owner/代次发布 → `NoStaleWake` 违反。
- 反例二：允许非 owner CPU 发布本地节点 → `NoStaleWake` 违反。

这证明“少拿全局锁”本身不是充分条件；必须先把任务状态、期限节点 owner 与 runnable 发布原子化到同一权威位置。直接实现 leaf-local 旁路会制造陈旧发布/重复唤醒窗口。

### 决策与后续条件

当前保留全局规范线性化点，不在生产代码中添加半安全快路径。未来只有满足任一条件后才重新评估：

1. 把任务状态、期限节点 owner 与 runnable 发布迁到同一 per-CPU 权威状态，并定义迁移交接协议；
2. 或引入跨 leaf 的轻量排他许可，且基准证明它比现有全局事务有实质收益。

在此之前，非运行预算与到期堆已按第四片事件化，不再每 tick 全任务扫描；继续优化应针对测得的具体全局锁区间，而不是先假设 owner-leaf 旁路更快。

复现：

```bash
bash verification/run-owner-leaf-fast-path-tlc.sh
```

## 10. 第六片：KVM 正式性能基线（2026-11-07）

- 分支：`dev/issue2-s6`
- 基线对照：Wave 1 `269fb84`（issue #2 第三/四片性能改造之前）
- 当前：Wave 6 `4c30e93`
- 环境：宿主 KVM、`-cpu host`、QEMU 10.2.1、CPU 4–11、8 个 vCPU；两组镜像和采样脚本相同。

当前版本共运行 10 轮：9 轮完整，1 轮 fanout 只收到 14335/14336 样本并因此被功能门拒绝。该失败轮保留，不从原始证据删除。补充 `errors/carried/pending` 诊断后当前连续 5 轮全部完整；失败未再复现，根因不能仅凭现有证据归为宿主噪声。

有效轮次的 p50/p99/p99.9（µs）：

| 版本 | isolated | fanout-7 | 说明 |
|---|---|---|---|
| `269fb84` | 10/30/40、10/40/80、10/30/80 | 10/30/50、10/40/60、10/40/50 | 3/3 完整 |
| `4c30e93` | 常见 10/20–30/40；另有 10/30/50、10/40/80 | 常见 10/30–40/50；另有 10/40/90 | 9/10 完整；当前诊断后连续 5/5 完整 |

结论：

- 当前版本的 isolated/fanout 唤醒 p99.9 稳定在 40–50 µs 的主区间，fanout 没有可重复的性能回退；
- 宿主 KVM 的 p99.99/max 受宿主调度长尾影响明显，单轮 max 从几十 µs 到数 ms 均出现过，不能把 max 当作内核固定开销；
- 一次样本缺失说明“高负载下性能采样完整性”仍需继续观察，不用丢弃失败轮或放宽 `complete` 断言来换取通过；
- KVM 已按用户裁决作为正式性能基线；裸机仅保留为硬件差异交叉核验，不再是当前阻塞条件。

复现当前版本五轮：

```bash
JASPER_CORES=4-11 ROUNDS=5 bash scripts/kvm-p999-repeat.sh
```

基线对照可先构建 `269fb84` 的 p999 镜像，再以
`IMAGE=<baseline-image> ROUNDS=3 bash scripts/kvm-p999-repeat.sh` 运行。
