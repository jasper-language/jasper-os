# Issue #47 阶段 1：CPU 固定容量消费链审计

更新时间：2026-11-19。

状态：**阶段 1 审计清单；当前 128 槽生产实现仍存在，阶段 2/3 尚未完成。**

## 已知固定事实

| 位置 | 当前事实 | 性质 |
| --- | --- | --- |
| `kernel-core/src/smp.rs` | `BOOTSTRAP_CPUS = 128` | 堆就绪前的 bootstrap 暂存容量；不得成为最终运行期上限 |
| `kernel-core/src/smp.rs` | `MAX_CPUS = BOOTSTRAP_CPUS` | 过渡期位图容量，当前仍限制生产拓扑 |
| `kernel-core/src/smp.rs` | `CpuSet([u64; CPU_SET_WORDS])` | 固定 128 位集合，需迁移到动态/分段结构 |
| `Topology` (`cpu-dynamic`) | 128 项 bootstrap + `Vec<u32>` overflow | 固件库存可超过 128，但最终调度集合仍无法表达 |
| 旧原生亲和 ABI | 固定宽度字 | 高位 CPU 必须显式拒绝或由新可变长 ABI 替代 |

`discovered`、`supported`、`admitted`、`online` 和 `rejected` 必须保持独立；
`Topology` 保留全部固件身份不代表调度器、IRQ 或原生 ABI 已支持对应 CPU。

## 生产消费链

以下清单排除了 `_demo`、`*/demo/*` 和测试文件。

| 消费域 | 生产文件 | 当前依赖 | 迁移归属 |
| --- | --- | --- | --- |
| CPU 集合/拓扑/击落/IPI | `kernel-core/src/smp.rs` | 33 处固定集合引用；固定 bitmap、定时数组、CallSlot 测试边界 | 阶段 2 核心 |
| 环境/亲和策略 | `kernel-core/src/environment.rs` | 用 `MAX_CPUS` 校验 demand CPU | 阶段 2/3 |
| FDT/IOMMU CPU 校验 | `kernel-core/src/fdt.rs`, `iommu.rs` | 固定 CPU 上限校验 target CPU | 阶段 2/3 |
| IRQ 路由/配额 | `kernel-core/src/irq.rs`, `kernel/src/irq.rs` | 每核 MSI handler/count/quota、固定行投影数组 | 阶段 3 |
| MSI 向量池 | `kernel-core/src/msi.rs` | 每核固定向量位图 | 阶段 3 |
| sharding/tickless | `kernel-core/src/shard.rs`, `tickless.rs` | shard 数量、每核 stop 时间数组 | 阶段 3 |
| per-CPU 数据/IPI/AOK | `kernel/src/smp/percpu.rs`, `kernel/src/smp/mod.rs` | `[PerCpu; MAX_CPUS]`、固定 board 初始化 | 阶段 2/3 |
| x86 SMP/GDT/TSS/syscall/user | `kernel/src/arch/x86_64/{smp,gdt,syscall,user}.rs` | 每核 HW ID、TSS/GDT、syscall 返回帧 | 阶段 3 |
| AArch64 SMP/GIC/user | `kernel/src/arch/aarch64/{smp,gic,user}.rs` | 每核接口、affinity、GIC 状态、用户栈 | 阶段 3 |
| RISC-V SMP/PLIC/devIRQ/user/boot | `kernel/src/arch/riscv/{smp,plic,devirq,user,boot}.rs` | mailbox、context、每核启动/用户状态 | 阶段 3 |
| LoongArch SMP | `kernel/src/arch/loongarch64/smp.rs` | HW ID 表、AP 静态栈和拓扑截断迁移 | 阶段 2/3 |
| 调度器 | `kernel/src/sched/scheduler.rs`, `sched/mod.rs` | 86+13 处固定数组：运行队列、wake/RT/NS heap、idle context、统计、timer | 阶段 3 |
| 调度探针/统计 | `kernel/src/sched/pex4_probe.rs`, `wcet.rs` | 每核采样数组、IRQ-off 计数 | 阶段 3 |
| 同步/锁诊断 | `kernel/src/sync.rs` | 每核 acquired 计数 | 阶段 3 |
| 配置/架构门 | `kernel/src/config.rs`, `kernel/src/arch/mod.rs` | CPU 容量检查/架构每核门面 | 阶段 2 |
| Linux 亲和兼容 | `kernel/src/linux_abi.rs` | 旧固定掩码语义 | 阶段 4 兼容适配 |

未纳入迁移的生产宏/生成代码必须在阶段 1 结束前补充；演示代码可以继续使用固定夹具，
但只能作为软件测试夹具，不能定义生产容量。

## 启动生命周期与分配约束

### 1. 堆前固件发现

- 尚无 `alloc` 时只允许写入受审计 bootstrap 暂存区；
- bootstrap 暂存区溢出必须保留 discovered/overflow 事实，禁止发布 `inventory_complete=true`；
- 固件 ID 可以稀疏、重复或非法，逻辑索引不得由硬件 ID 直接充当；
- disabled、转换失败、重复项和容量不足必须分别计数；
- 此阶段不得声称 CPU 已 supported/admitted/online。

### 2. 堆后拓扑迁移

- bootstrap 记录必须无损迁移到堆后备身份和动态集合；
- 迁移前冻结唯一 owner，完成后旧暂存区不得继续作为第二事实源；
- 分配失败时保留完整 discovered 事实并拒绝启动，不得回退为启动 128 个子集；
- 逻辑 CPU ID 分配、硬件 ID、NUMA 节点和 generation 必须在同一次发布中提交。

### 3. 资源准入与上线

- 准入成本至少包含身份/拓扑、per-CPU 状态、空闲栈、调度队列/统计、IRQ/MSI、
  timer/RT、TLB/IPI 与诊断元数据；
- 完整 enabled 库存必须同时满足预算；本阶段已加入无固定数量的预算函数，但当前
  只对 secondary idle stack 做了真实预算接线，其他静态元数据仍待阶段 3；
- 每个 secondary 的资源预留在 Start IPI 前完成；
- 分配失败、元数据初始化失败和状态迁移失败不得发布 Online；
- 迟到报到、超时或 reset 后，旧 generation 的 Handle/I/O/IRQ completion 不得复活。

### 4. Lock/IRQ 约束

- 拓扑发布锁、CPU 状态锁、调度锁和 IRQ 锁保持既有全局顺序；
- 不得在 IRQ 关闭或 IRQ-safe spinlock 持有时调用堆分配；
- 动态扩容/收缩先冻结候选集合，再在锁外分配，随后原子发布或整体回滚；
- IPI/TLB/cross-CPU call 只访问已发布且仍在线的 generation；
- CPU 下线时先停止新投递，再迁移/排空任务与 IRQ，最后撤销资源和集合成员。

## 阶段 2/3 迁移顺序

1. 把 `CpuSet` 从 `Copy` 固定位图迁为可扩展集合，提供运行期 `capacity/word`、成员迭代、
   union/intersection/without 和失败原子扩容；
2. 转换拓扑 bootstrap -> 堆后备 inventory，并建立唯一 CPU runtime registry；
3. 迁移 `PerCpu`、shootdown boards、mailbox/call slots 和 TLB/IPI；
4. 迁移四个架构 SMP/GIC/PLIC/TSS/syscall/user 入口；
5. 迁移调度器、timer/RT、IRQ/MSI 和 Workload/NUMA；
6. 迁移诊断/统计/探针，最后迁移原生亲和 ABI 和兼容翻译。

## 阶段 1 负例清单

- `present=129, disabled=1` 可准入 128；`disabled=0` 且预算只足够 128 时整体拒绝；
- 129/256/1024/4096 软件准入无固定数量上限；
- disabled 数大于 present、零 enabled、乘法溢出失败关闭；
- 重复、稀疏、异常硬件 ID 在 Topology/架构适配层保留并拒绝不完整拓扑；
- bootstrap 溢出不能被报告为 complete；
- 当前 128 边界必须保留正向与拒绝测试，直到动态结构替换完成。

## 尚未完成

本审计没有删除固定 `CpuSet`，也没有迁移生产每核数组。Issue #47 阶段 1 的清单已完成
第一版，但仍需在阶段 2 开工前逐文件确认生成代码、宏和构建期条件没有遗漏；阶段 2/3
完成前 `CPU-DYNAMIC-ADMISSION-1` 不能标记 done。

## 消费链迁移进度

- `kernel-core/src/msi.rs`：已完成首个生产迁移。`VectorPool` 在生产
  `cpu-dynamic` 构建中使用 `CpuBitmap` 在线集合和堆后备每核向量位图；CPU 129 的
  稀疏分配已有宿主测试。无该 feature 的用户运行时轻量构建继续使用固定兼容路径。
- `kernel/src/interrupt.rs` 将当前 legacy `CpuSet` 在线集合适配为动态 MSI 集合；
  分配失败时 MSI 池构造失败关闭。
- `kernel-core/src/shard.rs`：删除 `MAX_SHARDS = MAX_CPUS * 4`。路由分片数只受
  32 位分片编号格式范围约束，不再从 CPU 位图宽度派生非规范容量上限；任意更大
  运行期分片预算由服务自身资源准入决定。
- `kernel-core/src/iommu.rs`：中断重映射不再用 `MAX_CPUS` 拒绝目标 CPU；IOMMU
  只保留 `u8` 路由字段的协议表示范围，具体 CPU 是否存在/在线由 IRQ/调度权威校验。
  `target_cpu=255` 的保存与原样读回已有测试。
- `kernel-core/src/environment.rs`：CPU 资源 Demand 亲和集合在生产
  `cpu-dynamic` 构建中使用 `CpuBitmap`，删除 `MAX_CPUS` 平台检查。资源准入只依赖
  所选 CPU 是否在亲和集合中；实际硬件/在线资格由 CPU runtime registry 和调度器
  统一校验。轻量无 feature 构建保留 legacy `CpuSet` 适配。
- `kernel-core/src/tickless.rs`：`StopBoard` 的生产 `cpu-dynamic` 路径使用
  `CpuBitmap` 与按已准入 CPU 数预分配的起止时刻表，删除 `[u64; MAX_CPUS]`。
  调度器在 AP 启动前的静止事务中完成停表表和唤醒扫描暂存区预分配；`stop`/
  `restart` 与计时器 `kick_stopped` 路径不再临时扩容。宿主测试覆盖 129 和 4096
  号 CPU；无堆轻量构建保留 `CpuSet` 兼容路径。
- `kernel-core/src/numa.rs`：NUMA 节点的 CPU 本地域在生产 `cpu-dynamic` 构建中
  使用 `CpuBitmap`，节点查询与跨节点重复 CPU 校验消费同一动态成员集合。CPU 4096
  的本地节点和距离优先顺序已有宿主测试；无堆轻量构建保留 `CpuSet` 兼容路径。
- `kernel-core/src/cpu_runtime.rs`：新增堆后 CPU runtime registry，以同一次事务发布
  discovered / supported / admitted / online / offline / rejected 事实。逻辑 CPU
  与稀疏硬件 ID 分离，完整 enabled 库存必须同时满足支持与资源预算；重复硬件 ID、
  未支持 CPU、资源不足均不发布部分状态。内核启动已用该 registry 做准入、硬件 ID
  解析和 AP 上线代际登记。
- `kernel-core/src/{fdt,acpi,smp}.rs`：disabled CPU 不再只保留计数，具体硬件 ID
  进入 Topology；LoongArch 的堆前暂存路径也保留 disabled ID，暂存不足计入
  `dropped` 并失败关闭。
- `kernel-core/src/irq.rs` 与 `kernel/src/irq.rs`：IRQ 路由允许集合、在线集合、
  负载投影和自动均衡全部使用动态 CPU membership；`set_affinity_dynamic` 可直接
  接收高位稀疏集合。129/4096 号 CPU 的 spread/keep 决策已有宿主测试，真实
  QEMU IOAPIC 路由在 4 vCPU 上通过。
- `kernel/src/task.rs`、`kernel/src/sched/scheduler.rs`：任务亲和采用两阶段表示。
  堆前任务只保存 bootstrap 标记；`Scheduler::grow` 将全部任务事务化迁移到调度器
  持有的连续堆后备槽位表。CPU 准入后按实际数量重建该表，spawn、继承、
  `set_affinity`、实时预算放置和均衡候选均通过预分配槽位完成，不再在调度锁内
  临时分配。129/4096 号 CPU 的 placement/steal 已有宿主测试，4 vCPU QEMU
  IOAPIC/调度路由通过。
- `kernel/src/smp/percpu.rs`：每核数据保留堆前 bootstrap 区，并在 AP 启动前按
  已准入 CPU 数量一次性预留堆后备记录；`get`/`this` 已能通过同一逻辑索引访问
  bootstrap 之外的记录。分配失败会阻止任何 secondary 上线，不在中断路径扩容。
- `kernel/src/arch/mod.rs`、`kernel/src/smp/mod.rs`：全局 `cpu_index` 在 runtime
  registry 发布后按 lock-free 的 admitted CPU 数量校验，避免架构门面再次把合法
  逻辑 CPU 截断到 bootstrap 宽度。该快路径不能取 runtime 的 IRQ 安全锁，否则会
  形成 `lock -> per-CPU -> cpu_index -> lock` 自依赖；x86/LoongArch 的硬件 ID
  映射表仍需后续单独迁移。
- `kernel/src/arch/x86_64/{syscall,user}.rs`：每核 syscall 入口块与 clone/exec
  返回帧保留静态 bootstrap 区，并在任何 secondary CPU 启动前按完整准入数量一次性
  分配堆后备连续表。入口块地址在分配后保持稳定，AP 初始化、内核栈更新和用户态
  返回路径只索引已发布存储；缺失或分配失败会在启动前失败关闭，IRQ 路径不再依赖
  固定 `MAX_CPUS` 表。
- `kernel/src/arch/x86_64/gdt.rs`：每核 GDT、TSS、双重错误栈和初始 rsp0 栈同样在
  任意 AP 启动前全部预留。CPU 指针表采用 bootstrap 加堆后备扩展，具体 GDT/TSS
  使用稳定独立分配；任一表或栈分配失败都不会启动 secondary。`set_kernel_stack`
  和 AP 入口只查询已发布表，不在中断路径扩容。
- `kernel/src/arch/riscv/user.rs`：RV32/RV64 共用的每核用户返回内核栈记录改为
  bootstrap 加 AP 启动前堆扩展。4 处理器 RISC-V64 QEMU 中 SMP 汇总与
  `kstack per_cpu set/kept/restored=3/3` 通过。
- `kernel/src/arch/riscv/{boot,plic,smp}.rs`：PLIC context 注册从堆前
  `configure_devices` 移到堆后 `init_boot` 拓扑发布阶段，修复 CPU 1–3 context
  全缺失、设备中断只能落到 CPU0 的真实缺陷。context 存储改为 bootstrap 加堆扩展；
  4 vCPU QEMU 中每个 CPU 的两条中断均精确送达，`delivered_exact=4/4`，IRQ 汇总
  `failed=0`。该轮仍保留既有 PCI/KRN0 失败，不等于 RISC-V 全量验收完成。
- `kernel/src/{ifc,security,service_catalog}.rs`：把生产 64 位计数器/对象源
  从直接 `AtomicU64` 改为 `kernel_core::sync::Atomic64`。RV32 目标因此可以编译并
  完成真实 QEMU 启动；SMP、平衡、IRQ、IPC、用户运行时、QoS 等已运行阶段失败数为
  0，整体仍因既有 PCI/KRN0 缺口退出失败。
- `kernel/src/arch/aarch64/user.rs`：每核用户返回内核栈记录改为 bootstrap 加
  AP 启动前堆扩展。Pixel 6a 无损 runtime 在 `4.49s` 到达 PSCI reset，恢复到同一
  Android build，`sys.boot_completed=1` 且 slot 仍为 `a`。
- `kernel/src/arch/aarch64/gic.rs`：每核 GICv2 interface 目标、GICv3 affinity 与
 注册状态合并为 bootstrap 加堆后备记录，并在 AP 启动前一次性预留。SGI/IPI、
  SPI target 和中断记录路径只查询已发布 CPU 状态；下一次 Pixel 无损 runtime
  在 `4.48s` 到达 reset 并恢复 Android。
- `kernel/src/sched/scheduler.rs`：`cpu_stats`、`cpu_residency`、类别仲裁窗口和
  idle context 改用调度器内联 bootstrap + 堆后备扩展表，在 AP 启动前与 CPU
  容量一起原子预留。运行期这些每核统计与上下文不再由固定 128 槽决定容量。
- `kernel-core/src/deadline_forest.rs`：deadline forest 保留内联 bootstrap heaps，
  并增加按已准入 CPU 数预分配的堆后备 heap 表；CPU 130 的软件测试通过。
- `kernel/src/sched/scheduler.rs`：AP 启动前同时重建 wake、RT 和纳秒预算三个 forest
  及其按 CPU 步长排列的 entries，迁移现存期限事件后整体替换。timer/RT 热路径
  不在持锁时扩容，也不再依赖 `DeadlineForest<128>` 作为最终 CPU 上限。
- 调度器运行队列身份已从 `u8` 迁移到 `usize`，slot 链表的队列归属使用无符号
  非零整数编码而不是 `u8::MAX` 哨兵，双队列迁移的 CPU 对也不再经过 `u16` 截断。
  这移除了队列身份和规范化锁序上的 255/65535 上限。每个 leaf 只拥有一个外部
  CPU 运行队列，其本地 RunLists 表头因此固定为 1 项；外部 CPU 身份保存在
  `CoreQueue`/`SchedEntity` 的 `usize` 编号中，不再按全机拓扑复制表头。
- 其余调度器固定表、共享 CpuSet 门面、部分诊断和亲和 ABI 尚未迁移。
