# issue #6 进度：模块与 Profile 的服务能力实际可用性统一装配契约

## 第一切片（本次）

### 做了什么
- **`kernel-core::assembly`（新）**：服务装配契约。
  - 每个声明模块的运行时状态机：`Declared → Initializing → Ready → Stopped`，以及 `Blocked`（依赖未就绪，激活函数不被调用）与 `Failed`（激活失败）。只有 `Ready` 模块提供的能力进入发布掩码。
  - `Binding`：模块名 → 激活函数 / 可选停用函数。生效 Profile 声明的每个模块必须恰好有一条绑定（缺失、重复在构造时拒绝）；没有停用函数的模块是启动期常驻服务，停用请求得到 `permanent`。
  - 启动顺序由能力依赖自动推出（稳定拓扑序，同层按声明顺序），依赖成环在构造时拒绝；不再需要调用者手排顺序。
  - `published_mask`：按解析后能力表下标生成发布掩码；`audit`：把任意一份发布掩码与装配状态逐项比对（发布了未就绪能力、就绪未发布、未知位、就绪模块依赖未就绪，四类均报错）。
  - `availability`：区分「未声明」「声明但未就绪（附当前状态）」「可用」。
- **`kernel::assembly`（新）**：生效 Profile 的 8 个模块（core / memory / time / sched / channel / realtime / job / async）各绑定一个真实就绪检查（对象表与任务表已安装、内核堆已初始化、定时器在走、实时表已安装、作业队列启动时为空等）。启动期以全有全无策略装配、审计，通过后以 Release 写入发布掩码。
- **能力查询改为读发布结果**：`profile::has_capability`（实时类设置、批处理作业、多模式仲裁等全部调用者）不再查声明表，而是查发布掩码；装配前查询恒为不可用。只关心声明面的地方继续用 `profile::resolved()`。
- **`system.profile.get`**：渲染文本新增 `published=` 行，列出生效 Profile 当前真正可用的能力（非生效 Profile 恒为空）。
- **启动**：装配是启动阶段图（issue #7）的第十个阶段 `assembly`，依赖 `timer`、`capacity`、`profile`，紧接 Profile 校验执行；任何模块失败、被阻塞或审计不一致都拒绝继续启动（`[JSR-EXIT] failure assembly_failed=…`，阶段跟踪器同时记 `failed stage=assembly`），并逐模块输出 `[JSR-ASSEMBLY] module=… order=… state=… reason=…`。

### 裁决（对应工作要求 2）
| 情形 | 裁决 |
|---|---|
| 依赖顺序 | 由能力依赖自动推出的稳定拓扑序；成环构造时拒绝 |
| 缺依赖 | Profile 缺依赖由校验拒绝；运行时依赖未就绪 ⇒ `Blocked`，不调用激活，原因记为所缺能力 |
| 初始化中途失败 | 激活必须原子（失败不留半状态）；全有全无策略按就绪逆序回滚、什么都不发布，未尝试的模块保持 `Declared`；部分策略只阻塞失败模块的传递依赖者 |
| 部分启动 | 只在部分策略下发生，发布掩码恰为就绪模块的能力；内核启动采用全有全无 |
| 重复初始化 | 一份装配只能启动一次，第二次返回 `already_started` 且不调用任何激活；同名重复绑定构造时拒绝 |
| 停用 | 仍被就绪模块依赖 ⇒ `in_use`；常驻模块 ⇒ `permanent`；发布方须先撤回能力位再停用 |

### 对照验收条目
- [x] 有依赖的实际服务装配：内核 8 个模块按依赖装配（core 先）。
- [x] 缺依赖、初始化中途失败、回滚、重复装载、服务未就绪查询均有测试（kernel-core 单元测试 5 项 + 差分性质测试 + 模糊测试 + 有界模型检查）。
- [x] Profile 声明与运行时发布可自动比对：`audit` 在启动期对实际发布的掩码执行，任意偏离被拒（Kani 对任意非零翻转证明）。
- [x] 锁序与模块生命期正确性：装配不持锁、只在启动期单处理器执行；发布协议（Release 写 / Acquire 读）以 Loom 模型验证；就绪集合在启动、停用、回滚下保持依赖闭包（Verus 伴随模型）。
- [ ] 中心代码位置对比：见下节；`kmain` 中子系统的阶段性启动步骤仍保留（硬件约束顺序），本切片未把它们改成装配激活。

### 新增一种服务需要改的位置
| | 之前 | 本切片之后 |
|---|---|---|
| 声明 | `kernel-core::profile` 模块表加一项 | 同左 |
| 装配顺序 | 调用者手排 | 无需改动（由依赖推出） |
| 就绪判定 | 无（声明即可用） | `kernel::assembly::BINDINGS` 加一条绑定；缺了启动即报 `missing_binding` |
| 能力查询 | `has_capability` 查声明 | 无需改动（自动读发布掩码） |
| 验收 | — | `[JSR-ASSEMBLY]` 模块行自动出现 |

### 验证
- 六步验证链 `verification/toolbox/run-assembly-suite.sh` 整体通过（性质登记表 `ASSEMBLY-01`～`03`、`MODULE-MGR-01`）：Verus 伴随模型 13 verified / 0 errors（负例：停用漏掉「无就绪依赖者」前置条件，验证失败）；kernel-core 单元测试 5 + 4；Proptest 差分 3 项（随机依赖图 ≤8 模块 × 随机声明顺序 × 随机成败 × 两种策略，各 512 例）；Miri 固定序列 1；cargo-fuzz 装配 100 万次 0 崩溃（cov 417）、ModuleManager 100 万次 0 崩溃（cov 100），均开启泄漏检测；Kani 3 个证明 SUCCESSFUL；Loom 发布协议模型 1。
- 补链：既有 `ModuleManager`（原无验证链）一并完成上述六步（Loom 不适用：`&mut` 单所有者，无共享可变状态）。
- 定点验收：`asm1`（新增）、`pol2`、`pol3`、`sched2`、`m11` 通过；`m14`（定时器抢占演练，位于装配之前、本切片未改动）在虚拟机负载 9 下两次 tick 切换 8 < 10，单独复跑 tick 切换 12 通过，判为 TCG 执行速度相关的计时性判据。

### 合入验证（变基到含启动阶段图的 main 之后）
- 变基时把装配接入阶段图：`Stage::Assembly`（`COUNT` 由 9 变 10，`done_mask` 由 `0x1ff` 变 `0x3ff`），阶段跟踪器的 Verus 伴随模型、差分测试与 `BOOT-STAGE` 判据同步修改。阶段图套件 `run-boot-stage-suite.sh` 通过：Verus 34 verified / 0 errors + 负例、kernel-core 5、Proptest 3、Miri 1、fuzz 100 万 cov 82、Kani 4 个 harness 均 SUCCESSFUL，Loom N/A。
- 装配套件 `run-assembly-suite.sh` 在 `48cd76f` 通过除 Kani 外的五步：Verus 13 verified / 0 errors + 负例、kernel-core 5 + 4、Proptest 3、Miri 1、fuzz 装配 100 万 cov 417、ModuleManager 100 万 cov 100、Loom 1。
- **Kani 三个 harness 在现行上限（单个 10 分钟、虚拟内存 3.5 GB）下未判定**：`published_mask_never_reports_unready`、`audit_rejects_any_divergent_mask`、`loaded_set_stays_dependency_closed` 都因内存耗尽没有结论，日志中没有任何失败检查项。前两个是求解器跑过若干轮后驱动进程分配内存失败；第三个是求解器在命题化阶段报内存不足。把第一个收窄为两处任意激活后同样耗尽，已撤销收窄。上限之外的结论只有 `d0e7bc9`（无内存上限）的 3 个 SUCCESSFUL；它们覆盖的非测试代码至今未变，但本次没有在现行上限下复现。
- 修了一个测试缺陷：`failure_all_or_nothing_rolls_back_and_publishes_nothing` 与其他激活测试共用一份日志，并行时记录混入，偶发失败；现在这些测试串行执行，修复后连续 10 次通过。
- 定点验收 `accept-20261104-131513`：M1.1、BOOT-STAGE、ASM1、POL1、POL2、POL3、SCHED1、SCHED2、SCHED3 通过，`SCHED2/计时` 1 行超界（只作 QEMU 参考，不阻塞）。依赖审计 0 漏洞（只有 bincode 未维护告警）。
- **2026-11-05 更新：批次全量 `accept-20261105-114916` 已覆盖本片（ASM1 PASS，105 PASS / 0 FAIL）。** 当时记录：**定点通过，等批次全量**：本片尚未经过 1/4/8 核与 q35 全量验收；装配只在引导处理器的启动期执行，多处理器路径未单独运行。

## 第二切片（2026-11-06）

### 做了什么

- **容量校验与安装分离**：`capacity` 阶段只读取镜像记录、校验范围/一致性和内存预算，保存已批准容量与安装前堆余量。`core` 激活安装对象表并检查销毁分派，`sched` 激活扩容任务表和内核栈，`realtime` 激活安装实时准入容量；全部安装后统一恢复堆余量并报告实际表大小。
- **PCI 硬件准备与设备服务分离**：`devices` 阶段只取得平台配置空间访问者，满足 ECAM 映射等硬件顺序约束；`devices` 模块激活才枚举总线、建立只读设备表。Profile 新增 `device.pci` 能力与 `system.device` 服务，`HEADLESS` 和 `HEADLESS_MIN` 都声明该模块。
- **作业队列进入激活**：`job` 模块激活建立本次启动唯一的空队列，并拒绝重复激活；提交仍由发布后的 `sched.batch` 能力门控。
- **旧模块管理器退役**：删除 `kernel_core::module` 的 `ModuleDescriptor` / `ModuleManager` 第二套状态机，及其宿主测试、Verus 引用、Proptest 和 fuzz 目标。机制演练改为直接用 `kernel_core::assembly` 验证依赖顺序、发布审计、重复启动拒绝和失败依赖者不被激活。
- **计划同步**：`assembly` 阶段直接依赖 `devices`；全量计划的 `pci-table` 与 `capacity-report` 移到装配之后并声明依赖 `assembly`。阶段数仍为 16，生产/全量计划仍分别覆盖 `stages=0xffff`，未改变 issue #7 的 `first-program`、收尾和阶段顺序。

### 边界

- 本片没有实现运行时停用、能力撤回宽限期或健康降级；第三片的范围不变。
- 阶段失败仍停在当前启动路径，不新增内核内故障注入或阶段资源回滚。
- `capacity` 阶段仍负责容量记录不可信输入的拒绝，因此损坏记录的失败标记与退出行为保持不变。

### 验证

- 定向编译：x86_64 release 内核通过；AArch64 `production`、`--no-default-features` 内核通过。
- 宿主测试：`kernel-core` 533 passed / 0 failed。
- 装配套件 `run-assembly-suite.sh`：Verus 13 verified / 0 errors，负例 precondition not satisfied；kernel-core assembly 5 passed；Proptest 2 passed（512 例随机 DAG / 策略）；Miri 1 passed；装配 fuzz 100 万次 0 崩溃（cov 417、ft 1072）；Loom 1 passed。Kani 按发版规则未在本片提交上运行。
- 启动计划套件 `run-boot-stage-suite.sh`：Verus 43 verified / 0 errors + 负例；kernel-core 7 passed；Proptest 5 passed；Miri 1 passed；fuzz 100 万次 0 崩溃（cov 192）；Loom N/A（BSP 局部状态），Kani 发版时验证。
- 定点验收 `accept-20261106-183417`（共享 QEMU 锁）：M1.1、BOOT-STAGE、ASM1、POL2、M1.5、PRODUCTION 全 PASS；单核退出码 37，仅 `drv2c2` 与 `bench` 计时类超界。16 阶段按序到 `done_mask=0xffff`，full 计划 `stages=0xffff cases=53`。
- ASM1 原始证据：对象表 1024、任务表/内核栈 64、实时表 8、作业队列为空、PCI device 表 `port` 机制 8 个功能，均先于 `[JSR-CAP] boot`；9 个模块全部 ready，10 项能力发布并通过审计。M1.5 的装配机制演练 `checks=30 failed=0`，其中 2 个依赖模块成功、失败模块的依赖者未被调用激活。
- 生产模式在 1 核和 4 核均完成 16 阶段与 `plan=production stages=0xffff cases=1`，首个用户程序退出且进入 `alive` 等待；损坏容量记录仍以 `bad_version` 拒绝停机。

产物证据位于 `evidence/issue6/assembly-suite/`、`evidence/issue7/boot-stage-suite/` 与 `evidence/accept-20261106-183417/`。本片只做单核标准验收、生产 1/4 核和 AArch64 编译；未把结果写成批次全量通过，也未重跑 q35 / 8 核全量。

## 剩余切片
1. **第三片**：运行时停用 / 健康降级——发布掩码可撤回（先撤位再停用，读者以引用计数或宽限期保证不在撤回后进入服务），`system.profile.get` 增加逐模块状态；用户态授权与服务可用分开报告（区分编译期特性、启动期配置、运行时健康、用户授权四层）。
