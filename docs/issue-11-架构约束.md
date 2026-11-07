# issue #11：模块化宏内核的可装配架构约束

- 基线：公有 `main` 提交 `dc3f7ba`（2026-11-07）
- 状态：实现、约束矩阵与 K-06 真实双 Profile 审计均已落地
- 结论：当前正式实现仍是**模块化宏内核**。本文件不宣称已支持微内核、混合内核、
  外核或分离内核，也不把当前宏内核实现细节冻结为所有未来配置的永久语义。

## 1. 总原则

1. 模块能力契约、实现选择、执行域、生命周期和目标平台是不同维度；任一维度都不能
   被另一个维度的当前取值隐含决定。
2. 已登记系统操作必须有唯一服务所有者。操作未归任何模块，或所有者未在当前 Profile
   装配时，调用必须明确失败；不存在“没匹配到服务所以直接执行”的路径。
3. 编译期静态绑定可以长期保留。未来跨域模块若需要用户态服务、共享内存或其他通信，
   必须新增真实实现和验证，不能用一个空适配器把当前直接函数调用伪装成跨域调用。
4. 普通 Jasper 应用尽量不因内核内部形态变化而改写，是兼容目标，不是“所有配置的
   延迟、故障和安全保证完全相同”的承诺。
5. 任意模块组合不天然合法。缺失依赖、前缀歧义、缺绑定、装配失败、健康失效、
   权限不足和缺少验证证据都必须有结构化拒绝。

## 2. K-01～K-08 复核

| 编号 | 本切片结论 | 通用契约 | 当前实现假设 / 候选变化 | 源码与验证 |
|---|---|---|---|---|
| K-01 | 仍存在声明维度不足；本切片没有伪造执行域实现 | 模块必须声明能力、依赖、服务面、生命周期类别与资源下限 | 当前所有模块都是内核共享地址域；未来需显式增加执行域/隔离级/特权域，不能从“同一 Profile”推断同址 | `kernel-core/src/profile.rs::ModuleDecl`、`docs/issue-11-架构约束.md` |
| K-02 | 保留静态激活绑定 | 区分能力身份、实现选择、执行域与生命周期；失败不得发布半初始化能力 | 当前 9 个生产模块由 Rust `fn()` 激活；动态链接、热卸载和跨域服务停止协议均未实现 | `kernel/src/assembly.rs::BINDINGS`、`kernel-core/src/assembly.rs::Binding`；ASSEMBLY-01/02/03 |
| K-03 | 固定 16 阶段只属于当前启动图 | 所有配置共同的不变量、启动依赖、失败阻断和可审计回滚必须保留 | 未来配置可有不同阶段图，但必须重新证明依赖、锁序、回滚和失败位置；当前仍是 16 阶段 | `kernel-core/src/boot_stage.rs`、`kernel/src/kmain.rs`；BOOT-STAGE-01/02 |
| K-04 | 中央 `KObject` 载荷仍是当前实现细节 | Handle/Rights、对象身份与世代、所有权、关闭、closing/destroy、资源回收是外部不变量 | 当前 Process/Ring/Endpoint 等载荷同驻内核地址空间；跨域代理、服务死亡和旧引用失效协议未实现 | `kernel/src/kobj.rs`、`kernel/src/proc/mod.rs`；KRN1-EXIT-01、ASSEMBLY-* |
| K-05 | 直接 handler 调用仍是当前实现 | ABI、授权、能力可用性、错误分类、取消和终态语义必须保持 | 未来 handler 可经跨域 IPC；传输、拷贝/共享、在途取消、死亡恢复和性能契约必须另证 | `kernel/src/syscall/mod.rs`；S-2、J-6、RING-* |
| K-06 | **本切片已消除未认领操作的 `Ungated` 直通** | 每个登记操作在完整服务面中恰有一个模块所有者；当前 Profile 未装配该所有者时不可用，授权拒绝与不可用分开 | 当前 Profile 未声明异步/通道/作业模块时，对应操作明确不可用；sync、ABI、execution 归 core，event、io 归 async | `kernel-core/src/assembly.rs::operation_route`、`kernel/src/assembly.rs::enter_service`、`kernel/src/syscall/mod.rs::self_check`；K06 双 Profile 审计 |
| K-07 | 全局 `KERNEL_SCHED` 是当前宏内核选择 | 调度正确性、时间/预算、可观测性和跨核唤醒保证是外部契约 | 未来其他形态可替换共享状态组织，但不能因研究性重构提前改变当前快路径；单锁并非永久要求 | `kernel/src/sched/mod.rs`；SMP-2/3、HARDEN1D/1E、SCHED1–3 |
| K-08 | ISA、内核形态、Profile 和实现选择保持分离 | Profile 与 ABI 必须明确能力、平台和运行保证；不支持的组合拒绝 | `arch::Platform` 是 ISA 适配，不是内核形态开关；`profile-compact` 是参数档，模块面另由 Profile 选择 | `kernel/src/arch/mod.rs`、`kernel/src/profile.rs`；POL2、ISA/T-1 |

### 2.1 暂时不能迁出的机制

- 当前对象表、任务表、实时准入表、作业队列和 PCI 表都由内核模块在启动期安装并常驻。
- 用户程序装载、进程/线程对象、Ring/IPC 队列和调度器状态仍在内核地址空间直接管理。
- 启动阶段、锁序检查、不可信用户指针复制、跨核 TLB 击落和设备 DMA 隔离均属于当前
  可信计算基；迁移任一机制前必须重新给出跨域协议和故障模型，不能只移动代码位置。

## 3. 可装配约束矩阵

| 维度 | 合法条件 | 非法 / 不可满足条件 | 当前拒绝证据 |
|---|---|---|---|
| 模块依赖闭包 | 每项 `requires` 恰由一个 `provides` 满足，图无环 | 缺能力、能力自依赖、依赖成环 | `MissingCapability`、`DependencyCycle` |
| 服务面 | 服务前缀唯一且没有点边界包含关系 | 同前缀双所有者、`system.async` 与 `system.async.ring` 重叠 | `ServiceConflict`、`AmbiguousService` |
| 系统操作所有权 | 完整服务面中每个登记 op 恰有一个模块所有者 | 新增 op 未归任何服务；完整 Profile 仍有 unclaimed | `operation_route`、启动 `self_check`、`[JSR-K06-FAIL]` |
| 当前 Profile 可用性 | op 所有者已装配且能力已发布 | Profile 未声明模块、初始化失败、撤回或 health=unhealthy | `enter_service` 返回 `None` → `system.error.unsupported` |
| 调用者权限 | 当前任务的 SyscallSet 包含操作 ID | 未授权、子进程扩权、ID 越界 | `system.error.rights_denied`，J-6/SYS-* |
| 生命周期 | 激活成功才发布能力；停用先撤位并排空租约 | 半初始化发布、依赖者仍使用时停用、常驻模块伪装停止 | ASSEMBLY-01/03、ASM1 |
| 健康 | healthy 完整可用，degraded 在声明范围内可用 | 无健康证据却声明更强保证；unhealthy 仍发布服务 | ASSEMBLY-02/03、ASM1 |
| 启动图 | 所有阶段按依赖顺序完成，失败阻断并回滚 | 缺依赖、重复初始化、故障后继续下一阶段 | BOOT-STAGE、故障 guest |
| 时间保证 | 声明值对应真实机制、平台和同口径证据 | 无硬件/验证前提却承诺强实时或固定 p99.9 | QEMU 只判机制；性能结论须 KVM/裸机 |
| 平台前提 | ISA、设备、固件和验证范围明确 | 把 x86_64 TCG 结果外推到其他 ISA 或物理硬件 | ISA N/A、BM-1/BM-PERF 规划 |

### 3.1 合法与非法配置判例

合法：

- `headless`：9 个当前宏内核模块，完整服务面；所有登记操作有唯一所有者。
- `headless-min`：5 个模块；异步/通道/作业服务未装配，对应操作明确不可用，
  core 同步/ABI 与时间服务仍可用。

非法或暂不支持：

- 模块要求未提供的 `memory.virtual`：Profile 解析拒绝。
- 两个模块声明同一服务前缀：拒绝。
- 声明 `system.async` 和 `system.async.ring`：拒绝为前缀歧义。
- 声明用户态隔离模块却要求直接解引用内核 `Process`/`RingObj`：当前配置模型没有可
  证明的执行域与代理协议，拒绝发布；不能以“先注册能力”冒充支持。
- 要求强时间分区但目标平台没有预算/隔离机制和验证证据：拒绝发布。
- 服务停用后继续宣称可用，或在途调用未排空就运行停用动作：拒绝。
- 新增登记 op 未归任何服务：内核启动自检失败，不运行到“Ungated”状态。

机器可读版本见 `verification/architecture_constraints.toml`。

## 4. K-06 操作归属审计

完整服务面当前把操作分为：

- 内核基础：core 管辖的 task/process/handle/error/console/profile/sync/ABI/execution；
- 模块服务：memory、time、channel、job、async/event/io、device 等；
- 未装配：该操作在完整面有所有者，却不在活动 Profile 的模块表中。

入口顺序固定为：登记表/实现一致性 → 调用者 SyscallSet → 唯一所有者与发布租约 →
真实 handler。因此“服务未装配”得到 `unsupported`，“调用者未授权”得到
`rights_denied`，健康撤回则使租约取得失败并同样得到 `unsupported`；三种原因不混淆。

所有权分类不等于功能已实现。登记表中仍保留少量显式返回 `unsupported` 的预留操作
（例如部分 memory buffer、restricted execution 与 event batch wait），它们仍有确定的
服务归属和统一门禁，但没有被本节宣称为可用能力。

真实验证使用 `scripts/k06-service-audit.sh`：

- `headless` 要求 `active_unavailable=0`、异步环和时间/同步可用；
- `headless-min` 要求 `active_unavailable>0`、异步环不可用，但时间与同步仍可用；
- 两份串口都必须有 `unclaimed=0 gate_mismatch=0` 且无 panic。

本切片实际结果（`evidence/k06-service-audit/20261107-142327`，QEMU x86_64 4 处理器）：

```text
[JSR-K06] profile=headless ops=57 kernel_base=26 module_service=31 active_unavailable=0 unclaimed=0 gate_mismatch=0 ring=available time=available sync=available
[JSR-K06] profile=headless-min ops=57 kernel_base=26 module_service=31 active_unavailable=11 unclaimed=0 gate_mismatch=0 ring=unavailable time=available sync=available
```

宿主验证：

- `cargo test -p kernel-core`：548 个 lib 测试与全部集成/文档测试通过；
- `cargo test -p kernel-core --target i686-unknown-linux-musl --lib`：548 passed / 0 failed；
- `cargo test -p kernel-core profile:: --lib`：18 passed / 0 failed；
- `cargo test -p kernel-core assembly::tests --lib`：8 passed / 0 failed；
- x86_64 标准内核与 `rt1-no-realtime` 精简内核均构建通过；
- J-6 未授权负例真实 QEMU PASS（`accept-20261107-142917`）：越权调用仍为
  `rights_denied`，与未装配/健康撤回产生的 `unsupported` 保持区分。

正式定点验收 `accept-20261107-142434`：`K06 PASS`，QEMU 退出码 37 仅为既有计时参考，
串口确认完整服务面 `ops=57 kernel_base=26 module_service=31`。

## 5. 未来跨域部署的必要契约

以下均**尚未实现**，不得由当前模块化宏内核证据外推：

1. 对象：稳定 Handle/世代、代理身份、能力撤销、旧引用失效和资源最终回收。
2. IPC：有界消息、共享内存所有权、拷贝语义、背压、顺序与关闭传播。
3. 取消：请求 ID/世代、在途取消线性化点、完成与取消竞态的唯一终态。
4. 服务死亡：检测、调用失败分类、在途请求、依赖者降级、重启与状态恢复边界。
5. 权限：调用者、服务实现者和代理三者权限交集；不得因跨域自动扩权。
6. 启动回滚：部分服务启动、跨域资源残留、依赖者阻断和重新装配条件。
7. 性能：同口径吞吐、p50/p99/p99.9、最坏延迟、内存和上下文切换成本；不得用 TCG
   数值宣称物理实时保证。
8. 验证：真实配置启动、权限负例、故障注入、并发/死亡/取消模型、独立 CI 和平台前提。

## 6. 完成边界

本切片完成的是：

- Wave 4 最新源码上的 K-01～K-08 复核；
- 可装配约束矩阵和合法/非法判例；
- 登记操作唯一所有者、服务前缀歧义拒绝、K-06 双 Profile 真实审计；
- 未来跨域部署的契约清单和验证门槛。

本切片没有完成：

- 新的微内核/混合/外核实现；
- 任意内核形态自动组合；
- 跨地址空间对象代理、服务重启或热卸载；
- 物理性能、强实时和信息流隔离证明。

因此本 Issue 的“架构约束落地”可以完成，但 **Issue #10 的长期多形态研究仍是未完成方向**。
