# Issue #42：macOS/NT 机制原生化吸收跟踪

更新时间：2026-11-21。

状态：**最终裁决完成；不批准兼容 ABI，不新增第二对象或权限权威。**

本文保留 macOS/NT 经验来源和架构边界。Issue #42 的 25 个正式机制族已由
`docs/ISSUE-42-FINAL-DISPOSITION.md` 收口：15 个 `implemented-tested`、
10 个 `compat-retained`、0 个 `partial`、0 个 `research`。下列早期“部分具备”
描述属于候选调研历史；最终分类以机器台账为准。

机器可查的 25 机制族台账为 `verification/issue42-mechanism-ledger.tsv`，
由 `scripts/check-issue42-mechanism-ledger.py` 强制校验完整 ID、状态、分层、
证据路径和未关闭门。该台账把研究分类与工程验收分开；`partial` 或 `research`
不会因为存在同名测试而升级为 done。

## 裁决

Issue #42 的所有外部内核经验只作为问题域来源：

- Jasper 内核不实现 Mach、Windows NT、Linux、Darwin 或 Android ABI；
- 机制必须先证明脱离兼容层后的原生价值；
- 优先复用 Handle/Rights、Channel、AsyncRing、MemoryObject、Workload、
  SEC/PEP、IFC、Diagnostics、Device Broker/Driver Host、LC 安装/更新；
- 只有不可下放的原子性、调度、页表、授权和硬件隔离才进入内核；
- 服务、行业策略、追踪消费、内存回收策略和 PnP 管理优先留在用户态；
- 兼容层关闭后仍必须存在独立原生场景与证据。

## macOS 候选矩阵

| 候选 | 现有 Jasper 归属 | 当前状态 | 仍需关闭的门 |
| --- | --- | --- | --- |
| M-01 能力化 IPC/死亡通知 | Handle/Rights、Channel、Event、对象 generation；IPC 多 Handle 原子交付、对象 transfer 回滚和订阅关闭已实现 | 部分具备 | 跨域队列所有者退出、请求方取消、服务重启 generation 与完整回收矩阵 |
| M-02 服务生命周期 | Assembly、Workload、Workload Recovery、ServiceGate | 部分具备 | 版本化 Registered/Admitted/Starting/Ready/Draining/Stopped/Failed 契约和热替换 |
| M-03 QoS/Deadline 传播 | scheduler、Deadline、Priority Inheritance、AsyncRing controls | 部分具备 | 跨 IPC 有效 QoS 求交集、级联取消、过载和多核尾延迟 |
| M-04 用户态 Pager | MemoryObject、MemoryCapability、`fault_pager` 原生状态机 | 部分具备 | 真实页表/调度接线、CPL3 多处理器压力、重载和内存压力协作 |
| M-05 操作前 PEP 与操作后事件 | authz、PEP/MAC、security event、bounded audit | 部分具备 | 授权与安全观察分离、观察者 scope、持续容量与故障策略 |
| M-06 用户态驱动与静止 | Driver Host、DMA/IRQ/IOMMU、Driver Lifecycle | 部分具备 | 真实 MMIO/virtqueue、设备 reset/crash/hotplug 和物理隔离 |
| M-07 可信系统映像 | NativeInstall、PersistentInstall、LC-2/3/5 | 部分具备 | 真实生产密钥/TPM、公开启动链、物理安装/回滚 |
| M-08 快照/Clone/崩溃一致性 | FS production、journal、ext4 write | 部分具备 | 后端中立 Snapshot/Clone/Transaction 契约和故障一致性 |
| M-09 内存压力协作回收 | Pressure、Workload Recovery、OOM plan | 部分具备 | 可丢弃 MemoryObject、回写/压力协同、策略替换和真实回收 |
| M-10 事件订阅恢复 | EventSource、Subscription、WaitSet、resync；四领域 producer 已接入 kernel EventSource Handle | 已具备 | M01 专项覆盖失败原子性、overflow Resync、订阅关闭与资源回收 |

## Windows NT 候选矩阵

| 候选 | 不照搬的 NT 机制 | Jasper 原生落点 | 当前状态 |
| --- | --- | --- | --- |
| NT-01 | IRP/I/O Manager | AsyncRing/Channel 请求身份、唯一终态、取消、deadline、backend quiescence | 部分具备；FS/NET/device/graphics backend 尚未全部证明 |
| NT-02 | WDM/PnP/Power Manager | 既有 Device Service/Broker、Driver Host、Driver Lifecycle | 部分具备；真实热插拔/reset/IOMMU 矩阵未完成 |
| NT-03 | Driver Verifier | 独立验证 Profile、故障注入、模型/压力/运行时证据 | 候选；不可默认进入生产热路径 |
| NT-04 | ETW | 现有 trace/security audit + Diagnostics Service，统一 correlation ID | 候选；需核查因果重建、丢事件计数和受保护故障快照 |
| NT-05 | Working Set Manager | MemoryObject/FS cache/DMA pin 统一账务、Pressure 和可替换回收 | 部分具备；工作集语义未冻结 |
| NT-06 | Job Objects | Workload/Sandbox 层级预算、聚合计费、孤儿和撤销 | 部分具备；不得创建第二 Job 身份 |
| NT-07 | Dispatcher Objects | Event/Timer/Completion/Channel 的 WaitSet/Subscription 原子等待 | 部分具备；需跨对象竞争与多核完整矩阵 |
| NT-08 | NT 调度优先级经验 | 现有 QoS/RT/PI 机制与可替换策略 | 研究；必须先提供 p50/p99/p99.9、公平性和饥饿数据 |

## 跨机制硬边界

1. `IRP` 不是 Jasper 对象；统一的是请求/完成/取消/静止语义，不创建 I/O Manager。
2. `PnP` 不是新设备身份根；设备身份、代际、Handle/Rights 和 Driver Host 保持唯一。
3. ETW 风格追踪不替代 SEC 安全审计；可丢弃性能事件与不可静默丢失的安全事件分开。
4. Working Set 和 Job 经验复用 Workload/Memory 账务，不新增第二资源生命周期。
5. 验证 Profile 可以高开销，生产路径保持正常策略；故障注入必须可关闭且不改变 ABI。
6. 任何延迟任务都必须有兼容层关闭后的原生场景；否则保持候选，不升级为内核 ABI。

## 当前已落地的 Issue #42 原生切片

- IPC 多 Handle 交付具备 all-or-none 与槽位释放后的原子重试；
- 对象跨表 transfer 在目标安装或源移除失败时回滚；
- 25 机制族中的 M03 已通过真实进程、Channel 和 Ring 的服务退出/重启矩阵：
  退出会 drain 队列消息与携带 Handle、归还在途字节额度，在飞 recv 只得到
  一个 `peer_closed`，旧 Handle generation 不能解析到新端点；
- 关闭的订阅 Handle 返回结构化 `event.closed`，等待登记不再 panic；
- EventSource 广播有 generation、边界、终态和资源回收证据；
- `kernel-core::address_sync` 以 MemoryObject backing/generation 为条件身份，
  复用 Registration/WaitSet，完成受 capability 约束的 check/register/park
  状态机；它尚不是新 ABI，也未接线到原生 CPL3/MemoryObject 临界区；
- `kernel-core::fault_pager` 以既有 MemoryCapability 授权 Pager handler，
  完成 FaultEvent、handler generation、递归缺页、deadline、撤销和两阶段页表裁决；
  它不是 userfaultfd ABI，尚未修改真实页表或调度任务；
- root-exec 在真实 OVMF/CPL3 中恢复通过，包括 40 个并发 eventfd 和
  timerfd/signalfd/pipe 批量压力。

证据见 `docs/ISSUE-42-IPC-DELIVERY-ATOMICITY-status.md`、
`docs/ISSUE-42-OBJECT-TRANSFER-status.md`、
`docs/ISSUE-42-SERVICE-LOOP-status.md`、
`docs/ISSUE-42-SUBSCRIPTION-RESYNC-status.md` 和
`docs/ISSUE-42-COMPAT-ROOT-EXEC-status.md`；地址同步和 Pager 切片见
`docs/ISSUE-42-NATIVE-ADDRESS-SYNC-status.md` 与
`docs/ISSUE-42-NATIVE-PAGER-status.md`。

## 转入专项而非 Issue #42 未决

- 原生地址条件同步已由 M02 关闭，futex/rseq 协议仍永久属于兼容适配；
- userfaultfd/Mach pager 已裁决为兼容保留，`fault_pager` 仅为 proof-only；
- FS/NET/device/graphics 四类 AsyncRing backend 的软件静止矩阵已由 M09 关闭，
  物理 DMA/IRQ/IOMMU 属于 #43；
- 385 项 syscall disposition 只证明分发表完整性；当前枚举包含 2 个显式
  Jasper 扩展 `RseqSliceYield`（471）与 `Uprobe`（336），不得混入 Linux 兼容语义；
- 关闭兼容层后的 native Profile 依赖隔离由 M17/M20/M21 的最终边界约束；
- NT-03/04/05 的剩余生产强化由 Diagnostics、Memory/Storage 与验证专项承接。

## Syscall disposition 基础门

`docs/linux-syscall-disposition.tsv` 对 385 个枚举项逐项记录 scope、当前
disposition 和 `linux_abi.rs` dispatch 证据；`check-linux-syscall-disposition.py`
拒绝枚举遗漏、未知 variant 和矩阵漂移。当前结果为 383 个 Linux 项、2 个 Jasper
扩展、19 项显式 unsupported ABI。该矩阵只证明“每项都有可追踪分支”，不证明
Linux 语义、原生后端静止或生产验收已经完成。
