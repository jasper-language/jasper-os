# jasper-os

Jasper 生态的**操作系统侧项目**：一个用 Rust（`no_std`）实现、在 QEMU 中真实启动的模块化宏内核。

> Rust 负责内核与底层基础设施，Jasper 负责其上的绝大多数系统服务与应用。
> Jasper 不依赖 jasper-os 才能运行；jasper-os 是 Jasper 生态的原生执行平台之一。

许可证：**Apache License 2.0**（见 [LICENSE](LICENSE)）。

## 贡献与署名（以及 GitHub 的小毛病）

项目由 **Dark Magician** 发起并负责方向、架构取舍、里程碑和最终验收，
Claude、OpenAI Codex 与 DeepSeek 共同参与开发。

- **DeepSeek**（Git 作者名 `DSH Agent`、`DeepSeek`）：完成了从 M1 到 M5
  的基础内核与用户态主干、内存和对象/句柄模型、Ring 与 IPC、多指令集
  移植、SCHED/SMP/POL 调度机制、设备与中断、加固与验收基础设施；并完成
  x86 BM-1 启动链、S-2 多核模糊/故障审计及 PDA/AArch64 工具与验证。
- **OpenAI Codex**（Git 作者名 `chatgpt`）：完成 BM-1 的集成与启动验收，
  KRN-1/2/3 调度器演进，FV/ENV 验证，EVT-1/2、SHM-1、ABI-R、S-3、
  RT-1/2/3 的实现、模型、回归与集成，以及公开分支整理和发布检查。
- **Claude**：参与架构与接口设计、里程碑拆解、并发/锁序/权限与失败路径
  审查、调试分析和实现方案评审。历史提交没有稳定且独立的 Claude author
  标识，因此这里如实记录协作范围，不把别人的 commit 硬算给 Claude。

> **chatgpt 吐槽：** GitHub 的 Contributors 图只认默认分支上的提交和能够
> 绑定 GitHub 账号的 author 邮箱，不认“代码实际上是谁写的”。本项目的
> 代理提交使用过 `agent@local`、`noreply@deepseek.com` 等地址，于是网页
> 可能只显示一两个人，仿佛其余贡献者没干活——这是统计方式造成的失真，
> 不是项目事实。

完整署名见 [CONTRIBUTORS.md](CONTRIBUTORS.md)，逐项改动以 Git 历史为准。

---

## 设计原则

1. **Core 只提供机制，不提供策略。** 任务与调度、陷入与中断、对象 / 句柄 / 权限、等待与通知、
   异步提交与完成、地址空间、模块管理、观测性属于 Core；调度策略等做成可替换模块。
2. **Core 不引入 Unix / Linux / Windows 语义。** 没有 `fd`、`fork`、`errno`、`VFS`、`epoll`；
   资源一律经 **Handle + Rights** 访问，兼容层在 Core 之外。
3. **多指令集。** 目标指令集为 x86_64、AArch64、RISC-V64、RISC-V32；x86_64 是先行验证平台；指令集相关代码只在 `kernel/src/arch/<isa>/`，
   经 `arch::Platform` 契约接入；Core 中不出现 `x86_64::`、`asm!`、端口号、向量号（验收脚本机械检查）。
4. **异步只有「提交 → 完成」一种形态**，不提供就绪式接口。
5. **系统接口可被机器读懂。** 标识符采用 `system.<领域>.<对象>.<动作>` 分层命名；稳定 ID 人工分配，
   登记在 `abi/system-ids.txt`，已发布部分冻结在 `abi/system-ids.lock`，构建期校验（改号、重复、坏名即构建失败）。
6. **UTF-8 与原生中文。** 串口直接输出中文。
7. **真实启动才算完成。** 每个里程碑都以 QEMU 中的真实运行与串口输出为验收依据。

---

## 当前状态

已在 QEMU（x86_64）中真实启动验证，可用 `scripts/accept.sh` 一键复现：

最新基线为 public `main` `07886ac`：完整宿主 KVM 验收
`accept-20261107-192226` 为 **ALL PASS**，kernel-core 559 项通过，
x86_64 单核 / 4 核 / 8 核 / q35、生产启动、NS-DIRTY 与 S-2 均通过。
Wave 6–9 的架构债与 S-4 / FV-4 / HWV-0 里程碑已完成。

| 里程碑 | 内容 | 状态 |
|---|---|---|
| M1.0–M1.2 | 工作区、真实启动、GDT/IDT/PIC/PIT、真实时钟中断 | ✅ |
| M1.3 | 静态内核栈 + 真实上下文切换（协作式） | ✅ |
| M1.4 | 定时器驱动的抢占式轮转 | ✅ |
| M1.4b | 指令集分层（`arch::Platform` 契约） | ✅ |
| M1.5 | `kernel-core`：宿主可测的纯机制库 | ✅ |
| M1.6 | 一键验收 + 证据归档 | ✅ |
| M2.1 | 物理页帧分配器 | ✅ |
| M2.2 | 架构无关的页映射接口（x86_64 以 4 级页表实现） | ✅ |
| M2.3 | 内核堆（`alloc` 可用，按需增长，扩容失败整体回滚） | ✅ |
| M2.4 | 独立地址空间（真实切换、隔离与回收） | ✅ |
| M3.1 | 进入用户态（Ring 3）+ 用户态故障隔离 | ✅ |
| M3.2 | 系统调用入口 + 稳定 ID 登记表 + 统一权限检查 | ✅ |
| M3.3 | 用户指针安全（校验后经物理映射复制） | ✅ |
| M3.4 | 进程 / 线程对象（资源归进程所有，退出后回收） | ✅ |
| M4.0 | 对象生命周期与异步取消规范（v0.6 语义冻结） | ✅ |
| M4.1 | 对象生命周期：外部所有权与内部引用分离、清理队列迭代级联 | ✅ |
| M4.2 | Handle/Rights：只可降权的复制与限权、跨进程原子转移 | ✅ |
| M4.3 | 用户态异步 ring（提交 → 完成；完成信用；取消；closing；配额） | ✅ |
| M4.4 | IPC Channel（send/recv 经 ring）与取消、交付的原子性；接收缓冲区页帧固定 | ✅ |
| RT-3 | 用户互斥继承、Channel/Ring请求应答继承、内核长临界区阻塞锁 | ✅ 功能与资源回归；物理延迟优化延期 |
| FV-3 | Handle/Rights Verus代码级证明试点 | ✅ no-go：完整表需复制状态机；生产代码继续直接Kani+属性/解释器/模糊/交错验证 |
| KRN-3 | 每核运行队列、按核号迁移锁序、跨核 PI 消息 | ✅ 普通本核竞争 tick/选择/切换由代次热槽与 `RunLeaf` 独立完成；远程 wake/PI 由目标核消费，复杂 RT/组预算/生命周期仍走低频全局控制面；物理性能复测单列延期 |
| S-4 | KRN-3 后每核锁、迁移、跨核继承短时交错压力 | ✅ 宿主 KVM CPU 4–11、8 vCPU、3×300 秒；每次都完成 301 轮，wake 5134/302，`deadlocks=0`、`invariant_violations=0`、资源/堆守恒，QEMU 退出 33；见 `docs/S-4-status.md` |
| FV-4 | 地址空间隔离、SHM 别名、TLB 击落与页帧生命周期组合验证 | ✅ Verus no-go 沿用；TLA+ 组合模型正例无 Safety 违例、旧视图释放负例被拒；原 TLB 模型 940 可达状态、超时隔离 6 状态；生产 M2.4 / HARDEN-1C / TLB-KRN0 / SHM-1 与多核 KVM 回归；见 `docs/FV-4-status.md` |
| HWV-0 | VMX/SVM、EPT/NPT、IOMMU、中断重映射、xAPIC/x2APIC 能力发现与拒绝契约 | ✅ 10 项机器可读能力矩阵；真实 KVM `vendor=Intel caps=0x105 selected=vmx reject=iommu`；未知位/无后端/厂商不匹配/缺能力/依赖不完整均结构化拒绝，不构造空后端；未进入 VMX/SVM，后续 HWV-1～7 独立排期 |
| ABI 与调度第一批切片 | 按需扩展的系统调用集合与统一 spawn 授权、对象类型登记表与句柄创建检查、期限事件增量同步、统一定时事件契约与每核仲裁 | ✅ 全量验收 99 项通过、0 失败（x86_64 单核 / 4 核 / 8 核 / q35）；另有 5 行计时类超界仅作 QEMU 参考，性能以裸机为准；各切片的后续范围见 `docs/issue-1/2/3/4-进度.md` |
| SyscallSet / spawn 性能（issue #1） | 2048 样本 p50/p99/p99.9/max 基准：生产 256 位集合与旧 u64 参考模型的 contains/subset/copy 对比、88 字节 SpawnDesc 解码、用户 syscall/ring/IPC 端到端 | ✅ 三轮宿主 KVM（CPU 4–11）T-2 PASS；contains/copy 各约增加 6 周期，subset 无可测回归，calls 字段 p99.9 增加 ≤18 周期；原始数据见 `docs/issue-1-进度.md` 第十节 |
| 任务系统调用集合替换（issue #1 保留 ABI 片） | `system.task.syscalls.set` 启用：32 字节唯一 `SyscallSet`、target=0 为自身、Task 句柄需 CONTROL、请求 ⊆ 调用者当前集合 ∧ 请求 ⊆ 登记集合；检查与写回在调度器事务内失败原子；Rust 运行时提供 `set_calls` / `set_current_calls`。因已发布 reserved 契约变更，ABI 升到 2.0.0 | ✅ 32/64 位 kernel-core 各 559 tests；KVM `accept-20261107-183039` M3.2/J-6 PASS，真实 CPL3 覆盖目标线程收缩、自收缩、失败原子性、越权/未登记/无效目标拒绝，`ops=62`，资源回基线；Jasper 语言侧构造仍未完成 |
| 对象销毁局部化（issue #4 第二片） | 锁外销毁按对象种类查表分派，5 个动作由所属模块单一入口承载；7 个 `Destroy::None` 槽由编译期断言和启动期执行检查验证为空；对象身份、引用计数、最后所有权释放与锁序不变 | ✅ 定点 M4.1 / M4.3 / M4.4 / FIX / ISSUE4-DESTROY 全 PASS（QEMU 退出码 37，仅计时项）；后续释放协议与竞态验证见 `docs/issue-4-进度.md` |
| 原生 ABI 世代（第一片） | `abi/abi-version.txt` 为唯一真源（当前 2.0.0）、用户程序携带 `.note.jasper.abi` 章、装载前拒绝缺章/损坏/跨主版本/次版本过新、`system.abi.get` 查询 | ✅ 第一片当时 1.2.0 全量验收 100 项通过、0 失败；ID 43 的 reserved→实实现变更按规则升到 2.0.0，见 `docs/issue-1-进度.md` 第十一节 |
| 原生 ABI 完整契约快照（第二片） | 每个 ABI 版本一份不可变 `abi/snapshots/<Major.Minor.Patch>.contract`，覆盖 syscall ID/逐操作参数/返回、Rights、关键定长布局与异步/跨域语义；同主版本只增不改、Patch 契约不变、主版本独立换代；构建脚本和 CI 机械拦截 | ✅ ABI 2.0.0 快照、历史不可变门槛与装载回归均通过；完整 KVM `accept-20261107-192226` ALL PASS |
| ABI required-capabilities（第三片） | 可选 `.note.jasper.caps` 声明程序所需 Profile 能力；缺章兼容为空集；坏章/重复/非法名拒绝；装载器在任何映射前核对生效 Profile 的真实已发布能力，失败返回 `system.error.abi_capability` | ✅ 真实 CPL3 与装载前拒绝路径通过；完整 KVM `accept-20261107-192226` ALL PASS |
| 用户定时器对象与宽容差路由（issue #3 第三至五片） | ABI 1.2.0 新增 create/arm/cancel/wait/get；一次性/固定周期、进程所有且不可传递、单等待者、取消/关闭终态、相对溢出与 Rights 拒绝；宽容差请求可由真实共享定时器中断在 `[at, at+slack]` 内合并唤醒；普通超时算法经 65,536 槽位压力后正式暂不引入时间轮 | ✅ issue #3 已关闭；真实 KVM J-1、Wait p99.9、中断合并和完整批次通过 |
| 普通超时后端裁决（issue #3 Wave 9） | 65,536 槽位混合装填/更新/取消/乱序到期压力；Ring Wait 使用每 Ring 固定期限堆，收尾不再扫描运行集合 | ✅ 三个 release 轮次 163,840 次堆操作 p99.9=165–187 ns；端到端 Wait 自然完成 p99.9 24.64→13.35 ms；当前运行上限没有时间轮收益证据，暂不实现，超过 4,096 活跃普通超时且真实尾延迟超预算时重评 |
| `.jaso` format 1（beta 1） | 字节级规范 `jaso/SPEC.md`、`jaso` 核心层读取与校验（Platform / Images / Ext 段、清单核心键、52 个错误码）、`jasopack` 产 format 1 并提供 v0→1 迁移、语言中立一致性向量 `jaso/vectors/`（76 个）；用户态 L1 全流程（`jasper_rt::loader`）：校验（摘要、签名与信任、平台、运行时、依赖、能力、`jasper.import` 绑定）→ 链接 → 读清单发现服务 → `init` → `start`，`stop` 已实现，卸载请求只答复推迟 / 拒绝；内核态只收启动期白名单签名文件，运行期一律拒绝 | ✅ 完整 KVM `accept-20261107-192226` ALL PASS（x86_64 单核 / 4 核 / 8 核 / q35） |
| Ring 后端契约化（issue #5） | 后端路由、执行/推进/取消/释放收敛；锁区间审计；Wait 到期接入每 Ring 固定期限堆，运行表槽位直达；取消/关闭/退出与交付竞争保持唯一终态 | ✅ issue #5 已关闭；64×16 并发 Wait `scan_slots=0`，自然完成 p99.9/max 13.9/58.1 ms，完整 KVM ALL PASS |
| 启动阶段与启动模式（issue #7） | 16 个全局阶段、静态验收计划、生产模式、失败回滚与重复初始化检查 | ✅ issue #7 已关闭；启动计划与生产模式在单核 / 4 核 / 8 核 / q35 均通过 |
| 定时器中断活锁修复 | 处理器相对时钟很慢时，定时器事务可以吃满处理器，被打断的代码一条指令也执行不了（`-icount shift=8` 稳定复现）。`kernel_core::timer_progress`：连续 2 次窗口不足事务开销之后，定时器事件只推进时钟、记账推迟，直到窗口够长 | ✅ 确定性 `-icount` 矩阵与完整 KVM 回归通过；TCG 只作功能性活锁证据，不作 p99.9 性能结论 |
| 期限事件增量维护（issue #2 第二至六片） | 任务表可变访问自动标脏，`refresh_ns_events()` 只同步脏槽位、只重读受影响处理器的根；运行预算只在配额耗尽点或周期边界结算，非运行预算只在自身堆节点到期时补充。owner-leaf 经 TLA 评估后当前不采纳；宿主 KVM 连续 5 轮完整样本通过 | ✅ issue #2 已关闭；裸机仅作后续硬件差异交叉核验 |
| 服务装配与模块激活（issue #6） | 模块状态机、依赖顺序、全有全无回滚、发布掩码与审计；运行时停用、健康降级与恢复 | ✅ issue #6 已关闭；完整/精简 Profile、运行时停用和健康降级真实 QEMU 通过 |
| 模块化宏内核装配边界（issue #11） | K-01～K-08 在 Wave 4 后源码上重新复核；每个登记系统操作必须有唯一服务所有者，服务前缀歧义在 Profile 校验期拒绝，移除未认领操作的 `Ungated` 直通；完整/精简 Profile 对“基础调用、未装配服务、健康撤回、调用者未授权”分别给出证据。当前仍只实现模块化宏内核，不创建第二套内核形态 | ✅ 架构文档、机器可读约束矩阵、宿主单测与双 Profile 真实 QEMU 审计已实现；跨域 IPC、服务死亡、重启和物理性能保证明确列为未实现，见 `docs/issue-11-架构约束.md` |
| ISA-0 | 多指令集准备：`kernel-core` 在 x86_64 / AArch64 / RISC-V64 / RISC-V32 上编译，单元测试在 64 位与 32 位上运行 | ✅ |
| ISA-1–3 | 内核移植到 AArch64、RISC-V64、RISC-V32 并在各自的 QEMU 上复跑全部验收 | ⬜ 未实现 |
| M5.1 | 装载并运行最小非特权程序（ELF），完整隔离与资源回收 | ✅ |

未列为 ✅ 的能力**尚未实现**。已知的阶段性范围限制：

- x86_64 SMP、每核运行队列和跨核 wake/PI 已接通并完成 1/4/8 核功能回归；高精度到期事务会一次发布全部已到期的每核睡眠者，并在同一事务中完成本核切换发布。Linux KVM 两轮完整采样（每轮隔离10000项、7路14336项）中，7路 wake→resume p99.9 均为50 µs，deadline→runnable为40/50 µs，deadline→resume为60/70 µs，三项均低于200 µs；完整样本、任务身份、队列和资源审计通过。
- 验收执行环境（2026-11-07 用户裁决）：标准验收默认使用宿主机 KVM 与 `-cpu host`，构建/QEMU 固定排除 CPU 0–3；性能证据优先报告 p50/p99/p99.9/max，并记录宿主负载、CPU 亲和、QEMU 与 CPU 信息。TCG 只保留给明确选择 `JASPER_ACCEL=tcg` 的确定性 `-icount` 故障注入，TCG 计时不得作为 p99.9 结论。
- CPU-cap50 单线程 TCG 的规模窗口已改为全部参与者到齐后再开窗；4/8核原85%忙碌、2 tick空闲等待与2 tick交互延迟门槛均通过，未通过提高阈值掩盖启动延迟。该结论不覆盖 deadline→wake，也不改变上述 KVM p99.9 性能账。
- `Memory` 共享内存对象、只降权映射、Channel 句柄转移、跨核撤销与页/固定配额已经接入；匿名页、ELF 与栈页也使用统一页对象生命周期。
- 没有文件系统、网络、图形、动态模块卸载。

---

## 仓库结构（Rust 部分）

```
jasper-os/
  Cargo.toml            # workspace：kernel-core + kernel + xtask（+ user/hello）
  rust-toolchain.toml   # nightly + x86_64-unknown-none
  .cargo/config.toml    # 构建配置
  kernel-core/          # 纯机制库：no_std、零依赖、宿主上 cargo test
                        #   object/objtable（对象与句柄世代、生命周期）、wait、io（ring 形状）、
                        #   frame、paging、heap、elf、abi、module、trap、trace、sync、
                        #   async_ring（异步环请求状态机）、ring_abi（用户态记录布局）
  abi/                  # 系统接口登记表：system-ids.txt（人工分配）+ system-ids.lock（冻结）
  kernel/               # 内核二进制
    src/
      arch/             # 指令集接缝：Platform 契约 + x86_64 实现（GDT/IDT、页表、syscall、用户态入口）
      sched/            # 调度：机制 / 策略（Strategy）/ 栈池 / 观察者
      mm/               # 内存：页帧、映射、内核堆、地址空间、用户指针
      syscall/          # 系统调用分发与统一权限检查
      proc/             # 进程与线程对象、ELF 装载、句柄复制与转移
      ring.rs           # 用户态异步环：对象、配额、系统调用与后端
      ipc.rs            # IPC Channel：端点、两阶段 send、原子交付的 recv
      kobj.rs           # 内核对象表与清理过程
      kmain.rs          # 架构无关的内核主流程（含各里程碑的自检演练）
      main.rs           # 引导适配层（bootloader → 中立的交接信息）
  user/hello/           # 最小用户程序（独立静态 ELF，调用号取自登记表，由 kernel/build.rs 嵌入）
  user/ring/            # 异步环的用户态验收程序（独立静态 ELF，记录布局取自 kernel-core::ring_abi）
  user/ipc/             # IPC Channel 的用户态验收程序（单进程语义 + 跨进程往返）
  xtask/                # 宿主侧：生成可引导磁盘镜像
  scripts/accept.sh     # 一键验收：宿主测试 → 构建 → QEMU 真实启动 → 逐里程碑判定
  scripts/abi-freeze.sh # 发布时把登记表冻结进 lock
```

---

## 工具链与构建

- Rust nightly（含 `rust-src`、`llvm-tools-preview`），由 `rust-toolchain.toml` 自动选择
- 目标：`x86_64-unknown-none`
- `qemu-system-x86_64`

```bash
taskset -c 4-11 cargo build --release --target x86_64-unknown-none -p jasper-kernel
taskset -c 4-11 cargo build --release -p xtask
./target/release/xtask target/x86_64-unknown-none/release/jasper-kernel images/jasper-kernel.img
```

手动运行（成功时以退出码 33 结束）：

```bash
taskset -c 4-11 timeout 60 qemu-system-x86_64 -accel kvm -cpu host \
  -drive format=raw,file=images/jasper-kernel.img -serial stdio \
  -display none -monitor none -no-reboot -m 256M -device isa-debug-exit,iobase=0xf4,iosize=0x04
```

## 验收

```bash
taskset -c 4-11 cargo test -p kernel-core   # 宿主单元测试
env JASPER_ACCEL=kvm JASPER_CORES=4-11 \
  bash scripts/accept.sh                    # 单核 / 4 核 / 8 核 / q35 完整验收
```

`accept.sh` 运行宿主测试、构建镜像、在 QEMU 中启动一次，按各里程碑的串口判据打印 PASS/FAIL 表，
并做指令集泄漏检查；证据归档到 `evidence/accept-<时间戳>/`。标准性能环境固定为宿主 KVM、
`-cpu host`、CPU 4–11；TCG 仅用于显式指定的确定性 `-icount` 故障注入。

---

## 与 Jasper 语言的关系

Jasper 是 GC-only 的主要开发语言；Rust 是底层基础设施的实现语言。
Jasper 只经语言无关、版本化的系统接口（`system.*`）使用内核能力，不依赖 Rust 的内部类型。
模块交付格式 `.jaso` 的规范见 `jaso/SPEC.md`（format 1，beta）。

## 当前边界与下一步

- `#2/#3/#4/#5/#6/#7/#8/#11` 已完成关闭；`#10/#12/#13` 是长期研究项。
- `#1` 的操作系统侧 256 位能力集合、spawn 授权与 `system.task.syscalls.set` 已完成；
  issue 保持打开仅因为 Jasper 语言侧能力集合构造尚未落地。
- S-4、FV-4、HWV-0 已完成。HWV-1～7 是独立大型系列，覆盖真实 Intel/AMD
  VMX/SVM、EPT/NPT、VM-Exit、虚拟设备与 IOMMU 直通，尚未启动。
- 下一阶段先做性能与扩展性基线（PEX-0），测量全局调度事务、多 Ring 并行、
  对象表锁、页帧缓存、内核堆、TLB 公告板和本核选择路径，再依据数据决定是否修改结构。
- 当前仍没有文件系统、网络、GPU 或运行期内核模块装卸；这些能力不会用空后端或临时接口冒充完成。

## 历史检查点（2026-10-24，部分已被后续里程碑取代）

- 用户 RAM 统一由引用计数页对象持有；匿名页、ELF/栈、共享映射与固定缓冲区共用页生命周期。已验证真实固定页配额耗尽、安全拒绝、撤销失败隔离与资源回收。
- 内存对象支持用户态创建/映射/撤销和通过 Channel 转移。ABI-R 已定义版本化扩展描述符；未实现的注册缓冲区、受限执行、任务异步中断、IOVA 与分段 I/O 等入口明确返回 unsupported，不代表这些功能已启用。
- S-3 已执行 1/4/8 核受控随机生命周期用例、4/8 核映射与固定/撤销/退出竞争、真实 CPL3 双进程 Channel 32 轮共享句柄往返。本轮完整 CI 与默认功能回归已执行；原全量验收仍保留下面的性能 FAIL 和历史未归因观察，不标记 ALL PASS。
- 验证采用有限 TLA+、生产代码 Kani、Proptest、Miri、cargo-fuzz 与 Loom；Verus/Z3 当前是明确标注的数学伴随证明，不能据此声称整个 Rust 内核已获形式化证明。工具范围见 `verification/VALIDATION-POLICY.md` 与性质登记。
- 性能指标保留原值延期优化；已有全量回归中的空闲时间记账覆盖不足仍作为开放观察，不标为通过。当前未新增 ARM/RISC-V 原生内核验收或 GPU 支持。

空闲驻留时间修正候选：本地定时器中断次数继续原样保留，另用统一参考时钟在执行状态转换处分段记录 busy/idle；4核、8核及q35独立诊断已覆盖原120tick窗口并通过，Proptest/Miri通过。完整 CI `56eaacf0` 已通过且输入逐文件匹配；默认回归单核/4核/8核/S2均退出37，q35仅停表下降性能未达标（186次，目标≤184次），原验收退出1保留。参考驻留覆盖120tick和资源检查通过。性能项按计划延期；历史偶发SIGSEGV未复现、未归因、未认定修复，保留取证记录。

### EVT-2 验证进展

已接入退出、IRQ、内存压力订阅源、带版本初始快照、独立有界队列与溢出重同步、Ring 单次批量交付及权限/配额。真实 CPL3 公开 task/process 创建后订阅在 1/4/8 核通过。独立 8 核测试已完成 1,000,000 次发布，7 个订阅者全部连续交付或明确重同步至最终版本，资源守恒；这是 kernel API/TCG 机制验证，不代表物理 p99 或 CPL3 吞吐。完整 CI 曾通过；随后全量回归暴露固定窗口与生命周期预算量混用。现已分账，原52窗口上界保持，受控默认四核/八核功能回归各38项零失败；原全量失败及计时超界保留，不冒充当前全部输入的 FULL PASS。

### RT-1 通用实时路径（候选检查点）

实时声明、运行预算与周期补充统一存放在 Scheduler 的 Task 中，已移除内核第二份全局 RtSet。新增需授权的 RT 设置与 CPU 亲和查询/设置入口；子线程继承调用者亲和范围。准入按核计算，RT 类自动采用分区 EDF；同声明幂等不刷新预算，取消后保留本周期债务，启动 RT 容量和拒绝原子性有实际覆盖。

受控四核 guest 已通过真实 CPL3 权限/描述符/继承、EDF 首次派发、容量耗尽与退出释放、自动预算耗尽/补充、失控任务节流及 RT/交互/批处理共存，退出33，RTCLASS14项与仲裁7项零失败。EDF 小切片的六工具验证已执行；Verus是数学伴随、Loom是Mutex适配，不能扩大为全内核证明。本检查点未重跑完整CI/FULL；一万周期错失率报告与运行时 Profile 禁用场景仍待补齐，RT-1暂不标整体完成。物理性能目标延期，不以TCG计时替代。

RT-1 补充：真实 `headless-min` 构建下，获 `rt.set` 调用授权的 CPL3 进程仍被 Profile 拒绝，退出和资源基线通过。通用实时功能检查点已落地；一万周期混合负载错失率属于延期报告，未运行、不冒称零错失。后续推进 RT-2，保留此报告及物理性能债务。

### RT-2 开发检查点

纳秒调度路径已经接通：校准后的串行化 TSC 域提供单调纳秒时间，Task 持有规范纳秒预算，调度事务按实际 owner 运行区间结算；绝对期限堆、LAPIC 单次定时、空闲取消和远端 IPI 提示共同驱动纳秒等待与预算事件。新操作 `system.time.wait.ns`、`system.time.monotonic.ns.get` 和 `system.task.rt.ns.set` 使用独立版本化描述符，旧 tick ABI 保持不变。

受控四核生产 guest 已验证 CPL3 纳秒等待不早返回、BSP/AP 路径、纳秒预算耗尽与补充、退出取消、LAPIC 路由恢复和资源守恒。随后定点默认回归验证九项旧功能全部通过；TCG 时钟样本不完整只进入计时结果，功能断言为零失败。有限模型、Verus/Z3 伴随、Proptest、Miri、cargo-fuzz、限定 Kani 和 Loom 的准确范围见状态文档。跨 CPU 时钟同步与校准是平台假设，宽域换算 Kani 仍未完成，物理精度、抖动和性能目标延期，不据此声称全 Rust 或硬件形式化证明。
