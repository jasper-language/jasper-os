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
> 代理提交使用过无法绑定 GitHub 账号的本地或服务地址，于是网页
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
| ISA-0 | 多指令集准备：`kernel-core` 在 x86_64 / AArch64 / RISC-V64 / RISC-V32 上编译，单元测试在 64 位与 32 位上运行 | ✅ |
| ISA-1–3 | 内核移植到 AArch64、RISC-V64、RISC-V32 并在各自的 QEMU 上复跑全部验收 | ⬜ 未实现 |
| M5.1 | 装载并运行最小非特权程序（ELF），完整隔离与资源回收 | 🟡 ELF 装载与运行已验证；完整回收验收待 M4 |

未列为 ✅ 的能力**尚未实现**。已知的阶段性范围限制：

- x86_64 SMP 已覆盖 1/4/8 核功能回归；物理机延迟、扩展效率和 p99/p99.9 仍单列复测。
- Memory 对象、跨进程 Channel 转移、撤销与固定页配额已经接入；注册缓冲区、IOVA 与分段 I/O 仍返回 unsupported。
- 没有文件系统、网络、图形或动态模块卸载。

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
taskset -c 0-3 cargo build --release --target x86_64-unknown-none -p jasper-kernel
taskset -c 0-3 cargo build --release -p xtask
./target/release/xtask target/x86_64-unknown-none/release/jasper-kernel images/jasper-kernel.img
```

手动运行（成功时以退出码 33 结束）：

```bash
timeout 60 qemu-system-x86_64 -drive format=raw,file=images/jasper-kernel.img -serial stdio \
  -display none -monitor none -no-reboot -m 256M -device isa-debug-exit,iobase=0xf4,iosize=0x04
```

## 验收

```bash
taskset -c 0-3 cargo test -p kernel-core   # 宿主单元测试
bash scripts/accept.sh                     # 一次真实启动覆盖全部已完成里程碑
```

`accept.sh` 运行宿主测试、构建镜像、在 QEMU 中启动一次，按各里程碑的串口判据打印 PASS/FAIL 表，
并做指令集泄漏检查；证据归档到 `evidence/accept-<时间戳>/`。

---

## 与 Jasper 语言的关系

Jasper 是 GC-only 的主要开发语言；Rust 是底层基础设施的实现语言。
Jasper 只经语言无关、版本化的系统接口（`system.*`）使用内核能力，不依赖 Rust 的内部类型。
模块交付格式 `.jaso` 由 Jasper 语言项目定义。

## 共享内存与扩展契约进展（2026-10-24）

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

受控四核生产 guest 已验证 CPL3 纳秒等待不早返回、BSP/AP 路径、纳秒预算耗尽与补充、退出取消、LAPIC 路由恢复和资源守恒。随后定点默认回归验证九项旧功能全部通过；TCG 时钟样本不完整只进入计时结果，功能断言为零失败。有限模型、Verus/Z3 伴随、Proptest、Miri、cargo-fuzz、限定 Kani 和 Loom 的准确范围见 `verification/PROPERTIES.md`。跨 CPU 时钟同步与校准是平台假设，宽域换算 Kani 仍未完成，物理精度、抖动和性能目标延期，不据此声称全 Rust 或硬件形式化证明。
