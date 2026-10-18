# jasper-os

Jasper 生态的**操作系统侧项目**：一个用 Rust 实现、在 QEMU 中真实启动的模块化宏内核。

## 一句话

> **Rust 负责内核与底层基础设施，Jasper 负责其上的绝大多数系统服务与应用。**
> Jasper 不依赖 jasper-os 才能运行；jasper-os 是 Jasper 生态的原生执行平台之一。

---

## 设计原则

1. **Core 只提供机制，不提供策略。** 任务与调度、陷入与中断、对象 / 句柄 / 权限（capability）、
   等待与通知、异步 I/O 的提交与完成、地址空间、模块管理、观测性属于 Core；调度策略等可替换。
2. **Core 不引入 Unix / Linux / Windows 语义。** 没有 `fd`、`fork`、`errno`、`VFS`、`epoll`；
   这些属于兼容层。资源一律经 **Handle + Rights** 访问。
3. **多指令集。** 目标指令集为 x86_64、AArch64、RISC-V64、RISC-V32；x86_64 是先行验证平台；一切指令集相关代码都在 `kernel/src/arch/<isa>/`，
   经 `arch::Platform` 契约接入，Core 中不出现任何 ISA 专有代码（由验收脚本机械检查）。
4. **异步只有「提交 → 完成」一种形态。** 不提供就绪式（readiness）接口；每个被接受的请求恰好产生一个终态完成。
5. **系统接口可被机器读懂。** 对外标识符采用 `system.<领域>.<对象>.<动作>` 分层命名，
   每个接口带结构化元数据（版本、所需权限、副作用、中文显示名）；错误是带规范名的枚举而非整数错误码。
6. **UTF-8 与原生中文。** 内核文本接口按 UTF-8 处理，串口可直接输出中文。
7. **真实启动才算完成。** 每个里程碑都以 QEMU 中的真实运行与串口输出为验收依据，不以「编译通过」或宿主模拟代替。

---

## 当前状态

以下均已在 QEMU（x86_64）中真实启动验证，可用 `scripts/accept.sh` 一键复现：

| 里程碑 | 内容 | 状态 |
|---|---|---|
| M1.0–M1.2 | 工作区、真实启动、GDT/IDT/PIC/PIT、真实时钟中断 | ✅ |
| M1.3 | 静态内核栈 + 真实上下文切换（协作式） | ✅ |
| M1.4 | 定时器驱动的抢占式轮转 | ✅ |
| M1.4b | 指令集分层（`arch::Platform` 契约） | ✅ |
| M1.5 | `kernel-core`：宿主可测的纯机制库（对象/句柄世代、等待、异步 ring、模块、陷入分发、追踪等） | ✅ |
| M1.6 | 一键验收 + 证据归档 | ✅ |
| M2.1 | 物理页帧分配器 | ✅ |
| M2.2 | 架构无关的页映射接口（x86_64 以 4 级页表实现） | ✅ |
| M2.3 | 内核堆（`alloc` 可用，按需增长） | ✅ |
| M2.4 | 独立地址空间（真实切换，隔离与回收） | ✅ |
| M3.1 | 进入用户态（Ring 3）+ 用户态故障隔离 | ✅ |
| M3.2 | 系统调用入口（`syscall`/`sysretq`）+ 人工分配、构建期校验的稳定 ID 登记表（`abi/`）+ 统一权限检查 | ✅ |
| M3.3 | 用户指针安全（校验后经物理映射复制，内核从不直接解引用用户地址） | ✅ |
| M3.4 | 进程 / 线程对象（资源归进程所有，退出后完整回收） | ✅ |
| M4.0 | 对象生命周期与异步取消规范（语义冻结） | ✅ |
| M4.1 | 对象生命周期：外部所有权与内部引用分离、清理队列迭代级联 | ✅ |
| M4.2 | Handle/Rights：只可降权的复制与限权、跨进程原子转移 | ✅ |
| M4.3 | 用户态异步 ring（提交 → 完成；完成信用；取消；closing；配额） | ✅ |
| M4.4 | IPC Channel（send/recv 经 ring）与取消、交付的原子性；接收缓冲区页帧固定 | ✅ |
| ISA-0 | 多指令集准备：`kernel-core` 在 x86_64 / AArch64 / RISC-V64 / RISC-V32 上编译，单元测试在 64 位与 32 位上运行 | ✅ |
| ISA-1–3 | 内核移植到 AArch64、RISC-V64、RISC-V32 并在各自的 QEMU 上复跑全部验收 | ⬜ |
| M5.1 | 装载并运行最小非特权程序（ELF）：Ring 3 运行；读内核内存 / 特权指令 / 无效指令只终止该进程；坏系统调用指针被拒；多线程进程终止（含内核内阻塞的线程）与父进程等待；页帧 / 对象全部回收 | ✅ |
| J-1 | 用户态最小运行时 `jasper-rt`（`no_std` + `alloc`）：程序入口与 panic 处理、按需增长的堆（新增 `system.memory.map` / `unmap`）、线程、Channel、异步环；用它写成的普通 Rust 程序在 Ring 3 通过成功与失败路径检查 | ✅ |
| J-2 | 现有 Rust 库的可移植性：sha2、crc、miniz_oxide、smoltcp（环回 TCP）在用户态通过已知答案测试；形成可移植性清单 | ✅ |
| J-3 | 最小 `.jaso`（Native-only，格式 v0 实验性）：清单 + 段目录 + SHA-256 完整性、宿主打包工具、用户态装载器（重定位、W^X 权限、宿主接口表、卸载）；篡改 / 指令集 / 装载阶段 / 能力不符均被拒 | ✅ |

M5.1 已通过：「独立 Rust 内核」阶段目标在 x86_64（QEMU）上达成。未列为 ✅ 的能力**尚未实现**。

---

## 仓库结构

```
jasper-os/
  Cargo.toml            # workspace：kernel-core + kernel + xtask
  rust-toolchain.toml   # nightly + x86_64-unknown-none
  kernel-core/          # 纯机制库：no_std、零依赖、可在宿主上 cargo test
  abi/                  # 系统接口登记表：人工分配的稳定 ID + 已发布冻结表
  kernel/               # 内核二进制
    src/
      arch/             # 指令集接缝：Platform 契约 + x86_64 实现
      sched/            # 调度：机制 / 策略（Strategy）/ 栈池 / 观察者
      mm/               # 内存：页帧、映射、内核堆、地址空间、用户指针
      syscall/          # 系统调用分发与统一权限检查
      proc/             # 进程与线程对象
      kobj.rs           # 内核对象表与清理过程
      kmain.rs          # 架构无关的内核主流程
      main.rs           # 引导适配层（bootloader → 中立的交接信息）
  user/hello/           # 最小用户程序（独立静态 ELF，调用号取自登记表）
  user/ring/            # 异步环的用户态验收程序（独立静态 ELF）
  user/ipc/             # IPC Channel 的用户态验收程序（单进程语义 + 跨进程往返）
  user/prog/            # 最小非特权程序的验收程序（隔离、故障、进程终止与等待）
  user/rt/              # 用户态运行时 jasper-rt（入口、堆、线程、Channel、异步环）
  user/rtdemo/          # 用 jasper-rt 写成的验收程序
  user/libcheck/        # 现有 Rust 库（sha2 / crc / miniz_oxide / smoltcp）的已知答案测试
  user/jasodemo/        # .jaso 装载器的验收程序
  jaso/                 # .jaso 模块格式：解析与校验（no_std）、构建、从 ELF 打包
  modules/demo/         # 第一个 .jaso 模块
  tools/jasopack/       # 宿主侧工具：打包 / 检查 .jaso
  xtask/                # 宿主侧：生成可引导磁盘镜像
  scripts/accept.sh     # 一键验收：构建 → QEMU 真实启动 → 逐里程碑判定
  docs/rust-kernel.md   # 中文说明：结构、分层、构建与验收
```

---

## 构建与验收

需要 nightly 工具链（含 `rust-src`、`llvm-tools-preview`，由 `rust-toolchain.toml` 自动选择）与 `qemu-system-x86_64`：

```bash
bash scripts/accept.sh
```

脚本会运行 `kernel-core` 的宿主单元测试、构建内核与可引导镜像、在 QEMU 中真实启动一次，
按各里程碑判据检查串口输出并打印 PASS/FAIL 表；证据归档到 `evidence/accept-<时间戳>/`。

---

## 与 Jasper 语言的关系

Jasper 是 GC-only 的主要开发语言；Rust 是底层基础设施的实现语言。
Jasper 只经语言无关、版本化的系统接口使用内核能力，不依赖 Rust 的内部类型。
模块交付格式 `.jaso` 由 Jasper 语言项目定义。

---

## 许可证

**Apache License 2.0**，见 [LICENSE](LICENSE)。
