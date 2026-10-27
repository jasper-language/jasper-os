# jasper-os Rust 内核（M1.0 骨架）

> **状态声明：本目录下的 Rust 代码【未经编译】。**
> 本轮刻意采用「**只写不编译**」模式：未执行任何 `cargo` / `rustc` / `qemu` 命令。
> 凡涉及编译或运行行为的描述，都是**预测**，不是观测结果。

---

## 一、为什么先「只写不编译」

编译与链接是重负载（且需要针对 `x86_64-unknown-none` 做 `build-std` 交叉编译）。
在骨架阶段，**先把结构、模块边界与接口写清楚**，比反复编译更划算：

- 结构性问题（模块划分、trait 边界、启动路径）**看一眼就能发现**，不需要编译器
- 真正的编译错误（crate 版本、feature 名、签名）**留给专门的编译阶段一次性解决**
- 每次改动都编译会拖慢探索速度，且掩盖"设计是否合理"这个更重要的问题

因此本轮的交付物是：**一份完整的骨架 + 一份如实的不确定点清单**。

---

## 二、目录结构

| 路径 | 作用 |
|---|---|
| `rust-toolchain.toml` | nightly + `x86_64-unknown-none` 目标 + `llvm-tools-preview`、`rust-src` |
| `Cargo.toml` | workspace：成员 `kernel`、`xtask`；`panic = "abort"` |
| `.cargo/config.toml` | 按目标的 rustflags（链接脚本等） |
| `kernel/Cargo.toml` | `jasper-kernel` crate；依赖 `bootloader_api` / `x86_64` / `spin` / `pic8259` |
| `kernel/linker.ld` | 内核段布局（bootloader 路线下可能用不到） |
| `kernel/src/main.rs` | 入口：`bootloader_api::entry_point!` + `kernel_main`（M1.1 横幅、M1.2 初始化、退出码 33） |
| `kernel/src/lib.rs` | 库 crate 根，声明模块树 |
| `kernel/src/serial.rs` | COM1（`0x3F8`）输出 + `exit_qemu`（`isa-debug-exit`） |
| `kernel/src/panic.rs` | 唯一的 `#[panic_handler]` |
| `kernel/src/gdt.rs` | GDT + TSS + 双重故障 IST 栈（M1.2） |
| `kernel/src/idt.rs` | IDT：断点 / 双重故障 / 页故障 / PIT 向量 32（M1.2） |
| `kernel/src/interrupts.rs` | PIC 重映射 + 待处理队列 + EOI（M1.2） |
| `kernel/src/timer.rs` | PIT ~100 Hz + `[JSR-TICK]`（M1.2） |
| `kernel/src/memory.rs` | `VmProtection` / `VmRegion`（M1.5 骨架） |
| `kernel/src/mm.rs` | `AddressSpace` trait + `SimpleAddressSpace`（M1.5 骨架） |
| `kernel/src/task.rs` | `TaskId` / `TaskState` / `Task`（M1.3 骨架） |
| `kernel/src/sched.rs` | 轮转调度记账 + `demo()`（M1.3/M1.4 骨架） |
| `kernel/src/sync.rs` | 真实可用的 `SpinLock<T>` + `IrqSpinLock` 桩（M1.5 骨架） |
| `kernel/src/context.rs` | `TaskContext` + `global_asm! switch_context`（M1.3 骨架，**尚未接线**） |
| `kernel/src/object.rs` | `Rights` / `Handle` / `HandleTable`（M1.5 骨架） |
| `kernel/src/module.rs` | `ModuleDescriptor` / `ModuleManager`（M1.5 骨架） |
| `kernel/src/io.rs` | `IoOp` / `IoRequest` / `IoResult` / `Completion` / `MemIoCore`（M1.5 骨架） |
| `xtask/` | 宿主机侧镜像构建器（生成 bootloader BIOS 磁盘镜像） |

本仓库包含 Rust 内核实现。

---

## 三、里程碑与当前进度

| 里程碑 | 内容 | 本轮状态 |
|---|---|---|
| **M1.0** | workspace 骨架与双目标构建 | ✅ **已写**（未编译） |
| **M1.1** | 真实启动 + 串口横幅（**准入线**） | ✅ 代码已写（退出码 33 + 横幅），**待编译验证** |
| **M1.2** | 真中断：GDT + IDT + PIC + PIT | ✅ 代码已写，**待编译验证** |
| **M1.3** | 任务 + 协作式上下文切换 | 🟡 骨架（`context.rs` 未接线） |
| **M1.4** | 抢占式轮转（定时器驱动） | 🟡 骨架 |
| **M1.5** | 机制移植（对齐前期原型的机制表） | 🟡 骨架（各机制的类型与接口已定） |
| **M1.6** | 一键验收 + 证据归档 | ⬜ 未开始 |

---

## 四、构建注意事项

按风险排序，最关键的几条：

1. **`#[panic_handler]` 的位置**
   本实现把它放在 `kernel/src/panic.rs`（由 `lib.rs` 声明），
   目的是让最终二进制**只有一个** panic handler。
   **风险**：若链接模型与假设不同，会出现"缺失或重复的 panic handler"。
2. **同一个包里同时有 `[lib]` 与 `[[bin]]`**
   `main.rs` 里 `use jasper_kernel::{...}`，依赖 bin 自动链接同包 lib。
   **风险**：同包自引用在 `no_std` 交叉编译下的行为需实测。
3. **`bootloader_api` 版本与 `entry_point!` 宏签名**
4. **`x86_64` crate 的 feature 开关**（`abi_x86_interrupt` 等）与 nightly 的兼容性
5. **`.cargo/config.toml` 里 `build-std` 的写法**与工具链配置的组合

---

## 五、下一步

1. **编译阶段**：`cargo build --target x86_64-unknown-none`（需 nightly + `rust-src`），
   按上面的风险清单逐个消解
2. **启动验证**：QEMU 跑起来 → **退出码 33** + 串口出现 `[JSR-` 标记
   （这条链路已在早期启动试验中**打通过**，可作为对照）
3. 之后才是 M1.2–M1.6 的逐项落实与证据归档

---

## 六、与语言主线的关系

`jasper-os` 的终态是「**除内核外全栈 Jasper 化**」：内核用 Rust（这一层没法避免），
其上的运行时、系统服务、GUI 框架都用 Jasper 写。

因此本项目的**推进顺序**受语言主线约束：**自举是 jasper-os 的前置要求**
（OS 要自带 Jasper 工具链，工具链就得能在 jasper-os 上跑）。
在语言主线完成自举之前，本项目保持在「**骨架 + 设计**」阶段是合理的。
