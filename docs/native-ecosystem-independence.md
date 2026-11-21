# Jasper 独立生态与兼容组件边界

更新日期：2026-11-21。

## 原则

Jasper-OS 提供稳定、语言中立的系统执行环境。Jasper 语言生态独立开发，发行版
负责选择和集成 Jasper 运行时及应用框架；编译器、语法、标准库、工具链和自举
工作不进入 Jasper-OS 内核与系统机制 DAG。

Jasper-OS **不会提供 JVM/Java、.NET/CoreCLR/C# 或 Android Framework 的原生
框架 ABI**。这些框架及其运行时只能作为外部用户态组件，通过 Linux 兼容层
（Android Framework 可在 Linux ABI 之上叠加 Android 用户态适配）运行。这里
“可以运行”表示兼容验收，不表示 Jasper 原生生态支持该框架，也不授权为框架扩张
内核 ABI。

POSIX、Linux ABI、Android、Windows 与外部驱动适配是生态迁移和互操作设施，
不是 Jasper 原生体系的永久基础依赖。

兼容能力可以长期存在，但必须同时满足以下条件：

1. 由显式 Profile、系统服务或可安装组件启用；
2. 能从默认原生 Profile 的依赖树和发行配置中移除；
3. 停用或卸载后，Jasper 原生应用、系统接口、服务和驱动框架仍可独立构建与运行；
4. 不向原生 ABI 注入 fd、fork、errno、Linux syscall 编号或其他历史语义；
5. 服从 Handle/Rights、PEP、配额、审计、撤销和资源生命周期规则。

## 外部语言与应用框架边界

| 外部框架/运行时 | 合法执行路径 | Jasper 原生 ABI/框架 |
| --- | --- | --- |
| OpenJDK/JVM、Java 应用 | Linux ABI 兼容层中的未修改 Linux 用户态运行时 | 不新增 JVM、Java 或 JNI 内核 ABI；不是原生框架 |
| .NET Runtime/CoreCLR、C# 应用 | Linux ABI 兼容层中的未修改 Linux x64 用户态运行时 | 不新增 CLR、.NET 或 C# 内核 ABI；不是原生框架 |
| Android Framework/Activity、ART/APK | Linux ABI 之上由可选 Android 用户态兼容组件执行 | 不新增 Android Framework、ActivityManager 或 ART 内核 ABI；不是原生框架 |
| Win32/Direct3D 应用 | Wine 经 Linux ABI，DXVK/VKD3D 再经 Jasper Vulkan/GPU 服务 | 不新增 Win32、PE 或 Direct3D 内核 ABI；不是原生框架 |

兼容层可以因为真实运行时需求修复通用 Linux 机制，但不得据此把该框架的对象、
API、错误码、生命周期或权限模型升级成 Jasper 原生能力。只有与具体框架无关、
经过独立 ABI 审查的通用缺口，才能进入 Jasper `system.*` 或 `service.*`。

桌面、Terminal、系统设置和系统级应用使用 Jasper 技术栈；外部语言框架即使能
通过兼容层启动，也不能把“兼容运行”记作“Jasper 原生框架已支持”。

## 当前实现边界

| 组件 | 启用方式 | 默认 Jasper Profile |
| --- | --- | --- |
| Linux syscall 兼容服务 | `linux-abi` | 不编译、不链接 |
| Linux ELF 规划与页表后端 | `compat-elf` | 不编译、不链接 |
| Linux syscall 验收 | `compat-syscall-verify` | 不启用 |
| Linux ELF 后端验收 | `compat-elf-backend-verify` | 不启用 |
| Ubuntu 动态 libc 验收 | `compat-dynamic-libc-verify` | 不启用 |

`jasper-kernel` 对 `jasper-compat-core` 和 `jasper-compat-loader` 使用可选依赖。
Linux fd 表、兼容 pid、Linux 调用权限和 ELF 后端模块只在对应特性启用时进入
进程对象与模块树。Ubuntu 动态 libc 验收必须显式同时启用这两个服务；ELF fixture
校验不向默认内核构建依赖树加入 `goblin` 等兼容解析库。原生进程不携带这些状态。

## 验证矩阵

| 项目 | 验收方法 | 当前状态 |
| --- | --- | --- |
| 默认依赖隔离 | `cargo tree -p jasper-kernel --no-default-features` 不含两个兼容 crate | passed |
| 原生构建 | `cargo check -p jasper-kernel --target x86_64-unknown-none --no-default-features` | passed |
| Native 发行 Profile | `release/native-profile.toml` 精确使用默认内核特性且兼容组件列表为空 | passed |
| syscall 显式启用 | 启用 `compat-syscall-verify` 后引入并编译 `jasper-compat-core` | passed |
| ELF 后端显式启用 | 启用 `compat-elf-backend-verify` 后引入并编译 `jasper-compat-loader` | passed |
| 发行组件卸载 | 安装、停用、卸载后原生 Profile 启动与设备服务不回退 | pending |
| 默认发行退出 | 兼容组件不在默认发行配置，且原生应用生态可替代迁移需求 | pending |

机器检查脚本读取本矩阵、内核清单和源码门控锚点。`core-passed` 只表示默认依赖
隔离、显式装配和组件管理软件侧闭环，不表示真实默认发行退出与完整原生生态
迁移已经完成。

## 演进规则

新增兼容能力必须优先作为独立服务或可选 crate 接入。只有通用机制才能通过正式
ABI 审查进入 Jasper 原生能力；历史 ABI 语义继续留在兼容层。

默认发行配置应逐步减少兼容组件，但不得提前删除仍被真实迁移用户依赖的能力。
每次退出默认配置都必须有替代路径、兼容通知、回滚方案和真实回归证据。
