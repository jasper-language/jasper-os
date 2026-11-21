# Issue #42 最终机制裁决

更新时间：2026-11-21。

状态：**25 个机制族均已获得最终裁决；Issue #42 的审计与原生机制验收闭合。**

机器可查台账为 `verification/issue42-mechanism-ledger.tsv`。最终统计：

```text
implemented-tested=15
compat-retained=10
partial=0
research=0
total=25
```

`scripts/check-issue42-mechanism-ledger.py --final` 是关闭门。只要任一机制族仍为
`partial` 或 `research`，或者 `implemented-tested` 行仍声明未关闭的本机制门，
检查即失败。

本轮本地原生机制回归：

```text
cargo test -p kernel-core --features runtime-registries,network-dynamic
1137 passed; 0 failed

python3 scripts/check-issue42-mechanism-ledger.py --final
FINAL PASS compat-retained=10 implemented-tested=15 partial=0 research=0 total=25
```

## 裁决口径

- `implemented-tested`：Jasper 原生通用机制已有真实生产代码路径和自动化、压力或
  真实 QEMU 证据；外部 ABI 的协议翻译可继续由兼容层承担。
- `compat-retained`：Linux、Android、macOS、Windows 或图形协议应永久由版本化
  兼容/服务层承担，不进入 Jasper 原生 ABI；对应的通用 Jasper 基础能力仍指向
  `implemented-tested` 机制。
- 物理 DMA/IRQ/IOMMU、GPU reset、真实网络链路、Pixel UFS 与安全密钥等资格，
  不会因为状态机或 QEMU 测试通过而被冒充完成。它们由 Issue #43、LC 和硬件
  验收节点持有独立证据门。

## 原生机制已通过

| 机制族 | 最终原生权威与证据 |
| --- | --- |
| M01 多对象等待与事件订阅 | EventWait、Subscription、ServiceEvents；四领域 producer、overflow Resync、关闭和回收 |
| M02 地址条件同步 | MemoryObject backing/generation 身份、check/register/park、PI、拆除、退出和 remap；真实 KVM 多 CPU 矩阵 |
| M03 Handle/对象转移 | Rights 衰减、generation、原子 transfer、队列所有权 drain、服务死亡和最终释放 |
| M04 任务与 Workload 生命周期 | 稳定身份、父级保留、orphan drain、64 Workload 压力和 typed terminal |
| M07 内存映射 | MemoryCapability/Object、quota、撤销、重映射、等待登记和回收 |
| M09 AsyncRing 终态 | 唯一终态、取消、deadline、Driver Host/FS/NET/GPU backend 静止及 2048 请求并发压力 |
| M10 授权与安全观察 | PEP 前置授权、policy epoch、能力衰减、post-effect observation、AuditFull 前置失败 |
| M11 层级 Workload | 聚合账务、成员退出、64 成员树形崩溃、有序销毁和恢复 |
| M12 定时事件 | 单调 deadline、周期重装、取消、溢出、tickless 和任务域恢复 |
| M13 文件事件 | 版本化 observation、持久 cursor、bounded replay、缺口 Resync 和重启 generation 隔离 |
| M14 文件与存储契约 | 文件对象、持久身份、原子 namespace 事务、双 checkpoint journal 和真实 ext4 只读/JBD2 视图 |
| M15 网络端点 | bounded queue、quota、generation、signed policy、close/rebind 和网络恢复路径 |
| M18 GPU/设备同步基础 | DMA rights、Driver Host generation/reset/quarantine、GPU submission generation 与 quiescence |
| M23 调度与 QoS | 动态 affinity、稀疏高 CPU/NUMA 拓扑、Workload 限额、fair/RT、PI 和 deadline |
| M25 观测与诊断 | 授权 trace、父子因果关联、诊断导出、有界丢失账务、紧急 crash ring 和格式版本迁移 |

这些裁决不把 `io_uring`、futex、epoll、seccomp、Driver Host 或 trace 的外部协议
搬入 Jasper 原生 ABI；它们只确认 Jasper 自身已有唯一、可测试的通用机制。

## 永久兼容保留

| 机制族 | 保留边界 | 对应 Jasper 基础 |
| --- | --- | --- |
| M05 POSIX pipe/Unix socket | pipe、socketpair、sendmsg/recvmsg 格式与缓冲策略 | M01/M03/M09 |
| M06 System V/POSIX IPC | key、semundo、queue name 与消息格式 | M01/M03/M07 |
| M08 Pager/userfaultfd | userfaultfd 与 Mach pager wire ABI | `fault_pager` 仅保留 proof-only 状态机，不批准生产 ABI |
| M16 Linux signal | signal frame、mask、sigreturn、altstack | 原生 terminal/event/fault 结构化状态 |
| M17 ELF/dyld | ELF interpreter、TLS、RELRO 与动态装载协议 | 原生 image 授权、W^X、Module 生命周期 |
| M19 Vulkan/WSI/UI | Vulkan、surface、swapchain、外国桌面协议 | 版本化 UI service object/policy |
| M20 包与系统映像格式 | Linux package、repository、compat CLI | 原生 install identity、LC 事务、签名与回滚 |
| M21 Binder/ART/Activity | Binder、ART、zygote/system_server、Activity、HAL/SELinux | M03/M09/M10 的 IPC、授权和生命周期 |
| M22 POSIX credentials | uid/gid、keyring、capability 与 foreign entitlement 格式 | 原生 SecurityContext、PEP、撤销和审计 |
| M24 可执行路径发现 | Linux path、fd path 与 registry naming | Handle/Rights、measured image identity、Module lifecycle |

## 不属于 Issue #42 关闭门的后续证据

- Pixel 6a 原生 UFS、物理安装/断电回滚和 TPM/HSM 仪式：LC-2/LC-5 与 #38。
- 真实 Binder、zygote/system_server 和 Activity 生命周期：兼容层 Activity 专项。
- 真实 DMA/IRQ/flush-reset、hot-unplug、物理 IOMMU 与 GPU provider 切换：#43、
  #29 和相关 HWV 节点。
- Pixel 私有驱动不开发；优先复用官方开源驱动并把版本、namespace 和隔离边界
  固定在兼容域。

因此 Issue #42 的关闭表示“全部机制已裁决、原生通用能力已有验证、兼容保留边界
被冻结”，不表示兼容产品全部完成，也不把其它专项的物理或运行时证据提前记入。
