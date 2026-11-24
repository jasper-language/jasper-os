# Issue #56 宿主治理与分域兼容执行矩阵

更新日期：2026-11-22。

状态：**阶段 A 清单已建立，不代表跨生态统一治理已完成。**

Jasper-OS 只有一套宿主安全、资源、设备与应用治理事实源。Linux ELF、
Android APK、Wine 和 VM 可以保留各自执行 ABI，但只能通过适配映射到现有
Workload/Process、SEC/PEP、Handle/Rights、Memory、Device、Network、UI、
Install/Lifecycle 与诊断服务。本矩阵用于暴露真实接入程度，不创建第二套
Broker、权限根、资源账本或管理 ABI。

机器可读权威为
`verification/issue56-host-governance.tsv`。状态含义：

- `verified`：已有指定运行环境的端到端证据，管理操作与资源回收均闭环；
- `partial`：部分机制或代表性切片已接入，仍有明确缺口；
- `missing`：宿主机制存在，但该兼容后端尚未接入；
- `unsupported`：当前声明范围明确不支持，必须说明原因。

阶段 A 的完成只表示“能力、适配、缺口和权威所有者已经列清”。阶段 B/C/D
仍需分别完成桥接契约、代表性真实纵切和多 Profile/故障矩阵。

## 关键边界

1. 兼容后端中的 PID、UID、Android UID/package、Wine 进程/token 和 VM
   客体账号都不是 Jasper 宿主可信身份。
2. Linux root、Android system/SELinux、Windows Administrator 和 VM root
   不得自动提升为 Jasper 管理员。
3. VM 管理的默认粒度是 VM；未经 Guest Agent 身份、状态一致性和双向资源
   映射验证，不得宣称能管理客体内部单个应用。
4. UI 前端只能消费已授权的系统/服务事实，不能复制授权引擎或应用账本。
5. 停用全部兼容后端后，原生启动、安全、设备、文件和生命周期机制必须继续
   独立工作。

## 当前结论

- 原生后端已有较多机制级证据，但应用、Workload、UI、安装和诊断仍非全部
  端到端 closed。
- Linux ELF 在进程、fd、信号、文件、网络和受限图形路径上已有真实运行证据，
  但可信应用身份、完整配额归属、设备 UAPI 和窗口生命周期仍不完整。
- Android 已有 Bionic/Binder/ART/APK 执行切片，但 Activity/Framework、
  统一身份和生命周期接入仍缺失。
- Wine 目前仍停在 prefix/bootstrap，尚不能进入统一应用治理验收。
- VM 仅存在 Guest Integration 设计和局部隔离实验，尚无可信客体内应用映射。

完整逐域事实见机器台账；任何 `partial`、`missing` 或 `unsupported` 项都不得
被“程序能运行”替代。
