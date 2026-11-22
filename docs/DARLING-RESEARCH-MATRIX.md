# Darling 研究线路与失败关闭矩阵

更新日期：2026-11-22。

状态：**research-only，不是官方支持、不是 DAG 前置、不新增 Darwin/macOS 原生 ABI。**

Issue [#31](https://github.com/DarkMagier/jasper-os/issues/31) 已明确拒绝把
Darling、Mach-O、dyld、Cocoa 或 Apple 应用兼容纳入 Jasper-OS 交付义务。
Issue [#55](https://github.com/DarkMagier/jasper-os/issues/55) 只把 Darling 保留为
研究候选；Issue [#56](https://github.com/DarkMagier/jasper-os/issues/56) 要求即使研究
未来进入实现，也只能复用 Jasper 的统一身份、授权、资源、设备和生命周期事实源。

本线路当前只冻结上游事实、实验分层和禁止声明，不修改内核，也不为 Darling 建立
第二套权限、对象、进程或图形体系。

## 上游固定事实

| 字段 | 值 |
| --- | --- |
| 项目 | `darlinghq/darling` |
| release | `v0.1.20260608` |
| commit | `e947f0d5a3c6bba27e3631d9bf0da2a9840e6894` |
| 许可证 | GPL-3.0；子模块许可证需逐项审核 |
| source | `darling-source.tar.xz`，505807588 bytes |
| source SHA-256 | `4fc9eb9a94af2aa396d4fafa0b6bbf0bcd7e210170854d143c080de3b5bb8df7` |
| packages | `debs_20260608.zip`，118018438 bytes |
| packages SHA-256 | `27469ef3932da2e91dd7fb34b70e3628a3e54b7af9fb5480051f44af35eca1fd` |
| 包内版本 | `0.1.20260609~noble`，`amd64` |

2026-11-22 实际下载并校验了 `debs_20260608.zip`，SHA-256 与 GitHub release
元数据一致。包内 `darling-core` 声明 `libc6 >= 2.38`，依赖 `libfuse2t64`
和 `xdg-user-dirs`；外层 `darling` 包组合 CLI、GUI、Python 2、Ruby 和 Perl
组件。归档中的 `usr/bin/darling` 是 setuid-root 入口，官方容器化设计还依赖
mount namespace、PID namespace 和 overlayfs。

## 已通过的 host baseline

Darling `v0.1.20260608` 曾在隔离的 Linux 特权容器中启动，`/bin/echo` 输出：

```text
DARLING_EXEC_OK
```

该结果只证明 Linux 宿主 baseline。它没有经过 Jasper 的 CPL3、Linux ABI、root
image、Jasper VFS、资源核算或物理设备路径，因此不是 Jasper guest 结果。

## Jasper 实验分层

机器矩阵位于 `verification/darling-research.toml`。以下阶段必须逐层验收，
前层成功不得替代后层：

| 阶段 | 当前状态 | 核心退出条件 |
| --- | --- | --- |
| 容器启动 | 阻塞 | 未修改的 launch 入口受 Jasper 授权约束创建/销毁前缀 |
| mldr/Mach-O | 未运行 | 加载真实 Mach-O 并安全交棒 dyld |
| dyld/libSystem | 未运行 | 完成初始化并执行 `DARLING_EXEC_OK` |
| darlingserver/RPC | 未运行 | Mach/RPC、线程、死亡与取消终态一致 |
| Linux ABI 依赖 | 未运行 | UDS、SCM_RIGHTS、事件、信号、FUSE、进程与 namespace 语义有证据 |
| vchroot/VFS | 未运行 | 路径翻译正确，非法宿主根逃逸失败关闭 |
| 线程/TLS/信号 | 未运行 | 线程、TLS、kqueue、Mach exception 与信号资源守恒 |
| GUI/WindowServer | 未运行 | 真实 GUI probe 上屏并接收输入 |
| Metal/Vulkan | 未运行 | 真实 Metal probe 经声明后端提交并验证 presented pixels |
| 资源与安全 | 未运行 | 身份不越权，重复启动/失败/重启全部回到基线 |

即使未来阶段通过，也必须使用
`DARLING_JASPER_GUEST_OK` 和 `evidence/darling-jasper-*` 证据命名；当前矩阵
不存在任何 Jasper guest pass。

容器启动阶段已记录
`evidence/darling-jasper-dyld-r37/README.md`：固定 release 已在 Jasper guest
内完成有界 namespace、tmpfs、受控 overlay、procfs、darlingserver check-in、
Mach port RPC、vchroot 与 Mach-O/dyld 装载。当前裁剪 payload 在 libSystem
启动时报告缺少 `libobjc.A.dylib`；该证据仍不构成 Darling/Mach-O guest
成功结果。

## 当前明确 blocker

1. Issue #31 的排除裁决仍有效，研究不得升级成官方路线。
2. 固定 release 只有 `amd64`，Pixel 6a 是 AArch64，不能作为该 release 的验收机。
3. 官方 launcher 是 setuid-root，并依赖 namespace/overlayfs/FUSE；Jasper 当前
   bounded compatibility VFS 不具备这些语义。
4. Mach-O/mldr/dyld、darlingserver 和 GUI/Metal 是彼此独立的兼容层，host
   `/bin/echo` 完全不能证明它们。
5. GPL-3.0 与子模块混合许可证意味着不能未经逐项审核直接随 Jasper 发布二进制。

特权 host baseline 的 syscall 顺序记录在
`evidence/darling-launch-trace-20261122/README.md`。它明确了实现顺序：
UTS/IPC namespace → vfork/reap → mount namespace → tmpfs/slave remount →
overlay/vchroot，之后才是 `darlingserver` 和 Mach-O/dyld。不能跳级用
host echo 替代其中任何一层。

## 验证

```text
python3 scripts/check-darling-research.py --self-test
python3 scripts/check-darling-research.py
```

检查器会拒绝：官方支持、DAG 依赖、内核 Darwin ABI、未经验证的 guest pass、
被修改的 release digest、缺失 blocker，以及把 host baseline 当成 Jasper 结果。
