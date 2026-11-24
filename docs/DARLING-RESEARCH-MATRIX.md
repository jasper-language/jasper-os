# Darling 研究线路与失败关闭矩阵

更新日期：2026-11-23。

状态：**research-passed CLI；不是官方支持、不是 DAG 前置、不新增 Darwin/macOS
原生 ABI。** 未修改的 Darling 命令行已在 Jasper x86-64 guest 中真实执行并完成
资源回收；GUI/WindowServer 与 Metal 仍不在本轮完成范围。

Issue [#31](https://github.com/DarkMagier/jasper-os/issues/31) 已明确拒绝把
Darling、Mach-O、dyld、Cocoa 或 Apple 应用兼容纳入 Jasper-OS 交付义务。
Issue [#55](https://github.com/DarkMagier/jasper-os/issues/55) 只把 Darling 保留为
研究候选；Issue [#56](https://github.com/DarkMagier/jasper-os/issues/56) 要求即使研究
未来进入实现，也只能复用 Jasper 的统一身份、授权、资源、设备和生命周期事实源。

本线路冻结上游事实和实验分层，通过既有 Linux Compatibility 边界完成 CLI
执行，不为 Darling 建立第二套权限、对象、进程或图形体系。

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

## 已通过的 guest CLI 验收

`evidence/darling-jasper-final-r156/` 记录了 Jasper OVMF/virtio-blk guest 中的
真实验收。固定、未修改的 Darling release 经现有 Linux Compatibility 路径启动
launchd、darlingserver、shellspawn 和 dyld，执行未修改的 Mach-O `/bin/echo`：

```text
DARLING_EXEC_OK
[JSR-DARLING-START] attempt=1 exited_zero=true
[JSR-DARLING-CLEANUP] frames_before=433353 frames_after=446517 retained=0 processes=0
```

QEMU 以验收码 `33` 退出，没有 panic、Linux ABI failure 或动态兼容失败。第一次
冷启动未完成请求，受预算约束的重试在 launchd/shellspawn 已就绪后成功；随后兼容
进程被终止并 reaped，保留 frame 和进程数均归零。

## host baseline

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
| 容器启动 | 已通过 | 未修改的 launch 入口受 Jasper 授权约束创建/销毁前缀 |
| mldr/Mach-O | 已通过 | 加载真实 Mach-O 并安全交棒 dyld |
| dyld/libSystem | 已通过 | 完成初始化并执行 `DARLING_EXEC_OK` |
| darlingserver/RPC | 已通过 | Mach/RPC、线程、死亡与取消终态一致 |
| Linux ABI 依赖 | 已通过 | UDS、SCM_RIGHTS、事件、信号、进程与 namespace 语义有证据 |
| vchroot/VFS | 已通过 | 路径翻译正确，非法宿主根逃逸失败关闭 |
| 线程/TLS/信号 | 已通过 | CLI 生命周期内线程、TLS、kqueue 与信号资源守恒 |
| GUI/WindowServer | 未运行 | 真实 GUI probe 上屏并接收输入 |
| Metal/Vulkan | 未运行 | 真实 Metal probe 经声明后端提交并验证 presented pixels |
| 资源与安全 | 已通过 | 冷启动失败被回收，成功重试后进程与 frame 均回基线 |

guest CLI 证据使用固定 payload 输出的 `DARLING_EXEC_OK` 和
`evidence/darling-jasper-*` 命名。GUI 和 Metal 若后续通过，必须另建独立证据，
不能由 CLI 结果外推。

早期阻断记录保留在 `evidence/darling-jasper-dyld-r37/README.md`。它记录了从
namespace、tmpfs、受控 overlay、procfs、darlingserver check-in、Mach port
RPC、vchroot 和 dyld 装载逐步收敛到 CLI 成功的过程。

## 当前明确 blocker

1. Issue #31 的排除裁决仍有效，研究不得升级成官方路线。
2. 固定 release 只有 `amd64`，Pixel 6a 是 AArch64，不能作为该 release 的验收机。
3. 官方 launcher 是 setuid-root，并依赖 namespace/overlayfs/FUSE；Jasper 在
   bounded Compatibility 边界内提供已验收的 CLI 语义，但不提供无界宿主机 root。
4. CLI、GUI/WindowServer 和 Metal 是彼此独立的兼容层，CLI `/bin/echo` 成功
   不能证明 GUI 输入、present 或 Metal。
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

检查器会拒绝：官方支持、DAG 依赖、内核 Darwin ABI、缺少成功标记或资源回收
证据的 guest pass、被修改的 release digest、缺失 blocker，以及把 host
baseline 当成 Jasper 结果。
