# Issue #42 compatibility root-exec recovery slice

更新时间：2026-11-19。

状态：**真实 UEFI root-exec 与 LC-2 default-stack 回归恢复；Issue #42 仍保持 open。**

## 本切片

- root health probe 的 Linux syscall allowlist 补齐 `read`、`eventfd2`、
  `timerfd_create` 和 `signalfd4`。此前 40 个 eventfd 的 `write` 成功、`read`
  返回 `EPERM`，根因是探针实际能力集合未授权 `read`，不是 eventfd 状态损坏。
- `dup2/dup3` 现在只接受 Linux `int` 范围内的非负 fd；由 x86_64 零扩展形成的
  `> i32::MAX` 参数返回 `EBADF`，不会尝试扩展巨型描述符表。
- `getppid` 验收不再把旧的固定 `RLIMIT_NOFILE=64` 当成所有进程事实；测试读取
  运行时 rlimit，并以 `INT_MAX` 验证永远不能成为 live fd 的边界。后续 getrlimit、
  setrlimit、prlimit 读回和 raise rejection 都与同一运行时值比较。
- `sendmmsg/recvmmsg` 超过兼容批次上限时显式返回 `EINVAL`，不再把调用方的合法
  请求数量静默截成批次前缀。
- `first_program` 在资源基线前完成第一次 heap 页表扩展，避免把持久页表帧误判为
  进程泄漏。
- native install drill 在资源基线前预热一次完整的 virtio-blk 生命周期。首个 MMIO
  映射会创建持久内核页表帧；预热后的 RAM、DMA、Process 和对象仍必须由实际生命周期
  完整回收。

## 真实验收

```text
issue21-uefi-boot: PASS mode=root-exec qemu_rc=33
evidence: evidence/issue21-uefi-boot-20261119-160853
```

该运行包含真实 OVMF、x86_64 CPL3、动态 Ubuntu ELF/ld-linux/libc 程序、40 个并发
eventfd 写读、timerfd/signalfd/pipe 压力、动态 rlimit/FD 边界、sendmmsg 拒绝和
health-probe 退出/资源基线。

```text
native-install-default-stack: PASS rounds=2
evidence: evidence/native-install-warm-20261119-160000
```

该运行在同一 P0/virtio-blk 数据盘上完成首轮 format/upgrade 和次轮 reopen，两轮
均 `qemu_rc=33`、`summary failed=0 resources=true`。

宿主验证：

```text
kernel-core: 1015 passed; integration/doc tests passed
jasper-kernel x86_64-unknown-none: PASS
compat-core/loader/graphics/packages: 128 passed
hardcode gate self-test + inventory-baseline: no new finding
```

## 边界

本切片不关闭 Issue #42。Native address synchronization、受权用户态 Pager、
AsyncRing backend quiescence、完整 385 项 syscall native disposition（其中含
Jasper `RseqSliceYield`/`Uprobe` 扩展）以及关闭兼容层
后的原生 Profile 仍需独立实现和证据。
