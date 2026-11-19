# Terminal recovery PCI 快照一致性修复

更新日期：2026-11-19。

状态：**software slice passed**。terminal-recovery 的既有非确定性启动失败已定位
并修复，但不关闭 TERM-1、LC-2 或完整 DAG。

## 复现

公开 `main` `130cbb0` 的 terminal-recovery 公共 CI 在 update-control backend
初始化返回 `unsupported`，最终 `first_program state=None` 并超时。

隔离诊断在同一 QEMU 场景中观察到 PCI 表长度为 8，但前 3 项正常、后 5 项的 BDF
和 Header 被破坏；这使 virtio-blk `1af4:1001` 无法被选中。下一次加入表读取的
诊断运行则完整看到 8 个设备并正常启动 CLI，说明故障发生在 MMIO 初始化与 PCI
消费之间，而不是终端命令或缺少虚拟磁盘。

## 修复

`mmio::prepare_window_inner` 原先在准入窗口内逐块执行：

1. 分配一个 RAM 帧；
2. 映射到 MMIO 窗口；
3. 立即解除映射；
4. 释放该帧。

真实设备映射本来就会由 `Mapping::map` 按需分配中间页表，因此这个热身循环不是
功能前提。移除“映射后立即解除”的热身事务后，窗口初始化只计算运行时容量和活动
范围，不触碰 PCI 快照所在内存；实际 MMIO 映射仍保持不可缓存、写保护与原有
失败回滚语义。

## 验证

隔离 QEMU `terminal-recovery` 连续两轮通过：

```text
[JSR-PROD-DIAG] control_pci_after ready=true functions=8
... vendor=0x1af4 device=0x1001 class=0x1/0
native-help-ok
native-echo-ok
native-bye
[JSR-PROD] first_program state=Some(Exited { code: 0 }) reclaimed=true
issue21-uefi-boot: PASS mode=terminal-recovery qemu_rc=124
```

该模式以显式 180 秒超时结束 QEMU，是脚本对交互终端模式的既定退出条件。两次运行
证据位于隔离工作树的
`evidence/issue21-uefi-boot-20261119-150409/` 与
`evidence/issue21-uefi-boot-20261119-150834/`。

这不是 PCI 表内存一致性故障的完整形式化证明；本切片只移除了已复现的触发事务，
并要求后续 CI 和更多终端恢复场景继续回归。
