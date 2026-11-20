# Timer Progress: IOAPIC Lock Interrupt Safety

更新时间：2026-11-20。

状态：**已定位并修复单核 `-icount shift=10` 活锁。**

## 根因

`88f315c` 的三架构 acceptance 中，`TIMER-PROGRESS cpus=1 shift=10` 停在
574 行并以 600 秒超时失败。QEMU monitor 显示唯一 vCPU 在
`irq::device::rebalance` 内反复等待 x86_64 IOAPIC 的 `PINS` 普通
`spin::Mutex`；该锁此前可在任务上下文中被持有，而周期 timer interrupt 又会在同一
CPU 上进入 `rebalance` 并请求同一锁，形成单核自死锁。

同一风险也适用于 CMOS 索引/数据端口锁。两把锁均改为 `IrqSpinLock`：任务持锁期间
关闭本 CPU 中断，中断上下文不会重入同一锁；跨 CPU 等待仍使用现有 FIFO ticket lock。

## 复现与修复证据

修复前：

```text
cpus=1 shift=10 FAIL lines=574 rc=-9 timed_out=1 secs=600
RIP=irq::device::rebalance, spinning on IOAPIC PINS
```

修复后单例：

```text
cpus=1 shift=10 PASS marker=^\[JSR-DRV3\] device= lines=675
rc=0 timed_out=0 secs=11 info_at=9.6
```

完整 8 组 `-icount` 矩阵：

```text
1:5 PASS  1:6 PASS  1:7 PASS  1:8 PASS  1:9 PASS  1:10 PASS
4:9 PASS  8:9 PASS
```

`8:9` 在旧 TCG 主机负载下出现一次 141 秒停顿，但随后到 DRV-3 marker 并完成，
未超 600 秒；这属于计时/宿主调度观察，不作为多核功能失败掩盖。

## 边界

本修复证明上述 IOAPIC 锁重入路径已关闭，不替代完整三架构 CI、MSI-X 风暴、
真实 I/O APIC 热迁移或物理设备矩阵。
