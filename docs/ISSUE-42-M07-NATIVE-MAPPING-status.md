# Issue #42 M07：原生内存映射生命周期

更新时间：2026-11-21。

状态：**implemented-tested**。M07 关闭的是 Jasper 原生 MemoryObject 映射、
撤销、重映射与跨 CPU 等待生命周期；Linux VM/userfaultfd API 仍只属于兼容层。

## 退出门证据

- `kernel-core::memory_capability` 8/8：动态容量、split 复用、边界/Rights/
  generation、重叠拒绝、范围撤销和资源合并。
- `kernel-core::address_sync` 7/7：共享 backing identity + generation 条件、
  alias、同值发布防丢失唤醒、注册/唤醒单次消费、撤销、退出、deadline、容量
  和 64 task generation 广播。
- 真实内核演练使用两个 Process、同一 MemoryObject 的两个 capability 映射和
  真实 scheduler task event-wait。完整 CI `44897174802` 的 1/4/8-CPU QEMU
  验收全部通过。
- 四/八 CPU 等待者与发布者分散在三个 CPU；五阶段 marker 均为
  `terminal=true resources=true failed=0`。
- 等待期间撤销映射导致失败关闭；Process exit/reap 撤销映射与 capability；
  旧地址撤销后同一 MemoryObject 可映射到新地址并获得新 capability。
- 页帧、对象、映射和等待登记均回基线。

## 边界

本状态不新增 syscall 或用户 ABI，也不把 Linux futex、userfaultfd、PID 或 fd
语义写入内核。M02 已按“没有独立非兼容消费者则不批准 CPL3 ABI”完成裁决；
M08 userfaultfd/Mach pager 永久保留兼容，`fault_pager` 状态机只作为 proof-only；
物理设备 DMA 属于 #43 硬件验收。
