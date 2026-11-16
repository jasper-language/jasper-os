# DC-1 Device Broker Core

更新日期：2026-11-16。

状态：**partial**。已实现受限 Driver Host 的核心授权与生命周期状态机；
真实用户态 Driver Host 的 MMIO/DMA/IRQ 组合运行仍属于本节点退出门。

## 已实现

`kernel-core::driver_host` 将以下事实显式分层：

1. 硬件发现只形成候选，不自动授予设备访问；
2. 每次设备准入都必须提交明确的 Device/MMIO/DMA/IRQ 最小权限集合和容量策略；
3. Device 在任一时刻只绑定给一个 host generation；
4. MMIO、DMA、IRQ 请求在发布前检查授权和容量，容量失败不产生半发布状态；
5. 每个请求只有一个终态：完成、取消或撤销；
6. reset 在 DMA 与 IRQ 均确认静默前失败原子，不改变当前 grants；
7. host 崩溃立即撤销请求和 passes；没有静默证明时设备进入 quarantine，
   不能被新 host 重新绑定；
8. recovery 必须提供完整静默证明并推进 generation，使崩溃前 token 全部失效。

该模块不访问硬件、不发现 PCI、不写 IOMMU，也不替代 `system.device.*`、
Memory、Handle、IRQ 或 DMA 的既有强制机制。它只规定设备服务层如何在不制造第二
权限根的前提下组合这些机制。

## 验证

```text
cargo test --locked -p kernel-core driver_host
6 passed; 0 failed
```

覆盖发现与准入分离、最小权限、设备独占、请求单终态、reset 失败原子与 token
失效、崩溃 quarantine/recovery，以及容量失败不部分发布。

## 未完成

- 同一真实用户态进程组合获取 Device/Memory/IRQ/DMA capability；
- 真实 virtio 用户态驱动完成 MMIO、DMA queue、IRQ completion 和 timeout；
- host crash、设备 reset、驱动进程退出后的硬件级静默与资源回基线；
- Pixel 6a 物理验收。

因此 `DC-1-DRIVER-HOST` 不能标记为 done；上述内核状态机只作为后续运行路径的
准入与生命周期基础。
