# DC-1 Device Broker Core

更新日期：2026-11-17。

状态：**partial**。已实现受限 Driver Host 的核心授权与生命周期状态机；
真实用户态 Driver Host 的 MMIO/DMA/IRQ 组合运行仍属于本节点退出门。

## 已实现

`kernel-core::driver_host` 将以下事实显式分层：

1. 硬件发现只形成候选，不自动授予设备访问；
2. 每次设备准入都必须提交明确的 Device/MMIO/DMA/IRQ 最小权限集合和容量策略；
3. Device 在任一时刻只绑定给一个 host generation；
4. MMIO、DMA、IRQ 请求在发布前检查授权和容量，同一 pass 的 pending 请求会
   实际预留 MMIO region、DMA page 与 IRQ route 配额；完成、取消、reset 或 crash
   后释放，超配额失败不产生半发布状态；
5. 每个请求只有一个终态：完成、取消或撤销；
6. reset 在 DMA 与 IRQ 均确认静默前失败原子，不改变当前 grants；
7. host 崩溃立即撤销请求和 passes；没有静默证明时设备进入 quarantine，
   不能被新 host 重新绑定；
8. recovery 必须提供完整静默证明并推进 generation，使崩溃前 token 全部失效。

该模块不访问硬件、不发现 PCI、不写 IOMMU，也不替代 `system.device.*`、
Memory、Handle、IRQ 或 DMA 的既有强制机制。它只规定设备服务层如何在不制造第二
权限根的前提下组合这些机制。

### 用户态能力组合

`user-devprobe` 角色 6 在同一个未特权进程中组合：

- 打开真实 virtio-rng Device；
- 映射并读取现代 virtio common BAR；
- 创建、映射一个 Memory 对象并建立带 opaque IOVA 的可写 DMA 映射；
- 绑定真实 MSI-X 表项并创建 Ring；
- 提交 IRQ 等待，关闭 IRQ handle 后收到唯一 `InterruptClosed` 终态；
- 关闭 Ring/DMA/Memory/Device，要求对象与页帧资源回基线。

该组合由 `arch2-verify` 的同一用户驱动验收路径执行，避免 MMIO、DMA 和 IRQ 各自
在不同进程中通过却未证明组合能力。

## 验证

```text
cargo test --locked -p kernel-core driver_host
9 passed; 0 failed

cargo check --locked -p user-devprobe --target x86_64-unknown-none
PASS

cargo check --locked --target x86_64-unknown-none -p jasper-kernel --features arch2-verify
PASS

JASPER_CHECKS=arch2 JASPER_ACCEPT=spot bash scripts/accept.sh
qemu_rc=33; ARCH-2 PASS; accept: SPOT PASS
```

覆盖发现与准入分离、最小权限、设备独占、请求单终态、pending 请求资源预留与
释放、零需求拒绝、reset 失败原子与 token 失效、崩溃 quarantine/recovery，以及
容量失败不部分发布。

真实 x86_64 KVM guest 中，同一未特权 Driver Host 进程实际完成
Device/Memory/DMA/MSI-X/Ring 组合，IRQ 等待经关闭中断句柄得到唯一
`InterruptClosed` 终态，全部句柄关闭后对象与页帧回基线。证据：
`evidence/accept-20261117-131248/serial.log`。

## 未完成

- 真实 virtio 用户态 Driver Host 完成 queue notify、used-ring completion 和 timeout；
  当前 DMA capability 只向用户暴露 opaque IOVA，实际设备 queue 仍需经准入的
  IOMMU translation backend，不能把 capability 组合通过冒充 queue 完成；
- host crash、设备 reset、驱动进程退出后的硬件级静默与资源回基线；
- Pixel 6a 物理验收。

因此 `DC-1-DRIVER-HOST` 不能标记为 done；上述内核状态机只作为后续运行路径的
准入与生命周期基础。
