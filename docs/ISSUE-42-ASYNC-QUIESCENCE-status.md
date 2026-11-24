# Issue #42 M09：AsyncRing 后端静止矩阵

更新时间：2026-11-21。

## 状态

`implemented-tested`（M09 native mechanism）。已为 Driver Host、FS、NET 和
Graphics 四类 backend 补齐 AsyncRing 的 submitted → cancel → backend terminal
→ quiesce → completion 路径。真实硬件 DMA/IRQ 故障注入、hot-unplug 与物理
IOMMU 不在本状态机的完成口径内，继续由 #43 持有独立硬件门。

## 已闭合的设备矩阵

`kernel-core/src/async_ring_runtime.rs` 的
`device_backend_completion_waits_for_clean_reset_quiescence` 使用真实
`DriverHostBroker`、真实 queue-work 资源预留、真实 reset quiescence proof 和
`RuntimeAsyncRing`：

1. 提交访问缓冲区的 AsyncRing 请求，并将其开始为可中止；
2. 取消只裁决一次，此时 completion 不发布；
3. DMA/IRQ 未静止的 Driver Host reset 返回 `NotQuiesced`，请求和资源保持；
4. 干净 quiescence proof 后才取消 Driver Host 请求并使其静止；
5. Ring 随后发布唯一 `Cancelled` completion、归还信用、销毁控制块并归还
   不透明 context；
6. 再次 quiesce/consume 不明显成功，Driver Host pending/pass/bound 均归零。

同一矩阵新增 Host 崩溃/quarantine 路径：

- 请求取消后 completion 仍不可见；
- DMA 未静止时崩溃会把设备置为 quarantine，撤销 pass 和请求，并拒绝提前恢复；
- 干净 quiescence proof 恢复新 Host generation 后才允许完成 AsyncRing quiesce；
- 旧 Driver Host 请求 token 在崩溃后拒绝，Ring context 只回收一次。

FS 矩阵使用真实 `FsContract` 文件、open Handle 和 file mapping：

- 有缓冲的 AsyncRing 请求可中止取消后，completion 保持不可见；
- 关闭真实文件 Handle 使 mapping 失效并成为 FS backend 的静止事实；
- 随后只发布一次 `Cancelled` completion，归还 Ring context，live Handle 为 0；
- 重复 quiesce/consume 失败关闭。

NET 矩阵使用真实 `UdpSocketRuntime`、已排队 datagram 和配额：

- 请求取消后，在 socket close 前不得发布 completion；
- socket close 清空真实队列并完整归还 sockets/datagrams/bytes 配额；
- 随后只发布一次 `Cancelled` completion 并归还 Ring context；
- 旧 socket Handle 的 recv/再次 close 返回 `Closed`。

Graphics 矩阵使用真实 `VirtioGpuBackend` 的 2D resource 和 backing：

- 资源与 backing 已实际提交后，取消 AsyncRing 请求仍不发布 completion；
- GPU reset 清空 resource/resident bytes 并推进 generation，旧 generation
  completion 显式返回 `StaleGeneration`；
- reset 后才 quiesce 请求，产生唯一 `Cancelled` 终态并回收 context；
- 新 generation 可接受完成，旧 credit/context 与资源不回绕。

验证：

```text
cargo test -p kernel-core --features runtime-registries,network-dynamic \
  async_ring_runtime --lib
8 passed; 0 failed
```

并发压力：8 个调用者共享同一 `RuntimeAsyncRing`，各自完成 256 次
submit→start→finish/cancel→quiesce→consume 序列；最终所有请求只有一个终态，
credit、reserved、context 和完成队列均回到基线。

## 最终裁决边界

- 真实设备 DMA 仍访问、IRQ 迟到、FLR/物理 reset 失败、hot-unplug 和物理 IOMMU
  属于 #43 硬件验收；
- 真实多 CPU 内核调用方共享同一对象表锁下已有并发压力，后续更高负载 reclaim
  属于性能/验证专项；
- 本切片不新增用户 ABI，不把 Driver Host 软件状态机或 QEMU 证据提升为物理设备
  资格。
