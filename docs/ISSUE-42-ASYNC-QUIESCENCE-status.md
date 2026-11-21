# Issue #42 M09：AsyncRing 后端静止矩阵

更新时间：2026-11-21。

## 状态

`partial`。已为一类真实设备请求补齐 AsyncRing 的
submitted → cancel → backend terminal → quiesce → completion 路径；尚未把这个矩阵
扩展到 FS、NET、graphics 和真实硬件 DMA/IRQ 故障注入，不能关闭 M09。

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

验证：

```text
cargo test -p kernel-core --features runtime-registries \
  async_ring_runtime --lib
3 passed; 0 failed
```

## 尚未关闭

- FS/virtio-fs、NET 和 graphics 的同类真实 backend 矩阵；
- 真实设备 DMA 仍访问、IRQ 迟到、FLR/reset 失败、hot-unplug 和物理 IOMMU；
- 多 CPU 取消/完成竞争与高负载 reclaim。

本切片不新增用户 ABI，不把 Driver Host 测试提升为物理设备资格。
