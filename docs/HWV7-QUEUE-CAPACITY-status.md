# HWV-7 GPU 队列容量切片

更新时间：2026-11-19。

状态：**固定 32 请求和 32 completion 槽已移除，队列容量由调用方显式选择。**

## 实现

- `GpuQueue<Q, K>` 的 `Q` 表示可同时在飞请求槽，`K` 表示 completion 环槽数；
- `GraphicsService<W,S,I,G,K>` 同时显式选择窗口、surface、输入、GPU 请求和
  completion 容量；
- 服务内部 work 表使用同一 GPU 请求容量 `G`，不会出现队列已扩容但服务先截断的
  双层限制；
- `Q` 或 `K` 为 0 时拒绝创建；
- 测试使用 `GpuQueue<1,1>` 验证第二个请求返回 `QueueFull`，证明行为由显式容量
  决定，不依赖旧 32。

## 验证

```text
cargo test -p kernel-core hwv7::tests
5 passed; 0 failed

cargo test -p jasper-compat-graphics
19 passed; 0 failed

python3 scripts/check-hardcode-gate.py --inventory
337 findings; runtime-resource-capacity 62 unique fingerprints
```

## 尚未完成

- 调用方尚未由统一图形服务配置从实际可用内存、PCI queue 能力和 Workload 预算
  自动生成 `G/K`；
- 真实 GPU、Vulkan WSI、VFIO/mdev 与热插拔硬件验收仍未完成。
