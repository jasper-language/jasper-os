# NET-2 TCP 容量参数化

更新时间：2026-11-19。

状态：**TCP socket、事件和单连接接收缓冲不再有隐藏默认值。**

## 实现

`TcpService<N,E,R>` 要求调用方显式选择：

- `N`：TCP socket 表容量；
- `E`：网络事件队列容量；
- `R`：每个 socket 的接收缓冲字节数。

`TcpQuota` 仍独立限制实际 socket 数和累计字节数。服务创建时拒绝零容量；
接收窗口、BufferFull、EventQueueFull、quota、timeout、cancel 和 generation
语义不变。

生产 NET-2 验收显式使用 `TcpService<8,16,4096>`。这组值是验收 Profile，
不是内核全局默认上限。

## 验证

```text
cargo test -p kernel-core net2::tests
3 passed; 0 failed

cargo check -p jasper-kernel --target x86_64-unknown-none --features net2-verify
PASS

python3 scripts/check-hardcode-gate.py --inventory
329 findings; runtime-resource-capacity 58 unique fingerprints
```

## 尚未完成

- NET-2 验收 Profile 尚未从实际内存、网卡队列、Workload 和用户配额自动计算；
- 真实负载下的 socket 数量、接收缓冲和事件队列容量仍未做性能/回收矩阵。
