# Issue #42 M01：服务语义事件生产者

更新时间：2026-11-21。

## 已实现

`kernel-core::service_events` 建立统一的本地事件身份：

```text
(service kind, object identity, service generation, monotonic version)
```

服务状态提交成功后才能调用 `publish`；终止后拒绝继续发布。服务重启必须使用
更高 generation，并继续递增 version，使保留旧 generation 的订阅队列进入一次
权威 `Resync(snapshot)`。

四个真实领域状态提交点已经接线：

| 服务 | 真实提交点 | 发布语义 |
| --- | --- | --- |
| FS | `ProductionFileGate::revoke` 成功设置 revoked | 文件安全代际事件 |
| NET | `WireGuardService::receive` 成功解封装 / `close` 成功释放 socket | 数据、握手、keepalive、终止 |
| Driver Host | `reset`、`crash`、`recover` 完成状态迁移 | 新 host generation、终止、恢复 |
| Graphics | `VirtioGpuBackend::reset` 清空资源并推进 generation | 图形服务新 generation |

失败的 MAC、quota、未静止 reset、非法 peer 等操作不会发布成功事件。

## 验证

- `cargo test -p kernel-core fs_prod --lib`：4/4；
- `cargo test -p kernel-core driver_host --lib`：15/15；
- `cargo test -p kernel-core --features network-dynamic net4_service --lib`：2/2；
- `cargo test -p kernel-core virtio_gpu --lib`：10/10；
- `service_events` 自测覆盖旧 generation 拒绝、终止后发布拒绝和 Resync。

各测试把真实服务状态的 snapshot 送入现有有界订阅 Queue，而不是把四个字符串
标签交给同一个合成 producer。

## 尚未关闭

M01 仍为 `partial`，因为上述 source 尚未桥接为 kernel 用户态可持有的标准
EventSource Handle，也没有四个真实订阅者跨 FS/NET/device/graphics 同时消费、
取消、撤销和回收到基线的集成矩阵。本切片只关闭“领域状态没有 producer”缺口，
不能替代该 Handle/订阅集成门。
