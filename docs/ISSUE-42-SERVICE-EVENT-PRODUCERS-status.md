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
- `cargo test -p kernel-core --lib`：1077/1077；
- `service_events` 自测覆盖旧 generation 拒绝、终止后发布拒绝和 Resync。
- `kernel/src/service_event_demo.rs` 把四个真实服务 snapshot 接到普通 kernel
  EventSource Handle，验证失败操作不发布、Driver reset 队列溢出产生权威
  Resync、订阅关闭与对象回收；`--features evt2-verify` 的 x86_64 `no_std`
  内核构建通过。

各测试把真实服务状态的 snapshot 送入现有有界订阅 Queue，而不是把四个字符串
标签交给同一个合成 producer。

## 真实客户机验收

```text
JASPER_ACCEPT=spot JASPER_CHECKS=evt2 JASPER_ACCEL=kvm \
JASPER_CORES=4-11 JASPER_QEMU_TIMEOUT=360 bash scripts/accept.sh
evidence/accept-20261121-004907
qemu_rc=33
```

客户机得到：

```text
[JSR-EVT2-SERVICE] domains=4 fs=true net=true driver=true graphics=true \
  failure_atomic=true overflow_resync=true subscriptions_closed=true \
  resources=true failed=0
```

M01 已达到 `implemented-tested`。这不关闭其余 24 个 Issue #42 机制族。
