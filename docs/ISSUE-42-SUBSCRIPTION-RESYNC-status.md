# Issue #42 原生订阅版本连续性状态

更新时间：2026-11-18。

状态：**软件修复与定向测试完成；现有全量 QEMU 专项未进入 EVT-2 热路径，
因此不作运行级完成声明。**

## 问题

订阅发布路径原先在源版本已经推进后，对每个订阅队列使用 `assert!` 检查版本
连续性。该断言表达内部不变量，但若未来调用路径或状态扩展破坏该不变量，外部事件
可能把内核 panic 当成失败处理。

## 原生修复

- `Queue::accepts(version)` 只判定队列是否接受精确后继版本；
- 发布前先检查所有仍关联该源的活跃订阅，任一分歧返回结构化错误，源版本不推进；
- 预检通过后才推进源与订阅队列；
- 防御性提交失败会把该订阅置为一次权威 `Resync(snapshot)`，不 panic、不发布
  不连续局部事件；
- 不引入兼容 ABI、fd/errno、第二套事件源或资源所有权。

## 验证

```text
cargo test -p kernel-core subscription --lib
2 passed; 0 failed

cargo check -p jasper-kernel \
  --target x86_64-unknown-none \
  --features evt2-broadcast-verify
PASS
```

新增测试覆盖：版本 1 只接受 2、拒绝跳至 3；强制 Resync 后只交付一份完整最新
snapshot，后续版本继续从该 snapshot 连续推进。

现有 `evt2-broadcast` QEMU 脚本在完整 PREFIX 的 8-vCPU SMP console 阶段提前
重启，未到达 EVT-2 case；该次尝试没有被计为通过。真实消息队列、进程退出和
服务恢复矩阵仍需在新的最小专项镜像中执行。
