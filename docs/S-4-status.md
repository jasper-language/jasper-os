# S-4 短时交错压力状态

更新日期：2026-11-07 Europe/Berlin。

## 范围

S-4 按用户 2026-10-27 裁决执行：不跑 8 小时长跑，改为 8 处理器的短时交错压力；单次不超过 10 分钟，总时长不超过 30 分钟。每轮只重复 KRN-3 所有权、跨核发布、迁移与继承契约，不重复完整规模/预算饱和基准。

每轮覆盖：

* 代次安全的任务身份与重复通知；
* 远程唤醒、满邮箱回退；
* deadline-owner 与亲和性迁移；
* 传递优先级继承、持有者退出与恢复；
* 运行列表、任务表与队列一致性；
* 页帧、对象、固定帧与堆回到轮前基线。

## 运行配置

* 固定特性：`--no-default-features --features s4-soak`
* 宿主 KVM：`-accel kvm -cpu host`
* 8 个 vCPU，宿主亲和固定为 CPU 4–11；禁止 CPU 0–3；
* 锁序检查、故障注入与 KRN-2 观测编译开启；
* 三次串行运行，每次默认 300 秒，总计 15 分钟；
* 每轮之间可接受宿主停止请求，只有完整轮次之间的停止进入通过证据。

## 形式化检查

`verification/s4_leaf_interleaving.tla` 建模任务在 owner leaf 间迁移时，唤醒与 PI 消息和迁移并发。正例检查 `Safety`；负例允许陈旧代次唤醒入队，必须违反 `Safety`。

## 尚未宣称

本文件在三次 KVM 运行完成前不宣称 S-4 通过。完成时必须同时存在：

* 三次 `status.json` 均 `pass=true`；
* `[JSR-S4] ready cpus=8`、至少一个 `[JSR-S4] progress`、`[JSR-S4] complete`；
* `[JSR-EXIT] success|timing-only`；
* 每轮 `clean=true`、`deadlocks=0`、`invariant_violations=0`、资源与堆守恒；
* QEMU 优雅退出码 33 或 37。
