# Issue #42 原生订阅版本连续性状态

更新时间：2026-11-20。

状态：**软件修复、定向测试和百万事件真实 QEMU 专项均已完成；该结论只覆盖
订阅版本连续性切片，不等于 Issue #42 全部审计项完成。**

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
- EventSource 的 64 订阅者、每订阅 16 条和每进程 512 slot 按有界背压策略审理：
  满队列不丢事件，而是交付一次权威 `Resync(snapshot)`；订阅准入在发布前完成，
  超限原子拒绝；
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

## 百万事件专项

旧脚本复用全量 `PREFIX + SMP_UP`，在无关的 console/SMP 前置演练中提前重启，
没有到 EVT-2。专项现在使用满足依赖图的最小阶段闭包，不执行无关验收用例：

```text
console -> platform -> timer -> frames -> kernel_map -> heap -> capacity
-> devices -> profile -> assembly -> sched_mode -> space -> smp
```

`scripts/evt2-broadcast-sample.sh` 在 8 vCPU、768 MiB、TCG `icount shift=0`
下串行启动；先执行 4096 事件预热，再执行 1,000,000 事件正式轮次。最终证据：

```text
[JSR-SMP] start present=8 online=8 failed=0 source=acpi.madt dropped=0 disabled=0
[JSR-EVT2-BROADCAST-SUB] cpu=1 final=1000000 resyncs=20 continuous_or_resync=true
[JSR-EVT2-BROADCAST-SUB] cpu=2 final=1000000 resyncs=18 continuous_or_resync=true
[JSR-EVT2-BROADCAST-SUB] cpu=3 final=1000000 resyncs=21 continuous_or_resync=true
[JSR-EVT2-BROADCAST-SUB] cpu=4 final=1000000 resyncs=18 continuous_or_resync=true
[JSR-EVT2-BROADCAST-SUB] cpu=5 final=1000000 resyncs=18 continuous_or_resync=true
[JSR-EVT2-BROADCAST-SUB] cpu=6 final=1000000 resyncs=20 continuous_or_resync=true
[JSR-EVT2-BROADCAST-SUB] cpu=7 final=1000000 resyncs=18 continuous_or_resync=true
[JSR-EVT2-BROADCAST] cpus=8 events=1000000 subscribers=7 all_final=true sequence=true bounded=true resources=true failed=0
qemu_rc=33
```

每个订阅者的交付数与 resync 数之和守恒，最终版本精确为 1,000,000；
Process、EventSource、Subscription 和 ExitState 均在两轮结束后回收。证据位于
`evidence/issue42-evt2-broadcast-20261118/`。

该演练使用真实内核对象与调度 API，但不是 CPL3 客户端压力、硬件吞吐或 p99
声明；Issue #42 中原生地址同步、Pager、各 AsyncRing 后端静止等专题仍按各自
DAG 退出门验证。

## 订阅等待关闭 fail-closed

复核 EVT-2 对象级路径时，在未修改的公开 `main` `130cbb0` 上复现了一个已有回归：
关闭仍有在飞等待的 Subscription 后，Ring 前置的 Handle authority 检查先返回
`system.handle.error.invalid`，覆盖了该后端本应返回的
`system.event.error.closed`。

修复保持既有对象与能力权威不变：

- Subscription Wait 的 authority 失效时，继续进入订阅后端观察自身关闭状态；
- 等待登记不再使用 `assert!`；重复、关闭或无效目标分别返回
  `busy`、`closed`、`invalid`，不以内核 panic 处理外部状态；
- `system.event.subscription.create` 的输出写入若失败，会撤销刚创建的订阅句柄；
- `check_wait_in` 同时拒绝已关闭订阅，避免先创建 Ring 控制块再失败。

验证：

```text
cargo check -p jasper-kernel --target x86_64-unknown-none --features evt2-verify
PASS

1 vCPU: qemu_rc=33
4 vCPU: qemu_rc=33
[JSR-EVT2-RING] ... busy_atomic=true sub_close=true source_close=true pins=true resources=true failed=0
[JSR-EVT2-QUOTA] ... refused=true atomic=true retry=true exit=true resources=true failed=0
[JSR-EVT2-OBJECTS] ... source_close=true exit=true quota_return=true resources=true failed=0
```

8 vCPU TCG 与 KVM 重放均在无关的 SMP console 前置阶段达到 120/300 秒上限，未进入
EVT-2，因此不计入本切片通过。证据为
`evidence/evt1/issue42-subscription-failclosed-20261119f/`；该结果只关闭订阅等待
错误优先级与 panic 路径，不代表 Issue #42 或 EVT-2 DAG 节点整体完成。
