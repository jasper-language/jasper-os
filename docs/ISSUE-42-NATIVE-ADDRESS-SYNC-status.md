# Issue #42 原生地址条件同步状态

更新时间：2026-11-21。

状态：**native mechanism slice passed**。新增 `kernel-core::address_sync` 的
受权地址条件状态机；该项不是新 ABI，也不表示 Issue #42 或用户态 Pager 已完成。

## 边界

- 条件身份是 `MemoryObject backing identity + generation + offset + width`，
  不是 Linux futex 地址、fd 或操作码；
- 调用方必须先用现有 `MemoryCapability` 表验证对象、范围、epoch 和 Rights；
- 等待身份复用现有 `event_wait::Registration` / `WaitSet`，不新增第二套 Task
  生命周期或权限根；
- 模块不自行加锁、读取裸指针或切换调度。调用方必须在同一 MemoryObject 临界区
  内读取条件、执行 `wait`、完成调度停车，然后才释放对象锁；
- 不引入用户 ABI；原生应用和服务在独立需求与接口审查通过前不能调用该状态机。

## 原子性

- `AddressGrant::from_capability` 只接受 active capability、READ 权限和完整
  对齐的固定宽度条件；
- `AddressState` 同时携带 `version` 与 `value`，即使发布者把值写成相同内容也会
  推进 version；
- `AddressSync::wait` 在同一状态机内比较调用方观察到的 state 与当前 state，
  不一致立即返回 `Ready`，一致才登记 waiter，关闭 check/register 丢失唤醒窗口；
- 同一任务重复等待返回 `Busy`；容量满、版本耗尽、旧对象 generation 和过期 key
  均结构化拒绝，不覆盖或消费其他 waiter；
- `publish` 在任何状态变化前检查版本溢出，只唤醒请求数量内的 waiter；
- `take` 只消费一次；`cancel`、deadline expire 和 `cancel_task` 清理精确 key，
  陈旧 key 无副作用；
- 共享 MemoryObject 可由不同 capability ID 的进程别名访问，但地址身份必须与
  backing/generation/offset/width 完全一致。

## 验证

```text
cargo test -p kernel-core address_sync --lib
6 passed; 0 failed

cargo test -p kernel-core
1048 unit tests + integration suites passed, including address_sync 5/5

cargo check -p kernel-core --target x86_64-unknown-none
PASS
```

真实 KVM 客户机专项：

```text
JASPER_ACCEPT=spot JASPER_CHECKS=addresssync JASPER_ACCEL=kvm \
JASPER_CORES=4-11 JASPER_QEMU_TIMEOUT=360 bash scripts/accept.sh
evidence/accept-20261121-011206
```

两轮结果：

```text
[JSR-ADDRESS-SYNC] pass=1 phase=warmup parked=2 terminal=true same_object=true resources=true failed=0
[JSR-ADDRESS-SYNC] pass=2 phase=measured parked=2 terminal=true same_object=true resources=true failed=0
```

该矩阵使用两个真实 Process 对象、同一 MemoryObject 的两个映射和两个真实
scheduler task event-wait key；单次 published condition 只产生权威终态并唤醒
两个 waiter。对象、映射、页帧与等待登记回基线。

四 vCPU KVM 进一步把两个等待者与发布者固定到三个不同 CPU：

```text
[JSR-ADDRESS-SYNC] pass=1 phase=warmup cpus=4 distributed=true publisher_distributed=true parked=2 terminal=true same_object=true resources=true failed=0
[JSR-ADDRESS-SYNC] pass=2 phase=measured cpus=4 distributed=true publisher_distributed=true parked=2 terminal=true same_object=true resources=true failed=0
```

证据见 `evidence/issue42-m02-multicpu-20261121-r2/`。该次 QEMU 在后续长矩阵有界超时，
因此只把两项命名矩阵作为跨 CPU 证据，不声明完整启动验收。

第三轮在等待者停车后从另一 CPU 撤销其映射与 MemoryCapability，再排空 scheduler
wait key。等待者重新验证 capability 并失败关闭：

```text
[JSR-ADDRESS-SYNC] pass=3 phase=revoke mode=revoke cpus=4 distributed=true parked=1 terminal=true revoked=true resources=true failed=0
```

证据见 `evidence/issue42-m02-revoke-20261121-r3/`；页帧、对象、映射和等待登记均回基线。

第四轮在等待者停车后直接退出并回收所属 Process，由进程生命周期撤销映射和能力，
同样唤醒等待者并回到资源基线：

```text
[JSR-ADDRESS-SYNC] pass=4 phase=exit mode=exit cpus=4 distributed=true parked=1 terminal=true exited=true revoked=true resources=true failed=0
```

证据见 `evidence/issue42-m02-exit-20261121-r5/`。

第五轮在等待者停车后撤销旧映射，并把同一 MemoryObject 句柄重映射到新地址；
旧 capability 保持失效、新地址获得新的有效 capability：

```text
[JSR-ADDRESS-SYNC] pass=5 phase=remap mode=remap cpus=4 distributed=true parked=1 terminal=true remapped=true revoked=true resources=true failed=0
```

证据见 `evidence/issue42-m02-remap-20261121-r6/`。

覆盖场景：

- 两个 capability 别名连接同一条件；
- 同值发布仍防止 lost wake；
- 对象 generation 不同和 revoked capability 失败关闭；
- 重复任务、容量拒绝、取消、任务退出、deadline 优先级和幂等清理；
- version 溢出不改变条件或 waiter。

## 尚未完成

- 已完成内核内真实 Process/MemoryObject/调度停车接线，但尚无关闭兼容层后的
  CPL3 原生调用者和经批准的用户接口；
- 跨 CPU 等待/发布、停车后 capability 撤销、Process 退出和重映射已通过；尚缺原生 CPL3
  调用决策与更高并发压力公平性矩阵；
- 用户态 Pager 仍未实现；PagerCapability、FaultEvent、处理者死亡、递归缺页、
  队列满、超时、取消与页表最终裁决都需要独立 ABI/安全设计；
- 本切片不新增 syscall，不改变 `NO-HARDCODE-RESIDUAL-1` 或任何 DAG 节点状态。
