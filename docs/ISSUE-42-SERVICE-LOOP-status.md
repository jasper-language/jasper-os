# Issue #42 M03：原生 IPC 服务死亡、重启与队列所有权

更新时间：2026-11-21。

## 范围

本切片关闭机器台账 M03 的退出门：

> Cross-service death, restart and queue-owner drain still need one real
> service-loop matrix

它验证原生 Channel、Ring、Handle/Rights 与 Process 生命周期的真实组合，
不引入 Mach Port、Linux fd/SCM_RIGHTS 或 Windows Handle ABI，也不把兼容层
对象作为原生权威。

## 验收矩阵

`kernel/src/ipc_demo.rs::service_loop_death_restart` 在真实 x86_64 KVM
客户机中执行两轮，第一轮为 warmup，第二轮为 measured。每轮创建独立的
client/service Process、Channel pair 与 Ring，并执行：

此外，`service_loop_cpl3` 在同一客户机中运行两轮真实 CPL3 service/client
ELF：CPL3 service 线程等待后退出，client 已把带转移 Handle 的消息留在
service 队列并阻塞 recv，验证 service 退出、Handle 释放和客户端单次
`peer_closed`，而不是只用内核构造的 Process 对象模拟服务端。

1. client 通过真实 Ring 向 service 端点发送消息，消息携带一个带
   `TRANSFER` 的 Event Handle；发送后发送方不再持有该 Handle。
2. service 队列中确实存在一条消息，发送方 IPC 字节配额已计费。
3. client 在自身端点上登记一个在飞 recv。
4. service Process 退出；其端点 closing 路径 drain 队列，释放消息携带的
   Handle，归还发送方字节配额，并唤醒 client 等待者。
5. 在飞 recv 只产生一个 `peer_closed` 终态；再次收取完成记录为空。
6. service 退出后的 send 得到 `peer_closed`。
7. 同一 client 句柄表关闭旧端点与 Ring，再创建新 service、Channel pair
   和 Ring；旧 Handle 无法解析到新对象，新旧 ObjId generation 不同。
8. 新 pair 完成一次真实 send/recv，随后进程退出并回收到基线。

## 证据

定点运行：

```text
JASPER_ACCEPT=spot JASPER_CHECKS=m44 JASPER_ACCEL=kvm \
JASPER_CORES=4-11 JASPER_QEMU_TIMEOUT=360 bash scripts/accept.sh
```

结果：

```text
evidence/accept-20261121-005745
QEMU exit = 37（仅计时类退出）
M4.4 = PASS
```

两轮串口证据：

```text
[JSR-IPC] service_loop round=1 phase=warmup queued=true service_exited=true queue_drain=true handle_released=true recv_terminal=true peer_closed=true old_endpoint_gone=true old_handle_rejected=true fresh_generation=true fresh_mapped=true fresh_pair=true fresh_exited=true repeated_reap=true resources=true
[JSR-IPC] service_loop round=2 phase=measured queued=true service_exited=true queue_drain=true handle_released=true recv_terminal=true peer_closed=true old_endpoint_gone=true old_handle_rejected=true fresh_generation=true fresh_mapped=true fresh_pair=true fresh_exited=true repeated_reap=true resources=true
[JSR-IPC] objects_live=0/0 pending=0 pinned=(0, 0) reclaimed=true checks=25 failed=0
```

每轮关闭日志包含 `dropped_messages=1`，证明退出时清理的是实际排队消息，
而不是空队列上的形式检查。

## 边界

- 本切片关闭原生服务死亡/重启与队列所有权矩阵；不关闭 Issue #42 其余
  24 个机制族。
- 这不把用户态 `SCM_RIGHTS`、Linux fd 或协议级 service manager 语义升级为
  Jasper 原生 ABI；这些仍由兼容层或相应系统服务节点验收。
- QEMU 的定点 M4.4 PASS 不是全部架构、全部 Issue #42 或完整发行验收。
