# Issue #42：IPC 多 Handle 交付原子性

更新日期：2026-11-19。

状态：**software slice passed**。该切片关闭 Issue #42 指出的“接收方先写入部分
Handle，后续安装失败时静默跳过”的代码风险，不表示 Issue #42 的原生地址同步、
Pager、AsyncRing 后端静止或完整兼容矩阵已完成。

## 问题

原 `ipc::try_deliver_in` 已经预检接收方句柄表容量，但真正安装每个 Handle 时仍逐项
调用 `put_handle_in`。若内部能力分配在第二项或后续项意外失败，旧防御路径只释放
当前失败项的对象所有权，继续交付其余 Handle，可能形成部分消息和资源生命周期
不一致。

## 修复

- `HandleTable::put_many_into` 在修改前检查输出空间和全部句柄槽位；
- 多 Handle 安装若发生意外中途失败，删除本次已安装句柄后再返回错误；
- `proc::put_handles_in` 将多句柄安装保持在同一对象表锁内；
- `ipc::try_deliver_in` 先完成全部 Handle 安装，之后才扣减消息计费、写消息体并
  裁决完成；安装失败时把原消息放回队首，消息内容和 Handle 所有权均保持不变；
- send 侧也不再用 `if let Ok` 静默跳过复核或移动失败。

## 回归

内核侧 M4.4 场景发送一条携带两个 Handle 的消息，只给接收方保留一个句柄槽位：

1. 首次 recv 必须返回 `table_full`；
2. 消息仍完整留在队列，接收方句柄数不变；
3. 腾出一个槽位后，再次 recv 必须一次交付两个 Handle；
4. 进程退出后对象、队列、固定页和资源账务回到基线。

验收：

```text
JASPER_ACCEPT=spot JASPER_CHECKS=m44 JASPER_ACCEL=kvm \
  JASPER_CORES=4-11 JASPER_QEMU_TIMEOUT=300 bash scripts/accept.sh

[JSR-IPC] receiver_table_full result_table_full=true message_kept=true \
  released_slot=true complete_delivery=true
[JSR-IPC] ... reclaimed=true checks=21 failed=0
M4.4 PASS
accept: SPOT PASS
QEMU exit=37（仅计时参考项，功能检查通过）
```

证据：`evidence/accept-20261119-142255/`。

本证据来自 x86_64 KVM 定点 QEMU，不替代多架构、物理硬件或完整兼容产品验收。
