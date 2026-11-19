# Issue #42：对象转移提交回滚

更新日期：2026-11-19。

状态：**software slice passed**。该切片消除 Handle 转移提交阶段的内部 panic
假设，不关闭 Issue #42 或任何 DAG 节点。

## 问题

`HandleTable::transfer_to` 在目标和源位于不同表时，先完成目标插入，再假定源句柄
一定可以被移出。原实现使用 `expect`；若内部状态在未来扩展中意外变化，会以内核
panic 代替明确错误，并可能留下目标侧所有权。

同进程 `proc::transfer` 也先移除源句柄，再向目标表放入相同 Capability lineage。
后续放入若意外失败，原句柄已经消失，失败不再保持状态不变。

## 修复

- 跨表转移在源句柄移除失败时删除本次目标插入并返回原始错误；
- 同进程转移先把相同 Capability lineage 安装到新的目标槽位，再移除源句柄；
- 源句柄移除意外失败时删除新槽位，保留原句柄和原授权；
- 成功路径仍在同一对象表锁内执行，继续保证旧句柄永久失效且权威代际不分裂；
- 删除提交路径中的 `expect`，失败一律以结构化 Handle 错误返回。

## 验证

```text
cargo test -p kernel-core \
  transfer_to_full_destination_keeps_source_and_destination_unchanged
1 passed; 0 failed

cargo test -p kernel-core
1015 passed; 0 failed

cargo check -p jasper-kernel --target x86_64-unknown-none
PASS
```

新增测试证明目标表满时源句柄、源授权和目标原内容均不变，拒绝发生在任何所有权
变化之前。该结果不替代跨进程并发、物理硬件或完整兼容矩阵验收。
