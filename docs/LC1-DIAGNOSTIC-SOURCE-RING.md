# LC-1 故障源应急环策略

更新时间：2026-11-19。

状态：**`SOURCE_CAPACITY=4` 是明确的安全策略，不是待动态化的运行期容量。**

## 原因

`kernel/src/diagnostic_sources.rs` 接收 panic 与 boot-health failure 事件。该路径位于
故障处理和启动失败上下文，必须满足：

- 不进行堆分配；
- 不执行块 I/O；
- 不无限等待锁；
- 不使用可能递归进入 panic 路径的常规诊断服务。

因此采用四槽静态应急环。环满或锁已被占用时立即丢弃，并通过 `DROPPED` /
`CONTENDED` 计数报告，不伪造成功。正常 collector 随后将事件排空到持久诊断服务。

该容量不定义系统诊断总容量，也不限制持久诊断记录数量；它只限制一次故障上下文
中尚未被 collector 取走的最小应急快照数量。

## 审计

来源登记：

```text
source=diagnostic-source-panic-ring
issue=35
kind=policy
```

代码行使用结构化 `JASPER-HARDCODE-REVIEW` 注释放行；若来源未登记、issue 不匹配
或理由缺失，硬编码门仍会失败。

## 尚未完成

- 仍需在真实 panic、锁争用和 collector 不可用场景下验证 dropped/contended 计数；
- 本结论不关闭 Issue #35 的其余运行期容量项。
