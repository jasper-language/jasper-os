# JASO Wire 与 Channel 的单消息句柄边界

更新时间：2026-11-19。

状态：**每条消息 8 个句柄是 v1 冻结布局，不是系统或进程句柄总量上限。**

## 边界

- `jaso/src/wire.rs` 的 `MAX_HANDLES=8` 固化 JASO 隔离模块 Load 消息中的
  handle array 宽度；
- `user/rt/src/channel.rs` 的同名值固化 Jasper Channel v1 描述符中的单消息
  handle array 宽度；
- 两项均登记为 `spec` 来源，并由编解码器在数组宽度、描述符长度或数量不匹配时
  整体拒绝；
- 需要传递更多句柄时必须定义 v2 可变长/批量协议，不能在同一 v1 消息中静默截断
  或扩大后继续冒充兼容；
- 进程可持有句柄总量由对象表、Rights 和运行时预算决定，不由这两个单消息宽度
  决定。

## 验证

既有 JASO wire 测试覆盖第 9 个 handle 被 `TooMany` 拒绝；Channel Kotlin/Rust
runtime 构造测试覆盖描述符计数和容量检查。硬编码门通过结构化来源校验，来源缺失
或 issue 不匹配时仍会失败。

## 尚未完成

- 尚未定义 JASO/Channel v2 的变长句柄批次；
- 固定数组宽度若未来确实成为产品瓶颈，必须通过版本化 ABI 迁移解决，不能改写 v1
  语义。
