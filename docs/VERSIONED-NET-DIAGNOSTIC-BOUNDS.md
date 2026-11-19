# NET 与 Diagnostic v1 协议边界

更新时间：2026-11-19。

状态：**endpoint 名称 32 字节和 diagnostic 单页 8 事件是已版本化 wire 布局。**

## NET v1 endpoint 名称

`kernel-core/src/net.rs` 的 `MAX_ENDPOINT_NAME_BYTES=32` 是 NET v1 endpoint
对象名称字段宽度。超长名称在对象创建和 wire 解码阶段明确拒绝，不会截断或创建
别名。需要更长名称时必须新增版本化对象/协议，不能修改 v1 字段。

## LC-1 diagnostic v1 单页

`MAX_PAGE_EVENTS=8` 固化 candidate diagnostic USI v1 响应的一页记录数。查询请求
自身声明较小的 limit；响应编码器最多输出 8 条记录并要求调用方继续使用游标分页。
该上限不限制持久诊断事件总量，也不限制 collector 存储容量。

## 验证

```text
cargo test -p kernel-core net::tests
cargo test -p jasper-lifecycle-model diagnostic_usi
```

相关测试覆盖长度边界、截断拒绝、记录数量上限、短输出缓冲和分页游标。

## 尚未完成

- 更长 NET endpoint 名称与更大 diagnostic page 需要新协议版本；
- 两项结论都不改变网络或诊断服务的实际资源预算和持久容量。
