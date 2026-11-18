# Issue #35 USI Profile/Module 名称边界

更新时间：2026-11-18。

状态：**静默名称截断已修复，宿主测试通过。**

## 缺陷

USI v1 `Info.profile_name` 固定为 12 字节，`Module.name` 固定为 24 字节；Profile
解析原先只检查 kebab-case 和总长 64，因此合法通过解析的长名称会在 `info_get`
静默截断，或令整个 module list 返回无效参数。

## 修复

- Profile 解析同时检查 `usi::MAX_PROFILE_NAME`；
- 模块声明同时检查 `usi::MAX_MODULE_NAME`；
- `info_get` 不再使用 `.min()` 截断，非法长度直接返回
  `system.error.invalid_argument`；
- 内部 assembly 测试 Profile 名称缩至合法范围；
- 分类账将这些值明确归为 `protocol-abi`，不再视为运行期容量。

## 验证

```text
cargo test -p kernel-core profile -- --nocapture
27 passed; 0 failed
```

新增负例证明超过 USI 名称宽度的 Profile 和 Module 会在解析期得到
`invalid_name`。

## 后续

- 真实 USI CLI/结构化客户端仍需覆盖超长名称拒绝；
- 若未来需要更长名称，必须升级 USI wire version，不能扩展现有定宽字段。
