# ABI 契约快照

每个 `<Major.Minor.Patch>.contract` 文件是该 ABI 版本不可变的发布契约。文件由当前登记表与 `kernel-core::abi_contract` 中的权威布局/操作声明生成，禁止手改。

常用命令：

```bash
bash scripts/abi-release.sh 1.1.0   # 提升唯一版本真源并创建新快照
bash scripts/abi-contract.sh check  # 校验当前源码与全部快照
bash scripts/abi-freeze.sh          # 冻结名字/ID，再次校验完整契约
```

规则：

* 同主版本新增 Minor：旧快照的每一行必须原样保留，只能增加新条目。
* 同主同次新增 Patch：除 `abi=` 版本头外，契约正文必须完全相等。
* 新 Major：允许创建全新的快照，不要求继承旧主版本。
* 已提交快照不得修改、删除或重命名；CI 用 base...HEAD 差异检查历史不可变性。
* `xtask abi-contract generate` 不会覆盖一个内容不同的既有文件；契约变化必须先提升 ABI 版本。

当前快照的覆盖范围、发布流程与明确边界见 `docs/issue-8-进度.md`。
