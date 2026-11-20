# Issue #15：私有 `verify/*` PR 的真实 CI 门

更新时间：2026-11-20。

## 复现的缺口

GitHub 的 `pull_request` 事件把 `github.ref` 设为
`refs/pull/<number>/merge`，而不是源分支的
`refs/heads/verify/<name>`。此前 `host` 与 `accept` 两个作业都只检查
`github.ref`，因此私有仓库的 `verify/*` PR 可以创建运行记录，但两个真实作业
仍被条件跳过，形成空成功。

## 修复

两个作业使用同一门禁：

```text
公开仓库
  OR (pull_request AND github.head_ref startsWith "verify/")
  OR github.ref startsWith "refs/heads/verify/"
```

- `pull_request` 使用源分支 `github.head_ref`；
- `verify/*` 的 push 继续使用 `github.ref`；
- 公开仓库的每次 push/PR 行为不变；
- 只修复作业是否实际启动，不修改 `scripts/accept.sh` 或任何验收判据。

`scripts/check-ci-private-pr-gate.py` 对 workflow 文本和自身负例做机器检查。
它证明两个作业都同时保留 PR 与 push 条件，但不能替代真实 GitHub PR 事件；
关闭 Issue #15 前仍须在修复后的 `main` 上创建一次 `verify/*` PR，并确认
`host`、`accept` 都实际创建和运行。

## 验收顺序

1. 本地运行 checker 的 self-test 与正式检查；
2. 在公开 `main` 的完整 CI 成功后推送本切片；
3. 从私有仓库 `verify/issue-15-gate` 建立 PR；
4. 确认 PR run 创建了 `host` 和 `accept` 两项且不是 skipped；
5. 只有真实 PR 运行达到可解释终态后才关闭 Issue #15。
