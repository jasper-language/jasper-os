# Issue #34: JUCS Native Command Constraint

更新日期：2026-11-17。

状态：**active architecture constraint**。这不是已完成功能声明，也不自动修改统一
DAG；相关实现归入现有 LC-2、ISSUE-21 与 TERM-1 的后续验收。

## 固定规则

- Jasper 原生 Shell 的资源命令使用 `<领域> <资源> <动作> [--参数 值]`；
  `system update status` 是无工具前缀的已确认目标形式。
- JUCS 统一命令 ID、Schema、类型检查、帮助、发现、授权、审计、结构化结果和错误。
  Shell、GUI、脚本与 Agent 必须调用同一业务契约，不得各自实现执行器。
- 命令显示形式、JUCS 命令 ID、版本化服务 API 和内核 `system.*` ABI 是不同层。
  新增 `system update status` 不表示新增同名 syscall。
- Linux 命令、POSIX Shell 和传统服务工具只属于可选 Linux 兼容环境，不进入 Jasper
  原生默认命令集。

## 当前边界

- `jasper-update-recovery` 只是受信救援环境中的维护工具，允许显式携带受保护的
  control/journal/staging 路径；它不是正常原生命令，也不是正式的
  `system update status` 实现。
- 普通生产用户不得通过直接执行独立工具和构造路径获得更新恢复、归档或清理权限。
- 正式状态查询必须按调用者身份过滤，并以资源句柄或服务绑定的稳定事务身份定位
  更新，不接受调用者直接注入内部路径。
- `system update status`、受控 recovery 与 archive 动作必须复用现有
  `UpdateService`/`UpdateCoordinator` generation、journal/control 一致性、回滚和
  幂等语义。
- recovery 的最终资源/动词组合仍须经过 JUCS 官方动词裁决；不能用当前维护工具
  的 argv 形式替代正式命令合同。

## 分阶段交付

1. 建立 JUCS 命令身份、Schema、类型和 `system update status` 只读路由；
2. 将原生 TerminalSession 接入统一命令发现与调用，不允许 Shell 私自分派；
3. 建立版本化 update 服务调用、调用者身份/授权/租户过滤和审计关联；
4. 将 recovery/archive 作为有最小能力、事务绑定和幂等键的受控服务操作；
5. 在真实 Jasper 原生 Shell 中验证无前缀 `system update status`，并验证 GUI、
   CLI、结构化 Agent 调用结果一致；
6. 完成错误参数、越权、跨租户、旧 generation、错误摘要、并发冲突和断电恢复
   负例；救援工具继续只存在于可信恢复边界。

在步骤 1–6 完成前，LC-2 的正式 JUCS/Shell 命令入口必须保持未交付状态。
