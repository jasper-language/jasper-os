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
- recovery 使用正式无前缀 `system update recover`，不接受救援工具式路径参数；
  archive 在获得可写 terminal staging/journal 后端前不注册伪命令。

## 分阶段交付

1. 建立 JUCS 命令身份、Schema、类型和 `system update status` 只读路由；
2. 将原生 TerminalSession 接入统一命令发现与调用，不允许 Shell 私自分派；
3. 建立版本化 update 服务调用、调用者身份/授权/租户过滤和审计关联；
4. 将 recovery/archive 作为有最小能力、事务绑定和幂等键的受控服务操作；
5. 在真实 Jasper 原生 Shell 中验证无前缀 `system update status`，并验证 GUI、
   CLI、结构化 Agent 调用结果一致；
6. 完成错误参数、越权、跨租户、旧 generation、错误摘要、并发冲突和断电恢复
   负例；救援工具继续只存在于可信恢复边界。

## 当前实现切片

- JUCS 层已建立无分配的 `system.update.status` v1 命令身份、精确三段式解析、
  拒绝 `jucs`/`jasper` 工具前缀、未知参数失败关闭，并提供 `--help`/`--schema`；
- 原生 CLI 通过该 JUCS 路由调用版本化 `system.update.status.query`，不复制
  更新执行器；旧 `system.update.control.get` 保留为兼容只读机制；
- `system update status --json` 与人类可读形式消费同一个版本化响应；结构化结果
  固定携带 `service.update.status/1`、调用者盖章字段、A/B slot、release、
  attempts、digest 与 request identity，供脚本和后续 Agent 共用；
- `system.update.status.query` v1 增加版本化 `service.update.status` 请求/响应：
  请求携带非零请求 ID、可选 expected generation 和唯一平台范围；租户由内核
  安全身份与 Workload Domain 派生，请求不能指定其他租户或内部路径；
- 请求 ID 复用进程级幂等账本；身份缺失、未知租户范围、旧 generation、请求
  ID 冲突和协议损坏各有稳定结构化错误；
- `service.update.status` v1 返回固定请求头加状态载荷，调用者身份、租户和域
  均由内核盖章；control/staging/archive 路径不进入 ABI；
- LC-2 已登记 `service.update.action` v1：recover/archive 请求只含稳定
  request ID、可选 expected generation、transaction ID、manifest SHA-256、动作和
  platform scope；路径-free 响应绑定调用者 tenant/domain 与最终事务状态；
- ABI 3.18.0 注册 `system.update.action.recover`，JUCS/原生 CLI 增加
  `system update recover`；内核从控制记录派生稳定绑定，修复两份控制副本并
  flush/readback，调用者不能提供 control/staging/archive 路径；
- `kernel-core::update_client` 把 request 构造、status-to-action 绑定和响应校验
  固定为 CLI 与后续结构化 Agent 共用的唯一业务客户端，transport 只能传递协议；
- 查询先验证当前进程的活动安全身份，再读取并恢复同一双副本 A/B 控制记录；
- ABI 3.18.0 快照和系统接口冻结已更新。
- 真实 UEFI 串口和 framebuffer/PS-2 原生终端均输入了无前缀
  `system update status`，返回同一结构状态；首程序帧与堆资源断言保持
  `reclaimed=true`。
- 真实 UEFI 串口验收同时执行 `system update status --json`，以标准 JSON 解析器
  校验结构化字段，且查询仍走同一 JUCS 命令与 `system.update.status.query`。

当前已增加独立 Agent 进程与 CLI JSON 共用 `UpdateAgent`/`UpdateClient`：
固定 status/recover/archive 封套在真实 UEFI/virtio-blk 中通过，包含 sender
identity 固化、重复请求缓存和 deadline 拒绝。ABI 3.19 的正式
`system update archive` 与 `system update recover` 均已有真实 UEFI 证据。
仍需完成：租户过滤；完整权限、重放、旧 generation、错误摘要和并发冲突矩阵；
真实断电与 Pixel 安装/回滚闭环。在这些退出门完成前，Issue #34 和 LC-2 都不能
标记 done。
