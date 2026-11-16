# LC-2 Update Service Lifecycle

更新日期：2026-11-17。

状态：**core service implemented; LC-2 remains core-passed**。`UpdateService` 已成为
一个持有单一 `UpdateCoordinator` 和 `FileControlStore` 的有状态服务门面；
正式系统授权、租户作用域、跨重启审计查询和 Pixel 验收仍未完成。

## 服务状态机

服务对外提供以下有界操作：

- `prepare` / `prepare_from_source`：继续要求 `LocalInstallGrant`，并走原有签名、
  信任、撤销、反回滚、依赖、容量、事实源和暂存路径；
- `commit`：只接受 `Prepared` 阶段和当前 service generation；
- `begin_trial`：只接受 `Committed`；
- `report_health`：只接受 `Trial`，健康或失败进入唯一后续状态；
- `finalize_confirmed`：只接受 `Confirmed`；
- `finish_rollback`：只接受 `Rollback`，确认原 known-good 槽；
- `cancel_prepared`：只在 durable commit 前允许；
- `recover`：同时读取交易 journal 与双副本 boot control，修复崩溃窗口；
- `archive_and_cleanup`：只接受 `Complete`/`RolledBack`，先完成逐字节归档，
  再清理 staging；
- `status`：返回 service generation、coordinator 阶段、manifest digest、
  staging root、活动槽、候选槽、control transaction id 和
  `recovery_required`。

每次 prepare/recovery 都发布一个新的单调 generation。所有后续变更新命令必须
携带该 generation；旧 generation、阶段错位、重复活动事务和不存在的活动事务
均失败关闭，且不改变原有 coordinator 或控制记录。

如果 commit、trial、健康、finalize 或 rollback 在 control/journal 边界附近失败，
服务把当前事务标记为 `recovery_required`。此时普通命令继续拒绝；只有使用同一
staging root 和 manifest digest 的 recovery 能重建权威阶段，错配目标明确拒绝。

`UpdateService` 没有 URL、账号、Profile、逻辑目录或本地路径授权能力。在线/离线
来源仍只是传输方式，设备上的签名信任和 `LocalInstallGrant` 仍是准入事实源。

运维入口 `jasper-update-service` 提供两个有界命令：

```text
jasper-update-service status <control-root>
jasper-update-service recover <control-root> <staging-root> <manifest-sha256-hex>
```

`status` 只恢复并报告双副本控制记录；`recover` 才允许根据 journal 与 control
修复一个已存在的更新事务。该入口不能创建新事务、不能跳过签名，也没有注入任意
manifest 或执行路径的参数。

## 验证

```text
cargo test --locked -p jasper-lifecycle-staging
28 passed; 0 failed
```

新增测试覆盖：

- generation 过期拒绝；
- prepare→commit→trial→healthy→finalize→archive 完整成功路径；
- 错误阶段不能跳过健康确认或直接 finalize；
- unhealthy trial 是唯一进入 rollback 的路径；
- 模拟 control 已提交、journal 落后的崩溃后，recovery 修复到 Committed；
- recovery 后的新 generation 使旧命令失效；
- terminal staging 必须先归档再清理。

## 仍未完成

- `service.update.*` 的正式内核/系统服务注册、调用者身份和租户作用域；
- 信任根轮换、2-of-3 门限和签名撤销快照持久化；
- 断点续传、生产发布源高可用和跨重启审计查询；
- 系统级在线/离线发布演练和 Pixel 6a 安装/回滚/断电矩阵。

因此本切片不能把 `LC-2-COMPONENT-UPDATE` 升为 done。
