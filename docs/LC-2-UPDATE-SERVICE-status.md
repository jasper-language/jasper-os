# LC-2 Update Service Lifecycle

更新日期：2026-11-17。

状态：**core service implemented; LC-2 remains core-passed**。`UpdateService` 已成为
一个持有单一 `UpdateCoordinator` 和 `FileControlStore` 的有状态服务门面；
Issue #39 的全系统统一授权、完整并发/断电故障矩阵和 Pixel 验收仍未完成。

## 声明 Profile 的完整软件矩阵

2026-11-18 已在同一公开源码上重新执行 QEMU/OVMF + P0 virtio-blk 的完整软件出口：

- 三次候选试启动断电均恢复到 A；
- Confirmed 控制记录损坏后从 generation 3 恢复并重新确认到 generation 5；
- 最新控制副本损坏后回退到完整旧副本，恢复 generation 2 并确认 B；
- 真实终端 recovery、archive/audit、update list 和 4 个隔离 update Agent
  并发执行均通过；
- 同一 P0 首启 `initialized=true`，次启 `initialized=false`，package、
  installation、grant、runtime 和 update-list 状态跨重启保持。

汇总证据见 `evidence/lc2-exit-matrix-20261118/README.md`。该矩阵关闭软件
Profile 的事务和故障出口，不关闭 Pixel 物理安装门。

## 统一应用升级与数据作用域

原生安装模型现在增加应用版本切换事务，而不要求普通应用使用系统 A/B：

- 同一稳定 `InstallationKey` 只接受相同 AppID 和 publisher 的更高
  `PackageSpec.version`；同名不同 publisher 与同版本/降级均失败且不产生部分变更；
- 更新前已启动的 `RuntimeSnapshot` 冻结原包身份，运行中的旧会话不会被静默切换到
  新代码；后续启动读取安装当前版本；
- 应用数据记录持久化安装谱系，仅迁移目标安装作用域的数据。同一共享包被其他用户、
  组或租户安装时，其数据保持原版本作用域；
- 卸载代码仍不删除独立数据；旧安装谱系可以失效，但数据包身份仍阻止底层包字节被
  提前回收；
- 安装快照格式升级为 v3，v1/v2 快照可读取；旧快照中无法证明安装谱系的数据会在
  升级时返回 `system.install.error.data_scope`，不做猜测迁移。

真实 OVMF/virtio-blk 三轮演练在首轮创建 v1/v2 两个包、两个用户安装、运行会话、
授权和数据，升级用户 7 后重启两次。三轮都保持用户 7 当前包为 v2、已运行会话仍为
v1、用户 7 数据为 v2、用户 8 安装及数据仍为 v1，且九个持久化写/flush 中断点仍
保持完整旧状态或完整新状态。QEMU 退出码均为 33，资源均回到基线。证据见
`evidence/lc2-app-upgrade-20261118/`。

默认生产栈又使用同一制品完成两次 OVMF/virtio-blk 启动，未启用 fault-injection
专项目标；首启升级后，次启仍恢复相同版本/会话/数据作用域，QEMU 退出码均为 33。
证据见 `evidence/lc2-app-upgrade-default-20261118/`。

更新源现在支持清单绑定的持久下载 spool：目录/HTTPS 工件可从已落盘偏移续传，
镜像按声明顺序切换，只有签名和完整清单摘要一致的镜像才能参与工件获取。传输
断开、坏签名、坏工件摘要、跨清单 spool 复用和 Range 状态不一致均失败关闭。
详见 `docs/LC-2-RESUME-SOURCE-HA-status.md`。

该切片没有新增用户 ABI，也未完成 Issue #38 的企业策略、自动批量依赖安装/降级、
可逆 Schema 迁移、受权轮换 CLI/服务审计和真实整机闭环。

## 发布者密钥代际

安装状态现在为每个稳定安装保存 publisher signing key 与单调 key generation。
协作轮换必须由旧、新 key 对同一代际绑定消息签名；丢钥恢复要求安装所有者与本地
更新主体同时匹配，并证明持有新 key。轮换后旧 key 签发的更新失败，活动 runtime
保持启动时包身份。快照格式升级到 v4 并保留 v1-v3 读取兼容。

详见 `docs/LC-2-PUBLISHER-ROTATION-status.md`。内核提供 Ed25519 验证适配器，但
尚未接入受权 CLI/服务调用与审计，也没有物理设备断电矩阵，因此不改变 LC-2 的
core-passed 状态。

Pixel 6a 的只读 LUN/GPT 审计没有发现 Jasper 专用持久范围。现有 AOSP/Linux
UFS 后端为 GPL-2.0 系列并依赖 Linux 内核 API，upstream U-Boot 也缺少
GS101/Tensor UFS platform driver。因此 Pixel 安装、更新、回滚和断电矩阵必须
等待隔离的公开 Driver Host/Driver VM 或等价稳定 UFS UAPI；不得挪用
`userdata`、`super`、`metadata`，也不得用 RAM P0 或私有驱动代替。

## 当前 QEMU 与 Pixel 6a 边界

公开 `main` `235fc8a` 的四个独立 `user-updateagentd` 进程在真实
OVMF/virtio-blk 启动中经过显式 readiness barrier，再同时执行六轮 status 和
一次 list；所有请求成功，首程序退出 0 且资源回收。证据见
`evidence/issue21-uefi-boot-20261117-233206/README.md`。这关闭的是有界并发
起点、请求 ID 隔离和超时后继续服务，不是完整压力或断电矩阵。

同一公开内核也通过 Pixel 6a 实物 `fastboot boot` 完成当前 runtime plan 的
8 CPU/Ring 3/syscall/user-pointer 路径并走 PSCI reset，随后未改 slot 恢复
Android；证据见 `evidence/pixel6a-runtime-20261117-233437/README.md`。该探针
不包含 Jasper UFS provisioning、原生安装服务、更新事务、回滚或断电恢复，
因此不能作为 LC-2 的 Pixel 安装验收。

## 统一授权投影

status、recover、archive 和 audit 已接入 `kernel-core::authz` 的同一决策记录：

- issuer 必须精确等于内核 PEP，不接受任意非零 issuer；
- 主体必须是 active 的 Process/Task/Service，且使用
  `SecurityContext::require_active()` 验证，不把合法首代 generation 0 误判为无效；
- tenant、MAC domain、platform scope、SyscallSet capability 与 policy epoch 在
  执行前重新取证；
- status/audit 固定为 Read，recover/archive 固定为 Write，错配直接拒绝；
- 未集成全局撤销源时显式保持 `revocation=None`，不用对象 generation 冒充；
- 决策完整记录 subject、executor generation、tenant、domain、operation、scope、
  effect、policy 和拒绝原因，作为后续可靠审计输入。

真实 OVMF/virtio-blk 四进程并发验收中，status/recover/archive 的授权决策均为
`decision=true reason=allowed`，首程序退出 0 且资源回收。证据见
`evidence/issue21-uefi-boot-20261118-001049/README.md`。

该切片只关闭 LC-2 消费者接入一致性，不代表 Issue #39 全系统策略、委托、撤销
传播和所有资源域 PEP 已完成。

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
  再清理 staging；如果归档已发布而清理中断，可用同一 archive root 幂等续作；
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

安装服务同时提供有界的 `visible_updates` 集合查询。它从持久安装记录生成当前
authenticated subject 可更新的组件集合，只依据每条安装的显式 update authority，
不使用 DISCOVER 权限冒充更新权，也不把系统主体当作跨租户超级用户。输出容量在
写任何记录前检查；容量不足失败且不留下部分结果。租户 scope、更新主体与安装数据
scope 仍保持独立。

ABI 3.20 将该集合暴露为 `system.install.update.list`（ID 114）。请求只携带
request ID；主体、租户与可见范围全部由内核认证信息派生。响应使用固定
header + 96 字节记录，包含安装、包、AppID、publisher、version、content、scope、
source 和 enabled，不包含路径或调用者可选择的身份。容量不足和保留身份字节被篡改
均在写用户缓冲前失败关闭。

原生 JUCS/CLI 现在提供 `system update list [--help|--schema|--json]`。
`kernel-core::update_list_agent` 对 ABI 3.20 响应执行 request、record count、
record width、尾随字节和短输出校验；人类输出与 JSON 消费同一个
`UpdateListClient`，JSON 的稳定 Schema 为 `service.update.list/1`。外部
`user-updateagentd` 的 v2 Channel 协议已支持有界 list operation，并在独立子进程
中复用同一 `UpdateListClient`。该传输只桥接固定协议，不注入 tenant、subject、
scope 或路径；真机/UEFI 证据见
`evidence/issue21-uefi-boot-20261117-214003/README.md`。

### 生产持久后端

原生安装/list ABI 已从验证 RAM 盘切换到真实 P0 virtio-blk 保留区：

- store 固定在 Control A 分区内 `P0_INSTALL_STORE_LBA` 起 16 MiB 区域，不覆盖
  control record、archive receipt、ESP、System A/B 或 Data；
- `PersistentInstallStore::mount` 只对完整零区首启格式化；存在非零数据但无有效
  store header、损坏快照或 I/O 错误均失败关闭，不覆盖未知数据；
- 安装服务复用 lifecycle 已验证的同一 P0 BlockDevice，不创建第二份设备授权；
- BlockDevice 创建时缓存 DMA 物理页，热路径不再重新查询对象表，避免
  `NATIVE_INSTALL -> OBJECT_TABLE` 反向锁序；
- 同一 P0 镜像第一次 UEFI 启动记录 `initialized=true`；第二次复用相同
  Control/OVMF/Data 状态启动记录 `initialized=false`，并再次通过
  package、register、grant、query、update list 和资源回收。

受信救援环境可以携带底层路径运行独立的 `jasper-update-recovery` 维护工具：

```text
jasper-update-recovery status <control-root>
jasper-update-recovery recover <control-root> <staging-root> <manifest-sha256-hex>
jasper-update-recovery cleanup <control-root> <staging-root> <manifest-sha256-hex> <archive-root>
```

`status` 只恢复并报告双副本控制记录；`recover` 根据 journal 与 control 修复
一个已存在的更新事务；`cleanup` 只对恢复后的 Complete/RolledBack 事务执行
归档与清理。该入口不能创建新事务、不能跳过签名，也没有注入任意 manifest 或
执行路径的参数。

按照 Issue #34，**该工具不是 Jasper 原生 Shell 的正常用户命令**。正式原生入口
必须是无前缀的 `system update status`，通过 JUCS 命令发现、Schema、调用者身份
与版本化更新服务执行；普通生产用户不能通过直接提供 control/staging/archive
路径获得恢复特权。

当前源码已交付只读状态链的第一片：

- 原生 CLI 解析规范化 `system update status`，同时提供 `--help` 与 `--schema`；
- JUCS 命令身份为 `system.update.status` v1，不把命令名当 syscall；
- 内核机制 `system.update.control.get` 只接收输出缓冲与容量，不接受路径；
- 原生 CLI 已通过版本化 `system.update.status.query` 调用
  `service.update.status` v1：请求含稳定请求 ID、可选 expected generation 和
  平台范围，但租户只能由内核认证身份/Workload Domain 派生；
- 原生 CLI 的 `--json` 与人类可读输出使用同一次
  `system.update.status.query` 响应，不复制服务执行器；JSON 固定包含 generation、
  transaction、A/B 状态、release/attempts/digest、schema、caller/domain/tenant 与
  request identity；
- 已建立路径-free 的 recovery/archive action 契约：请求只携带 request ID、
  expected generation、transaction ID、manifest digest、动作与 platform scope；
  响应固定回传内核盖章的 caller/tenant/domain、最终 service generation、
  transaction、digest、recovery-required 和 archived 事实。动作权限、事务绑定、
  digest 与旧 generation 均在执行前失败关闭；
- `UpdateService` 已增加 `TransactionBinding` 与 managed execution：调用者使用
  generation、transaction ID、manifest digest 绑定当前事务；`recover_bound`
  使用服务内部 staging root，`archive_bound` 使用运维启动时配置的 archive root，
  普通 action 调用不再提交内部路径；
- ABI 3.18 新增 `system.update.action.recover`。内核只接受固定
  `TransactionActionRequest`，从当前双副本控制记录派生 transaction 与候选/活动
  manifest digest，强制 request、generation、transaction、digest、platform scope
  绑定后，重写两份控制副本、flush 并读回；调用者不能提供 control、staging 或
  archive 路径；
- JUCS 新增 `system update recover [--help|--schema|--json]`，与 status 共用 kernel
  authenticated caller/tenant/domain 与 request ledger；JSON 结果是
  `service.update.action/1`，不含路径；
- `kernel-core::update_client` 成为 CLI 与后续结构化 Agent 共用的业务客户端：
  transport 仅负责 syscall/消息传递，request 构造、status-to-action digest 派生、
  response request 校验和 transaction/generation/digest 绑定校验只实现一次；
  一次 recover 显式消费独立 status/action 请求 ID，符合进程级账本“ID 跨服务不得
  复用”的规则；
- 共用客户端拒绝零请求 ID，并要求 status 响应内的 caller domain 与认证域一致；
  recover 响应必须与同一 exchange 的 status 保持 tenant、domain 和 scope 一致，
  防止结构化 Agent transport 将不同主体的响应与事务拼接成一次成功调用；
- `kernel-core::update_agent` 提供有界的 `UpdateAgent` 结构化前端。它直接包装
  `UpdateClient`，由共享客户端完成认证结果校验和事务绑定；Agent 与 CLI JSON
  模式共同调用同一个固定缓冲区序列化器，输出 `service.update.status/1` 与
  `service.update.action/1`，不能再各自维护一份 JSON 协议；
- status 解码器现在拒绝“无候选槽却保留候选 release/state/attempts/digest”的
  矛盾记录，并要求存在候选槽时 release 与 digest 均非空；该一致性门位于共享
  协议层，文本 CLI、JSON CLI 和 Agent 前端不能产生不同判断；
- `update_agent_ipc` v2 定义 112 字节固定请求和最多 3136 字节的固定容量响应
  封套：请求允许 status/recover/archive/list，去掉消息头后仍必须通过原服务请求
  解码，envelope ID 必须与服务请求 ID 一致；响应绑定同一 message ID、operation、
  payload 长度与结果形态；
- 独立 `user-updateagentd` broker 通过内核 Channel 接收请求，首次收到的
  kernel-stamped `sender_app` 会被固化；客户端同样固化首次响应的发送应用身份，
  身份为 0 或后续变化均失败关闭；
- broker 对同一 message ID、operation 和 service payload 的重试返回缓存的完全
  相同响应；重试 deadline 可以更新，但同一 ID 改换 operation 或 payload 被拒绝；
  绝对 deadline 过期由 broker 在调用服务前拒绝，之后仍可继续服务；
- 客户端 Channel recv 经 async Ring 的 deadline enter 提交。超时后同步取消请求、
  收取 cancelled completion，并关闭与完成竞态到达的句柄；迟到响应若不属于当前
  message ID/operation 会被丢弃，不会返回给后续请求，也不产生陈旧成功；
- 服务先验证当前调用者身份/系统域，再读取并恢复同一组双副本 A/B 控制记录；
- 返回 `service.update.status` v1 请求头与固定状态载荷，包含 generation、transaction、槽状态、
  release、回滚下限、安全纪元、Schema 范围以及调用者身份；
- 返回记录不包含 control/staging/archive 路径或任意可执行对象。

身份缺失、租户范围注入、旧 generation、请求 ID 冲突和协议损坏均有独立错误；
请求 ID 复用进程级幂等账本。真实 UEFI 验证已覆盖串口与 framebuffer/PS-2
两个原生终端前端：输入
`system update status` 后均返回同一份 A/B 控制记录，`--help`/`--schema` 也可发现；
`system update status --json` 返回可由标准 JSON 解析器读取的同一状态；
首程序查询前后资源断言为 `reclaimed=true`。

所有 update status/recover/archive/audit 入口现在先经过
`kernel-core::authz` 的统一决策投影。该投影引用现有 active
`SecurityContext`、进程 SyscallSet、租户/domain 和 MAC policy epoch，不维护
第二份权限表；身份、scope、操作/effect、能力、policy 代际、时间和委托深度
任一不满足都失败关闭。全系统撤销代际源尚未接入，因此记录明确为
`None`/`revocation_unavailable`，不会把对象 generation 冒充撤销代际，也不据此
宣称 Issue #39 已完成。

这仍不是 Issue #34 的整体完成：tenant A/B 可见性和 4 个隔离 Agent 进程的
并发 status/list 请求已经通过，但更大规模并发、完整重放/断电矩阵和 Pixel
安装矩阵尚未交付。因此 LC-2 继续保持 `core-passed`。

recovery 已具备 path-free 数据/授权契约、`UpdateService` managed execution、
ABI syscall 和原生 Shell 消费。archive 已具备内核持久收据和正式 ABI；
调用者不能选择终态、事务或归档路径。

## 独占控制租约与重启恢复矩阵

`FileControlStore` 现在对每个 control root 持有进程生命周期内的独占 POSIX
record lock，并用进程内 canonical-path 登记保持同一进程内的互斥。同一 root
的第二个存活服务在读取 generation 前即以 `Busy` 失败；进程退出或崩溃后由内核
自动释放租约，因此不会留下永久锁，也不能让两个服务同时基于同一旧 generation
提交不同结果。

此前 `flock` 绑定 open-file-description；并发测试或其他调用者执行
`fork` 后、子进程尚未 `exec` 时会短暂继承描述符，导致已经 drop 的服务仍让下一
次 `open` 误报 `Busy`。POSIX record lock 与进程关联，不会被 fork 子进程继承，
同时保留跨进程崩溃释放语义。完整 lifecycle-staging 41 项测试连续运行 5 轮均
通过。

恢复路径同时修正了三个持久状态问题：

- `Prepared` 新事务尚未写 boot control 时，control 中可能仍是上一笔 Completed
  或 RolledBack transaction 的 terminal。恢复器现在只在 terminal digest 与当前
  manifest 精确匹配时采用它，不会把旧 terminal 拼接到新事务。
- `RolledBack` terminal 的状态重建必须先经过 `FailHealth → Rollback →
  FinishRollback`；旧实现从 `Trial` 选择了健康路径并在 `Complete` 后失败。
- 同一稳定 staging root 与 manifest digest 的恢复响应用于客户端超时重试时是
  幂等的：已恢复服务返回同一 generation 与状态，不再产生第二次恢复事务；不同
  target 仍失败关闭。

新增确定性重启矩阵覆盖：

- `Prepared`、`Committed`、`Trial`、`Confirmed`、`Complete`、`Rollback` 和
  `RolledBack` 七类状态下，control 已越过 durable boundary、journal 仍停留前
  一阶段的窗口；
- `Committed` 到 `RolledBack` 六类 journal 双副本替换中断窗，即一份旧、一份新；
- 每个窗口首次恢复后的同 target 重放结果逐字段一致，错误 digest 失败关闭。

验证结果：

```text
cargo test -p jasper-lifecycle-staging --lib \
  -- --skip formats_system_and_data_ext4_without_overwriting_existing_filesystems \
     --skip installs_bootloader_fat_tree_into_empty_esp
38 passed; 0 failed; 2 filtered out

cargo test -p kernel-core update
38 passed; 0 failed

cargo clippy -p jasper-lifecycle-staging --lib -- -D warnings
PASS
```

被过滤的两项依赖宿主 `mkfs` / `fsck` 工具，不是本切片代码失败；完整 CI/VM
仍须执行。该矩阵是宿主文件系统与真实 `UpdateService` 的确定性故障注入，不替代
OVMF/virtio-blk 断电实验或 Pixel UFS 安装矩阵，因此 LC-2 仍保持
`core-passed`。

## 终态归档收据与持久后端

新增 `jasper_lifecycle_model::archive` 的 128 字节固定归档收据：

- 只接受 `Complete` 或 `RolledBack`，绑定非零 transaction、清单 SHA-256、
  单调 archive sequence 和前一份收据的完整 SHA-256；
- 使用固定双副本 `write_copy -> flush -> read_copy`；
- 单副本撕裂可恢复，同 sequence 冲突失败且不写，跳号、错误前序和读写失败关闭；
- `lifecycle-staging::archive_store::FileArchiveStore` 提供真实文件后端；提交发生在
  staging 清理之前，同一终态交易重试幂等；
- `UpdateService::configure_archive_ledger` 只接受运维启动时配置的目录，
  action caller 仍不能提交任意路径；
- `kernel::lifecycle_health` 增加了 P0 Control A/B 分区内固定归档页的块设备适配器，
  可读写、修复并提交同一收据协议。

该阻塞已关闭：

- 控制记录使用原有保留字节持久化 `None/Complete/RolledBack` 终态，并以唯一
  transaction participant 槽绑定真实 manifest digest；新候选会原子清除上一终态；
- `UpdateCoordinator::finalize_confirmed` 与 `finish_rollback` 先提交权威控制
  终态，再推进 journal；崩溃后 `recover_with_control` 可从终态恢复 Complete 或
  RolledBack，不能由调用者自行声明；
- ABI 3.19 新增 `system.update.action.archive` ID 113 与
  `system update archive [--help|--schema|--json]`。请求只含 request/generation/
  transaction/digest，内核从控制记录派生终态和固定归档页；
- 同时修复块层请求页数泄漏：BlockDevice 虽按容量申请多页 DMA，但现在每个请求
  只向设备发布 `request.pages` 个描述符。此前单页控制写入会额外覆盖后续四页，
  正是 Archive B 固定页出现伪数据的原因。

真实 UEFI terminal-recovery 已在 OVMF/virtio-blk 上通过 human、JSON、schema、
help 四条 archive 路径，receipt 写入/读回成功，重复 action 幂等，CLI 资源回收。
完整并发/重放矩阵和 Pixel 安装断电矩阵仍未完成。

## 跨重启归档审计查询

ABI 3.21 新增 `system.update.audit.query`（ID 115）和原生
`system.update.audit [--help|--schema|--json]`：

- 请求只包含 request ID 和可选 expected archive sequence，不携带 tenant、
  subject、路径或块设备选择；
- 内核从 authenticated principal 派生 tenant/domain，并通过既有
  `read_archive_receipt` 读取恢复、校验后的最高有效归档收据；
- 响应固定包含 available、archive sequence、transaction、manifest digest、
  previous digest 和 terminal stage；
- 无归档是显式 `available=false`；损坏或同代冲突副本失败关闭，不会伪装成空历史；
- native CLI、JSON 与共享 `UpdateAuditClient` 使用同一响应验证。

同一 P0/OVMF 状态连续启动两次；第二次没有重新生成 GPT、文件系统或 control，
仍查询到同一归档：

```text
available=true sequence=1 transaction=1 terminal=complete
digest=68d00296644483d365ecb17f4163588c5f1b27944a56f26f73556507a9c2bd3a
```

## 验证

```text
cargo test --locked -p jasper-lifecycle-staging
31 passed; 0 failed

cargo test --locked -p kernel-core jucs::tests
2 passed; 0 failed

cargo test --locked -p kernel-core update_service::tests
6 passed; 0 failed

cargo test --locked -p kernel-core update_client::tests
5 passed; 0 failed

cargo test --locked -p kernel-core update_agent::tests
4 passed; 0 failed

cargo test --locked -p kernel-core update_audit::tests
3 passed; 0 failed

cargo test --locked -p kernel-core update_agent_ipc::tests
6 passed; 0 failed

cargo test --locked -p kernel-core update_list_agent::tests
2 passed; 0 failed

cargo test --locked -p kernel-core native_install_service::tests
3 passed; 0 failed

cargo test --locked -p kernel-core persistent_install::tests
7 passed; 0 failed

cargo check --locked -p user-updateagentd --target x86_64-unknown-none
PASS

cargo check --locked -p user-agentprobe --target x86_64-unknown-none
PASS

cargo check --locked -p user-cli
passed

cargo test --locked -p jasper-lifecycle-model archive::tests
6 passed; 0 failed

cargo test --locked -p jasper-lifecycle-staging
36 passed; 0 failed

cargo test --locked -p jasper-lifecycle-boot
22 passed; 0 failed

cargo check --locked -p jasper-kernel --target x86_64-unknown-none \
  --no-default-features --features production,lifecycle-ab-health
passed

bash scripts/issue21-uefi-boot-check.sh
PASS mode=terminal-recovery qemu_rc=124

ISSUE21_UEFI_MODE=update-agent bash scripts/issue21-uefi-boot-check.sh
PASS mode=update-agent qemu_rc=33

ISSUE21_UEFI_MODE=update-list bash scripts/issue21-uefi-boot-check.sh
PASS mode=update-list qemu_rc=33

ISSUE21_UEFI_MODE=native-install-abi \
ISSUE21_NATIVE_INSTALL_EXPECT=initialized \
ISSUE21_KEEP_DERIVED=1 bash scripts/issue21-uefi-boot-check.sh
PASS mode=native-install-abi initialized=true qemu_rc=33

ISSUE21_UEFI_MODE=native-install-abi \
ISSUE21_UEFI_PREBUILT=1 \
ISSUE21_REUSE_P0=1 \
ISSUE21_NATIVE_INSTALL_EXPECT=reopened \
bash scripts/issue21-uefi-boot-check.sh
PASS mode=native-install-abi initialized=false qemu_rc=33

bash scripts/abi-contract.sh check
PASS (3.21.0)
```

新增测试覆盖：

- 双副本回填：高低有效世代、单副本损坏、同世代冲突、write/flush/readback
  失败均原子失败或完成，冲突路径不产生写；
- recovery 与健康确认共用一个内核 mutation guard；并发 mutation 明确返回 busy，
  不会让较旧 recovery 覆盖另一条新提交；
- generation 过期拒绝；
- prepare→commit→trial→healthy→finalize→archive 完整成功路径；
- 错误阶段不能跳过健康确认或直接 finalize；
- unhealthy trial 是唯一进入 rollback 的路径；
- 模拟 control 已提交、journal 落后的崩溃后，recovery 修复到 Committed；
- recovery 后的新 generation 使旧命令失效；
- 在线/离线来源通过同一 service 信任和暂存路径；
- terminal staging 必须先归档再清理；
- 归档已发布但清理中断时，同一 archive root 可以幂等续作。
- 零请求 ID、status 内部认证域不一致，以及 status/action 跨租户、域或作用域
  拼接均在提交恢复动作前失败关闭。
- Agent 固定缓冲区过小时不发布半截 JSON；无候选槽的残留候选事实在解码阶段被拒绝。
- 归档收据逐字节篡改、非终态、跳号、错误前序、单副本撕裂、同代冲突以及
  write/flush/readback 失败均失败关闭；真实文件后端重开和幂等提交通过。
- 控制终态与 transaction participant 绑定正反例、Complete/RolledBack 崩溃恢复，
  以及 ABI 3.19 的 archive human/JSON/schema/help 均通过。
- 外部 Agent 固定封套逐字节篡改、operation/ID 错配、错误 code/payload 形态被拒；
  独立子进程的 status/recover/archive/list、同 ID 同 operation 但 payload 变化的
  缓存冲突、重复请求缓存、sender identity 固化、async deadline timeout、
  `system.async.cancel` 成功、completion 排空和 timeout 后继续服务均通过真实
  UEFI/virtio-blk。
- 4 个独立 broker 进程并行执行 6 轮 status 和一次 list，进程隔离、协议身份、
  request ID 及资源回收全部通过真实 UEFI/virtio-blk；这是并发起点而不是完整
  压力矩阵。
- tenant A/B 的可见更新集合互不串租户；系统主体不隐式获得租户更新权；输出缓冲
  过小时整体返回容量错误且不写入部分 record。
- ABI 3.20 的 `system.install.update.list` 在真实 OVMF guest 中返回当前主体的
  update record；short buffer 与伪造保留身份字节均被拒绝，首程序资源回基线。
- `system update list` 的 human/JSON/schema/help 在真实 OVMF guest 中通过，CLI
  的机器结果绑定 ABI request ID，首程序退出 0 且资源回收。
- archive-audit request/response 的零 ID、错误 scope、空/可用记录与路径泄漏负例；
- 第二次真实 OVMF 启动仍返回相同 archive sequence、transaction、digest 和
  terminal stage。

## 仍未完成

- 生产密钥托管、远端审计留存和签名仪式；2-of-3 门限核心验证与持久撤销快照
  已由 LC-5 切片提供，但尚未接入生产发布环境；
- 断点续传和生产发布源高可用；
- 系统级在线/离线发布演练和 Pixel 6a 安装/回滚/断电矩阵。

因此本切片不能把 `LC-2-COMPONENT-UPDATE` 升为 done。
