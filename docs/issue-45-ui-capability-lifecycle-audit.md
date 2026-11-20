# Issue #45：设备能力、交互模式与应用生命周期现状审计

更新时间：2026-11-19。

状态：**架构审计已完成，版本化契约与 Scene/Surface 迁移状态机已实现；不新增
syscall，不改变现有 ABI，不宣称 Mobile/Pad/Desktop 策略服务或真实 UI 生命周期
验收已经完成。**

## 裁决边界

Issue #45 要求把三类事实正交表达：

1. **设备能力**来自实际发现与准入，不能由设备型号字符串推断；
2. **交互模式**是可配置、可版本化的产品策略，不是内核构建期枚举；
3. **应用生命周期**管理 Scene 可见性、焦点、后台预算、暂停与恢复，但不得把
   “UI 不可见”错误等同于“进程必须结束”。

Jasper-OS 内核继续只负责不可绕过的资源隔离、Handle/Rights、调度执行点、对象
生命周期和统一授权。Mobile 单主前台、Pad 分屏、Desktop 多窗口、Remote 多会话
等产品政策属于用户态 Service/Policy 层。

## 现有实现审计

| 能力 | 当前实现与真实证据 | 状态 | 唯一权威边界 |
| --- | --- | --- | --- |
| 显示/输入会话 | `kernel_core::display_input` 提供 `DisplayCapabilities`、`SurfaceSpec`、`DisplayInputSession`、帧票据和输入队列；真实 CPL3 framebuffer/PS-2 路径已有 QEMU 证据 | 部分具备 | 显示服务拥有会话和 Surface 生命周期；内核只保留资源与授权执行点 |
| 合成与焦点 | `kernel_core::ui_service::UiService` 在一个显示会话上维护多个 client、唯一 focus、generation token 和帧票据；已有双客户端隔离单测 | 部分具备 | UI Service 拥有焦点与合成顺序；不建立第二授权源 |
| Scene 传输 | `kernel_core::ui_protocol` 定义 JSUI v1 的 Scene/Patch/Input/Present/Cancel/Close/Error 与 request/sequence 校验 | 部分具备 | JSUI 是 Channel 上的版本化传输契约，不是新 syscall 族 |
| UI 执行宿主 | `user/ui-service` 通过预打开的原生 Channel 接收 Scene，使用固定版本 Jasper UI Engine CPU 核心产生 RGBA8 Present；另有 CPU Compositor/framebuffer 证据 | 部分具备 | UI Service 负责执行与呈现；内核和 `kernel_core` 不链接 UI Engine |
| 应用身份与进程 | 现有 Process/Task、Workload、Handle/Rights、PEP 和资源配额构成执行与授权主体 | 已具备基础 | 这些既有机制是应用执行权威，UI Service 不复制进程或权限系统 |
| 交互 Profile 与策略快照 | 当前没有独立、版本化的 Device Capabilities / Interaction Profile / Lifecycle Policy 快照 | 缺失 | 应由用户态 Profile/Policy Service 消费能力事实并发布不可变快照 |
| Scene 生命周期事务 | 当前 client 有创建、焦点、帧提交和关闭，但没有 Visible/Focused/Rendering/Background 四态分离，也没有迁移事务 | 缺失 | UI Service 需要事务化 Scene/Surface 状态并复用统一授权与资源预检 |
| 后台执行例外 | 现有 Workload/资源预算可承载授权后台任务，但没有 UI 生命周期到后台音频、下载、通知策略的统一映射 | 缺失 | 后台资格由权限与预算准入决定，不能因隐藏窗口自动获得 |
| 多会话/远程隔离 | 现有显示、输入、用户/租户 scope 可作为基础；没有本地/远程多席位策略和重连防重放协议 | 缺失 | 远程 Session Service 必须绑定已认证会话、显示/输入席位和可撤销授权 |
| 动态能力变化 | 显示/设备发现已有能力对象与事件基础；没有“能力事件到 Scene/Surface 事务迁移”的统一闭环 | 缺失 | 能力发现、策略计算、授权/资源预检和 Surface 发布必须分层 |
| UI 故障救援 | Console/Terminal 与 UI Engine 分离，UI Engine 可失败关闭；尚缺完整 UI Service 崩溃后的真实重启/救援矩阵 | 部分具备 | Terminal/Console 不依赖 UI Service 存活 |

## 生命周期模型草案

以下名称是 Issue #45 的设计草案，不是已注册 ABI：

- **Application**：稳定应用身份和业务状态；
- **Scene**：独立视图实例，拥有 `visible`、`focused`、`rendering` 三个独立事实；
- **Runtime Task**：实际执行主体，继续由 Process/Task/Workload 管理；
- **Background Grant**：后台音频、导航、下载、通知等特定权限与预算，不与 Scene
  可见性绑定；
- **Suspension Record**：说明是停止绘制、暂停执行、保存可恢复状态、重启恢复还是
  进程结束，并携带 epoch/generation。

任何 Scene 迁移至少需要：

```text
capability_epoch
policy_epoch
application_identity
session_scope
scene_key + generation
old_surface + new_surface
authorization_decision
resource_reservation
transaction_id
```

旧 `surface`、旧输入路由和旧 token 在新事务提交后必须失效。失败时只能回滚到
明确仍有效的旧状态或进入显式失败终态，不能静默把旧输入投递给新 Scene。

## 版本化策略快照草案

未来用户态策略服务可发布不可变 `UiPolicySnapshot`，至少包含：

- schema/version；
- 设备、用户、租户、会话与显示/输入席位 scope；
- 实际观察到的能力 `capability_epoch`；
- 选中的交互 Profile ID 与可解释的 selection reason；
- 主交互 Scene 上限及多窗口/分屏规则；
- 后台 Workload 的权限、预算与例外条件；
- 快照 `policy_epoch`、撤销代际和来源身份。

消费者只能按自己支持的最低 schema 做协商。未知版本、过期 epoch、越界 scope 和
能力缺失必须显式拒绝或降级，不能猜测为 Mobile/Desktop。

## 实施顺序

1. **A：审计与 Schema 收口**：`kernel-core::ui_policy` 已提供版本化能力、Profile、
   生命周期快照、编码负例和 Surface 迁移事务；真实用户态 Policy Service、多应用
   生命周期和动态设备事件闭环仍未完成。
2. **B：Mobile 单主前台**：在真实 CPL3 UI Service 上用双应用验证焦点互斥、输入
   路由、可见/暂停分离、后台允许/拒绝、关闭与崩溃清理。
3. **C：Pad/Desktop 与动态切换**：验证多 Scene、多窗口、Surface generation、
   外接显示/键鼠、迁移失败回滚和资源回收。
4. **D：Remote/多会话/可穿戴**：验证会话隔离、远程输入认证、撤销、断线重连和
   重放负例。
5. **E：生态与版本治理**：与 Jasper UI Framework、JSUI、系统升级回滚和
   多版本消费者交叉验证。

## 当前不能宣称

- 不能把当前唯一 focus 和 client 表宣称为完整 Mobile/Pad/Desktop 策略引擎；
- 不能把 QEMU framebuffer、PS-2 或宿主 UI Engine loopback 当作物理显示/输入
  资格；
- 不能因为 Scene 不可见就自动杀死应用或撤销后台权限；
- 不能从设备型号、固定屏幕数、固定窗口数或编译期 Profile 推断设备能力；
- 不能在 UI Service、Framework 和内核中保存互相冲突的生命周期权威；
- 不能新增绕过 SEC/PEP、Handle/Rights、Workload 或资源预算的第二授权路径。
