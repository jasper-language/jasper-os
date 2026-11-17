# Issue #39：现有统一授权事实源审计

更新日期：2026-11-17。

状态：**现有机制审计，不是完整授权体系完成声明**。Issue #39 要求统一授权位于
系统基础设施层；本文件只核对当前代码中已经存在的事实源、执行点和缺口，不新增
`system.auth.*` ABI，也不替代 LC、PEP、Handle/Rights 或租户域机制。

已落地的第一类 adapter 是 `kernel-core::authz`：它把 active
`SecurityContext`、进程 SyscallSet、租户/domain、MAC policy epoch、资源 scope
与请求条件投影为固定决策记录，当前已接入 update status/recover/archive/audit。
它不拥有权限状态，也不会在缺少完整撤销源时用对象 generation 冒充全局撤销代际。

来源：<https://github.com/DarkMagier/jasper-os/issues/39>

## 现有事实源

### Handle/Rights 与能力图

- `kernel-core::object::Rights` 定义 READ、WRITE、EXECUTE、WAIT、CONTROL、
  DUPLICATE、TRANSFER、MAP、SUBSCRIBE 九个稳定权限位。
- 句柄由槽位和世代组成；槽位世代耗尽后永久退役，旧句柄不能因复用重新有效。
- 委派句柄带全局 `CapabilityId` 和父边；子权限必须是父权限子集，父撤销覆盖
  当前句柄表内的后代。
- 跨进程委派使用 `put_delegated_shared`，关闭或撤权时由进程/对象清理路径统一
  处理；已有测试覆盖跨进程后代撤销和陈旧世代。
- `kernel-core::capability::AuthoritySnapshot` 把 Rights、SyscallSet、服务发布位和
  程序能力位固定为一次效果检查的快照；快照变化会使在途 grant 失效。

### 身份、域、标签与审计

- `SecurityContext` 绑定 boot identity、对象 identity/class、generation、
  application identity 和 MAC label；PID 不是安全身份。
- `PolicyContext` 已带 policy epoch 和 revocation generation；
  `AuditContext` 已带 audit epoch 和 event generation，但目前仍是版本化载体，
  不能据此宣称所有资源路径都已持久审计。
- `kernel-core::mac` 按主体标签、对象标签、操作和对象类求值；无匹配规则的未知
  情况失败关闭。允许和拒绝都进入有界审计队列，队列耗尽也失败关闭。

### HWV-5 PEP

- `Hwv5Pep` 在 PIO、Net、Fs、VMM 表面检查对象、generation、surface、Rights、
  跨域 delegation、MAC secrecy/integrity 和审计容量。
- 委派必须由资源 owner 在现有 Rights 子集内建立，并绑定 resource epoch；
  revoke/reset/renew 使旧委派失效。
- 审计记录 actor、owner、object、generation、surface、requested rights、effect、
  decision 和 resource epoch。

### 原生安装

- `PackageKey`、`InstallationKey`、`GrantKey`、`RuntimeKey`、`DataKey` 均带
  slot+generation，路径和 AppID 不是授权凭证。
- `OwnerScope` 已区分 System、Device、User、Group、Tenant、Workload；
  `Subject` 另外区分 Service。
- 安装来源 Store、UserImport、Enterprise、Developer、SystemBuiltin 只是供应链
  元数据，不等于运行或更新权限。
- Grant 带操作 Rights 和可选 `expires_at`；持久安装记录保存 owner scope、来源、
  更新主体和运行主体。

### LC-2 与 LC-4

- LC-2 status/action 从进程安全上下文派生 caller、tenant、domain，绑定 request、
  generation、transaction、manifest digest 和独立回收入口。
- LC-4 使用 32 字节 Ed25519 signer、trusted signer、revocation 集、release/
  security floor 和设备 generation；Driver Host admission/reset/crash/recovery
  共享同一代际链。

## 当前缺口

1. **缺少单一跨域决策对象**：上述模块使用不同 Rights 位集、decision/error 词汇
   和审计字段，尚无一个统一投影完整表达 identity、decision maker、executor、
   resource、operation、scope、expiry、delegation depth、conditions、
   policy version 和 revocation generation。`authz` 已提供基础投影并接入 update
   子系统，但尚未成为所有资源域的共同执行入口。
2. **PEP 覆盖不均**：HWV-5 设备/VMM 面已有统一 PEP；进程、文件、IPC、网络、
   UI/媒体、服务和虚拟化尚未全部经过同一语义的决策入口。
3. **决策者与执行主体未统一分离**：原生安装有 owner/update authority/runtime
   principal，LC-2 有 caller/tenant/domain，但尚未形成全系统共同记录。
4. **时间、委托深度和条件不完整**：安装 Grant 有时限，HWV-5 委派有 resource
   epoch，但没有统一 session/single-use/clock-quality/delegation-depth 条件。
5. **撤销覆盖不一致**：句柄和 HWV-5 表面可撤销；UI、媒体、文件映射、IPC 在途
   请求、异步工作和跨兼容层的统一撤销传播仍需逐资源审计。
6. **审计字段不一致**：MAC/PEP 记录较完整，但普通资源路径、服务决策和 LC 事务
   尚未统一持久化 policy version、决策者、执行者、条件与拒绝原因。
7. **系统服务例外未统一封闭**：需要逐一证明系统服务也经过权限/PEP，而不是因
   class/domain 获得无条件放行。
8. **兼容适配边界未全部证明**：Linux/Android/Wine 等适配器尚无统一清单证明其
   外部身份只映射为本地资源权限，且不能绕过底层 PEP。
9. **LC-2 capability flag 仍偏局部**：status/action principal 中的布尔能力来自
   调用路径，尚未接入统一 owner/organization/remote-delegation 策略求值。

## 后续实施边界

- 先建立“现有事实源投影 + adapter”，不立即新增公开 `system.auth.*` ABI。
- 统一授权对象必须引用现有 Handle/Rights、SyscallSet、service/program capability、
  MAC、DomainKey 和 capability graph，不能复制权限状态。
- 高频路径允许使用快照化本地 grant/token，但必须绑定 policy/revocation generation、
  资源 generation、作用域和期限，并可由统一撤销传播失效。
- 每个资源域必须补正反例：身份伪造、跨租户、过期/离线、超集委托、撤销竞态、
  执行主体替换和系统服务越权。
- 最终验收必须在真实 Jasper-OS 执行路径完成；mock、stub 和纯模型测试只能作为
  中间证据。
