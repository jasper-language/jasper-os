# LC-2 发布者密钥轮换与丢钥恢复

更新日期：2026-11-18。

状态：**软件机制切片完成；LC-2、Issue #38 和真实设备发布门未完成**。

## 当前能力

原生安装模型把以下事实保持分离：

- 稳定的数字 publisher 账号；
- 包字节与版本身份；
- 当前发布者签名公钥；
- 本地更新权；
- 安装所有者范围。

新包可由信任边界通过 `add_signed_package` /
`PersistentInstallStore::install_signed_package` 登记。签名公钥随包身份持久化，
不能被同版本、同摘要的后续插入静默替换。

每个 `InstallationSnapshot` 保存当前 publisher key 与单调 key generation。应用
升级必须由与该安装当前 key 完全相同的已签发包完成；未绑定 key 的旧安装不能猜测
继承，必须先经过显式再授权。

## 轮换与丢钥恢复

`PublisherRotationRequest` 绑定安装 key、AppID、publisher、当前包版本、
key generation、nonce、轮换类型和新 key。证明由
`PublisherRotationVerifier` 在受信签名边界验证，模型不接受调用者提供的布尔值。

- 协作轮换要求旧 key 与新 key 对同一规范消息分别签名；
- 丢钥恢复不要求旧 key 签名，但必须同时满足当前本地更新权和安装所有者范围，并
  证明持有新 key；
- 已使用 generation 的请求重放失败；
- 错误旧证明、错误新证明、非所有者、非更新主体、同 key 轮换均失败；
- 成功轮换只递增 publisher-key generation 并替换安装的当前验签身份，不改变更新
  权、授权 grant、活动 runtime 的启动包身份或用户数据作用域；
- 轮换后旧 key 签发的包不能继续作为更新使用。

## 持久化

安装快照格式升级到 v4：

- package snapshot 增加可选 publisher key；
- installation snapshot 增加当前 publisher key 与 generation；
- v1/v2/v3 快照可读取，缺少 key 的历史安装保持 `None`，不会自动相信后续 key；
- 下次提交后写入 v4。

## 服务授权接线

包状态修改不再直接接受请求：`authorize_publisher_rotation` 先按安装所有者范围、
当前主体 `SecurityContext`、SyscallSet、策略代际和 `system.install.package.write`
能力生成统一 `authz::Decision`，并把允许或拒绝的完整决策交给审计边界。审计不可保留
时不生成 `PublisherRotationAuthorization`，状态机不会执行轮换。

内核服务入口从当前进程重新取得 subject、tenant、domain、Workload 与能力，不能由
请求伪造。得到审计后的授权 token 后才调用 `NativeInstallService` 和持久化 store；
Ed25519 验签、更新权和所有者范围仍是独立门禁。真实 OVMF/virtio-blk 三轮演练首启
记录的授权决策为：

```text
[JSR-AUTHZ] version=1 issuer=1 tenant=7 domain=1
operation=system.install.publisher.rotate scope=user effect=write
decision=true reason=allowed
```

首启安装并轮换到新 key，后两启验证 key generation、旧 key 的用户 8 安装和数据作用域
保持不变；九个写/flush 中断点继续通过。证据见
`evidence/lc2-publisher-rotation-service-20261118/`。该入口目前是内核内部版本化
服务形状，尚未冻结为用户 syscall/JUCS 命令。

## 验证边界

当前状态机与持久化路径提供结构化失败，不授予发现、启动或更新权。真正生产使用仍需：

- 为已接通的内核服务入口冻结独立用户 ABI/JUCS 命令，并完成客户端兼容审查；
- 在真实 OVMF/P0 与 Pixel 生命周期中验证断电、回滚和撤销快照；
- 将 key generation 绑定 LC-5 的硬件单调锚；当前存储内防重放不能抵御整盘快照回滚；
- 完成企业策略、发布者身份证明、同名并行身份和密钥泄露后的隔离策略。

本切片不改变 LC-2 的 `core-passed` 状态，也不关闭任何 DAG 节点。
