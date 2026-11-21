# Issue #46 阶段 C：Software Evidence 纵向切片

更新时间：2026-11-21。

状态：**software vertical slice implemented-tested；硬件证明仍未完成**。

## 声明范围

`jasper-trust-service` 实现 Jasper Trust v1 的首个低等级证据链：

```text
真实签名 .jaso 包
  -> SEC Process/Object/ApplicationIdentity 世代
  -> Collector 测量并声明软件覆盖范围与缺口
  -> Relying Party nonce/audience Challenge
  -> Ed25519 Broker Evidence
  -> Verifier 验签、范围、世代、时间、nonce、Provider 撤销与 replay
  -> 有界 signed Result
  -> Profile Policy 产生 allow/degrade/deny
```

结果固定声明 `software-observation`，不能声明受保护启动测量、TPM/TEE 背书或
“不存在作弊”。默认 coverage gaps 明确包含：

- 运行时进程内存未测量；
- 运行时依赖闭包未测量；
- 启动链不在软件观测范围；
- 当前没有硬件证明 Provider。

Policy 只有显式接受这些 gap 时才返回 `degrade`，否则拒绝。普通 `verified`
只适用于调用方请求且实际提供的范围没有 gap 的情形。

## 身份与测量绑定

- `SubjectSnapshot` 只从 active `SecurityContext` 派生，使用 SEC-1 的
  Process/Service/Module/Device object id、object generation、BootId、
  ApplicationIdentity stable id/generation 和 32 字节 content measurement；
- Collector 只接受与 Challenge 主体身份、应用世代和 BootId 完全匹配的上下文；
- 真实 `.jaso` 必须可解析、带发布者签名，并且 `jaso::digest_of` 必须精确等于
  SEC ApplicationIdentity measurement；
- 缺失测量、篡改包、其他 Subject、旧/新 generation 均失败关闭；
- Trust 服务不创建 Process、PID、Handle、Rights 或第二授权权威。

## Challenge、Evidence 与 Result

- Challenge 包含 32 字节 nonce、audience、预期 Subject、accepted levels、
  disclosure fields、accepted gaps、policy epoch 与短有效期；
- Evidence ID 和 Challenge ID 由域分隔 SHA-256 派生，nonce、主体测量、时间和
  单调 Challenge 序号共同阻止相同 nonce 产生可重放身份；
- Challenge/Evidence/Result/Policy 使用有界规范 CBOR envelope；
- Evidence 与 Result 均使用独立 Ed25519 密钥严格验签；
- Provider signer、generation、有效期、revocation epoch 和 trust chain 必须与
  Verifier 配置一致；
- Challenge 只能成功消费一次；失败路径回收未完成 slot，Broker 停止会清空未决
  Challenge。

## 当前隔离边界

本切片是 system-service 的纯 Rust 实现，尚未部署为三个真实 OS Process。
Collector、Broker、Verifier 和 Policy 是独立对象/密钥/数据职责，并通过
`TrustDaemon` 的显式生命周期组合；生产部署仍必须由 ServiceGate/Channel/Workload
装配为隔离用户态进程，并提供真实 CSPRNG 与持久撤销源。

因此本状态关闭的是 Issue #46 阶段 C 的软件纵向数据与密码学语义，不关闭：

- TPM/TEE、受保护启动测量和证明密钥的真实 Pixel 6a 验收；
- 第三方 Verifier 网络互操作；
- ServiceGate 进程化部署和持久远端撤销；
- 任何行业 Profile 或“无作弊”声明。

## 验证

```text
cargo test -p jasper-trust-service
9 passed; 0 failed
```

覆盖：

- 真实签名 `.jaso` 与 SEC 世代/nonce 绑定；
- Challenge CBOR 往返；
- 缺失测量、篡改包、伪造 Subject、跨 generation；
- stale Challenge、过期 Evidence、成功后的 replay；
- Provider 撤销、过期 Policy、Broker 死亡；
- bounded Challenge capacity 与成功后回收；
- Evidence/Result 截断、篡改和签名拒绝。

机器验收记录在 `verification/trust-framework-spec.toml` 的
`software-evidence-vertical` 项；硬件项继续保持 pending。
