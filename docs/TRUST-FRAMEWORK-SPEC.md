# Jasper Trust Framework Protocol v1

状态：**Normative specification draft**。本文定义 Issue #46 阶段 B 的外部协议、
角色、证据语义、隐私和失败边界；它不实现生产 Attester、Verifier、TPM/TEE
Provider，也不批准新的内核 system ABI。

规范中的“必须”和“不得”是协议符合性要求。任何实现只能声明其实际覆盖的证据等级；
缺少 Provider、测量、网络、策略或新鲜度证明时必须返回明确错误或降级结果。

## 1. 范围与信任边界

Jasper Trust 把证明拆成以下角色：

| 角色 | 职责 | 不得承担 |
| --- | --- | --- |
| Attester | 在现有应用、进程、模块或设备身份下收集被授权事实 | 不得跨域扫描，不得自行把软件自报升级为硬件证据 |
| Evidence Collector | 通过 Handle/Rights、PEP/MAC、IFC 和资源配额读取声明范围 | 不得建立第二权限源 |
| Attestation Broker | 绑定 Challenge 与 Evidence，选择已登记 Provider | 不得决定业务权限 |
| Verifier | 验证签名、受众、nonce、新鲜度、世代、范围和撤销状态 | 不得调用业务授权旁路 |
| Provider Registry | 发布经过签名和版本化的软件/硬件 Provider | 不得按厂商名称硬编码默认为可信 |
| Policy Evaluator | 产生有解释的 allow/deny/degrade/unavailable 决策 | 不得放宽 SEC、MAC、IFC 或 Relying Party 策略 |
| Relying Party | 结合证明、业务身份和风控作最终业务决定 | 不得把低等级证明解释成“无作弊”或“绝对安全” |

内核仍是主体/对象身份、Handle/Rights、PEP、隔离、审计和撤销的唯一强制权威。
Trust Framework v1 是外部用户态协议与可选用户态服务集合，不增加 system ABI。

## 2. 消息与会话

所有 v1 消息使用规范 CBOR envelope，Schema 位于
`trust/schema/v1/trust.cddl`。接收方必须检查：

1. 顶层消息类型和协议版本；
2. 发送者通过现有 SEC 身份与授权机制完成认证；
3. `message_id` 在会话内唯一，`correlation_id` 只能引用调用者可见的会话；
4. 定义长度、最大时间戳和接收者的实际资源配额；
5. 关键扩展未理解时拒绝，非关键扩展可以忽略且不得改变安全语义；
6. 重复 key、非最短整数、超长文本/字节串、深度或声明数量超预算时拒绝。

协议协商只接受双方共同支持的版本、算法和证据等级。不得选择调用者未请求的
更强声明，也不得因为双方没有共同版本而回退到隐式 v0。

## 3. Challenge

Challenge 由 Relying Party 或 Verifier 创建，至少包含：

- 不可预测的 nonce；nonce 长度由协商算法规定并受接收预算限制；
- 目标 audience 和预期的 subject 类型；
- 请求的证据等级、字段集合和最大披露范围；
- 可接受时间窗口及 `policy_epoch`；
- 是否允许 Provider 返回覆盖缺口。

Challenge 不能包含任意进程列表、稳定全球设备标识或未授权读取指令。默认只允许
Attester 观测自身、其所拥有对象和经显式授权的服务状态。

## 4. Evidence

每条 Evidence 必须携带：

- Evidence Schema 版本、唯一 ID、创建/失效时间；
- Challenge ID 和 nonce 的原像绑定；
- Boot ID、subject identity、subject generation、object generation；
- Provider ID/generation、证据等级、算法和签名链；
- 测量类型、摘要、测量范围、依赖范围和 `coverage_gaps`；
- 策略 epoch、撤销 epoch 和当前状态；
- 字段披露集合，以及未披露字段不能推断为已验证。

Evidence 等级只能使用：

`software-observation`、`signed-static-package`、
`protected-system-measurement`、`hardware-backed`。

高级等级不会由签名本身产生。应用包签名、运行时进程绑定和硬件启动测量必须是
不同字段，并分别由对应 Provider 或系统证据支持。

## 5. Result

Verifier 的 Result 必须区分：

- `verified`：所有请求范围和关键字段得到证明；
- `verified-with-gaps`：只允许在调用者明确接受时返回，并逐项列出缺口；
- `rejected`：签名、nonce、受众、时间、世代、范围、撤销或策略无效；
- `unavailable`：Provider、网络、Verifier 或所需原语不可用；
- `unsupported`：版本、算法、Provider 或证据等级不支持。

不得把 `unavailable`、`unsupported` 或签名不完整转换为成功。`verified` 只表示
声明的证据属性，不表示业务风险为零。

## 6. Provider 协商

Provider Registry 条目必须包含 ID、generation、签名者、支持的协议/算法、证据等级、
平台范围、撤销 epoch 和有效期。协商失败时返回稳定的错误码，不使用厂商名称作为
可信默认值。

Registry、Policy 和 Provider 的更新必须通过现有统一授权、审计和版本化发布路径。
Broker 可以缓存公开目录，但缓存过期或撤销 epoch 不匹配时不能继续产生 `verified`。

## 7. Freshness、重放与失效

验证器必须把 Challenge 的 nonce、audience、时间窗、subject generation、
object generation、Boot ID、Provider generation 和 policy epoch 一起验证。
以下任一情况使 Evidence 失效：

- 进程/对象重启或 generation 改变；
- 模块、应用、策略或 Provider 更新；
- 证据有效期结束；
- 签名或 Provider 被撤销；
- Boot ID 改变；
- 同一 nonce 被另一 audience 或 subject 使用。

旧 Evidence 不得因签名仍有效而继续通过。撤回后重新验证必须获得新的 Challenge。

## 8. 隐私与最小披露

默认不返回稳定硬件序列号、全局设备 ID、其他进程状态或原始内存。字段披露必须由
Challenge 请求、调用者授权、Relying Party 受众和 Policy 共同允许，取交集而非并集。
Verifier 和 Broker 的审计只记录必要标识、字段集合、决策和错误类别；敏感证据的
摘要不能成为跨站点跟踪标识。

## 9. 资源与失败关闭

所有输入长度、签名字段、证据项、覆盖缺口、Provider 链、并发 Challenge 和审计
队列必须使用实际接收者配额与优先准入。分配失败、服务死亡、Broker 重启、时钟不可信、
网络不可用、TPM/TEE 不可用、撤销状态不可读或策略加载失败时，结果为拒绝或显式
不可用，并回收全部对象和临时内存。

## 10. RATS / EAT 互操作映射

本规范采用 IETF RATS 架构的 Attester、Verifier、Relying Party、Evidence、
Endorsement、Reference Values 和 Attestation Result 语义。网络互操作映射到
EAT claims 时必须保留：

- subject 与 generation 绑定；
- nonce/freshness 和 audience；
- 测量摘要、范围与缺口；
- Provider 信任根与撤销；
- 结果有效性、策略版本和失败原因；
- 低等级证据不得编码成硬件背书。

v1 不定义强制网络传输、远程 URL 格式或厂商认证方案。后续实现可以增加 CBOR/COSE
传输 Profile，但必须通过独立 ABI/协议评审。

## 11. 内核 ABI 裁决

当前结论：**不新增 system ABI**。Collector、Broker、Verifier、Policy 和 Registry
优先组合现有 SEC 身份、ApplicationIdentity/measurement、`.jaso` 签名、
Handle/Rights、PEP/MAC、IFC、审计、LC-2 安装与撤销机制。

只有现有机制无法提供受保护启动测量、不可伪造证明密钥、硬件证据或原子对象世代绑定
时，才提交最小内核原语提案。提案必须包含威胁模型、ABI 版本与冻结影响、失败关闭、
资源准入、替代方案和真实硬件负向验收。

## 12. 威胁模型

必须覆盖普通应用伪造/越权读取、失陷 Broker/Verifier 获取跨域权限、恶意 Provider、
被替换依赖、恶意 Relying Party 过度披露、重放/跨设备/跨世代复用、过期策略、
资源耗尽、服务崩溃和审计丢失。每个威胁都必须有负向测试或协议拒绝路径；
无证据不能默认为安全。

## 13. 符合性

实现符合 v1 不意味着通过硬件证明、完成 Issue #46 阶段 C/D 或获得任何行业认证。
符合性至少要求 Schema/版本协商、nonce/freshness/audience、世代与撤销、最小披露、
有界输入、错误不升级和 Provider 失败关闭；生产硬件 Provider 仍需 Pixel 6a 或其他
批准设备的独立验收。
