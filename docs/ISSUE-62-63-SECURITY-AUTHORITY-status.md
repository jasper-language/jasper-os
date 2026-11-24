# Issue #62 / #63：硬件与软件安全的统一权威边界

更新日期：2026-11-24。

状态：**架构约束已吸收；实现状态未提升**。#62 的硬件资产、外设准入和
设备完整性，以及 #63 的软件供应链、执行准入、运行时防护和响应，仍然不是
已完成的 EDR、DLP、设备认证或合规能力。

来源：

- <https://github.com/DarkMagier/jasper-os/issues/62>
- <https://github.com/DarkMagier/jasper-os/issues/63>
- <https://github.com/DarkMagier/jasper-os/issues/39>
- <https://github.com/DarkMagier/jasper-os/issues/46>

## 唯一权威

Jasper-OS 只有一套原生主体、资源、授权、撤销和审计事实源：

| 层 | 唯一职责 | 不得承担 |
| --- | --- | --- |
| Kernel/Core | Handle/Rights、对象身份与世代、PEP/MAC、资源隔离、撤销和最小测量原语 | 不内置厂商黑名单、行业 EDR 规则或第二套身份 |
| SEC（#39） | 主体、资源、操作、作用域、期限、委托、条件和撤销的唯一授权决策/执行链 | 不由签名、Trust Result、兼容层 root 或外部策略服务直接授权 |
| Trust（#46） | Challenge、Evidence、Verifier、Result、证据等级和覆盖缺口 | 不授予文件/设备/进程权限，不把签名升级为运行时完整性 |
| Device/Broker（#29/#43） | 设备发现、拓扑、代际、Driver Host 准入和硬件资源所有权 | 不把序列号或描述符自动升级为可信物理身份 |
| LC（#21/#38） | 安装、更新、回滚、驱动/固件事务及生命周期 | 不因安装成功跳过 SEC/技术安全双门禁 |
| 用户态 Security Service（#62/#63） | 资产/软件清单、风险关联、策略编排、告警、取证和恢复建议 | 不建立第二 PEP、万能扫描 ABI 或绕过 Handle/Rights |
| Compatibility | 把 Linux/Android/Wine/VM 外部身份投影为 Jasper 本地主体 | 不把 guest root/管理员、Windows 驱动或外部 HAL 变成宿主权威 |

#62 和 #63 可以使用各自领域的事实模型，但授权请求必须落到同一 SEC 主体、
资源、操作、scope、期限、generation、policy epoch、撤销和审计字段。

## 硬件与软件事实分离

- 硬件侧区分内部 `DeviceIdentity`、设备 generation、总线位置、可选序列号、
  证书/公钥、固件测量和经过验证的硬件证据。
- 软件侧区分 `ApplicationIdentity`、包摘要/签名、发布者、依赖闭包、进程/映像
  generation、运行时测量和风险判定。
- 任一描述符、签名或测量只证明其明确覆盖的属性；不能产生泛化的
  `trusted=true`、`secure=true` 或 `authorized=true`。
- 新设备首次出现、合法维修、固件升级、软件更新和策略更新必须区分，异常后
  不得自动学习为可信基线。

## 成熟标准和实现复用

标准是互操作与证据输入，不是 Jasper 的第二架构或合规证明。

| 领域 | 候选标准 | 接入约束 |
| --- | --- | --- |
| 硬件信任与证明 | TPM 2.0、DICE、SPDM、RATS RFC 9334、EAT RFC 9711 | 版本固定、许可证/漏洞审计、真实硬件与失败路径分别验收 |
| 证明与消息格式 | CBOR RFC 8949、COSE RFC 9052 | 可作为外部 Trust 协议；不要求内核对象统一改用 CBOR |
| 更新与供应链 | TUF、in-toto、SLSA、Sigstore/Cosign | 只覆盖各自更新/来源语义；不能替代运行授权 |
| 成分与漏洞交换 | SPDX、CycloneDX、CSAF、CVE/CWE/CVSS | 用于交换和风险输入；已知漏洞不等于已可利用，也不等于恶意 |
| 认证与身份 | FIDO2/CTAP、WebAuthn L3、X.509/PKIX | 认证成功不等价于资源授权 |
| 策略互操作 | NIST SP 800-162、XACML 3.0 | 只作管理面/导入导出评估；不能让外部 PDP 绕过内核 PEP |
| 密码互操作 | SM2/SM3/SM4、FIPS 140-3、ISO/IEC 19790 对照 | 算法可用不等于实现、密钥生命周期或产品认证通过 |
| 审计互操作 | Syslog RFC 5424、OpenTelemetry | 只作导出格式；内部仍需保留不可伪造主体、generation、policy epoch 和丢事件语义 |

引入任何 Provider 前必须记录规范版本、实现版本、适用平台、许可证、攻击面、
更新维护者、撤销机制和真实验收证据。未完成第三方认证时不得宣称合规。

## 验收边界

#62 的低等级正向结果可以来自总线枚举、资产基线、未知设备默认拒绝、旧
generation 撤销和双类真实外设的替换/重插测试；高等级结果必须另有真实设备
证书、TPM/DICE/SPDM 或等价硬件证据。#63 的低等级结果可以来自文件/包签名、
依赖闭包和 runtime generation；它不能证明全部进程内存、全部依赖或“无恶意软件”。

以下门仍为 pending：

- 至少两类真实外设完成发现、基线、阻断、重插、撤销和恢复；
- 至少一种真实兼容运行路径证明 guest 高权限不能绕过宿主 SEC/PEP；
- 真实签名软件完成安装、执行、运行中撤销、审计和恢复纵切；
- Trust Challenge/Evidence/Result 与 SEC 决策在真实服务路径上分离协作；
- TPM/TEE、SPDM 或其他硬件证明在物理设备上完成正反验收；
- 个人开放、企业受管和严格受管策略共用机制，且不造成不可恢复锁死。

#62/#63 当前只更新架构约束，不擅自插入或重排已有 DAG。相关实现必须继续
通过 #39、#46、#29/#43 和 LC 的既有权威与验收流程。
