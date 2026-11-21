# Issue #46 阶段 B：Trust Framework v1 规范状态

状态：规范已定义；软件证据纵向切片已实现并测试；硬件 Provider、真实隔离
ServiceGate 部署和行业 Profile 未完成。

## 本次交付

- `docs/TRUST-FRAMEWORK-SPEC.md`：角色、证据等级、Challenge/Evidence/Result、
  Provider 协商、nonce/freshness/generation/revocation、最小披露和失败关闭要求。
- `trust/schema/v1/trust.cddl`：版本化外部协议 Schema；不是内核 ABI。
- RATS 角色与 EAT claim 语义映射，保留证据范围、缺口、受众、策略和 Provider 版本。
- 明确内核 ABI 裁决：v1 不新增 system ABI，复用 SEC、ApplicationIdentity、
  `.jaso`、Handle/Rights、PEP/MAC、IFC、审计和 LC-2 发布撤销能力。

## 软件证据纵向切片

`jasper-trust-service` 和 `docs/ISSUE-46-SOFTWARE-EVIDENCE-status.md` 已实现：

- 真实签名 `.jaso` 内容测量与 SEC Process/Object/ApplicationIdentity 绑定；
- nonce/audience Challenge、Ed25519 Evidence/Result/Policy、显式 coverage gaps；
- replay、过期、跨 generation、Provider 撤销、Broker 死亡和容量回收测试；
- 结果只声明 `software-observation`，没有升级成硬件或“无作弊”证明。

该实现仍不是隔离 OS Process 的生产部署，也不表示 Issue #46 可以关闭。

## 未完成门

- ServiceGate/Channel/Workload 三个真实隔离服务的部署与持久远端撤销；
- TPM/TEE、受保护启动测量和证明密钥的真实 Pixel 6a 验收；
- 第三方 Verifier 互操作、远程传输 Profile 和行业 Profile；
- 任何新增内核原语及 ABI 冻结评审。

本规范不能作为“硬件可信”“无作弊”“所有设备支持”的实现证明。
