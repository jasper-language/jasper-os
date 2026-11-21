# Issue #46 阶段 B：Trust Framework v1 规范状态

状态：规范已定义；生产实现、硬件 Provider 和行业 Profile 未完成。

## 本次交付

- `docs/TRUST-FRAMEWORK-SPEC.md`：角色、证据等级、Challenge/Evidence/Result、
  Provider 协商、nonce/freshness/generation/revocation、最小披露和失败关闭要求。
- `trust/schema/v1/trust.cddl`：版本化外部协议 Schema；不是内核 ABI。
- RATS 角色与 EAT claim 语义映射，保留证据范围、缺口、受众、策略和 Provider 版本。
- 明确内核 ABI 裁决：v1 不新增 system ABI，复用 SEC、ApplicationIdentity、
  `.jaso`、Handle/Rights、PEP/MAC、IFC、审计和 LC-2 发布撤销能力。

## 未完成门

- 软件证据纵向切片、服务崩溃/资源回收的实现与真实负向测试；
- TPM/TEE、受保护启动测量和证明密钥的真实 Pixel 6a 验收；
- 第三方 Verifier 互操作、远程传输 Profile 和行业 Profile；
- 任何新增内核原语及 ABI 冻结评审。

本规范不能作为“硬件可信”“无作弊”“所有设备支持”的实现证明。
