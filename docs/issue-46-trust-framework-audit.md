# Issue #46：Jasper Trust Framework 阶段 A 审计

更新时间：2026-11-19。

状态：**现状审计、威胁边界与实现矩阵草案。本文不新增 ABI、安全权威或 DAG
节点，也不代表远程证明、TPM/TEE、游戏反作弊或任何行业 Profile 已实现。**

## 核心裁决

Jasper Trust 必须建立在现有 SEC 体系之上：

- 内核继续是 Handle/Rights、对象身份、PEP、资源隔离和撤销的唯一强制权威；
- ApplicationIdentity 的安装身份与内容测量保持分离；
- `.jaso` 签名证明发布者与文件内容来源，不等价于当前进程完整性；
- 硬件启动链、TPM/TEE 证据与普通软件自报必须使用不可混淆的证据等级；
- Attestation Broker、Verifier、Policy Evaluator、Provider Registry 和行业
  Profile 均属于隔离用户态服务，不能获得内核任意执行或跨进程扫描权限；
- 缺少硬件证据、验证器、网络或策略时明确拒绝或降级，不产生默认成功。

## 现有能力矩阵

| 能力 | 当前证据/代码 | 状态 | 缺口 |
| --- | --- | --- | --- |
| 对象与主体身份 | `kernel_core::security::{BootId, ObjId, SecurityContext}`；SEC-1 验证进程、Memory、子进程、IPC 和模块身份隔离 | 已具备基础 | 不是远程证明身份；需要证据 Schema 明确主体和对象世代 |
| 应用稳定身份 | `ApplicationIdentity` 分离稳定 ID、generation 和 32 字节 measurement；装载时由内核写入且应用不可改 | 已具备基础 | 尚无 challenge/nonce 绑定、证据签名、范围声明和外部验证 |
| 内容测量状态 | `MeasurementState::{Unavailable, Present}` 防止旧式 app ID 被冒充为内容测量 | 已具备基础 | 需覆盖模块依赖、运行时映像、配置和测量缺口 |
| `.jaso` 发布者签名 | Ed25519 签名段、SHA-256 内容摘要、发布者表和 TrustPolicy；内核模块有 boot/build 阶段准入 | 已具备供应链切片 | 只能证明静态包来源，不能证明运行中的服务、进程或设备状态 |
| PEP/MAC | `SecurityDomain`、MAC label、operation/effect/scope 决策和统一审计；拒绝路径失败关闭 | 已具备基础 | 证据读取/披露必须走同一 PEP，不能建立旁路 Verbose API |
| 能力撤销与世代 | Handle/Rights、对象 generation、SecurityContext revocation generation、Workload/lease 撤销 | 已具备基础 | 需把撤销/更新/重启映射到证明结果失效和重新验证 |
| IFC | SEC-5 覆盖 IPC、共享内存、文件、网络、剪贴板、显示和 VM I/O 等流通道 | 已具备基础 | 证据字段最小披露和验证方数据流需单独建模 |
| 审计 | MAC/IFC 及授权路径有有界审计与 digest；持久性依赖对应系统服务 | 部分具备 | 远程不可变审计、跨重启证明、日志容量/丢失语义未完成 |
| Driver/DMA 隔离 | Driver Host、DMA/IRQ/IOMMU 准入和 GC-1 QEMU 证据存在 | 部分具备 | 真实 Pixel 多 IOMMU、既有根表接管、崩溃/热插拔全矩阵未验收 |
| 发布防回滚 | LC-2/LC-5 有内容寻址、发布者轮换、撤销和审计设计；TPM2 NV counter 适配存在脚本协议切片 | 部分具备 | 真实 TPM provisioning、auth/session、断电恢复和远端审计未完成 |
| 远端 Attestation | 当前没有 verifier、nonce/challenge 服务、Evidence/Result Schema 或 Provider Registry | 缺失 | 需要新用户态服务与版本化协议，尚不应新增内核 ABI |
| TEE / Secure Boot / PCR 证明 | 当前主机可见 Intel fTPM，但无生产 Jasper 证明链和 tpm2-tools 权限 | 缺失/未验收 | 必须专项实现并在物理设备验证，QEMU/fake TPM 不能关闭 |

## 威胁模型

必须分别处理：

1. **普通应用**：尝试伪造测量、读取其他进程状态、拿稳定设备标识或提升证据等级；
2. **失陷用户态服务**：Broker/Verifier/Policy Service 被攻陷后不得获得跨域任意读取或
   第二授权权威；
3. **恶意或被替换驱动/设备**：DMA、MMIO、IRQ 和恢复过程不得破坏其他域；
4. **恶意依赖方/验证方**：不得借 challenge 获取超范围数据或稳定跟踪标识；
5. **重放/跨设备/跨世代攻击**：旧 evidence、旧进程、旧设备、旧策略或旧 nonce
   不得被接受；
6. **供应链攻击**：合法发布者签名不能掩盖运行时被篡改或依赖被替换；
7. **资源耗尽**：畸形证据、超大声明、签名链、并发 challenge 和审计溢出必须有界
   失败并回收资源。

## 提议的证据分层

以下等级只用于规范草案，不是已发布 ABI：

| 等级 | 可声明内容 | 不可声明内容 |
| --- | --- | --- |
| `software-observation` | 调用者授权的当前软件观察值、测量的范围和缺口 | 受硬件保护的启动状态或设备真实性 |
| `signed-static-package` | `.jaso` 内容摘要、发布者签名和静态供应链来源 | 当前进程未被篡改或没有作弊行为 |
| `protected-system-measurement` | 由经验证的受保护启动/系统组件产生的测量 | 业务无风险或第三方自动信任 |
| `hardware-backed` | 由明确硬件信任根和设备证明密钥背书的证据 | 所有设备和验证方自动支持 |

任何结果必须携带 `measurement_scope`、`coverage_gaps`、`source`、`validity`、
`nonce`、`subject_generation`、`policy_epoch` 和撤销状态。缺字段不能默认为完整。

## 用户态服务边界

未来 Jasper Trust Service 可包含：

- Evidence Collector：只经授权读取应用/服务/模块/设备允许披露的事实；
- Attestation Broker：组装证据并调用 Provider，不决定全局授权；
- Verifier：验证签名链、范围、nonce、freshness、generation 与撤销；
- Policy Evaluator：评价验证结果并产出有解释的行业 Profile 决策；
- Provider Registry：签名并版本化硬件/软件 Provider，不按厂商硬编码默认可信；
- Privacy/Audit Service：最小披露、访问审计、撤销与 retention 策略。

这些服务必须使用现有 Process/Workload、Channel、Handle/Rights、PEP 和资源配额。
它们不能通过管理业务权限记录而成为第二全局权限源。

## 首个最小纵向切片

在独立规范批准后，最小切片应从已有能力开始：

```text
受测量的 .jaso 应用装载
  -> 生成进程/应用/对象 generation 事实
  -> 受权 Collector 读取测量和范围
  -> 依赖方提供随机 nonce
  -> 用户态 Broker 组装低等级软件证据
  -> 用户态 Verifier 验证签名、nonce、范围和有效期
  -> Policy Evaluator 返回有解释的结果
  -> 撤销/更新/重启使旧结果失效
```

该切片只能声明软件静态签名和运行时主体绑定，不能声明硬件可信启动或“无作弊”。

## 必须新增与不应新增

必须由用户态服务实现：

- Evidence/Challenge/Result/Policy/Provider 版本化 Schema 与协商；
- nonce、freshness、撤销和重验；
- 第三方验证器与隐私最小披露；
- 行业 Profile 与业务依赖方决策。

只有在现有机制确认不可替代时，才研究最小内核原语：

- 受保护的启动测量绑定；
- 不可伪造的测量/证明密钥访问；
- 硬件证据获取与防重放单调状态；
- 证据来源与当前对象世代的原子绑定。

明确不应新增：

- 任意进程扫描或跨域调试 ABI；
- 第二套主体、权限、审计或对象生命周期；
- Windows 驱动/反作弊 ABI 或自动兼容声明；
- 由内核直接执行行业作弊判定；
- 为单一 TPM/TEE/云 Provider 写死的强制依赖。

## 结论

Issue #46 当前适合完成阶段 A：复用矩阵和威胁模型已经可以从现有 SEC、`.jaso`、
Driver Host 和 LC 防回滚能力得出。生产 Trust Framework、RATS/EAT 互操作、
真实 TPM/TEE Provider、远端验证器和游戏 Profile 都需要后续独立设计、ABI 裁决和
真实硬件验收，不能由本轮审计关闭。
