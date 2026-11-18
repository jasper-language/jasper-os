# LC-5 Stable/LTS 发布准备

更新日期：2026-11-17。

状态：**in-progress；LC-2 与 LC-4 的真实设备/事务出口完成后才能升级**。

## 当前切片

新增 `scripts/release-sbom.py`，从锁定依赖和 workspace 元数据生成确定性
CycloneDX 1.5 SBOM：

- 包含全部 workspace 与 Cargo.lock 包、版本、许可证、source 与依赖图；
- registry 包使用 Cargo.lock checksum；
- workspace 包按 Git 跟踪文件和路径内容计算 SHA-256 源码摘要；
- 缺少 workspace 许可证、组件引用重复、无来源摘要或两次生成不一致时失败；
- 文档不包含时间戳、随机 serial number 或机器路径，保证相同源码产生相同字节。

CI 使用 `--check` 连续生成两次并比较。

新增 `scripts/release-repro-check.sh`：用固定工具链/lockfile、
`SOURCE_DATE_EPOCH=0`、关闭 incremental、相同 RUSTFLAGS 和 CPU 亲和执行两个
完全独立的 x86_64 no-default-features kernel release build，要求 ELF SHA-256
一致。默认尝试本机验收预算 `4-11`；宿主或 CI 的 cpuset 不允许该集合时，
明确记录 `affinity=scheduler-selected` 后由调度器选核，不放宽两次构建的字节
一致性。该检查不启动 VM。

当前实测：

```text
release-repro: PASS target=x86_64-unknown-none
sha256=eb6eeb387c592da0089d04a42337c1fe6d4324c1c9fe55decd3c3a691bd2e644
```

在故意请求不可用 cpuset 的 fallback 路径中，两次独立构建仍得到上述同一
SHA-256；CI 托管运行器不再因固定的 `4-11` 亲和失败。

`release/release-policy.toml` 与 `scripts/check-release-policy.py` 定义了 stable
和 LTS 通道、支持期、漏洞响应时限，以及 SBOM、reproducible build、签名清单、
离线源和至少两个更新源的强制策略。CI 验证通道唯一性、LTS 支持期、漏洞期限、
workspace 许可证和所需供应链工具存在。

新增 `scripts/release-artifact.py`、`scripts/release-source-drill.py` 和
`scripts/release-supply-check.sh`：

- release manifest 是固定 Schema 的规范 JSON，Ed25519 签名带
  `JASPER-RELEASE-V1` 域分隔；签名者身份由公钥 DER 的 SHA-256 派生，不能由
  调用者任意声明；
- manifest 绑定 stable/LTS 通道、ABI、目标、完整源码 commit、内核载荷字节数/
  SHA-256 和 SBOM 字节数/SHA-256；验证不读取主机绝对路径；
- 信任目录只接受与签名者指纹精确匹配的唯一公钥，撤销表优先于信任根；测试已覆盖
  撤销旧键、加入新键、撤掉旧根后的根轮换；
- 两套独立 HTTPS loopback 源使用临时 CA 与主机名验证，逐文件比较两个在线源和
  一个离线副本；主源对象缺失时只从镜像取得完全相同字节；
- 载荷、SBOM、manifest 或签名任一改变都失败关闭；ABI 3.18 内核载荷
  `eb6eeb…e644` 与当前 SBOM `475d05…9a84` 通过上述完整演练。

新增 `release/vulnerabilities.toml` 与 `scripts/check-vulnerabilities.py`：
生产登记表当前为空；确定性演练数据覆盖 Critical/High 响应与修复期限、受影响范围、
缓解、stable/LTS 两条回补通道、发布号和完整回补 commit。已回补记录必须同时具备
两个通道，任一通道超过 24 小时响应或对应修复期限即失败。

该演练使用临时测试密钥，不包含生产私钥，也不冒充真实生产发布签名。

新增 `scripts/release-revocations.py`、`scripts/release-revocations-check.sh` 与
release policy 的 `require_signed_revocation_snapshot`：

- 撤销快照由独立治理密钥签名，不能由被撤销的发布签名密钥自行决定撤销状态；
- 快照使用单调 epoch 与前序快照 SHA-256 链，只接受精确后继；当前快照可幂等重放，
  陈旧 epoch、跳号和错误前序摘要均失败关闭；
- 撤销集合只增不减，任何删除既有撤销项的尝试都会被拒绝；
- 状态保留已签名快照与签名；status/accept/export 使用外部治理公钥重新验证，
  修改 revoked 集合或快照内容不能仅靠同步改写两份状态绕过；
- 两份持久状态副本必须逐字节一致，分歧时 status/accept/export 均拒绝继续；
- 审计 journal 先于状态写入并形成连续 epoch 链；若状态写前中断，只有精确匹配
  journal 末项的快照能完成恢复，不能借此跳过 epoch；
- 导出给发布验证器的撤销列表来自已接受的签名快照，而不是调用者可任意改写的原始
  文本；
- CI 覆盖签名篡改、精确重放、陈旧重放、epoch 间隔、前序错误、删除撤销项、
  双副本分歧和中断恢复。

本地双副本与审计日志可以发现普通文件回滚和副本分歧，但不具备 TPM/安全单调计数器
的物理回滚保护；生产密钥托管、审计远端留存和硬件背书仍属于未完成的生产发布门。

新增 TPM2 硬件单调锚适配层：

- `accept`、`export` 和 `status` 默认要求 `--tpm-nv-index`，并调用现成
  `tpm2_nvincrement` / `tpm2_nvread`；只有显式
  `--development-software-anchor` 的测试路径可以跳过硬件锚；
- 新快照先写 durable increment intent，再执行 TPM 递增，必须读回恰好
  “前值 + 1”才能写审计和撤销状态；
- anchor 同时绑定 TPM 计数值与签名快照 SHA-256；状态/TPM 回退、未登记的 TPM
  增量、错误 8 字节读数、工具失败/超时或残留未完成 intent 均失败关闭；
- 同一快照重放只读取并核对硬件计数，不重复递增；递增命令已成功但读回/状态
  写入中断时，下一次重试只完成同一次 intent，不跳过计数值；
- 自动化和负例测试使用临时 fake TPM executable，只证明调用协议、持久顺序与
  失败语义，不改写为“真实 TPM 已验证”。

生产调用形态：

```text
python3 scripts/release-revocations.py accept \
  --snapshot ... --signature ... \
  --governance-public-key ... --state-dir ... \
  --tpm-nv-index 0x01800001
```

实际 NV index、owner/NV auth、TPM 资源管理器和 salted session 必须由发布环境
提供；当前宿主未安装 `tpm2-tools`，因此尚无真实 TPM 计数器证据。

## 2-of-3 发布门限

`jasper.release-artifact/v2` 将以下事实纳入同一签名消息：

- stable/LTS 通道、源提交、ABI、目标架构；
- payload 与 SBOM 的名称、大小和 SHA-256；
- 三个互不相同的签名者指纹；
- 门限值 2，以及每个指纹对应的签名文件名。

验证端执行以下失败关闭规则：

- 少于两个独立签名时拒绝；
- 同一签名文件重复提交时拒绝；
- 未声明文件、未知公钥或非 64 字节 Ed25519 签名时拒绝；
- manifest 声明的任一签名者已撤销时拒绝；
- manifest、payload、SBOM 或签名文件被篡改时拒绝。

`scripts/release-supply-check.sh` 使用三个测试发布密钥完成正反例：3-of-3 和
2-of-3 成功、1-of-3 拒绝、重复签名拒绝、撤销密钥拒绝、轮换到新的 B/C/D
三密钥集合后 2-of-3 成功，并从两个认证 HTTPS 源和一个离线副本得到相同字节。

```text
release-policy: PASS channels=stable,lts sources>=2 signatures=2-of-3
release-supply-check: PASS threshold=2 signers=3 revocation=true
  revocation_snapshot_epoch=2 rotation=true https_sources=2
  offline_sources=1 tamper_rejected=true
```

## 仍未完成

- 生产发布私钥只能由相互隔离的 HSM/离线签名环境持有，本仓库不保存生产私钥；
- TPM2 适配代码已存在，但仍需在真实 TPM 2.0 或等价硬件上完成 NV 索引 provisioning、
  auth/session、断电恢复、计数回退拒绝与远端审计证据；fake TPM 不能关闭该门；
- 远端不可篡改审计留存、签名仪式与双人操作的现场证据尚未完成；
- CVE 响应期限、补丁回移、实际 stable/LTS 发布和旧版本再次升级尚未形成真实
  发行闭环；
- LC-5 依赖 LC-2、LC-3、LC-4 的完整退出门，当前不能升级为 done。
