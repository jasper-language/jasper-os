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
sha256=66e6ad288b6fda73585f1799230a0d1d75d20f5a0e7ec099f6fd7008c4dc0661
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
- 载荷、SBOM、manifest 或签名任一改变都失败关闭；实际内核载荷
  `66e6ad…c0661` 与 SBOM `59da70…90969` 通过上述完整演练。

新增 `release/vulnerabilities.toml` 与 `scripts/check-vulnerabilities.py`：
生产登记表当前为空；确定性演练数据覆盖 Critical/High 响应与修复期限、受影响范围、
缓解、stable/LTS 两条回补通道、发布号和完整回补 commit。已回补记录必须同时具备
两个通道，任一通道超过 24 小时响应或对应修复期限即失败。

该演练使用临时测试密钥，不包含生产私钥，也不冒充真实生产发布签名。

## 仍未完成

- 生产 release/LTS 通道密钥托管、签名审计与旧制品删除策略；
- LC-2 action 执行/断电矩阵和 LC-4 真实设备矩阵。

因此 LC-5 不升级状态。
