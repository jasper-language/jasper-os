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
一致。该检查不启动 VM。

当前实测：

```text
release-repro: PASS target=x86_64-unknown-none
sha256=66e6ad288b6fda73585f1799230a0d1d75d20f5a0e7ec099f6fd7008c4dc0661
```

## 仍未完成

- release/LTS 通道、补丁回源和删除策略；
- 签名 release artifact 与信任根轮换；
- 漏洞公告扫描、受影响版本、缓解和回补跟踪；
- 离线与多个在线更新源的真实发布演练；
- LC-2 action 执行/断电矩阵和 LC-4 真实设备矩阵。

因此 LC-5 不升级状态。
