# LC-2 断点续传与更新源高可用

更新时间：2026-11-18。

状态：**软件闭环候选；LC-2 仍为 core-passed，Pixel 实机验收暂停**。

## 当前切片

`jasper-lifecycle-staging` 新增持久化下载 spool。每次尝试都先重新读取并验证清单与
签名；只有认证后的完整清单摘要相同，才能继续使用已有部分工件。spool checkpoint
绑定清单 SHA-256，不同已签名清单不能混用同一个 spool。

- 离线目录与 HTTPS 来源实现同一 `resume_artifact` 契约；
- HTTPS 通过 `Range: bytes=<durable-offset>-` 继续传输，并禁止内容编码改变字节；
- 已持久化的部分文件只能在长度等于 checkpoint 偏移时继续；
- 清单必须先通过同一 `TrustPolicy` / `ThresholdTrustPolicy`；
- 镜像按调用方声明顺序尝试；认证失败、工件错误或摘要错误会切换到下一镜像；
- 镜像返回的清单摘要必须与首个成功认证的清单完全相同；
- 完整工件仍由认证清单中的大小和 SHA-256 复核，失败工件会清零后从下一镜像重取；
- 下载失败保留已验证清单对应的部分文件，供下一次调用续传；
- 下载和最终 staging 完成后 spool 才删除。
- 镜像长期健康快照由调用方显式给出路径，只持久化镜像身份哈希、成功/失败次数和
  本地单调序号；健康评分仅改变尝试顺序，不参与签名、授权、反回滚或摘要判断。
- 健康快照使用固定版本头、原子临时文件发布、`fsync` 父目录和
  `O_NOFOLLOW`；每次发布使用进程号与单调序号组成的独立临时文件，快照损坏、
  零/重复身份或长度/计数不一致会失败关闭。
- HTTP 镜像的持久身份必须由调用方显式提供稳定哈希，不从可能携带凭据或查询参数的
  URL 自动派生；未提供身份的镜像保持调用方顺序。

该接口不把 URL、镜像优先级、HTTP 状态或传输身份作为授权事实，也不改变现有
`UpdateService` generation、grant、签名、反回滚、事务和启动控制权威。

## 测试

当前 Rust 测试覆盖：

- 首个镜像传输 7 字节后主动断开，第二个镜像从持久偏移继续并完成；
- 无效签名的优先镜像不阻止后续受信镜像；
- 受信但内容错误的镜像被工件摘要拒绝，随后从正确镜像重取；
- 同一 spool 不能切换到另一份已签名清单；
- 真实 loopback HTTP 服务第一次主动断连，第二次以 `Range` 返回剩余字节；
- `UpdateService::prepare_from_sources` 通过续传 spool 发布 `Prepared` generation。
- 镜像 A 的工件摘要失败后，镜像 B 成功；写入持久健康快照后，第二次材料化先尝试
  已知健康的 B，而不是重新优先尝试失败的 A。
- `UpdateService::prepare_from_sources_with_health` 使用同一路径发布 `Prepared`
  generation。
- 八个并发健康快照发布者不会共享临时路径，最终快照仍可重新载入。

```text
cargo test --locked -p jasper-lifecycle-staging
49 passed; 0 failed

cargo clippy --locked -p jasper-lifecycle-staging --all-targets -- -D warnings
passed
```

## 仍未关闭

- Pixel 6a 更新/断电/回滚实机验收按当前优先级暂停；
- 生产发布端点仍需要 HSM/TPM、远端不可变审计和真实多源运维证据；
- HTTP `Range` 仅接受服务器返回的精确剩余字节；忽略 Range 或返回额外字节的来源会
  失败关闭，不会被静默拼接；
- LC-2 的 Issue #38 企业策略、完整 Schema 迁移、受权轮换服务和真实设备生命周期
  仍未完成。

本切片不能把 LC-2 或 Issue #21 标记为 done。
