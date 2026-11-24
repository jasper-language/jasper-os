# NET-4：独立 netd 进程生命周期

更新时间：2026-11-21。

状态：**hosted 用户态进程边界已实现并测试；NET-4 仍保持 core-passed。**

## 已实现

- `netd` 现在有独立的 `jasper-netd` 二进制入口，而不是只能被其他宿主程序
  作为库调用；
- bind、证书、私钥、连接数、流字节和 datagram 字节都来自显式启动参数，
  零值和缺失值在绑定前拒绝；
- `--check` 会实际解析 PEM、构造 rustls/Quinn TLS 配置，只有完整材料有效时
  才输出 `configuration-valid`；
- 启动成功后立即报告实际绑定地址，SIGINT/SIGTERM 触发同一个关闭路径；
- 关闭会等待 QUIC 连接 drain，并输出 accepted/rejected/active/completed/
  streams/errors 终态统计；关闭超时会失败返回，不伪装成功；
- QUIC/TLS 继续使用 Quinn/rustls，没有手写密码学或协议数据面。

## 验证

```text
cargo test -p jasper-netd
12 + 2 passed; 0 failed

python3 scripts/check-hardcode-gate.py --base HEAD
PASS
```

使用临时自签 PEM 执行 `--check`：

```text
jasper-netd state=configuration-valid bind=127.0.0.1:4433
max_connections=2 max_stream_bytes=4096 max_datagram_bytes=1200
```

真实启动到 `127.0.0.1:0` 后报告绑定地址，发送 Ctrl-C：

```text
jasper-netd state=Starting bind=127.0.0.1:42760
jasper-netd state=stopped accepted=0 rejected=0 active=0 completed=0
streams=0 errors=0
```

## 尚未关闭

- 该进程仍是 hosted std 服务，尚未进入当前 Jasper no_std CPL3 用户运行时；
- 尚未通过 Jasper UDP socket ABI 与内核 virtio-net、服务生命周期和统一授权
  完成端到端接线；
- 尚未执行外部 WireGuard/QUIC peer、真实丢包/迁移、PMTUD/ICMP
  frag-needed 和物理网络验收；
- 因此不得把本切片升格为 NET-4 done 或生产网络完成证明。
