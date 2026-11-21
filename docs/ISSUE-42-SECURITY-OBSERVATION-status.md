# Issue #42 M10：操作前授权与操作后安全观察

更新时间：2026-11-21。

## 边界

本切片不创建第二授权权威，也不对用户暴露新 syscall/ABI：

- 操作前唯一放行决定仍来自既有 `authz` / `security_domain` PEP；
- `security_observation` 只保存操作终态后的结构化观察事实；
- 观察者 scope 仅过滤已由系统产生的记录，不获得额外操作权限；
- 观察容量必须在副作用前预留，无法预留时副作用不执行；
- 既有 DomainTable 安全审计容量满时，在返回操作决定前失败关闭。

## 状态机

`kernel-core::security_observation::Service<N>` 提供：

1. `reserve()`：在副作用前占用有界观察槽；
2. 调用方执行真实受保护状态变更；
3. `commit()`：仅在效果终态已知后写入观察；
4. `abort()`：效果未尝试时释放预留；
5. `visible(scope)`：按 `Platform`、`Subject(domain)` 或 `Owner(domain)` 过滤。

预留、提交与序列寿命均显式失败，不接受陈旧 reservation。

## 真实矩阵

`kernel/src/security_observation_demo.rs` 使用既有 `DomainTable`：

- Application 通过单一 Ipc gateway 访问 Service 资源；
- Allowed 决定后才执行受保护状态变更，并在成功终态提交观察；
- 撤销 gateway 后同一访问被拒绝，受保护状态不变；
- DomainTable 两条安全审计记录耗尽后，下一次访问在副作用前返回
  `AuditFull`，状态仍不变；
- 观察队列满后，`reserve()` 失败且副作用未发生；
- Subject/Owner scope 只能看到本域事件，外部 Domain 看不到；
- Service compromise 回收资源/gateway，restart generation 隔离旧资源。

## 证据

```text
cargo test -p kernel-core security_observation --lib
3 passed; 0 failed

JASPER_ACCEPT=spot JASPER_CHECKS=sec4 JASPER_ACCEL=kvm \
JASPER_CORES=4-11 JASPER_QEMU_TIMEOUT=360 bash scripts/accept.sh
evidence/accept-20261121-011957
qemu_rc=33
SEC-4 PASS
```

客户机标记：

```text
[JSR-SEC-OBSERVE] pep_once=true after_effect=true deny_no_effect=true \
audit_full_no_effect=true observation_capacity_no_effect=true scope=true \
restart=false resources=true failed=0
```

该结果关闭 M10 的观察后置、scope、审计/观察容量失败关闭和跨域生产矩阵。
Linux seccomp/Landlock/LSM 的协议语义仍属于相应兼容机制，不由本切片扩大为
原生 ABI。
