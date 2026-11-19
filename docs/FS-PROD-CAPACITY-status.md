# FS Production Gate 容量参数化

更新时间：2026-11-19。

状态：**`ProductionFileGate` 不再隐藏默认 64 文件/256 审计记录容量。**

## 实现

`ProductionFileGate<N,A>` 要求调用方显式选择：

- `N`：受安全策略管理的文件对象记录容量；
- `A`：有界审计记录容量。

这两项是具体文件服务实例的准入结果，不在 kernel-core 中由隐藏默认值决定。
现有调用只有测试夹具，分别显式使用 8/32、8/16 和 4/1。

如果未来生产 FS 服务装配该门，必须从对象预算、审计预算和内存配额生成 `N/A`，
并保持 Duplicate、Capacity、AuditFull、Revoke 和 generation 语义不变。

## 验证

现有 `fs_prod` 单元测试覆盖：

- 文件注册、重复拒绝和容量边界；
- MAC/IFC 授权、拒绝与审计顺序；
- 文件 generation 撤销；
- 有界 audit-full 失败关闭。

## 尚未完成

- 尚无生产 `ProductionFileGate` 实例，因此没有真实 FS 服务容量接线；
- 本切片不代表 FS-1-PROD 或 Issue #35 全部完成。
