# Jasper UI Engine 与 Jasper-OS 集成边界

更新时间：2026-11-18。

状态：**精确版本与边界已锁定；CPU Engine 宿主测试通过；Jasper 原生目标集成
受 `std` 依赖阻塞。**

## 精确版本

- 仓库：`https://github.com/jasper-language/jasper-ui-engine`
- commit：`4194117011f13fdc063977683162fd5a145c85d7`
- 版本/许可：`0.1.0` / Apache-2.0
- Cargo feature：只选择 `native-engine-cpu`
- `Cargo.lock`、`Cargo.toml`、许可证 digest 固定在 `ui-engine.lock.toml`
- Jasper UI Engine 不进入 `kernel` 或 `kernel-core`；宿主 loopback 不作为 OS
  集成验收

## 已核实

在干净 worktree 的精确 commit 上：

```text
cargo test --locked --no-default-features --lib
180 passed; 0 failed
```

这证明宿主无关核心及现有测试在该提交上可复现，不代表 Jasper-OS 运行通过。

同一提交对 Jasper 当前用户态目标构建时，即使关闭 Cargo 默认特性，仍启用：

- `serde/std`
- `serde_json/std`
- `taffy/std`

代码本身还使用 `std::collections`、文件/错误 I/O、时间、字体注入和原生 CPU
渲染栈。目标检查首先在 `memchr` 的 `extern crate std` 失败。`native-engine-cpu`
的 Blitz/Vello 路径会引入更多 `std` 依赖。

## 宿主映射

| UI Engine 契约 | Jasper-OS 宿主责任 |
| --- | --- |
| `HostInbox` 会话、序号、背压、重连 epoch | 用户态 UI Service 通过原生 Channel/Ring 提供真实传输、主体与审计 |
| `Scene` / `Typed UiBatch` | 未来版本化 `service.ui.gui.*` 场景入口 |
| `HostRenderer` CPU Surface 代际 | 系统显示/合成服务的真实 Surface 所有权和撤销 |
| `submit_rgba8` / `present` | Jasper 显示宿主写入经授权的 framebuffer/Surface，不由内核链接引擎 |
| 规范化指针、触摸、键盘、IME | `service.ui.input.*` 与现有系统输入归属 |
| AccessKit 语义/动作 | `service.ui.accessibility.*`，不能绕过统一授权 |
| Surface pause/resume/retire | UI Service 恢复、崩溃隔离和 Console 救援边界 |

`service.ui.*` 目前仍是逻辑命名研究，不因本审计注册新 ABI。

## 最小可行端口

1. 在 UI Engine 独立仓库拆分 `ui-engine-core` 的 `no_std + alloc` 构建：
   用 `alloc`/成熟 no_std 容器替换 std collections，序列化使用 alloc profile，
   文件、时钟、字体和图片读取改为宿主 trait。
2. 把 CPU native 适配层的字体、图片、时间、错误 I/O 从 OS 文件系统移到显式
   注入的 Jasper 宿主能力；不得在引擎中直接调用 Linux syscall。
3. 建立 Jasper 用户态 UI Service crate，精确依赖固定 Engine commit；通过原生
   Channel/Ring 收场景，输出 RGBA8 到现有 framebuffer/Surface，并接入输入与
   Surface 代际。
4. 在同一镜像完成首帧、输入、present、服务死亡、重启、资源回收、越权负例和
   Console 救援；之后才进入 LC-2 签名升级、回滚和跨版本验收。

## 当前禁止宣称

- 禁止把 Engine 拷入内核或 `kernel-core`；
- 禁止把 Ubuntu/Wayland、Windows、Android、host loopback 或 `target check`
  当作 Jasper-OS UI Service 已完成；
- 禁止以固定截图、mock IPC 或 CPU compositor 冒充官方 Engine；
- 禁止在真实 Jasper Vulkan Loader/驱动/WSI 路径通过前宣称原生 GPU UI 完成。
