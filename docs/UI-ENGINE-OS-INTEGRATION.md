# Jasper UI Engine 与 Jasper-OS 集成边界

更新时间：2026-11-18。

状态：**精确版本与边界已锁定；`no_std-core` 已在 Jasper-OS CPL3 UI Service
中完成 Typed UI IR → CPU RGBA8 → JSUI Present 首帧集成。输入、合成器采纳和
物理显示仍未完成。**

## 精确版本

- 仓库：`https://github.com/jasper-language/jasper-ui-engine`
- commit：`b21dec1ae504a06923defcc715722c7b9e9c1dc8`
- 版本/许可：`0.1.0` / Apache-2.0
- Cargo feature：只选择 `no-std-core`
- `Cargo.lock`、`Cargo.toml`、许可证 digest 固定在 `ui-engine.lock.toml`
- Jasper UI Engine 不进入 `kernel` 或 `kernel-core`；宿主 loopback 不作为 OS
  集成验收

## 已核实

在精确 commit 上：

```text
RUSTUP_TOOLCHAIN=nightly-2026-10-17 cargo check --locked \
  --target x86_64-unknown-none --no-default-features --features no-std-core --lib
PASS

cargo test -p user-ui-service --features native-engine-core --lib
5 passed; 0 failed
```

镜像级 `scripts/ui-process-check.sh` 通过真实 CPL3 Service、原生 Channel、
16,384 字节 RGBA8 Present 帧、进程退出和资源回收检查：

```text
ui-process: PASS cpl3=true channel=true jsui=true engine=cpu \
  rendered=true present=true exit=0 terminal=true resources=true
qemu_rc=33
```

证据为 `evidence/ui-process-20261118-203825/`，来源审计见
`evidence/ui-engine-cpu-b21dec1/README.md`。这只关闭首帧集成，不关闭 UI-OS-1。

## 宿主映射

| UI Engine 契约 | Jasper-OS 宿主责任 |
| --- | --- |
| `HostInbox` 会话、序号、背压、重连 epoch | 用户态 UI Service 通过原生 Channel/Ring 提供真实传输、主体与审计 |
| `Scene` / `Typed UiBatch` | 当前经 JSUI v1 Scene 帧接收严格 Typed UI IR；稳定 ABI 注册仍未完成 |
| `HostRenderer` CPU Surface 代际 | 系统显示/合成服务的真实 Surface 所有权和撤销 |
| `submit_rgba8` / `present` | Jasper 显示宿主写入经授权的 framebuffer/Surface，不由内核链接引擎 |
| 规范化指针、触摸、键盘、IME | `service.ui.input.*` 与现有系统输入归属 |
| AccessKit 语义/动作 | `service.ui.accessibility.*`，不能绕过统一授权 |
| Surface pause/resume/retire | UI Service 恢复、崩溃隔离和 Console 救援边界 |

`service.ui.*` 目前仍是逻辑命名研究，不因本审计注册新 ABI。

## 最小可行端口

1. **已完成**：UI Engine 独立仓库提供 `no_std + alloc` core；std 文件、时钟、
   字体、图片和窗口路径留在 host feature，不进入 bare-metal 分支。
2. 把 CPU native 适配层的字体、图片、时间、错误 I/O 从 OS 文件系统移到显式
   注入的 Jasper 宿主能力；不得在引擎中直接调用 Linux syscall。
3. **首帧部分已完成**：Jasper 用户态 UI Service 精确依赖固定 Engine commit，
   通过原生 Channel 收场景并生成宿主拥有的 RGBA8 Surface。尚未把该 Surface
   接入合成器采纳、物理显示、输入和 Surface 重建。
4. 在同一镜像完成首帧、输入、present、服务死亡、重启、资源回收、越权负例和
   Console 救援；之后才进入 LC-2 签名升级、回滚和跨版本验收。

## 当前禁止宣称

- 禁止把 Engine 拷入内核或 `kernel-core`；
- 禁止把 Ubuntu/Wayland、Windows、Android、host loopback 或 `target check`
  当作 Jasper-OS UI Service 已完成；
- 禁止以固定截图、mock IPC 或 CPU compositor 冒充官方 Engine；
- 禁止在真实 Jasper Vulkan Loader/驱动/WSI 路径通过前宣称原生 GPU UI 完成。
