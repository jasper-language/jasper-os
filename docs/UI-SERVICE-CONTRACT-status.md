# Jasper UI Service 契约切片（UI-OS-1 前置）

更新时间：2026-11-18。

状态：**宿主契约软件切片通过；Jasper UI Engine 进程与真实系统镜像端到端仍未完成。**

## 本切片

`kernel-core::ui_service` 在既有机制上组合出后端中立的 `service.ui.*` 逻辑契约：

- 使用现有 `DisplayInputSession`、`Compositor`、`FrameTicket`、Surface 和键输入队列，
  不创建第二套窗口、渲染、显示或输入机制；
- 每个客户端持有独立、带 generation 的 `UiClientKey`；关闭后复用槽位会生成新代，
  旧 token 不能复活；
- 焦点唯一；非焦点客户端不能读取输入，错误 owner/scope 不能跨应用读取；
- 帧票据绑定准备它的客户端，其他客户端即使拿到票据也不能提交；
- 服务失败提交唯一终态并清空全部客户端，Linux/Terminal 等救援路径不依赖该服务；
- `UiCapability` 只接受共享 `authz::Decision`：operation、effect、subject、scope
  和 admitted reason 必须精确匹配，调用者不能传入布尔值伪造授权；
- 新增逻辑操作仅为 `service.ui.session.create/close`、`service.ui.focus.set`、
  `service.ui.frame.present`、`service.ui.input.read`，**没有登记内核 syscall ID**；
- 契约不包含 `Vk*`、Vulkan 句柄、GPU 后端选择或 UI Engine 源码。
- `ui_protocol` 定义版本化 `JSUI` Scene/Patch/Input/Present/Cancel/Close/Error
  帧，载荷对内核不透明；Handle/MemoryObject 仍通过既有 Channel/对象机制带外
  转移，未增加 syscall。

## 验证

```text
cargo test -p kernel-core ui_service -- --nocapture
3 passed; 0 failed

python3 scripts/check-gpu-abi-boundary.py --self-test
PASS
```

覆盖双客户端焦点隔离、输入 owner 拒绝、跨客户端帧票据拒绝、授权/操作不匹配拒绝、
关闭后 generation 更新以及服务失败后旧客户端失效。

## 尚未完成

- 把版本化帧接入真实 Jasper IPC/Ring 服务入口，不新增内核 syscall；
- 集成锁定 commit 的 Jasper UI Engine 用户态 CPU 服务；
- 在 Jasper-OS UEFI 系统镜像中完成首帧、真实键盘/指针输入、Surface 重配、服务
  崩溃后 Terminal/Console 救援和重启资源回基线；
- 多应用窗口策略、IME、无障碍、字体资源、GPU/Vulkan 路径和 LC-2 组件更新。
