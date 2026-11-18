# Jasper UI Service 契约切片（UI-OS-1 前置）

更新时间：2026-11-18。

状态：**宿主契约、真实 CPL3 UI Service Scene/Patch/Input/Present 三帧会话和原生
Compositor/framebuffer 采纳通过；硬件输入、物理显示资格、多应用窗口和重启链路仍未完成。**

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

scripts/ui-process-check.sh
engine=cpu rendered=true present=true patch=true input=true frames=3 display=true exit=0 resources=true
PASS

python3 scripts/check-gpu-abi-boundary.py --self-test
PASS
```

覆盖双客户端焦点隔离、输入 owner 拒绝、跨客户端帧票据拒绝、授权/操作不匹配拒绝、
关闭后 generation 更新以及服务失败后旧客户端失效。

## 尚未完成

- 完成物理显示资格和 Surface 生命周期接线；
- 完成长时间持续 Patch、真实硬件键盘/指针输入、Surface 重配和服务重连；
- 在 Jasper-OS UEFI 系统镜像中完成服务崩溃后 Terminal/Console 救援和重启资源回基线；
- 多应用窗口策略、IME、无障碍、字体资源、GPU/Vulkan 路径和 LC-2 组件更新。
