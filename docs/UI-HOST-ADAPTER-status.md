# Jasper UI Engine 宿主适配骨架

更新时间：2026-11-18。

状态：**Jasper-OS 用户态宿主 crate、RGBA Surface 和真实 CPL3 Service 已接入固定
UI Engine `no_std-core`，Scene/Patch/Input/Present 会话和原生 framebuffer 采纳已通过；
QEMU i8042/PS-2 键盘到 JSUI Input 的原生路径已通过；物理键盘、显示资格和重启
链路仍未完成。**

## 已实现

- 新增独立 `user/ui-service` workspace crate，不链接内核，不修改或复制
  `jasper-ui-engine`；
- `EngineHost` 接口把场景更新、CPU RGBA 渲染与宿主 Surface 生命周期分开；
- `CpuFrame` 校验实际 Surface 几何、帧字节数、scene version、Surface generation
  和单调 sequence；
- `SurfaceBinding` 拒绝错误 Surface、陈旧 generation 与重复/回退 sequence；
- `NativeUiEndpoint` 通过真实 Jasper Channel 句柄收发 UI 服务消息；
- `NativeUiEndpoint::receive_frame/send_frame/send_frame_into` 直接调用
  `kernel-core::ui_protocol` 的 JSUI v1 编解码；未知版本、Magic、kind、flags、
  generation、request id、截断和尾随数据由协议层失败关闭；
- `ui-service` 进程从启动者接收一个预打开 Channel，消费真实 JSUI Scene 请求；
  开启 `native-engine-core` 时，`CpuEngineHost` 使用固定 Engine 严格解析 Typed UI IR、
  执行布局/绘制并写入宿主拥有的 RGBA8 Surface，随后返回携带相同
  client/request/sequence 的 JSUI Present 帧；随后消费 JSUI Patch 并渲染新 revision，
  再消费 JSUI Input，
  Engine 校验焦点节点 Activate 权限/身份/代际并渲染第二帧，Close 后正常退出；
- 原生显示会话增加互斥输入路由：UI 捕获期间按键只交给 UI 宿主，终端不会抢先
  消费；验证脚本在 QEMU 中向真实 i8042/PS-2 控制器发送 Enter，内核轮询驱动把
  set-1 `0x1C` 转为 `0x0103`，UI 宿主再映射为 JSUI `28` 并发送 Input 帧；
- 未开启 `native-engine-core` 的构建保留显式 `UnavailableEngine` 失败关闭路径；
  任何帧发送都受单条原生 Channel 消息上限约束，不把 JSUI 头之外的载荷按
  64 KiB 独立计算；
- `kernel::ui_process_demo` 把该 ELF 嵌入 Jasper-OS 验证内核，建立真实宿主与
  Service Channel，在 CPL3 调度 Service，并检查 64×64 RGBA8 像素、退出码 0、
  Service/Channel 资源基线、Console 存活；随后把 Present Surface 注册为原生
  Compositor 第 3 层，中心写入真实 framebuffer 并回读像素；
- 同一镜像连续创建两轮独立的 host/service 进程、Channel 和 Surface generation；
  每轮完成 Scene/Patch/PS-2 Enter/Present 三帧后正常退出，逐轮检查对象、队列、
  pins 和页帧回到该轮基线，总计六帧；
- `kernel-core::display_input::PixelLayout` 增加 RGBA，Compositor 与 framebuffer
  写入路径按 R/G/B/A 顺序处理，匹配 CPU Engine 的 RGBA8 输出。

固定 Engine 仍为：

```text
commit=b21dec1ae504a06923defcc715722c7b9e9c1dc8
feature=no-std-core
target-status=integrated-cpu
```

## 验证

```text
cargo test -p user-ui-service --features native-engine-core --lib
5 passed; 0 failed

cargo check -p user-ui-service \
  --target x86_64-unknown-none \
  --features native-transport,native-engine-core
PASS

cargo check -p jasper-kernel \
  --target x86_64-unknown-none --no-default-features \
  --features ui-process-verify
PASS

cargo test -p kernel-core 'display_'
27 passed; 0 failed

bash scripts/ui-process-check.sh
ui-process: PASS cpl3=true channel=true jsui=true \
  engine=cpu rendered=true present=true patch=true input=true native_keyboard=true \
  frames=6 display=true exit=0 terminal=true restart=true resources=true
qemu_rc=33
```

键盘路径证据见 `evidence/ui-native-keyboard-20261118/`，双会话重启证据见
`evidence/ui-restart-20261118/`。这些结果不冒充物理键盘、Pixel 硬件或崩溃恢复
验收。

## 尚未完成

- 完成物理显示资格和真实硬件键盘/指针/IME 设备输入；
- 接入 Engine `HostInbox` 的持续会话、背压、取消、重连和 Surface 重建；
- 完成 Service 崩溃、Console 救援和重启后的连续帧；
- 把 UI service 接入 LC-2 签名组件安装、健康检查和回滚；
- 多应用窗口、无障碍、字体资源、真实文本和 Vulkan/WSI 路径。
