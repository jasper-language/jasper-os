# Jasper UI Engine 宿主适配骨架

更新时间：2026-11-18。

状态：**Jasper-OS 用户态宿主 crate、RGBA Surface 路径和真实 CPL3 Service
启动/失败关闭路径已建立；固定 UI Engine 仍因 `std` 依赖无法进入 Jasper 原生目标。**

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
  固定 engine 未就绪时返回携带相同 client/request/sequence 的 JSUI Error 帧，
  payload 为 `service.ui.error.engine_unavailable`，并以 69 失败关闭，不生成
  伪造渲染帧；响应发送失败返回 70，接收或解码失败返回 68，错误 kind 返回 65；
- `kernel::ui_process_demo` 把该 ELF 嵌入 Jasper-OS 验证内核，建立真实宿主与
  Service Channel，在 CPL3 调度 Service，并检查退出码 69、JSUI 错误帧、Console
  存活以及对象、固定帧、Channel 队列和页帧回收；
- `kernel-core::display_input::PixelLayout` 增加 RGBA，Compositor 与 framebuffer
  写入路径按 R/G/B/A 顺序处理，匹配 CPU Engine 的 RGBA8 输出。

固定 Engine 仍为：

```text
commit=4194117011f13fdc063977683162fd5a145c85d7
feature=native-engine-cpu
target-status=blocked-no-std
```

## 验证

```text
cargo test -p user-ui-service --lib
4 passed; 0 failed

cargo check -p user-ui-service \
  --target x86_64-unknown-none --features native-transport
PASS

cargo check -p jasper-kernel \
  --target x86_64-unknown-none --no-default-features \
  --features ui-process-verify
PASS

cargo test -p kernel-core 'display_'
27 passed; 0 failed

bash scripts/ui-process-check.sh
ui-process: PASS cpl3=true channel=true jsui=true \
  engine=blocked-no-std exit=69 terminal=true resources=true
qemu_rc=33
```

## 尚未完成

- 另一开发线需在 UI Engine 仓库提供 Jasper-OS 可构建的 `no_std + alloc` core；
- 将真实 Engine `HostRenderer`/`HostInbox` 实现接入 `EngineHost` 与 Channel 协议；
- 在 Jasper-OS UEFI 系统镜像中接入该 CPL3 Service，完成真实首帧、键盘/指针输入、
  Surface 重建和服务退出重启；
- 把 UI service 接入 LC-2 签名组件安装、健康检查和回滚；
- 多应用窗口、IME、无障碍、字体资源和真实 Vulkan/WSI 路径。
