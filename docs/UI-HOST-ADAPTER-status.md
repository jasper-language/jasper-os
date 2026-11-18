# Jasper UI Engine 宿主适配骨架

更新时间：2026-11-18。

状态：**Jasper-OS 用户态宿主 crate 与 RGBA Surface 路径已建立；固定 UI Engine
仍因 `std` 依赖无法进入 Jasper 原生目标。**

## 已实现

- 新增独立 `user/ui-service` workspace crate，不链接内核，不修改或复制
  `jasper-ui-engine`；
- `EngineHost` 接口把场景更新、CPU RGBA 渲染与宿主 Surface 生命周期分开；
- `CpuFrame` 校验实际 Surface 几何、帧字节数、scene version、Surface generation
  和单调 sequence；
- `SurfaceBinding` 拒绝错误 Surface、陈旧 generation 与重复/回退 sequence；
- `NativeUiEndpoint` 通过真实 Jasper Channel 句柄收发 UI 服务消息；
- `ui-service` 进程从启动者接收一个预打开 Channel；固定 engine 未就绪时输出
  `service.ui.error.engine_unavailable` 并以 69 失败关闭，不生成伪造帧；
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
2 passed; 0 failed

cargo check -p user-ui-service \
  --target x86_64-unknown-none --features native-transport
PASS

cargo test -p kernel-core 'display_'
27 passed; 0 failed

cargo check -p jasper-kernel \
  --target x86_64-unknown-none --no-default-features
PASS
```

## 尚未完成

- 另一开发线需在 UI Engine 仓库提供 Jasper-OS 可构建的 `no_std + alloc` core；
- 将真实 Engine `HostRenderer`/`HostInbox` 实现接入 `EngineHost` 与 Channel 协议；
- 在 Jasper-OS UEFI 系统镜像中启动 UI service，完成真实首帧、键盘/指针输入、
  Surface 重建、服务退出重启和资源回收；
- 把 UI service 接入 LC-2 签名组件安装、健康检查和回滚；
- 多应用窗口、IME、无障碍、字体资源和真实 Vulkan/WSI 路径。
