# 兼容图形 WSI 输入容量切片

更新时间：2026-11-19。

状态：**隐藏的固定 32 项输入队列已移除；窗口、surface 与输入队列均由调用方
显式选择容量。**

## 实现

- `Wsi<W, S, Q>` 的第三维 `Q` 表示归一化输入事件队列容量，与窗口数 `W` 和
  surface 数 `S` 同级；
- 不再导出或读取全局 `INPUT_QUEUE_CAPACITY=32`；
- `GraphicsService<W, S, Q>` 把同一个 `Q` 传给内部 WSI，避免服务层重新引入隐藏
  容量；
- 销毁窗口、环形出队、容量拒绝和 Default 初始化均使用 `Q`；
- 单元测试使用 `Q=3`，验证第 4 个输入事件被明确拒绝，证明行为不依赖旧 32 槽。

WSI 仍不创建真实 X11/Wayland/DRM surface；本切片不改变 Vulkan 与显示后端边界。

## 验证

```text
cargo test -p jasper-compat-graphics
19 passed; 0 failed

python3 scripts/check-hardcode-gate.py --inventory
344 findings; runtime-resource-capacity 68 unique fingerprints
```

## 尚未完成

- 当前调用方仍需在创建 `GraphicsService` 时选择具体 `Q`，尚无统一的用户态
  图形服务预算配置入口；
- 真实 Wayland/X11/Android WSI、物理 GPU 和输入延迟矩阵不属于本容量切片；
- Issue #35 其余 68 个运行期容量项仍未清零。
