# COMPAT-GRAPHICS-1 software Vulkan acceptance

Command:

```text
COMPAT_GRAPHICS_OUT=/home/auth/.codex/worktrees/compat-graphics-agent2/evidence/compat-graphics-software-compute-r9 bash scripts/compat-graphics-software-check.sh
```

The Jasper root userland loaded the unmodified Vulkan loader and SwiftShader
ICD, then ran the upstream metal2vulkan compute example. All 1000 output values
matched the upstream expectation and the process returned to the resource
baseline.

This proves the declared software Vulkan path only. It does not prove a physical
GPU backend, metal2vulkan render-to-texture/WSI, hardware display, DXVK/VKD3D
execution, GPU reset, DMA silence, IOMMU isolation or performance. The current
render example reaches the fragment pipeline but faults at
`ip=0x100086f1909d` while reading `0x10006e4ba4f0`; it remains a diagnosed
pending compatibility bug.
