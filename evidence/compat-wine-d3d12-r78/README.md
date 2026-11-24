# Wine D3D12/VKD3D diagnostic r78

Date: 2026-11-23.

Status: **failed; not a completion claim**.

The unmodified Wine 11.22, DXVK 3.1.1, VKD3D-Proton 3.1 and Mesa lavapipe
staging path now reaches the native D3D12 probe with `--service-child`, avoiding
the earlier service-desktop parent. The probe loads:

```text
d3d12.dll
d3d12core.dll
dxgi.dll
DXVK: v3.1.1
```

The process then remains in DXVK/Vulkan device initialization until the bounded
12,076-tick deadline and is killed with code 124. No
`D3D12_PROBE_OK` is produced, so D3D12/VKD3D remains open.

The preceding diagnostic runs established two separate facts:

- the earlier `Failed to load libvulkan.so.1` was a staging omission, not a
  Linux ABI failure;
- substituting Wine's built-in DXGI requires the `wined3d.dll` and
  `opengl32.so` closure and then fails at Wine desktop creation in the
  headless path.

The current failure is therefore before a meaningful VKD3D semantic verdict.
It must be diagnosed as an initialization/resource issue without weakening the
gate or claiming semantic inconsistency.
