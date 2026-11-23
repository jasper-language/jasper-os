# Wine D3D12 diagnostic r109

Date: 2026-11-23.

Status: **failed; no D3D12 guest pass is claimed**.

This round disables the Wine explorer override in the D3D12 verification
environment and batches virtual-file materialization instead of acquiring the
process lock once per page. The guest reaches the DXVK/VKD3D and lavapipe
startup path without the prior explorer fault, but Wine then remains in its
headless desktop fallback until the bounded deadline:

```text
get_desktop_window failed to start explorer c0000135
get_desktop_window failed to create desktop window
[JSR-COMPAT-DYNAMIC-FAIL] program=compat-wine-d3d12 stage=deadline_exceeded deadline=12076
```

No `D3D12_PROBE_OK` or `D3D12_PROBE_FAIL` marker is present in this round.
Therefore this is not a VKD3D or Vulkan semantic verdict. The remaining
prerequisite is a Wine desktop/display bridge that lets the headless guest
complete its Win32 desktop initialization.
