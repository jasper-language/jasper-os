# COMPAT-D3D-1 WSI/present fixture status

Updated: 2026-11-22.

Status: **verification-pending**. The offscreen D3D11 pixel pass does not cover
window creation, DXGI swapchains, WSI or presentation.

The tracked fixture
`verification/fixtures/windows/d3d11_wsi_probe.c` requires this complete chain:

```text
Wine service desktop
-> real HWND through win32u
-> DXGI factory and hwnd swapchain
-> D3D11 backbuffer/render target/clear
-> staging readback pixel check
-> IDXGISwapChain1::Present returns S_OK
-> D3D11_WSI_PROBE_OK
```

Any failed stage emits `D3D11_WSI_PROBE_FAIL` and exits non-zero. The checker
also rejects a pass marker placed before `Present` or a manifest that claims an
unproven Jasper guest or physical GPU pass.

## Build

The reference cross-build uses a pinned x86-64 MinGW toolchain and deliberately
disables PE dynamic base loading for Jasper's current bounded user window:

```sh
bash scripts/build-d3d11-wsi-probe.sh --check-source
bash scripts/build-d3d11-wsi-probe.sh
```

The source/static checker is part of CI. Binary compilation requires
`x86_64-w64-mingw32-gcc`; it fails explicitly with exit status 69 when the
toolchain is absent.

## Remaining gates

- Run the binary through the fixed Wine 11.22/DXVK/lavapipe Jasper staging root.
- Require a literal `D3D11_WSI_PROBE_OK ... present=1` serial transcript.
- Require `exit_zero=true`, `resources=true` and `failed=0`.
- Add visible desktop input/focus and resize/revoke coverage.
- Keep physical GPU, display and Pixel 6a acceptance separate.
