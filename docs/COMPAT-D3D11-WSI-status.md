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

The fixed staging root carries this probe under `/opt/wine-devel`, and the
kernel exposes the separate `compat-wine-wsi-verify` feature. Its UEFI mode is
`ISSUE21_UEFI_MODE=compat-wine-wsi`; the host-side gate requires the literal
`D3D11_WSI_PROBE_OK ... present=1` marker and `resources=true`.

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

## Current diagnostic boundary

The fixture binds directly to `__wineservice_winstation` and dynamically loads
`d3d11.dll` after that binding. The Wine profile disables explorer launch and
tracks `uxtheme.dll` as part of the tested module closure. This isolates WSI
from the earlier explorer PE relocation fault.

The guest now proceeds through both the D3D11 import closure and `uxtheme.dll`,
but Wine still cannot create the service-desktop top-level window:

```text
D3D11_WSI_DESKTOP service=true
get_desktop_window failed to create desktop window
NtUserRegisterClassExWOW Failed to get shared session object for window class
D3D11_WSI_PROBE_FAIL stage=register-window-class
```

The failure is before `CreateSwapChainForHwnd`; it is not yet a DXVK, Vulkan
surface or Present semantic verdict. Evidence:
`evidence/compat-wine-wsi-r106/README.md`.

## Remaining gates

- Run the binary through the fixed Wine 11.22/DXVK/lavapipe Jasper staging root.
- Provide the Wine desktop display-driver bridge that creates the service
  desktop and its shared session object from a Jasper display surface.
- Require a literal `D3D11_WSI_PROBE_OK ... present=1` serial transcript.
- Require `exit_zero=true`, `resources=true` and `failed=0`.
- Add visible desktop input/focus and resize/revoke coverage.
- Keep physical GPU, display and Pixel 6a acceptance separate.
