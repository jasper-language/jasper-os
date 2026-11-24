# COMPAT-D3D-1 WSI/present fixture status

Updated: 2026-11-23.

Status: **passed for the hidden Wine service desktop on Mesa lavapipe**.

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

## Verified path

The fixture binds directly to `__wineservice_winstation` and dynamically loads
`d3d11.dll` after that binding. The Wine profile disables explorer launch and
tracks `uxtheme.dll` as part of the tested module closure.

The Vulkan transcript contains the real WSI path:

```text
vkCreateSwapchainKHR
vkAcquireNextImageKHR
vkQueuePresentKHR
D3D11_WSI_PROBE_OK feature=0xb000 hwnd=1 swapchain=1 buffer=1 present=1 pixel=32,64,128,255 size=64x64
```

The service-desktop HWND reports `visible=1 iconic=0 client=64x64`. Three
consecutive guest runs passed; the second and third runs also passed the strict
resource gate with `resources=true`, and the third run was required by the
verification profile. Evidence:
`evidence/compat-wine-wsi-r125/README.md`.

## Remaining gates

- Add visible desktop input/focus and resize/revoke coverage.
- Keep physical GPU, display and Pixel 6a acceptance separate.
