# D3D11 WSI fixture build evidence

Date: 2026-11-22.

This record proves that the bounded D3D11 WSI probe source cross-builds as a
Windows x86-64 PE. The Jasper guest result is recorded separately in
`evidence/compat-wine-wsi-r125/README.md`.

## Toolchain

```text
container=debian:bookworm-slim
compiler=x86_64-w64-mingw32-gcc-posix 13
command=bash scripts/build-d3d11-wsi-probe.sh
```

## Result

```text
target/windows/d3d11-wsi-probe.exe:
  PE32+ executable (GUI) x86-64
bytes=935481
sha256=7851a8ac7a9bfb1c361c4457b6776ec67e50ee67b28d887287bb90976ccd6a1e
```

The fixture was built with `--disable-dynamicbase` because Jasper's current
bounded user window does not cover Wine's randomized PE base, and
`--no-insert-timestamp` so the pinned binary digest is reproducible.

The Jasper guest captured the marker, executed the Vulkan swapchain and present
path, and passed the strict steady-state resource gate. Visible input/focus,
physical GPU and Pixel 6a display remain open gates.

## Staging verification

The pinned Wine/DXVK/lavapipe root was extended with VKD3D-Proton 3.1,
`d3d12-probe.exe` and `d3d11-wsi-probe.exe`. The staging verifier checked all
17 final file digests and the staged `wine --version` result:

```text
wine-d3d-staging: VERIFY PASS
```
