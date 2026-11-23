# D3D11 WSI fixture build evidence

Date: 2026-11-22.

This record proves that the bounded D3D11 WSI probe source cross-builds as a
Windows x86-64 PE. It is not a Jasper guest or physical GPU result.

## Toolchain

```text
container=debian:bookworm-slim
compiler=x86_64-w64-mingw32-gcc from Debian bookworm mingw-w64
command=bash scripts/build-d3d11-wsi-probe.sh
```

## Result

```text
target/windows/d3d11-wsi-probe.exe:
  PE32+ executable (GUI) x86-64
bytes=659156
sha256=22cbfb78baf265730235bbba58bf56f5fcaa519309a9f85a4835b926014c2138
```

The fixture was built with `--disable-dynamicbase` because Jasper's current
bounded user window does not cover Wine's randomized PE base, and
`--no-insert-timestamp` so the pinned binary digest is reproducible.

No `D3D11_WSI_PROBE_OK` marker has been captured in Jasper. Swapchain
presentation, input, resource reclamation, physical GPU and Pixel 6a remain
open gates.

## Staging verification

The pinned Wine/DXVK/lavapipe root was extended with VKD3D-Proton 3.1,
`d3d12-probe.exe` and `d3d11-wsi-probe.exe`. The staging verifier checked all
15 final file digests and the staged `wine --version` result:

```text
wine-d3d-staging: VERIFY PASS
```
