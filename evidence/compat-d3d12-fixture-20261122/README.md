# D3D12 fixture build evidence

Date: 2026-11-22.

This record proves that the bounded D3D12 probe source builds as a Windows
x86-64 PE. It is not a Jasper runtime result.

## Toolchain

```text
container=debian:bookworm-slim
compiler=x86_64-w64-mingw32-gcc 12.2.0
headers=mingw-w64-x86-64-dev 10.0.0
command=bash scripts/build-d3d12-probe.sh
```

## Result

```text
target/compat-d3d12/d3d12-probe.exe:
  PE32+ executable (console) x86-64, for MS Windows, 19 sections
sha256=95b5bf0e1531b18a300d13c92972aa52a4d8d6c78b99f9c8ee5fbf0aa7485634
```

The build uses `--disable-dynamicbase` only because Jasper's current bounded
user window does not cover Wine's randomized PE base.

## VKD3D-Proton baseline

```text
release=v3.1
archive=vkd3d-proton-3.1.tar.zst
archive_sha256=b85ea8219b71093a3924913dd7aae6172333dc0c069983ed510816d67f02120b
d3d12.dll_sha256=502694a5fd5e06381ef2cdb33359c5948b6a012938902ddc9e9b381841bc0ce7
d3d12core.dll_sha256=0dfd690a39ef8361ca3b64e9fd8e945b27d2c568dac5dc0dce1a45abf65914cc
```

No `D3D12_PROBE_OK` marker has been captured in Jasper. D3D12 runtime, WSI,
input, resource reclamation, physical GPU and Pixel 6a remain open.
