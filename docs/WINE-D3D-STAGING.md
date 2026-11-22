# Wine D3D11/D3D12/WSI/lavapipe staging

Updated: 2026-11-22.

`verification/wine-d3d-staging.json` pins the software used by the bounded
Wine D3D11 verification path:

- Wine `11.22` source tag, commit, source archive digest, and WineHQ
  `wine-devel`/`wine-devel-amd64` package digests;
- unmodified DXVK `3.1.1` and VKD3D-Proton `3.1` releases and digests;
- Ubuntu Resolute Mesa lavapipe `26.0.8-1ubuntu0.3` and the complete pinned
  host-package baseline used to stage its ELF and ICD closure;
- the Jasper D3D11, D3D11 WSI and D3D12 fixture sources and reference MinGW
  artifact digests;
- final digests for the Wine loader, wineserver, preloader, built-in command
  programs, DXVK/VKD3D DLLs, probes, Vulkan ICD and LLVM library.

The staging script creates a new root from the immutable package archives and
host-package closure. It refuses an existing output directory, any package
version drift, an altered archive/probe digest or a missing final file.

```sh
JASPER_D3D11_PROBE=/path/to/d3d11-probe.exe \
JASPER_D3D12_PROBE=/path/to/d3d12-probe.exe \
JASPER_D3D11_WSI_PROBE=/path/to/d3d11-wsi-probe.exe \
  python3 scripts/prepare-wine-d3d-staging.py --prepare \
  --output /path/to/new/wine-d3d-root

python3 scripts/prepare-wine-d3d-staging.py \
  --verify-only /path/to/new/wine-d3d-root
```

Wine archives are downloaded from their pinned public URLs unless these
environment variables point at already verified copies:

- `JASPER_WINE_DEVEL_DEB`
- `JASPER_WINE_DEVEL_AMD64_DEB`
- `JASPER_DXVK_ARCHIVE`
- `JASPER_VKD3D_PROTON_ARCHIVE`

The probe binaries are intentionally external build artifacts because the
reference image was cross-built with MinGW. Their sources and digests are
tracked; the staging check never substitutes the host compiler or accepts a
different binary hash.

The same command can also be supplied the explicit flags
`--probe`, `--d3d12-probe` and `--d3d11-wsi-probe`. Missing or digest-mismatched
inputs fail closed.

This staging success is not a Jasper guest pass. D3D12, WSI/present, desktop
input, resource reclamation and physical GPU/Pixel 6a acceptance remain
separate DAG gates.
