# Wine D3D11 offscreen probe evidence

Date: 2026-11-22.

Wine 11.22, unmodified DXVK 3.1.1 and Mesa lavapipe ran through Jasper's real
UEFI/root-image path on a four-core host KVM run. The service-desktop probe
completed the following chain:

```text
DXVK: v3.1.1
Found device: llvmpipe (LLVM 21.1.0, 256 bits)
D3D11_PROBE_OK feature=0xb000 pixel=32,64,128,255
[JSR-LIFE-ROOT-DYNAMIC] program=compat-wine-d3d11 ... exit_zero=true ... failed=0
qemu_rc=33
```

This is a core D3D11 device, render-target, copy and mapped-pixel-readback
result. It does not establish D3D12/VKD3D-Proton, WSI/present, desktop input,
resource-baseline cleanup, or physical GPU/Pixel acceptance. The probe is
linked without `DYNAMIC_BASE` because the current Jasper user window does not
yet cover Wine's randomized PE base.

The complete serial transcript is retained in the local verification output;
only this reproducible summary and exit code are checked into the public tree.
