# Wine D3D12 offscreen probe r86

Date: 2026-11-23.

Status: **host passed; Jasper guest failed**.

The D3D12 probe now runs on Wine's current desktop instead of forcing the
first-launch service desktop. This removes the unrelated explorer high-address
rebase fault from the offscreen device path.

Host control with the pinned Wine 11.22, DXVK 3.1.1, VKD3D-Proton 3.1 and
lavapipe assets:

```text
D3D12_PROBE_OK pixel=32,64,128,255 observed=32,64,128,255 row_pitch=256
```

Jasper guest with 2 GiB and 4 GiB still returns:

```text
D3D12_PROBE_FAIL stage=create-device hr=0x8007000e
```

The guest failure occurs before the probe reaches resource creation. No
`D3D12_PROBE_OK` is claimed for Jasper.
