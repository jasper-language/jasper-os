# Wine 11.22 + VKD3D-Proton 3.1 D3D12 software acceptance

Date: 2026-11-24.

Status: **PASS for the bounded Jasper UEFI/QEMU software-D3D12 profile.**

This run executes the unmodified Wine 11.22 loader with the pinned
VKD3D-Proton 3.1 `d3d12.dll` and `d3d12core.dll`, DXVK 3.1.1 `dxgi.dll`, the
Mesa lavapipe ICD and the fixed D3D12 probe. It does not claim a physical GPU,
visible desktop, D3D12 WSI or D3D12 conformance pass.

## Command

```text
JASPER_BUILD_ALLOW_VBOX=1 \
ISSUE21_UEFI_MODE=compat-wine-d3d12 \
ISSUE21_UEFI_OUT="$PWD/evidence/compat-wine-d3d12-r143-steady-state" \
ISSUE21_UEFI_TARGET="$PWD/target/issue21-wine-d3d12-r143" \
JASPER_ANDROID_TREE=/home/auth/.codex/worktrees/compat-wine-root/wine-d3d-staging-service-desktop-r134 \
ISSUE21_QEMU_ACCEL=tcg ISSUE21_QEMU_MEMORY=4G ISSUE21_QEMU_CPUS=4-5 \
ISSUE21_UEFI_TIMEOUT=900 \
bash scripts/issue21-uefi-boot-check.sh
```

Harness result:

```text
issue21-uefi-boot: PASS mode=compat-wine-d3d12 qemu_rc=124
```

`qemu_rc=124` is the expected existing control-group timeout result for this
guest mode. The guest completed the bounded lifecycle before the wrapper
timeout and remained idle until the timeout terminated QEMU.

## Functional result

The same probe was executed twice. Both runs produced:

```text
D3D12_PROBE_OK pixel=32,64,128,255 observed=32,64,128,255 row_pitch=256
```

The second run is the acceptance run:

```text
[JSR-LIFE-ROOT-DYNAMIC] program=compat-wine-d3d12 \
path=/opt/wine-devel/lib/wine/x86_64-unix/wine \
interpreter=/lib64/ld-linux-x86-64.so.2 mapped=true \
interpreter_syscalls=true syscalls=32690 exit_zero=true \
frames_before=940409 resources=true failed=0
[JSR-LIFE-HEALTH] result=root_execution_complete
```

The first run initializes the Wine prefix and compatibility caches and reports
`resources=false`; it is intentionally not used as the steady-state result.
The second run performs no `JSR-COMPAT-DYNAMIC-RESOURCE` failure diagnostic and
returns to the pre-run baseline.

The guest log records VKD3D-Proton's actual application version and build:

```text
vkd3d-proton - applicationVersion: 3.1.0.
vkd3d-proton - build: 4522cc1a8b1347f.
```

## Native Linux ABI repair exercised

The earlier VKD3D failure was caused by a fixed 64 MiB Linux compatibility-heap
window. r143 reaches:

```text
[JSR-LINUX-BRK] requested=0x10001458e000 \
current=0x10001456b000 ceiling=0x100040000000
```

The ceiling is now derived from the first live mapping or reservation above
the current heap end. Physical-frame and process quotas remain authoritative;
the change does not grant unlimited physical memory and is not VKD3D-specific.

## Remaining evidence boundary

The following remain open:

- physical GPU vendor ICD and hardware pixel presentation;
- D3D12/DXGI swapchain and presented pixels;
- visible desktop, focus, resize and input;
- D3D12 conformance and application-wide compatibility;
- Pixel 6a hardware display acceptance.

A Wine helper still faults at its PE preferred base `0x7ff600003670` during
startup. The main D3D12 probe continues and completes, but this helper fault
remains a real Wine desktop/loader compatibility defect and is not hidden by
this bounded D3D12 result.

Machine-readable detail and artifact hashes are in
`verification/compat-d3d12.toml` and `artifacts.sha256`.
