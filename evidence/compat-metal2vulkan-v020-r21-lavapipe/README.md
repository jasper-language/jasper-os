# Metal2Vulkan v0.2.0 render-to-texture acceptance

Date: 2026-11-24.

Status: **PASS for the bounded Jasper UEFI/KVM software-Vulkan profile.**

This run executes unmodified Metal2Vulkan v0.2.0 examples
(`compute_dispatch` and `render_to_texture`) through Jasper's Linux ABI on the
Mesa lavapipe ICD. It proves the Linux Vulkan loader, lavapipe, the runtime's
Metal-to-Vulkan translation, render pipeline, render pass, texture clear,
draw, copy-to-buffer and mapped pixel readback. It does not prove a physical
GPU, visible WSI, compositor presentation or hardware display.

## Source baseline

- repository: `https://github.com/steelbrain/metal2vulkan`
- tag: `v0.2.0`
- commit: `d9236a8a11d3b90a1aa27b54e2d74d3891c4d2e5`
- compute SHA-256:
  `13038ca43ce77990c9f5367602ef882437ce30c283a45355d9e1db8f947f03eb`
- render SHA-256:
  `4330c8fd1b6025382dee03aab1f007c3d959d32a6cc32c9722edde6da85c7be5`
- lavapipe ICD SHA-256:
  `d9a8bc5d4b3ec0e065562d362541c2a4cb3f3d6208ac715f7ff1dcf01289d164`

The example binaries and AIR fixture are not modified.

## Command

The guest root was assembled from the pinned Wine/D3D staging closure and the
Metal2Vulkan examples. The image was then built and run with:

```text
JASPER_BUILD_ALLOW_VBOX=1 \
ISSUE21_REUSE_ROOT=1 ISSUE21_KEEP_DERIVED=1 \
ISSUE21_UEFI_MODE=vulkan-metal2vulkan \
ISSUE21_UEFI_OUT="$PWD/evidence/compat-metal2vulkan-v020-r21-lavapipe" \
ISSUE21_UEFI_TARGET="$PWD/target/issue21-metal2vulkan-lvp-full-v020-r20" \
JASPER_ANDROID_TREE=/home/auth/.cache/jasper-abi-runtime-test/vulkan-metal2vulkan-lvp-full-v0.2.0 \
ISSUE21_QEMU_ACCEL=kvm ISSUE21_QEMU_CPU=host \
ISSUE21_QEMU_MEMORY=4G ISSUE21_QEMU_SMP=4 ISSUE21_QEMU_CPUS=4-7 \
ISSUE21_UEFI_TIMEOUT=600 \
bash scripts/issue21-uefi-boot-check.sh
```

Harness result:

```text
issue21-uefi-boot: PASS mode=vulkan-metal2vulkan qemu_rc=33
```

## Functional result

The guest selected:

```text
device: llvmpipe (LLVM 21.1.8, 256 bits)
```

Both executions produced:

```text
output[0..4] = [0.0, 3.0, 6.0, 9.0], ..., output[999] = 2997: as expected
every texel as expected: the top-left quarter drawn, the rest cleared
```

The second steady-state executions reported:

```text
program=metal2vulkan-compute syscalls=3668 exit_zero=true
frames_before=941344 resources=true failed=0
program=metal2vulkan-render syscalls=3718 exit_zero=true
frames_before=941344 resources=true failed=0
[JSR-LIFE-HEALTH] result=root_execution_complete
```

The render example produced the required 8x8 RGBA8 image with the top-left
quarter drawn and the remaining texels cleared, then exited zero.

## Validation coverage

- unmodified Linux ELF loader and PIE execution;
- Vulkan loader, lavapipe ICD and physical-device selection;
- compute pipeline and output buffer readback;
- render pipeline with vertex and fragment functions;
- private render texture, clear, two-triangle draw and store;
- blit/copy from texture to shared buffer;
- fence/completion, mapped readback and exact texel comparison;
- two consecutive executions with steady-state resource recovery.

## Remaining boundary

- The SwiftShader render backend still fails independently in its JIT path at
  a read of an already-unmapped anonymous allocation. That failure is not
  hidden by the lavapipe result.
- Physical GPU vendor ICD, hardware queue completion and reset;
- visible WSI/swapchain/present and compositor surface;
- display, focus, resize and input integration;
- Pixel 6a hardware presentation.

The reproducible lavapipe tree helper added in this change is
`scripts/prepare-metal2vulkan-lavapipe-tree.sh`. It consumes the pinned
Wine/D3D staging root rather than downloading a second copy of Vulkan.
