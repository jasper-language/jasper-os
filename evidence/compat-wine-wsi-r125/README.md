# Wine D3D11 WSI guest acceptance r125

Date: 2026-11-23.

Status: **Jasper guest passed**.

The fixed Wine 11.22 / DXVK 3.1.1 / Mesa lavapipe staging root ran the
unmodified probe three times in one Jasper guest:

```text
D3D11_WSI_PROBE_OK feature=0xb000 hwnd=1 swapchain=1 buffer=1 present=1 pixel=32,64,128,255 size=64x64
```

The logs show the real Vulkan WSI chain:

```text
vkCreateSwapchainKHR
vkAcquireNextImageKHR
vkQueuePresentKHR
```

The service-desktop HWND reported `visible=1 iconic=0 client=64x64`. The first
run initializes bounded compatibility-service caches. The second and third
runs passed the strict resource gate with `resources=true`; the third run was
the mandatory acceptance run:

```text
frames_before=416213 frames_after=416213 retained=0 heap_mapped_delta=0
resources=true exit_zero=true failed=0
```

Two Linux ABI/cache defects found by this path were fixed:

- `memfd_create(MFD_EXEC)` is accepted with executable and sealing semantics;
- `/proc/<exited-pid>` compatibility cache files, directories and symlinks are
  reclaimed from process teardown.

The PASS/FAIL markers are emitted with one `WriteFile` so concurrent kernel
serial diagnostics cannot split the acceptance marker.

This proves a hidden Win32 service-desktop swapchain and Vulkan Present. It does
not claim physical GPU presentation, visible desktop input/focus, or Pixel 6a
display acceptance.
