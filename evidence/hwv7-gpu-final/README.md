# HWV-7 virtio-gpu Linux guest acceptance

The guest is Linux 6.12.0 with:

```text
CONFIG_DRM=y
CONFIG_DRM_KMS_HELPER=y
CONFIG_DRM_VIRTIO_GPU=y
CONFIG_DRM_FBDEV_EMULATION=y
CONFIG_FB=y
```

Boot artifacts:

```text
setup-header.bin sha256 fe0cf3b8d511de0f430013d28afd02b4898d019a305b6c07cf5f8a483daa9ebe
vmlinux.bin      sha256 83bee8879c180a2d7ea6dbf36aa2c66a934b652acf0c9160a0cb479b60559b28
```

The Linux DRM dumb-buffer/fbdev path discovers virtio-mmio GPU device 16,
queries display information, creates/attaches a 2D resource, configures
scanout, transfers and flushes pixels, creates and removes a second resource,
then returns to the fbdev baseline.

Two consecutive runs exit 33. Representative result:

```text
[JSR-HWV5-GPU] device=gpu discovered=true display=true create=true
  attach=true scanout=true transfer=true flush=true unref=true reset=true ok=true
[JSR-HWV7-GPU] backend=virtio-mmio commands=36 created=2 destroyed=1
  scanouts=4 transfers=11 flushes=11 rejected=0 resources=1
  reset_generation=2 ok=true
```

The remaining resource is the kernel fbdev baseline, not a guest-created leak.
The paravirtual vendor backend and physical passthrough/mdev backend are not
claimed by this evidence.
