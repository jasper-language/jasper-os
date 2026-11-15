# HWV-5 NET/FS final acceptance

The run uses a Linux 6.12.0 bzImage built with an empty internal initramfs and
an externally loaded gzip cpio initramfs.

```text
setup-header.bin sha256 0bad1c2cd090033f07fa1b4124d145bfdc4058095b56a05450a2003b0b6344a3
vmlinux.bin      sha256 c0854289c73d5553fd3a79f7bc804a4aab806d20924679208a4e6ac3d92e0eb6
```

Required guest configuration:

```text
CONFIG_NET=y
CONFIG_PACKET=y
CONFIG_INET=y
CONFIG_VIRTIO_MMIO=y
CONFIG_VIRTIO_NET=y
CONFIG_FUSE_FS=y
CONFIG_VIRTIO_FS=y
```

Command:

```text
taskset -c 0-3 env \
  JSR_LINUX_GUEST_HEADER=<setup-header.bin> \
  JSR_LINUX_GUEST_KERNEL=<vmlinux.bin> \
  JSR_LINUX_GUEST_INITRAMFS=<initramfs.cpio> \
  HWV5_CORE_CPUS=0-3 HWV5_CORE_SMP=4 \
  bash scripts/hwv5-core-check.sh
```

The gate requires QEMU exit 33, core, PIO, NET and FS markers, non-zero guest
TX/RX and FUSE request counts, `pio_marker=true`, `marker=true`,
`reclaim=true`, `policy_overflow=0` and no failure marker.

Final result:

```text
qemu_rc=33
[JSR-HWV5-NET] device=net discovered=true link=true tx=true rx=true arp=true ok=true
[JSR-HWV5-FS] device=fs discovered=true mount=true lookup=true read=true write=true ok=true
[JSR-HWV4-LINUX] virtio_net_tx_frames=1 virtio_net_rx_frames=1
  virtio_net_backend_tx=1 virtio_net_backend_rx=1 virtio_fs_requests=13
  pio_marker=true marker=true reclaim=true
[JSR-HWV5] vmm=true policy=true policy_overflow=0 failed=0
```

The FUSE sequence includes INIT, LOOKUP, OPEN, READ, WRITE, FLUSH and RELEASE.
After WRITE, the guest closes and reopens the file, then reads 22 bytes and
matches `Jasper virtio-fs guest`.
