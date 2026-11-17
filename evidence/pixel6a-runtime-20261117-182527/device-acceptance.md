# Pixel 6a runtime probe acceptance

Date: 2026-11-17

Device and command:

```text
serial=31311JEGR07191
product=bluejay
current-slot=a
unlocked=yes
boot image sha256=81e2d85f242cb0c1ab7b10fe0709803914ebad78b5e29c33a4a1b1e52bb2b853
fastboot boot pixel6a-runtime-boot.img
```

The temporary image was booted without flashing or changing a slot. The device
left fastboot and returned to fastboot after the Jasper runtime reset path; the
observed round trip completed in one second. `fastboot reboot` then restored
Android:

```text
ro.product.device=bluejay
ro.build.fingerprint=google/bluejay/bluejay:16/BP4A.251205.006/14401865:user/release-keys
```

This is physical-device evidence for the existing early runtime probe only. It
is not evidence for LC-2 component updates, a writable Pixel lifecycle layout,
LC-4 vendor firmware, or the full Jasper userspace/terminal DAG node.
