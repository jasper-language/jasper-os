# Pixel 6a LC-2 preflight

Date: 2026-11-18

This run performed no `flash`, `erase`, or persistent partition write.
It recorded the Android build/slot/AVB state, fastboot-visible partition sizes,
and verified that a fastboot round trip returned to `boot_completed=1`.

Persistent LC-2 installation still requires a public UFS access backend in the
Driver Host. This preflight is not an install, update, rollback, or power-loss
acceptance result.
