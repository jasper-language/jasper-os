# Pixel 6a LC-2 preflight

Date: 2026-11-18

This run performed no `flash`, `erase`, or persistent partition write.
It recorded the Android build/slot/AVB state, fastboot-visible partition sizes,
and verified that a fastboot round trip returned to `boot_completed=1`.

```text
serial=31311JEGR07191
product=bluejay
fingerprint=google/bluejay/bluejay:16/BP4A.251205.006/14401865:user/release-keys
slot=a
verifiedbootstate=orange
unlocked=yes
data_available_kib=104327188
userdata_bytes=118398996480
super_bytes=8531214336
boot_a_bytes=67108864
boot_b_bytes=67108864
fastboot_round_trip=PASS
post_boot_slot=a
post_boot_completed=1
```

Persistent LC-2 installation still requires a public UFS access backend in the
Driver Host. This preflight is not an install, update, rollback, or power-loss
acceptance result.
