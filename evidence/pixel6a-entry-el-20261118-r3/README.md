# Pixel 6a runtime timing baseline

Date: 2026-11-18.

This run is the control for `pixel6a-entry-el-20261118-r4` and uses the normal
Pixel runtime without the EL2 observation delay.

```text
runtime_return_seconds=4.59
post_boot_fingerprint=google/bluejay/bluejay:16/BP4A.251205.006/14401865:user/release-keys
android boot_completed=1
```

The device returned to the existing Android slot after the Jasper PSCI reset.
