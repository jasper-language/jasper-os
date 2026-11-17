# Pixel 6a current-main runtime acceptance

Date: 2026-11-17

The current public `main` kernel was injected into the matching stock PE/AVB
carrier and booted on the attached Pixel 6a with `fastboot boot`. No partition
was flashed and the active slot was not changed.

```text
serial=31311JEGR07191
product=bluejay
slot=a
unlocked=yes
boot-image-sha256=e21d8b9c1ec0465274d844be8afd8ef68ea0fd29be7c896b46dd65ca87077657
runtime_return_seconds=4.55
android-recovery-fingerprint=google/bluejay/bluejay:16/BP4A.251205.006/14401865:user/release-keys
post-boot-slot=a
post-boot-completed=1
```

The observed PSCI reset after the runtime success path proves that the current
physical kernel plan reached its completion boundary on Pixel 6a. The script
then rebooted the unchanged slot and Android recovered successfully.

This closes only current-main physical runtime rehearsal. It is not evidence
that Jasper userspace, writable UFS provisioning, LC-2 install/update/rollback,
power-loss recovery, or LC-4 driver/firmware lifecycle can run on Pixel 6a.
