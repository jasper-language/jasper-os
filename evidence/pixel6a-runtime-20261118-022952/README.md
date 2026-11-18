# Pixel 6a current-main runtime acceptance

Date: 2026-11-18

The public `main` kernel was injected into the matching stock PE/AVB carrier
and booted on the attached Pixel 6a with `fastboot boot`. No partition was
flashed and the active slot was not changed.

```text
serial=31311JEGR07191
product=bluejay
slot=a
unlocked=yes
boot-image-sha256=691fcef4d77f6dcc7d8a8d9bc4c36b381c24f7e4033905482dcacbdb727909c6
elf-sha256=251b6cb790534c8b612a05c20675b91978ba5641830b840287eef87def183143
runtime_return_seconds=4.40
android-recovery-fingerprint=google/bluejay/bluejay:16/BP4A.251205.006/14401865:user/release-keys
post-boot-slot=a
post-boot-completed=1
```

The observed PSCI reset after the runtime success path proves that the latest
public kernel reached its completion boundary on Pixel 6a. The script then
rebooted the unchanged slot and Android recovered.

This is physical runtime evidence only. It does not prove Jasper UFS
provisioning, writable userspace, LC-2 installation/update/rollback/power-loss
recovery, LC-4 driver/firmware lifecycle, GPU/display, or interactive CLI.
