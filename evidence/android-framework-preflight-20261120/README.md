# Android Framework Namespace Preflight

Date: 2026-11-20

Input image:

```text
/home/auth/.cache/jasper-abi-runtime-test/android-system-image/android-34-default-x86_64/x86_64/framework-root-v1.img
```

The image is a real Android 34 ext4 framework root produced for Jasper
verification. `scripts/android-framework-preflight.py` inspected it read-only
through `debugfs`.

Observed framework content:

- `app_process64`, `servicemanager`, and `installd` are executable;
- `framework.jar`, `services.jar`, and `am.jar` are present;
- `framework-res.apk` has 7,880 ZIP entries and a 16,421,724-byte
  `resources.arsc`;
- `/system/etc/permissions` and `/apex/com.android.runtime` are present.

Static Activity launch prerequisites:

- `/system/etc/init/hw/init.zygote64.rc` starts
  `/system/bin/app_process64 -Xzygote /system/bin --zygote`;
- the same service passes `--start-system-server`, so modern Android does not
  require separate `zygote64` or `system_server` executable files;
- the image also contains `framework-res.apk`, the runtime APEX, permission
  configuration and the boot-critical Android user-space services listed above.

The next audit pass corrected two false static blockers:

- `/linkerconfig/ld.config.txt` is intentionally absent from the system image.
  `init.rc` creates `/linkerconfig/bootstrap`, writes an early config, bind
  mounts it over `/linkerconfig`, starts `apexd-bootstrap`, and then runs the
  `update_linker_config` init command;
- `/system/etc/passwd` is an empty regular file owned by Android UID/GID 1000
  in this stock AOSP image. Presence and ownership are the static facts;
  Android user/group services provide runtime identity rather than the image
  requiring a non-empty passwd database.

Result: `container_ready=true`, `activity_runtime_ready=false`, `missing=[]`.

This evidence does not claim Activity lifecycle. It establishes that the
current root fixture has the complete static zygote/system_server launch,
linker-config generation, Framework, APEX, SELinux, permission and user
database prerequisites. The next slice must actually start the chain with
matching APEX mounts and Binder services, then exercise
`onCreate/onStart/onResume`, resource/configuration delivery, graphics, input
and audio.
