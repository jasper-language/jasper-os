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

The corrected check also found real namespace/identity blockers:

- `/linkerconfig/ld.config.txt` is absent, so Bionic cannot apply the Android
  Framework/APEX linker namespace map;
- `/system/etc/passwd` exists only as a zero-byte file;
- VINTF manifest, SELinux policy, init definitions and `/system/apex` are
  present.

Result: `container_ready=false`, `activity_runtime_ready=false`.

This evidence does not claim Activity lifecycle. It establishes that the
current root fixture has the correct zygote/system_server launch *definition*
and most Framework files, but still lacks the linker namespace map and
non-empty Android user database needed for a complete static launch root. The
next slice must supply those, actually start the chain with matching APEX
mounts and Binder services, then exercise `onCreate/onStart/onResume`,
resource/configuration delivery, graphics, input and audio.
