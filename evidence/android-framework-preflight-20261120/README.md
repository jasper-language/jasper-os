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

Missing Activity launch prerequisites:

- `/system/bin/zygote64`;
- `/system/bin/system_server`.

Result: `container_ready=false`, `activity_runtime_ready=false`.

This evidence does not claim Activity lifecycle. It establishes that the
current root fixture cannot start ActivityManager even though the framework
files and resource table are present. The next slice must admit a complete
zygote/system_server/APEX/SELinux/Binder namespace and then exercise
`onCreate/onStart/onResume`, resource/configuration delivery, graphics, input
and audio.
