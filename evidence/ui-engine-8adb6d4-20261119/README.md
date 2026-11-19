# Jasper-OS UI Engine 8adb6d4 acceptance

Exact Engine:

```text
https://github.com/jasper-language/jasper-ui-engine
codex/no-std-core
8adb6d4432c8385250192304eef04a07b22594d2
```

The real CPL3 UI Service ran two sequential sessions. Each session received
Scene and Patch, consumed a QEMU i8042/PS-2 Enter through the native input
queue, rendered three 64x64 RGBA8 Present frames through `CoreRgbaRenderer`,
closed normally, and returned process/object/Channel/frame state to its round
baseline.

```text
[JSR-UI-PROCESS] rounds=2 started=true channel=true request_queued=true engine=cpu rendered=true present=true patch=true input=true native_keyboard=true frames=6 display=true exit=0 response=true terminal_alive=true restart=true resources=true checks=31 failed=0
qemu_rc=33
```

No panic or UI process failure marker occurs. This is QEMU CPU/compositor
evidence, not physical display, crash recovery, Surface retire or UI-OS-1
completion.
