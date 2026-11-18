# Jasper-OS native keyboard to JSUI input

Date: 2026-11-18.

This evidence proves the QEMU i8042/PS-2 emulated keyboard path through the
native Jasper-OS input session into the real UI Service and Engine. It is not a
physical keyboard, Pixel 6a, USB, pointer, touch or IME qualification.

## Path

```text
QEMU monitor: sendkey ret
-> emulated i8042/PS-2 controller
-> Jasper native polled set-1 decoder
-> KeyInput { code: 0x0103, pressed: true }
-> UI-owned bounded display input queue
-> OS host translation to JSUI Input code 28
-> native Channel
-> CPL3 ui-service
-> Engine focus/Activate admission
-> third RGBA8 Present frame
-> native compositor/framebuffer
```

The display runtime has an exclusive UI input route while the UI host owns the
keyboard. The terminal remains alive but cannot consume the key ahead of the UI
transaction.

## Result

```text
[JSR-UI-PROCESS] waiting_real_key=true native_enter=0x0103
[JSR-UI-PROCESS] native_keyboard=true native_code=0x0103 jsui_code=28
[JSR-UI-PROCESS-BASELINE] before=Baseline { free_frames: 125721, objects: 0, pending: 0, pins: (0, 0) } after=Baseline { free_frames: 125721, objects: 0, pending: 0, pins: (0, 0) } queued=0/0
[JSR-DISPLAY-UI] presented=true width=64 height=64 x=608 y=328 layers=3
[JSR-UI-PROCESS] started=true channel=true request_queued=true engine=cpu rendered=true present=true patch=true input=true native_keyboard=true frames=3 display=true exit=0 response=true terminal_alive=true resources=true checks=15 failed=0
qemu_rc=33
```

No `panicked` or `JSR-PANIC` marker occurs. Service and host processes, Channel
queues, objects, pins and frames return to the pre-run baseline.

## Artifacts

```text
serial.txt
qemu_rc.txt
artifacts.sha256
kernel.img
```

Kernel image SHA-256:

```text
664d5bf99a1dd1c336e66d278f19780f29f9e2f9a49055cfdae730bea15c5fc6
```

## Scope

This closes the native keyboard-controller to UI Engine input path on x86_64
QEMU. Physical keyboard/USB, pointer, touch, IME, Pixel display/keyboard,
long-running input, multi-application focus isolation and reboot continuity
remain separate exit gates.
