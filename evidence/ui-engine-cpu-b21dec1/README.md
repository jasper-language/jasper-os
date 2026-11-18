# Jasper UI Engine CPU core integration

Date: 2026-11-18.

Exact source:

```text
repository=https://github.com/jasper-language/jasper-ui-engine
commit=b21dec1ae504a06923defcc715722c7b9e9c1dc8
feature=no-std-core
target=x86_64-unknown-none
license=Apache-2.0
```

The public source branch is `codex/no-std-core`.

## Verified path

The Jasper-OS `user/ui-service` CPL3 process receives a JSUI v1 Scene frame over
a real native Channel, parses Typed UI IR, runs the pinned Engine CPU core, and
returns a versioned JSUI Present frame containing a host-owned 64x64 RGBA8
surface. The host first verifies Service/Channel cleanup, then adopts the Surface
as a third native Compositor layer at `(608, 328)` and reads the framebuffer
pixel back as `0A 84 FF`.

The acceptance scene is a 64x64 container with background `#0A84FFFF`. The host
verifies all 16,384 payload bytes are present, the first pixel is the expected
`0A 84 FF FF`, every alpha byte is `FF`, the service exits with code zero, and
Channel/process/frame resources return to baseline.

Evidence:

```text
ui-host-adapter-20261118-204008/
ui-process-20261118-205633/serial.log
ui-process-20261118-205633/qemu_rc.txt=33
```

Final marker:

```text
[JSR-DISPLAY-UI] presented=true width=64 height=64 x=608 y=328 layers=3
[JSR-UI-PROCESS] started=true channel=true request_queued=true engine=cpu rendered=true present=true display=true exit=0 response=true terminal_alive=true resources=true
ui-process: PASS cpl3=true channel=true jsui=true engine=cpu rendered=true present=true display=true exit=0 terminal=true resources=true
```

This closes the Engine-to-RGBA8-to-native-framebuffer first-frame slice. It does
not claim UI-OS-1 completion: physical display qualification, sustained
interactive input, restart continuity, fonts/text rendering and GPU/WSI remain
open.
